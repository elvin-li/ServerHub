"""Regression tests for the vulnerabilities found in the security audit.

Each class pins one fix.  Every one of these was reachable before the patch, so
the tests are written to fail loudly if the behaviour is ever reintroduced --
including by a well-meaning refactor that "simplifies" a comparison back to
``secrets.compare_digest`` or a template back to an f-string.

The tests deliberately assert the *property*, not the implementation, wherever
that is possible: "a non-ASCII token is a clean auth failure" rather than "this
function is called".
"""
from __future__ import annotations

import os
import plistlib
import re
import shutil
import socket
import sys
import tempfile
import unittest
import urllib.request
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from fastapi import Request, Response  # noqa: E402

from hub import auth, backups, bookmarks_svc, cloudflared_svc, files_svc  # noqa: E402
from hub.routers import auth_api  # noqa: E402


def request(
    *,
    client="127.0.0.1",
    method="GET",
    path="/api/status",
    scheme="http",
    headers: list[tuple[bytes, bytes]] | None = None,
) -> Request:
    return Request({
        "type": "http",
        "method": method,
        "path": path,
        "headers": headers or [],
        "scheme": scheme,
        "server": ("localhost", 8086),
        "client": (client, 12345),
    })


def mode_of(path: Path) -> int:
    return path.stat().st_mode & 0o777


class NonAsciiCredentialTests(unittest.TestCase):
    """A malformed credential must be an auth failure, never a 500.

    ``secrets.compare_digest`` raises TypeError on a str containing any
    non-ASCII character.  Starlette decodes request headers as latin-1, so a
    single 0xFF byte in the local-client token header arrived as U+00FF and blew
    up the comparison inside ``require_auth`` -- which is a global dependency, so
    an unauthenticated attacker could turn *every* protected endpoint into an
    unhandled 500 with one request header.
    """

    #: What latin-1 header decoding produces from a raw 0xFF 0xFE body.
    NON_ASCII = b"\xff\xfe".decode("latin-1")

    def test_the_helper_accepts_arbitrary_unicode(self):
        self.assertFalse(auth.constant_time_equals(self.NON_ASCII, "expected"))
        self.assertFalse(auth.constant_time_equals("expected", self.NON_ASCII))
        self.assertFalse(auth.constant_time_equals(None, "expected"))
        self.assertFalse(auth.constant_time_equals("expected", None))

    def test_the_helper_still_compares_correctly(self):
        self.assertTrue(auth.constant_time_equals("s3cret", "s3cret"))
        self.assertTrue(auth.constant_time_equals("\u4f60\u597d", "\u4f60\u597d"))
        self.assertFalse(auth.constant_time_equals("s3cret", "s3cres"))
        self.assertFalse(auth.constant_time_equals("s3cret", "s3cret "))

    def test_a_non_ascii_local_token_header_does_not_raise(self):
        with tempfile.TemporaryDirectory() as tmp:
            token_file = Path(tmp) / "token"
            token_file.write_text("real-token\n", encoding="utf-8")
            headers = [(
                auth.LOCAL_TOKEN_HEADER.encode(),
                self.NON_ASCII.encode("latin-1"),
            )]
            with mock.patch.object(auth, "LOCAL_TOKEN_FILE", token_file):
                # The property: a decision, not an exception.
                self.assertFalse(
                    auth.local_client_authenticated(request(headers=headers))
                )

    def test_a_non_ascii_username_is_rejected_not_crashed(self):
        # dotless i: a plausible homoglyph attempt against "admin".
        self.assertFalse(auth_api.secrets_compare("adm\u0131n", "admin"))
        self.assertTrue(auth_api.secrets_compare("admin", "admin"))

    def test_a_non_ascii_setup_token_is_rejected_not_crashed(self):
        with (
            mock.patch.object(auth, "setup_required", return_value=True),
            mock.patch.object(auth, "setup_token", return_value="expected-token"),
        ):
            self.assertFalse(
                auth.complete_setup("t\u00f6ken", "long-enough-pw", "admin")
            )

    def test_a_non_ascii_password_against_a_legacy_plaintext_config(self):
        with mock.patch.object(
            auth, "_auth_cfg", return_value={"password": "legacy-plaintext"}
        ):
            self.assertFalse(auth.verify_password("p\u00e4ssword"))
            self.assertTrue(auth.verify_password("legacy-plaintext"))

    def test_no_call_site_uses_the_crashing_comparison_on_request_data(self):
        """secrets.compare_digest must not come back for network-supplied text."""
        source = (BASE / "hub" / "auth.py").read_text()
        # The call form specifically -- prose mentions of the name are fine.
        self.assertNotIn(
            "secrets.compare_digest(",
            source,
            "hub/auth.py compares network-supplied strings; secrets.compare_digest "
            "raises TypeError on non-ASCII input, so use constant_time_equals",
        )


class SessionCookieSecureFlagTests(unittest.TestCase):
    """The session cookie must carry ``Secure`` whenever the browser used TLS.

    ServerHub is meant to be published through cloudflared or nginx, and both
    terminate TLS then speak plain HTTP to this origin.  Reading only
    ``request.url.scheme`` therefore saw "http" on precisely the deployment that
    is exposed to the internet, and issued the session cookie without ``Secure``.
    """

    def _cookie_for(self, **kw) -> str:
        response = Response()
        with mock.patch.object(auth, "create_session", return_value="token"):
            auth_api._set_session(response, request(**kw), "admin")
        return response.headers["set-cookie"]

    def test_direct_https_sets_secure(self):
        self.assertIn("Secure", self._cookie_for(scheme="https"))

    def test_x_forwarded_proto_https_sets_secure(self):
        cookie = self._cookie_for(headers=[(b"x-forwarded-proto", b"https")])
        self.assertIn("Secure", cookie)

    def test_the_first_value_of_a_forwarded_proto_chain_is_used(self):
        cookie = self._cookie_for(headers=[(b"x-forwarded-proto", b"https, http")])
        self.assertIn("Secure", cookie)

    def test_rfc7239_forwarded_header_sets_secure(self):
        cookie = self._cookie_for(
            headers=[(b"forwarded", b'for=203.0.113.4;proto=https;by=proxy')]
        )
        self.assertIn("Secure", cookie)

    def test_plain_http_on_the_lan_still_works(self):
        # Marking this Secure would make the cookie unusable over LAN HTTP, so
        # the absence here is deliberate and must not regress into always-on.
        self.assertNotIn("Secure", self._cookie_for(scheme="http"))

    def test_the_cookie_keeps_its_other_protections(self):
        cookie = self._cookie_for(scheme="https")
        self.assertIn("HttpOnly", cookie)
        self.assertIn("samesite=strict", cookie.lower())


class FileBrowserLogPathTests(unittest.TestCase):
    """The FileBrowser log must not live in a world-writable directory.

    It was ``/tmp/filebrowser-hub.log``.  /tmp is world-writable and sticky, so
    any other local account could pre-create that name as a symlink and have
    ServerHub append the child process's output into a file of the attacker's
    choosing, running as the panel user.
    """

    def test_the_log_is_not_in_a_shared_temp_directory(self):
        self.assertFalse(
            str(files_svc.FB_LOG).startswith("/tmp/"),
            f"{files_svc.FB_LOG} is in a world-writable directory",
        )
        self.assertFalse(str(files_svc.FB_LOG).startswith("/var/tmp/"))

    def test_the_log_lives_under_the_users_own_home(self):
        self.assertTrue(
            str(files_svc.FB_LOG).startswith(str(Path.home())),
            f"{files_svc.FB_LOG} should be inside the user's home",
        )

    def test_the_source_no_longer_references_the_shared_temp_path(self):
        source = (BASE / "hub" / "files_svc.py").read_text()
        self.assertNotIn("/tmp/filebrowser", source)

    def test_the_log_is_opened_without_following_symlinks(self):
        source = (BASE / "hub" / "files_svc.py").read_text()
        self.assertIn(
            "O_NOFOLLOW",
            source,
            "opening the log must refuse a symlink planted at that exact path",
        )

    def test_a_symlink_at_the_log_path_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            victim = Path(tmp) / "victim"
            victim.write_text("original\n")
            planted = Path(tmp) / "planted.log"
            planted.symlink_to(victim)
            with self.assertRaises(OSError):
                os.close(os.open(
                    planted,
                    os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW,
                    0o600,
                ))
            self.assertEqual(
                victim.read_text(),
                "original\n",
                "the symlink target must be left untouched",
            )


class BackupPrivacyTests(unittest.TestCase):
    """Backups carry the same secrets as the files they copy.

    ``backup_configs`` archives services.yaml verbatim -- the admin password
    hash and any tunnel tokens -- and it landed at the umask default (0644) in a
    traversable directory, handing every other local account the exact secrets
    the 0600 original protects.
    """

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="serverhub-backup-test-"))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_the_backup_directory_is_not_listable_by_other_users(self):
        self.assertEqual(
            mode_of(Path(backups.BACKUP_ROOT)),
            0o700,
            "the backup directory holds credential-bearing archives",
        )

    def test_a_destination_is_private_before_the_tool_writes_to_it(self):
        # umask forced open and chmod suppressed: only the creation mode counts.
        # tar and pg_dump open the output O_CREAT|O_TRUNC, which keeps the mode
        # of an existing file, so creating it 0600 first is what makes the
        # archive private for its whole lifetime rather than after the fact.
        dest = self.tmp / "configs.tgz"
        old_umask = os.umask(0)
        try:
            with mock.patch("os.chmod"):
                backups._private_dest(dest)
        finally:
            os.umask(old_umask)
        self.assertEqual(mode_of(dest), 0o600)

    def test_an_existing_world_readable_destination_is_tightened(self):
        dest = self.tmp / "stale.tgz"
        dest.write_text("old")
        os.chmod(dest, 0o644)
        backups._private_dest(dest)
        self.assertEqual(mode_of(dest), 0o600)

    def test_success_is_judged_by_content_not_by_existence(self):
        # _private_dest pre-creates the file, so dest.exists() is always true
        # afterwards; an empty placeholder must not read as a successful backup.
        dest = self.tmp / "empty.tgz"
        backups._private_dest(dest)
        self.assertTrue(dest.exists())
        self.assertEqual(backups._written_bytes(dest), 0)

    def test_a_failed_run_leaves_no_placeholder_behind(self):
        dest = self.tmp / "discarded.tgz"
        backups._private_dest(dest)
        backups._discard(dest)
        self.assertFalse(dest.exists())

    def test_written_bytes_reports_zero_for_a_missing_file(self):
        self.assertEqual(backups._written_bytes(self.tmp / "absent.tgz"), 0)


class BookmarkProbeTests(unittest.TestCase):
    """A reachability probe must only speak HTTP, and must verify public TLS.

    ``urlopen`` also handles file:, ftp: and data:.  Bookmark URLs are not all
    typed by the operator -- some are derived from container labels and VM
    metadata discovered at runtime -- so an unrestricted probe could be made to
    read a local file and report its status through the dashboard.
    """

    def test_non_http_schemes_are_refused_without_being_opened(self):
        for url in (
            "file:///etc/passwd",
            "ftp://example.com/x",
            "data:text/plain,hello",
            "gopher://example.com",
            "",
        ):
            with self.subTest(url=url):
                # Any attempt to open it at all is a failure, so make opening fatal.
                with mock.patch.object(
                    urllib.request, "build_opener", side_effect=AssertionError("opened")
                ):
                    result = bookmarks_svc._probe(url)
                self.assertFalse(result["ok"])
                self.assertIn("unsupported scheme", result["error"])

    def test_loopback_and_private_hosts_are_treated_as_lan(self):
        for host in (
            "localhost", "127.0.0.1", "::1", "192.168.1.10", "10.1.2.3",
            "172.16.5.6", "169.254.169.254", "nas.local", "box.lan",
            "host.internal", "bare-name",
        ):
            with self.subTest(host=host):
                self.assertTrue(bookmarks_svc._is_private_host(host))

    def test_public_hosts_are_not_treated_as_lan(self):
        for host in (
            "example.com", "sub.example.co.uk", "8.8.8.8", "1.1.1.1",
            "myserver.duckdns.org",
        ):
            with self.subTest(host=host):
                self.assertFalse(bookmarks_svc._is_private_host(host))

    def test_the_lan_decision_never_consults_dns(self):
        """A resolver is not a trustworthy input for a security decision.

        Split-horizon DNS and fake-IP proxies such as Clash or Surge map every
        public name into a private-looking range -- 198.18.0.0/15 on the machine
        this was found on -- which would silently disable certificate
        verification for the entire internet.
        """
        def explode(*a, **kw):
            raise AssertionError("_is_private_host must not resolve DNS")

        with mock.patch.object(socket, "getaddrinfo", explode):
            self.assertFalse(bookmarks_svc._is_private_host("example.com"))
            self.assertTrue(bookmarks_svc._is_private_host("192.168.0.2"))

    def test_a_redirect_out_of_http_is_not_followed(self):
        handler = bookmarks_svc._SchemeSafeRedirects()
        req = urllib.request.Request("http://127.0.0.1/")
        for target in ("file:///etc/passwd", "ftp://example.com/x", "data:text/html,x"):
            with self.subTest(target=target):
                self.assertIsNone(
                    handler.redirect_request(req, None, 302, "Found", {}, target),
                    f"a 302 to {target} must not be followed",
                )

    def test_a_redirect_within_http_is_still_followed(self):
        handler = bookmarks_svc._SchemeSafeRedirects()
        req = urllib.request.Request("http://127.0.0.1/a")
        self.assertIsNotNone(
            handler.redirect_request(req, None, 302, "Found", {}, "http://127.0.0.1/b")
        )

    def test_the_scheme_allowlist_is_exactly_http_and_https(self):
        self.assertEqual(set(bookmarks_svc._ALLOWED_SCHEMES), {"http", "https"})


class CloudflaredPlistTests(unittest.TestCase):
    """The LaunchAgent plist must be serialised, not string-formatted.

    The hand-built XML template escaped none of its interpolated values.  A path
    containing ``&``, ``<`` or ``"`` produced either a plist launchd silently
    refuses, or -- given a value that ever becomes attacker-influenced -- extra
    ``<string>`` elements inside ProgramArguments, which is command execution at
    login.
    """

    def _write(self, bin_path: str, extra: list[str]) -> dict:
        tmp = Path(tempfile.mkdtemp(prefix="serverhub-plist-test-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        token_file = tmp / "tunnel.token"
        token_file.write_text("t" * 64)
        with (
            mock.patch.object(cloudflared_svc, "PLIST", tmp / "agent.plist"),
            mock.patch.object(cloudflared_svc, "TOKEN_FILE", token_file),
            mock.patch.object(cloudflared_svc, "_ensure_dirs", lambda: None),
            mock.patch.object(cloudflared_svc, "_bin", lambda: bin_path),
            mock.patch.object(
                cloudflared_svc, "_edge_workaround_args", lambda: extra
            ),
        ):
            written = cloudflared_svc._write_launchagent_token()
        return plistlib.loads(written.read_bytes())

    def test_xml_metacharacters_stay_inside_one_argument(self):
        hostile = '/bin/cloudflared" /><key>RunAtLoad</key><string>injected'
        parsed = self._write(hostile, [])
        self.assertEqual(parsed["ProgramArguments"][0], hostile)
        self.assertIs(parsed["RunAtLoad"], True)

    def test_an_ampersand_in_a_path_does_not_corrupt_the_plist(self):
        parsed = self._write("/opt/a&b/cloudflared", [])
        self.assertEqual(parsed["ProgramArguments"][0], "/opt/a&b/cloudflared")

    def test_the_argument_order_cloudflared_requires_is_preserved(self):
        parsed = self._write("/bin/cloudflared", ["--edge-ip-version", "4"])
        argv = parsed["ProgramArguments"]
        # --edge must precede the `run` subcommand or cloudflared exits and, under
        # KeepAlive, respawns forever.
        self.assertEqual(argv[:5], [
            "/bin/cloudflared", "tunnel", "--no-autoupdate",
            "--edge-ip-version", "4",
        ])
        self.assertEqual(argv[5:7], ["run", "--token-file"])

    def test_the_agent_keeps_its_launchd_settings(self):
        parsed = self._write("/bin/cloudflared", [])
        self.assertEqual(parsed["Label"], cloudflared_svc.LABEL)
        self.assertIs(parsed["KeepAlive"], True)
        self.assertIs(parsed["RunAtLoad"], True)
        self.assertIn("PATH", parsed["EnvironmentVariables"])

    def test_the_writer_does_not_hand_build_xml(self):
        source = (BASE / "hub" / "cloudflared_svc.py").read_text()
        self.assertNotIn(
            "<key>Label</key>",
            source,
            "plists must go through plistlib, which escapes by construction",
        )


class LegacyIndexEscapingTests(unittest.TestCase):
    """The fallback UI must not build executable markup from API values.

    ``esc()`` did not escape the single quote, and the values were interpolated
    into single-quoted JS string literals inside ``onclick`` attributes.  HTML
    entity escaping cannot secure that position: the HTML parser decodes
    entities *before* the JS parser runs, so an escaped quote still terminated
    the string literal and everything after it executed.
    """

    @classmethod
    def setUpClass(cls):
        cls.html = (BASE / "index.html").read_text()
        cls.script = re.search(r"<script>([\s\S]*?)</script>", cls.html).group(1)

    def test_esc_escapes_the_characters_that_break_out_of_attributes(self):
        start = self.script.index("function esc(s)")
        # The function body spans the replace chain up to its closing brace.
        body = self.script[start:self.script.index("}", start) + 1]
        for char, entity in (("&", "&amp;"), ("<", "&lt;"), (">", "&gt;"),
                             ('"', "&quot;"), ("'", "&#39;")):
            with self.subTest(char=char):
                self.assertIn(entity, body, f"esc() must escape {char!r}")

    def test_no_inline_handler_interpolates_an_api_value(self):
        # (?<![-\w]) so "data-confirm=" does not match as an "onfirm=" handler.
        offenders = re.findall(r'(?<![-\w])on\w+\s*=\s*"[^"]*\$\{', self.script)
        self.assertEqual(
            offenders,
            [],
            "an inline event handler is being built from interpolated data; "
            "HTML escaping does not protect that position -- use a data-* "
            "attribute and a delegated listener instead",
        )

    def test_the_action_buttons_use_delegated_listeners(self):
        self.assertIn("data-role=", self.script)
        self.assertIn("addEventListener(\"click\"", self.script)

    def test_hrefs_go_through_a_scheme_check(self):
        """esc() cannot stop "javascript:", which executes on click.

        The value may be checked one line earlier (``const url=safeUrl(s.url)``),
        so this follows the interpolated identifier back to its assignment rather
        than demanding the call appear inline.
        """
        hrefs = re.findall(r'href="\$\{([^}]*)\}"', self.script)
        self.assertTrue(hrefs, "no interpolated href found -- has the UI changed?")
        for expr in hrefs:
            with self.subTest(expr=expr):
                if "safeUrl" in expr:
                    continue
                names = [n for n in re.findall(r"[A-Za-z_$][\w$]*", expr)
                         if n not in {"esc"}]
                checked = any(
                    re.search(rf"\b{re.escape(n)}\s*=\s*safeUrl\(", self.script)
                    for n in names
                )
                self.assertTrue(
                    checked,
                    f"href interpolates {expr!r}, which does not come from "
                    "safeUrl() -- a javascript: URL would execute on click",
                )

    def test_no_href_interpolates_a_raw_url_property(self):
        raw = [e for e in re.findall(r'href="\$\{([^}]*)\}"', self.script)
               if re.search(r"\.\s*url\b", e) and "safeUrl" not in e]
        self.assertEqual(
            raw,
            [],
            "an href is built straight from an API url property: " + ", ".join(raw),
        )

    def test_the_system_stats_block_escapes_every_value(self):
        block = re.search(r'\$\("sys"\)\.innerHTML=([\s\S]*?);\n', self.script)
        self.assertIsNotNone(block, "the system stats assignment was not found")
        raw = []
        for expr in re.findall(r"\$\{([^}]*)\}", block.group(1)):
            if not re.search(r"\b(esc|num|pct)\(", expr):
                raw.append(expr)
        self.assertEqual(
            raw,
            [],
            "these values reach innerHTML unescaped: " + ", ".join(raw),
        )

    def test_maintenance_ids_are_encoded_into_the_url(self):
        for call in re.findall(r"/api/maintenance/\$\{([^}]*)\}", self.script):
            with self.subTest(expr=call):
                self.assertIn("encodeURIComponent", call)


class ContentSecurityPolicyTests(unittest.TestCase):
    """The SPA's protection against `javascript:` URLs is the CSP, nothing else.

    Vue does not sanitize `:href`.  The SPA binds it straight to server-supplied
    URLs in ~18 places -- bookmarks, service links, container WebUI links, share
    and VNC URLs -- and those values come from services.yaml and from Docker
    labels discovered at runtime, not from a trusted constant.  A `javascript:`
    URL there would execute on click.

    What stops it is `script-src 'self'` with no `unsafe-inline`: per CSP,
    `javascript:` URLs are governed by script-src and are refused without
    `unsafe-inline`.  So adding `unsafe-inline` to script-src would not merely
    "allow inline scripts" -- it would turn every one of those bindings into a
    live XSS sink.  That consequence is not visible at the line where someone
    would make the change, which is why it is pinned here.

    The legacy fallback UI does not rely on this; index.html sanitizes URLs
    itself via safeUrl(), because it must also work if the header is ever lost.
    """

    @classmethod
    def setUpClass(cls):
        from fastapi.testclient import TestClient

        from hub.app_factory import create_app

        response = TestClient(create_app()).get("/api/auth/status")
        cls.csp = response.headers.get("content-security-policy", "")
        cls.headers = response.headers

    def _directive(self, name: str) -> str:
        match = re.search(rf"(?:^|;)\s*{re.escape(name)}\s([^;]*)", self.csp)
        return match.group(1).strip() if match else ""

    def test_a_policy_is_sent_at_all(self):
        self.assertTrue(self.csp, "no Content-Security-Policy header was sent")

    def test_script_src_forbids_inline(self):
        script_src = self._directive("script-src")
        self.assertEqual(script_src, "'self'", f"script-src is {script_src!r}")
        self.assertNotIn(
            "unsafe-inline",
            script_src,
            "unsafe-inline in script-src re-enables javascript: URLs, and the "
            "SPA binds :href directly to URLs from config and Docker labels",
        )
        self.assertNotIn("unsafe-eval", script_src)

    def test_the_other_containment_directives_hold(self):
        self.assertEqual(self._directive("object-src"), "'none'")
        self.assertEqual(self._directive("base-uri"), "'none'")
        self.assertEqual(self._directive("frame-ancestors"), "'none'")
        self.assertEqual(self._directive("default-src"), "'self'")

    def test_the_defensive_headers_are_present(self):
        self.assertEqual(self.headers.get("x-content-type-options"), "nosniff")
        self.assertEqual(self.headers.get("x-frame-options"), "DENY")

    def test_the_spa_really_does_bind_href_to_server_data(self):
        """Keeps the docstring above honest.

        If the SPA ever sanitizes these itself, this test should be updated
        deliberately rather than the CSP reliance quietly becoming stale.
        """
        web = BASE / "web" / "src"
        if not web.is_dir():
            self.skipTest("SPA sources not present")
        bindings = 0
        for vue in web.rglob("*.vue"):
            bindings += len(re.findall(r':href="', vue.read_text()))
        self.assertGreater(
            bindings,
            5,
            "expected the SPA to bind :href to data in several places; if that "
            "is no longer true, revisit whether the CSP is still load-bearing",
        )

    def test_the_only_v_html_is_a_locally_generated_qr_code(self):
        """v-html is safe here only because the value is machine-generated.

        qrcode-generator's createSvgTag emits <svg>/<rect>/<path> from encoded
        modules and never interpolates the payload as markup, so a hostile peer
        config cannot become elements.  Any *other* v-html would not have that
        property.
        """
        web = BASE / "web" / "src"
        if not web.is_dir():
            self.skipTest("SPA sources not present")
        sinks = []
        for vue in web.rglob("*.vue"):
            for line in vue.read_text().splitlines():
                if "v-html" in line:
                    sinks.append(f"{vue.relative_to(web)}: {line.strip()}")
        self.assertEqual(
            len(sinks),
            1,
            "a new v-html appeared; each one needs its own argument for why the "
            "value cannot contain markup:\n" + "\n".join(sinks),
        )
        self.assertIn("qrSvg", sinks[0], sinks[0])


class DiscoveryHostileInputTests(unittest.TestCase):
    """Discovery parses attacker-influenceable text, so it must not crash.

    ``docker ps --format`` output ends with a *label*, which is an arbitrary
    string.  The parse split on every tab and then unpacked four names, so a
    label containing a tab produced five fields and raised ValueError -- uncaught,
    out of ``discover_containers()`` and into ``/api/status``.  One crafted
    ``docker run --label`` took the dashboard down for every user.
    """

    def setUp(self):
        from hub.discovery import apps, containers

        self.apps = apps
        self.containers = containers
        self.addCleanup(containers.invalidate_containers)

    def _discover(self, docker_output: str):
        self.containers.invalidate_containers()
        with mock.patch.object(
            self.containers, "sh", return_value=(0, docker_output, "")
        ):
            return self.containers.discover_containers(force=True)

    def test_a_tab_in_a_label_does_not_raise(self):
        items, _ = self._discover("web\trunning\tUp 2 hours\tproj\tINJECTED")
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["id"], "web")

    def test_many_tabs_in_a_label_do_not_raise(self):
        items, _ = self._discover("web\trunning\tUp 2 hours\ta\tb\tc\td")
        self.assertEqual(len(items), 1)
        self.assertIsInstance(items[0]["group"], str)

    def test_a_short_line_is_skipped_not_fatal(self):
        items, _ = self._discover("web\trunning")
        self.assertEqual(items, [])

    def test_normal_output_still_parses_correctly(self):
        items, engine_up = self._discover(
            "web\trunning\tUp 2 hours (healthy)\tteslamate\n"
            "db\texited\tExited (0) 3 days ago\tteslamate\n"
            "solo\trunning\tUp 5 minutes\t"
        )
        self.assertTrue(engine_up)
        self.assertEqual({i["id"] for i in items}, {"web", "db", "solo"})
        states = {i["id"]: i["state"] for i in items}
        self.assertEqual(states["web"], "ok")
        self.assertEqual(states["db"], "stopped")

    def test_an_unhealthy_container_is_still_flagged(self):
        items, _ = self._discover("web\trunning\tUp 1 hour (unhealthy)\tp")
        self.assertEqual(items[0]["state"], "warn")

    def test_an_option_shaped_process_name_never_reaches_pgrep(self):
        """`process` is a bare positional, so "-f" would be a pgrep flag."""
        calls = []

        def fake_sh(argv, **kw):
            calls.append(argv)
            return (1, "", "")

        config = {"apps": [
            {"id": "good", "process": "syncthing"},
            {"id": "opt", "process": "-f"},
            {"id": "opt2", "process": "--help"},
            {"id": "missing"},
            {"id": "blank", "process": "   "},
        ]}
        with (
            mock.patch.object(self.apps, "sh", fake_sh),
            mock.patch.object(self.apps, "cfg", lambda: config),
            mock.patch.object(self.apps, "port_open", lambda p: None),
        ):
            items = self.apps.collect_apps(engine_up=True)

        patterns = [argv[2] for argv in calls if len(argv) > 2]
        self.assertIn("syncthing", patterns)
        self.assertNotIn("-f", patterns)
        self.assertNotIn("--help", patterns)
        self.assertEqual(
            [i["id"] for i in items],
            ["good"],
            "an entry with an unusable process name must be skipped, not listed",
        )

    def test_an_app_entry_without_a_process_key_does_not_raise(self):
        # This used to be a KeyError, which took the whole status response down.
        with (
            mock.patch.object(self.apps, "sh", lambda *a, **k: (1, "", "")),
            mock.patch.object(self.apps, "cfg", lambda: {"apps": [{"id": "x"}]}),
            mock.patch.object(self.apps, "port_open", lambda p: None),
        ):
            self.assertEqual(self.apps.collect_apps(engine_up=True), [])


class ComposeFilePrivacyTests(unittest.TestCase):
    """A compose file carries the stack's generated credentials.

    ``secure_io``'s own docstring names this payload -- "generated database and
    admin passwords inside compose files" -- yet ``compose_svc`` wrote them with
    ``write_text()`` and chmod'ed afterwards, so the compose file, its ``.bak``
    and the temp file it was renamed from were each created at the umask default
    (0644 here) and only then tightened.  A local process only has to win that
    window once, and a password cannot be un-leaked.
    """

    def setUp(self):
        from hub import compose_svc

        self.svc = compose_svc
        self.tmp = Path(tempfile.mkdtemp(prefix="serverhub-compose-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.stack = self.tmp / "Services" / "demo"
        self.stack.mkdir(parents=True)
        self.compose = self.stack / "docker-compose.yml"

    def _save(self, content, *, existing=None, suppress_chmod=False):
        if existing is not None:
            self.compose.write_text(existing)
            os.chmod(self.compose, 0o600)
        patches = [
            mock.patch.object(
                self.svc, "_find_stack",
                lambda sid: {"id": "demo", "compose_path": str(self.compose),
                             "path": str(self.stack), "name": "demo"},
            ),
            # Not about compose syntax, and docker need not be installed.
            mock.patch.object(self.svc, "validate_compose_text",
                              lambda *a, **k: {"ok": True}),
            mock.patch.object(self.svc, "inv", lambda: None),
            mock.patch.object(Path, "home", staticmethod(lambda: self.tmp)),
        ]
        if suppress_chmod:
            patches += [mock.patch("os.chmod"), mock.patch.object(Path, "chmod")]
        old_umask = os.umask(0) if suppress_chmod else None
        for p in patches:
            p.start()
        try:
            return self.svc.save_compose("demo", content)
        finally:
            for p in reversed(patches):
                p.stop()
            if old_umask is not None:
                os.umask(old_umask)

    SECRET = (
        "services:\n  db:\n    image: postgres:17\n"
        "    environment:\n      POSTGRES_PASSWORD: generated-secret\n"
    )

    def test_the_compose_file_is_private_at_creation(self):
        # chmod suppressed and umask open: only the creation mode survives, which
        # is exactly the state a concurrent reader would have found.
        self._save(self.SECRET, suppress_chmod=True)
        self.assertEqual(mode_of(self.compose), 0o600)

    def test_the_backup_is_private_at_creation(self):
        self._save(self.SECRET, existing="services: {}\n", suppress_chmod=True)
        backup = self.compose.with_suffix(self.compose.suffix + ".bak")
        self.assertTrue(backup.exists())
        self.assertEqual(mode_of(backup), 0o600)

    def test_the_new_content_lands_and_the_backup_keeps_the_old(self):
        old = "services:\n  db:\n    image: postgres:16\n"
        self._save(self.SECRET, existing=old)
        self.assertEqual(self.compose.read_text(), self.SECRET)
        backup = self.compose.with_suffix(self.compose.suffix + ".bak")
        self.assertEqual(backup.read_text(), old)

    def test_no_temp_file_is_left_behind(self):
        self._save(self.SECRET, existing="services: {}\n")
        leftovers = [p.name for p in self.stack.iterdir() if p.name.endswith(".tmp")]
        self.assertEqual(leftovers, [], f"leftover temp file: {leftovers}")

    def test_a_compose_path_outside_services_is_refused(self):
        outside = self.tmp / "elsewhere" / "docker-compose.yml"
        outside.parent.mkdir(parents=True)
        outside.write_text("services: {}\n")
        with (
            mock.patch.object(
                self.svc, "_find_stack",
                lambda sid: {"id": "x", "compose_path": str(outside),
                             "path": str(outside.parent)},
            ),
            mock.patch.object(self.svc, "validate_compose_text",
                              lambda *a, **k: {"ok": True}),
            mock.patch.object(Path, "home", staticmethod(lambda: self.tmp)),
        ):
            with self.assertRaises(Exception) as raised:
                self.svc.save_compose("x", self.SECRET)
        self.assertEqual(getattr(raised.exception, "status_code", None), 403)
        self.assertEqual(
            outside.read_text(),
            "services: {}\n",
            "a refused save must not have written anything",
        )


class AuditRedactionTests(unittest.TestCase):
    """Key material must be dropped by the redactor, not by caller discipline.

    ``hub/audit.py`` states that redaction is applied by key name inside
    ``record()`` precisely so no caller has to remember -- but the hint list had
    no entry for key material, so ``private_key``, ``psk`` and
    ``preshared_key`` were written verbatim.  WireGuard peer events are audited
    and a peer's private key *is* the credential, so the safety net was missing
    exactly where it mattered most.  No caller was actually leaking (they pass
    only the public half by hand), which is the situation this closes.
    """

    def setUp(self):
        from hub import audit

        self.audit = audit

    def test_key_material_is_redacted(self):
        for field in (
            "private_key", "privatekey", "psk", "preshared_key", "presharedkey",
            "wg_key", "signing_key", "passphrase", "seed", "bearer", "key",
            "password", "current_password", "setup_token", "session", "cookie",
        ):
            with self.subTest(field=field):
                self.assertTrue(
                    self.audit._is_secret_key(field), f"{field} is not redacted"
                )

    def test_the_public_half_of_a_keypair_is_kept(self):
        """pubkey is how the operator identifies a peer; dropping it blinds the trail."""
        for field in ("pubkey", "public_key", "publickey", "peer_pubkey"):
            with self.subTest(field=field):
                self.assertFalse(self.audit._is_secret_key(field))

    def test_ordinary_fields_are_kept(self):
        for field in (
            "username", "client", "ip", "name", "device", "mount", "volume",
            "action", "outcome", "reason", "mode", "op", "count", "kind",
            "enabled", "created", "prefix", "urgency", "batch", "imported",
        ):
            with self.subTest(field=field):
                self.assertFalse(
                    self.audit._is_secret_key(field),
                    f"{field} is a legitimate audit field and must survive",
                )

    def test_redaction_reaches_nested_structures(self):
        got = self.audit.redact(
            {"peer": {"pubkey": "PUB", "private_key": "PRIV", "psk": "PSK"},
             "peers": [{"psk": "x", "name": "phone"}],
             "ok": True}
        )
        self.assertEqual(
            got,
            {"peer": {"pubkey": "PUB"}, "peers": [{"name": "phone"}], "ok": True},
        )

    def test_every_audit_call_site_field_survives_redaction(self):
        """The redactor must not silently start dropping a real audit field."""
        source = "\n".join(
            p.read_text() for p in (BASE / "hub").rglob("*.py")
        )
        used = set()
        for call in re.finditer(r"audit\.record\((.*?)\)\n", source, re.S):
            used.update(re.findall(r"(\w+)\s*=", call.group(1)))
        dropped = sorted(f for f in used if self.audit._is_secret_key(f))
        self.assertEqual(
            dropped,
            [],
            "these fields are passed to audit.record but would be redacted, so "
            "the event would lose them: " + ", ".join(dropped),
        )


class PinnedBinaryResolutionTests(unittest.TestCase):
    """A "pinned" copy is only worth using if it is genuinely root-owned.

    The sudoers policy names /usr/local/libexec/serverhub/<tool>, so if that path
    were ever writable by the panel account, trusting it would be *worse* than
    not pinning at all: the rule would point straight at a file the attacker
    controls, with the argument narrowing lending it false credibility.
    ``pinned_or`` therefore verifies ownership instead of assuming it.
    """

    def setUp(self):
        from hub import paths

        self.paths = paths
        self.tmp = Path(tempfile.mkdtemp(prefix="serverhub-pin-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def _resolve(self, name, fallback="/opt/homebrew/bin/tool"):
        with mock.patch.object(self.paths, "PINNED_BIN_DIR", self.tmp):
            return self.paths.pinned_or(name, fallback)

    def test_a_missing_copy_falls_back(self):
        self.assertEqual(self._resolve("absent"), "/opt/homebrew/bin/tool")

    def test_a_copy_this_account_owns_is_refused(self):
        """The decisive case: a file we can rewrite must never be trusted."""
        tool = self.tmp / "smartctl"
        tool.write_text("#!/bin/sh\necho pwned\n")
        os.chmod(tool, 0o755)
        self.assertEqual(
            self._resolve("smartctl"),
            "/opt/homebrew/bin/tool",
            "a pinned path owned by this account was trusted; the sudoers rule "
            "names that path, so trusting it hands over passwordless root",
        )

    def test_a_non_executable_copy_is_refused(self):
        tool = self.tmp / "smartctl"
        tool.write_text("")
        os.chmod(tool, 0o644)
        self.assertEqual(self._resolve("smartctl"), "/opt/homebrew/bin/tool")

    def test_ownership_is_checked_not_assumed(self):
        tool = self.tmp / "tool"
        tool.write_text("x")
        self.assertFalse(
            self.paths._is_root_owned(tool),
            "_is_root_owned must reject a file owned by this account",
        )
        # A real root-owned system binary, as the positive control.
        self.assertTrue(self.paths._is_root_owned(Path("/bin/sh")))

    def test_a_group_or_world_writable_root_file_is_refused(self):
        # Root-owned is not sufficient: 0777 root:wheel is still anyone's to edit.
        self.assertFalse(
            self.paths._is_root_owned(Path("/tmp")),
            "/tmp is root-owned but world-writable, so it must not read as pinned",
        )

    def test_the_policy_and_the_code_name_the_same_directory(self):
        """If these drift, sudo authorises one file and the panel runs another."""
        from hub import sudoers_policy

        self.assertEqual(
            str(self.paths.PINNED_BIN_DIR),
            str(sudoers_policy.PINNED_BIN_DIR),
            "hub.paths and hub.sudoers_policy disagree on the pinned directory, "
            "so every privileged call would silently need a password",
        )

    def test_the_policy_forbids_the_unpinned_homebrew_paths(self):
        from hub import sudoers_policy

        for path in ("/opt/homebrew/bin/smartctl", "/opt/homebrew/bin/wg"):
            self.assertIn(
                path,
                sudoers_policy.UNPINNED_EQUIVALENTS,
                f"{path} must stay on the forbidden list; granting it again is "
                "the escalation the pinning exists to close",
            )


class SudoersSwappableBinaryTests(unittest.TestCase):
    """Pinning a rule's arguments is worthless if the program can be replaced.

    A NOPASSWD rule naming a binary the granting account can rewrite is
    passwordless root however precisely the argument list is spelled: overwrite
    the file, run the rule, and the argument regex authorises your own code.

    On Apple Silicon this is the default state of everything under
    /opt/homebrew -- brew chowns its prefix to the installing user -- so rules
    naming smartctl, wg, wg-quick or bash look pinned and are not.  ``visudo -cf``
    checks grammar and verify-sudoers checks whether a rule can *match*; neither
    can see this.

    Writability is injected here rather than probed, so the tests are
    deterministic and say nothing about the machine they run on.
    """

    def setUp(self):
        from hub import sudoers_policy

        self.policy = sudoers_policy

    def test_the_binary_is_the_executed_path(self):
        self.assertEqual(
            self.policy.executed_paths("/usr/bin/pmset ^-a womp [0-9]+$"),
            ["/usr/bin/pmset"],
        )

    def test_an_interpreters_script_argument_is_also_executed(self):
        # Two replaceable files, not one: bash runs wg-quick.
        self.assertEqual(
            self.policy.executed_paths(
                "/opt/homebrew/bin/bash /opt/homebrew/bin/wg-quick up /etc/wg0.conf"
            ),
            ["/opt/homebrew/bin/bash", "/opt/homebrew/bin/wg-quick"],
        )

    def test_a_non_interpreter_does_not_absorb_its_path_argument(self):
        rule = "/opt/homebrew/bin/wg syncconf wg0 /tmp/wg0.sync.conf"
        self.assertEqual(self.policy.executed_paths(rule), ["/opt/homebrew/bin/wg"])
        self.assertEqual(self.policy.path_arguments(rule), ["/tmp/wg0.sync.conf"])

    def test_a_regex_argument_list_is_not_read_as_paths(self):
        # "/dev/[A-Za-z0-9]+" is a pattern, not a file that could be writable.
        self.assertEqual(
            self.policy.path_arguments(
                "/opt/homebrew/bin/smartctl ^-a /dev/[A-Za-z0-9]+$"
            ),
            [],
        )

    def test_a_writable_binary_is_reported(self):
        rules = [
            "/opt/homebrew/bin/smartctl -V",
            "/usr/bin/pmset ^-a womp [0-9]+$",
        ]
        found = self.policy.swappable_rules(
            rules, writable=lambda p: p.startswith("/opt/homebrew/")
        )
        self.assertEqual(
            [rule for rule, _ in found], ["/opt/homebrew/bin/smartctl -V"]
        )
        self.assertEqual(found[0][1], ["/opt/homebrew/bin/smartctl"])

    def test_root_owned_binaries_are_not_reported(self):
        rules = [
            "/usr/bin/pmset ^-a womp [0-9]+$",
            "/sbin/shutdown -h now",
            "/bin/launchctl print system/com.wireguard.wg0",
        ]
        self.assertEqual(self.policy.swappable_rules(rules, writable=lambda p: False), [])

    def test_a_writable_config_argument_is_reported_separately(self):
        """wg-quick executes PostUp from its config, so this is a root code path.

        It is reported apart from the executed set because the consequence
        depends on the program, and because it survives making every binary
        immutable -- the panel has to be able to write the config it generates.
        """
        rule = (
            "/opt/homebrew/bin/bash /opt/homebrew/bin/wg-quick up "
            "/opt/homebrew/etc/wireguard/wg0.conf"
        )
        found = self.policy.writable_argument_rules(
            [rule], writable=lambda p: p.endswith("wg0.conf")
        )
        self.assertEqual(found, [(rule, ["/opt/homebrew/etc/wireguard/wg0.conf"])])

    def test_a_readonly_file_in_a_writable_directory_is_not_pinned(self):
        """Unlink and replace needs only the directory, not the file."""
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "tool"
            target.write_text("#!/bin/sh\n")
            # Read-only file, writable parent. No chmod back: TemporaryDirectory
            # removes it either way, and a cleanup hook would run after the
            # directory is already gone.
            os.chmod(target, 0o555)
            self.assertTrue(
                self.policy.user_writable(str(target)),
                "a read-only file inside a writable directory can still be "
                "swapped, so it must not count as pinned",
            )

    def test_a_symlink_to_a_writable_target_is_not_pinned(self):
        with tempfile.TemporaryDirectory() as tmp:
            real = Path(tmp) / "real"
            real.write_text("#!/bin/sh\n")
            link = Path(tmp) / "link"
            link.symlink_to(real)
            self.assertTrue(self.policy.user_writable(str(link)))

    def test_a_root_owned_system_binary_reads_as_pinned(self):
        # /usr/bin/pmset is root:wheel inside root-owned directories on every
        # supported macOS, so this also proves the probe is not simply true.
        self.assertFalse(self.policy.user_writable("/usr/bin/pmset"))

    def test_the_verifier_treats_a_swappable_rule_as_a_failure(self):
        source = (BASE / "deploy" / "verify-sudoers.py").read_text()
        self.assertIn("swappable_rules", source)
        self.assertIn(
            "problems.append",
            source.split("swappable_rules(rules)")[1][:400],
            "a swappable binary must count as a policy failure, not a warning",
        )


if __name__ == "__main__":
    unittest.main()
