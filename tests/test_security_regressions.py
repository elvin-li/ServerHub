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


if __name__ == "__main__":
    unittest.main()
