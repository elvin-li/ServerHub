"""No user-supplied value may reach argv where a CLI would read it as an option.

Every subprocess call in this codebase already uses list argv, so there is no
shell-metacharacter injection to worry about.  The remaining hole is narrower and
easier to miss: a value that merely *starts with a hyphen* is parsed as a flag by
the program being run, even though it occupies a positional slot.

The consequences are concrete, not theoretical:

  * ``docker stop --all`` stops every container instead of the requested one.
  * ``brew services stop --all`` stops every Homebrew service on the host.
  * ``networksetup -setdnsservers <svc> -foo`` feeds an option to a privileged
    network tool.
  * ``dig -f /etc/passwd`` turns a DNS lookup endpoint into a file-read
    primitive, because the output is returned to the caller.

Three validators admitted such values before this file existed: a character
class containing ``-`` with no anchor on the first character, an ``int()``-based
IP check that accepts ``-0`` because ``0 <= -0 <= 255``, and a blocklist that
enumerates bad characters instead of allowing only good ones.

These tests assert on the *validator*, not on a live subprocess, so they run
without docker/brew/networksetup present and without mutating the host.
"""
from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from fastapi import HTTPException  # noqa: E402

from hub import cli_args  # noqa: E402

# Values a CLI would read as options rather than as the positional it replaced.
OPTION_LIKE = [
    "--all",
    "-a",
    "--force",
    "-f",
    "--rm",
    "-rf",
    "--file=/tmp/evil",
    "-",
]


class SafeArgHelperTests(unittest.TestCase):
    """The shared guard the call sites are converted onto."""

    def test_rejects_every_option_like_value(self):
        for value in OPTION_LIKE:
            with self.subTest(value=value):
                self.assertFalse(
                    cli_args.is_safe_positional(value),
                    f"{value!r} would be parsed as an option, not a positional",
                )

    def test_accepts_ordinary_names(self):
        for value in ["nginx", "immich_server", "my-app.1", "postgres@14", "a"]:
            with self.subTest(value=value):
                self.assertTrue(
                    cli_args.is_safe_positional(value),
                    f"{value!r} is a legitimate name and must not be rejected",
                )

    def test_rejects_control_characters_and_nulls(self):
        # A trailing newline slips past a `$`-anchored regex, which is how
        # disk_power_svc's DISK_RE could match "disk0\n".
        for value in ["nginx\n", "nginx\r\n", "ng\x00inx", "a\nb"]:
            with self.subTest(value=value):
                self.assertFalse(cli_args.is_safe_positional(value))

    def test_rejects_empty_and_whitespace(self):
        for value in ["", "   ", None]:
            with self.subTest(value=value):
                self.assertFalse(cli_args.is_safe_positional(value))

    def test_require_positional_raises_http_400(self):
        with self.assertRaises(HTTPException) as caught:
            cli_args.require_positional("--all", label="container")
        self.assertEqual(caught.exception.status_code, 400)

    def test_require_positional_returns_the_stripped_value(self):
        self.assertEqual(cli_args.require_positional("  nginx  ", label="x"), "nginx")


class ContainerActionTests(unittest.TestCase):
    """``docker stop --all`` must be impossible via the batch endpoint."""

    def test_rejects_option_like_container_name(self):
        from hub import containers_svc

        for value in ["--all", "-f", "--force"]:
            with self.subTest(value=value):
                with self.assertRaises(HTTPException) as caught:
                    containers_svc.container_action(value, "stop")
                self.assertEqual(
                    caught.exception.status_code,
                    400,
                    f"{value!r} reached the docker argv as a positional",
                )

    def test_still_rejects_a_bad_action(self):
        from hub import containers_svc

        with self.assertRaises(HTTPException):
            containers_svc.container_action("nginx", "not-an-action")


class BrewServiceNameTests(unittest.TestCase):
    """``brew services stop --all`` would stop every service on the host."""

    def test_brew_svc_rejects_option_like_name(self):
        from hub import brew_svc

        for value in ["--all", "-a"]:
            with self.subTest(value=value):
                with self.assertRaises(HTTPException) as caught:
                    brew_svc.service_action(value, "stop")
                self.assertEqual(caught.exception.status_code, 400)

    def test_autostart_rejects_option_like_name(self):
        from hub import autostart_svc

        for value in ["--all", "-a"]:
            with self.subTest(value=value):
                with self.assertRaises(HTTPException) as caught:
                    autostart_svc.set_brew_autostart(value, False)
                self.assertEqual(caught.exception.status_code, 400)


class NetworkValidatorTests(unittest.TestCase):
    """The DNS and IP validators both admitted a leading hyphen."""

    def test_valid_ip_rejects_signed_octets(self):
        from hub import network_svc

        # "-0.0.0.0" passed because int("-0") == 0 satisfies 0 <= n <= 255.
        for value in ["-0.0.0.0", "-0.-0.-0.-0", "+1.2.3.4"]:
            with self.subTest(value=value):
                self.assertFalse(
                    network_svc._valid_ip(value),
                    f"{value!r} is not an address; it is an option in disguise",
                )

    def test_valid_ip_still_accepts_real_addresses(self):
        from hub import network_svc

        for value in ["192.0.2.1", "0.0.0.0", "255.255.255.255", "198.51.100.7"]:
            with self.subTest(value=value):
                self.assertTrue(network_svc._valid_ip(value))

    def test_dns_server_validator_rejects_option_like_values(self):
        from hub import network_svc

        for value in ["-getinfo", "--help", "-setdnsservers"]:
            with self.subTest(value=value):
                self.assertFalse(
                    network_svc._valid_dns_server(value),
                    f"{value!r} would be handed to networksetup as a flag",
                )

    def test_dns_server_validator_accepts_addresses_and_hostnames(self):
        from hub import network_svc

        for value in ["1.1.1.1", "8.8.8.8", "dns.example.com", "resolver1.opendns.com"]:
            with self.subTest(value=value):
                self.assertTrue(network_svc._valid_dns_server(value))


class ToolsNetworkTests(unittest.TestCase):
    """``dig -f /etc/passwd`` returns file contents to the caller."""

    def test_dns_lookup_rejects_option_like_name(self):
        """These two report refusal in the payload rather than raising.

        Asserting the established contract instead of changing it: callers in
        Tools.vue render `message` from the returned dict, so switching to an
        exception here would be a silent API change dressed up as a fix.
        """
        from hub import tools_svc

        for value in ["-f/etc/passwd", "-f", "--help"]:
            with self.subTest(value=value):
                out = tools_svc.net_dns_lookup(value)
                self.assertFalse(
                    out.get("ok"),
                    f"{value!r} reached dig's argv",
                )
                # No lookup may have run: a refusal must not carry results.
                self.assertNotIn("dig", out)

    def test_ping_rejects_option_like_host(self):
        from hub import tools_svc

        for value in ["-c100000", "--flood", "-f"]:
            with self.subTest(value=value):
                out = tools_svc.net_ping(value, 1)
                self.assertFalse(out.get("ok"), f"{value!r} reached ping's argv")
                self.assertNotIn("output", out)

    def test_dns_lookup_still_accepts_a_real_name(self):
        """The guard must not have closed the endpoint to legitimate input."""
        from hub import tools_svc

        # Uses a literal address so the test does no live DNS resolution.
        out = tools_svc.net_dns_lookup("127.0.0.1")
        self.assertNotEqual(
            out.get("message"), "非法字符", "a valid host was rejected as illegal"
        )


class FileBrowserCredentialTests(unittest.TestCase):
    """A username in option position reaches the FileBrowser CLI as a flag."""

    def test_apply_filebrowser_refuses_an_option_like_username(self):
        """Drive the real function, not the regex.

        Asserting that ``_HTTP_USER_RE`` rejects ``--help`` proves nothing about
        ``apply_filebrowser``: the pattern already existed and was already
        correct, and the defect was that this code path never consulted it.  A
        test on the pattern alone stays green with the guard deleted.  So call
        the function and require refusal *before* it reaches the CLI.
        """
        from hub import service_credentials

        calls = []

        def spy(cmd, **kwargs):
            calls.append(cmd)
            return (0, "", "")

        for value in ["--help", "-d", "--database=/tmp/x", "-"]:
            with self.subTest(value=value):
                calls.clear()
                with mock.patch("hub.util.sh", spy):
                    with self.assertRaises(HTTPException) as caught:
                        service_credentials.apply_filebrowser(value, "pw-123456")
                self.assertEqual(caught.exception.status_code, 400)
                self.assertEqual(
                    calls,
                    [],
                    f"{value!r} reached the FileBrowser argv",
                )


class RegressionSurfaceTests(unittest.TestCase):
    """Guard the shape of the fix, so it cannot be quietly undone."""

    def test_no_confirmed_site_relies_on_a_hyphen_permissive_class(self):
        # `^[\w@.+-]+$` and friends match "--all".  If one of these reappears at
        # a converted call site, this test names the file.
        offenders = []
        suspect = re.compile(r"\^\[\\w@\.\+-\]\+\$")
        for name in ["brew_svc.py", "autostart_svc.py"]:
            src = (BASE / "hub" / name).read_text(encoding="utf-8")
            for line in src.splitlines():
                stripped = line.strip()
                # Skip comments: each converted site explains the old pattern in
                # prose, and quoting it there is documentation, not a guard.
                if stripped.startswith("#"):
                    continue
                if suspect.search(line):
                    offenders.append(f"{name}: {stripped}")
        self.assertEqual(
            offenders,
            [],
            "a hyphen-permissive regex is guarding an argv positional again",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
