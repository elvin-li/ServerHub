"""Three WireGuard defects found from operator reports.

1. Every mutation could report "wireguard-tools is not installed" on a host where
   it plainly was. Presence was derived from `wg --version` succeeding, so any
   transient failure of that subprocess -- a timeout under load, a stray non-zero
   exit -- disabled the whole page behind a wildly misleading error.

2. Four GET endpoints hand back key material: a peer's private key, or the
   server's own. They carried no route-level guard and no cache directives. The
   global auth dependency does already refuse non-admin sessions, so this was
   defence in depth rather than an open hole, but a private key reaching the
   browser's disk cache is a problem regardless of who fetched it.

3. The QR code rendered only partially. The generated SVG is scalable -- a viewBox
   with no width/height -- so it had no intrinsic size and was either collapsed or
   clipped by the dialog.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import wireguard_svc  # noqa: E402

ROUTER = BASE / "hub" / "routers" / "wireguard_api.py"
VIEW = BASE / "web" / "src" / "views" / "WireGuard.vue"

#: The genuine Path.exists, captured before any patching.
_REAL_EXISTS = Path.exists


def _only_wireguard_missing(self: Path) -> bool:
    """Report the WireGuard binaries as absent and tell the truth about the rest.

    A blanket ``return_value=False`` on ``Path.exists`` is process-wide, and other
    modules read the filesystem during the same call. Delegating keeps the lie
    scoped to what the test is actually about.
    """
    if str(self) in {
        wireguard_svc.WG,
        wireguard_svc.WG_QUICK,
        wireguard_svc.WIREGUARD_GO,
    }:
        return False
    return _REAL_EXISTS(self)


class InstallationDetectionTests(unittest.TestCase):
    """Presence must be a fact about the filesystem, not about a subprocess."""

    def test_a_failing_version_probe_does_not_mean_uninstalled(self):
        with patch.object(wireguard_svc, "sh", return_value=(1, "", "boom")):
            info = wireguard_svc.installation()
        self.assertTrue(
            info["installed"],
            "a failed `wg --version` reported the tools as missing, which disables "
            "every operation behind a misleading error",
        )
        self.assertTrue(info["probe_failed"], "the degraded state should be visible")

    def test_a_timeout_does_not_mean_uninstalled(self):
        with patch.object(wireguard_svc, "sh", side_effect=TimeoutError("slow")):
            with self.assertRaises(TimeoutError):
                wireguard_svc.installation()

    def test_missing_binaries_do_mean_uninstalled(self):
        # Only the WireGuard binaries are made to look absent. `patch.object(
        # wireguard_svc.Path, "exists", return_value=False)` reaches much further
        # than this test: wireguard_svc.Path IS pathlib.Path, so it made every
        # path in the process report itself missing -- including services.yaml,
        # which config._bootstrap() then recreated from defaults, wiping the admin
        # account, the apps and the bookmarks on every test run.
        with patch.object(wireguard_svc.Path, "exists", _only_wireguard_missing):
            info = wireguard_svc.installation()
        self.assertFalse(info["installed"])
        self.assertFalse(info["probe_failed"], "absent is not the same as degraded")

    def test_a_healthy_host_is_not_flagged_as_degraded(self):
        with patch.object(wireguard_svc, "sh", return_value=(0, "wireguard-tools v1.0", "")):
            info = wireguard_svc.installation()
        self.assertTrue(info["installed"])
        self.assertFalse(info["probe_failed"])


class SecretEndpointGuardTests(unittest.TestCase):
    """Anything returning a private key is guarded and never cacheable."""

    #: Handler names that return key material.
    SECRET_HANDLERS = (
        "api_wireguard_conf",
        "api_wireguard_peer_config",
        "api_wireguard_peer_download",
        "api_wireguard_export",
    )

    def setUp(self):
        self.source = ROUTER.read_text()

    def _body(self, handler: str) -> str:
        start = self.source.index(f"def {handler}(")
        rest = self.source[start:]
        end = rest.find("\n@router.")
        return rest if end < 0 else rest[:end]

    def test_each_secret_endpoint_is_guarded(self):
        for handler in self.SECRET_HANDLERS:
            with self.subTest(handler=handler):
                self.assertIn(
                    "_guard(request)",
                    self._body(handler),
                    f"{handler} returns key material without the admin guard",
                )

    def test_each_secret_endpoint_sets_no_store(self):
        for handler in self.SECRET_HANDLERS:
            with self.subTest(handler=handler):
                self.assertIn(
                    "_SECRET_HEADERS",
                    self._body(handler),
                    f"{handler} lets a private key be cached",
                )

    def test_the_no_store_header_actually_says_no_store(self):
        self.assertRegex(self.source, r'"Cache-Control":\s*"no-store')

    def test_public_key_travels_as_a_query_parameter(self):
        """Base64 keys contain '/', which Starlette decodes before routing."""
        self.assertIn('@router.get("/api/wireguard/peers/config")', self.source)
        self.assertNotIn("/api/wireguard/peers/{pubkey}/config", self.source)


class QrRenderingTests(unittest.TestCase):
    def setUp(self):
        self.source = VIEW.read_text()

    def test_the_qr_has_a_bounded_container(self):
        # A scalable SVG inherits no size; without an explicitly sized wrapper it
        # collapsed or overflowed the dialog and the symbol was cut off.
        self.assertIn('class="wg-qr"', self.source)
        self.assertRegex(self.source, r"\.wg-qr\s*\{")
        self.assertRegex(self.source, r"max-width:\s*\d+px")

    def test_the_svg_is_stretched_to_the_container(self):
        self.assertRegex(self.source, r"\.wg-qr :deep\(svg\)\s*\{")
        self.assertRegex(self.source, r"width:\s*100%")

    def test_the_qr_sits_on_a_light_background(self):
        """A dark theme behind a QR defeats most phone cameras."""
        self.assertRegex(self.source, r"\.wg-qr[\s\S]{0,200}background:\s*#fff")

    def test_only_scannable_formats_get_a_code(self):
        # A full Clash config is kilobytes; encoding it produces a symbol no
        # camera can resolve, so those formats deliberately get none.
        self.assertRegex(self.source, r"fmt !== 'wg' && fmt !== 'sr'")


if __name__ == "__main__":
    unittest.main()
