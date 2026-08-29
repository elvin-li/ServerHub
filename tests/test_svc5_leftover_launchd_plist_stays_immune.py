"""Fifth leftover-500s sweep of the Services / launchd surfaces.

Driven over the real ``create_app()`` with
``TestClient(raise_server_exceptions=False)``, so a genuine unhandled leftover
would arrive as an uncoded HTTP 500 (Starlette's plain ``Internal Server
Error`` body) rather than as a re-raised exception.  A coded 4xx/422/503, or
the designed ``{ok: false, message}`` per-id / action contract, is not a
leftover.

The svc / svc2 / svc3 / svc4 sweeps already closed every live leak they found
in ``services_manage_svc``, ``services_uninstall_svc``, ``actions`` and
``discovery.launchd`` (hex/over-cap ints that load uncapped through
``int(x, 16)``, numeric YAML ids, lone UTF-8 surrogates in keys and values,
the ``json.loads`` ValueError body guard, the vanished-CLI 503, the FIFO
that must not hang).  This sweep re-reproduced those hunted classes against
the launchd plist ingest path — the one place that parses attacker-influenced
``.plist`` files off disk for GET /api/services, /api/status, detail, logs
and uninstall preview — and found **no live 500 remaining**.  Every case
below is therefore a stays-immune pin, so the hardening cannot silently
regress:

* a leftover **FIFO occupying a ``*.plist`` path** (or a plist's
  ``StandardOutPath``) must be skipped, never block ``os.open`` waiting for a
  writer — the read is ``O_NONBLOCK`` + a regular-file check;
* a **torn XML plist** (``plistlib`` ExpatError), a **root ``<array>``**
  (AttributeError on ``.get``) and an **empty ``ProgramArguments``**
  (IndexError on ``args[0]``) all degrade to an empty/absent parse;
* an **over-cap hex ``<integer>``** in ``Label`` / ``Program`` /
  ``WorkingDirectory`` / ``StandardOutPath`` loads uncapped and must render
  through the ``str()``-probe scrub, never raise CPython's 4300-digit
  int->str ValueError;
* a **lone surrogate** carried in a binary plist's ``Label`` /
  ``StandardOutPath`` must survive Starlette's strict UTF-8 encode;
* an **oversize plist** (> the 256 KiB read cap) is dropped, not OOM'd;
* a **symlink-loop plist** is refused, not followed into ELOOP.
"""
from __future__ import annotations

import os
import plistlib
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock
from urllib.parse import quote

from fastapi.testclient import TestClient

from hub.app_factory import create_app
from hub.auth import require_auth

_HUGE_HEX = "0x" + "f" * 5000

_app = None


def _the_app():
    global _app
    if _app is None:
        _app = create_app()
        _app.dependency_overrides[require_auth] = lambda: None
    return _app


def _client() -> TestClient:
    return TestClient(_the_app(), raise_server_exceptions=False)


def _is_leftover_500(r) -> bool:
    """True only for an uncoded traceback 500, not a coded/ok:false body."""
    if r.status_code != 500:
        return False
    try:
        body = r.json()
    except Exception:
        return True  # non-JSON == Starlette "Internal Server Error"
    detail = body.get("detail") if isinstance(body, dict) else None
    if isinstance(detail, dict) and detail.get("code"):
        return False
    if isinstance(body, dict) and "ok" in body and "message" in body:
        return False
    return True


def _surrogate_binary_plist(label: str, out_path: str) -> bytes:
    """A binary plist carrying a lone ``\\ud800`` in Label and StandardOutPath.

    ``plistlib.dumps`` refuses a lone surrogate on write, so build with a safe
    sentinel and patch its UTF-16 bytes to the surrogate — exactly the hostile
    leftover a torn UTF-16 plist on disk can hold.
    """
    sentinel = "\uffff"
    data = plistlib.dumps(
        {
            "Label": label + sentinel,
            "ProgramArguments": ["/bin/true"],
            "StandardOutPath": out_path + sentinel,
        },
        fmt=plistlib.FMT_BINARY,
    )
    return data.replace(
        sentinel.encode("utf-16-be"),
        "\ud800".encode("utf-16-be", "surrogatepass"),
    )


class LaunchdPlistIngestStaysImmune(unittest.TestCase):
    """Hostile ``*.plist`` leftovers over the real Services / launchd routes."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.agents = Path(self._tmp.name)
        self._write_fixtures()
        # AGENTS_DIR is resolved at import in four launchd-facing modules;
        # patch every one so the whole ingest path reads this temp dir.
        import hub.actions as actions_mod
        import hub.discovery.launchd as dl
        import hub.services_manage_svc as sms
        import hub.services_uninstall_svc as sus

        for mod, attr in (
            (sms, "AGENTS_DIR"),
            (sus, "AGENTS_DIR"),
            (actions_mod, "AGENTS_DIR"),
            (dl, "AGENTS_DIR"),
        ):
            p = mock.patch.object(mod, attr, str(self.agents))
            p.start()
            self.addCleanup(p.stop)

    def _write_fixtures(self):
        a = self.agents
        # 1. FIFO occupying a plist path — a plain open() would block forever.
        os.mkfifo(a / "local.fifo.plist")
        # 2. torn XML → plistlib ExpatError.
        (a / "local.torn.plist").write_text(
            '<?xml version="1.0"?><plist><dict><key>Label', encoding="utf-8"
        )
        # 3. root is an <array>, not a <dict> → AttributeError on .get.
        (a / "local.rootarray.plist").write_text(
            '<?xml version="1.0" encoding="UTF-8"?><plist version="1.0">'
            "<array><string>x</string></array></plist>",
            encoding="utf-8",
        )
        # 4. empty ProgramArguments → IndexError on args[0].
        (a / "local.emptyargs.plist").write_text(
            '<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict>'
            "<key>Label</key><string>local.emptyargs</string>"
            "<key>ProgramArguments</key><array/>"
            "<key>RunAtLoad</key><true/></dict></plist>",
            encoding="utf-8",
        )
        # 5. over-cap hex <integer> in Label / Program / WorkingDirectory.
        (a / "local.hexid.plist").write_text(
            '<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict>'
            f"<key>Label</key><integer>{_HUGE_HEX}</integer>"
            f"<key>Program</key><integer>{_HUGE_HEX}</integer>"
            f"<key>WorkingDirectory</key><integer>{_HUGE_HEX}</integer>"
            "</dict></plist>",
            encoding="utf-8",
        )
        # 6. binary plist with a lone surrogate in Label and StandardOutPath.
        (a / "local.surr.plist").write_bytes(
            _surrogate_binary_plist("local.surr", "/tmp/log")
        )
        # 7. oversize plist (> 256 KiB read cap).
        (a / "local.big.plist").write_text(
            '<?xml version="1.0"?><plist version="1.0"><dict>'
            "<key>Label</key><string>" + "A" * (300 * 1024) + "</string></dict></plist>",
            encoding="utf-8",
        )
        # 8. plist whose StandardOutPath is a FIFO — logs must not hang on it.
        os.mkfifo(a / "log.fifo")
        (a / "local.fifolog.plist").write_text(
            '<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict>'
            "<key>Label</key><string>local.fifolog</string>"
            "<key>ProgramArguments</key><array><string>/bin/true</string></array>"
            f"<key>StandardOutPath</key><string>{a / 'log.fifo'}</string>"
            "</dict></plist>",
            encoding="utf-8",
        )
        # 9. symlink-loop plist — resolve/stat must refuse, not ELOOP-500.
        os.symlink(a / "local.loop.plist", a / "local.loop.plist")

        self.labels = [
            "local.fifo", "local.torn", "local.rootarray", "local.emptyargs",
            "local.hexid", "local.surr", "local.big", "local.fifolog",
            "local.loop",
        ]

    def test_service_and_status_listings_never_traceback(self):
        for path in ("/api/services?force=true", "/api/status?force=true"):
            r = _client().get(path)
            self.assertFalse(_is_leftover_500(r), f"{path}: {r.text[:200]}")
            self.assertEqual(r.status_code, 200)

    def test_detail_and_logs_and_preview_never_traceback(self):
        c = _client()
        for label in self.labels:
            q = quote(label, safe="")
            for suffix in ("detail", "logs", "uninstall/preview"):
                r = c.get(f"/api/services/{q}/{suffix}")
                self.assertFalse(
                    _is_leftover_500(r), f"{label}/{suffix}: {r.text[:200]}"
                )

    def test_fifo_logpath_returns_promptly_and_does_not_hang(self):
        """A FIFO StandardOutPath must be reported, not block on os.open."""
        done = threading.Event()
        holder = {}

        def call():
            holder["r"] = _client().get("/api/services/local.fifolog/logs")
            done.set()

        t = threading.Thread(target=call, daemon=True)
        t.start()
        self.assertTrue(done.wait(timeout=20), "GET logs hung on a FIFO log path")
        r = holder["r"]
        self.assertEqual(r.status_code, 200)
        # Not a regular file → reported as absent/invalid, never streamed.
        self.assertIn("log.fifo", r.json()["log"])

    def test_hexid_plist_logs_render_through_the_scrub(self):
        r = _client().get("/api/services/local.hexid/logs")
        self.assertFalse(_is_leftover_500(r), r.text[:200])
        self.assertEqual(r.status_code, 200)


if __name__ == "__main__":
    unittest.main()
