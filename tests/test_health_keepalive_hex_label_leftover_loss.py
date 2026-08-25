"""Leftover hex-int plist Label silently dropped a KeepAlive health warning.

plistlib parses ``<integer>0xFFF…</integer>`` through ``int(raw, 16)`` — a
power-of-two base CPython's 4300-digit parse cap does not apply to — so a
poisoned LaunchAgent plist hands ``_collect_checks`` an *already-int* Label
past the int->str digit cap.  The KeepAlive loop ran a bare
``str(pl.get("Label") or …)`` over it; the ValueError landed in the loop's
``except Exception: continue`` and the agent's "KeepAlive not running"
warning vanished from GET /api/health/checks without a trace — the exact
silent-loss shape ``stale_runtime.scan`` already fixed with an ``_as_text``
str() probe plus the on-disk filename as the fallback identity.

Also pinned (already immune, so these guard against regression):

* the health / sensors / smart ``_jsonable`` sanitizers replace-encode
  surrogate dict *keys* as well as values, decode bytes keys, and drop an
  over-cap int key while keeping its renderable siblings;
* a full ``run_checks`` payload built while the poisoned plist is on disk
  still passes Starlette's ``allow_nan=False`` UTF-8 encode.
"""
from __future__ import annotations

import json
import plistlib
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hub import health_svc, launchd_cache, sensors_svc, smart_test_svc

#: Over CPython's 4300-digit str<->int cap once parsed from hex.
_HUGE_HEX = "0x" + "F" * 4300
_HUGE_INT = int("9" * 4300) + int("9" * 4300)
#: A lone surrogate, as os.environ / surrogateescape decodes produce.
_SURROGATE = "\udce6"

#: A plist whose Label is an over-cap hex integer.  Built by hand because
#: ``plistlib.dumps`` itself cannot render the int back to text.
_POISONED_PLIST = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<plist version="1.0"><dict>'
    "<key>Label</key><integer>" + _HUGE_HEX + "</integer>"
    "<key>KeepAlive</key><true/>"
    "</dict></plist>"
).encode("utf-8")


def _starlette(payload) -> None:
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class KeepAliveHexLabelTests(unittest.TestCase):
    """A poisoned Label must fall back to the plist filename, not vanish."""

    def setUp(self):
        health_svc._cache.update(t=0.0, v=None)
        self.addCleanup(lambda: health_svc._cache.update(t=0.0, v=None))
        launchd_cache.invalidate_launchd()
        self.addCleanup(launchd_cache.invalidate_launchd)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        agents = Path(self.tmp.name)
        (agents / "local.poisoned.plist").write_bytes(_POISONED_PLIST)
        (agents / "local.good.plist").write_bytes(plistlib.dumps({
            "Label": "local.good",
            "KeepAlive": True,
        }))
        self.agents = agents

    def _checks(self) -> list[dict]:
        with (
            mock.patch.object(health_svc, "AGENTS_DIR", self.agents),
            mock.patch.object(health_svc, "engine_up", return_value=True),
            mock.patch.object(health_svc, "nginx_overview",
                              side_effect=RuntimeError("no nginx")),
            mock.patch.object(health_svc, "port_open", return_value=True),
            mock.patch.object(health_svc, "launchd_running_labels",
                              return_value=frozenset()),
            mock.patch.object(health_svc, "brew_services_list", return_value=[]),
            mock.patch.object(health_svc, "sh", return_value=(1, "", "")),
            mock.patch.object(health_svc, "override", return_value={}),
            mock.patch.object(health_svc, "_smart_checks", return_value=[]),
            mock.patch.object(health_svc, "_immich_checks", return_value=[]),
            mock.patch.object(health_svc, "_wireguard_checks", return_value=[]),
            mock.patch.object(health_svc, "_time_machine_checks", return_value=[]),
            mock.patch.object(health_svc, "_ollama_checks", return_value=[]),
            mock.patch.object(health_svc, "_stale_runtime_checks", return_value=[]),
            mock.patch.object(health_svc, "_worker_checks", return_value=[]),
        ):
            result = health_svc.run_checks(force=True)
        self.assertIsInstance(result, dict)
        return result["checks"]

    def test_poisoned_label_falls_back_to_the_filename(self):
        ids = [c["id"] for c in self._checks()]
        # The healthy sibling was never at risk; the poisoned plist used to
        # vanish from the payload entirely instead of being reported under
        # its on-disk name (the stale_runtime.scan convention).
        self.assertIn("la_local.good", ids)
        self.assertIn("la_local.poisoned", ids)

    def test_full_payload_still_starlette_encodes(self):
        with (
            mock.patch.object(health_svc, "AGENTS_DIR", self.agents),
            mock.patch.object(health_svc, "engine_up", return_value=True),
            mock.patch.object(health_svc, "nginx_overview",
                              side_effect=RuntimeError("no nginx")),
            mock.patch.object(health_svc, "port_open", return_value=True),
            mock.patch.object(health_svc, "launchd_running_labels",
                              return_value=frozenset()),
            mock.patch.object(health_svc, "brew_services_list", return_value=[]),
            mock.patch.object(health_svc, "sh", return_value=(1, "", "")),
            mock.patch.object(health_svc, "override", return_value={}),
            mock.patch.object(health_svc, "_smart_checks", return_value=[]),
            mock.patch.object(health_svc, "_immich_checks", return_value=[]),
            mock.patch.object(health_svc, "_wireguard_checks", return_value=[]),
            mock.patch.object(health_svc, "_time_machine_checks", return_value=[]),
            mock.patch.object(health_svc, "_ollama_checks", return_value=[]),
            mock.patch.object(health_svc, "_stale_runtime_checks", return_value=[]),
            mock.patch.object(health_svc, "_worker_checks", return_value=[]),
        ):
            result = health_svc.run_checks(force=True)
        _starlette(result)


class SanitizerKeyPins(unittest.TestCase):
    """Already immune — pinned so a refactor cannot regress the key rules."""

    def test_sensors_jsonable_replace_encodes_surrogate_keys_and_values(self):
        cleaned = sensors_svc._jsonable({("k" + _SURROGATE): ("v" + _SURROGATE)})
        self.assertEqual(cleaned, {"k?": "v?"})
        _starlette(cleaned)

    def test_sensors_jsonable_decodes_bytes_keys(self):
        cleaned = sensors_svc._jsonable({b"k\xff": 1})
        self.assertEqual(cleaned, {"k\ufffd": 1})
        _starlette(cleaned)

    def test_health_jsonable_drops_over_cap_int_key_keeps_siblings(self):
        cleaned = health_svc._jsonable({_HUGE_INT: "gone", "kept": 3})
        self.assertEqual(cleaned, {"kept": 3})
        _starlette(cleaned)

    def test_sensors_jsonable_drops_over_cap_int_key_keeps_siblings(self):
        cleaned = sensors_svc._jsonable({_HUGE_INT: "gone", "kept": 3})
        self.assertEqual(cleaned, {"kept": 3})
        _starlette(cleaned)

    def test_smart_jsonable_drops_over_cap_int_key_keeps_siblings(self):
        cleaned = smart_test_svc._jsonable({_HUGE_INT: "gone", "kept": 3})
        self.assertEqual(cleaned, {"kept": 3})
        _starlette(cleaned)


if __name__ == "__main__":
    unittest.main()
