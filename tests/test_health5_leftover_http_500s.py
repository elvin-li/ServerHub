"""Fifth leftover-500s sweep of the Health surfaces, over the real mounted app.

The hunted classes (UTF-8 surrogates in keys AND values, CPython's
4300-digit int cap — including the YAML/plist hex form that loads uncapped
through ``int(x, 16)`` — huge-number JSON where ``json.loads`` raises
ValueError not JSONDecodeError, numeric ids through a str() probe,
iterbombs, FIFO/oversize/invalid-UTF-8 leftovers, plist
ExpatError/AttributeError/IndexError) were re-reproduced against
GET /api/health/checks and the SMART routes.  Live leftovers surfaced:

* ``health_svc._jsonable`` lacked the iteration guards its
  nginx_svc/smart_test_svc siblings carry: a mapping that refuses
  ``items()`` or a sequence subclass whose ``__iter__`` raises — planted in
  the cache ``v`` (the sibling of the ``t`` poisoning health4 fixed), or
  arriving as a raw Immich/Ollama check row that bypasses ``_check`` —
  raised out of ``_serve_cached`` (every TTL hit) and out of the final
  collection pass, 500ing GET /api/health/checks.
* ``_collect_checks``'s summary sums called ``.get`` bare on rows the
  function does not own: one dict-subclass row whose ``.get`` raises 500'd
  the whole collection after every probe had already answered.
* ``checks.extend(_as_checks(...))`` and the brew loop accepted a list
  *subclass* through the bare isinstance gate; a lazily-raising
  ``__iter__`` escaped ``_safe`` (which only covers the probe call) and
  500'd the route.  A set subclass with a raising ``__contains__``
  silently dropped every KeepAlive warning through the per-row guards.
* ``smart_test_svc._schedule_cfg`` AttributeError'd ``.get`` on a
  non-mapping ``settings`` — 500 GET /api/smart through ``get_schedule()``,
  and the same raise escaped ``schedule_due()`` inside the scheduler tick.

The rest of the battery pins the already-immune corners this sweep
re-checked: the on-disk LaunchAgent plist zoo (FIFO must not hang,
oversize, truncated binary plist, invalid UTF-8, array payload, absurd
<date>), the SMART journal zoo (FIFO, ``Infinity`` literals, over-cap digit
runs through the parse_int hook, surrogate-escaped keys/values, deep
nests), hostile smartctl/diskutil bytes, a poisoned smart_schedule block,
and the coded refusals of the SMART action routes.
"""
from __future__ import annotations

import json
import os
import threading
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from fastapi.testclient import TestClient

from hub import health_svc, smart_test_svc
from hub.app_factory import create_app
from hub.auth import require_auth
from hub.routers import nas_storage

#: The hex spelling parses uncapped (``int(x, 16)``), so a live over-cap int
#: really can exist in memory; only rendering it back is impossible.
_HUGE_INT = int("F" * 5000, 16)
_SURROGATE = "\udce6"

_app = None


def _the_app():
    global _app
    if _app is None:
        _app = create_app()
        _app.dependency_overrides[require_auth] = lambda: None
    return _app


def _client() -> TestClient:
    # raise_server_exceptions=False: a real 500 must arrive as HTTP 500, not
    # as a re-raised exception that would mask which route crashed.
    return TestClient(_the_app(), raise_server_exceptions=False)


class _ItemsBombDict(dict):
    """A mapping that refuses iteration — the ups_svc/nginx_svc guard class."""

    def items(self):
        raise RuntimeError("items bomb")


class _GetBombDict(dict):
    def get(self, *args, **kwargs):
        raise RuntimeError("get bomb")


class _IterBombList(list):
    def __iter__(self):
        raise RuntimeError("iter bomb")


class _ClearBombDict(dict):
    def clear(self):
        raise RuntimeError("clear bomb")


class _ContainsBombSet(frozenset):
    def __contains__(self, item):
        raise RuntimeError("contains bomb")


_CLEAN_SNAPSHOT = {
    "ts": "now",
    "summary": {"ok": 1, "warn": 0, "error": 0, "total": 1},
    "checks": [{"id": "x", "name": "X", "level": "ok", "ok": True,
                "detail": "", "fix": ""}],
    "healthy": True,
}


class _HealthCacheSandbox(unittest.TestCase):
    """Save/restore the module cache so poisonings cannot leak between tests."""

    def setUp(self):
        saved = dict(health_svc._cache)
        self.addCleanup(lambda: health_svc._cache.update(saved))
        health_svc._cache.update(t=0.0, v=None)


class TtlHitPoisonedSnapshotObjectTests(_HealthCacheSandbox):
    """The ``v`` sibling of health4's ``t`` poisoning: a planted snapshot
    *object* that fights ``_serve_cached`` must never 500 the TTL hit."""

    def test_items_bomb_snapshot_is_http_200(self):
        health_svc._cache.update(t=time.time(), v=_ItemsBombDict(_CLEAN_SNAPSHOT))
        response = _client().get("/api/health/checks")
        self.assertEqual(response.status_code, 200, response.text[:300])
        # Nothing salvageable: the fail-closed empty snapshot answers.
        payload = response.json()
        self.assertEqual(payload["checks"], [])
        self.assertFalse(payload["healthy"])

    def test_iterbomb_checks_list_costs_only_that_field(self):
        bad = dict(_CLEAN_SNAPSHOT)
        bad["checks"] = _IterBombList(_CLEAN_SNAPSHOT["checks"])
        health_svc._cache.update(t=time.time(), v=bad)
        response = _client().get("/api/health/checks")
        self.assertEqual(response.status_code, 200, response.text[:300])
        payload = response.json()
        # The sequence-rank drop: the field is gone, its siblings survive.
        self.assertIsNone(payload["checks"])
        self.assertEqual(payload["ts"], "now")

    def test_nested_items_bomb_row_drops_alone(self):
        bad = dict(_CLEAN_SNAPSHOT)
        bad["checks"] = [
            _ItemsBombDict({"id": "poison"}),
            {"id": "sane", "name": "S", "level": "ok", "ok": True,
             "detail": "", "fix": ""},
        ]
        health_svc._cache.update(t=time.time(), v=bad)
        response = _client().get("/api/health/checks")
        self.assertEqual(response.status_code, 200, response.text[:300])
        checks = response.json()["checks"]
        self.assertEqual(
            [c.get("id") for c in checks if isinstance(c, dict)], ["sane"],
        )
        self.assertIn(None, checks)  # the poison row dropped, not the payload

    def test_clear_bomb_snapshot_serves_the_cleaned_copy(self):
        dirty = _ClearBombDict(_CLEAN_SNAPSHOT)
        dirty["junk"] = float("inf")  # forces the dirty path into clear()
        health_svc._cache.update(t=time.time(), v=dirty)
        response = _client().get("/api/health/checks")
        self.assertEqual(response.status_code, 200, response.text[:300])
        payload = response.json()
        self.assertEqual(payload["ts"], "now")
        self.assertIsNone(payload["junk"])  # inf dropped by the scrub

    def test_jsonable_returns_none_for_the_bomb_classes(self):
        self.assertIsNone(health_svc._jsonable(_ItemsBombDict({"a": 1})))
        self.assertIsNone(health_svc._jsonable(_IterBombList([1])))
        # The guards must not eat the sane shapes beside them: a nested bomb
        # drops to None per element, its list siblings survive.
        self.assertEqual(
            health_svc._jsonable({"a": [_ItemsBombDict({}), "b"]}),
            {"a": [None, "b"]},
        )


class ColdCollectionProviderBombTests(_HealthCacheSandbox):
    """Rows and shapes the collection does not own must cost only themselves."""

    def _get(self, **module_patches):
        from contextlib import ExitStack

        with ExitStack() as stack:
            stack.enter_context(
                mock.patch.object(health_svc, "sh", return_value=(1, "", ""))
            )
            for target, value in module_patches.items():
                stack.enter_context(mock.patch(target, return_value=value))
            return _client().get("/api/health/checks")

    def test_immich_items_bomb_row_is_http_200(self):
        response = self._get(**{
            "hub.immich_svc.run_checks": {"checks": [
                _ItemsBombDict({"id": "im"}),
                {"id": "im_ok", "name": "I", "level": "ok", "ok": True,
                 "detail": "", "fix": ""},
            ]},
        })
        self.assertEqual(response.status_code, 200, response.text[:300])
        ids = [c.get("id") for c in response.json()["checks"]
               if isinstance(c, dict)]
        self.assertIn("im_ok", ids)      # the sane sibling row survived
        self.assertIn("disk_root", ids)  # and so did the rest of the page

    def test_immich_get_bomb_row_survives_the_summary(self):
        response = self._get(**{
            "hub.immich_svc.run_checks": {"checks": [
                _GetBombDict({"id": "im", "ok": False, "level": "warn"}),
            ]},
        })
        self.assertEqual(response.status_code, 200, response.text[:300])
        summary = response.json()["summary"]
        self.assertIsInstance(summary["total"], int)
        self.assertGreaterEqual(summary["total"], 1)

    def test_ollama_iterbomb_list_subclass_is_http_200(self):
        response = self._get(**{
            "hub.ollama_svc.health_checks": _IterBombList(
                [{"id": "ol", "ok": True}]
            ),
        })
        self.assertEqual(response.status_code, 200, response.text[:300])
        ids = [c.get("id") for c in response.json()["checks"]
               if isinstance(c, dict)]
        self.assertIn("disk_root", ids)

    def test_brew_iterbomb_list_subclass_is_http_200(self):
        with (
            mock.patch.object(health_svc, "sh", return_value=(1, "", "")),
            mock.patch.object(
                health_svc, "brew_services_list",
                return_value=_IterBombList([{"name": "mosquitto"}]),
            ),
        ):
            response = _client().get("/api/health/checks")
        self.assertEqual(response.status_code, 200, response.text[:300])

    def test_contains_bomb_running_labels_keeps_the_brew_recheck(self):
        # Pre-fix the bomb was carried verbatim and every per-row `in`
        # raised into its guard: brew "none" rows silently lost their
        # launchd re-check.  The materialized copy answers truthfully.
        with (
            mock.patch.object(health_svc, "sh", return_value=(1, "", "")),
            mock.patch.object(
                health_svc, "launchd_running_labels",
                return_value=_ContainsBombSet({"homebrew.mxcl.mosquitto"}),
            ),
            mock.patch.object(
                health_svc, "brew_services_list",
                return_value=[{"name": "mosquitto", "status": "none"}],
            ),
        ):
            response = _client().get("/api/health/checks")
        self.assertEqual(response.status_code, 200, response.text[:300])
        rows = {c["id"]: c for c in response.json()["checks"]
                if isinstance(c, dict) and "id" in c}
        self.assertIn("brew_mosquitto", rows)
        self.assertTrue(rows["brew_mosquitto"]["ok"])
        self.assertEqual(rows["brew_mosquitto"]["detail"], "running (launchd)")


class PlistZooStaysImmuneTests(_HealthCacheSandbox):
    """The KeepAlive scan over hostile on-disk plists: skip, never 500/hang."""

    def setUp(self):
        super().setUp()
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.agents = Path(tmp.name) / "agents"
        self.agents.mkdir(parents=True)
        os.mkfifo(self.agents / "local.fifo.plist")
        (self.agents / "local.big.plist").write_bytes(b"x" * (300 * 1024))
        # Truncated binary plist: plistlib raises IndexError-class errors.
        (self.agents / "local.trunc.plist").write_bytes(b"bplist00\x01")
        (self.agents / "local.badutf8.plist").write_bytes(b"\xff\xfe\x00junk")
        (self.agents / "local.array.plist").write_text(
            '<?xml version="1.0"?><plist version="1.0">'
            "<array><string>x</string></array></plist>",
            encoding="utf-8",
        )
        (self.agents / "local.date.plist").write_text(
            '<?xml version="1.0"?><plist version="1.0"><dict>'
            "<key>Label</key><date>99999999-99-99T99:99:99Z</date>"
            "<key>KeepAlive</key><true/></dict></plist>",
            encoding="utf-8",
        )
        (self.agents / "local.good.plist").write_text(
            '<?xml version="1.0"?><plist version="1.0"><dict>'
            "<key>Label</key><string>local.good</string>"
            "<key>KeepAlive</key><true/></dict></plist>",
            encoding="utf-8",
        )

    def test_the_zoo_answers_200_without_hanging(self):
        holder = []

        def _do():
            with (
                mock.patch.object(health_svc, "AGENTS_DIR", str(self.agents)),
                mock.patch("hub.stale_runtime.AGENTS_DIR", str(self.agents)),
                mock.patch.object(health_svc, "sh", return_value=(1, "", "")),
            ):
                holder.append(_client().get("/api/health/checks"))

        worker = threading.Thread(target=_do, daemon=True)
        worker.start()
        # A leftover FIFO plist must not park the request on open() forever.
        worker.join(30)
        self.assertFalse(worker.is_alive(), "GET /api/health/checks hung on a FIFO plist")
        response = holder[0]
        self.assertEqual(response.status_code, 200, response.text[:300])
        response.text.encode("utf-8")
        ids = [c.get("id") for c in response.json()["checks"]
               if isinstance(c, dict)]
        # Every hostile plist dropped alone; the sane KeepAlive warning
        # beside them still renders.
        self.assertIn("la_local.good", ids)
        for poisoned in ("la_local.fifo", "la_local.big", "la_local.trunc",
                         "la_local.badutf8", "la_local.array"):
            self.assertNotIn(poisoned, ids)


class SmartOverviewStaysImmuneTests(unittest.TestCase):
    """GET /api/smart over hostile journal, settings, and smartctl output."""

    def setUp(self):
        self.addCleanup(smart_test_svc.invalidate)
        smart_test_svc.invalidate()
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.journal = Path(tmp.name) / "smart-tests.json"

    def _get(self, sh_stub=None):
        with (
            mock.patch.object(smart_test_svc, "HISTORY_PATH", self.journal),
            mock.patch.object(
                smart_test_svc, "sh",
                sh_stub if sh_stub is not None
                else mock.Mock(return_value=(1, "", "")),
            ),
        ):
            smart_test_svc.invalidate()
            return _client().get("/api/smart")

    def test_fifo_journal_answers_200_without_hanging(self):
        os.mkfifo(self.journal)
        holder = []

        def _do():
            holder.append(self._get())

        worker = threading.Thread(target=_do, daemon=True)
        worker.start()
        worker.join(30)
        self.assertFalse(worker.is_alive(), "GET /api/smart hung on a FIFO journal")
        response = holder[0]
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertEqual(response.json()["history"], [])

    def test_poisoned_journal_keeps_the_document(self):
        # Infinity parses (json.loads accepts the literal), the over-cap
        # digit run is ValueError-not-JSONDecodeError for the whole document
        # without the parse_int hook, and the surrogate escapes decode to
        # lone surrogates that must never reach Starlette's UTF-8 encode.
        self.journal.write_text(
            '[{"ts": Infinity, "n": ' + "9" * 5000
            + ', "k\\ud800": "v\\udfff", "device": "/dev/disk0"}, 42, "row"]',
            encoding="utf-8",
        )
        response = self._get()
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertNotIn("\ud800", response.text)
        response.text.encode("utf-8")
        history = response.json()["history"]
        self.assertEqual(len(history), 1)  # the dict row survived, junk dropped
        row = history[0]
        self.assertIsNone(row["ts"])       # Infinity dropped
        self.assertIsNone(row["n"])        # over-cap digit run dropped alone
        self.assertEqual(row["device"], "/dev/disk0")

    def test_deeply_nested_journal_is_http_200(self):
        self.journal.write_text("[" * 6000 + "]" * 6000, encoding="utf-8")
        response = self._get()
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertEqual(response.json()["history"], [])

    def test_hostile_smartctl_and_diskutil_bytes_are_http_200(self):
        huge = "9" * 5000

        def hostile_sh(argv, timeout=None, **kwargs):
            joined = " ".join(str(a) for a in argv)
            if "diskutil" in joined:
                # Surrogate bytes on stdout + a live node.
                return (0, b"/dev/disk0 (internal) \xed\xa0\x80\n", b"")
            if "-c" in argv:
                return (0, (
                    "Short self-test routine recommended polling time: ( "
                    + huge + ") minutes.\n"
                    "Extended self-test routine\n"
                    "Self-test routine in progress...\n"
                    + huge + "% of test remaining\n"
                ).encode("utf-8") + b"\xed\xa0\x80", b"")
            if "selftest" in joined:
                return (0, (
                    "# " + huge + "  Short offline  Completed without error"
                    "  00%  " + huge + "  -\n"
                    "Self-test status: junk "
                ).encode("utf-8") + b"\xed\xbf\xbf", b"")
            return (0, b"", b"")

        response = self._get(sh_stub=hostile_sh)
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertNotIn("\ud800", response.text)
        response.text.encode("utf-8")
        devices = response.json()["devices"]
        self.assertEqual(len(devices), 1)
        report = devices[0]
        # Over-cap polling time fell back to the hint minutes (never the
        # drive's unrenderable number); over-cap log ints dropped to 0; the
        # in-progress percent stayed unknown, not negative.
        self.assertEqual(
            report["capabilities"]["estimated_minutes"].get("short"),
            smart_test_svc._KIND_HINT_MINUTES["short"],
        )
        self.assertTrue(
            all(r["index"] in (0,) and r["power_on_hours"] in (0,)
                for r in report["log"])
        )
        self.assertTrue(report["progress"]["running"])
        self.assertIsNone(report["progress"]["percent_remaining"])

    def test_poisoned_schedule_settings_are_http_200(self):
        poison = {
            "interval": _HUGE_INT,           # already-int hex over-cap
            "kind": {"a": 1},                # mapping where a word belongs
            "last_run": float("inf"),
            "devices": [_HUGE_INT, "/dev/disk0", None, b"\xff",
                        "/dev/disk0\n", "sd" + _SURROGATE],
        }
        with mock.patch.object(
            smart_test_svc, "cfg",
            return_value={"settings": {"smart_schedule": poison}},
        ):
            response = self._get()
        self.assertEqual(response.status_code, 200, response.text[:300])
        response.text.encode("utf-8")
        schedule = response.json()["schedule"]
        self.assertEqual(schedule["interval"], "off")
        self.assertEqual(schedule["kind"], "short")
        self.assertEqual(schedule["last_run"], 0.0)
        self.assertIn("/dev/disk0", schedule["devices"])
        self.assertNotIn(_SURROGATE, response.text)

    def test_settings_not_a_mapping_is_http_200(self):
        # This module does not own the provider: the real cfg() normalizes
        # ``settings: []`` at the top level, but a patched/odd one used to
        # AttributeError ``.get`` and 500 GET /api/smart.
        with mock.patch.object(
            smart_test_svc, "cfg", return_value={"settings": ["oops"]},
        ):
            response = self._get()
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertEqual(response.json()["schedule"]["interval"], "off")

    def test_schedule_due_survives_a_non_mapping_settings(self):
        # The same raise used to escape the scheduler tick and silently
        # stop every scheduled self-test.
        with mock.patch.object(
            smart_test_svc, "cfg", return_value={"settings": "junk"},
        ):
            self.assertFalse(smart_test_svc.schedule_due())


class SmartActionRoutesCodedRefusalTests(unittest.TestCase):
    """The action routes answer coded 4xx for hostile bodies, never raw 500s."""

    def _admin(self):
        return mock.patch.object(
            nas_storage, "require_admin_browser", return_value="admin",
        )

    def _no_smartctl(self):
        return mock.patch.object(
            smart_test_svc, "sh", return_value=(1, "", ""),
        )

    def test_surrogate_device_is_a_coded_400(self):
        # json.loads accepts the escaped lone surrogate, so the service
        # really sees "\ud800"; the coded bad_device must answer.
        with self._admin(), self._no_smartctl():
            response = _client().post(
                "/api/smart/test",
                content=b'{"device": "\\ud800", "kind": "short"}',
                headers={"Content-Type": "application/json"},
            )
        self.assertEqual(response.status_code, 400, response.text[:300])
        response.text.encode("utf-8")
        self.assertNotIn("\ud800", response.text)

    def test_huge_device_string_is_a_coded_400(self):
        with self._admin(), self._no_smartctl():
            response = _client().post(
                "/api/smart/test",
                json={"device": "/dev/disk" + "9" * 5000, "kind": "short"},
            )
        self.assertEqual(response.status_code, 400, response.text[:300])

    def test_abort_surrogate_device_is_a_coded_400(self):
        with self._admin(), self._no_smartctl():
            response = _client().post(
                "/api/smart/abort",
                content=b'{"device": "\\udfff"}',
                headers={"Content-Type": "application/json"},
            )
        self.assertEqual(response.status_code, 400, response.text[:300])
        response.text.encode("utf-8")

    def test_schedule_surrogates_are_a_coded_400(self):
        with self._admin(), self._no_smartctl():
            response = _client().put(
                "/api/smart/schedule",
                content=(
                    b'{"interval": "\\ud800", "kind": "x",'
                    b' "devices": ["\\ud800"]}'
                ),
                headers={"Content-Type": "application/json"},
            )
        self.assertEqual(response.status_code, 400, response.text[:300])
        response.text.encode("utf-8")

    def test_over_cap_history_limit_is_a_coded_422(self):
        response = _client().get("/api/smart/history?limit=" + "9" * 5000)
        self.assertEqual(response.status_code, 422, response.text[:300])
        response.text.encode("utf-8")


if __name__ == "__main__":
    unittest.main()
