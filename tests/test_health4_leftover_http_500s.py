"""Fourth leftover-500s sweep of the Health page, over the real mounted app.

The hunted classes (lone UTF-8 surrogates in keys AND values, the CPython
4300-digit int cap — including the YAML/plist hex form that loads uncapped
through ``int(x, 16)`` and so arrives *already-int* — huge-number JSON where
``json.loads`` raises ValueError not JSONDecodeError, numeric ids through a
str() probe) were re-reproduced against GET /api/health/checks, the one
route web/src/views/Health.vue mounts.  Two live leftovers surfaced:

* ``_fresh_snapshot`` subtracted ``_cache["t"]`` bare: an over-cap int (or
  any non-number) planted in the cache timestamp made ``time.time() - t``
  OverflowError/TypeError and 500'd GET /api/health/checks on *every*
  request — unlike the ``v`` poisonings, which ``_serve_cached`` already
  re-sanitized, there was no recovery until restart.  An unusable timestamp
  now counts as expired, and the cold collection rewrites both keys.
* ``_nginx_pair`` rendered ``f"running pid={ngx.get('pid')} …"`` inside the
  pair-wide try that exists for "nginx not installed".  health_svc does not
  own the overview dict (nginx_svc's ``_pid_text`` guards its own payload,
  but a patched/odd provider can answer any shape), so an already-int
  over-cap pid/site_count ValueError'd str() there — a *running* nginx then
  collapsed into the combined not-installed error row with the digit-cap
  exception text as its detail, and the config-syntax sibling silently
  vanished.  ``(message or "")[:160]`` TypeError'd an int message into the
  same collapse.  Per-field ``_as_text`` now costs a leftover only itself.

The rest of the battery pins the already-immune corners of the *cold*
collection over ``create_app()`` (dash4 pinned only the TTL-hit path):
poisoned on-disk LaunchAgent plists, a poisoned brew disk journal read
through the real ``json.loads`` hook, surrogate-bytes smartctl output, an
over-cap SERVERHUB_PORT, and raw Immich/Ollama check rows that bypass
``_check`` entirely.
"""
from __future__ import annotations

import json
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from fastapi.testclient import TestClient

from hub import brew_cache, health_svc
from hub.app_factory import create_app
from hub.auth import require_auth

#: The hex spelling parses uncapped (``int(x, 16)``), so a live over-cap int
#: really can exist in memory; only rendering it back is impossible.
_HUGE_HEX = "0x" + "F" * 5000
_HUGE_INT = int("F" * 5000, 16)
#: A lone surrogate, as os.environ / surrogateescape decodes produce.
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


class _HealthCacheSandbox(unittest.TestCase):
    """Save/restore the module cache so poisonings cannot leak between tests."""

    def setUp(self):
        saved = dict(health_svc._cache)
        self.addCleanup(lambda: health_svc._cache.update(saved))
        health_svc._cache.update(t=0.0, v=None)


class CacheTimestampLeftoverTests(_HealthCacheSandbox):
    """An unusable ``_cache["t"]`` must count as expired, never 500."""

    _CLEAN_SNAPSHOT = {
        "ts": "now",
        "summary": {"ok": 1, "warn": 0, "error": 0, "total": 1},
        "checks": [{"id": "x", "name": "X", "level": "ok", "ok": True,
                    "detail": "", "fix": ""}],
        "healthy": True,
    }

    def test_over_cap_int_timestamp_is_http_200_not_500(self):
        health_svc._cache.update(t=_HUGE_INT, v=dict(self._CLEAN_SNAPSHOT))
        response = _client().get("/api/health/checks")
        self.assertEqual(response.status_code, 200, response.text[:300])
        response.text.encode("utf-8")

    def test_garbage_timestamp_is_http_200_not_500(self):
        health_svc._cache.update(t="not-a-time", v=dict(self._CLEAN_SNAPSHOT))
        response = _client().get("/api/health/checks")
        self.assertEqual(response.status_code, 200, response.text[:300])

    def test_the_collection_heals_the_poisoned_timestamp(self):
        health_svc._cache.update(t=_HUGE_INT, v=dict(self._CLEAN_SNAPSHOT))
        _client().get("/api/health/checks")
        stamp = health_svc._cache["t"]
        self.assertIsInstance(stamp, float)
        self.assertLessEqual(stamp, time.time())

    def test_fresh_snapshot_treats_unusable_t_as_expired(self):
        health_svc._cache.update(t=_HUGE_INT, v=dict(self._CLEAN_SNAPSHOT))
        self.assertIsNone(health_svc._fresh_snapshot())

    def test_inf_timestamp_still_serves_the_cached_hit(self):
        # inf subtracts finitely (-inf age): the everlasting-hit shape other
        # suites lean on for "serve from cache, never rebuild" must survive
        # the new guard.
        health_svc._cache.update(t=float("inf"), v=dict(self._CLEAN_SNAPSHOT))
        response = _client().get("/api/health/checks")
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertEqual(response.json()["ts"], "now")


class NginxPairFieldGuardTests(_HealthCacheSandbox):
    """A render leftover costs its own field, never the pair."""

    def _pair(self, overview, test={"ok": True, "message": "ok"}):
        with (
            mock.patch.object(health_svc, "nginx_overview", return_value=overview),
            mock.patch.object(health_svc, "nginx_test", return_value=test),
        ):
            return health_svc._nginx_pair()

    def test_over_cap_pid_keeps_the_running_row_and_its_sibling(self):
        rows = self._pair({"running": True, "pid": _HUGE_INT, "site_count": 3})
        self.assertEqual([r["id"] for r in rows], ["nginx", "nginx_conf"])
        self.assertTrue(rows[0]["ok"])
        self.assertEqual(rows[0]["detail"], "running pid=? · sites 3")
        json.dumps(rows, ensure_ascii=False, allow_nan=False).encode("utf-8")

    def test_over_cap_site_count_drops_only_its_field(self):
        rows = self._pair({"running": True, "pid": "42", "site_count": _HUGE_INT})
        self.assertEqual(rows[0]["detail"], "running pid=42 · sites ?")
        self.assertTrue(rows[0]["ok"])

    def test_int_config_message_keeps_the_conf_row(self):
        rows = self._pair(
            {"running": True, "pid": "42", "site_count": 2},
            test={"ok": False, "message": _HUGE_INT},
        )
        self.assertEqual(rows[1]["id"], "nginx_conf")
        self.assertFalse(rows[1]["ok"])
        self.assertEqual(rows[1]["detail"], "")
        json.dumps(rows, ensure_ascii=False, allow_nan=False).encode("utf-8")

    def test_surrogate_message_replace_encodes(self):
        rows = self._pair(
            {"running": True, "pid": "42", "site_count": 2},
            test={"ok": False, "message": "unexpected \ud800 token"},
        )
        self.assertEqual(rows[1]["detail"], "unexpected ? token")

    def test_not_installed_still_collapses_to_the_single_error_row(self):
        # The pair-wide try exists for this: no nginx at all is one error,
        # not one error plus a redundant config-syntax failure.
        with mock.patch.object(
            health_svc, "nginx_overview", side_effect=RuntimeError("no nginx"),
        ):
            rows = health_svc._nginx_pair()
        self.assertEqual([r["id"] for r in rows], ["nginx"])

    def test_the_mounted_route_serves_both_rows_at_200(self):
        with (
            mock.patch.object(
                health_svc, "nginx_overview",
                return_value={"running": True, "pid": _HUGE_INT, "site_count": 3},
            ),
            mock.patch.object(
                health_svc, "nginx_test",
                return_value={"ok": True, "message": "ok"},
            ),
            mock.patch.object(health_svc, "sh", return_value=(1, "", "")),
        ):
            response = _client().get("/api/health/checks")
        self.assertEqual(response.status_code, 200, response.text[:300])
        rows = {c["id"]: c for c in response.json()["checks"]}
        self.assertIn("nginx", rows)
        self.assertIn("nginx_conf", rows)
        self.assertTrue(rows["nginx"]["ok"])
        self.assertNotIn("4300", rows["nginx"]["detail"])


class ColdCollectPoisonedDiskHttpTests(_HealthCacheSandbox):
    """Stays immune: the cold seven-way collection over hostile on-disk state.

    One request carries every disk-borne leftover at once: a hex over-cap
    ``<integer>`` Label (parses past the digit cap, scrubs to "" — the row
    must fall back to the plist filename, not vanish), a ``<data>`` bytes
    Label, an over-cap int nested in a KeepAlive dict, a >4300-digit number
    inside the brew disk journal (``json.loads`` raises ValueError, not
    JSONDecodeError — the parse_int hook must keep the document, so
    postgresql@18 still renders), surrogate bytes on smartctl's stdout, and
    an over-cap SERVERHUB_PORT.
    """

    def setUp(self):
        super().setUp()
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.agents = Path(tmp.name) / "agents"
        self.agents.mkdir(parents=True)
        header = (
            '<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0">'
        )
        (self.agents / "local.poison.plist").write_text(
            header + "<dict>"
            "<key>Label</key><integer>" + _HUGE_HEX + "</integer>"
            "<key>KeepAlive</key><true/>"
            "</dict></plist>",
            encoding="utf-8",
        )
        (self.agents / "local.bytes.plist").write_text(
            header + "<dict>"
            "<key>Label</key><data>/w==</data>"  # 0xff: undecodable byte
            "<key>KeepAlive</key><true/>"
            "</dict></plist>",
            encoding="utf-8",
        )
        (self.agents / "local.hugeival.plist").write_text(
            header + "<dict>"
            "<key>Label</key><string>local.hugeival</string>"
            "<key>KeepAlive</key><dict><key>SuccessfulExit</key>"
            "<integer>" + _HUGE_HEX + "</integer></dict>"
            "</dict></plist>",
            encoding="utf-8",
        )

        # Poisoned brew journal at the real DATA_DIR path; module cache
        # cleared so the read is forced through json.loads + the parse_int
        # hook.  brew's own subprocess is stubbed to the vanished sentinel so
        # a host that *does* have brew cannot answer live rows instead.
        self._saved_brew = dict(brew_cache._cache)
        self._saved_disk_ok = brew_cache._disk_ok
        try:
            self._saved_journal = brew_cache._DISK.read_bytes()
        except OSError:
            self._saved_journal = None
        self.addCleanup(self._restore_brew)
        brew_cache._DISK.parent.mkdir(parents=True, exist_ok=True)
        brew_cache._DISK.write_text(
            '[{"name": "postgresql@18", "status": "started", "exit_code": '
            + "9" * 5000 + '},\n {"name": "mosquitto", "status": "none"}]',
            encoding="utf-8",
        )
        brew_cache._cache.update(t=0.0, v=None)
        brew_cache._disk_ok = True

    def _restore_brew(self):
        brew_cache._cache.update(self._saved_brew)
        brew_cache._disk_ok = self._saved_disk_ok
        if self._saved_journal is None:
            try:
                brew_cache._DISK.unlink()
            except OSError:
                pass
        else:
            brew_cache._DISK.write_bytes(self._saved_journal)

    def _get(self):
        with (
            mock.patch.object(health_svc, "AGENTS_DIR", str(self.agents)),
            mock.patch("hub.stale_runtime.AGENTS_DIR", str(self.agents)),
            mock.patch.object(
                health_svc, "sh",
                return_value=(
                    0,
                    b"SMART overall-health self-assessment test result: "
                    b"PASSED \xed\xa0\x80",
                    b"",
                ),
            ),
            mock.patch.object(
                brew_cache, "sh", return_value=(-1, "", "not found"),
            ),
            mock.patch.object(brew_cache, "_brew_busy", return_value=False),
            mock.patch.dict("os.environ", {"SERVERHUB_PORT": "9" * 5000}),
        ):
            return _client().get("/api/health/checks")

    def test_the_whole_zoo_is_http_200_with_a_clean_utf8_body(self):
        response = self._get()
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertNotIn("\ud800", response.text)
        self.assertNotIn(_SURROGATE, response.text)
        response.text.encode("utf-8")

    def test_each_leftover_costs_only_its_own_field(self):
        payload = self._get().json()
        ids = [c["id"] for c in payload["checks"]]
        # Hex over-cap Label fell back to the filename instead of dropping
        # its KeepAlive warning; the bytes Label decoded with replacement;
        # the over-cap int inside the KeepAlive dict stayed truthy.
        self.assertIn("la_local.poison", ids)
        self.assertIn("la_local.hugeival", ids)
        self.assertIn("la_\ufffd", ids)
        # The huge exit_code cost only itself: both journal rows survived the
        # ValueError-not-JSONDecodeError parse, postgresql@18 included.
        self.assertIn("brew_postgresql@18", ids)
        self.assertIn("brew_mosquitto", ids)
        # Over-cap SERVERHUB_PORT fell back to the default panel port.
        self.assertIn("port_8086", ids)
        # Surrogate smartctl stdout replace-encoded into the SMART row.
        smart = next(c for c in payload["checks"] if c["id"] == "smart_disk0")
        self.assertTrue(smart["ok"])
        self.assertNotIn("\ud800", smart["detail"])


class ColdCollectPoisonedModuleRowsHttpTests(_HealthCacheSandbox):
    """Stays immune: Immich/Ollama rows bypass ``_check`` — the final
    ``_jsonable`` pass is the only thing between them and Starlette."""

    _POISON_ROWS = [
        {
            "id": "im" + _SURROGATE, "name": b"na\xffme", "level": "warn",
            "ok": False, "detail": _HUGE_INT, ("k" + _SURROGATE): float("inf"),
        },
        "not-a-dict",
    ]

    def _get(self):
        with (
            mock.patch(
                "hub.immich_svc.run_checks",
                return_value={"checks": list(self._POISON_ROWS)},
            ),
            mock.patch(
                "hub.ollama_svc.health_checks",
                return_value=[{"id": "ol", "ok": True, "resident": _HUGE_INT}],
            ),
            mock.patch.object(health_svc, "sh", return_value=(1, "", "")),
        ):
            return _client().get("/api/health/checks")

    def test_raw_rows_render_scrubbed_at_200(self):
        response = self._get()
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertNotIn(_SURROGATE, response.text)
        response.text.encode("utf-8")
        checks = response.json()["checks"]
        immich = next(c for c in checks if isinstance(c, dict) and c.get("id") == "im?")
        self.assertEqual(immich["name"], "na\ufffdme")
        self.assertIsNone(immich["detail"])       # over-cap int dropped
        self.assertIsNone(immich["k?"])           # inf dropped, key scrubbed
        ollama = next(c for c in checks if isinstance(c, dict) and c.get("id") == "ol")
        self.assertIsNone(ollama["resident"])

    def test_the_summary_still_counts_the_renderable_rows(self):
        payload = self._get().json()
        summary = payload["summary"]
        self.assertIsInstance(summary["total"], int)
        self.assertGreaterEqual(summary["warn"], 1)


if __name__ == "__main__":
    unittest.main()
