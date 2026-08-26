"""Fourth leftover-500s sweep of the Tools page, over the real mounted app.

The hunted classes (lone UTF-8 surrogates in keys AND values, the CPython
4300-digit int cap — including the plist hex form that loads uncapped through
``int(x, 16)`` and so arrives *already-int* — numeric ids, huge-number JSON
bodies where ``json.loads`` raises ValueError not JSONDecodeError,
vanished-CLI classification) were re-reproduced against the routes the Tools
page mounts:

    GET  /api/tools/hardware        (Hardware tab: profiler sections + disks)
    GET  /api/tools/syslog          (Syslog tab)
    GET  /api/system/scheduler      (Scheduler tab, timers table)
    GET  /api/tools/agents          (Scheduler tab, agents table)
    GET  /api/docker/df             (Docker tab)
    POST /api/tools/docker/prune    (Docker tab's cleanup buttons)
    POST /api/tools/net/ping        (Network tab)
    POST /api/tools/net/dns         (Network tab)
    GET  /api/tools/updates         (Updates tab)
    GET  /api/system/diagnostics    (System info tab)
    GET  /api/tools/about           (About tab)

One live leak was found and is fixed with this battery:

* GET /api/tools/hardware copied six fields of each ``list_power_disks`` row
  raw into its payload.  ``disk_power_svc`` sanitizes its own fields today,
  but the boundary trusted that cross-module contract wholesale, so one
  leftover ``\\ud800`` disk name, inf/over-cap ``size_gb`` or bytes
  ``power_state`` 500'd the route at Starlette's encode — outside the
  ``except`` around the listing — and the poisoned payload then sat in
  ``_hw_cache``, re-serving that 500 for the full 5-minute TTL with the four
  profiler sections wiped alongside (the sibling-wipe class).  The subset
  builder now scrubs per field (``_power_disk_row``), so a poisoned row
  costs itself one field, its clean siblings survive, and the cache holds a
  renderable payload.

Every other route above was already immune at the service layer (the
tools_svc ``_as_text`` wrap, ``_plist_int`` / ``_plist_jsonable``, the
``parse_int_capped`` GitHub reader, ``soft_fail``'s param scrub, FastAPI's
body-parse 400) — but those pins drive the service functions directly.  This
battery pins the whole cycle through ``create_app()`` so the immunity cannot
silently regress at the layer the SPA actually polls: request routing,
Pydantic body/query parsing, the audit hook on the mutating routes, and
Starlette's strict UTF-8 render of the final body.
"""
from __future__ import annotations

import io
import json
import plistlib
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from hub import tools_svc
from hub.app_factory import create_app
from hub.auth import require_auth
from hub.routers import system_extra

#: Built arithmetically: int("9" * 5000) itself trips the digit cap.
_HUGE_INT = 16 ** 5000
_HUGE_DIGITS = "9" * 5000

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


def _clean(response) -> None:
    """The body decoded, carries no lone surrogate, and re-encodes as UTF-8."""
    text = response.text
    assert "\ud800" not in text and "\udc80" not in text, text[:300]
    text.encode("utf-8")


class HardwarePoisonedDiskRowHttpTests(unittest.TestCase):
    """GET /api/tools/hardware: the live leak this sweep found and fixed."""

    #: One row carrying every leftover shape at once, next to a clean sibling.
    _POISON_ROW = {
        "id": "disk4", "name": "u\ud800sb", "size_gb": float("inf"),
        "ssd": None, "power_state": b"as\xffleep", "system": False,
    }
    _CLEAN_ROW = {
        "id": "disk0", "name": "APPLE SSD", "size_gb": 494.4,
        "ssd": True, "power_state": "active", "system": True,
    }

    def setUp(self):
        tools_svc._hw_cache.update(t=0.0, v=None)
        self.addCleanup(tools_svc._hw_cache.update, t=0.0, v=None)

    def _get(self, rows):
        with (
            mock.patch.object(tools_svc, "sh", lambda *a, **k: (0, "Chip: M1", "")),
            mock.patch("hub.disk_power_svc.list_power_disks", lambda: rows),
        ):
            return _client().get("/api/tools/hardware")

    def test_poisoned_row_is_http_200_and_costs_only_its_own_fields(self):
        response = self._get([dict(self._POISON_ROW), dict(self._CLEAN_ROW)])
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        disks = response.json()["disks"]
        self.assertEqual(len(disks), 2)
        self.assertEqual(disks[0]["name"], "u?sb")
        self.assertIsNone(disks[0]["size_gb"])
        self.assertEqual(disks[0]["power_state"], "as\ufffdleep")
        # The clean sibling row survives untouched (the sibling-wipe class).
        self.assertEqual(disks[1], dict(self._CLEAN_ROW))

    def test_profiler_sections_survive_the_poisoned_row(self):
        payload = self._get([dict(self._POISON_ROW)]).json()
        sections = payload["sections"]
        self.assertEqual(sorted(sections), ["hardware", "memory", "power", "storage"])
        self.assertTrue(all(s["ok"] for s in sections.values()))

    def test_over_cap_hex_size_and_numeric_id_degrade_per_field(self):
        """A plist-hex over-cap int arrives already-int (str() probe drops
        it); a numeric id coerces via the same probe instead of dropping."""
        response = self._get([{
            "id": 4, "name": "usb", "size_gb": _HUGE_INT,
            "ssd": False, "power_state": "idle", "system": False,
        }])
        self.assertEqual(response.status_code, 200, response.text[:300])
        row = response.json()["disks"][0]
        self.assertEqual(row["id"], "4")
        self.assertIsNone(row["size_gb"])
        self.assertEqual(row["name"], "usb")

    def test_non_dict_row_drops_alone(self):
        response = self._get(["junk", dict(self._CLEAN_ROW)])
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertEqual(response.json()["disks"], [dict(self._CLEAN_ROW)])

    def test_the_cached_payload_is_left_clean_for_the_next_reader(self):
        """The old shape re-served the 500 from _hw_cache for 5 minutes."""
        first = self._get([dict(self._POISON_ROW)])
        self.assertEqual(first.status_code, 200, first.text[:300])
        cached = tools_svc._hw_cache["v"]
        json.dumps(cached, ensure_ascii=False, allow_nan=False).encode("utf-8")
        # And the next HTTP reader (a TTL hit, no rebuild) serves it clean.
        def boom(*_a, **_k):
            raise AssertionError("a cache hit must not rebuild")

        with mock.patch("hub.disk_power_svc.list_power_disks", boom):
            second = _client().get("/api/tools/hardware")
        self.assertEqual(second.status_code, 200, second.text[:300])
        _clean(second)

    def test_renderable_number_probe(self):
        self.assertIsNone(tools_svc._renderable_number(_HUGE_INT))
        self.assertIsNone(tools_svc._renderable_number(float("inf")))
        self.assertIsNone(tools_svc._renderable_number(float("nan")))
        self.assertIsNone(tools_svc._renderable_number(True))
        self.assertIsNone(tools_svc._renderable_number("494"))
        self.assertEqual(tools_svc._renderable_number(494.4), 494.4)
        self.assertEqual(tools_svc._renderable_number(16), 16)


class SyslogHttpTests(unittest.TestCase):
    """GET /api/tools/syslog: hostile `log show` output and hostile queries."""

    def setUp(self):
        tools_svc._syslog_cache.clear()
        self.addCleanup(tools_svc._syslog_cache.clear)

    def test_surrogate_bytes_from_log_show_render_scrubbed(self):
        hostile = b"Timestamp Thread\nl\xed\xa0\x80ine one\nline t\xffwo\n"
        with mock.patch.object(tools_svc, "sh", lambda *a, **k: (0, hostile, None)):
            response = _client().get("/api/tools/syslog?minutes=5&limit=10&force=true")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        payload = response.json()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["lines"], ["l\ufffd\ufffd\ufffdine one", "line t\ufffdwo"])

    def test_none_sh_leftovers_are_a_readable_failure(self):
        with mock.patch.object(tools_svc, "sh", lambda *a, **k: (None, None, None)):
            response = _client().get("/api/tools/syslog?minutes=6&limit=10&force=true")
        self.assertEqual(response.status_code, 200, response.text[:300])
        payload = response.json()
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["lines"], [])

    def test_huge_digit_minutes_is_the_parse_422_not_500(self):
        response = _client().get("/api/tools/syslog?minutes=" + _HUGE_DIGITS)
        self.assertEqual(response.status_code, 422, response.text[:300])
        _clean(response)


class LaunchdPlistOnDiskHttpTests(unittest.TestCase):
    """GET /api/system/scheduler and /api/tools/agents with a real hex plist
    on disk — the over-cap int arrives already-int through plistlib."""

    #: plistlib routes 0x text through int(raw, 16), which the conversion
    #: limit does not apply to; plistlib.dumps refuses the value on write,
    #: so the file is spelled by hand exactly as a leftover would be.
    _HEX_PLIST = (
        b'<?xml version="1.0" encoding="UTF-8"?><plist version="1.0">'
        b"<dict><key>Label</key><integer>42</integer>"
        b"<key>StartInterval</key><integer>0x" + b"f" * 5000 + b"</integer>"
        b"<key>ProgramArguments</key><array><string>true</string></array>"
        b"</dict></plist>"
    )

    def _routes(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        agents = Path(tmp.name)
        (agents / "poisoned.plist").write_bytes(self._HEX_PLIST)
        (agents / "healthy.plist").write_bytes(plistlib.dumps({
            "Label": "good.job", "StartInterval": 60,
            "ProgramArguments": ["/usr/bin/true"],
        }))
        client = _client()
        with mock.patch.object(
            tools_svc.os.path, "expanduser", return_value=str(agents),
        ):
            return client.get("/api/system/scheduler"), client.get("/api/tools/agents")

    def test_hex_interval_costs_its_field_not_its_siblings(self):
        scheduler, agents = self._routes()
        self.assertEqual(scheduler.status_code, 200, scheduler.text[:300])
        self.assertEqual(agents.status_code, 200, agents.text[:300])
        _clean(scheduler)
        _clean(agents)
        # Timers: the poisoned entry has nothing renderable to schedule by,
        # so it is skipped; the healthy sibling survives (numeric Label falls
        # back to the stem for the poisoned row on the agents table).
        timers = scheduler.json()["timers"]
        self.assertEqual([t["label"] for t in timers], ["good.job"])
        self.assertEqual(timers[0]["interval_sec"], 60)
        rows = {a["label"]: a for a in agents.json()["agents"]}
        self.assertEqual(sorted(rows), ["good.job", "poisoned"])
        self.assertIsNone(rows["poisoned"]["interval_sec"])
        self.assertEqual(rows["good.job"]["interval_sec"], 60)


class DockerRoutesHttpTests(unittest.TestCase):
    """GET /api/docker/df and POST /api/tools/docker/prune."""

    def setUp(self):
        tools_svc.docker_disk_usage.invalidate()
        self.addCleanup(tools_svc.docker_disk_usage.invalidate)

    def test_vanished_cli_df_and_prune_stay_the_coded_engine_down_shapes(self):
        with (
            mock.patch.object(tools_svc, "engine_up", lambda force=False: not force),
            mock.patch.object(tools_svc, "docker", lambda *a, **k: (-1, "", "not found")),
            mock.patch.object(tools_svc, "cli_on_disk", lambda: False),
        ):
            df = _client().get("/api/docker/df")
            tools_svc.docker_disk_usage.invalidate()
            prune = _client().post(
                "/api/tools/docker/prune", json={"what": "dangling", "confirm": True},
            )
        self.assertEqual(df.status_code, 200, df.text[:300])
        self.assertEqual(df.json(), {"engine_up": False, "raw": "", "lines": []})
        self.assertEqual(prune.status_code, 200, prune.text[:300])
        detail = prune.json()
        self.assertFalse(detail["ok"])
        self.assertEqual(detail["code"], "container.engine_down")

    def test_surrogate_escape_what_echoes_back_scrubbed_in_the_soft_fail(self):
        """A ``\\ud800`` JSON escape decodes to a real lone surrogate through
        request.json(); the coded bad_prune echo must scrub it, and the audit
        hook the route runs afterwards must not raise either."""
        with (
            mock.patch.object(tools_svc, "engine_up", lambda force=False: True),
            mock.patch.object(system_extra.audit, "record") as record,
        ):
            response = _client().post(
                "/api/tools/docker/prune",
                content=b'{"what": "da\\ud800ngling", "confirm": true}',
                headers={"content-type": "application/json"},
            )
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        payload = response.json()
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["code"], "tools.bad_prune")
        self.assertEqual(payload["params"]["what"], "da?ngling")
        record.assert_called_once()

    def test_huge_int_literal_in_the_body_is_the_parse_400_not_500(self):
        # json.loads raises the digit-cap ValueError (not JSONDecodeError);
        # the body-parse guard must map it to 400, never a 500.
        response = _client().post(
            "/api/tools/docker/prune",
            content=b'{"what": ' + b"9" * 5000 + b', "confirm": true}',
            headers={"content-type": "application/json"},
        )
        self.assertEqual(response.status_code, 400, response.text[:300])

    def test_the_executed_prune_still_writes_its_audit_line(self):
        with (
            mock.patch.object(tools_svc, "engine_up", lambda force=False: True),
            mock.patch.object(
                tools_svc, "docker", lambda *a, **k: (0, "Total reclaimed space: 0B", ""),
            ),
            mock.patch.object(system_extra.audit, "record") as record,
        ):
            response = _client().post(
                "/api/tools/docker/prune", json={"what": "dangling", "confirm": True},
            )
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertTrue(response.json()["ok"])
        record.assert_called_once()
        self.assertEqual(record.call_args.kwargs.get("kind"), "dangling")


class NetToolsHttpTests(unittest.TestCase):
    """POST /api/tools/net/ping and /api/tools/net/dns."""

    def test_surrogate_host_is_the_coded_soft_fail_with_no_echo(self):
        for path, body in (
            ("/api/tools/net/ping", b'{"host": "8.8.8\\ud800.8"}'),
            ("/api/tools/net/dns", b'{"name": "x\\ud800y.example"}'),
        ):
            response = _client().post(
                path, content=body, headers={"content-type": "application/json"},
            )
            self.assertEqual(response.status_code, 200, response.text[:300])
            _clean(response)
            payload = response.json()
            self.assertFalse(payload["ok"])
            self.assertEqual(payload["code"], "tools.bad_host")

    def test_huge_int_count_body_is_the_parse_400_not_500(self):
        response = _client().post(
            "/api/tools/net/ping",
            content=b'{"host": "8.8.8.8", "count": ' + b"9" * 5000 + b"}",
            headers={"content-type": "application/json"},
        )
        self.assertEqual(response.status_code, 400, response.text[:300])

    def test_rfc_infinity_count_is_the_validation_422_not_500(self):
        response = _client().post(
            "/api/tools/net/ping",
            content=b'{"host": "8.8.8.8", "count": 1e999}',
            headers={"content-type": "application/json"},
        )
        self.assertEqual(response.status_code, 422, response.text[:300])
        _clean(response)


class _FakeResp:
    def __init__(self, body: bytes):
        self._body = body

    def read(self, n=-1):
        return self._body

    def close(self):
        pass


class _FakeOpener:
    def __init__(self, latest=None):
        self._latest = latest

    def open(self, req, timeout=None):
        if "/releases/latest" in req.full_url and self._latest is not None:
            return _FakeResp(self._latest)
        raise urllib.error.HTTPError(
            req.full_url, 404, "Not Found", {}, io.BytesIO(b"404"),
        )


class UpdatesHttpTests(unittest.TestCase):
    """GET /api/tools/updates with a poisoned GitHub payload and hostile
    brew / softwareupdate leftovers, through the whole cycle."""

    def setUp(self):
        tools_svc._updates_cache.update(t=0.0, v=None)
        tools_svc._github_cache.update(t=0.0, v=None)
        self.addCleanup(tools_svc._updates_cache.update, t=0.0, v=None)
        self.addCleanup(tools_svc._github_cache.update, t=0.0, v=None)

    def test_huge_release_id_and_hostile_probes_keep_the_card_200(self):
        latest = (
            '{"tag_name": "v9.9.9",'
            ' "html_url": "https://github.com/elvin-li/ServerHub/releases/tag/v9.9.9",'
            ' "body": "no\\ud800tes", "published_at": "2026-01-01",'
            ' "id": ' + "1" * 5000 + "}"
        ).encode()

        def hostile_sh(argv, **kwargs):
            # brew / softwareupdate / git leftovers: bytes with junk, None err.
            return 0, b"pkg 1.0 \xed\xa0\x80 1.1\n", None

        with (
            # The route's first act is starting the warmer thread; keep the
            # suite free of a 25s-delayed background probe.
            mock.patch.object(tools_svc, "start_updates_warmer", lambda *a, **k: None),
            mock.patch("hub.http_guard.no_redirect_opener",
                       return_value=_FakeOpener(latest=latest)),
            mock.patch.object(tools_svc, "sh", hostile_sh),
        ):
            response = _client().get("/api/tools/updates?force=true")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        payload = response.json()
        github = payload["github"]
        # One unrenderable number wiped the whole card before the
        # parse_int_capped reader; the fields the card renders survive.
        self.assertTrue(github["ok"])
        self.assertEqual(github["tag"], "v9.9.9")
        self.assertEqual(github["notes"], "no?tes")
        self.assertIn("brew", payload)
        self.assertIn("macos", payload)


class DiagnosticsAboutHttpTests(unittest.TestCase):
    """GET /api/system/diagnostics and /api/tools/about, whole cycle."""

    def test_huge_sysctl_digits_are_http_200(self):
        with (
            mock.patch.object(tools_svc, "sh", lambda *a, **k: (0, _HUGE_DIGITS, "")),
            mock.patch.object(tools_svc, "engine_up", lambda force=False: False),
        ):
            response = _client().get("/api/system/diagnostics")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        payload = response.json()
        # >4300-digit hw.ncpu / hw.memsize: ValueError at int(), dropped.
        self.assertIsNone(payload["ncpu"])
        self.assertIsNone(payload["mem_gb"])

    def test_about_with_surrogate_base_is_http_200(self):
        with mock.patch.object(tools_svc, "BASE", "/srv/hu\ud800b"):
            response = _client().get("/api/tools/about")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        self.assertEqual(response.json()["base"], "/srv/hu?b")


if __name__ == "__main__":
    unittest.main()
