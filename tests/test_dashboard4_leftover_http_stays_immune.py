"""Fourth leftover-500s sweep of the Dashboard, over the real mounted app.

The hunted classes (lone UTF-8 surrogates in keys AND values, the CPython
4300-digit int cap — including the YAML hex form that loads uncapped through
``int(x, 16)`` and so arrives *already-int* — numeric YAML ids, huge-number
JSON bodies where ``json.loads`` raises ValueError not JSONDecodeError,
vanished-CLI 503-vs-500) were re-reproduced against the routes the Dashboard
page mounts:

    GET  /api/status            (admin build + member filter + member ?force=)
    POST /api/action            (attention-tile start/restart buttons)
    GET  /api/tools/ports       (the Ports tile)
    GET  /api/health/checks     (the Health tile)

No live leak was found: dash3's service-layer hardening (``status._jsonable``
/ ``_name_text``, ``config.load_yaml_int_capped`` + ``panel_locale``'s
guarded str(), ``auth._cfg_text`` over account resources, the confirmed-
vanish 503 in ``actions.run_action``, ``tools_svc._sh``'s ``_as_text`` wrap,
``health_svc._serve_cached``) already covers every vector.  But those pins
all drive ``status._build_status()`` / ``run_action()`` / the parsers
directly — none of them crosses request routing, the auth-derived member
filter, Pydantic body parsing, app_factory's sanitizing handlers, or
Starlette's strict UTF-8 render of the final body.  This battery pins the
whole cycle through ``create_app()`` so the immunity cannot silently regress
at the layer the SPA actually polls:

* a poisoned services.yaml **on disk** (an over-cap hex quick-link port that
  arrives already-int, ``\\ud800`` escapes in a link name AND a mapping key,
  a ``.inf`` port, a YAML timestamp value, a numeric ``groups_order`` id
  next to an over-cap hex one and a nested mapping) costs each field only
  itself on GET /api/status — and the numeric group id still orders its
  group via the str() probe;
* a poisoned discovery row (surrogate id, bytes name, over-cap hex port)
  rides through the same build without 500ing the encode;
* the member GET /api/status filter coerces a numeric YAML resource id
  through the str() probe (the row still matches), drops the over-cap hex
  resource without raising, scrubs surrogates, and keeps admin data
  (system / links / adaptive) off the member payload; member ``?force=true``
  is served from cache and can never trigger a rebuild;
* POST /api/action: a docker CLI that vanished mid-request answers the coded
  503 only after the disk confirm, the same sentinel with the CLI still on
  disk (or the engine probe answering up) keeps the raw uncoded result, a
  >4300-digit int literal in the body is the parse 400 (ValueError, not
  JSONDecodeError), a ``\\ud800`` escape in the target echoes back scrubbed
  in the coded 404, surrogate/bytes stderr renders clean, and the executed
  action still writes its SERVICE_ACTION audit line;
* GET /api/tools/ports survives surrogate lsof columns, drops an over-cap
  port row without dropping its neighbours, renders an over-cap pid (a
  string column) verbatim-scrubbed, and reports a failed/vanished lsof as
  ``ok: false`` with a clean message;
* GET /api/health/checks re-sanitizes a poisoned snapshot on the TTL-hit
  path (over-cap int, inf, bytes, surrogate keys and values) and leaves the
  shared cache object itself clean for the next reader.
"""
from __future__ import annotations

import json
import time
import unittest
from unittest import mock

import yaml
from fastapi.testclient import TestClient

from hub import actions, auth, config, health_svc, status, tools_svc
from hub.app_factory import create_app
from hub.auth import require_auth
from hub.routers import api as api_router

#: The hex spelling parses uncapped (``int(x, 16)``), so a live over-cap int
#: really can exist in memory; only rendering it back is impossible.
_HUGE_HEX = "0x" + "F" * 5000
_HUGE_INT = int("F" * 5000, 16)

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


#: services.yaml as an operator's hand-edit could leave it.  Double-quoted
#: YAML ``\\ud800`` escapes decode to real lone surrogates; ``0xF…`` loads
#: through ``int(x, 16)`` past the digit cap; ``.inf`` is a float; the bare
#: timestamp loads as datetime.  The member account carries a numeric YAML
#: resource id (must still match its row), an over-cap hex one (must drop
#: only itself), and a plain string id.
_POISONED_YAML = """\
settings:
  adaptive: false
  auth:
    enabled: true
    username: admin
    password_hash: "x"
    accounts:
      - username: fam
        password_hash: "y"
        role: member
        resources: [8080, %(huge)s, "plex"]
groups_order: [2024, %(huge)s, {nested: mapping}, "Media"]
quick_links:
  - name: "NAS\\ud800 box"
    url: "http://nas.local"
    port: %(huge)s
  - name: good-link
    url: "http://y"
    port: .inf
    "k\\ud800ey": "v\\ud800al"
    when: 2023-01-02 03:04:05
apps: []
scripts: []
""" % {"huge": _HUGE_HEX}


class _ConfigSandbox(unittest.TestCase):
    """Write the poisoned services.yaml to the real on-disk path, restore after."""

    def setUp(self):
        try:
            self._previous = config.YAML_PATH.read_bytes()
        except OSError:
            self._previous = None
        config.YAML_PATH.parent.mkdir(parents=True, exist_ok=True)
        config.YAML_PATH.write_text(_POISONED_YAML, encoding="utf-8")
        config.reload_cfg()
        self.addCleanup(self._restore_config)
        self._reset_status_cache()
        self.addCleanup(self._reset_status_cache)

    def _restore_config(self):
        if self._previous is None:
            try:
                config.YAML_PATH.unlink()
            except OSError:
                pass
        else:
            config.YAML_PATH.write_bytes(self._previous)
        config.reload_cfg()

    @staticmethod
    def _reset_status_cache():
        status.invalidate_status()
        with status._lock:
            status._status_cache.update(t=0.0, v=None)


class AdminStatusPoisonedConfigHttpTests(_ConfigSandbox):
    """GET /api/status: the on-disk zoo plus a poisoned discovery row."""

    #: One row carrying every discovery-side leftover at once.  Group "2024"
    #: is a *string* here (discovery emits text); the configured order entry
    #: is the YAML *int* 2024 — the str() probe is what joins them.
    _POISON_ROW = {
        "id": "svc\ud800", "name": b"na\xffme", "state": "ok",
        "group": "2024", "port": _HUGE_INT, "actions": ["open", {"x": 1}],
    }

    def _get_status(self):
        with (
            mock.patch.object(status, "discover_launchd", lambda: []),
            mock.patch.object(
                status, "discover_containers",
                lambda: ([dict(self._POISON_ROW)], True),
            ),
            mock.patch.object(status, "discover_vms", lambda: []),
            mock.patch.object(status, "collect_system", lambda: {"load1": 0.1}),
            mock.patch.object(status, "collect_scripts", lambda: []),
            mock.patch.object(status, "collect_apps", lambda up: []),
        ):
            return _client().get("/api/status")

    def test_the_whole_zoo_is_http_200_with_a_clean_utf8_body(self):
        response = self._get_status()
        self.assertEqual(response.status_code, 200, response.text[:300])
        # TestClient already decoded the body; a lone surrogate would only
        # exist if Starlette had emitted one (it refuses — that is the 500).
        self.assertNotIn("\ud800", response.text)
        self.assertNotIn("\udc80", response.text)
        response.text.encode("utf-8")

    def test_quick_link_leftovers_cost_each_field_only_itself(self):
        payload = self._get_status().json()
        links = payload["links"]
        self.assertEqual(len(links), 2)
        self.assertEqual(links[0]["name"], "NAS? box")
        # Over-cap hex int arrived already-int; the str() probe drops it.
        self.assertIsNone(links[0]["port"])
        self.assertEqual(links[0]["url"], "http://nas.local")
        # ``.inf`` drops like NaN; the datetime renders as its isoformat.
        self.assertIsNone(links[1]["port"])
        self.assertEqual(links[1]["when"], "2023-01-02T03:04:05")
        self.assertEqual(links[1]["k?ey"], "v?al")

    def test_numeric_groups_order_id_still_orders_its_group(self):
        payload = self._get_status().json()
        groups = [g["group"] for g in payload["groups"]]
        # The YAML int 2024 coerced through the str() probe and claimed its
        # configured first position; the over-cap hex neighbour and the
        # nested mapping dropped without costing the list.
        self.assertEqual(groups[0], "2024")

    def test_poisoned_discovery_row_renders_sanitized(self):
        payload = self._get_status().json()
        row = payload["groups"][0]["services"][0]
        self.assertEqual(row["id"], "svc?")
        self.assertEqual(row["name"], "na\ufffdme")
        self.assertIsNone(row["port"])
        self.assertEqual(payload["counts"]["ok"], 1)
        self.assertIs(payload["engine_up"], True)


class MemberStatusFilterHttpTests(_ConfigSandbox):
    """GET /api/status as the member account, over a poisoned snapshot."""

    def setUp(self):
        super().setUp()
        snapshot = {
            "version": "9.9", "ts": "12:00:00",
            "groups": [{"group": "Media", "services": [
                {"id": "8080", "name": "num\ud800app", "state": "ok",
                 "port": _HUGE_INT, "actions": ["open"]},
                {"id": "plex", "name": "Plex", "state": "warn",
                 "detail": "de\ud800tail", "actions": ["open", "detail"]},
                {"id": "secret", "name": "Admin only", "state": "down",
                 "actions": ["open"]},
            ]}],
            "system": {"load1": 0.5}, "counts": {"ok": 2},
            "links": [{"name": "admin-link"}], "engine_up": True,
            "adaptive": {"orphan_count": 3},
        }
        # t=inf: every ``now - t < ttl`` check hits, so the member request is
        # served from cache and can never start a discovery build.
        with status._lock:
            status._status_cache.update(t=float("inf"), v=snapshot)

    def _get(self, path="/api/status"):
        with mock.patch.object(auth, "request_username", return_value="fam"):
            return _client().get(path)

    def test_member_view_is_http_200_and_clean(self):
        response = self._get()
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertNotIn("\ud800", response.text)
        response.text.encode("utf-8")

    def test_numeric_resource_id_matches_and_over_cap_drops_only_itself(self):
        payload = self._get().json()
        rows = {
            s["id"]: s
            for g in payload["groups"] for s in g["services"]
        }
        # resources: [8080, 0xF…, "plex"] — the YAML int matched its row via
        # the str() probe; the over-cap hex entry dropped without raising;
        # the unassigned row stayed invisible.
        self.assertEqual(sorted(rows), ["8080", "plex"])
        self.assertEqual(rows["8080"]["name"], "num?app")
        self.assertIsNone(rows["8080"]["port"])
        self.assertEqual(rows["plex"]["detail"], "de?tail")

    def test_admin_data_stays_off_the_member_payload(self):
        payload = self._get().json()
        self.assertEqual(payload["system"], {})
        self.assertEqual(payload["links"], [])
        self.assertEqual(payload["adaptive"], {})
        self.assertEqual(payload["counts"], {"ok": 1, "warn": 1, "down": 0,
                                             "stopped": 0, "unknown": 0})
        problems = [s["id"] for s in payload["problems"]]
        self.assertEqual(problems, ["plex"])

    def test_member_force_is_served_from_cache_never_a_rebuild(self):
        def boom(*_a, **_k):
            raise AssertionError("member ?force= must not start discovery")

        with (
            mock.patch.object(status, "discover_launchd", boom),
            mock.patch.object(status, "discover_containers", boom),
            mock.patch.object(status, "discover_vms", boom),
        ):
            response = self._get("/api/status?force=true")
        self.assertEqual(response.status_code, 200, response.text[:300])


class ActionRouteHttpTests(unittest.TestCase):
    """POST /api/action (the Attention tile's start/restart buttons)."""

    def _act(self, *, sh_result, on_disk, engine, body=None, raw_body=None):
        with (
            mock.patch.object(actions, "registry",
                              lambda: {"web": ("container", {})}),
            mock.patch.object(actions, "sh", lambda *a, **k: sh_result),
            mock.patch.object(actions, "cli_on_disk", lambda: on_disk),
            mock.patch.object(actions, "engine_up", lambda force=False: engine),
        ):
            client = _client()
            if raw_body is not None:
                return client.post(
                    "/api/action", content=raw_body,
                    headers={"content-type": "application/json"},
                )
            return client.post(
                "/api/action",
                json=body or {"target": "web", "action": "stop"},
            )

    def test_vanished_cli_answers_the_coded_503_after_the_disk_confirm(self):
        response = self._act(
            sh_result=(-1, "", "not found"), on_disk=False, engine=False,
        )
        self.assertEqual(response.status_code, 503, response.text[:300])
        self.assertEqual(
            response.json()["detail"]["code"], "container.engine_down",
        )

    def test_sentinel_with_cli_on_disk_keeps_the_raw_uncoded_result(self):
        # A vanished *cwd* produces the identical sentinel; the CLI still on
        # disk must keep the raw result.  The route's failed-action contract
        # is the deliberate menubar-compatible 500 {ok, message} — uncoded,
        # but a clean render, never an unhandled crash.
        response = self._act(
            sh_result=(-1, "", "not found"), on_disk=True, engine=False,
        )
        self.assertEqual(response.status_code, 500, response.text[:300])
        self.assertEqual(
            response.json(), {"ok": False, "message": "not found"},
        )

    def test_running_engine_stays_the_final_arbiter(self):
        response = self._act(
            sh_result=(-1, "", "not found"), on_disk=False, engine=True,
        )
        self.assertEqual(response.status_code, 500, response.text[:300])
        self.assertEqual(
            response.json(), {"ok": False, "message": "not found"},
        )

    def test_surrogate_and_bytes_stderr_render_clean(self):
        response = self._act(
            sh_result=(1, b"", b"bad \xed\xa0\x80 stderr"),
            on_disk=True, engine=True,
        )
        self.assertEqual(response.status_code, 500, response.text[:300])
        self.assertNotIn("\ud800", response.text)
        response.text.encode("utf-8")
        self.assertFalse(response.json()["ok"])

    def test_huge_int_literal_in_the_body_is_the_parse_400_not_500(self):
        # json.loads raises the digit-cap ValueError (not JSONDecodeError);
        # the body-parse guard must map it to 400, never wipe the request
        # into a 500.
        response = self._act(
            sh_result=(0, "", ""), on_disk=True, engine=True,
            raw_body=b'{"target": ' + b"9" * 5000 + b', "action": "stop"}',
        )
        self.assertEqual(response.status_code, 400, response.text[:300])

    def test_surrogate_escape_target_echoes_back_scrubbed_in_the_coded_404(self):
        response = self._act(
            sh_result=(0, "", ""), on_disk=True, engine=True,
            raw_body=b'{"target": "w\\ud800eb", "action": "stop"}',
        )
        self.assertEqual(response.status_code, 404, response.text[:300])
        self.assertNotIn("\ud800", response.text)
        detail = response.json()["detail"]
        self.assertEqual(detail["code"], "actions.unknown_target")
        self.assertEqual(detail["params"]["target"], "w?eb")

    def test_the_executed_action_still_writes_its_audit_line(self):
        with mock.patch.object(api_router.audit, "record") as record:
            response = self._act(
                sh_result=(0, "stopped", ""), on_disk=True, engine=True,
            )
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertTrue(response.json()["ok"])
        record.assert_called_once()
        self.assertEqual(record.call_args.kwargs.get("target"), "web")
        self.assertEqual(record.call_args.kwargs.get("action"), "stop")
        self.assertIs(record.call_args.kwargs.get("ok"), True)


class ToolsPortsHttpTests(unittest.TestCase):
    """GET /api/tools/ports (the Ports tile) with hostile lsof output."""

    _HOSTILE_LSOF = (
        "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n"
        "rap\ud800portd 381 me\ud800 13u IPv4 0xdead 0t0 TCP *:49152 (LISTEN)\n"
        "hugeport 42 me 13u IPv4 0xdead 0t0 TCP *:" + "9" * 5000 + " (LISTEN)\n"
        "bigpid " + "9" * 4400 + " me 13u IPv4 0xdead 0t0 TCP 127.0.0.1:8086 (LISTEN)\n"
    )

    def test_surrogates_scrub_and_the_over_cap_port_row_drops_alone(self):
        with mock.patch.object(
            tools_svc, "sh", lambda *a, **k: (0, self._HOSTILE_LSOF, ""),
        ):
            response = _client().get("/api/tools/ports")
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertNotIn("\ud800", response.text)
        response.text.encode("utf-8")
        payload = response.json()
        self.assertTrue(payload["ok"])
        rows = {r["command"]: r for r in payload["ports"]}
        # The over-cap *port* row dropped alone (int() refused it); the
        # over-cap *pid* is a string column and renders as-is.
        self.assertEqual(sorted(rows), ["bigpid", "rap?portd"])
        self.assertEqual(rows["rap?portd"]["port"], 49152)
        self.assertEqual(rows["rap?portd"]["user"], "me?")
        self.assertEqual(rows["bigpid"]["pid"], "9" * 4400)
        self.assertEqual(payload["count"], 2)

    def test_failed_lsof_reports_ok_false_with_a_clean_message(self):
        with mock.patch.object(
            tools_svc, "sh", lambda *a, **k: (2, "", "ls\ud800of died"),
        ):
            response = _client().get("/api/tools/ports")
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertNotIn("\ud800", response.text)
        payload = response.json()
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["ports"], [])
        self.assertEqual(payload["message"], "ls?of died")

    def test_vanished_lsof_sentinel_stays_a_readable_ok_false(self):
        # Read-only tile: no mutation, so no 503 escalation — the row simply
        # reports the probe failed and the Dashboard renders load_failed.
        with mock.patch.object(
            tools_svc, "sh", lambda *a, **k: (-1, "", "not found"),
        ):
            response = _client().get("/api/tools/ports")
        self.assertEqual(response.status_code, 200, response.text[:300])
        payload = response.json()
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["message"], "not found")


class HealthChecksPoisonedCacheHttpTests(unittest.TestCase):
    """GET /api/health/checks (the Health tile) on the TTL-hit path."""

    def setUp(self):
        self._saved = dict(health_svc._cache)
        self.addCleanup(lambda: health_svc._cache.update(self._saved))
        health_svc._cache.update(t=time.time(), v={
            "ts": "now",
            "summary": {"ok": _HUGE_INT, "warn": float("inf"),
                        "error": 0, "total": 2},
            "checks": [{
                "id": b"ra\xffw", "name": "n\ud800ame", "level": "warn",
                "ok": False, "detail": "d", "\ud800fix": "f",
            }],
            "healthy": True,
        })

    def test_poisoned_snapshot_serves_200_sanitized(self):
        response = _client().get("/api/health/checks")
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertNotIn("\ud800", response.text)
        response.text.encode("utf-8")
        payload = response.json()
        self.assertIsNone(payload["summary"]["ok"])
        self.assertIsNone(payload["summary"]["warn"])
        self.assertEqual(payload["summary"]["error"], 0)
        check = payload["checks"][0]
        self.assertEqual(check["name"], "n?ame")
        self.assertEqual(check["?fix"], "f")
        self.assertEqual(check["id"], "ra\ufffdw")

    def test_the_shared_cache_object_is_left_clean_for_the_next_reader(self):
        _client().get("/api/health/checks")
        # _serve_cached mutates the hit in place when dirty, so the second
        # read (and every single-flight waiter) shares the clean snapshot.
        cached = health_svc._cache["v"]
        json.dumps(cached, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertIsNone(cached["summary"]["ok"])


class YamlHexVectorPin(unittest.TestCase):
    def test_hex_yaml_still_loads_past_the_digit_cap(self):
        """The vector this file leans on: PyYAML routes 0x text through
        int(raw, 16), which the conversion limit does not apply to."""
        loaded = yaml.safe_load("port: " + _HUGE_HEX)
        self.assertIsInstance(loaded["port"], int)
        with self.assertRaises(ValueError):
            str(loaded["port"])


if __name__ == "__main__":
    unittest.main()
