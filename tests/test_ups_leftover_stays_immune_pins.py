"""UPS leftover-500 sweep: every remaining vector probed came back immune,
so these pins hold the line at the HTTP layer.

What this file adds over ``test_ups_leftover_hexint_surrogate_vanish_500s``
(hex script ids, surrogate state *keys*, worker-pid overflow, sudo disk
confirm) and ``test_ups_svc`` / ``test_ups_policy`` (service-level jsonable
drops, the state machine):

* **Request bodies through the real app.**  The sanitizing 422 handler is
  registered by ``create_app`` and only pinned against POST /api/auth/login;
  the UPS routes take numeric bodies where ``1e999`` / ``Infinity`` / lone
  ``"\\ud800"`` escapes / an unknown surrogate *key* under ``extra="forbid"``
  are all echoed back in ``detail[].input`` / ``loc``.  A bare router without
  that handler answers 500 for every one of these — the pin is on the
  wiring, not just the helper.
* **The over-cap body int is a parse-time refusal.**  ``json.loads`` raises
  the digit-cap ValueError before pydantic ever sees a >4300-digit literal,
  so the route answers 4xx; a merely huge (100-digit) ``haltlevel`` parses
  fine and must hit the coded ``ups.halt_bad_level`` 400 *before* any
  ``str(level)`` render could raise.
* **A poisoned state file never 500s GET /api/ups.**  A >4300-digit int
  literal makes ``json.loads`` raise ValueError — and *not* JSONDecodeError,
  which is the exact trap ``_load_state``'s ``except`` must keep covering;
  ``Infinity`` / ``NaN`` literals parse fine and must be dropped from the
  body (Starlette renders with ``allow_nan=False``); junk field shapes
  (int reason, non-dict steps rows) are filtered, not fatal.
* **Numeric / over-cap YAML stack ids in the plan catalog.**  The script
  side is already pinned; the *stack* side flows through
  ``containers_svc._stack_paths``'s str() probe: ``id: 42`` renders as
  ``"42"`` (not silently renamed), an over-cap hex id falls back to the
  directory name with a path and drops without one.
* **PUT /api/ups/settings over a poisoned store.**  The effective-merge
  validation reads the stored shutdown policy: leftover inf / over-cap
  triggers normalize to None, so enabling the policy answers the coded
  ``ups.policy_no_condition`` 400 — a coded refusal, never a 500 — and a
  flat-key patch still saves.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

import hub.containers_svc as containers_svc  # noqa: E402
from hub import ups_policy, ups_svc  # noqa: E402

#: Built arithmetically: int("9" * 5000) itself trips the parse cap.
_HUGE_INT = 10 ** 5000
_INF = float("inf")


def _starlette(payload) -> None:
    """What Starlette's JSONResponse does to the body (allow_nan=False)."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


def _router_client():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from hub.routers.ups_api import router

    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=False)


class UpsPolicyStateBase(unittest.TestCase):
    """Redirect the policy state/lock into a temp dir."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.state_file = Path(tmp.name) / "ups-policy-state.json"
        for patched in (
            mock.patch.object(ups_policy, "STATE_FILE", self.state_file),
            mock.patch.object(
                ups_policy, "_LOCK_PATH", Path(tmp.name) / "state.lock",
            ),
        ):
            patched.start()
            self.addCleanup(patched.stop)


class UpsBodyValidation422Tests(unittest.TestCase):
    """Rejected UPS request bodies stay 4xx through the real app wiring.

    ``create_app`` registers the sanitizing RequestValidationError handler;
    without it every one of these bodies made the *handler itself* raise
    while echoing ``detail[].input`` and the route answered a bare 500.
    """

    @classmethod
    def setUpClass(cls):
        from fastapi.testclient import TestClient
        from hub.app_factory import create_app
        from hub.auth import require_auth

        cls._app = create_app()
        cls._app.dependency_overrides[require_auth] = lambda: True
        cls.client = TestClient(cls._app, raise_server_exceptions=False)

    @classmethod
    def tearDownClass(cls):
        cls._app.dependency_overrides.clear()

    def _put(self, path: str, body: str):
        return self.client.put(
            path, content=body, headers={"Content-Type": "application/json"},
        )

    def test_non_finite_settings_bodies_answer_422(self):
        for body in (
            '{"low_battery_pct": 1e999}',
            '{"low_battery_pct": Infinity}',
            '{"shutdown": {"trigger_pct": NaN}}',
            '{"shutdown": {"trigger_remaining_min": -Infinity}}',
        ):
            with self.subTest(body=body):
                r = self._put("/api/ups/settings", body)
                self.assertEqual(r.status_code, 422, r.text)
                _starlette(r.json())

    def test_non_finite_haltlevel_answers_422(self):
        r = self._put("/api/ups/halt", '{"haltlevel": 1e999}')
        self.assertEqual(r.status_code, 422, r.text)
        _starlette(r.json())

    def test_surrogate_haltlevel_string_does_not_echo(self):
        r = self._put("/api/ups/halt", '{"haltlevel": "x\\ud800"}')
        self.assertEqual(r.status_code, 422, r.text)
        _starlette(r.json())
        self.assertNotIn("\ud800", r.text)

    def test_surrogate_unknown_key_under_extra_forbid_does_not_echo(self):
        # extra="forbid" puts the offending *key* into detail[].loc.
        r = self._put("/api/ups/settings", '{"bogus\\ud800": 1}')
        self.assertEqual(r.status_code, 422, r.text)
        _starlette(r.json())
        self.assertNotIn("\ud800", r.text)

    def test_over_cap_int_literal_is_refused_before_parse(self):
        # json.loads raises the digit-cap ValueError, so the body never
        # reaches pydantic; the answer is a client error, never a 500.
        for path in ("/api/ups/settings", "/api/ups/halt"):
            with self.subTest(path=path):
                field = "haltlevel" if path.endswith("halt") else "low_battery_pct"
                r = self._put(path, '{"%s": %s}' % (field, "9" * 5000))
                self.assertLess(r.status_code, 500, r.text)
                self.assertGreaterEqual(r.status_code, 400)
                _starlette(r.json())


class HaltLevelRangeCheckTests(unittest.TestCase):
    """A merely-huge haltlevel hits the coded 400 before any str() render."""

    def test_hundred_digit_haltlevel_is_the_coded_400(self):
        from hub.routers import ups_api

        client = _router_client()
        with mock.patch.object(
            ups_api, "require_admin_browser", lambda request: "admin",
        ):
            r = client.put(
                "/api/ups/halt",
                content='{"haltlevel": %s}' % ("9" * 100),
                headers={"Content-Type": "application/json"},
            )
        self.assertEqual(r.status_code, 400, r.text)
        self.assertEqual(r.json()["detail"]["code"], "ups.halt_bad_level")
        _starlette(r.json())


class PoisonedStoredSettingsTests(UpsPolicyStateBase):
    """GET /api/ups keeps answering over a fully poisoned settings.ups."""

    #: Every leftover shape a hand-edited services.yaml can load: surrogate
    #: keys AND values, already-int hex past the digit cap, inf/nan floats,
    #: bytes, and poison inside the shutdown block and its lists.
    POISON = {
        "settings": {
            "ups": {
                "alerts_enabled": _HUGE_INT,
                "low_battery_pct": _INF,
                "\ud800key": "v",
                "stray": "x\ud800y",
                "hexint": _HUGE_INT,
                "shutdown": {
                    "enabled": True,
                    "trigger_pct": _HUGE_INT,
                    "trigger_remaining_min": _INF,
                    "require_both": b"\xff",
                    "stacks": [_HUGE_INT, "ok-stack", "\ud800bad"],
                    "stop_scripts": [_HUGE_INT, {"nested": 1}],
                    "\ud800skey": _HUGE_INT,
                },
            },
        },
    }

    def _get_ups(self):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                ups_svc, "cfg", lambda: self.POISON,
            ))
            stack.enter_context(mock.patch.object(
                ups_svc, "ups_snapshot",
                lambda force=False: {"present": False, "halt_levels": None},
            ))
            return _router_client().get("/api/ups")

    def test_get_ups_is_200_and_encodable(self):
        resp = self._get_ups()
        self.assertEqual(resp.status_code, 200, resp.text)
        _starlette(resp.json())
        self.assertNotIn("\ud800", resp.text)

    def test_unrenderable_policy_numbers_fall_back(self):
        body = self._get_ups().json()
        settings = body["settings"]
        # inf floor falls back to the default rather than leaking.
        self.assertEqual(settings["low_battery_pct"], 20)
        # Over-cap / inf triggers normalize to "condition off".
        self.assertIsNone(settings["shutdown"]["trigger_pct"])
        self.assertIsNone(settings["shutdown"]["trigger_remaining_min"])

    def test_poisoned_snapshot_values_are_dropped(self):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                ups_svc, "cfg", lambda: {"settings": {}},
            ))
            stack.enter_context(mock.patch.object(
                ups_svc, "ups_snapshot",
                lambda force=False: {
                    "present": True, "kind": "ups", "name": "APC\ud800",
                    "source": "ups", "on_ac": False, "on_battery": True,
                    "battery_percent": _HUGE_INT, "charging": None,
                    "time_remaining_min": _INF,
                    "halt_levels": {"haltlevel": _HUGE_INT},
                },
            ))
            resp = _router_client().get("/api/ups")
        self.assertEqual(resp.status_code, 200, resp.text)
        _starlette(resp.json())
        body = resp.json()
        self.assertIsNone(body["battery_percent"])
        self.assertIsNone(body["time_remaining_min"])
        self.assertNotIn("\ud800", resp.text)


class PoisonedStateFileTests(UpsPolicyStateBase):
    """Leftover state-file shapes GET /api/ups must ride out."""

    def _get_ups(self):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                ups_svc, "cfg", lambda: {"settings": {}},
            ))
            stack.enter_context(mock.patch.object(
                ups_svc, "ups_snapshot",
                lambda force=False: {"present": False, "halt_levels": None},
            ))
            return _router_client().get("/api/ups")

    def test_over_cap_int_literal_raises_valueerror_not_jsondecodeerror(self):
        # The trap _load_state's ``except ValueError`` must keep covering:
        # a handler that only caught json.JSONDecodeError would crash here.
        text = '{"engaged_at": ' + "9" * 5000 + "}"
        with self.assertRaises(ValueError) as ctx:
            json.loads(text)
        self.assertNotIsInstance(ctx.exception, json.JSONDecodeError)

    def test_over_cap_int_literal_state_degrades_to_idle(self):
        self.state_file.write_text(
            '{"phase": "engaged", "engaged_at": ' + "9" * 5000 + "}",
        )
        resp = self._get_ups()
        self.assertEqual(resp.status_code, 200, resp.text)
        _starlette(resp.json())
        # The document is unreadable as a whole; the honest degrade is idle.
        self.assertEqual(resp.json()["shutdown_state"]["phase"], "idle")

    def test_infinity_and_nan_literals_are_dropped_from_the_body(self):
        # json.loads accepts these extensions; Starlette's allow_nan=False
        # encoder does not — they must be gone by render time.
        self.state_file.write_text(
            '{"phase": "engaged", "engaged_at": Infinity,'
            ' "last": {"restored_at": NaN}}',
        )
        resp = self._get_ups()
        self.assertEqual(resp.status_code, 200, resp.text)
        _starlette(resp.json())
        state = resp.json()["shutdown_state"]
        self.assertEqual(state["phase"], "engaged")
        self.assertIsNone(state["engaged_at"])
        self.assertIsNone(state["last"]["restored_at"])

    def test_junk_field_shapes_are_filtered_not_fatal(self):
        self.state_file.write_text(json.dumps({
            "phase": "engaged",
            "reason": 12345,
            "steps": [{"kind": "stack", "id": "immich"}, "junk", 7, None],
            "last": "not-a-dict",
        }))
        resp = self._get_ups()
        self.assertEqual(resp.status_code, 200, resp.text)
        _starlette(resp.json())
        state = resp.json()["shutdown_state"]
        self.assertEqual(state["reason"], "")
        self.assertEqual(
            [s["id"] for s in state["steps"]], ["immich"],
        )
        self.assertIsNone(state["last"])


class PlanStackIdCoercionTests(UpsPolicyStateBase):
    """Numeric / over-cap YAML stack ids in the shutdown-plan catalog."""

    def _plan(self, stacks_cfg, tmp_path: str):
        import hub.config as config

        cfg = {"settings": {}, "stacks": stacks_cfg, "scripts": []}
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                ups_svc, "cfg", lambda: cfg,
            ))
            stack.enter_context(mock.patch.object(
                containers_svc, "cfg", lambda: cfg,
            ))
            # ups_policy._catalog resolves ``from hub.config import cfg`` at
            # call time, so the module attribute needs the same patch.
            stack.enter_context(mock.patch.object(
                config, "cfg", lambda: cfg,
            ))
            stack.enter_context(mock.patch.object(
                containers_svc, "list_containers",
                lambda with_stats=False: [],
            ))
            stack.enter_context(mock.patch.object(
                containers_svc, "user_home", lambda: Path(tmp_path) / "nohome",
            ))
            stack.enter_context(mock.patch.object(
                ups_policy, "_ups_status", lambda: {"present": False},
            ))
            return _router_client().get("/api/ups/shutdown/plan")

    def test_numeric_stack_id_renders_via_str_probe(self):
        # YAML ``id: 42`` loads as int; an isinstance(str) gate would rename
        # the stack to its directory name and 404 later actions on it.
        with tempfile.TemporaryDirectory() as tmp:
            resp = self._plan([{"id": 42, "containers": ["c1"]}], tmp)
        self.assertEqual(resp.status_code, 200, resp.text)
        _starlette(resp.json())
        ids = [s["id"] for s in resp.json()["catalog"]["stacks"]]
        self.assertIn("42", ids)

    def test_over_cap_stack_id_with_path_falls_back_to_dirname(self):
        with tempfile.TemporaryDirectory() as tmp:
            stack_dir = Path(tmp) / "gravity"
            stack_dir.mkdir()
            (stack_dir / "docker-compose.yml").write_text("services: {}\n")
            resp = self._plan(
                [{"id": _HUGE_INT, "path": str(stack_dir)}], tmp,
            )
        self.assertEqual(resp.status_code, 200, resp.text)
        _starlette(resp.json())
        ids = [s["id"] for s in resp.json()["catalog"]["stacks"]]
        self.assertIn("gravity", ids)

    def test_over_cap_stack_id_without_path_drops_only_its_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            resp = self._plan([
                {"id": _HUGE_INT, "containers": ["c1"]},
                {"id": "immich", "containers": ["c2"]},
            ], tmp)
        self.assertEqual(resp.status_code, 200, resp.text)
        _starlette(resp.json())
        ids = [s["id"] for s in resp.json()["catalog"]["stacks"]]
        self.assertEqual(ids, ["immich"])


class PutSettingsOverPoisonedStoreTests(UpsPolicyStateBase):
    """The settings PUT reads the stored policy for its effective merge."""

    POISON = {
        "settings": {
            "ups": {
                "low_battery_pct": _INF,
                "shutdown": {
                    "enabled": False,
                    "trigger_pct": _HUGE_INT,
                    "trigger_remaining_min": _INF,
                },
            },
        },
    }

    def _client_with_store(self, stack: ExitStack, saved: list):
        stack.enter_context(mock.patch.object(
            ups_svc, "cfg", lambda: self.POISON,
        ))
        stack.enter_context(mock.patch.object(
            ups_svc, "ups_snapshot",
            lambda force=False: {"present": False, "halt_levels": None},
        ))
        stack.enter_context(mock.patch.object(
            ups_svc, "update_settings", lambda patch: saved.append(patch),
        ))
        return _router_client()

    def test_enabling_over_normalized_none_triggers_is_the_coded_400(self):
        # Both stored triggers are unrenderable, so they normalize to
        # "condition off"; enabling must be the coded refusal, not a 500
        # (and not a policy that silently never fires).
        saved: list = []
        with ExitStack() as stack:
            client = self._client_with_store(stack, saved)
            resp = client.put(
                "/api/ups/settings", json={"shutdown": {"enabled": True}},
            )
        self.assertEqual(resp.status_code, 400, resp.text)
        self.assertEqual(
            resp.json()["detail"]["code"], "ups.policy_no_condition",
        )
        _starlette(resp.json())
        self.assertEqual(saved, [])

    def test_flat_key_patch_still_saves_beside_the_poison(self):
        saved: list = []
        with ExitStack() as stack:
            client = self._client_with_store(stack, saved)
            resp = client.put(
                "/api/ups/settings", json={"low_battery_pct": 50},
            )
        self.assertEqual(resp.status_code, 200, resp.text)
        _starlette(resp.json())
        self.assertEqual(saved, [{"ups": {"low_battery_pct": 50}}])

    def test_surrogate_stack_id_is_the_coded_400_without_echoing_raw(self):
        saved: list = []
        with ExitStack() as stack:
            client = self._client_with_store(stack, saved)
            resp = client.put(
                "/api/ups/settings",
                content='{"shutdown": {"stacks": ["b\\ud800d"]}}',
                headers={"Content-Type": "application/json"},
            )
        self.assertEqual(resp.status_code, 400, resp.text)
        self.assertEqual(resp.json()["detail"]["code"], "ups.bad_stack_id")
        _starlette(resp.json())
        self.assertNotIn("\ud800", resp.text)
        self.assertEqual(saved, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
