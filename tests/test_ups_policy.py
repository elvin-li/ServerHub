"""UPS safe-shutdown policy: trigger conditions, latch, executor, recovery.

The policy stops real compose stacks with nobody at the keyboard, so these
tests pin the properties that make it safe to leave enabled:

* **no sensor, no action** — an empty pmset read (present=False) or a raised
  probe neither triggers nor resets;
* **latched per outage** — one power-loss event executes one stop sequence,
  and a charge level flapping around the floor (49% ↔ 51%) while on battery
  cannot re-fire; only positively seeing AC power releases the latch;
* **only what the policy stopped is started back** — a stack the operator
  had stopped by hand is skipped on the way down and therefore untouched on
  the way up;
* **crash-safe** — ``stop_issued`` is persisted before each ``compose
  stop``, so a panel killed mid-sequence resumes the remaining stops on
  battery and starts everything recorded once AC returns;
* **the drill executes nothing** — it reports the plan and leaves state,
  docker and services alone.

Every subprocess/cross-module seam (`_run_argv`, `_svc_action`,
`_list_stacks`, `_service_states`, `_engine_up`, `_ups_status`,
`containers_svc._stack_paths`) is mocked; no test stops a container, runs a
script command or reads real pmset state.  Workers run synchronously through
a patched ``_spawn`` so the state machine is deterministic.
"""
from __future__ import annotations

import datetime
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from hub import alerts, audit, ups_policy, ups_svc  # noqa: E402

NOW = 1_800_000_000


def _status(*, present=True, on_battery=True, pct=18, remaining=None):
    return {
        "present": present,
        "kind": "ups",
        "name": "Back-UPS ES 750",
        "source": "ups" if on_battery else "ac",
        "on_ac": not on_battery,
        "on_battery": on_battery,
        "battery_percent": pct,
        "charging": not on_battery,
        "time_remaining_min": remaining,
        "halt_levels": None,
        "settings": {},
    }


def _policy(**over):
    p = dict(ups_svc.SHUTDOWN_DEFAULTS)
    p["enabled"] = True
    p.update(over)
    return p


STACKS = [
    {"id": "immich", "name": "Immich", "status": "ok"},
    {"id": "teslamate", "name": "TeslaMate", "status": "ok"},
    {"id": "music-assistant", "name": "Music Assistant", "status": "exists"},
]

STACK_PATHS = [
    {"id": "immich", "compose_path": "/srv/immich/docker-compose.yml"},
    {"id": "teslamate", "compose_path": "/srv/teslamate/docker-compose.yml"},
    {"id": "music-assistant", "compose_path": "/srv/ma/docker-compose.yml"},
]


class PolicyBase(unittest.TestCase):
    """Redirect state, capture alerts/audits, run workers synchronously."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.state_file = Path(tmp.name) / "ups-policy-state.json"
        self.emitted: list[dict] = []
        self.audits: list[tuple[str, dict]] = []
        self.spawned: list[str] = []
        self.argv_calls: list[list[str]] = []
        self.svc_calls: list[tuple[str, str]] = []

        def capture_alert(**kw):
            self.emitted.append(kw)
            return {"id": kw.get("alert_id"), **kw}

        def capture_audit(event, **fields):
            self.audits.append((event, fields))
            return fields

        def sync_spawn(target):
            self.spawned.append(target.__name__)
            target()
            return True

        def fake_run_argv(argv, *, timeout):
            self.argv_calls.append(list(argv))
            return self.argv_rc(argv)

        def fake_svc_action(sid, action):
            self.svc_calls.append((sid, action))
            return 0, "done", ""

        patches = [
            mock.patch.object(ups_policy, "STATE_FILE", self.state_file),
            mock.patch.object(alerts, "emit_alert", capture_alert),
            mock.patch.object(audit, "record", capture_audit),
            mock.patch.object(ups_policy, "_spawn", sync_spawn),
            mock.patch.object(ups_policy, "_run_argv", fake_run_argv),
            mock.patch.object(ups_policy, "_svc_action", fake_svc_action),
            mock.patch.object(ups_policy, "_engine_up", lambda: True),
            mock.patch.object(ups_policy, "_list_stacks", lambda: list(STACKS)),
            mock.patch.object(ups_policy, "_service_states", lambda: {"gravity": "ok"}),
            mock.patch("hub.containers_svc._stack_paths", lambda: list(STACK_PATHS)),
            mock.patch("hub.status.invalidate_status", lambda: None),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        ups_policy._worker_active.clear()
        self.addCleanup(ups_policy._worker_active.clear)

    #: Overridable per test: rc/out/err for one compose call.
    def argv_rc(self, argv):
        return 0, "", ""

    def state(self) -> dict:
        if not self.state_file.exists():
            return {}
        return json.loads(self.state_file.read_text())

    def sweep(self, status, policy, now=NOW):
        with mock.patch.object(ups_policy, "_ups_status", lambda: status), \
             mock.patch.object(ups_policy, "shutdown_settings", lambda: policy):
            return ups_policy.sweep(now)


class ConditionTests(unittest.TestCase):
    """Trigger arithmetic, including the unreadable-value rules."""

    def test_pct_floor_triggers_at_or_below(self):
        hit, reason = ups_policy._condition(_status(pct=25), _policy(trigger_pct=25))
        self.assertTrue(hit)
        self.assertIn("25%", reason)
        hit, _ = ups_policy._condition(_status(pct=26), _policy(trigger_pct=25))
        self.assertFalse(hit)

    def test_remaining_floor(self):
        pol = _policy(trigger_pct=None, trigger_remaining_min=10)
        hit, reason = ups_policy._condition(_status(pct=80, remaining=8), pol)
        self.assertTrue(hit)
        self.assertIn("8 min", reason)
        hit, _ = ups_policy._condition(_status(pct=80, remaining=25), pol)
        self.assertFalse(hit)

    def test_on_ac_never_triggers(self):
        hit, _ = ups_policy._condition(
            _status(on_battery=False, pct=5), _policy(trigger_pct=25))
        self.assertFalse(hit)

    def test_either_condition_fires_by_default(self):
        pol = _policy(trigger_pct=25, trigger_remaining_min=10)
        hit, _ = ups_policy._condition(_status(pct=20, remaining=60), pol)
        self.assertTrue(hit, "pct alone must fire in any-of mode")

    def test_require_both_needs_both(self):
        pol = _policy(trigger_pct=25, trigger_remaining_min=10, require_both=True)
        hit, _ = ups_policy._condition(_status(pct=20, remaining=60), pol)
        self.assertFalse(hit)
        hit, reason = ups_policy._condition(_status(pct=20, remaining=5), pol)
        self.assertTrue(hit)
        self.assertIn(" and ", reason)

    def test_require_both_blocks_on_unreadable_estimate(self):
        """pmset omits the estimate for a while after a power event; "both"
        must read that conservatively (no fire), not as "condition passed"."""
        pol = _policy(trigger_pct=25, trigger_remaining_min=10, require_both=True)
        hit, _ = ups_policy._condition(_status(pct=20, remaining=None), pol)
        self.assertFalse(hit)

    def test_unreadable_percent_does_not_fire_pct_condition(self):
        hit, _ = ups_policy._condition(_status(pct=None), _policy(trigger_pct=25))
        self.assertFalse(hit)

    def test_hand_edited_percent_string_does_not_500(self):
        hit, _ = ups_policy._condition(_status(pct=10), _policy(trigger_pct="25%"))
        self.assertFalse(hit)

    def test_huge_trigger_integers_do_not_500(self):
        """Leftover YAML ``trigger_pct: 10**400`` OverflowError'd ``float()`` on the plan."""
        huge = 10 ** 400
        hit, _ = ups_policy._condition(_status(pct=18), _policy(trigger_pct=huge))
        self.assertFalse(hit)
        hit, _ = ups_policy._condition(
            _status(pct=80, remaining=huge),
            _policy(trigger_pct=None, trigger_remaining_min=10),
        )
        self.assertFalse(hit)

    def test_no_conditions_configured_never_fires(self):
        pol = _policy(trigger_pct=None, trigger_remaining_min=None)
        hit, _ = ups_policy._condition(_status(pct=1), pol)
        self.assertFalse(hit)


class PlanTests(PolicyBase):
    def test_all_stacks_in_enumeration_order_then_scripts(self):
        steps = ups_policy.build_plan(_policy(stop_scripts=["gravity"]))
        self.assertEqual(
            [(s["kind"], s["id"]) for s in steps],
            [("stack", "immich"), ("stack", "teslamate"),
             ("stack", "music-assistant"), ("service", "gravity")],
        )
        by_id = {s["id"]: s for s in steps}
        self.assertTrue(by_id["immich"]["running"])
        self.assertFalse(by_id["music-assistant"]["running"],
                         "status=exists means stopped containers, not running")
        self.assertTrue(by_id["gravity"]["running"])

    def test_custom_order_is_preserved_and_deduped(self):
        steps = ups_policy.build_plan(
            _policy(stacks=["teslamate", "immich", "teslamate", "ghost"]))
        self.assertEqual([s["id"] for s in steps], ["teslamate", "immich", "ghost"])
        ghost = steps[-1]
        self.assertFalse(ghost["known"])
        self.assertFalse(ghost["running"], "an unknown stack must never be acted on")

    def test_down_service_is_not_stoppable(self):
        with mock.patch.object(ups_policy, "_service_states",
                               lambda: {"gravity": "down"}):
            steps = ups_policy.build_plan(_policy(stacks=[], stop_scripts=["gravity"]))
        self.assertFalse(steps[0]["running"],
                         "a service the operator stopped must not be stopped (or restarted) by policy")

    def test_junk_stack_rows_do_not_500(self):
        with mock.patch.object(
            ups_policy, "_list_stacks",
            lambda: [None, "oops", {"id": "ok", "name": "OK", "status": "ok"}],
        ):
            steps = ups_policy.build_plan(_policy(stacks="all"))
            cat = ups_policy._catalog()
        self.assertEqual([s["id"] for s in steps], ["ok"])
        self.assertEqual([s["id"] for s in cat["stacks"]], ["ok"])

    def test_non_list_scripts_catalog_does_not_500(self):
        with mock.patch.object(ups_policy, "_list_stacks", lambda: []), \
             mock.patch("hub.config.cfg", lambda: {"scripts": 3}):
            self.assertEqual(ups_policy._catalog()["scripts"], [])


class Leftover500Tests(unittest.TestCase):
    """Request-path leftovers that 500 GET /api/ups and /api/ups/shutdown/plan."""

    def test_junk_status_groups_do_not_500(self):
        """``g.get("services")`` 500'd the plan on leftover status rows."""
        with mock.patch(
            "hub.status.full_status",
            return_value={"groups": [
                None, "oops",
                {"services": [None, "x", {"id": "gravity", "state": "ok"}]},
            ]},
        ):
            states = ups_policy._service_states()
        self.assertEqual(states, {"gravity": "ok"})

    def test_infinite_state_fields_do_not_500(self):
        """``1e400`` in the persisted state used to 500 GET /api/ups."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        state_file = Path(tmp.name) / "ups-policy-state.json"
        state_file.write_text(json.dumps({
            "phase": "engaged",
            "engaged_at": float("inf"),
            "reason": "battery 18% ≤ 25%",
            "steps": [{"kind": "stack", "id": "immich"}],
            "last": {"restored_at": float("nan")},
        }))
        with mock.patch.object(ups_policy, "STATE_FILE", state_file):
            st = ups_policy.public_state()
        json.dumps(st, allow_nan=False)
        self.assertEqual(st["phase"], "engaged")
        self.assertIsNone(st["engaged_at"])
        self.assertIsNone(st["last"]["restored_at"])

    def test_state_file_stat_eio_does_not_500(self):
        """A dying ``data/`` mount used to OSError ``exists()`` on GET /api/ups."""
        with mock.patch.object(Path, "exists", side_effect=OSError(5, "I/O error")):
            st = ups_policy.public_state()
        json.dumps(st, allow_nan=False)
        self.assertEqual(st["phase"], "idle")
        self.assertIsNone(st["last"])

    def test_huge_state_file_does_not_oom(self):
        """``read_text()`` of leftover multi-MB ups-policy-state.json used to OOM GET /api/ups."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        state_file = Path(tmp.name) / "ups-policy-state.json"
        state_file.write_bytes(b"x" * (2 * 1024 * 1024))
        with mock.patch.object(ups_policy, "STATE_FILE", state_file):
            st = ups_policy.public_state()
        json.dumps(st, allow_nan=False)
        self.assertEqual(st["phase"], "idle")

    def test_infinite_worker_claim_ts_does_not_500(self):
        """Leftover ``worker_owner.ts: 1e400`` OverflowError'd ``int(inf)`` on the sweep."""
        ups_policy._worker_active.clear()
        self.assertFalse(ups_policy._worker_busy({
            "worker_owner": {"pid": 1, "ts": float("inf")},
        }))

    def test_save_state_drops_leftover_inf(self):
        """``json.dumps`` without allow_nan=False used to rewrite Infinity onto disk."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        state_file = Path(tmp.name) / "ups-policy-state.json"
        with mock.patch.object(ups_policy, "STATE_FILE", state_file):
            ups_policy._save_state({
                "phase": "engaged",
                "engaged_at": float("inf"),
                "reason": b"battery",
            })
        raw = json.loads(state_file.read_text())
        json.dumps(raw, allow_nan=False)
        self.assertEqual(raw["phase"], "engaged")
        self.assertIsNone(raw["engaged_at"])
        self.assertEqual(raw["reason"], "battery")


class SweepStateMachineTests(PolicyBase):
    """idle → engaged → restoring → idle, with the latch in the middle."""

    def test_no_sensor_tracks_nothing(self):
        out = self.sweep(_status(present=False), _policy())
        self.assertEqual(out, [])
        self.assertEqual(self.state(), {})
        self.assertEqual(self.spawned, [])

    def test_probe_failure_neither_triggers_nor_resets(self):
        with mock.patch.object(ups_policy, "_ups_status",
                               side_effect=RuntimeError("pmset broke")), \
             mock.patch.object(ups_policy, "shutdown_settings", lambda: _policy()):
            self.assertEqual(ups_policy.sweep(NOW), [])
        # And while engaged: an unreadable sensor must not release the latch.
        ups_policy._save_state({"phase": "engaged", "steps": [], "stop_done": True})
        with mock.patch.object(ups_policy, "_ups_status",
                               side_effect=RuntimeError("pmset broke")), \
             mock.patch.object(ups_policy, "shutdown_settings", lambda: _policy()):
            ups_policy.sweep(NOW)
        self.assertEqual(self.state()["phase"], "engaged")

    def test_disabled_policy_never_engages(self):
        out = self.sweep(_status(pct=1), _policy(enabled=False))
        self.assertEqual(out, [])
        self.assertEqual(self.state(), {})

    def test_trigger_latches_announces_then_stops(self):
        out = self.sweep(_status(pct=18), _policy(trigger_pct=25, stop_scripts=["gravity"]))
        # One down alert, sent before any stop was issued (emit precedes spawn).
        self.assertEqual(len(out), 1)
        self.assertEqual(self.emitted[0]["level"], "down")
        self.assertIn("battery 18% ≤ 25%", self.emitted[0]["message"])
        self.assertIn("immich", self.emitted[0]["message"])
        st = self.state()
        self.assertEqual(st["phase"], "engaged")
        self.assertTrue(st["stop_done"])
        self.assertEqual(self.spawned, ["_run_stop_sequence"])
        # Both running stacks stopped in order; the idle one skipped.
        self.assertEqual(self.argv_calls, [
            [mock.ANY, "compose", "-f", "/srv/immich/docker-compose.yml", "stop"],
            [mock.ANY, "compose", "-f", "/srv/teslamate/docker-compose.yml", "stop"],
        ])
        self.assertEqual(self.svc_calls, [("gravity", "stop")])
        by_id = {(s["kind"], s["id"]): s for s in st["steps"]}
        self.assertTrue(by_id[("stack", "immich")]["stop_ok"])
        self.assertEqual(by_id[("stack", "music-assistant")]["skipped"], "not_running")
        self.assertNotIn("stop_issued", by_id[("stack", "music-assistant")])
        trigger_audits = [a for a in self.audits if a[0] == audit.UPS_POLICY_TRIGGERED]
        step_audits = [a for a in self.audits if a[0] == audit.UPS_POLICY_STEP]
        self.assertEqual(len(trigger_audits), 1)
        self.assertEqual(len(step_audits), 3, "each executed stop is audited")

    def test_latched_outage_does_not_refire_on_charge_flap(self):
        self.sweep(_status(pct=18), _policy(trigger_pct=25))
        self.emitted.clear()
        self.argv_calls.clear()
        self.spawned.clear()
        # 49 ↔ 51 style flapping while still on battery: nothing may happen.
        for pct in (26, 18, 26, 12):
            out = self.sweep(_status(pct=pct), _policy(trigger_pct=25))
            self.assertEqual(out, [])
        self.assertEqual(self.emitted, [])
        self.assertEqual(self.argv_calls, [])
        self.assertEqual(self.spawned, [], "stop_done latch must hold all outage long")
        self.assertEqual(self.state()["phase"], "engaged")

    def test_power_restore_starts_only_what_policy_stopped(self):
        self.sweep(_status(pct=18), _policy(trigger_pct=25, stop_scripts=["gravity"]))
        self.emitted.clear()
        self.argv_calls.clear()
        self.svc_calls.clear()
        self.sweep(_status(on_battery=False, pct=30), _policy(trigger_pct=25))
        # Stacks the policy stopped come back; music-assistant (never touched)
        # and nothing else is started.
        self.assertEqual(self.argv_calls, [
            [mock.ANY, "compose", "-f", "/srv/immich/docker-compose.yml", "start"],
            [mock.ANY, "compose", "-f", "/srv/teslamate/docker-compose.yml", "start"],
        ])
        self.assertEqual(self.svc_calls, [("gravity", "start")])
        st = self.state()
        self.assertEqual(st["phase"], "idle")
        self.assertNotIn("steps", st)
        last = st["last"]
        self.assertEqual(last["restarted"], ["immich", "teslamate", "gravity"])
        self.assertEqual(last["failed"], [])
        self.assertEqual(last["restored_at"], mock.ANY)
        # Reset alert is ok/resolved so notify_resolve routing applies.
        self.assertEqual(self.emitted[-1]["level"], "ok")
        self.assertEqual(self.emitted[-1]["event"], "resolved")
        reset_audits = [a for a in self.audits if a[0] == audit.UPS_POLICY_RESET]
        self.assertEqual(len(reset_audits), 1)

    def test_failed_restart_is_a_warn_alert_naming_the_stack(self):
        self.sweep(_status(pct=18), _policy(trigger_pct=25))
        self.emitted.clear()

        def failing(argv):
            if "start" in argv and "immich" in " ".join(argv):
                return 1, "", "no such container"
            return 0, "", ""
        with mock.patch.object(self, "argv_rc", failing):
            self.sweep(_status(on_battery=False), _policy(trigger_pct=25))
        self.assertEqual(self.emitted[-1]["level"], "warn")
        self.assertIn("immich", self.emitted[-1]["message"])
        self.assertEqual(self.state()["last"]["failed"], ["immich"])

    def test_second_outage_after_reset_engages_again(self):
        self.sweep(_status(pct=18), _policy(trigger_pct=25))
        self.sweep(_status(on_battery=False), _policy(trigger_pct=25))
        self.emitted.clear()
        out = self.sweep(_status(pct=10), _policy(trigger_pct=25))
        self.assertEqual(len(out), 1, "a new outage is a new event")
        self.assertEqual(self.state()["phase"], "engaged")


class CrashRecoveryTests(PolicyBase):
    """The persisted phase, not process memory, is the source of truth."""

    def test_panel_killed_mid_stop_resumes_remaining_steps_on_battery(self):
        # As left behind by a death after immich's stop was issued but before
        # teslamate was reached: immich resolved, teslamate untouched.
        ups_policy._save_state({
            "phase": "engaged", "engaged_at": NOW - 60, "reason": "battery 18% ≤ 25%",
            "stop_done": False,
            "steps": [
                {"kind": "stack", "id": "immich", "name": "Immich", "running": True,
                 "known": True, "stop_issued": True, "done": True, "stop_ok": True,
                 "compose_path": "/srv/immich/docker-compose.yml"},
                {"kind": "stack", "id": "teslamate", "name": "TeslaMate",
                 "running": True, "known": True},
            ],
        })
        self.sweep(_status(pct=15), _policy(trigger_pct=25))
        self.assertEqual(self.spawned, ["_run_stop_sequence"])
        self.assertEqual(self.argv_calls, [
            [mock.ANY, "compose", "-f", "/srv/teslamate/docker-compose.yml", "stop"],
        ], "already-resolved steps must not be re-stopped")
        self.assertTrue(self.state()["stop_done"])
        self.assertEqual(self.emitted, [], "a resumed sequence is not a new event")

    def test_panel_killed_after_stop_restores_from_marker_on_ac(self):
        ups_policy._save_state({
            "phase": "engaged", "engaged_at": NOW - 600, "reason": "battery 18% ≤ 25%",
            "stop_done": True,
            "steps": [
                {"kind": "stack", "id": "immich", "name": "Immich", "running": True,
                 "known": True, "stop_issued": True, "done": True, "stop_ok": True,
                 "compose_path": "/srv/immich/docker-compose.yml"},
                {"kind": "stack", "id": "music-assistant", "name": "MA",
                 "running": False, "known": True, "done": True, "skipped": "not_running"},
            ],
        })
        self.sweep(_status(on_battery=False, pct=40), _policy(trigger_pct=25))
        self.assertEqual(self.argv_calls, [
            [mock.ANY, "compose", "-f", "/srv/immich/docker-compose.yml", "start"],
        ], "only the recorded stop survives the restart — the skip does too")
        self.assertEqual(self.state()["phase"], "idle")

    def test_interrupted_restore_reruns_idempotently(self):
        ups_policy._save_state({
            "phase": "restoring", "engaged_at": NOW - 600, "reason": "r",
            "stop_done": True,
            "steps": [
                {"kind": "stack", "id": "immich", "name": "Immich", "running": True,
                 "known": True, "stop_issued": True, "done": True, "stop_ok": True,
                 "compose_path": "/srv/immich/docker-compose.yml",
                 "start_ok": True, "start_detail": ""},
            ],
        })
        self.sweep(_status(on_battery=False), _policy(trigger_pct=25))
        self.assertEqual(self.argv_calls, [
            [mock.ANY, "compose", "-f", "/srv/immich/docker-compose.yml", "start"],
        ], "compose start is idempotent, so re-running the restore is safe")
        self.assertEqual(self.state()["phase"], "idle")


class StopSequenceEdgeTests(PolicyBase):
    def test_engine_down_skips_stacks_without_marking_them_stopped(self):
        with mock.patch.object(ups_policy, "_engine_up", lambda: False):
            self.sweep(_status(pct=10), _policy(trigger_pct=25))
        self.assertEqual(self.argv_calls, [])
        st = self.state()
        for step in st["steps"]:
            if step["kind"] == "stack":
                self.assertNotIn("stop_issued", step)
        # Restore after such an outage starts nothing.
        self.argv_calls.clear()
        self.sweep(_status(on_battery=False), _policy(trigger_pct=25))
        self.assertEqual(self.argv_calls, [])
        self.assertEqual(self.state()["phase"], "idle")

    def test_power_return_mid_sequence_aborts_remaining_stops(self):
        """Once a concurrent sweep flips the phase off engaged (AC is back),
        the worker must not stop targets it would immediately restart."""
        def flip(argv):
            ups_policy._mutate(lambda s: s.update(phase="restoring"))
            return 0, "", ""
        with mock.patch.object(self, "argv_rc", flip):
            self.sweep(_status(pct=10), _policy(trigger_pct=25))
        stops = [c for c in self.argv_calls if "stop" in c]
        self.assertEqual(len(stops), 1)
        by_id = {s["id"]: s for s in self.state()["steps"] if s["kind"] == "stack"}
        self.assertTrue(by_id["immich"].get("stop_issued"),
                        "the stack stopped before the flip keeps its marker")
        self.assertNotIn("stop_issued", by_id["teslamate"])

    def test_stop_failure_is_recorded_and_stack_still_restored(self):
        """A non-zero compose stop may still have taken containers down, so
        the stack counts as touched and is started back — the same contract
        as the stack backup's finally-restart."""
        def failing(argv):
            if "stop" in argv and "immich" in " ".join(argv):
                return 1, "", "compose stop blew up"
            return 0, "", ""
        with mock.patch.object(self, "argv_rc", failing):
            self.sweep(_status(pct=10), _policy(trigger_pct=25))
        by_id = {s["id"]: s for s in self.state()["steps"] if s["kind"] == "stack"}
        self.assertFalse(by_id["immich"]["stop_ok"])
        self.assertIn("blew up", by_id["immich"]["detail"])
        self.argv_calls.clear()
        self.sweep(_status(on_battery=False), _policy(trigger_pct=25))
        started = [" ".join(c) for c in self.argv_calls if "start" in c]
        self.assertTrue(any("immich" in c for c in started))


class DrillTests(PolicyBase):
    def test_drill_reports_without_acting(self):
        with mock.patch.object(ups_policy, "_ups_status",
                               lambda: _status(pct=18)), \
             mock.patch.object(ups_policy, "shutdown_settings",
                               lambda: _policy(trigger_pct=25, stop_scripts=["gravity"])), \
             mock.patch("hub.config.cfg", lambda: {"scripts": [
                 {"id": "gravity", "name": "Gravity", "stop": "kill ..."},
             ]}):
            result = ups_policy.drill()
        self.assertTrue(result["would_trigger_now"])
        self.assertIn("battery 18%", result["reason"])
        self.assertEqual(
            [s["id"] for s in result["steps"]],
            ["immich", "teslamate", "music-assistant", "gravity"],
        )
        # The catalog is the full menu for the settings form, independent of
        # what the current config selects.
        self.assertEqual([s["id"] for s in result["catalog"]["stacks"]],
                         ["immich", "teslamate", "music-assistant"])
        self.assertEqual(result["catalog"]["scripts"],
                         [{"id": "gravity", "name": "Gravity", "has_stop": True}])
        self.assertEqual(self.argv_calls, [], "a drill must never touch docker")
        self.assertEqual(self.svc_calls, [])
        self.assertEqual(self.spawned, [])
        self.assertEqual(self.state(), {}, "a drill must not latch")
        self.assertEqual(self.emitted, [])

    def test_drill_without_sensor_is_still_a_plan(self):
        with mock.patch.object(ups_policy, "_ups_status",
                               lambda: _status(present=False)), \
             mock.patch.object(ups_policy, "shutdown_settings",
                               lambda: _policy(trigger_pct=25)):
            result = ups_policy.drill()
        self.assertFalse(result["would_trigger_now"])
        self.assertFalse(result["sensor_present"])
        self.assertEqual(len(result["steps"]), 3)


class SpawnGuardTests(unittest.TestCase):
    def test_second_spawn_is_refused_while_a_worker_runs(self):
        ups_policy._worker_active.clear()
        self.addCleanup(ups_policy._worker_active.clear)
        ups_policy._worker_active.set()
        self.assertFalse(ups_policy._spawn(lambda: None))


class SettingsNormalizationTests(unittest.TestCase):
    """settings.ups.shutdown round-trip through ups_svc."""

    def test_defaults_when_absent(self):
        with mock.patch.object(ups_svc, "cfg", lambda: {"settings": {}}):
            s = ups_svc.ups_settings()
        self.assertEqual(s["shutdown"], ups_svc.SHUTDOWN_DEFAULTS)

    def test_explicit_null_condition_survives_normalization(self):
        raw = {"ups": {"shutdown": {"enabled": True, "trigger_pct": None,
                                    "trigger_remaining_min": 10, "junk": 1}}}
        with mock.patch.object(ups_svc, "cfg", lambda: {"settings": raw}):
            s = ups_svc.ups_settings()["shutdown"]
        self.assertIsNone(s["trigger_pct"], "null means 'condition off', not 'default'")
        self.assertEqual(s["trigger_remaining_min"], 10)
        self.assertNotIn("junk", s)

    def test_save_filters_unknown_shutdown_keys(self):
        saved = {}
        with mock.patch.object(ups_svc, "update_settings",
                               lambda patch: saved.update(patch)), \
             mock.patch.object(ups_svc, "cfg", lambda: {"settings": {}}):
            ups_svc.save_ups_settings({
                "shutdown": {"enabled": True, "evil": "x"},
                "low_battery_pct": 30,
                "junk": 1,
            })
        self.assertEqual(saved["ups"]["shutdown"], {"enabled": True})
        self.assertEqual(saved["ups"]["low_battery_pct"], 30)
        self.assertNotIn("junk", saved["ups"])


class ApiTests(PolicyBase):
    def _client(self, admin: str | None = "tester"):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from hub.routers import ups_api

        app = FastAPI()
        app.include_router(ups_api.router)
        if admin is not None:
            p = mock.patch.object(ups_api, "require_admin_browser", lambda request: admin)
            p.start()
            self.addCleanup(p.stop)
        return TestClient(app)

    def test_get_ups_carries_policy_state(self):
        ups_policy._save_state({"phase": "engaged", "reason": "r", "steps": []})
        with mock.patch.object(ups_svc, "ups_status", lambda force=False: {"present": False}):
            r = self._client().get("/api/ups")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["shutdown_state"]["phase"], "engaged")

    def test_put_settings_saves_nested_shutdown_and_audits(self):
        with mock.patch.object(ups_svc, "save_ups_settings",
                               return_value={"shutdown": {"enabled": True}}) as save, \
             mock.patch.object(ups_svc, "ups_settings",
                               return_value={"shutdown": dict(ups_svc.SHUTDOWN_DEFAULTS)}), \
             mock.patch.object(ups_svc, "ups_status", lambda force=False: {"present": False}), \
             mock.patch("hub.auth.request_username", lambda request: "tester"):
            r = self._client().put("/api/ups/settings", json={
                "shutdown": {"enabled": True, "trigger_pct": 30,
                             "stacks": ["immich", "teslamate"]},
            })
        self.assertEqual(r.status_code, 200)
        save.assert_called_once_with({
            "shutdown": {"enabled": True, "trigger_pct": 30,
                         "stacks": ["immich", "teslamate"]},
        })
        self.assertEqual([a[0] for a in self.audits], [audit.UPS_POLICY_CHANGED])

    def test_enabling_without_any_condition_is_refused(self):
        current = dict(ups_svc.SHUTDOWN_DEFAULTS)
        current["trigger_pct"] = None  # operator had switched pct off earlier
        with mock.patch.object(ups_svc, "ups_settings",
                               return_value={"shutdown": current}), \
             mock.patch.object(ups_svc, "save_ups_settings") as save:
            r = self._client().put("/api/ups/settings",
                                   json={"shutdown": {"enabled": True}})
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.json()["detail"]["code"], "ups.policy_no_condition")
        save.assert_not_called()

    def test_switching_last_condition_off_under_enabled_policy_is_refused(self):
        current = dict(ups_svc.SHUTDOWN_DEFAULTS)
        current["enabled"] = True
        with mock.patch.object(ups_svc, "ups_settings",
                               return_value={"shutdown": current}), \
             mock.patch.object(ups_svc, "save_ups_settings") as save:
            r = self._client().put("/api/ups/settings",
                                   json={"shutdown": {"trigger_pct": None}})
        self.assertEqual(r.status_code, 400)
        save.assert_not_called()

    def test_bad_stack_id_is_refused(self):
        r = self._client().put("/api/ups/settings", json={
            "shutdown": {"stacks": ["ok-stack", "../etc"]},
        })
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.json()["detail"]["code"], "ups.bad_stack_id")

    def test_drill_requires_admin_browser_session(self):
        r = self._client(admin=None).post("/api/ups/shutdown/drill")
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.json()["detail"]["code"], "admin.browser_session_required")

    def test_drill_is_audited_and_dry(self):
        with mock.patch.object(ups_policy, "_ups_status", lambda: _status(pct=50)), \
             mock.patch.object(ups_policy, "shutdown_settings",
                               lambda: _policy(trigger_pct=25)):
            r = self._client().post("/api/ups/shutdown/drill")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertFalse(body["would_trigger_now"])
        self.assertEqual(len(body["steps"]), 3)
        drills = [a for a in self.audits if a[0] == audit.UPS_POLICY_DRILL]
        self.assertEqual(len(drills), 1)
        self.assertEqual(drills[0][1]["username"], "tester")
        self.assertEqual(self.argv_calls, [])

    def test_plan_endpoint_is_the_unaudited_form_source(self):
        with mock.patch.object(ups_policy, "_ups_status", lambda: _status(pct=50)), \
             mock.patch.object(ups_policy, "shutdown_settings",
                               lambda: _policy(trigger_pct=25)):
            r = self._client(admin=None).get("/api/ups/shutdown/plan")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.audits, [])

    def test_halt_write_goes_through_admin_flow_and_audits(self):
        calls = []
        with mock.patch("hub.macos_admin.run_admin",
                        side_effect=lambda argv, timeout: calls.append(argv) or {"ok": True}), \
             mock.patch.object(ups_svc, "ups_status", lambda force=False: {"present": False}):
            r = self._client().put("/api/ups/halt", json={"haltlevel": 20})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(calls, [["/usr/bin/pmset", "-u", "haltlevel", "20"]])
        self.assertEqual([a[0] for a in self.audits], [audit.UPS_HALT_CHANGED])
        self.assertEqual(self.audits[0][1]["haltlevel"], 20)

    def test_halt_level_bounds(self):
        with mock.patch("hub.macos_admin.run_admin") as run:
            r = self._client().put("/api/ups/halt", json={"haltlevel": 3})
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.json()["detail"]["code"], "ups.halt_bad_level")
        run.assert_not_called()

    def test_halt_off_value_passes(self):
        with mock.patch("hub.macos_admin.run_admin",
                        return_value={"ok": True}) as run, \
             mock.patch.object(ups_svc, "ups_status", lambda force=False: {"present": False}):
            r = self._client().put("/api/ups/halt", json={"haltlevel": -1})
        self.assertEqual(r.status_code, 200)
        run.assert_called_once()

    def test_halt_password_required_maps_to_admin_error(self):
        """409 admin.password_required is what the SPA turns into its own
        macOS-password dialog and a retry — the same flow as shares/NFS."""
        with mock.patch("hub.macos_admin.run_admin",
                        return_value={"ok": False, "error": "password_required"}):
            r = self._client().put("/api/ups/halt", json={"haltlevel": 20})
        self.assertEqual(r.status_code, 409)
        self.assertEqual(r.json()["detail"]["code"], "admin.password_required")


class UpsClockLeftoverTests(unittest.TestCase):
    def test_infinite_clock_does_not_raise(self):
        """int(time.time()) OverflowError on leftover inf used to 500 UPS restore."""
        with mock.patch.object(ups_policy.time, "time", return_value=float("inf")):
            self.assertEqual(ups_policy._now(), 0)


class UpsPolicyJsonableLeftoverTests(unittest.TestCase):
    def test_isoformat_inf_date_bytes_set_do_not_500(self):
        """Leftover YAML dates/!!set/isoformat inf used to 500 GET /api/ups."""
        class _Stamp:
            def isoformat(self):
                return float("inf")

        class Recursing:
            def __str__(self):
                raise RecursionError("nested")

        self.assertEqual(ups_policy._as_text(Recursing()), "Recursing")
        self.assertIsNone(ups_policy._jsonable(_Stamp()))
        out = ups_policy._jsonable({
            "when": _Stamp(),
            "name": datetime.date(2026, 8, 19),
            "blob": b"ups",
            "tags": {"battery"},
            "n": float("inf"),
        })
        json.dumps(out, allow_nan=False)
        self.assertIsNone(out["when"])
        self.assertEqual(out["name"], "2026-08-19")
        self.assertEqual(out["blob"], "ups")
        self.assertEqual(out["tags"], ["battery"])
        self.assertIsNone(out["n"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
