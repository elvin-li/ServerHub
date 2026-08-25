"""Leftover UPS 500s: hex-YAML over-cap script ids, surrogate state-file
keys, the sudo-vanished 503 that fired without a disk confirm, and the
over-cap worker pid that aborted every policy sweep.

The earlier UPS hardening sweeps sanitized the *values* the endpoints emit
(``_jsonable`` drops inf/NaN/over-cap ints, re-encodes strings).  This sweep
covers the shapes that dodged those guards:

* YAML hex/octal integers load uncapped (``int(x, 16)`` is exempt from
  CPython's 4300-digit conversion limit), so a hand-edited leftover
  ``scripts: [{id: 0xFF…}]`` arrived *already-int* and the bare ``str()``
  inside ``ups_policy._catalog`` raised the digit-cap ValueError — 500ing
  GET /api/ups/shutdown/plan and POST /api/ups/shutdown/drill, i.e. the
  whole UPS settings form;
* ``_jsonable`` re-encoded string *values* but passed string *keys* through
  untouched, so a leftover JSON ``"\\ud800…"`` key inside the policy state
  file's ``last`` / ``steps`` 500'd Starlette's UTF-8 encode of GET
  /api/ups — and ``_save_state``'s own encode failed the same way, so every
  ``_mutate`` silently stopped persisting while the poisoned key sat there
  (the crash-safety contract gone, with nothing logged);
* ``macos_admin._run_with_password`` classified any failed sudo spawn as
  ``unavailable`` (the coded 503 "macOS administrator authorization is
  unavailable") on the exception alone.  execve also ENOENTs for a
  still-present binary whose loader is broken, and a spawn can fail for
  reasons that have nothing to do with sudo (ENOMEM), so PUT /api/ups/halt
  misdirected the operator while sudo sat right there.  The vanished-CLI
  503 now fires only after a fresh disk probe confirms sudo is gone (the
  vms/rsync/backups rule), probing only on that failure path;
* ``_worker_busy`` probed the persisted worker pid with ``os.kill(pid, 0)``
  catching only OSError; a leftover pid past the C long range raises
  OverflowError, which escaped ``sweep()`` — check_once's containment ate
  it, so the whole UPS policy tick silently aborted on every sweep, never
  engaging and never restoring.  A ``pid: true`` leftover (bool passes
  ``isinstance(int)``) probed pid 1 and read busy for up to a day.
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

import hub.config as config  # noqa: E402
from hub import macos_admin, ups_policy, ups_svc  # noqa: E402

#: Built arithmetically: int("9" * 5000) itself trips the parse cap.
_HUGE_INT = 10 ** 5000


def _starlette(payload) -> None:
    """What Starlette's JSONResponse does to the body."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


def _client():
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


class CatalogOverCapHexIntTests(UpsPolicyStateBase):
    """GET /api/ups/shutdown/plan drops the poisoned script, not the route."""

    def _plan(self, scripts):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                config, "cfg", lambda: {"scripts": scripts},
            ))
            stack.enter_context(mock.patch.object(
                ups_policy, "_list_stacks", lambda: [],
            ))
            stack.enter_context(mock.patch.object(
                ups_policy, "_ups_status", lambda: {"present": False},
            ))
            stack.enter_context(mock.patch.object(
                ups_svc, "cfg", lambda: {"settings": {}},
            ))
            return _client().get("/api/ups/shutdown/plan")

    def test_hex_yaml_loads_past_the_digit_cap(self):
        """The vector this file guards: PyYAML routes 0x text through
        int(raw, 16), which the conversion limit does not apply to."""
        import yaml
        loaded = yaml.safe_load("id: 0x" + "f" * 5000)
        self.assertIsInstance(loaded["id"], int)
        with self.assertRaises(ValueError):
            str(loaded["id"])

    def test_over_cap_script_id_drops_only_its_entry(self):
        resp = self._plan([
            {"id": _HUGE_INT, "name": "poisoned", "stop": "x stop"},
            {"id": "gravity", "name": "Gravity", "stop": "g stop"},
        ])
        self.assertEqual(resp.status_code, 200)
        scripts = resp.json()["catalog"]["scripts"]
        self.assertEqual([s["id"] for s in scripts], ["gravity"])

    def test_over_cap_script_name_falls_back_to_the_id(self):
        resp = self._plan([{"id": "gravity", "name": _HUGE_INT}])
        self.assertEqual(resp.status_code, 200)
        scripts = resp.json()["catalog"]["scripts"]
        self.assertEqual(scripts, [
            {"id": "gravity", "name": "gravity", "has_stop": False},
        ])

    def test_sane_numeric_id_still_coerces(self):
        """A numeric id is odd but was accepted; this sweep keeps it."""
        resp = self._plan([{"id": 42, "name": "answer"}])
        self.assertEqual(resp.status_code, 200)
        scripts = resp.json()["catalog"]["scripts"]
        self.assertEqual(scripts[0]["id"], "42")

    def test_surrogate_script_name_stays_encodable(self):
        resp = self._plan([{"id": "gravity", "name": "grav\ud800ity"}])
        self.assertEqual(resp.status_code, 200)
        _starlette(resp.json())


class SurrogateStateKeyTests(UpsPolicyStateBase):
    """A lone-surrogate key in the state file must not 500 GET /api/ups."""

    def _get_ups(self):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                ups_svc, "cfg", lambda: {"settings": {}},
            ))
            stack.enter_context(mock.patch.object(
                ups_svc, "ups_snapshot",
                lambda force=False: {"present": False, "halt_levels": None},
            ))
            return _client().get("/api/ups")

    def test_surrogate_key_in_last_is_sanitized(self):
        self.state_file.write_text(json.dumps({
            "phase": "idle",
            "last": {"reason": "battery 18% ≤ 25%", "\ud800detail": 1},
        }))
        resp = self._get_ups()
        self.assertEqual(resp.status_code, 200)
        _starlette(resp.json())
        last = resp.json()["shutdown_state"]["last"]
        self.assertEqual(last["reason"], "battery 18% ≤ 25%")

    def test_surrogate_key_in_steps_is_sanitized(self):
        self.state_file.write_text(json.dumps({
            "phase": "engaged",
            "steps": [{"kind": "stack", "id": "immich", "\ud800x": True}],
        }))
        resp = self._get_ups()
        self.assertEqual(resp.status_code, 200)
        _starlette(resp.json())
        steps = resp.json()["shutdown_state"]["steps"]
        self.assertEqual(steps[0]["id"], "immich")

    def test_mutate_still_persists_beside_a_poisoned_key(self):
        """_save_state's encode used to fail silently, so the latch —
        the whole crash-safety contract — was never written to disk."""
        self.state_file.write_text(json.dumps({
            "phase": "idle",
            "last": {"\ud800detail": 1},
        }))
        ups_policy._mutate(lambda s: s.update(phase="engaged"))
        on_disk = json.loads(self.state_file.read_text())
        self.assertEqual(on_disk.get("phase"), "engaged")


class WorkerPidOverflowTests(UpsPolicyStateBase):
    """A leftover pid past the C long range must not abort the sweep."""

    def _sweep(self):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                ups_policy, "_ups_status", lambda: {
                    "present": True, "on_battery": True, "on_ac": False,
                    "battery_percent": 10, "time_remaining_min": 5,
                },
            ))
            stack.enter_context(mock.patch.object(
                ups_svc, "cfg", lambda: {"settings": {"ups": {"shutdown": {
                    "enabled": True, "trigger_pct": 25,
                }}}},
            ))
            spawned: list = []
            stack.enter_context(mock.patch.object(
                ups_policy, "_spawn", lambda target: spawned.append(target.__name__) or True,
            ))
            return ups_policy.sweep(1_800_000_100), spawned

    def test_sweep_survives_and_resumes_past_an_over_cap_pid(self):
        self.state_file.write_text(json.dumps({
            "phase": "engaged",
            "steps": [{"kind": "stack", "id": "immich", "running": True}],
            "stop_done": False,
            "worker_owner": {"pid": 10 ** 19, "ts": 1_800_000_000},
        }))
        emitted, spawned = self._sweep()
        self.assertEqual(emitted, [])
        # The dead-looking owner reads as free, so the interrupted stop
        # sequence resumes instead of the tick raising OverflowError.
        self.assertEqual(spawned, ["_run_stop_sequence"])

    def test_bool_pid_does_not_read_as_pid_one(self):
        """``pid: true`` passes isinstance(int) and probed pid 1 — always
        alive — wedging the policy as busy for up to a day."""
        self.assertFalse(ups_policy._worker_busy({
            "worker_owner": {"pid": True, "ts": ups_policy._now()},
        }))

    def test_nonpositive_pid_reads_as_free(self):
        for pid in (0, -1):
            with self.subTest(pid=pid):
                self.assertFalse(ups_policy._worker_busy({
                    "worker_owner": {"pid": pid, "ts": ups_policy._now()},
                }))

    def test_live_pid_still_reads_busy(self):
        import os
        self.assertTrue(ups_policy._worker_busy({
            "worker_owner": {"pid": os.getpid(), "ts": ups_policy._now()},
        }))


class SudoVanishedDiskConfirmTests(unittest.TestCase):
    """The admin ``unavailable`` 503 fires only after a disk confirm."""

    def _run_admin(self, on_disk):
        def boom(*_a, **_k):
            raise FileNotFoundError(2, "No such file or directory", macos_admin.SUDO)

        with (
            mock.patch.object(macos_admin.subprocess, "run", boom),
            mock.patch.object(macos_admin, "_sudo_on_disk", lambda: on_disk),
            macos_admin.use_admin_password("hunter2"),
        ):
            return macos_admin.run_admin(
                ["/usr/bin/pmset", "-u", "haltlevel", "50"],
            )

    def test_spawn_failure_with_sudo_on_disk_is_not_unavailable(self):
        """rc -1 is also ENOMEM / a broken loader; while sudo is still on
        disk, "authorization is unavailable" misdirects the operator."""
        result = self._run_admin(on_disk=True)
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "failed")
        self.assertIn("No such file", result["message"])

    def test_spawn_failure_with_sudo_gone_keeps_the_coded_503(self):
        result = self._run_admin(on_disk=False)
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "unavailable")
        from hub.routers.nas_common import raise_for_admin_result
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as ctx:
            raise_for_admin_result(result)
        self.assertEqual(ctx.exception.status_code, 503)

    def test_successful_run_never_probes_the_disk(self):
        """The re-check runs only on the failure path (the ollama rule)."""
        probe = mock.Mock(return_value=True)
        completed = mock.Mock(returncode=0, stdout="", stderr="")
        with (
            mock.patch.object(macos_admin.subprocess, "run", return_value=completed),
            mock.patch.object(macos_admin, "_sudo_on_disk", probe),
            macos_admin.use_admin_password("hunter2"),
        ):
            result = macos_admin.run_admin(
                ["/usr/bin/pmset", "-u", "haltlevel", "50"],
            )
        self.assertTrue(result["ok"])
        probe.assert_not_called()

    def test_prime_sudo_ticket_follows_the_same_rule(self):
        def boom(*_a, **_k):
            raise FileNotFoundError(2, "No such file or directory", macos_admin.SUDO)

        for on_disk, expected in ((True, "failed"), (False, "unavailable")):
            with self.subTest(on_disk=on_disk):
                with (
                    mock.patch.object(macos_admin.subprocess, "run", boom),
                    mock.patch.object(macos_admin, "_sudo_on_disk", lambda v=on_disk: v),
                    macos_admin.use_admin_password("hunter2"),
                ):
                    result = macos_admin.prime_sudo_ticket()
                self.assertEqual(result["error"], expected)

    def test_sudo_on_disk_probe_matches_the_filesystem(self):
        self.assertEqual(
            macos_admin._sudo_on_disk(), Path(macos_admin.SUDO).is_file(),
        )
        with mock.patch.object(
            macos_admin.Path, "is_file", side_effect=OSError(5, "EIO"),
        ):
            # A dying volume counts as gone: authorization is unreachable
            # either way, so the coded 503 is the honest answer.
            self.assertFalse(macos_admin._sudo_on_disk())


if __name__ == "__main__":
    unittest.main(verbosity=2)
