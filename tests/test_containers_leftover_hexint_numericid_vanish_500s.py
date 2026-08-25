"""Leftover 500s / silent-loss classes on the Docker containers domain.

Four survivors of the earlier container sweeps, all reproduced before the fix:

* **fixed** — every docker mutation in ``containers_svc`` (action / exec /
  prune / rm / rmi / pull / rename / run / volume / network / restart-policy)
  routed failures through ``_raise_if_engine_down``, whose only gate was the
  daemon-socket message pattern.  The docker CLI *itself* vanishing
  mid-request surfaces as ``sh``'s two-word sentinel ``"not found"`` (rc -1),
  which that pattern never matches — so the response was an uncoded
  ``{"ok": false, "message": "not found"}`` instead of the coded 503
  ``container.engine_down`` every sibling classifier (compose, actions,
  tools, services) already raises.  Classification now requires the sentinel
  AND a fresh on-disk ``cli_on_disk`` probe, both on the failure path only;
  timeouts and genuine CLI exits keep their original shape.

* **fixed** — both branches of ``_stack_paths`` gated the configured stack
  ``id`` with ``isinstance(x, str)``.  YAML ``id: 42`` loads as an int, so a
  containers-only stack silently vanished from GET /api/stacks and a path
  stack was silently renamed to its directory name (POST /api/stacks/42/run
  then 404'd a stack the operator could see).  A ``_field_text`` str()-probe
  renders the numeric id; only genuinely unrenderable ids (huge hex ints
  past CPython's digit cap, mappings) still fall back.

* **fixed** — a leftover >4300-digit number in docker-update-status.json
  made ``json.loads`` itself raise ValueError (int(str) digit cap — NOT
  JSONDecodeError), which ``_load_update_status`` read as a corrupt file:
  the whole journal fell to ``{}`` and the next ``_save_update_status``
  silently wiped every other image's update state.  The same ValueError
  turned ``docker inspect`` output containing one huge number into a coded
  404 ``container.not_found`` for a container that exists, dropped whole
  NDJSON inventory rows, and collapsed the engine-info panel into a raw
  blob.  ``docker_cli.parse_int_capped`` loads the huge literal as None
  (the drop ``_jsonable`` already applies to an already-int leftover) so
  every sibling entry survives.

* **stays immune** — lone surrogates in the update journal's keys AND
  values are scrubbed by ``_jsonable`` before they can reach Starlette's
  UTF-8 encode; pinned here so the funnel cannot regress.
"""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

import yaml  # noqa: E402
from fastapi import HTTPException  # noqa: E402

from hub import containers_svc, docker_cli, docker_info_svc  # noqa: E402

#: Loads as an int past CPython's 4300-digit str<->int cap: hex conversion is
#: uncapped, so the value exists in memory and only str() explodes.
_HUGE_HEX_YAML = "0x" + "f" * 5000
#: A JSON literal past the cap: ``json.loads`` raises ValueError while
#: *parsing* it (int(str) cap), before any encoder is involved.
_HUGE_JSON_INT = "1" * 5000


def _starlette(payload) -> None:
    """What Starlette's JSONResponse does to a payload."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class VanishedCliMutation503Tests(unittest.TestCase):
    """A docker CLI gone from disk is a coded 503, not a raw sentinel."""

    def _quiet(self):
        return (
            mock.patch.object(containers_svc, "invalidate_container_lists"),
            mock.patch.object(containers_svc, "invalidate_status"),
        )

    def test_vanished_cli_mutations_carry_the_code(self):
        calls = {
            "action": lambda: containers_svc.container_action("web", "restart"),
            "exec": lambda: containers_svc.exec_in_container("web", "ls"),
            "policy": lambda: containers_svc.set_restart_policy("web", "always"),
            "prune": lambda: containers_svc.prune("system"),
            "rmi": lambda: containers_svc.remove_image("nginx:latest"),
            "volume_rm": lambda: containers_svc.remove_volume("data"),
            "network_rm": lambda: containers_svc.remove_network("appnet"),
            "pull": lambda: containers_svc.pull_image("nginx:latest"),
            "rename": lambda: containers_svc.rename_container("web", "web2"),
            "volume_create": lambda: containers_svc.create_volume("data"),
            "network_create": lambda: containers_svc.create_network("appnet"),
        }
        q1, q2 = self._quiet()
        with (
            mock.patch.object(
                containers_svc, "docker", return_value=(-1, "", "not found")
            ),
            mock.patch.object(containers_svc, "cli_on_disk", return_value=False),
            mock.patch.object(containers_svc, "engine_up", return_value=False),
            q1, q2,
        ):
            for label, call in calls.items():
                with self.subTest(label):
                    with self.assertRaises(HTTPException) as ctx:
                        call()
                    self.assertEqual(ctx.exception.status_code, 503)
                    self.assertEqual(
                        ctx.exception.detail["code"], "container.engine_down"
                    )

    def test_batch_rows_carry_the_code(self):
        q1, q2 = self._quiet()
        with (
            mock.patch.object(
                containers_svc, "docker", return_value=(-1, "", "not found")
            ),
            mock.patch.object(containers_svc, "cli_on_disk", return_value=False),
            mock.patch.object(containers_svc, "engine_up", return_value=False),
            q1, q2,
        ):
            out = containers_svc.batch_action(["a", "b"], "stop")
        self.assertFalse(out["ok"])
        for row in out["results"]:
            self.assertEqual(row["code"], "container.engine_down")
        _starlette(out)

    def test_sentinel_with_the_cli_still_on_disk_keeps_the_raw_shape(self):
        # ``"not found"`` is any FileNotFoundError spawn; with the binary
        # present the failure is something else and must not be relabelled —
        # and the engine is never probed for it.
        probe = mock.Mock(side_effect=AssertionError("engine probed"))
        q1, q2 = self._quiet()
        with (
            mock.patch.object(
                containers_svc, "docker", return_value=(-1, "", "not found")
            ),
            mock.patch.object(containers_svc, "cli_on_disk", return_value=True),
            mock.patch.object(containers_svc, "engine_up", probe),
            q1, q2,
        ):
            out = containers_svc.container_action("web", "restart")
        self.assertEqual(out, {"ok": False, "message": "not found"})

    def test_timeouts_keep_their_shape_and_never_probe(self):
        engine = mock.Mock(side_effect=AssertionError("engine probed"))
        disk = mock.Mock(side_effect=AssertionError("disk probed"))
        q1, q2 = self._quiet()
        with (
            mock.patch.object(
                containers_svc, "docker", return_value=(-1, "", "timeout")
            ),
            mock.patch.object(containers_svc, "cli_on_disk", disk),
            mock.patch.object(containers_svc, "engine_up", engine),
            q1, q2,
        ):
            out = containers_svc.container_action("web", "restart")
        self.assertEqual(out, {"ok": False, "message": "timeout"})

    def test_auth_style_failures_keep_their_stderr(self):
        engine = mock.Mock(side_effect=AssertionError("engine probed"))
        disk = mock.Mock(side_effect=AssertionError("disk probed"))
        q1, q2 = self._quiet()
        with (
            mock.patch.object(
                containers_svc, "docker",
                return_value=(1, "", "unauthorized: authentication required"),
            ),
            mock.patch.object(containers_svc, "cli_on_disk", disk),
            mock.patch.object(containers_svc, "engine_up", engine),
            q1, q2,
        ):
            out = containers_svc.pull_image("nginx:latest")
        self.assertFalse(out["ok"])
        self.assertIn("unauthorized", out["message"])

    def test_the_healthy_path_never_probes(self):
        engine = mock.Mock(side_effect=AssertionError("engine probed"))
        disk = mock.Mock(side_effect=AssertionError("disk probed"))
        q1, q2 = self._quiet()
        with (
            mock.patch.object(
                containers_svc, "docker", return_value=(0, "web", "")
            ),
            mock.patch.object(containers_svc, "cli_on_disk", disk),
            mock.patch.object(containers_svc, "engine_up", engine),
            q1, q2,
        ):
            out = containers_svc.container_action("web", "restart")
        self.assertTrue(out["ok"])


class NumericStackIdTests(unittest.TestCase):
    """YAML ``id: 42`` is a stack the operator can see and address."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="stack-numeric-id-"))
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))

    def _stacks(self, entries):
        with (
            mock.patch.object(
                containers_svc, "cfg", return_value={"stacks": entries}
            ),
            mock.patch.object(containers_svc, "user_home", return_value=None),
        ):
            return containers_svc._stack_paths()

    def test_numeric_id_on_a_containers_only_stack_is_kept(self):
        entry = yaml.safe_load("id: 42\ncontainers: [db]\n")
        self.assertIsInstance(entry["id"], int)
        stacks = self._stacks([entry])
        self.assertEqual(len(stacks), 1)
        self.assertEqual(stacks[0]["id"], "42")
        self.assertEqual(stacks[0]["name"], "42")
        _starlette({"stacks": stacks})

    def test_numeric_id_on_a_path_stack_stays_addressable(self):
        d = self.tmp / "mydir"
        d.mkdir()
        (d / "docker-compose.yml").write_text("services: {}\n")
        stacks = self._stacks([{"id": 42, "path": str(d)}])
        # Before the probe this silently became "mydir", so
        # POST /api/stacks/42/run 404'd a stack the operator could see.
        self.assertEqual(stacks[0]["id"], "42")
        _starlette({"stacks": stacks})

    def test_huge_hex_id_still_falls_back_without_raising(self):
        huge = yaml.safe_load(f"id: {_HUGE_HEX_YAML}")["id"]
        self.assertIsInstance(huge, int)
        d = self.tmp / "hexdir"
        d.mkdir()
        stacks = self._stacks([
            {"id": huge, "path": str(d)},
            {"id": huge, "containers": ["db"]},
        ])
        # The path stack falls back to its directory name; the containers-only
        # stack has nothing renderable to address it by and is skipped.
        self.assertEqual(len(stacks), 1)
        self.assertEqual(stacks[0]["id"], "hexdir")
        _starlette({"stacks": stacks})


class UpdateJournalHugeNumberTests(unittest.TestCase):
    """One poisoned entry must not wipe every other image's journal state."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="upd-journal-"))
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))
        self.path = self.tmp / "docker-update-status.json"

    def _load(self):
        with mock.patch.object(containers_svc, "UPDATE_STATUS_PATH", self.path):
            return containers_svc._load_update_status()

    def test_huge_number_does_not_wipe_the_journal(self):
        self.path.write_text(
            '{"nginx:latest": {"status": "false", "update": false},'
            ' "leftover": ' + _HUGE_JSON_INT + "}"
        )
        loaded = self._load()
        # The sibling survives; the unrenderable number loads as None.
        self.assertEqual(
            loaded["nginx:latest"], {"status": "false", "update": False}
        )
        self.assertIsNone(loaded["leftover"])
        _starlette(loaded)

    def test_save_after_load_keeps_the_siblings(self):
        self.path.write_text(
            '{"nginx:latest": {"status": "false"}, "n": ' + _HUGE_JSON_INT + "}"
        )
        with mock.patch.object(containers_svc, "UPDATE_STATUS_PATH", self.path):
            status = containers_svc._load_update_status()
            status["redis:7"] = {"status": "true"}
            containers_svc._save_update_status(status)
            again = containers_svc._load_update_status()
        self.assertIn("nginx:latest", again)
        self.assertIn("redis:7", again)

    def test_surrogate_keys_and_values_stay_immune(self):
        # Stays-immune pin: _jsonable scrubs both sides before Starlette.
        self.path.write_text(
            json.dumps(
                {"k\ud800ey": {"status": "x\ud800"}, "_checked_at": "t\ud800"},
                ensure_ascii=True,
            )
        )
        loaded = self._load()
        _starlette(loaded)
        for key in loaded:
            self.assertNotIn("\ud800", key)
        self.assertNotIn("\ud800", loaded["_checked_at"])

    def test_truly_corrupt_json_still_reads_empty(self):
        self.path.write_text("{not json")
        self.assertEqual(self._load(), {})


class InspectHugeNumberTests(unittest.TestCase):
    """A huge number inside docker JSON is a dropped field, not a lost doc."""

    _INSPECT = (
        '[{"Id": "abcdef123456", "Name": "/web",'
        ' "Config": {"Image": "nginx"}, "Leftover": ' + _HUGE_JSON_INT + "}]"
    )

    def test_inspect_object_survives_a_huge_int(self):
        data = docker_cli.inspect_object(self._INSPECT)
        self.assertIsInstance(data, dict)
        self.assertEqual(data["Name"], "/web")
        self.assertIsNone(data["Leftover"])

    def test_inspect_container_is_not_a_404_lie(self):
        with mock.patch.object(
            containers_svc, "docker", return_value=(0, self._INSPECT, "")
        ):
            out = containers_svc.inspect_container("web")
        self.assertEqual(out["Name"], "web")
        _starlette(out)

    def test_ndjson_rows_with_a_huge_int_still_list(self):
        ndjson = (
            '{"Repository": "nginx", "Size": ' + _HUGE_JSON_INT + "}\n"
            '{"Repository": "redis", "Size": 123}\n'
        )
        with mock.patch.object(
            docker_cli, "docker", return_value=(0, ndjson, "")
        ):
            rows, rc, err = docker_cli.docker_json(
                ["images", "--format", "{{json .}}"]
            )
        self.assertEqual(rc, 0)
        self.assertEqual([r["Repository"] for r in rows], ["nginx", "redis"])
        self.assertIsNone(rows[0]["Size"])
        _starlette({"images": rows})

    def test_engine_info_keeps_its_fields(self):
        payload = (
            '{"ServerVersion": "27.1", "NCPU": ' + _HUGE_JSON_INT + "}"
        )
        with mock.patch.object(
            docker_info_svc, "docker", return_value=(0, payload, "")
        ):
            slim = docker_info_svc._slim_info()
        # Before the hook the whole decode fell to a raw-text blob and every
        # slim field read None.
        self.assertEqual(slim["ServerVersion"], "27.1")
        self.assertIsNone(slim["NCPU"])
        _starlette(slim)


if __name__ == "__main__":
    unittest.main()
