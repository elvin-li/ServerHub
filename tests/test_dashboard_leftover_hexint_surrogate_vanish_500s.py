"""Leftover Dashboard 500s: hex-YAML over-cap ints, surrogate host CLIs,
and the vanished-docker action that answered an uncoded 500.

The digit-cap battery (test_leftover_host_sensor_digit_500s) pinned the
*string* parses — over-cap sysctl/pmset payloads arrive as str and die in
``int(text)``.  This sweep covers the shapes that dodge that cap on the
Dashboard's own endpoints:

* YAML hex/octal integers load uncapped (``int(x, 16)`` is exempt from
  CPython's 4300-digit conversion limit), so a leftover ``port: 0xFF…`` in
  ``quick_links`` arrived *already-int*, passed ``status._jsonable``'s bare
  ``isinstance(value, int)`` branch untouched, and Starlette's ``json.dumps``
  itself raised the int->str digit-cap ValueError — 500ing GET /api/status.
  The same passthrough let an over-cap int planted in the status cache 500
  GET /api/health (``cached_status`` promises to re-sanitize) and an
  over-cap member ``port`` 500 the member GET /api/status
  (``filter_status_for_resources`` uses the same sanitizer).  ``system.
  _jsonable`` had the identical gap, so a leftover in the SMART cache 500'd
  the ``system`` leg of GET /api/status (metrics/docker_cli already guard);
* ``_host_snapshot`` resolves ``docker_cli`` / ``orb_cli`` via
  ``shutil.which`` at import, and ``os.environ`` decodes PATH with
  surrogateescape — a leftover non-UTF-8 byte there surfaces as a lone
  surrogate in the resolved path, which the snapshot returned raw and 500'd
  GET /api/system/host at Starlette's UTF-8 encode (every sibling field
  already goes through ``_as_text``);
* a docker CLI that vanished between the registry read and the spawn made
  POST /api/action answer HTTP 500 with the raw ``sh`` sentinel ``"not
  found"`` — the same operator-facing state the branch right next to it
  already maps to the coded 503 ``container.engine_down`` for daemon-socket
  failures.  Classification requires the disk confirm (the docker_cli
  ``looks_cli_vanished`` contract: pattern-match, then confirm), run only
  on the failure path, so a still-present CLI whose output merely reads
  ``not found`` keeps its raw result.
"""
from __future__ import annotations

import json
import unittest
from unittest import mock

from fastapi import HTTPException

from hub import actions, status, system
from hub.routers import system_extra

#: Built arithmetically: int("9" * 5000) itself trips the digit cap.
_HUGE_INT = 10 ** 5000


def _starlette(payload) -> None:
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


def _code(exc: HTTPException) -> str:
    detail = exc.detail
    return detail["code"] if isinstance(detail, dict) else str(detail)


class HexYamlVectorTest(unittest.TestCase):
    def test_hex_yaml_loads_past_the_digit_cap(self):
        """The vector this file guards: PyYAML routes 0x text through
        int(raw, 16), which the conversion limit does not apply to."""
        import yaml
        loaded = yaml.safe_load("port: 0x" + "f" * 5000)
        self.assertIsInstance(loaded["port"], int)
        with self.assertRaises(ValueError):
            str(loaded["port"])


class StatusOverCapIntTests(unittest.TestCase):
    """status._jsonable must drop what json.dumps cannot render."""

    def _build(self, cfg_data):
        patches = [
            mock.patch.object(status, "cfg", lambda: cfg_data),
            mock.patch.object(status, "discover_launchd", lambda: []),
            mock.patch.object(status, "discover_containers", lambda: ([], True)),
            mock.patch.object(status, "discover_vms", lambda: []),
            mock.patch.object(status, "collect_system", lambda: {"load1": 0.1}),
            mock.patch.object(status, "collect_scripts", lambda: []),
            mock.patch.object(status, "collect_apps", lambda up: []),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        return status._build_status()

    def test_quick_link_hex_int_does_not_500_status(self):
        payload = self._build({
            "settings": {"adaptive": False},
            "quick_links": [
                {"name": "NAS", "url": "http://x", "port": _HUGE_INT},
            ],
        })
        _starlette(payload)
        self.assertEqual(payload["links"][0]["name"], "NAS")
        self.assertIsNone(payload["links"][0]["port"])

    def test_service_row_hex_port_does_not_500_status(self):
        payload = self._build({"settings": {"adaptive": False}})
        # A planted row with an over-cap port travels the same sanitizer.
        cleaned = status._jsonable(
            {"id": "svc", "port": _HUGE_INT, "ports": [_HUGE_INT, 80]}
        )
        _starlette(cleaned)
        self.assertIsNone(cleaned["port"])
        self.assertEqual(cleaned["ports"], [None, 80])
        _starlette(payload)

    def test_planted_cache_over_cap_count_does_not_500_health(self):
        """cached_status() promises to re-sanitize the planted cache —
        GET /api/health serves its ``counts`` straight to the encoder."""
        with mock.patch.dict(
            status._status_cache, {"t": 0, "v": {"counts": {"ok": _HUGE_INT}}}
        ):
            got = status.cached_status()
        _starlette(got)
        self.assertIsNone(got["counts"]["ok"])

    def test_member_filter_over_cap_port_does_not_500(self):
        snap = {"groups": [{"group": "G", "services": [{
            "id": "svc", "name": "svc", "state": "ok",
            "port": _HUGE_INT, "actions": ["open"],
        }]}]}
        got = status.filter_status_for_resources(snap, ["svc"])
        _starlette(got)
        self.assertIsNone(got["groups"][0]["services"][0]["port"])

    def test_finite_ints_still_pass(self):
        cleaned = status._jsonable({"port": 8080, "count": -3})
        self.assertEqual(cleaned, {"port": 8080, "count": -3})


class SystemOverCapIntTests(unittest.TestCase):
    """system._jsonable seals the ``system`` leg of GET /api/status."""

    def test_planted_smart_cache_over_cap_int_does_not_500(self):
        with mock.patch.dict(
            system._smart_cache, {"t": 10 ** 12, "v": {"written": _HUGE_INT}}
        ):
            got = system.collect_system()
        _starlette(got)
        self.assertIsNone(got["smart"]["written"])

    def test_finite_ints_still_pass(self):
        self.assertEqual(system._jsonable({"ncpu": 8}), {"ncpu": 8})


class HostSnapshotSurrogateTests(unittest.TestCase):
    """GET /api/system/host must survive surrogate CLI paths."""

    def test_surrogate_docker_cli_does_not_500_host(self):
        with mock.patch.object(system_extra, "DOCKER", "/usr/local/bin/d\ud800ocker"), \
             mock.patch.object(system_extra, "ORB", "/opt/homebrew/bin/o\ud800rb"):
            snap = system_extra._host_snapshot(True)
        # Snapshot is memoised; the poisoned entry must not be served later.
        self.addCleanup(system_extra._host_snapshot.invalidate)
        _starlette(snap)
        self.assertNotIn("\ud800", snap["docker_cli"])
        self.assertNotIn("\ud800", snap["orb_cli"])

    def test_clean_cli_paths_pass_through(self):
        with mock.patch.object(system_extra, "DOCKER", "/usr/local/bin/docker"), \
             mock.patch.object(system_extra, "ORB", "/usr/local/bin/orb"):
            snap = system_extra._host_snapshot(True)
        self.addCleanup(system_extra._host_snapshot.invalidate)
        self.assertEqual(snap["docker_cli"], "/usr/local/bin/docker")
        self.assertEqual(snap["orb_cli"], "/usr/local/bin/orb")


class VanishedDockerActionTests(unittest.TestCase):
    """POST /api/action on a container: vanished CLI is the coded 503."""

    def _run(self, sh_result, *, on_disk: bool, engine: bool = False):
        with mock.patch.object(actions, "registry",
                               lambda: {"web": ("container", {})}), \
             mock.patch.object(actions, "sh", lambda *a, **k: sh_result), \
             mock.patch.object(actions, "cli_on_disk", lambda: on_disk), \
             mock.patch.object(actions, "engine_up", lambda force=False: engine):
            return actions.run_action("web", "stop")

    def test_vanished_cli_answers_coded_engine_down(self):
        """The sentinel + a disk probe confirming the CLI left ->
        the same coded 503 the daemon-socket classifier next to it raises,
        instead of HTTP 500 with the raw two-word sentinel."""
        with self.assertRaises(HTTPException) as caught:
            self._run((-1, "", "not found"), on_disk=False)
        self.assertEqual(_code(caught.exception), "container.engine_down")
        self.assertEqual(caught.exception.status_code, 503)

    def test_sentinel_with_cli_on_disk_keeps_raw_result(self):
        """rc -1 with the CLI still present (a cwd that vanished raises the
        same FileNotFoundError) must not be blamed on the engine."""
        rc, out, err = self._run((-1, "", "not found"), on_disk=True)
        self.assertEqual((rc, out, err), (-1, "", "not found"))

    def test_real_exit_saying_not_found_keeps_raw_result(self):
        """A genuine docker exit whose stderr reads "not found" is that
        container's own truth, not a vanished CLI."""
        rc, out, err = self._run((1, "", "not found"), on_disk=False, engine=True)
        self.assertEqual((rc, out, err), (1, "", "not found"))

    def test_running_engine_never_reports_engine_down(self):
        """The forced probe stays the final arbiter, matching the
        daemon-socket branch."""
        rc, out, err = self._run((-1, "", "not found"), on_disk=False, engine=True)
        self.assertEqual((rc, out, err), (-1, "", "not found"))


if __name__ == "__main__":
    unittest.main()
