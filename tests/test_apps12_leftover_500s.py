"""Twelfth leftover-500s sweep of the Apps managed surfaces.

apps11 sealed the junk ``sh()`` shapes behind the native logs' launchctl
branch (``_sh_triple`` + ``_rc_int``).  What was still live on the pre-fix
tree, driven through ``create_app()`` +
``TestClient(raise_server_exceptions=False)``, was the same rc/shape family
riding the two spawn seams that wave never reached:

* GET /api/apps/managed/detail?id=docker:* — ``_inspect`` guards the
  ``docker()`` *call* and unpack but hands the rc slot back verbatim, so an
  rc-*subclass* whose ``__ne__`` raises rode through its try and detonated
  the bare ``rc != 0`` probe in ``_docker_detail``'s per-container loop —
  a raw 500 on the detail route after every inspect had already run.
* GET /api/apps/managed/logs?id=docker:* and the compose branches of
  POST /api/apps/managed/action — ``_compose_cmd`` unpacked ``run_capped``'s
  return bare and probed the rc bare (``rc == -1`` / ``rc != 0`` /
  ``rc == 0``).  The try around the runner absorbed a wrong-arity tuple and
  an rc ``__eq__``/``__ne__`` bomb into ``ok: false`` — never a 500 — but
  the compose output already in hand was folded into the bomb's own
  message with it (the apps11 ``run_action`` story, one seam over).

No new error codes: the locales are untouched.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from hub import apps_manage_svc
from hub.app_factory import create_app
from hub.auth import require_auth

_app = None


def _client() -> TestClient:
    global _app
    if _app is None:
        _app = create_app()
        _app.dependency_overrides[require_auth] = lambda: None
    return TestClient(_app, raise_server_exceptions=False)


def _strict_utf8(resp) -> str:
    """The body must already be valid UTF-8 — decode strictly on purpose."""
    return resp.content.decode("utf-8")


# ─── leftover zoo ─────────────────────────────────────────────────────────────

class _NeBombInt(int):
    """An rc whose ``==``/``!=`` probes raise; the real value sits underneath."""

    def __eq__(self, other):
        raise RuntimeError("leftover rc __eq__ bomb")

    __ne__ = __eq__
    __hash__ = int.__hash__


_INSPECT_JSON = json.dumps([{
    "Mounts": [{"Type": "bind", "Source": "/srv/web/data",
                "Destination": "/data", "RW": True}],
    "NetworkSettings": {
        "Networks": {"web_default": {"IPAddress": "172.18.0.2",
                                     "Gateway": "172.18.0.1"}},
        "Ports": {"80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}]},
    },
    "Config": {"Env": ["TZ=UTC"]},
}])


# ─── rigs ─────────────────────────────────────────────────────────────────────

class _DockerDetailRig(unittest.TestCase):
    """One related container; the ``docker()`` helper is planted per test."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        services = Path(self._tmp.name) / "services"
        services.mkdir()
        apps_manage_svc.inventory.invalidate()
        self.addCleanup(apps_manage_svc.inventory.invalidate)
        for target, kwargs in (
            ("hub.apps_manage_svc.SERVICES_ROOT", {"new": services}),
            ("hub.containers_svc.list_stacks", {"return_value": []}),
            ("hub.containers_svc.list_containers", {"return_value": {
                "containers": [{"id": "web1", "project": "web",
                                "state": "ok", "ports": "0.0.0.0:8080->80/tcp"}],
            }}),
        ):
            patched = mock.patch(target, **kwargs)
            patched.start()
            self.addCleanup(patched.stop)

    def _detail(self, docker_kwargs):
        with mock.patch("hub.apps_manage_svc.docker", **docker_kwargs):
            return _client().get(
                "/api/apps/managed/detail", params={"id": "docker:web"}
            )


class DockerInspectRcJunkHttpTests(_DockerDetailRig):
    """A junk inspect rc costs its own reading, never the detail route."""

    def test_an_rc_ne_bomb_keeps_the_detail_route(self):
        # ``_inspect`` guards the call and unpack but returns the rc slot
        # verbatim: the bare ``rc != 0`` probe ran the subclass ``__ne__`` —
        # a raw 500 where the rc really was 0 and the inspect JSON was
        # already in hand.
        resp = self._detail({"return_value": (_NeBombInt(0), _INSPECT_JSON, "")})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertEqual(payload["source_id"], "web")
        # The laundered rc keeps the success branch: the inspect JSON parses.
        self.assertEqual(payload["mounts"][0]["source"], "/srv/web/data")

    def test_a_wrong_arity_docker_return_falls_back_to_list_fields(self):
        # ``_inspect`` already absorbs a blown unpack into ``(1, "")``; pin
        # the degradation — the container keeps its list-row ports.
        resp = self._detail({"return_value": ("only", "two")})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertEqual(payload["ports"][0]["published"],
                         "0.0.0.0:8080->80/tcp")

    def test_a_sane_inspect_stays_intact(self):
        # The new launder must not over-absorb: an exact rc 0 still parses.
        resp = self._detail({"return_value": (0, _INSPECT_JSON, "")})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertEqual(payload["networks"][0]["ip"], "172.18.0.2")
        self.assertEqual(payload["ports"][0]["published"], "0.0.0.0:8080")

    def test_a_sane_failing_inspect_falls_back_to_list_fields(self):
        resp = self._detail({"return_value": (1, "", "no such object")})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertEqual(payload["ports"][0]["published"],
                         "0.0.0.0:8080->80/tcp")


class _ComposeRunnerRig(unittest.TestCase):
    """One compose stack on disk; ``run_capped`` is planted per test."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        services = Path(self._tmp.name) / "services"
        web = services / "web"
        web.mkdir(parents=True)
        (web / "docker-compose.yml").write_text("services: {}\n")
        apps_manage_svc.inventory.invalidate()
        self.addCleanup(apps_manage_svc.inventory.invalidate)
        for target, kwargs in (
            ("hub.apps_manage_svc.SERVICES_ROOT", {"new": services}),
            # Any on-disk binary: only the presence gate reads it, and the
            # spawn itself is the planted run_capped below.
            ("hub.apps_manage_svc.DOCKER", {"new": "/bin/ls"}),
        ):
            patched = mock.patch(target, **kwargs)
            patched.start()
            self.addCleanup(patched.stop)

    def _logs(self, run_capped_kwargs):
        with mock.patch("hub.apps_manage_svc.run_capped", **run_capped_kwargs):
            return _client().get(
                "/api/apps/managed/logs", params={"id": "docker:web"}
            )

    def _action(self, run_capped_kwargs, action="start"):
        with mock.patch("hub.apps_manage_svc.run_capped", **run_capped_kwargs):
            return _client().post(
                "/api/apps/managed/action",
                json={"id": "docker:web", "action": action},
            )


class ComposeRunnerJunkHttpTests(_ComposeRunnerRig):
    """Junk ``run_capped`` shapes cost their rc, never the output in hand."""

    def test_an_rc_ne_bomb_keeps_the_compose_log_text(self):
        # The bare ``rc == -1`` / ``rc != 0`` probes ran the subclass
        # ``__ne__``: the try absorbed the bomb into ``ok: false`` whose
        # message was the bomb's text — the log body itself was lost.
        resp = self._logs({"return_value": (_NeBombInt(0), "compose log text")})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertTrue(payload["ok"])
        self.assertIn("compose log text", payload["log"])

    def test_an_rc_ne_bomb_keeps_the_action_output(self):
        resp = self._action({"return_value": (_NeBombInt(0), "started web")})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertTrue(payload["ok"])
        self.assertIn("started web", payload["message"])

    def test_a_wrong_arity_runner_return_reads_as_failure(self):
        # The bare 2-tuple unpack blew on a leftover 3-tuple; ``-255`` is no
        # honest exit status, so junk reads as failure (the _sh_triple rule).
        resp = self._logs({"return_value": (0, "text", "extra")})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertFalse(payload["ok"])
        self.assertIn("exit -255", payload["log"])

    def test_a_raising_runner_keeps_its_failure_text(self):
        # A *raising* run_capped is the pre-existing contract: the caller's
        # try answers ok:false with the honest exception text — the shape
        # guard must not eat it.
        resp = self._logs({"side_effect": RuntimeError("runner torn")})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertFalse(payload["ok"])
        self.assertIn("runner torn", payload["log"])

    def test_a_sane_compose_run_stays_intact(self):
        resp = self._logs({"return_value": (0, "web  | ready")})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertTrue(payload["ok"])
        self.assertIn("web  | ready", payload["log"])

    def test_a_sane_failing_compose_run_keeps_its_text(self):
        resp = self._logs({"return_value": (1, "no such service: web")})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertFalse(payload["ok"])
        self.assertIn("no such service: web", payload["log"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
