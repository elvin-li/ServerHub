"""Leftover 500 on POST /api/stacks/{id}/run: the body ``action`` was echoed raw.

Reproduced before the fix: ``start_stack_job`` embedded the request body's
``action`` string verbatim in the job id (``stack-<id>-<action>-<epoch>``)
and the retained job dict.  Anything unknown silently fell to the *update*
branch (pull + up + prune), and a leftover lone-surrogate action
(``{"action": "x\\ud800y"}`` — ``json.loads`` accepts the lone escape)

* 500'd the run response itself on Starlette's UTF-8 encode, **after** the
  job was already registered and running, and
* because job dicts outlive the request, poisoned every later
  GET /api/stacks (``latest_stack_jobs`` → ``job_public``) and
  GET /api/stacks/jobs/{id} (``stack_job_log``) render until the panel
  restarted — one bad request took the stacks listing down for every client.

Fixed on the same shape as ``container_action`` / ``prune``: the four compose
verbs are an allowed set and anything else is the coded 400
``container.bad_action`` (whose params ``error_payload`` already scrubs),
raised before any job is registered.  ``job_public`` / ``stack_job_log``
additionally scrub the echoed job fields, so a job dict poisoned any other
way can never take the listing routes down with it.

Stays-immune pins at the HTTP layer (through the real ``create_app`` wiring):
a non-finite / over-cap-int action body is a 4xx from the sanitizing
validation handler, and GET /api/containers over a poisoned update journal
(huge int literal + surrogate keys/values) answers 200.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from fastapi import HTTPException  # noqa: E402

from hub import containers_svc  # noqa: E402

#: A JSON literal past CPython's 4300-digit int(str) cap: ``json.loads``
#: raises ValueError while *parsing* it, before any encoder is involved.
_HUGE_JSON_INT = "1" * 5000


def _starlette(payload) -> None:
    """What Starlette's JSONResponse does to a payload."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class _SyncThread:
    """threading.Thread stand-in that runs the job body on start()."""

    def __init__(self, target=None, daemon=None):
        self._target = target

    def start(self):
        if self._target is not None:
            self._target()


class _JobSandbox(unittest.TestCase):
    STACK = {
        "id": "media",
        "name": "media",
        "path": "/tmp/media",
        "compose_file": "docker-compose.yml",
        "compose_path": "/tmp/media/docker-compose.yml",
        "containers": [],
        "source": "config",
    }

    def setUp(self):
        import types

        self._saved = dict(containers_svc._cjobs)
        containers_svc._cjobs.clear()
        self.addCleanup(self._restore_jobs)
        patches = [
            mock.patch.object(
                containers_svc, "threading",
                types.SimpleNamespace(Thread=_SyncThread),
            ),
            mock.patch.object(containers_svc, "maintenance_env", lambda: {}),
            mock.patch.object(containers_svc, "invalidate_status", lambda: None),
            mock.patch.object(
                containers_svc, "_stack_paths", lambda: [dict(self.STACK)],
            ),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def _restore_jobs(self):
        containers_svc._cjobs.clear()
        containers_svc._cjobs.update(self._saved)


class SurrogateStackActionTests(_JobSandbox):
    """An unknown/unencodable action is a coded 400 raised before any job."""

    def test_surrogate_action_is_a_coded_400_not_a_500(self):
        with self.assertRaises(HTTPException) as ctx:
            containers_svc.start_stack_job("media", "x\ud800y")
        self.assertEqual(ctx.exception.status_code, 400)
        detail = ctx.exception.detail
        self.assertEqual(detail["code"], "container.bad_action")
        # The error body itself must render (error_payload scrubs params).
        _starlette(detail)
        # Nothing was registered: the poison cannot outlive the request.
        self.assertEqual(containers_svc._cjobs, {})
        _starlette({"jobs": containers_svc.latest_stack_jobs()})

    def test_unknown_action_no_longer_falls_to_the_update_branch(self):
        # ``destroy`` used to silently run pull + up + prune.
        stream = mock.Mock(return_value=0)
        with mock.patch.object(containers_svc, "_stream_job_command", stream):
            with self.assertRaises(HTTPException) as ctx:
                containers_svc.start_stack_job("media", "destroy")
        self.assertEqual(ctx.exception.detail["code"], "container.bad_action")
        stream.assert_not_called()

    def test_the_four_compose_verbs_still_run_and_render(self):
        for action in ("update", "up", "down", "pull"):
            with self.subTest(action=action):
                containers_svc._cjobs.clear()
                with mock.patch.object(
                    containers_svc, "_stream_job_command", return_value=0,
                ):
                    r = containers_svc.start_stack_job("media", action)
                self.assertTrue(r["ok"])
                self.assertIn(f"-{action}-", r["job_id"])
                _starlette(r)
                job = containers_svc.stack_job_log(r["job_id"])
                self.assertEqual(job["rc"], 0)
                self.assertEqual(job["action"], action)
                _starlette(job)
                _starlette({"jobs": containers_svc.latest_stack_jobs()})


class PoisonedJobDictFunnelTests(_JobSandbox):
    """A job dict poisoned any other way still cannot 500 the listings."""

    def _poison(self):
        containers_svc._cjobs["stack-media-x\ud800y-1"] = {
            "running": False,
            "rc": 1,
            "log": ["!! failed\ud800"],
            "started": "10:00:00",
            "finished": "10:00:05",
            "stack_id": "media\ud800",
            "action": "x\ud800y",
            "code": "container.engine_down\ud800",
        }

    def test_latest_stack_jobs_scrubs_the_echoed_fields(self):
        self._poison()
        jobs = containers_svc.latest_stack_jobs()
        _starlette({"jobs": jobs})
        self.assertEqual(len(jobs), 1)
        for field in ("job_id", "stack_id", "action", "code"):
            self.assertNotIn("\ud800", jobs[0][field])

    def test_stack_job_log_scrubs_the_echoed_fields(self):
        self._poison()
        out = containers_svc.stack_job_log("stack-media-x\ud800y-1")
        _starlette(out)
        for field in ("job_id", "stack_id", "action", "code", "log"):
            self.assertNotIn("\ud800", out[field])

    def test_non_str_leftover_fields_drop_instead_of_leaking(self):
        containers_svc._cjobs["stack-media-up-2"] = {
            "running": False, "rc": 0, "log": [],
            "started": "10:00:00", "finished": "10:00:01",
            "stack_id": "media", "action": {"up"}, "code": 7,
        }
        out = containers_svc.stack_job_log("stack-media-up-2")
        self.assertIsNone(out["action"])
        self.assertIsNone(out["code"])
        _starlette(out)


class StackRunHttpLayerTests(unittest.TestCase):
    """The same contract through the real app wiring, not just the helper."""

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

    def setUp(self):
        self._saved = dict(containers_svc._cjobs)
        containers_svc._cjobs.clear()
        self.addCleanup(self._restore_jobs)

    def _restore_jobs(self):
        containers_svc._cjobs.clear()
        containers_svc._cjobs.update(self._saved)

    def _post_run(self, body: str):
        return self.client.post(
            "/api/stacks/media/run",
            content=body,
            headers={"Content-Type": "application/json"},
        )

    def test_surrogate_action_answers_400_and_does_not_poison_the_listing(self):
        resp = self._post_run(json.dumps({"action": "x\ud800y"}))
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.json()["detail"]["code"], "container.bad_action")
        # The listing stays alive afterwards — before the fix the poisoned
        # job dict 500'd every GET /api/stacks until the panel restarted.
        with (
            mock.patch.object(containers_svc, "cfg", return_value={"stacks": []}),
            mock.patch.object(containers_svc, "user_home", return_value=None),
            mock.patch.object(
                containers_svc, "_container_list_cached",
                return_value=(True, []),
            ),
        ):
            listing = self.client.get("/api/stacks")
        self.assertEqual(listing.status_code, 200)
        self.assertEqual(listing.json()["jobs"], [])

    def test_non_finite_and_overcap_action_bodies_stay_4xx(self):
        # The sanitizing RequestValidationError handler is registered by
        # create_app; a bare router 500s echoing these back in detail[].input.
        for body in ('{"action": Infinity}', '{"action": 1e999}',
                     '{"action": ' + _HUGE_JSON_INT + '}'):
            with self.subTest(body=body[:24]):
                resp = self._post_run(body)
                self.assertLess(resp.status_code, 500)
                self.assertGreaterEqual(resp.status_code, 400)
                resp.json()

    def test_containers_listing_survives_a_poisoned_update_journal(self):
        # Stays-immune pin: huge int literal + surrogate keys/values in
        # docker-update-status.json answer 200 through the real wiring.
        with tempfile.TemporaryDirectory() as tmp:
            journal = Path(tmp) / "docker-update-status.json"
            journal.write_text(
                '{"nginx:latest": {"status": "false", "update": false},'
                ' "leftover": ' + _HUGE_JSON_INT + ","
                ' "k\\ud800ey": "v\\ud800", "_checked_at": "t\\ud800"}'
            )
            row = {
                "id": "nginx", "name": "nginx", "raw_state": "running",
                "project": None, "image": "nginx:latest",
            }
            with (
                mock.patch.object(containers_svc, "UPDATE_STATUS_PATH", journal),
                mock.patch.object(
                    containers_svc, "_container_list_cached",
                    return_value=(True, [row]),
                ),
                mock.patch.object(containers_svc, "_stats_cached", return_value={}),
            ):
                resp = self.client.get("/api/containers")
        self.assertEqual(resp.status_code, 200)
        payload = resp.json()
        self.assertTrue(payload["engine_up"])
        self.assertEqual(payload["containers"][0]["id"], "nginx")
        self.assertNotIn("\ud800", json.dumps(payload))


if __name__ == "__main__":
    unittest.main()
