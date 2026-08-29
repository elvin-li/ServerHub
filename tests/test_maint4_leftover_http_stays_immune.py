"""Fourth leftover-500s sweep of the Maintenance page, over the real mounted app.

The hunted classes (lone UTF-8 surrogates in keys AND values, the CPython
4300-digit int cap — including the uncapped YAML hex form that arrives
already-int — numeric YAML ids, huge-number JSON bodies where ``json.loads``
raises ValueError not JSONDecodeError, vanished-CLI classification, and
sibling-row wipes) were re-reproduced against the three routes the page
mounts:

    GET  /api/maintenance
    POST /api/maintenance/{tid}/run
    GET  /api/maintenance/{tid}/log

One live leftover was found and is fixed with this battery:

* The run/log routes matched ``{tid}`` — a single path segment — while
  ``jobs._task_id`` deliberately serves ids verbatim, slashes included
  (``id: brew/upgrade`` in services.yaml).  The SPA percent-encodes the id
  (the maint3 ``encodeURIComponent`` fix), but ASGI servers decode ``%2F``
  back to ``/`` *before* routing, so a slash id could never reach either
  handler: the decoded path fell through the whole API router into
  app_factory's SPA fallback, where POST run answered **405 Method Not
  Allowed** and the log poll answered a **404 with an HTML body** the SPA's
  JSON client cannot parse.  A task the list offered a Run button for was
  unrunnable and unloggable — the same "listed id the run route can never
  match" class the surrogate-id scrub already fixed.  Both routes now match
  ``{tid:path}``; tid is only ever a mapping key (never a filesystem path or
  argv), so the greedy match is safe
  (:class:`SlashIdHttpTests` fails on the pre-fix tree).

Everything else was already immune at the service layer (``jobs._jsonable``
/ ``_task_id`` / ``_log_lines``, ``config.load_yaml_int_capped`` /
``_as_config`` / ``_env_text``) — but the existing pins mock ``jobs.cfg`` and
drive a bare router.  This battery pins the whole cycle through
``create_app()`` and the real on-disk services.yaml: disk read,
``load_yaml_int_capped``, request routing, the audit hook on the mutating
route, and Starlette's strict UTF-8 render of the final body.
"""
from __future__ import annotations

import time
import unittest

from fastapi.testclient import TestClient

from hub import config, jobs
from hub.app_factory import create_app
from hub.auth import require_auth

#: The decimal spelling whose json.loads raises the digit-cap ValueError.
_HUGE_DIGITS = "9" * 5000

#: Real services.yaml text, not Python-built objects: the slash id is served
#: verbatim, hex ids load already-int (``int(x, 16)`` is exempt from the
#: 4300-digit cap, so the 4400-hex-digit id really is over-cap), and the
#: double-quoted escape loads as a lone surrogate.
_YAML_TEXT = (
    "maintenance:\n"
    "  - id: brew/upgrade\n"
    "    name: Brew upgrade\n"
    "    command: echo slash-ok\n"
    "    timeout: 10\n"
    "  - id: plain\n"
    "    name: Plain\n"
    "    command: 'true'\n"
    "    timeout: 10\n"
    "  - id: 0x2A5F\n"
    '    name: "up\\ud800grade"\n'
    "    command: 'true'\n"
    "  - id: 0x" + "F" * 4400 + "\n"
    "    name: Overcap\n"
    "    command: 'true'\n"
    "  - id: sib\n"
    "    name: Sib\n"
    "    desc: .nan\n"
    "    confirm: .inf\n"
    "    command: 'true'\n"
)

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
    assert "\ud800" not in text, text[:300]
    text.encode("utf-8")


def _wait_finished(tid: str, timeout: float = 20.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        row = jobs._jobs.get(tid) or {}
        if isinstance(row, dict) and not row.get("running"):
            return row
        time.sleep(0.05)
    raise AssertionError(f"job {tid!r} did not finish")


class _DiskYamlSandbox(unittest.TestCase):
    """The poisoned config on the REAL config path — no ``jobs.cfg`` mock, so
    the request walks disk → load_yaml_int_capped → _as_config → route."""

    def setUp(self):
        try:
            self._original = config.YAML_PATH.read_bytes()
        except FileNotFoundError:
            self._original = None
        config.YAML_PATH.parent.mkdir(parents=True, exist_ok=True)
        config.YAML_PATH.write_text(_YAML_TEXT, encoding="utf-8")
        config.reload_cfg()
        self.addCleanup(self._restore)
        jobs._jobs.clear()
        self.addCleanup(jobs._jobs.clear)

    def _restore(self):
        if self._original is None:
            try:
                config.YAML_PATH.unlink()
            except FileNotFoundError:
                pass
        else:
            config.YAML_PATH.write_bytes(self._original)
        config.reload_cfg()


class SlashIdHttpTests(_DiskYamlSandbox):
    """The fixed leak: a slash task id must be runnable and loggable.

    Fails on the pre-fix tree: with ``{tid}`` the decoded ``%2F`` path fell
    through to the SPA fallback — POST run answered 405 Method Not Allowed
    and the log poll answered a text/html 404 the SPA cannot parse.
    """

    def test_the_listed_slash_id_is_listed_verbatim(self):
        response = _client().get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        ids = [row["id"] for row in response.json()]
        self.assertIn("brew/upgrade", ids)

    def test_run_and_log_round_trip_exactly_what_the_spa_sends(self):
        client = _client()
        # encodeURIComponent("brew/upgrade") — see web/src/api/client.js.
        response = client.post("/api/maintenance/brew%2Fupgrade/run")
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertEqual(response.json(), {"ok": True, "message": "Task started"})
        _wait_finished("brew/upgrade")
        response = client.get("/api/maintenance/brew%2Fupgrade/log")
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertIn("application/json", response.headers.get("content-type", ""))
        payload = response.json()
        self.assertEqual(payload["rc"], 0)
        self.assertIn("slash-ok", payload["log"])

    def test_an_unknown_slash_id_run_is_the_coded_404_not_a_405(self):
        response = _client().post("/api/maintenance/no%2Fsuch/run")
        self.assertEqual(response.status_code, 404, response.text[:300])
        _clean(response)
        self.assertEqual(
            response.json()["detail"]["code"], "maintenance.unknown_task"
        )

    def test_an_unknown_slash_id_log_is_the_json_missing_shape_not_html(self):
        response = _client().get("/api/maintenance/no%2Fsuch/log")
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertIn("application/json", response.headers.get("content-type", ""))
        self.assertEqual(
            response.json(),
            {"running": False, "rc": None, "log": "(not run yet)"},
        )

    def test_single_segment_ids_keep_matching(self):
        client = _client()
        response = client.post("/api/maintenance/plain/run")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _wait_finished("plain")
        response = client.get("/api/maintenance/plain/log")
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertEqual(response.json()["rc"], 0)


class DiskYamlPipelineHttpTests(_DiskYamlSandbox):
    """Stays-immune pins for the full disk→route pipeline: the existing hex /
    surrogate / over-cap / NaN pins mock ``jobs.cfg`` and drive a bare router;
    a regression in cfg()'s loader stack would slip past them."""

    def test_list_keeps_every_renderable_sibling_and_scrubs_the_body(self):
        response = _client().get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        by_id = {row["id"]: row for row in response.json()}
        # The over-cap hex id drops only its own entry; the hex id coerces
        # through the str() probe; every sibling survives.
        self.assertEqual(
            sorted(by_id),
            sorted(["brew/upgrade", "plain", str(0x2A5F), "sib"]),
        )
        self.assertEqual(by_id[str(0x2A5F)]["name"], "up?grade")

    def test_nan_desc_and_inf_confirm_from_disk_stay_http_200(self):
        response = _client().get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        row = next(r for r in response.json() if r["id"] == "sib")
        # allow_nan=False: a 200 proves the NaN never reached the encoder,
        # and the junk confirm fails closed to the unconfirmed default.
        self.assertIsNone(row["desc"])
        self.assertIs(row["confirm"], False)


class BodylessRunRouteHostileBodyHttpTests(_DiskYamlSandbox):
    """POST run takes no body, so a hostile one must never be parsed: a huge
    number literal is the digit-cap ValueError (not JSONDecodeError) inside
    json.loads, and a lone-surrogate escape breaks the strict UTF-8 render —
    both must cost nothing on a body-less route."""

    def _post(self, raw_body: bytes):
        return _client().post(
            "/api/maintenance/no-such-task/run",
            content=raw_body,
            headers={"content-type": "application/json"},
        )

    def test_huge_int_body_is_ignored_and_the_coded_404_answers(self):
        response = self._post(b'{"x": ' + _HUGE_DIGITS.encode() + b"}")
        self.assertEqual(response.status_code, 404, response.text[:300])
        _clean(response)
        self.assertEqual(
            response.json()["detail"]["code"], "maintenance.unknown_task"
        )
        # The refused run must not have minted a job row.
        self.assertNotIn("no-such-task", jobs._jobs)

    def test_surrogate_escape_body_is_ignored_the_same_way(self):
        response = self._post(b'{"x": "\\ud800"}')
        self.assertEqual(response.status_code, 404, response.text[:300])
        _clean(response)
        self.assertEqual(
            response.json()["detail"]["code"], "maintenance.unknown_task"
        )


class ConcurrentRunHttpTests(_DiskYamlSandbox):
    """The single-runner mutex keeps its coded 409 through the real app."""

    def test_second_run_is_the_coded_409_and_the_row_survives(self):
        jobs._jobs["busy"] = {"running": True, "rc": None, "log": []}
        response = _client().post("/api/maintenance/plain/run")
        self.assertEqual(response.status_code, 409, response.text[:300])
        _clean(response)
        self.assertEqual(
            response.json()["detail"]["code"], "jobs.already_running"
        )
        # The refused run neither replaced the running row nor minted its own.
        self.assertTrue(jobs._jobs["busy"]["running"])
        self.assertNotIn("plain", jobs._jobs)


if __name__ == "__main__":
    unittest.main()
