"""Fifth leftover-500s sweep of the Maintenance page, over the real mounted app.

The hunted classes were re-driven against the three routes the page mounts —

    GET  /api/maintenance
    POST /api/maintenance/{tid:path}/run
    GET  /api/maintenance/{tid:path}/log

— through ``create_app()`` with ``raise_server_exceptions=False``.  Two live
leftover families were found and are fixed with this battery:

* **Dict-subclass / method-bomb job rows** (the usage5/metrics5 row-bomb
  class).  ``hub.jobs`` gated every ``_jobs`` row and every configured task
  with bare ``isinstance(..., dict)`` / ``isinstance(..., list)`` checks, so
  a leftover *subclass* whose ``.get()`` / ``.items()`` / ``__iter__`` /
  ``__bool__`` raises passed the gate and 500'd one call later:
  ``job_state`` took down GET /api/maintenance for *every* task,
  ``job_log`` took down the log route, and ``start_job``'s single-runner
  mutex scan took down POST run for every task.  A ``__bool__``-bomb
  ``running`` value additionally wedged or crashed the mutex, and a
  property-bomb ``isoformat`` escaped ``getattr``'s default inside
  ``_jsonable``.  Thirteen distinct live 500s were reproduced pre-fix.
  ``jobs._plain_dict`` / ``_truthy`` / the metrics5-style ``_jsonable``
  guards now copy through the C-level storage so an overridden method
  cannot fire (:class:`MethodBombRowsHttpTests`,
  :class:`MethodBombConfigHttpTests`).

* **Newline task ids: listed but unrunnable/unloggable** (the maint4
  slash-id class again).  ``jobs._task_id`` served ids verbatim, and a YAML
  literal-block / ``"a\\nb"`` id was listed with a Run button — but
  Starlette's ``{tid:path}`` convertor is ``.*`` compiled without DOTALL,
  and ``.`` matches every decoded path character *except* ``\\n``, so the
  SPA's percent-encoded ``%0A`` request could never match the run or the
  log route: both answered the framework's bare ``{"detail": "Not Found"}``
  instead of starting the task / serving the coded shapes.  Every other
  control character (``\\t``, ``\\r``, even NUL) routes fine — only the
  newline is unreachable.  ``_task_id`` now folds ``\\r\\n`` / ``\\n`` to a
  space before the id becomes the mapping key, so the id the list serves is
  once again the id the routes can match
  (:class:`NewlineIdHttpTests` fails on the pre-fix tree).

Plus stays-immune pins for the corners that were probed and found already
coded: a FIFO squatting services.yaml answers ``[]`` without parking the
list route (``read_text_capped`` opens O_NONBLOCK), torn-IPv6 forwarded
headers ride the run route's audit hook without a 500, and a genuine
running row still answers the coded 409 after the bomb-row guards.
"""
from __future__ import annotations

import os
import threading
import time
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from hub import config, jobs
from hub.app_factory import create_app
from hub.auth import require_auth

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


class _GetBomb(dict):
    """Passes ``isinstance(dict)``; ``.get()`` raises (the row-bomb class)."""

    def get(self, *a, **k):  # noqa: D102
        raise RuntimeError("leftover get bomb")


class _ItemsBomb(dict):
    def items(self):  # noqa: D102
        raise RuntimeError("leftover items bomb")


class _BoolBomb:
    def __bool__(self):
        raise RuntimeError("leftover bool bomb")


class _IterBombList(list):
    """Passes ``isinstance(list)``; iterating raises."""

    def __iter__(self):
        raise RuntimeError("leftover iter bomb")


class _PropBomb:
    @property
    def isoformat(self):
        raise RuntimeError("leftover property bomb")


class _DiskYamlSandbox(unittest.TestCase):
    """Poisoned config on the REAL config path — the request walks
    disk → load_yaml_int_capped → _as_config → route, like maint4's battery."""

    YAML_TEXT = "maintenance:\n  - id: plain\n    name: Plain\n    command: 'true'\n    timeout: 10\n"

    def setUp(self):
        try:
            self._original = config.YAML_PATH.read_bytes()
        except FileNotFoundError:
            self._original = None
        config.YAML_PATH.parent.mkdir(parents=True, exist_ok=True)
        config.YAML_PATH.write_text(self.YAML_TEXT, encoding="utf-8")
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


class NewlineIdHttpTests(_DiskYamlSandbox):
    """The fixed leak: a newline task id must be listed in a routable form.

    Fails on the pre-fix tree: the verbatim ``line1\\nline2`` id was listed,
    but the SPA's ``%0A`` request could not match ``{tid:path}`` (``.*``
    never spans a newline), so POST run and the log poll both fell through
    to the bare ``{"detail": "Not Found"}`` — a Run button for a task that
    could never run or be tailed.
    """

    # Real YAML text: the double-quoted escape loads a real newline, and the
    # literal block (``|-``) is the way an operator's hand edit produces one.
    YAML_TEXT = (
        "maintenance:\n"
        '  - id: "line1\\nline2"\n'
        "    name: Newline id\n"
        "    command: echo nl-ok\n"
        "    timeout: 10\n"
        "  - id: |-\n"
        "      block\n"
        "      id\n"
        "    name: Block id\n"
        "    command: echo block-ok\n"
        "    timeout: 10\n"
        '  - id: "crlf\\r\\nid"\n'
        "    name: CRLF id\n"
        "    command: echo crlf-ok\n"
        "  - id: plain\n"
        "    name: Plain\n"
        "    command: 'true'\n"
    )

    def test_no_listed_id_contains_a_newline(self):
        response = _client().get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        ids = [row["id"] for row in response.json()]
        self.assertEqual(
            sorted(ids), sorted(["line1 line2", "block id", "crlf id", "plain"])
        )
        for tid in ids:
            self.assertNotIn("\n", tid)
            self.assertNotIn("\r", "".join(c for c in tid if c == "\n"))

    def test_run_and_log_round_trip_exactly_what_the_spa_sends(self):
        client = _client()
        # encodeURIComponent("line1 line2") — see web/src/api/client.js.
        response = client.post("/api/maintenance/line1%20line2/run")
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertEqual(response.json(), {"ok": True, "message": "Task started"})
        _wait_finished("line1 line2")
        response = client.get("/api/maintenance/line1%20line2/log")
        self.assertEqual(response.status_code, 200, response.text[:300])
        payload = response.json()
        self.assertEqual(payload["rc"], 0)
        self.assertIn("nl-ok", payload["log"])

    def test_the_literal_block_id_is_runnable_too(self):
        client = _client()
        response = client.post("/api/maintenance/block%20id/run")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _wait_finished("block id")
        response = client.get("/api/maintenance/block%20id/log")
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertIn("block-ok", response.json()["log"])

    def test_task_id_folds_newlines_but_keeps_other_controls(self):
        # \t / \r / NUL all route through ``.*`` — only \n is unreachable,
        # so only \n (and the \r\n pair, as one separator) is folded.
        self.assertEqual(jobs._task_id("a\nb"), "a b")
        self.assertEqual(jobs._task_id("a\r\nb"), "a b")
        self.assertEqual(jobs._task_id("a\tb"), "a\tb")
        self.assertEqual(jobs._task_id("a\rb"), "a\rb")
        self.assertEqual(jobs._task_id("\n\n"), "")

    def test_mapping_key_still_equals_the_served_id(self):
        tasks = jobs.maintenance_tasks()
        for key, row in tasks.items():
            self.assertEqual(key, row["id"])


class MethodBombRowsHttpTests(_DiskYamlSandbox):
    """The fixed leak: leftover dict-subclass / method-bomb ``_jobs`` rows.

    Every case here answered a raw HTTP 500 on the pre-fix tree.
    """

    def test_get_bomb_row_keeps_the_list_route_up(self):
        jobs._jobs["plain"] = _GetBomb(running=False, rc=0)
        response = _client().get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        # The C-level copy still serves the row's real storage.
        row = next(r for r in response.json() if r["id"] == "plain")
        self.assertEqual(row["rc"], 0)

    def test_get_bomb_row_keeps_the_log_route_up(self):
        jobs._jobs["plain"] = _GetBomb(running=False, rc=0)
        response = _client().get("/api/maintenance/plain/log")
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertEqual(response.json()["rc"], 0)

    def test_get_bomb_row_keeps_the_run_mutex_coded(self):
        # The C-level copy serves the row's real storage: ``running: True``
        # still counts as a live job, so the answer is the coded 409 —
        # pre-fix the ``.get()`` bomb made this a raw 500.
        jobs._jobs["junk"] = _GetBomb(running=True)
        response = _client().post("/api/maintenance/plain/run")
        self.assertEqual(response.status_code, 409, response.text[:300])
        _clean(response)
        self.assertEqual(
            response.json()["detail"]["code"], "jobs.already_running"
        )

    def test_get_bomb_row_with_finished_storage_does_not_block_the_mutex(self):
        jobs._jobs["junk"] = _GetBomb(running=False, rc=1)
        response = _client().post("/api/maintenance/plain/run")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _wait_finished("plain")

    def test_bool_bomb_running_value_stays_served_and_not_running(self):
        jobs._jobs["plain"] = {"running": _BoolBomb(), "rc": 0, "log": []}
        client = _client()
        response = client.get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        row = next(r for r in response.json() if r["id"] == "plain")
        # Fails closed: a bomb is junk, not a live job.
        self.assertIs(row["running"], False)
        response = client.get("/api/maintenance/plain/log")
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertIs(response.json()["running"], False)

    def test_bool_bomb_running_value_does_not_wedge_the_run_mutex(self):
        jobs._jobs["junk"] = {"running": _BoolBomb(), "rc": None, "log": []}
        response = _client().post("/api/maintenance/plain/run")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _wait_finished("plain")

    def test_items_bomb_value_inside_a_row_stays_served(self):
        jobs._jobs["plain"] = {
            "running": False, "rc": _ItemsBomb(), "log": ["x"],
            "started": "1", "finished": "2",
        }
        client = _client()
        for url in ("/api/maintenance", "/api/maintenance/plain/log"):
            response = client.get(url)
            self.assertEqual(response.status_code, 200, response.text[:300])
            _clean(response)

    def test_iter_bomb_log_list_recovers_its_readable_lines(self):
        # jobs14/maint14: the unbound ``list.__iter__`` snapshot reads the
        # real C-level storage underneath the subclass's ``__iter__`` bomb,
        # so the readable lines survive instead of degrading to the waiting
        # placeholder — the raise is still absorbed, never a 500.
        jobs._jobs["plain"] = {
            "running": False, "rc": 0, "log": _IterBombList(["a"]),
        }
        response = _client().get("/api/maintenance/plain/log")
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertEqual(response.json()["log"], "a")

    def test_property_bomb_isoformat_stays_served(self):
        jobs._jobs["plain"] = {
            "running": False, "rc": 0, "log": [], "finished": _PropBomb(),
        }
        client = _client()
        for url in ("/api/maintenance", "/api/maintenance/plain/log"):
            response = client.get(url)
            self.assertEqual(response.status_code, 200, response.text[:300])
            _clean(response)

    def test_a_genuine_running_row_still_answers_the_coded_409(self):
        # The fail-closed bomb guards must not have reshaped the real mutex.
        jobs._jobs["busy"] = {"running": True, "rc": None, "log": []}
        response = _client().post("/api/maintenance/plain/run")
        self.assertEqual(response.status_code, 409, response.text[:300])
        _clean(response)
        self.assertEqual(
            response.json()["detail"]["code"], "jobs.already_running"
        )
        self.assertNotIn("plain", jobs._jobs)

    def test_start_job_survives_a_dict_subclass_task(self):
        # tools_svc hands start_job its own dicts; a leftover subclass whose
        # .get() raises used to raise straight into the calling route.  The
        # C-level copy reads the real storage, so the job simply runs.
        jobs.start_job(_GetBomb(id="x", command="echo bomb-task-ok", timeout=10))
        row = _wait_finished("x")
        self.assertEqual(row.get("rc"), 0)


class MethodBombConfigHttpTests(_DiskYamlSandbox):
    """Leftover subclass bombs in the *config* snapshot (a poisoned in-process
    cfg cache) must cost their entry, never the list route."""

    def test_iter_bomb_maintenance_list_serves_an_empty_list(self):
        with mock.patch.object(jobs, "cfg", return_value={"maintenance": _IterBombList()}):
            response = _client().get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertEqual(response.json(), [])

    def test_get_bomb_task_row_still_serves_through_the_c_level_copy(self):
        poisoned = {"maintenance": [_GetBomb(id="ok", command="true"), {"id": "sib", "command": "true"}]}
        with mock.patch.object(jobs, "cfg", return_value=poisoned):
            response = _client().get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        ids = [row["id"] for row in response.json()]
        # dict() copies through the C storage, so the bomb row's real
        # contents survive alongside its sibling.
        self.assertEqual(sorted(ids), ["ok", "sib"])


class FifoConfigHttpTests(_DiskYamlSandbox):
    """A leftover FIFO squatting services.yaml must neither hang nor 500 the
    list route (read_text_capped opens O_NONBLOCK and refuses non-files)."""

    def test_fifo_services_yaml_answers_empty_list_without_hanging(self):
        config.YAML_PATH.unlink()
        os.mkfifo(config.YAML_PATH)
        self.addCleanup(lambda: config.YAML_PATH.exists() and config.YAML_PATH.unlink())
        config._cfg["mtime"] = 0.0
        config._cfg["data"] = {}

        result: dict = {}

        def probe():
            result["response"] = _client().get("/api/maintenance")

        # A regression re-introducing a blocking open would park this thread
        # until a writer appeared; the join timeout turns that hang into a
        # test failure instead of a wedged run.
        worker = threading.Thread(target=probe, daemon=True)
        worker.start()
        worker.join(timeout=10)
        self.assertFalse(worker.is_alive(), "GET /api/maintenance hung on a FIFO services.yaml")
        response = result["response"]
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertEqual(response.json(), [])


class HostileForwardedHeadersHttpTests(_DiskYamlSandbox):
    """The run route's audit hook parses forwarded headers; torn IPv6 /
    oversize junk must ride along without a 500 (urlsplit-ValueError class)."""

    def test_torn_forwarded_headers_stay_coded_on_the_run_route(self):
        client = _client()
        hostile = ["[::1", "[", "1.2.3.4:99999", "a,b,c;for=[::", "::::::", "%" * 512]
        for header in hostile:
            jobs._jobs.clear()
            response = client.post(
                "/api/maintenance/plain/run",
                headers={"x-forwarded-for": header, "forwarded": header},
            )
            self.assertEqual(response.status_code, 200, (header, response.text[:300]))
            _clean(response)
            _wait_finished("plain")


if __name__ == "__main__":
    unittest.main()
