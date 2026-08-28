"""Fourteenth leftover-500s sweep of the Maintenance surface, over the real
mounted app.

maint13 sealed the BaseException bomb family: every guard on the listing pipe
re-raises genuine control flow and launders everything else exactly like its
Exception twin.  A fresh hunt over the same mounted tree (create_app +
TestClient, raise_server_exceptions=False) drove the shapes the assistant14/
bookmarks14/users14 sweeps found still live in their domains — and found all
four alive on the Maintenance routes:

* **Mid-walk mutation** (the assistant14 ``_dget`` shape at ``_jsonable``
  rank): the dict arm iterated the *live* ``value.items()`` view, so a nested
  cell whose ``isoformat`` hook mutates its own mapping mid-walk
  RuntimeError'd the iteration outside every net — a raw 500 on
  GET /api/maintenance through ``job_state``'s merge (a poisoned ``_jobs``
  row) AND on POST /api/maintenance/{tid}/run through ``maintenance_tasks``'s
  row laundering (a poisoned cfg row).  The walk now snapshots
  ``list(dict.items(value))`` first.

* **Default ``object.__repr__`` heap-address leaks**: ``_jsonable``'s
  fallback arm ran the dispatching ``str()`` on any leftover shape, and for a
  type that never overrode ``__str__``/``__repr__`` the answer is
  ``<X object at 0x7f...>`` — a raw heap address, served verbatim as an
  ``rc`` / ``desc`` / ``started`` cell; the dict-key path ran bare ``str(k)``
  and served the same address as a JSON *key*.  A slot probe on the real
  ``type(value)`` plus the address belt now degrade the unrenderable cell to
  ``""`` and drop the unrenderable key, keeping every sibling.

* **Wrong-rank drops behind a lying ``__class__``** (the modules14/files16
  shape): ``isinstance`` consults ``value.__class__`` only after the
  real-MRO check misses, so a lying claim steered a leftover into the arm of
  its claim, the unbound descriptor there refused the real layout, and an
  early return threw honest renderable storage away — a genuine int id
  claiming str vanished its task from the listing (and made it unrunnable),
  a genuine str desc claiming int wiped to ``null``, a genuine str name
  claiming bytes wiped to the id fallback, a genuine float claiming int
  dropped to ``null``.  The rejected arms in ``_jsonable`` / ``_utf8_text``
  / ``_task_id`` / ``_log_lines`` now fall through to the arm the *real*
  storage matches, probed via ``type(value)`` (``_real``) so the lie cannot
  steer the walk twice; total impostors keep the established ``None``/``""``
  drops.

* **Bound nested materialisers vaporising honest storage**: ``list(value)``
  in ``_jsonable``'s sequence arm, ``_log_lines`` and ``maintenance_tasks``'s
  row walk dispatched a real subclass's overridden ``__iter__``, so an
  iter-bomb whose C-level storage was perfectly walkable lost its rows/lines
  even though the raise was absorbed.  Unbound snapshots
  (``list.__iter__`` / ``tuple.__iter__``, both bases real-layout
  first-come — the jobs13/nas13 decode rule at sequence rank) read the real
  storage without running the override.

:class:`MidWalkMutationTests`, :class:`ReprAddressLeakTests`,
:class:`LyingClassWrongRankRecoveryTests` and :class:`IterBombRecoveryTests`
fail on the pre-fix tree; :class:`ControlFlowStillPropagates` pins the
passthrough so no new guard can widen into a hang;
:class:`HealthyAndImpostorShapeUnchanged` re-pins the SPA contract and the
established total-impostor drops so the recovery cannot weaken the
maint9-maint13 union.
"""
from __future__ import annotations

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
    """The body decoded, carries no lone surrogate, no heap address, and
    re-encodes as UTF-8."""
    text = response.text
    assert "\ud800" not in text, text[:300]
    assert " at 0x" not in text, text[:300]
    text.encode("utf-8")


def _wait_finished(tid: str, timeout: float = 20.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        row = jobs._jobs_row(tid) or {}
        if isinstance(row, dict) and not row.get("running"):
            return row
        time.sleep(0.05)
    raise AssertionError(f"job {tid!r} did not finish")


class _Mutator:
    """A nested cell whose guarded ``isoformat`` hook mutates its own parent
    mapping: the hook's raise (none) is absorbed, but the *live*
    ``dict.items`` view then RuntimeErrors on its next step — outside every
    net on the pre-fix tree."""

    def __init__(self, victim: dict):
        self._victim = victim

    def isoformat(self):
        self._victim.pop("sibling", None)
        return "mutated"


def _mutating_dict() -> dict:
    victim: dict = {}
    victim["bomb"] = _Mutator(victim)
    victim["sibling"] = 1
    return victim


class _LyingStrInt(int):
    """A genuine int whose ``__class__`` lies str: the str arm's unbound
    read refuses the layout, and the pre-fix early return dropped the honest
    number — a task id vanished from the listing."""

    @property
    def __class__(self):  # noqa: D105
        return str


class _LyingIntStr(str):
    """A genuine str whose ``__class__`` lies int: the int arm's unbound
    ``int.__index__`` refuses the layout, and the pre-fix early return wiped
    the honest text to ``None`` at the wrong rank."""

    @property
    def __class__(self):  # noqa: D105
        return int


class _LyingIntFloat(float):
    """A genuine float whose ``__class__`` lies int."""

    @property
    def __class__(self):  # noqa: D105
        return int


class _LyingBytesStr(str):
    """A genuine str whose ``__class__`` lies bytes: both unbound base
    decodes refuse the layout, and the pre-fix ``""`` wipe lost the honest
    text sitting right there."""

    @property
    def __class__(self):  # noqa: D105
        return bytes


class _LyingStrList(list):
    """A genuine list whose ``__class__`` lies str: the str arm refused it
    and the pre-fix ``""`` wipe dropped every honest line."""

    @property
    def __class__(self):  # noqa: D105
        return str


class _IterBombList(list):
    """A real list subclass whose ``__iter__`` raises: the bound ``list()``
    materialiser dispatched the override and vaporised perfectly walkable
    C-level storage; the unbound ``list.__iter__`` reads underneath it."""

    def __iter__(self):  # noqa: D105
        raise RuntimeError("leftover iter bomb")


class _DiskYamlSandbox(unittest.TestCase):
    """One plain task on the REAL config path — the request walks
    disk -> load_yaml_int_capped -> _as_config -> route, like maint4-maint13."""

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
        try:
            config.YAML_PATH.unlink()
        except FileNotFoundError:
            pass
        if self._original is not None:
            config.YAML_PATH.write_bytes(self._original)
        config.reload_cfg()


class MidWalkMutationTests(_DiskYamlSandbox):
    """The fixed 500s: a nested cell mutating its own mapping mid-walk used
    to RuntimeError the live ``dict.items`` iteration inside ``_jsonable``
    and crash the route raw."""

    def test_mutating_jobs_row_cell_keeps_the_listing_up(self):
        # job_state merges the raw in-memory row: the nested dict walks at
        # depth 1, where the pre-fix live-view iteration blew up.
        jobs._jobs["plain"] = {"running": False, "rc": 0,
                               "finished": _mutating_dict()}
        response = _client().get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        row = next(r for r in response.json() if r["id"] == "plain")
        self.assertEqual(row["rc"], 0)
        # The snapshot keeps walking: the surviving cell still renders.
        self.assertEqual(row["finished"]["bomb"], "mutated")

    def test_mutating_jobs_row_cell_keeps_the_log_route_up(self):
        jobs._jobs["plain"] = {"running": False, "rc": 7, "log": ["ok"],
                               "started": _mutating_dict()}
        response = _client().get("/api/maintenance/plain/log")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        payload = response.json()
        self.assertEqual(payload["rc"], 7)
        self.assertEqual(payload["log"], "ok")

    def test_mutating_cfg_row_cell_keeps_the_run_route_up(self):
        # maintenance_tasks launders every row through _jsonable before the
        # run route matches the id: the pre-fix RuntimeError escaped the
        # route bare (maintenance_view's own net only covers the listing).
        rows = [{"id": "plain", "name": "Plain", "command": "true",
                 "timeout": 10, "extra": _mutating_dict()}]
        with mock.patch.object(jobs, "cfg",
                               return_value={"maintenance": rows}):
            response = _client().post("/api/maintenance/plain/run")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        self.assertEqual(response.json(),
                         {"ok": True, "message": "Task started"})
        self.assertEqual(_wait_finished("plain").get("rc"), 0)

    def test_mutating_cfg_row_cell_keeps_the_row_listed(self):
        rows = [{"id": "plain", "name": "Plain", "command": "true",
                 "extra": _mutating_dict()}]
        with mock.patch.object(jobs, "cfg",
                               return_value={"maintenance": rows}):
            response = _client().get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        # Pre-fix the raise fell to maintenance_view's outer net and wiped
        # the WHOLE listing; the poisoned cell now costs nothing the SPA
        # reads.
        self.assertEqual([r["id"] for r in response.json()], ["plain"])


class ReprAddressLeakTests(_DiskYamlSandbox):
    """The fixed leaks: a plain-object leftover whose type never overrode
    ``__str__``/``__repr__`` used to serve its default ``object.__repr__``
    — a raw heap address — verbatim in the JSON body."""

    def test_object_rc_cell_never_leaks_its_address(self):
        jobs._jobs["plain"] = {"running": False, "rc": object(),
                               "finished": None}
        response = _client().get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        row = next(r for r in response.json() if r["id"] == "plain")
        # The unrenderable cell degrades like an unreadable one.
        self.assertEqual(row["rc"], "")

    def test_object_desc_cell_never_leaks_its_address(self):
        rows = [{"id": "plain", "name": "Plain", "command": "true",
                 "desc": object()}]
        with mock.patch.object(jobs, "cfg",
                               return_value={"maintenance": rows}):
            response = _client().get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        row = response.json()[0]
        self.assertEqual(row["desc"], "")
        self.assertEqual(row["name"], "Plain")

    def test_object_key_in_a_nested_cell_drops_only_its_entry(self):
        jobs._jobs["plain"] = {"running": False,
                               "rc": {object(): 1, "sane": 2},
                               "finished": None}
        response = _client().get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        row = next(r for r in response.json() if r["id"] == "plain")
        # The unrenderable key drops just its entry; the sibling survives.
        self.assertEqual(row["rc"], {"sane": 2})

    def test_object_started_cell_never_leaks_on_the_log_route(self):
        jobs._jobs["plain"] = {"running": False, "rc": 0, "log": ["ok"],
                               "started": object()}
        response = _client().get("/api/maintenance/plain/log")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        self.assertEqual(response.json()["log"], "ok")


class LyingClassWrongRankRecoveryTests(_DiskYamlSandbox):
    """The fixed wrong-rank drops: a lying ``__class__`` steered honest
    renderable storage into the claimed arm, whose unbound descriptor
    refused it — and the early return threw the real data away."""

    def test_int_id_claiming_str_lists_and_runs_as_its_number(self):
        rows = [{"id": _LyingStrInt(42), "name": "Answer",
                 "command": "true", "timeout": 10}]
        client = _client()
        with mock.patch.object(jobs, "cfg",
                               return_value={"maintenance": rows}):
            response = client.get("/api/maintenance")
            self.assertEqual(response.status_code, 200, response.text[:300])
            _clean(response)
            # Pre-fix the whole task vanished ([]): the str arm wiped the
            # honest number to "" and _task_id dropped the entry.
            self.assertEqual([r["id"] for r in response.json()], ["42"])
            # The listed id is the id the run route can match.
            response = client.post("/api/maintenance/42/run")
            self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertEqual(_wait_finished("42").get("rc"), 0)

    def test_str_desc_claiming_int_keeps_its_text(self):
        rows = [{"id": "plain", "name": "Plain", "command": "true",
                 "desc": _LyingIntStr("dumps the config")}]
        with mock.patch.object(jobs, "cfg",
                               return_value={"maintenance": rows}):
            response = _client().get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        # Pre-fix: the int arm's refused coercion returned None and the
        # honest text rendered as null.
        self.assertEqual(response.json()[0]["desc"], "dumps the config")

    def test_str_name_claiming_bytes_keeps_its_text(self):
        rows = [{"id": "plain", "command": "true",
                 "name": _LyingBytesStr("Nightly cleanup")}]
        with mock.patch.object(jobs, "cfg",
                               return_value={"maintenance": rows}):
            response = _client().get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        # Pre-fix: both base decodes refused the str layout, the "" wipe
        # lost the name, and the row fell back to its id.
        self.assertEqual(response.json()[0]["name"], "Nightly cleanup")

    def test_float_desc_claiming_int_keeps_its_number(self):
        rows = [{"id": "plain", "name": "Plain", "command": "true",
                 "desc": _LyingIntFloat(2.5)}]
        with mock.patch.object(jobs, "cfg",
                               return_value={"maintenance": rows}):
            response = _client().get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        self.assertEqual(response.json()[0]["desc"], 2.5)


class IterBombRecoveryTests(_DiskYamlSandbox):
    """The fixed vaporisation: bound materialisers dispatched a real
    subclass's overridden ``__iter__`` and lost perfectly walkable C-level
    storage; the unbound snapshots read underneath the override."""

    def test_iter_bomb_log_list_keeps_its_lines(self):
        jobs._jobs["plain"] = {"running": False, "rc": 0,
                               "log": _IterBombList(["line one", "line two"])}
        response = _client().get("/api/maintenance/plain/log")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        # Pre-fix: the bound list() dispatched the bomb and the tail showed
        # "(waiting for output…)" over a finished job's real lines.
        self.assertEqual(response.json()["log"], "line one\nline two")

    def test_lying_str_log_list_keeps_its_lines(self):
        jobs._jobs["plain"] = {"running": False, "rc": 0,
                               "log": _LyingStrList(["a", "b"])}
        response = _client().get("/api/maintenance/plain/log")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        # Pre-fix: the claimed-str arm wiped the honest list to "".
        self.assertEqual(response.json()["log"], "a\nb")

    def test_iter_bomb_nested_value_keeps_its_rows(self):
        jobs._jobs["plain"] = {"running": False, "rc": _IterBombList([0, 7]),
                               "finished": None}
        response = _client().get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        row = next(r for r in response.json() if r["id"] == "plain")
        # Pre-fix: _jsonable's bound list() dropped the honest cell to null.
        self.assertEqual(row["rc"], [0, 7])

    def test_iter_bomb_task_list_recovers_its_real_rows(self):
        # The maint13 pin held this at the drop shape ([]); the maint14
        # unbound snapshot reads the real storage instead, so the honest
        # task lists (the bookmarks14 recovered-shape rule).
        raw = _IterBombList([{"id": "plain", "name": "Plain",
                              "command": "true"}])
        with mock.patch.object(jobs, "cfg",
                               return_value={"maintenance": raw}):
            response = _client().get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        self.assertEqual([r["id"] for r in response.json()], ["plain"])


class ControlFlowStillPropagates(unittest.TestCase):
    """No new guard may widen into a hang: genuine control flow raised out
    of a hook keeps propagating through every upgraded seam.  Pinned at the
    helper rank — through the client it would only tear down the test
    server thread."""

    def test_key_text_reraises_keyboard_interrupt(self):
        class _KIKey:
            def __str__(self):
                raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            jobs._key_text(_KIKey())

    def test_utf8_text_coercion_arm_reraises_system_exit(self):
        class _SEObj:
            def __str__(self):
                raise SystemExit(3)

        with self.assertRaises(SystemExit):
            jobs._utf8_text(_SEObj())

    def test_jsonable_isoformat_reraises_keyboard_interrupt(self):
        class _KIStamp:
            def isoformat(self):
                raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            jobs._jsonable(_KIStamp())


class HealthyAndImpostorShapeUnchanged(_DiskYamlSandbox):
    """The SPA contract and the established total-impostor drops, re-pinned
    so the recovery cannot weaken the maint9-maint13 union."""

    def test_healthy_rows_keep_the_exact_contract(self):
        config.YAML_PATH.write_text(
            "maintenance:\n"
            "  - id: backup\n    name: Backup\n    desc: dump\n"
            "    confirm: true\n    command: 'true'\n"
            "  - id: bare\n    command: 'true'\n",
            encoding="utf-8")
        config.reload_cfg()
        response = _client().get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        by_id = {r["id"]: r for r in response.json()}
        self.assertEqual(by_id["backup"], {
            "id": "backup", "name": "Backup", "desc": "dump", "confirm": True,
            "running": False, "rc": None, "finished": None})
        self.assertEqual(by_id["bare"]["name"], "bare")
        self.assertEqual(by_id["bare"]["desc"], "")
        self.assertIs(by_id["bare"]["confirm"], False)

    def test_total_impostors_keep_their_established_drops(self):
        class _Lie:
            """A claim with no usable layout underneath — the maint9 shape."""

            def __init__(self, claim):
                self._claim = claim

            @property
            def __class__(self):  # noqa: D105
                return self._claim

            def __hash__(self):  # usable as a mapping key
                return 17

            def __eq__(self, other):  # noqa: D105
                return NotImplemented

        rows = [{"id": "plain", "name": _Lie(str), "desc": _Lie(bytes),
                 "confirm": _Lie(bool), "command": "true",
                 "timeout": _Lie(int), "weight": _Lie(float)}]
        with mock.patch.object(jobs, "cfg",
                               return_value={"maintenance": rows}):
            response = _client().get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        row = next(r for r in response.json() if r["id"] == "plain")
        # The claim-str/claim-bytes impostors keep the "" drop, so the name
        # still falls back to the id; confirm keeps failing closed.
        self.assertEqual(row["name"], "plain")
        self.assertEqual(row["desc"], "")
        self.assertIs(row["confirm"], False)

    def test_a_genuine_job_traceback_line_keeps_its_addresses(self):
        # The address belt guards the *coercion* arm only: real str storage
        # is data, and a job's own log line quoting a Python repr must serve
        # verbatim.
        jobs._jobs["plain"] = {
            "running": False, "rc": 1,
            "log": ["error in <handler at 0xdeadbeef>"], "finished": None}
        response = _client().get("/api/maintenance/plain/log")
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertEqual(response.json()["log"],
                         "error in <handler at 0xdeadbeef>")


if __name__ == "__main__":
    unittest.main()
