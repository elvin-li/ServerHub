"""Thirteenth leftover-500s sweep of the Jobs domain: BaseException-shaped
bombs past ``except Exception``, the clock-net escapes, and decode fidelity.

jobs12 sealed the row-field rank (hash-shadowing bomb keys through
``_mapping_get``), but every guard beneath it — in ``hub.jobs``,
``hub.scheduler_svc`` and the scheduler router — stopped at
``except Exception``.  Three leftover classes survived it:

* A leftover whose hooks raise a *BaseException* subclass (the
  modules12/logs12/nas13 watchdog/timeout shape) sailed past every catch at
  once: a ``__class__``-property bomb blew ``_isinst`` — the gate every
  sanitizer arm in both modules stands on — raw out of GET /api/maintenance,
  its run and log routes, GET /api/scheduler/jobs and every mutation's
  get_job scan; shadow-key ``__eq__`` bombs blew ``_mapping_get`` /
  ``_jobs_row`` / ``_matches_id`` past their nets; ``__bool__`` / ``__str__``
  / ``__iter__`` / ``__int__`` bombs blew ``_truthy`` / ``_utf8_text`` /
  ``_cron_field_tokens`` / ``_clamp_timeout`` / ``_job_timeout``; a bombed
  runner broke ``_execute``'s "never raises" contract so the run was never
  journalled; and a bombed high-water mark or matcher member aborted the
  whole engine tick.
* Two clock nets named only the arithmetic quartet/trio, so even an
  *Exception*-shaped ``__float__`` bomb (RuntimeError) rode out raw:
  ``_delay_until_next_minute`` runs *outside* ``_loop``'s blanket tick catch,
  so a patched clock killed the engine thread outright — no job ever fired
  again — and ``_tick_once`` / the router's SMART-bridge ``last_run`` probe
  degraded at the wrong rank (the whole tick / the whole bridged row instead
  of one field).
* The claimed-base decode gap (the modules12/nas13 ``_decode_bytes`` rule):
  both modules picked the decode base off the *claimed* ``__class__``, so a
  genuine ``bytearray`` whose ``__class__`` lied ``bytes`` was handed to
  ``bytes.decode``, refused by the descriptor, and its perfectly decodable
  content went blank — a task name vanished from the Maintenance listing and
  a log line emptied.

The fixes are the module-local ``_CONTROL_FLOW`` convention (every guard
re-raises KeyboardInterrupt / SystemExit and launders everything else
BaseException-shaped exactly like its Exception twin), the widened clock
nets, and the both-bases first-come decode.  These tests plant each bomb
against our own handlers in-process and assert 200 / coded 4xx bodies with
valid UTF-8 JSON, never a raw raise — and pin control flow still
propagating, because swallowing a Ctrl-C to save one JSON field would turn
the sanitizer into a hang.
"""
from __future__ import annotations

import json
import sys
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from hub import jobs, scheduler_svc  # noqa: E402

_APP = None


def _client():
    global _APP
    from fastapi.testclient import TestClient

    if _APP is None:
        from hub.app_factory import create_app
        from hub.auth import require_auth

        _APP = create_app()
        _APP.dependency_overrides[require_auth] = lambda: True
    return TestClient(_APP, raise_server_exceptions=False)


def _starlette(payload) -> None:
    """What Starlette's JSONResponse does: ensure_ascii=False then UTF-8."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class LeftoverBaseBomb(BaseException):
    """BaseException-shaped, but *not* control flow — a bomb like any other."""


def _base_raising_property():
    return property(
        lambda self: (_ for _ in ()).throw(LeftoverBaseBomb("leftover base bomb")))


class _ClassPropBaseBomb:
    """``__class__`` property raising BaseException — used to blow ``_isinst``
    itself, the gate every sanitizer arm in both modules stands on."""

    __class__ = _base_raising_property()

    def __str__(self):
        return "still-renderable"


class _BoolBaseBomb:
    """A field whose ``__bool__`` raises BaseException (confirm / name)."""

    def __bool__(self):
        raise LeftoverBaseBomb("bool base bomb")


class _StrBaseBomb:
    """A field whose ``__str__`` raises BaseException."""

    def __str__(self):
        raise LeftoverBaseBomb("str base bomb")


class _IntBaseBomb:
    """A timeout whose ``__int__`` raises BaseException."""

    def __int__(self):
        raise LeftoverBaseBomb("int base bomb")


class _FloatRuntimeBomb:
    """A clock/epoch whose ``__float__`` raises RuntimeError.

    The old clock nets named only the arithmetic types, so even this
    *Exception*-shaped bomb rode out of the probe raw.
    """

    def __float__(self):
        raise RuntimeError("float runtime bomb")


class _FloatBaseBomb:
    def __float__(self):
        raise LeftoverBaseBomb("float base bomb")


class _ShadowBaseStr(str):
    """Same text and hash as a real field name, ``__eq__`` raising a
    BaseException subclass — every hash probe of the row dispatches into it
    reflected (subclass first), past the jobs12 Exception-shaped seal."""

    def __eq__(self, other):  # noqa: D105
        raise LeftoverBaseBomb("leftover shadow eq base bomb")

    __ne__ = __eq__

    def __hash__(self):  # noqa: D105
        return str.__hash__(self)


class _EqBaseBombValue:
    """An id *value* whose equality raises BaseException (_matches_id rank)."""

    def __eq__(self, other):  # noqa: D105
        raise LeftoverBaseBomb("leftover id value eq base bomb")

    __ne__ = __eq__

    def __hash__(self):  # noqa: D105
        return 5


class _IterBaseBombList(list):
    """A sequence whose bound ``__iter__`` raises BaseException."""

    def __iter__(self):
        raise LeftoverBaseBomb("iter base bomb")


class _EqBaseBombInt(int):
    """A matcher-set member whose reflected ``__eq__`` raises BaseException."""

    def __eq__(self, other):  # noqa: D105
        raise LeftoverBaseBomb("member eq base bomb")

    __ne__ = __eq__

    def __hash__(self):  # noqa: D105
        return int.__hash__(self)


class _EqBaseBombTuple(tuple):
    """A leftover ``_last_minute`` mark whose comparison raises BaseException."""

    def __eq__(self, other):  # noqa: D105
        raise LeftoverBaseBomb("mark eq base bomb")

    __ne__ = __eq__

    def __lt__(self, other):  # noqa: D105
        raise LeftoverBaseBomb("mark lt base bomb")

    def __hash__(self):  # noqa: D105
        return tuple.__hash__(self)


class _BytesLiarBytearray(bytearray):
    """A genuine bytearray whose ``__class__`` lies ``bytes``.

    The old decode arms picked the base off this very lie, handed the operand
    to ``bytes.decode``, and the descriptor's TypeError cost the perfectly
    decodable content — a blank task name, an empty log line.
    """

    @property
    def __class__(self):
        return bytes


def _row(jid="good", **over):
    row = {"id": jid, "name": "n", "type": "command", "cron": "* * * * *",
           "enabled": True, "params": {"command": "true"}}
    row.update(over)
    return row


def _shadowed(field, base=None):
    """*base* with *field*'s key replaced by a same-text base-bomb key."""
    row = dict(base if base is not None else _row())
    value = row.pop(field, None)
    row[_ShadowBaseStr(field)] = value
    return row


def _sched_cfg(rows):
    return mock.patch.object(scheduler_svc, "cfg", lambda: {"schedules": rows})


def _disk(rows):
    """mutate() re-reads services.yaml, not the cfg() snapshot; give the
    mutation routes an in-memory stand-in so a hit really lands."""
    store = {"schedules": rows}

    def fake_mutate(mutator):
        mutator(store)
        return store

    return mock.patch.object(scheduler_svc, "mutate", fake_mutate)


class GuardContractTests(unittest.TestCase):
    """The shared guards degrade a BaseException-shaped bomb exactly like its
    Exception twin — in both modules."""

    def test_isinst_reads_a_class_prop_base_bomb_as_no_match(self):
        for module in (jobs, scheduler_svc):
            with self.subTest(module=module.__name__):
                self.assertIs(module._isinst(_ClassPropBaseBomb(), dict), False)

    def test_truthy_reads_a_bool_base_bomb_as_false(self):
        self.assertIs(jobs._truthy(_BoolBaseBomb()), False)

    def test_utf8_text_reads_a_str_base_bomb_as_empty(self):
        for module in (jobs, scheduler_svc):
            with self.subTest(module=module.__name__):
                self.assertEqual(module._utf8_text(_StrBaseBomb()), "")

    def test_clamp_timeout_reads_an_int_base_bomb_as_default(self):
        self.assertEqual(jobs._clamp_timeout(_IntBaseBomb()),
                         jobs.JOB_TIMEOUT_DEFAULT)

    def test_job_timeout_reads_an_int_base_bomb_as_default(self):
        self.assertEqual(scheduler_svc._job_timeout({"timeout": _IntBaseBomb()}),
                         scheduler_svc.DEFAULT_TIMEOUT)

    def test_mapping_get_degrades_a_base_bomb_shadow_key(self):
        for module in (jobs, scheduler_svc):
            with self.subTest(module=module.__name__):
                row = {_ShadowBaseStr("id"): "junk"}
                self.assertIsNone(module._mapping_get(row, "id"))

    def test_plain_dict_drops_a_class_prop_base_bomb(self):
        for module in (jobs, scheduler_svc):
            with self.subTest(module=module.__name__):
                self.assertIsNone(module._plain_dict(_ClassPropBaseBomb()))

    def test_jsonable_launders_base_bomb_shapes(self):
        # The guard contract is the same for both modules: the bomb is
        # laundered, never re-raised.  hub.jobs additionally recovers the
        # perfectly walkable real storage underneath the override since the
        # maint14 unbound-snapshot sweep (the bookmarks14 recovered-shape
        # rule); scheduler_svc keeps the guarded drop.
        self.assertEqual(jobs._jsonable(_IterBaseBombList([1])), [1])
        self.assertIsNone(scheduler_svc._jsonable(_IterBaseBombList([1])))
        for module in (jobs, scheduler_svc):
            with self.subTest(module=module.__name__):
                self.assertEqual(module._jsonable(_StrBaseBomb()), "")

    def test_in_field_reads_a_member_eq_base_bomb_as_no_match(self):
        self.assertIs(
            scheduler_svc._in_field(5, {_EqBaseBombInt(5)}), False)

    def test_cron_tokens_convert_base_bombs_to_the_one_valueerror(self):
        # ValueError is the one signal every caller catches; a BaseException
        # subclass used to ride out of next_run_ts's net and 500 the list.
        with self.assertRaises(ValueError):
            scheduler_svc._cron_field_tokens(_IterBaseBombList(["*"] * 5))
        with self.assertRaises(ValueError):
            scheduler_svc._cron_field_tokens(
                ["0", "4", "*", "*", _StrBaseBomb()])
        self.assertIs(
            scheduler_svc.valid_cron(_IterBaseBombList(["*"] * 5)), False)

    def test_jobs_row_rescue_scan_survives_a_base_bomb_key(self):
        row = {"running": False, "rc": 0, "log": ["done"]}
        with mock.patch.object(jobs, "_jobs", {_ShadowBaseStr("t1"): row}):
            self.assertIs(jobs._jobs_row("t1"), row)

    def test_matches_id_steps_past_a_base_bomb_id_value(self):
        self.assertIs(
            scheduler_svc._matches_id({"id": _EqBaseBombValue()}, "good"),
            False)

    def test_run_watchdog_reads_a_base_bomb_popen_as_failure(self):
        def _raise(*a, **k):
            raise LeftoverBaseBomb("popen base bomb")

        log: list[str] = []
        with mock.patch.object(jobs.subprocess, "Popen", _raise):
            rc = jobs.run_watchdog(["true"], timeout=5, log=log)
        self.assertEqual(rc, -1)
        self.assertTrue(any("!! error" in line for line in log), log)


class ControlFlowPassthroughTests(unittest.TestCase):
    """Genuine control flow keeps propagating through every guard —
    swallowing a Ctrl-C to save one JSON field would turn the sanitizer
    into a hang."""

    def test_isinst_reraises_control_flow(self):
        for kind in (KeyboardInterrupt, SystemExit):
            class Bomb:
                __class__ = property(
                    lambda self, _kind=kind: (_ for _ in ()).throw(_kind()))

            for module in (jobs, scheduler_svc):
                with self.subTest(module=module.__name__, kind=kind.__name__):
                    with self.assertRaises(kind):
                        module._isinst(Bomb(), dict)

    def test_truthy_reraises_control_flow(self):
        for kind in (KeyboardInterrupt, SystemExit):
            class Bomb:
                def __bool__(self, _kind=kind):
                    raise _kind()

            with self.subTest(kind=kind.__name__):
                with self.assertRaises(kind):
                    jobs._truthy(Bomb())

    def test_utf8_text_reraises_control_flow(self):
        for kind in (KeyboardInterrupt, SystemExit):
            class Bomb:
                def __str__(self, _kind=kind):
                    raise _kind()

            for module in (jobs, scheduler_svc):
                with self.subTest(module=module.__name__, kind=kind.__name__):
                    with self.assertRaises(kind):
                        module._utf8_text(Bomb())

    def test_execute_reraises_control_flow_and_still_unparks_the_job(self):
        for kind in (KeyboardInterrupt, SystemExit):
            def _raise(job, log, _kind=kind):
                raise _kind()

            with self.subTest(kind=kind.__name__), \
                    mock.patch.dict(scheduler_svc._RUNNERS,
                                    {"command": _raise}), \
                    mock.patch.object(scheduler_svc, "_running", set()):
                with self.assertRaises(kind):
                    scheduler_svc._execute(_row(), "manual")
                # The finally still ran: the id is not parked "running".
                self.assertIs(scheduler_svc.is_running("good"), False)

    def test_run_watchdog_reraises_control_flow(self):
        for kind in (KeyboardInterrupt, SystemExit):
            def _raise(*a, _kind=kind, **k):
                raise _kind()

            with self.subTest(kind=kind.__name__):
                with mock.patch.object(jobs.subprocess, "Popen", _raise):
                    with self.assertRaises(kind):
                        jobs.run_watchdog(["true"], timeout=5, log=[])


class MaintenanceBaseBombHttpTests(unittest.TestCase):
    """BaseException-shaped bombs no longer 500 the Maintenance routes."""

    def _listing(self, rows):
        with mock.patch.object(jobs, "cfg",
                               return_value={"maintenance": rows}):
            r = _client().get("/api/maintenance")
        self.assertEqual(r.status_code, 200, r.text[:300])
        payload = r.json()
        _starlette(payload)
        return {t.get("id"): t for t in payload}

    def test_class_prop_base_bomb_row_drops_and_sibling_survives(self):
        by_id = self._listing(
            [_ClassPropBaseBomb(), {"id": "ok", "command": "true"}])
        self.assertIn("ok", by_id)

    def test_confirm_bool_base_bomb_fails_closed_at_the_view_rank(self):
        # Straight into maintenance_view's _truthy (the maint12 seam): via
        # cfg the bomb is laundered to its repr first, but an in-process
        # leftover row reaching the view rank raw used to blow the old
        # Exception-only _truthy with a BaseException subclass and 500 the
        # list route.
        rows = {"ok": {"id": "ok", "name": "OK", "confirm": _BoolBaseBomb()}}
        with mock.patch.object(jobs, "maintenance_tasks", return_value=rows):
            r = _client().get("/api/maintenance")
        self.assertEqual(r.status_code, 200, r.text[:300])
        payload = r.json()
        _starlette(payload)
        self.assertIs(payload[0]["confirm"], False)

    def test_base_bomb_shadow_id_key_costs_only_its_row(self):
        junk = {_ShadowBaseStr("id"): "junk", "command": "true"}
        by_id = self._listing([junk, {"id": "ok", "command": "true"}])
        self.assertIn("ok", by_id)
        self.assertNotIn("junk", by_id)

    def test_log_route_survives_a_base_bomb_jobs_table_key(self):
        table = {_ShadowBaseStr("t1"): {
            "running": False, "rc": 0, "log": ["all done"]}}
        with mock.patch.object(jobs, "cfg", return_value={"maintenance": [
                {"id": "t1", "command": "true"}]}), \
                mock.patch.object(jobs, "_jobs", table):
            r = _client().get("/api/maintenance/t1/log")
        self.assertEqual(r.status_code, 200, r.text[:300])
        payload = r.json()
        _starlette(payload)
        self.assertIn("all done", payload["log"])

    def test_run_route_survives_a_bool_base_bomb_running_flag(self):
        # A bomb row is junk, not a live job: the mutex scan fails it closed
        # instead of detonating (or wedging the single runner forever).
        table = {"other": {"running": _BoolBaseBomb()}}
        with mock.patch.object(jobs, "cfg", return_value={"maintenance": [
                {"id": "t1"}]}), \
                mock.patch.object(jobs, "_jobs", table):
            r = _client().post("/api/maintenance/t1/run")
        self.assertEqual(r.status_code, 200, r.text[:300])
        _starlette(r.json())


class MaintenanceDecodeFidelityTests(unittest.TestCase):
    """A genuine bytearray whose ``__class__`` lies ``bytes`` decodes through
    its real layout instead of degrading at the wrong rank."""

    def test_decode_bytes_reads_the_honest_content(self):
        liar = _BytesLiarBytearray(b"honest content")
        for module in (jobs, scheduler_svc):
            with self.subTest(module=module.__name__):
                self.assertEqual(module._decode_bytes(liar), "honest content")
                # Honest operands keep decoding first-come.
                self.assertEqual(module._decode_bytes(b"plain"), "plain")
                self.assertEqual(
                    module._decode_bytes(bytearray(b"plain")), "plain")
                # A total liar (real type is neither base) still degrades.
                self.assertEqual(module._decode_bytes("not bytes"), "")

    def test_task_name_survives_the_lie_into_the_listing(self):
        rows = [{"id": "t1", "command": "true",
                 "name": _BytesLiarBytearray(b"Nightly cleanup")}]
        with mock.patch.object(jobs, "cfg",
                               return_value={"maintenance": rows}):
            r = _client().get("/api/maintenance")
        self.assertEqual(r.status_code, 200, r.text[:300])
        by_id = {t.get("id"): t for t in r.json()}
        # The old claimed-base pick blanked the name; the both-bases decode
        # keeps the honest text.
        self.assertEqual(by_id["t1"]["name"], "Nightly cleanup")

    def test_log_line_survives_the_lie_into_the_tail(self):
        table = {"t1": {"running": False, "rc": 0,
                        "log": [_BytesLiarBytearray(b"tick line")]}}
        with mock.patch.object(jobs, "_jobs", table):
            r = _client().get("/api/maintenance/t1/log")
        self.assertEqual(r.status_code, 200, r.text[:300])
        self.assertIn("tick line", r.json()["log"])


class SchedulerBaseBombHttpTests(unittest.TestCase):
    """BaseException-shaped bombs no longer 500 the scheduler routes."""

    def _list_by_id(self):
        r = _client().get("/api/scheduler/jobs")
        self.assertEqual(r.status_code, 200, r.text[:300])
        payload = r.json()
        _starlette(payload)
        return {j.get("id"): j for j in payload["jobs"]}

    def test_class_prop_base_bomb_row_drops_and_sibling_survives(self):
        with _sched_cfg([_ClassPropBaseBomb(), _row("good")]):
            by_id = self._list_by_id()
            self.assertIn("good", by_id)
            self.assertIsInstance(by_id["good"]["next_run"], int)

    def test_base_bomb_shadow_keys_cost_only_their_fields(self):
        for field in ("id", "enabled", "cron"):
            with self.subTest(field=field), \
                    _sched_cfg([_shadowed(field, _row("junk")), _row("good")]):
                by_id = self._list_by_id()
                self.assertIn("good", by_id)

    def test_cron_class_prop_base_bomb_parks_next_run(self):
        with _sched_cfg([_row("good", cron=_ClassPropBaseBomb())]):
            by_id = self._list_by_id()
            self.assertIsNone(by_id["good"]["next_run"])

    def test_delete_on_healthy_sibling_survives_base_bomb_junk(self):
        rows = [_shadowed("id", _row("junk")),
                _row("junk2", id=_EqBaseBombValue()), _row("good")]
        with _sched_cfg(rows), _disk([_row("good")]):
            r = _client().delete("/api/scheduler/jobs/good")
            self.assertEqual(r.status_code, 200, r.text[:300])
            self.assertTrue(r.json()["ok"])

    def test_run_now_survives_base_bomb_shadow_type_in_audit_fields(self):
        with _sched_cfg([_shadowed("type")]):
            r = _client().post("/api/scheduler/jobs/good/run-now")
            self.assertEqual(r.status_code, 200, r.text[:300])
            self.assertTrue(r.json()["ok"])


class SmartBridgeTests(unittest.TestCase):
    """The read-only SMART bridge degrades field-level, never 500s."""

    def test_a_base_bomb_provider_drops_only_the_bridge_row(self):
        def _raise():
            raise LeftoverBaseBomb("schedule provider base bomb")

        with _sched_cfg([_row("good")]), \
                mock.patch("hub.smart_test_svc.get_schedule", _raise):
            r = _client().get("/api/scheduler/jobs")
        self.assertEqual(r.status_code, 200, r.text[:300])
        payload = r.json()
        _starlette(payload)
        self.assertEqual(payload["system"], [])
        self.assertTrue(any(j.get("id") == "good" for j in payload["jobs"]))

    def test_last_run_float_bombs_degrade_field_level(self):
        # The old net named only (TypeError, ValueError, OverflowError):
        # a RuntimeError-shaped bomb — let alone the BaseException twin —
        # used to cost the whole bridged row instead of one field.
        for bomb in (_FloatRuntimeBomb(), _FloatBaseBomb()):
            with self.subTest(bomb=type(bomb).__name__), \
                    _sched_cfg([]), \
                    mock.patch("hub.smart_test_svc.get_schedule",
                               return_value={"interval": "weekly",
                                             "kind": "short",
                                             "devices": ["disk0"],
                                             "last_run": bomb}):
                r = _client().get("/api/scheduler/jobs")
            self.assertEqual(r.status_code, 200, r.text[:300])
            system = r.json()["system"]
            self.assertEqual(len(system), 1, system)
            self.assertEqual(system[0]["last_run"], 0)
            self.assertIs(system[0]["enabled"], True)


class EngineTickTests(unittest.TestCase):
    """A BaseException-shaped bomb costs only its own row, never the tick —
    and the clock seams outside the blanket catch can no longer kill the
    engine thread."""

    ANCHOR = 1_900_000_000 - (1_900_000_000 % 60) + 60

    def _launched(self, rows, anchor=None):
        ran: list[str] = []
        with _sched_cfg(rows), \
                mock.patch.object(scheduler_svc, "_execute",
                                  lambda job, trigger: ran.append(
                                      scheduler_svc._job_id(job))), \
                mock.patch.object(scheduler_svc, "_last_minute", None):
            return scheduler_svc._tick_once(anchor or self.ANCHOR), ran

    def test_base_bomb_shadow_cron_key_costs_only_its_row(self):
        launched, ran = self._launched(
            [_shadowed("cron", _row("junk")), _row("good")])
        self.assertEqual(launched, ["good"])
        self.assertEqual(ran, ["good"])

    def test_class_prop_base_bomb_cron_costs_only_its_row(self):
        launched, _ = self._launched(
            [_row("junk", cron=_ClassPropBaseBomb()), _row("good")])
        self.assertEqual(launched, ["good"])

    def test_a_base_bomb_high_water_mark_reanchors_not_forever_stalls(self):
        mark = _EqBaseBombTuple((2030, 1, 1, 0, 0))
        with _sched_cfg([_row("good")]), \
                mock.patch.object(scheduler_svc, "_execute",
                                  lambda job, trigger: None), \
                mock.patch.object(scheduler_svc, "_last_minute", mark):
            # The bombed mark costs this tick (re-anchor, boot semantics)…
            self.assertEqual(scheduler_svc._tick_once(self.ANCHOR), [])
            # …but the next minute fires: the junk mark is gone for good.
            self.assertEqual(
                scheduler_svc._tick_once(self.ANCHOR + 60), ["good"])

    def test_tick_clock_bombs_cost_one_tick_not_a_raise(self):
        for bomb in (_FloatRuntimeBomb(), _FloatBaseBomb()):
            with self.subTest(bomb=type(bomb).__name__):
                self.assertEqual(scheduler_svc._tick_once(bomb), [])

    def test_delay_clock_bombs_read_as_the_fallback(self):
        # This helper runs OUTSIDE _loop's blanket catch: the old named net
        # let a RuntimeError-shaped clock bomb kill the engine thread.
        for bomb in (_FloatRuntimeBomb(), _FloatBaseBomb()):
            with self.subTest(bomb=type(bomb).__name__):
                self.assertEqual(
                    scheduler_svc._delay_until_next_minute(bomb), 30.0)

    def test_genuine_rows_still_fire_on_their_minute(self):
        launched, ran = self._launched([_row("good")])
        self.assertEqual(launched, ["good"])
        self.assertEqual(ran, ["good"])


class ExecuteNeverRaisesBaseBombTests(unittest.TestCase):
    """_execute's "never raises" contract now survives BaseException bombs."""

    def _run(self, job, runners=None):
        journalled: list[dict] = []
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                scheduler_svc, "_record_run", journalled.append))
            stack.enter_context(mock.patch.object(
                scheduler_svc, "_running", set()))
            if runners:
                stack.enter_context(
                    mock.patch.dict(scheduler_svc._RUNNERS, runners))
            entry = scheduler_svc._execute(job, "manual")
        return entry, journalled

    def test_a_base_bomb_runner_still_journals_a_failed_run(self):
        def _raise(job, log):
            raise LeftoverBaseBomb("runner base bomb")

        entry, journalled = self._run(_row(), runners={"command": _raise})
        self.assertEqual(entry.get("status"), "failed")
        self.assertEqual(len(journalled), 1)
        self.assertIn("!! error", entry.get("tail", ""))
        # The finally ran: the id is not parked "running" forever.
        self.assertIs(scheduler_svc.is_running("good"), False)

    def test_a_bool_base_bomb_name_degrades_to_the_id(self):
        entry, journalled = self._run(_row(name=_BoolBaseBomb()))
        self.assertEqual(len(journalled), 1)
        self.assertEqual(entry.get("name"), "good")

    def test_a_base_bomb_shadow_type_key_journals_a_failed_run(self):
        entry, journalled = self._run(_shadowed("type"))
        self.assertEqual(entry.get("status"), "failed")
        self.assertEqual(len(journalled), 1)
        self.assertIn("unknown job type", entry.get("tail", ""))

    def test_an_iter_base_bomb_command_keeps_the_diagnosis(self):
        job = _row(params={"command": _IterBaseBombList(["true"])})
        entry, _ = self._run(job)
        self.assertEqual(entry.get("status"), "failed")
        self.assertIn("no command configured", entry.get("tail", ""))


class StaysImmunePins(unittest.TestCase):
    """Semantics the laundering must not have changed."""

    def test_genuine_cron_and_ids_still_round_trip(self):
        self.assertTrue(scheduler_svc.valid_cron("*/5 2-4 * * 1"))
        self.assertEqual(scheduler_svc._job_id({"id": " j1 "}), "j1")
        self.assertEqual(scheduler_svc._job_id({"id": 123}), "123")

    def test_genuine_enabled_semantics_survive(self):
        self.assertIs(scheduler_svc.job_enabled({"enabled": True}), True)
        self.assertIs(scheduler_svc.job_enabled({"enabled": "false"}), False)
        self.assertIs(scheduler_svc.job_enabled({"enabled": 0}), False)

    def test_genuine_timeouts_still_clamp(self):
        self.assertEqual(jobs._clamp_timeout(90), 90)
        self.assertEqual(jobs._clamp_timeout(10**9), jobs.JOB_TIMEOUT_MAX)
        self.assertEqual(scheduler_svc._job_timeout({"timeout": 90}), 90)

    def test_exception_shaped_bombs_stay_laundered(self):
        # The jobs12-era Exception-shaped seals must not have weakened.
        class EqBomb(str):
            def __eq__(self, other):  # noqa: D105
                raise RuntimeError("exception-shaped eq bomb")

            __ne__ = __eq__

            def __hash__(self):  # noqa: D105
                return str.__hash__(self)

        self.assertIsNone(
            scheduler_svc._mapping_get({EqBomb("id"): "x"}, "id"))
        self.assertIsNone(jobs._mapping_get({EqBomb("id"): "x"}, "id"))


class ProductVersionPin(unittest.TestCase):
    def test_product_version_stays_pinned(self):
        from hub import __version__

        self.assertEqual(__version__, "3.9.3")


if __name__ == "__main__":
    unittest.main(verbosity=2)
