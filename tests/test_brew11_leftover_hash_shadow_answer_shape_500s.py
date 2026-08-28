"""Eleventh leftover-500s sweep of the Homebrew listing / action / update card.

brew10 sealed the lying-``__class__`` impostors on the unbound-descriptor
seams.  Re-running the zoo with the vms/terminal/health11 *hash-shadowing
key* shape and the docker11/health11 *answer-shape* bombs surfaced live
leftovers on the very next seam over.  Every 500 below was reproduced
through the real app (``create_app()`` + ``TestClient(
raise_server_exceptions=False)``) before it was fixed.

Live 500s found and fixed here:

* POST /api/brew/services/{name}/action — a str-subclass key whose hash
  shadows ``t``/``v`` and whose ``__eq__`` raises, planted in
  ``brew_cache._cache``, detonated ``invalidate_brew_services``' bare
  ``_cache["t"] = 0.0`` assignment at the C-level insert compare.  That
  call sits *outside* the spawn try (the coded-503 rule), so the 500
  landed after the start/stop had already run on the host.
* POST /api/brew/services/{name}/action — the same shape planted in
  ``status._status_cache``, reached through the action's bare
  ``invalidate_status()`` call, 500'd it the same way.
* GET /api/tools/updates — the same shape in ``tools_svc._updates_cache``
  raised out of ``_updates_fresh``'s bare ``_updates_cache["v"]``
  subscript, and out of the final ``_updates_cache.update`` insert
  compare at the very end of a *successful* probe (after ``brew
  outdated`` and ``softwareupdate`` had already been paid for).  The
  Homebrew card rides that snapshot.
* POST /api/tools/updates/brew — ``brew_cache._brew_busy``'s bare
  ``proc.returncode == 0`` compare runs *outside* its spawn try, so an rc
  subclass whose ``__eq__`` raises (the rc-liar class) — or a
  ``returncode`` attribute that raises at all — raised straight out of
  the handler's only Homebrew-lock probe.

Row/snapshot wipes of the same class, now costing only the poisoned value:

* GET /api/brew/services — a shadowed ``user``/``file``/``exit_code`` key
  raised inside ``list_services``' per-row try and cost that whole
  service its row (name, status and actions with it).
* GET /api/brew/services — the shadowed ``v`` slot's raise escaped
  ``brew_services()`` into ``list_services``' broad except, so every brew
  row silently vanished into the (empty) text fallback.
* GET /api/brew/services — a tuple-subclass ``__iter__`` bomb around the
  ``sh`` answer raises ``RuntimeError``, which escaped ``_load``'s
  ``(TypeError, ValueError)`` tuple and discarded the last-good snapshot;
  in the text fallback it threw away the honest listing riding inside the
  wrapper.
* POST /api/brew/services/{name}/action — the same wrapper made the
  action report a raw Python unpack message ("cannot unpack non-iterable
  … object") as its failure text, with an honest ``exit 0`` inside.
* GET /api/tools/updates — a shadowed ``brew`` key in the cached snapshot
  raised out of ``_brew_outdated``'s busy/cooldown fallback, dropping the
  card's previous answer into the pool's generic empty result.

Stays-immune pins (probed, already sealed, pinned so they stay):

* a FIFO at the on-disk snapshot path answers empty rows, never a 500
  (``read_text_capped``'s ``O_NONBLOCK`` + ``EINVAL``).
* a 5000-digit ``exit_code`` — in ``brew services list --json`` output and
  as an already-int provider field — drops that one field
  (``_capped_json_int`` / ``_json_safe``).
* a dict-subclass row whose ``__bool__`` raises keeps its real pairs.
* a surrogate ``BREW`` path answers empty rows / the coded 503, and a
  junk spawn *shape* never forges the ``-1`` vanished sentinel: the
  ``brew.not_found`` 503 still requires the fresh disk confirm.

Fixes keep the brew6..10 union guards untouched and follow the sibling
conventions: ``_mapping_get`` degrades only the shadowed field,
``_cache_store`` falls back to clear+rewrite (``clear()`` never compares
keys), and ``_sh_answer`` / ``_spawn_pair`` read the answer's real
storage through the unbound base descriptors, degrading junk to ``None``
slots that ``_plain_rc`` reads as failure.  Product version stays 3.9.3.
"""
from __future__ import annotations

import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from hub import brew_cache, brew_svc, status, tools_svc
from hub.app_factory import create_app
from hub.auth import require_auth

_client_instance = None


def client() -> TestClient:
    global _client_instance
    if _client_instance is None:
        app = create_app()
        app.dependency_overrides[require_auth] = lambda: None
        # The SPA's failure mode is what is under test, not exception
        # propagation into the test process.
        _client_instance = TestClient(app, raise_server_exceptions=False)
    return _client_instance


def _assert_clean(test: unittest.TestCase, resp) -> None:
    """The body must be strictly renderable UTF-8 with no lone surrogates."""
    text = resp.text
    test.assertFalse(
        any("\ud800" <= ch <= "\udfff" for ch in text),
        "lone surrogate survived into the HTTP body",
    )
    text.encode("utf-8")
    # What Starlette's JSONResponse already did, asserted explicitly.
    json.dumps(resp.json(), ensure_ascii=False, allow_nan=False)


def _shadow_key(target: str):
    """A str-subclass key whose hash shadows *target* and whose ``__eq__``
    raises.

    Inserting it downgrades the dict off CPython's unicode fast path, so
    any later C-level probe for *target* lands on its slot and detonates
    the compare — including a plain ``d[target] = x`` assignment.  The
    vms/terminal/health11 hash-shadow zoo shape.
    """

    class Shadow(str):
        __hash__ = lambda self: hash(target)  # noqa: E731

        def __eq__(self, other):
            raise RuntimeError("shadow eq bomb")

        __ne__ = __eq__

    return Shadow("junk-" + target)


def _liar(claimed):
    """A lying ``__class__`` impostor (the brew10/json9 shape)."""

    class Liar:
        @property
        def __class__(self):
            return claimed

    return Liar()


class _EqBombRc(int):
    """Genuine int subclass whose comparisons raise (the rc-liar class)."""

    def __eq__(self, other):
        raise RuntimeError("rc eq bomb")

    def __ne__(self, other):
        raise RuntimeError("rc ne bomb")

    __hash__ = int.__hash__


class _TupleIterBomb(tuple):
    """Honest ``sh``/``run_capped`` answer whose own ``__iter__`` raises."""

    def __iter__(self):
        raise RuntimeError("iter bomb")


class _ListIterBomb(list):
    def __iter__(self):
        raise RuntimeError("iter bomb")


class _BrewCacheSandbox(unittest.TestCase):
    """Per-test brew snapshot cache, on its own temp disk path."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.disk = Path(self._tmp.name) / "brew-services.cache.json"
        patched = mock.patch.object(brew_cache, "_DISK", self.disk)
        patched.start()
        self.addCleanup(patched.stop)
        self.addCleanup(self._restore_cache)
        brew_cache.invalidate_brew_services()

    def _restore_cache(self):
        brew_cache._cache.clear()
        brew_cache._cache.update(t=0.0, v=None)
        brew_cache.invalidate_brew_services()

    def _prime_disk(self, rows=({"name": "redis", "status": "started"},)):
        self.disk.write_text(json.dumps(list(rows)), encoding="utf-8")

    def _plant(self, target: str):
        """Plant a hash-shadowing key in the snapshot cache.

        The shadow goes in *first*: inserting it while the real *target*
        key is already present makes the insert itself probe that slot and
        detonate, which is the C-level compare under test — the table only
        reaches its poisoned state when the bomb lands in a free slot.
        """
        brew_cache._cache.clear()
        brew_cache._cache[_shadow_key(target)] = 1
        for slot, value in (("t", 0.0), ("v", None)):
            if slot != target:
                brew_cache._cache[slot] = value

    def _listing(self, spawn=(0, "[]", "")):
        with (
            mock.patch.object(brew_svc, "_brew_present", return_value=True),
            mock.patch.object(brew_cache, "_brew_busy", return_value=False),
            mock.patch.object(brew_cache, "sh", return_value=spawn),
            mock.patch.object(brew_svc, "sh", return_value=(1, "", "")),
        ):
            resp = client().get("/api/brew/services")
        _assert_clean(self, resp)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        return sorted(r["id"] for r in resp.json()["services"])


# --------------------------------------------------------------------------
# Hash-shadowing keys in the brew snapshot cache
# --------------------------------------------------------------------------
class BrewCacheShadowKeyTests(_BrewCacheSandbox):
    """A shadow key in ``brew_cache._cache`` costs a refresh, never a 500."""

    def _action(self, rc=0, msg="ok"):
        with (
            mock.patch.object(brew_svc, "_brew_present", return_value=True),
            mock.patch.object(brew_svc, "run_capped", return_value=(rc, msg)),
        ):
            resp = client().post(
                "/api/brew/services/redis/action", json={"action": "restart"}
            )
        _assert_clean(self, resp)
        return resp

    def test_shadowed_t_slot_does_not_500_the_action(self):
        # Pre-fix: invalidate_brew_services' bare ``_cache["t"] = 0.0``
        # raised out of the C-level insert compare — a raw 500 *after* the
        # start/stop had already run on the host.
        self._plant("t")
        resp = self._action()
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        self.assertTrue(body["ok"])
        self.assertEqual(body["message"], "ok")

    def test_shadowed_v_slot_does_not_500_the_action(self):
        self._plant("v")
        resp = self._action()
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertTrue(resp.json()["ok"])

    def test_shadowed_v_slot_keeps_the_listing_rows(self):
        # Pre-fix: the bare ``_cache["v"]`` subscript in _fresh raised, the
        # raise escaped brew_services() into list_services' broad except,
        # and every brew row silently vanished into the text fallback.
        self._plant("v")
        rows = self._listing((0, '[{"name":"a","status":"started"}]', ""))
        self.assertEqual(rows, ["a"])

    def test_poisoned_cache_is_evicted_so_the_next_read_is_an_ordinary_hit(self):
        self._plant("v")
        first = self._listing((0, '[{"name":"a","status":"started"}]', ""))
        self.assertEqual(first, ["a"])
        # clear+rewrite evicted the bomb, so the table is exact-str again.
        self.assertEqual(
            sorted({type(k).__name__ for k in brew_cache._cache}), ["str"]
        )
        # A TTL hit now answers from memory without another spawn.
        with mock.patch.object(
            brew_cache, "sh", side_effect=AssertionError("must not respawn")
        ):
            self.assertEqual(
                sorted(r["name"] for r in brew_cache.brew_services()), ["a"]
            )

    def test_mapping_get_degrades_only_the_shadowed_field(self):
        d = {"keep": 2}
        d[_shadow_key("gone")] = 1
        self.assertIsNone(brew_cache._mapping_get(d, "gone"))
        self.assertEqual(brew_cache._mapping_get(d, "keep"), 2)
        self.assertEqual(brew_cache._mapping_get(_liar(dict), "k", "d"), "d")
        self.assertEqual(brew_cache._mapping_get("not-a-dict", "k", "d"), "d")

    def test_unreadable_timestamp_slot_reads_as_expired_not_a_500(self):
        # A leftover non-numeric / inf stamp used to TypeError/OverflowError
        # the ``time.time() - _cache["t"]`` subtraction.
        brew_cache._cache.clear()
        brew_cache._cache.update(t="junk", v=[{"name": "stale"}])
        self.assertIsNone(brew_cache._fresh())
        brew_cache._cache.update(t=float("inf"), v=[{"name": "stale"}])
        self.assertIsNone(brew_cache._fresh())


class BrewActionForeignCacheShadowTests(unittest.TestCase):
    """The action's two invalidate calls sit outside its spawn try."""

    def setUp(self):
        self._saved = dict(status._status_cache)
        self.addCleanup(self._restore)

    def _restore(self):
        status._status_cache.clear()
        status._status_cache.update(self._saved)

    def test_shadowed_status_cache_does_not_500_the_finished_action(self):
        # Pre-fix: invalidate_status()'s bare ``_status_cache["t"] = 0``
        # raised out of the insert compare and 500'd POST
        # /api/brew/services/{name}/action after brew had already run.
        status._status_cache.clear()
        status._status_cache[_shadow_key("t")] = 1
        with (
            mock.patch.object(brew_svc, "_brew_present", return_value=True),
            mock.patch.object(brew_svc, "run_capped", return_value=(0, "started")),
        ):
            resp = client().post(
                "/api/brew/services/redis/action", json={"action": "start"}
            )
        _assert_clean(self, resp)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        self.assertTrue(body["ok"])
        self.assertEqual(body["message"], "started")


# --------------------------------------------------------------------------
# Hash-shadowing keys in a brew row
# --------------------------------------------------------------------------
class BrewRowShadowKeyTests(unittest.TestCase):
    """A shadowed row field costs the field, not the service's whole row."""

    def _rows(self, data):
        with (
            mock.patch.object(brew_svc, "_brew_present", return_value=True),
            mock.patch.object(brew_svc, "brew_services_list", return_value=data),
            mock.patch.object(brew_svc, "sh", return_value=(1, "", "")),
        ):
            resp = client().get("/api/brew/services")
        _assert_clean(self, resp)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        return {r["id"]: r for r in resp.json()["services"]}

    def test_shadowed_user_key_keeps_the_row(self):
        # Pre-fix: the unbound ``dict.get(s, "user")`` probe landed on the
        # shadow slot and raised inside the per-row try — redis lost its
        # name, status and actions over one poisoned field.
        row = {"name": "redis", "status": "started"}
        row[_shadow_key("user")] = 1
        rows = self._rows([row])
        self.assertEqual(sorted(rows), ["redis"])
        self.assertEqual(rows["redis"]["status"], "started")
        self.assertIsNone(rows["redis"]["user"])
        self.assertEqual(rows["redis"]["actions"], ["restart", "stop"])

    def test_shadowed_exit_code_and_file_keys_keep_the_row(self):
        row = {"name": "redis", "status": "error"}
        row[_shadow_key("exit_code")] = 1
        row[_shadow_key("file")] = 1
        rows = self._rows([row])
        self.assertEqual(sorted(rows), ["redis"])
        self.assertEqual(rows["redis"]["state"], "warn")
        self.assertIsNone(rows["redis"]["exit_code"])
        self.assertIsNone(rows["redis"]["file"])

    def test_shadowed_name_key_costs_only_that_row(self):
        # A row with no readable name has nothing to render; its siblings
        # must still answer.
        row = {"status": "started"}
        row[_shadow_key("name")] = "redis"
        rows = self._rows([row, {"name": "glances", "status": "none"}])
        self.assertEqual(sorted(rows), ["glances"])

    def test_mapping_get_degrades_only_the_shadowed_field(self):
        d = {"keep": 2}
        d[_shadow_key("gone")] = 1
        self.assertIsNone(brew_svc._mapping_get(d, "gone"))
        self.assertEqual(brew_svc._mapping_get(d, "keep"), 2)
        self.assertEqual(brew_svc._mapping_get(_liar(dict), "k", "d"), "d")


# --------------------------------------------------------------------------
# sh() / run_capped() answer-shape bombs
# --------------------------------------------------------------------------
class BrewLoadAnswerShapeTests(_BrewCacheSandbox):
    """``brew_cache._load``'s unpack caught only TypeError/ValueError."""

    def test_iter_bomb_wrapper_still_publishes_the_honest_rows(self):
        # Pre-fix: the RuntimeError escaped the (TypeError, ValueError)
        # tuple, raised out of _load and discarded the last-good snapshot —
        # every brew row vanished where keep-last-good should have answered.
        self._prime_disk()
        rows = self._listing(
            _TupleIterBomb((0, '[{"name":"fresh","status":"started"}]', ""))
        )
        self.assertEqual(rows, ["fresh"])

    def test_list_wrapper_iter_bomb_also_yields_the_honest_rows(self):
        self._prime_disk()
        rows = self._listing(
            _ListIterBomb([0, '[{"name":"fresh","status":"started"}]', ""])
        )
        self.assertEqual(rows, ["fresh"])

    def test_tuple_liar_answer_keeps_the_last_good_snapshot(self):
        # No real sequence storage: junk reads as a failed spawn, so the
        # keep-last-good tail answers instead of publishing emptiness.
        self._prime_disk()
        self.assertEqual(self._listing(_liar(tuple)), ["redis"])

    def test_wrong_arity_and_scalar_answers_keep_the_last_good_snapshot(self):
        self._prime_disk()
        self.assertEqual(self._listing((0, "[]")), ["redis"])
        self.assertEqual(self._listing("junk"), ["redis"])

    def test_raising_sh_keeps_the_last_good_snapshot(self):
        self._prime_disk()
        with (
            mock.patch.object(brew_svc, "_brew_present", return_value=True),
            mock.patch.object(brew_cache, "_brew_busy", return_value=False),
            mock.patch.object(
                brew_cache, "sh", side_effect=RuntimeError("spawn bomb")
            ),
            mock.patch.object(brew_svc, "sh", return_value=(1, "", "")),
        ):
            resp = client().get("/api/brew/services")
        _assert_clean(self, resp)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(
            [r["id"] for r in resp.json()["services"]], ["redis"]
        )

    def test_sh_answer_junk_is_never_the_vanished_sentinel(self):
        for junk in (_liar(tuple), "junk", (0, ""), 0, None):
            rc, out, err = brew_cache._sh_answer(junk)
            self.assertIsNone(rc)
            self.assertIsNone(brew_cache._plain_rc(rc))
            self.assertNotEqual(brew_cache._plain_rc(rc), -1)
        # An honest answer inside a wrapper survives intact.
        self.assertEqual(
            brew_cache._sh_answer(_TupleIterBomb((0, "out", "err"))),
            (0, "out", "err"),
        )


class BrewListFallbackAnswerShapeTests(unittest.TestCase):
    """``list_services``' text fallback swallowed the wrapper's raise."""

    def _rows(self, spawn):
        with (
            mock.patch.object(brew_svc, "_brew_present", return_value=True),
            mock.patch.object(brew_svc, "brew_services_list", return_value=[]),
            mock.patch.object(brew_svc, "sh", return_value=spawn),
        ):
            resp = client().get("/api/brew/services")
        _assert_clean(self, resp)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        return sorted(r["id"] for r in resp.json()["services"])

    def test_iter_bomb_wrapper_still_parses_the_honest_listing(self):
        # Pre-fix: the raise landed in the except above and the honest
        # listing inside the wrapper was thrown away as "no rows".
        rows = self._rows(
            _TupleIterBomb((0, "Name Status User\nredis started me\n", ""))
        )
        self.assertEqual(rows, ["redis"])

    def test_tuple_liar_and_wrong_arity_read_as_a_failed_spawn(self):
        self.assertEqual(self._rows(_liar(tuple)), [])
        self.assertEqual(self._rows((0, "Name Status\nredis started\n")), [])

    def test_sh_answer_junk_is_never_the_vanished_sentinel(self):
        for junk in (_liar(tuple), "junk", (0, ""), None):
            rc, _out, _err = brew_svc._sh_answer(junk)
            self.assertIsNone(brew_svc._plain_rc(rc))
        self.assertEqual(
            brew_svc._sh_answer(_TupleIterBomb((0, "out", "err"))),
            (0, "out", "err"),
        )


class BrewActionAnswerShapeTests(unittest.TestCase):
    """``service_action``'s ``rc, msg`` unpack ran inside the spawn try."""

    def _post(self, answer, present=True):
        with (
            mock.patch.object(brew_svc, "_brew_present", return_value=present),
            mock.patch.object(brew_svc, "run_capped", return_value=answer),
        ):
            resp = client().post(
                "/api/brew/services/redis/action", json={"action": "restart"}
            )
        _assert_clean(self, resp)
        return resp

    def test_iter_bomb_wrapper_still_reports_the_honest_exit(self):
        # Pre-fix: {"ok": false, "message": "iter bomb"} — a successful
        # restart reported as a failure carrying the bomb's own text.
        resp = self._post(_TupleIterBomb((0, "")))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        self.assertTrue(body["ok"])
        self.assertEqual(body["message"], "exit 0")

    def test_list_wrapper_iter_bomb_reports_the_honest_message(self):
        resp = self._post(_ListIterBomb([0, "already started"]))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        self.assertTrue(body["ok"])
        self.assertEqual(body["message"], "already started")

    def test_junk_shapes_answer_exit_unknown_not_a_python_unpack_message(self):
        # Pre-fix the SPA was handed "cannot unpack non-iterable Liar
        # object" / "too many values to unpack (expected 2)" as the
        # action's own failure text.
        for junk in (_liar(tuple), (0, "", "extra"), 0, None):
            resp = self._post(junk)
            self.assertEqual(resp.status_code, 200, resp.text[:300])
            body = resp.json()
            self.assertFalse(body["ok"])
            self.assertEqual(body["message"], "exit unknown")

    def test_junk_shape_cannot_forge_the_vanished_brew_503(self):
        # The coded 503 needs the (-1, "not found") sentinel *and* a fresh
        # disk confirm; a junk shape carries no exit status at all, so a
        # brew that vanished between the check and the spawn still reports
        # its own answer rather than a forged classification.
        with (
            mock.patch.object(
                brew_svc, "_brew_present", side_effect=[True, False]
            ),
            mock.patch.object(brew_svc, "run_capped", return_value=_liar(tuple)),
        ):
            resp = client().post(
                "/api/brew/services/redis/action", json={"action": "restart"}
            )
        _assert_clean(self, resp)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(resp.json()["message"], "exit unknown")

    def test_spawn_pair_junk_never_answers_the_minus_one_sentinel(self):
        for junk in (_liar(tuple), "junk", (0, "", ""), 0, None):
            rc, _msg = brew_svc._spawn_pair(junk)
            self.assertIsNone(rc)
            self.assertNotEqual(brew_svc._plain_rc(rc), -1)
        self.assertEqual(
            brew_svc._spawn_pair(_TupleIterBomb((0, "done"))), (0, "done")
        )

    def test_real_vanished_sentinel_still_maps_to_the_coded_503(self):
        # Pin (the vms/brew/rsync rule): the sentinel plus a confirmed
        # absent binary is the one shape that becomes brew.not_found.
        with (
            mock.patch.object(
                brew_svc, "_brew_present", side_effect=[True, False]
            ),
            mock.patch.object(
                brew_svc, "run_capped", return_value=(-1, "not found")
            ),
        ):
            resp = client().post(
                "/api/brew/services/redis/action", json={"action": "restart"}
            )
        _assert_clean(self, resp)
        self.assertEqual(resp.status_code, 503, resp.text[:300])
        self.assertEqual(resp.json()["detail"]["code"], "brew.not_found")

    def test_sentinel_with_brew_still_on_disk_keeps_its_raw_result(self):
        # Pin: a signal-killed brew is also rc -1, so a brew that is still
        # present must not answer "Homebrew is not installed".
        resp = self._post((-1, "not found"), present=True)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertFalse(resp.json()["ok"])


# --------------------------------------------------------------------------
# _brew_busy: the pgrep returncode compare runs outside the spawn try
# --------------------------------------------------------------------------
class BrewBusyReturncodeTests(unittest.TestCase):
    """POST /api/tools/updates/brew's only Homebrew-lock probe."""

    def _upgrade(self, proc):
        with (
            mock.patch.object(brew_cache.subprocess, "run", return_value=proc),
            mock.patch.object(tools_svc.Path, "is_file", lambda self: True),
        ):
            resp = client().post(
                "/api/tools/updates/brew", json={"confirm": True}
            )
        _assert_clean(self, resp)
        return resp

    def test_rc_eq_bomb_returncode_does_not_500_the_upgrade(self):
        # Pre-fix: the bare ``proc.returncode == 0`` compare dispatched
        # into the bomb outside the spawn try — a raw 500.
        proc = mock.Mock()
        proc.returncode = _EqBombRc(0)
        proc.stdout = b""
        with mock.patch("hub.jobs.start_job", lambda spec: None):
            resp = self._upgrade(proc)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(resp.json()["job_id"], "brew-upgrade")

    def test_raising_returncode_attribute_reads_as_not_busy(self):
        class RaisingRC:
            stdout = b""

            @property
            def returncode(self):
                raise RuntimeError("attr bomb")

        # An unreadable lock probe reads as "not busy" — brew's own flock
        # arbitrates from there — instead of 500ing the handler.
        with mock.patch("hub.jobs.start_job", lambda spec: None):
            resp = self._upgrade(RaisingRC())
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(resp.json()["job_id"], "brew-upgrade")

    def test_an_absent_homebrew_still_answers_the_coded_409(self):
        # Pin: the laundered "not busy" read must not turn a missing
        # Homebrew into a job that cannot run.
        proc = mock.Mock()
        proc.returncode = 1
        proc.stdout = b""
        with mock.patch.object(brew_cache.subprocess, "run", return_value=proc):
            resp = client().post(
                "/api/tools/updates/brew", json={"confirm": True}
            )
        _assert_clean(self, resp)
        self.assertEqual(resp.status_code, 409, resp.text[:300])
        self.assertEqual(resp.json()["detail"]["code"], "tools.brew_busy")

    def test_rc_bomb_keeps_the_listing_rows(self):
        proc = mock.Mock()
        proc.returncode = _EqBombRc(0)
        proc.stdout = b""
        with tempfile.TemporaryDirectory() as tmp:
            disk = Path(tmp) / "brew-services.cache.json"
            with mock.patch.object(brew_cache, "_DISK", disk):
                brew_cache.invalidate_brew_services()
                try:
                    with (
                        mock.patch.object(
                            brew_svc, "_brew_present", return_value=True
                        ),
                        mock.patch.object(
                            brew_cache.subprocess, "run", return_value=proc
                        ),
                        mock.patch.object(
                            brew_cache, "sh",
                            return_value=(
                                0, '[{"name":"a","status":"started"}]', ""
                            ),
                        ),
                        mock.patch.object(
                            brew_svc, "sh", return_value=(1, "", "")
                        ),
                    ):
                        resp = client().get("/api/brew/services")
                    _assert_clean(self, resp)
                    self.assertEqual(resp.status_code, 200, resp.text[:300])
                    self.assertEqual(
                        [r["id"] for r in resp.json()["services"]], ["a"]
                    )
                finally:
                    brew_cache.invalidate_brew_services()

    def test_bombing_subprocess_run_reads_as_not_busy(self):
        with mock.patch.object(
            brew_cache.subprocess, "run", side_effect=RuntimeError("run bomb")
        ):
            self.assertFalse(brew_cache._brew_busy())

    def test_honest_pgrep_hit_still_reads_as_busy(self):
        # Pin: the laundering must not blind the lock probe.
        proc = mock.Mock()
        proc.returncode = 0
        proc.stdout = b"4321\n"
        with mock.patch.object(
            brew_cache.subprocess, "run", return_value=proc
        ):
            self.assertTrue(brew_cache._brew_busy())


# --------------------------------------------------------------------------
# The Homebrew update card's snapshot cache
# --------------------------------------------------------------------------
class _UpdatesCacheSandbox(unittest.TestCase):
    def setUp(self):
        self._saved = dict(tools_svc._updates_cache)
        self.addCleanup(self._restore)
        tools_svc._updates_cache.clear()
        tools_svc._updates_cache.update(t=0.0, v=None)
        warmer = mock.patch.object(
            tools_svc, "start_updates_warmer", lambda *a, **k: None
        )
        warmer.start()
        self.addCleanup(warmer.stop)

    def _restore(self):
        tools_svc._updates_cache.clear()
        tools_svc._updates_cache.update(self._saved)

    def _plant(self, target: str):
        # Shadow first, then the sibling slot: see _BrewCacheSandbox._plant.
        tools_svc._updates_cache.clear()
        tools_svc._updates_cache[_shadow_key(target)] = 1
        for slot, value in (("t", 0.0), ("v", None)):
            if slot != target:
                tools_svc._updates_cache[slot] = value


class UpdatesCacheShadowKeyTests(_UpdatesCacheSandbox):
    """GET /api/tools/updates carries the Homebrew card."""

    def _get(self, query=""):
        with (
            mock.patch.object(tools_svc, "_brew_busy", return_value=False),
            mock.patch.object(
                tools_svc, "github_update_status",
                lambda fetch=True, force=False: {"ok": False},
            ),
            mock.patch.object(tools_svc, "sh", return_value=(0, "", "")),
        ):
            resp = client().get("/api/tools/updates" + query)
        _assert_clean(self, resp)
        return resp

    def test_shadowed_v_slot_does_not_500_the_card(self):
        # Pre-fix: _updates_fresh's bare ``_updates_cache["v"]`` subscript
        # detonated the C-level lookup on every request.
        self._plant("v")
        resp = self._get()
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertIn("brew", resp.json())

    def test_shadowed_t_slot_does_not_500_the_card(self):
        self._plant("t")
        resp = self._get()
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertIn("brew", resp.json())

    def test_shadowed_slot_survives_the_final_cache_write(self):
        # Pre-fix: the probe succeeded and then the final
        # ``_updates_cache.update`` insert compare detonated — a 500 at the
        # very end of a run that had already paid for brew outdated.
        self._plant("v")
        resp = self._get("?force=true")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertIn("brew", resp.json())
        # clear+rewrite evicted the bomb, so the TTL hit lands next time.
        self.assertEqual(
            sorted({type(k).__name__ for k in tools_svc._updates_cache}),
            ["str"],
        )
        self.assertIsNotNone(tools_svc._updates_fresh())

    def test_shadowed_brew_key_in_the_snapshot_keeps_the_previous_card(self):
        # Pre-fix: _brew_outdated's bound ``hit.get("brew")`` raised out of
        # the busy/cooldown fallback and the card silently lost its
        # previous answer to the pool's generic empty result.
        previous = {"ok": True, "outdated": ["pkg 1.0"], "count": 1, "raw": ""}
        snapshot = {"github": {"ok": False}, "macos": {}, "brew": previous}
        snapshot[_shadow_key("junk")] = 1
        tools_svc._updates_cache.clear()
        tools_svc._updates_cache.update(t=time.time(), v=snapshot)
        with (
            mock.patch.object(tools_svc, "_brew_busy", return_value=True),
            mock.patch.object(
                tools_svc, "github_update_status",
                lambda fetch=True, force=False: {"ok": False},
            ),
            mock.patch.object(tools_svc, "sh", return_value=(0, "", "")),
            mock.patch.object(tools_svc.Path, "exists", lambda self: True),
        ):
            resp = client().get("/api/tools/updates?force=true")
        _assert_clean(self, resp)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(resp.json()["brew"]["outdated"], ["pkg 1.0"])

    def test_unreadable_timestamp_reads_as_expired(self):
        tools_svc._updates_cache.clear()
        tools_svc._updates_cache.update(t="junk", v={"brew": {}})
        self.assertIsNone(tools_svc._updates_fresh())
        tools_svc._updates_cache.update(t=float("inf"), v={"brew": {}})
        self.assertIsNone(tools_svc._updates_fresh())

    def test_honest_snapshot_still_serves_a_ttl_hit(self):
        # Pin: the laundering must not turn every request into a re-probe.
        snapshot = {"brew": {"ok": True}, "macos": {}, "github": {}}
        tools_svc._updates_cache.clear()
        tools_svc._updates_cache.update(t=time.time(), v=snapshot)
        self.assertIs(tools_svc._updates_fresh(), snapshot)

    def test_mapping_get_degrades_only_the_shadowed_field(self):
        d = {"keep": 2}
        d[_shadow_key("gone")] = 1
        self.assertIsNone(tools_svc._mapping_get(d, "gone"))
        self.assertEqual(tools_svc._mapping_get(d, "keep"), 2)
        self.assertEqual(tools_svc._mapping_get(_liar(dict), "k", "d"), "d")


# --------------------------------------------------------------------------
# Stays-immune pins (probed and found sealed; pinned so they stay)
# --------------------------------------------------------------------------
class BrewStaysImmunePins(_BrewCacheSandbox):
    def test_fifo_snapshot_path_answers_empty_rows_not_a_500(self):
        # read_text_capped opens O_NONBLOCK and rejects a non-regular file
        # with EINVAL, so a leftover FIFO cannot park the request thread.
        self.disk.unlink(missing_ok=True)
        os.mkfifo(self.disk)
        rows = self._listing((1, "", "boom"))
        self.assertEqual(rows, [])

    def test_over_cap_exit_code_in_brew_json_drops_only_that_field(self):
        huge = "1" * 5000
        rows_json = '[{"name":"a","status":"started","exit_code":' + huge + "}]"
        with (
            mock.patch.object(brew_svc, "_brew_present", return_value=True),
            mock.patch.object(brew_cache, "_brew_busy", return_value=False),
            mock.patch.object(brew_cache, "sh", return_value=(0, rows_json, "")),
            mock.patch.object(brew_svc, "sh", return_value=(1, "", "")),
        ):
            resp = client().get("/api/brew/services")
        _assert_clean(self, resp)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        row = resp.json()["services"][0]
        self.assertEqual(row["id"], "a")
        self.assertIsNone(row["exit_code"])

    def test_already_int_over_cap_exit_code_drops_only_that_field(self):
        over_cap = int("1" * 4000) * 10 ** 1200
        with (
            mock.patch.object(brew_svc, "_brew_present", return_value=True),
            mock.patch.object(
                brew_svc, "brew_services_list",
                return_value=[
                    {"name": "a", "status": "started", "exit_code": over_cap}
                ],
            ),
            mock.patch.object(brew_svc, "sh", return_value=(1, "", "")),
        ):
            resp = client().get("/api/brew/services")
        _assert_clean(self, resp)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        row = resp.json()["services"][0]
        self.assertEqual(row["id"], "a")
        self.assertIsNone(row["exit_code"])

    def test_dict_subclass_bool_bomb_row_keeps_its_real_pairs(self):
        class BoolBomb(dict):
            def __bool__(self):
                raise RuntimeError("bool bomb")

        with (
            mock.patch.object(brew_svc, "_brew_present", return_value=True),
            mock.patch.object(
                brew_svc, "brew_services_list",
                return_value=[BoolBomb({"name": "redis", "status": "started"})],
            ),
            mock.patch.object(brew_svc, "sh", return_value=(1, "", "")),
        ):
            resp = client().get("/api/brew/services")
        _assert_clean(self, resp)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(resp.json()["services"][0]["status"], "started")

    def test_surrogate_brew_path_answers_empty_rows_and_the_coded_503(self):
        bad = "/opt/homebrew/bin/br\ud800ew"
        with mock.patch.object(brew_svc, "BREW", bad):
            listing = client().get("/api/brew/services")
            action = client().post(
                "/api/brew/services/redis/action", json={"action": "restart"}
            )
        _assert_clean(self, listing)
        _assert_clean(self, action)
        self.assertEqual(listing.status_code, 200, listing.text[:300])
        self.assertEqual(listing.json()["services"], [])
        self.assertEqual(action.status_code, 503, action.text[:300])
        self.assertEqual(action.json()["detail"]["code"], "brew.not_found")


class BrewConflictPolicyPins(unittest.TestCase):
    """brew6..10 union guards: pinned, never weakened."""

    def test_isinstance_stays_fail_closed(self):
        class ClassBomb:
            @property
            def __class__(self):
                raise RuntimeError("class bomb")

        for module in (brew_svc, brew_cache):
            self.assertFalse(module._isinstance(ClassBomb(), dict))
            self.assertFalse(module._isinstance(ClassBomb(), (str, bytes)))

    def test_json_safe_needs_type_is_bool(self):
        # brew10: a bool-liar must be laundered, not returned raw.
        for module in (brew_svc, brew_cache):
            self.assertIs(module._json_safe(True), True)
            self.assertIs(module._json_safe(_liar(bool)), True)

    def test_json_safe_still_drops_nan_inf_and_over_cap_ints(self):
        for module in (brew_svc, brew_cache):
            self.assertIsNone(module._json_safe(float("nan")))
            self.assertIsNone(module._json_safe(float("inf")))
            self.assertIsNone(
                module._json_safe(int("1" * 4000) * 10 ** 1200)
            )

    def test_plain_rc_absorbs_the_eq_bomb_and_junk(self):
        for module in (brew_svc, brew_cache):
            self.assertEqual(module._plain_rc(_EqBombRc(0)), 0)
            self.assertIsNone(module._plain_rc("junk"))
            self.assertIsNone(module._plain_rc(_liar(bool)) or None)

    def test_as_text_launders_liars_and_bombs(self):
        for module in (brew_svc, brew_cache):
            self.assertIsInstance(module._as_text(_liar(bytes)), str)
            self.assertEqual(module._as_text(None), "")
            self.assertEqual(module._as_text(b"ok"), "ok")

    def test_capped_json_int_drops_only_the_over_cap_number(self):
        self.assertEqual(brew_cache._capped_json_int("12"), 12)
        self.assertIsNone(brew_cache._capped_json_int("1" * 5000))

    def test_guarded_decode_survives_a_subclass_bomb(self):
        class DecodeBomb(bytes):
            def decode(self, *a, **k):
                raise RuntimeError("decode bomb")

        for module in (brew_svc, brew_cache):
            self.assertEqual(module._as_text(DecodeBomb(b"ok")), "ok")

    def test_rc_junk_is_never_the_vanished_sentinel(self):
        # The docker11/health11 rule at brew rank: junk keeps the failure
        # branch and can never forge the coded 503.
        for module in (brew_svc, brew_cache):
            self.assertNotEqual(module._plain_rc("junk"), -1)
            self.assertNotEqual(module._plain_rc(None), -1)

    def test_version_is_unchanged(self):
        from hub import __version__

        self.assertEqual(__version__, "3.9.3")


if __name__ == "__main__":
    unittest.main()
