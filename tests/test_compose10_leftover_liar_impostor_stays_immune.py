"""Compose leftover sweep #10: the files13/json9 liar zoo stays immune.

A tenth adversarial pass over the Compose/stacks surfaces (GET /api/stacks,
GET/PUT /api/compose/{id}, POST /api/compose/{id}/validate,
POST /api/stacks/{id}/run, GET /api/stacks/jobs/{id}) through the real
``create_app`` wiring with ``TestClient(raise_server_exceptions=False)``
hunted the class files13/json9 found alive next door after their own
``_isinst`` sweeps:

* **lying ``__class__`` impostors** — objects whose ``__class__`` property
  *answers* a real type (str/bytes/int/float/bool/dict/list) so they pass
  the guarded ``_isinst``/``_isa`` gate, then blow the bound operation that
  follows unless it is unbound-or-guarded (the modules8 rule);
* **bool-liars** — the impostor claiming ``bool``, which no ``type(x) is
  bool`` exact check can be fooled by but an ``_isa(x, bool)`` rank gate
  admits;
* **hash-shadowing keys** — a key whose ``__hash__`` collides with the
  literal a reader fetches and whose ``__eq__`` raises during the probe
  itself, one seam *earlier* than any value gate (``dict.get`` on a
  laundered copy is still a hash-table probe).

The hunt found **no live 500**: compose7–9 left every follow-up behind an
``_isa`` gate unbound (``str.__str__`` / ``int.__index__`` /
``float.__float__`` / ``bytes.decode`` via the base type / ``dict()`` /
``list()`` C-level copies) and inside a try, ``_plain_job`` drops non-str
row keys and launders str-subclass ones before any ``row.get``, and the two
root probes (``dict.get(cfg-root, "stacks")``, ``_cjobs.get(job_id)``) each
sit in their own try.  The on-disk update-status journal that
GET /api/stacks reads through ``list_containers`` passes ``_jsonable``,
whose dict branch re-keys through ``_utf8_text`` — so a shadow key cannot
survive the only funnel that feeds ``.get("_checked_at")`` /
``.get(image)``.

This module pins all of that so a refactor cannot quietly reopen the class:
unit pins on the laundering funnels, then HTTP pins driving the liar zoo
through the two stores the compose9 convention treats as poisonable — the
``cfg()`` snapshot's ``stacks:`` rows and the ``_cjobs`` job store.
"""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from hub import compose_svc, containers_svc  # noqa: E402
from hub.containers_svc import (  # noqa: E402
    _field_text, _isinst, _job_field, _job_scalar, _log_text, _plain_job,
    _plain_text, _str_list, _truthy,
)

VALID_COMPOSE = "services:\n  web:\n    image: nginx:alpine\n"


# ── The liar zoo ─────────────────────────────────────────────────────────────
def _liar(claim):
    """An object whose ``__class__`` property *lies* about its type.

    It passes ``_isinst(x, claim)`` but has none of the claimed type's
    C-level layout, so any unbound base call on it raises TypeError — the
    follow-up must be guarded or the liar 500s one line past the gate.
    """
    return type("Liar", (object,), {"__class__": property(lambda self: claim)})()


class RaisingIterListLiar:
    """Claims list; its real ``__iter__`` raises when the launderer runs."""

    @property
    def __class__(self):  # type: ignore[override]
        return list

    def __iter__(self):
        raise RuntimeError("liar iter bomb")


class RealIterListLiar:
    """Claims list and really iterates: the items (one a liar) must launder."""

    @property
    def __class__(self):  # type: ignore[override]
        return list

    def __iter__(self):
        return iter(["c1", _liar(str)])


class ItemsBombDictLiar:
    """Claims dict; ``dict(x)`` reaches its raising ``keys`` and must drop."""

    @property
    def __class__(self):  # type: ignore[override]
        return dict

    def keys(self):
        raise RuntimeError("liar keys bomb")

    def items(self):
        raise RuntimeError("liar items bomb")


class _EqBombKey:
    """A non-str key whose ``__hash__`` collides with the fetched literal and
    whose ``__eq__`` raises — the files13 section-key shape.  The probe
    itself detonates unless the read is guarded or the key was dropped."""

    def __init__(self, target: str):
        self._h = hash(target)

    def __eq__(self, other):
        raise RuntimeError("shadow key eq bomb")

    def __hash__(self):
        return self._h


class _StrEqBombKey(str):
    """The str-subclass twin: still demotes the row off CPython's exact-str
    fast path, so the raising ``__eq__`` runs during ``row.get``."""

    def __eq__(self, other):  # noqa: D401
        raise RuntimeError("shadow key eq bomb (str subclass)")

    def __ne__(self, other):
        raise RuntimeError("shadow key ne bomb (str subclass)")

    def __hash__(self):
        return str.__hash__(str.__str__(self))


def _shadowed(base: dict, target: str, bomb_cls) -> dict:
    """*base* with *target*'s entry replaced by a hash-shadowing bomb key."""
    out = {k: v for k, v in base.items() if k != target}
    out[bomb_cls(target)] = "x"
    return out


# ── Unit pins: the laundering funnels absorb every liar ──────────────────────
class IsInstLiarUnitTests(unittest.TestCase):
    def test_liar_reports_its_claim(self):
        # The modules8 rule: a lying __class__ is a claim, not an error.
        self.assertTrue(_isinst(_liar(str), str))
        self.assertTrue(_isinst(_liar(dict), dict))
        self.assertTrue(_isinst(_liar(bool), bool))

    def test_liar_does_not_match_other_types(self):
        self.assertFalse(_isinst(_liar(str), int))
        self.assertFalse(_isinst(_liar(bool), (bytes, bytearray)))


class FieldTextLiarUnitTests(unittest.TestCase):
    def test_str_liar_drops_to_fallback(self):
        # Passes the str gate; the unbound str.__str__ copy TypeErrors.
        self.assertEqual(_field_text(_liar(str), "fb"), "fb")

    def test_bytes_liar_drops_to_fallback(self):
        self.assertEqual(_field_text(_liar(bytes), "fb"), "fb")

    def test_int_liar_drops_to_fallback(self):
        self.assertEqual(_field_text(_liar(int), "fb"), "fb")

    def test_float_liar_drops_to_fallback(self):
        self.assertEqual(_field_text(_liar(float), "fb"), "fb")

    def test_bool_liar_drops_to_fallback(self):
        # The bool arm drops the value outright: junk is not a flag.
        self.assertEqual(_field_text(_liar(bool), "fb"), "fb")

    def test_dict_liar_drops_to_fallback(self):
        self.assertEqual(_field_text(_liar(dict), "fb"), "fb")


class RowAndListLiarUnitTests(unittest.TestCase):
    def test_plain_job_items_bomb_dict_liar_drops(self):
        self.assertIsNone(_plain_job(ItemsBombDictLiar()))

    def test_plain_job_inert_dict_liar_drops(self):
        # Claims dict, has no mapping protocol at all: dict() TypeErrors.
        self.assertIsNone(_plain_job(_liar(dict)))

    def test_plain_job_drops_non_str_shadow_keys(self):
        row = _shadowed({"id": "a", "path": "/x"}, "path", _EqBombKey)
        out = _plain_job(row)
        self.assertEqual(out, {"id": "a"})

    def test_plain_job_launders_str_subclass_shadow_keys(self):
        row = _shadowed({"id": "a", "path": "/x"}, "id", _StrEqBombKey)
        out = _plain_job(row)
        self.assertEqual(out.get("id"), "x")
        self.assertTrue(all(type(k) is str for k in out))

    def test_str_list_raising_iter_liar_returns_empty(self):
        self.assertEqual(_str_list(RaisingIterListLiar()), [])

    def test_str_list_real_iter_liar_launders_items(self):
        self.assertEqual(_str_list(RealIterListLiar()), ["c1"])

    def test_plain_text_str_liar_drops(self):
        self.assertIsNone(_plain_text(_liar(str)))

    def test_truthy_liar_is_just_truthy(self):
        # bool() reads real slots, not __class__: an inert liar is True and
        # that is fine — _truthy only exists to absorb raising __bool__.
        self.assertTrue(_truthy(_liar(bool)))


class JobScalarLiarUnitTests(unittest.TestCase):
    def test_job_scalar_liars_degrade_never_raise(self):
        for claim in (str, bytes, int, float, bool, dict, list):
            out = _job_scalar(_liar(claim))
            # Whatever survives must be JSON-encodable, not a raise.
            json.dumps(out)

    def test_log_text_liars_degrade_to_text(self):
        for claim in (str, bytes, int, bool):
            out = _log_text(_liar(claim))
            self.assertIsInstance(out, str)

    def test_job_field_str_liar_degrades(self):
        # Passes the str gate; _as_text renders the repr (an exact str), so
        # the field degrades to JSON-safe junk text rather than raising.
        out = _job_field(_liar(str))
        self.assertIsInstance(out, str)
        json.dumps(out)


# ── HTTP sandbox: real app wiring + a real stack on disk ─────────────────────
class _Compose10Sandbox(unittest.TestCase):
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
        self.home = Path(tempfile.mkdtemp(prefix="compose10-8a44-"))
        self.addCleanup(lambda: shutil.rmtree(self.home, ignore_errors=True))
        self.stack_dir = self.home / "Services" / "app-8a44"
        self.stack_dir.mkdir(parents=True)
        (self.stack_dir / "docker-compose.yml").write_text(VALID_COMPOSE)
        p = mock.patch.object(compose_svc, "user_home", return_value=self.home)
        p.start()
        self.addCleanup(p.stop)
        cp = mock.patch.object(containers_svc, "user_home", return_value=self.home)
        cp.start()
        self.addCleanup(cp.stop)
        self._saved_jobs = dict(containers_svc._cjobs)
        containers_svc._cjobs.clear()
        self.addCleanup(self._restore_jobs)

    def _restore_jobs(self):
        containers_svc._cjobs.clear()
        containers_svc._cjobs.update(self._saved_jobs)

    def _with_cfg(self, value):
        return mock.patch.object(containers_svc, "cfg", return_value=value)

    def _row(self, extra):
        row = {"id": "app-8a44", "path": str(self.stack_dir)}
        row.update(extra)
        return row

    def _assert_renders(self, resp):
        self.assertLess(resp.status_code, 500, resp.text)
        self.assertNotIn("\ud800", json.dumps(resp.json()))

    def _sweep(self, sid: str = "app-8a44"):
        self._assert_renders(self.client.get("/api/stacks"))
        self._assert_renders(self.client.get(f"/api/compose/{sid}"))
        self._assert_renders(self.client.post(f"/api/compose/{sid}/validate"))
        self._assert_renders(self.client.put(
            f"/api/compose/{sid}",
            content=json.dumps({"content": VALID_COMPOSE + "# e\n", "check": False}),
            headers={"Content-Type": "application/json"},
        ))
        self._assert_renders(self.client.post(
            f"/api/stacks/{sid}/run", json={"action": "down"},
        ))
        self._assert_renders(self.client.get("/api/stacks/jobs/jb"))
        self._assert_renders(self.client.get(f"/api/stacks/jobs/{sid}"))


class ConfigRowLiarHttpTests(_Compose10Sandbox):
    """Liar impostors riding ``stacks:`` rows degrade; the routes render."""

    def test_stacks_value_raising_iter_list_liar(self):
        with self._with_cfg({"stacks": RaisingIterListLiar()}):
            self._sweep()

    def test_stacks_value_real_iter_list_liar_of_liar_rows(self):
        with self._with_cfg({"stacks": RealIterListLiar()}):
            self._sweep()

    def test_row_items_bomb_dict_liar(self):
        with self._with_cfg({"stacks": [ItemsBombDictLiar(), self._row({})]}):
            self._sweep()

    def test_row_inert_dict_liar(self):
        with self._with_cfg({"stacks": [_liar(dict), self._row({})]}):
            self._sweep()

    def test_liar_fields_never_500(self):
        for field in ("id", "name", "path", "compose_file", "containers"):
            for claim in (str, bytes, int, float, bool, dict, list):
                with self.subTest(field=field, claim=claim.__name__):
                    with self._with_cfg({"stacks": [self._row({field: _liar(claim)})]}):
                        self._assert_renders(self.client.get("/api/stacks"))

    def test_liar_id_row_falls_back_to_directory_name(self):
        # The str-liar id passes the gate, TypeErrors the unbound copy, and
        # the row keeps listing under its directory name — never a 500.
        with self._with_cfg({"stacks": [self._row({"id": _liar(str)})]}):
            resp = self.client.get("/api/stacks")
            self.assertLess(resp.status_code, 500, resp.text)
            ids = [s.get("id") for s in resp.json().get("stacks", [])]
            self.assertIn("app-8a44", ids)

    def test_containers_item_liars_drop_not_raise(self):
        row = self._row({"containers": [_liar(str), _liar(bool), _liar(bytes), "c1"]})
        with self._with_cfg({"stacks": [row]}):
            self._sweep()


class ShadowKeyHttpTests(_Compose10Sandbox):
    """Hash-shadowing keys (the files13 section-key shape) stay sealed."""

    def test_cfg_root_shadow_key_over_stacks(self):
        # The guarded ``dict.get(data, "stacks")`` probe absorbs the bomb;
        # the listing degrades to the on-disk scan and still finds the stack.
        for bomb_cls in (_EqBombKey, _StrEqBombKey):
            with self.subTest(bomb=bomb_cls.__name__):
                with self._with_cfg({bomb_cls("stacks"): [self._row({})]}):
                    resp = self.client.get("/api/stacks")
                    self.assertLess(resp.status_code, 500, resp.text)
                    ids = [s.get("id") for s in resp.json().get("stacks", [])]
                    self.assertIn("app-8a44", ids)

    def test_row_shadow_keys_never_500(self):
        for target in ("id", "path", "compose_file", "name", "containers"):
            for bomb_cls in (_EqBombKey, _StrEqBombKey):
                with self.subTest(target=target, bomb=bomb_cls.__name__):
                    row = _shadowed(self._row({}), target, bomb_cls)
                    with self._with_cfg({"stacks": [row]}):
                        self._sweep()


class JobStoreLiarHttpTests(_Compose10Sandbox):
    """Liar impostors and shadow keys in ``_cjobs`` never 500 the job routes."""

    def _drive(self):
        with self._with_cfg({"stacks": [self._row({})]}):
            self._assert_renders(self.client.get("/api/stacks"))
            self._assert_renders(self.client.get("/api/stacks/jobs/jb"))
            self._assert_renders(self.client.get("/api/stacks/jobs/app-8a44"))
            self._assert_renders(self.client.post(
                "/api/stacks/app-8a44/run", json={"action": "down"},
            ))

    def _base_job(self):
        return {"stack_id": "app-8a44", "running": False, "rc": 0, "log": []}

    def test_liar_job_fields_never_500(self):
        shapes = (
            ("str-liar", lambda: _liar(str)),
            ("bytes-liar", lambda: _liar(bytes)),
            ("int-liar", lambda: _liar(int)),
            ("bool-liar", lambda: _liar(bool)),
            ("raising-iter-list-liar", RaisingIterListLiar),
            ("items-bomb-dict-liar", ItemsBombDictLiar),
        )
        for field in ("stack_id", "action", "code", "rc", "started",
                      "finished", "running", "log"):
            for name, mk in shapes:
                with self.subTest(field=field, shape=name):
                    containers_svc._cjobs.clear()
                    job = self._base_job()
                    job[field] = mk()
                    containers_svc._cjobs["jb"] = job
                    self._drive()

    def test_liar_log_items_degrade(self):
        containers_svc._cjobs["jb"] = dict(
            self._base_job(),
            log=["ok", _liar(str), _liar(bytes), _liar(bool), "done"],
        )
        self._drive()

    def test_job_row_dict_liars_drop(self):
        for mk in (ItemsBombDictLiar, lambda: _liar(dict)):
            with self.subTest(shape=type(mk()).__name__):
                containers_svc._cjobs.clear()
                containers_svc._cjobs["jb"] = mk()
                self._drive()

    def test_job_row_shadow_keys_never_500(self):
        for target in ("running", "rc", "stack_id", "log"):
            for bomb_cls in (_EqBombKey, _StrEqBombKey):
                with self.subTest(target=target, bomb=bomb_cls.__name__):
                    containers_svc._cjobs.clear()
                    containers_svc._cjobs["jb"] = _shadowed(
                        self._base_job(), target, bomb_cls,
                    )
                    self._drive()

    def test_job_store_shadow_key_over_queried_id(self):
        # The ``_cjobs.get(job_id)`` probe sits in its own try; the fallback
        # scan re-finds the row through _plain_text.
        for bomb_cls in (_EqBombKey, _StrEqBombKey):
            with self.subTest(bomb=bomb_cls.__name__):
                containers_svc._cjobs.clear()
                containers_svc._cjobs[bomb_cls("jb")] = self._base_job()
                self._drive()

    def test_job_store_shadow_key_over_stack_id(self):
        # The stack-id fallback and latest_stack_jobs never look rows up by
        # key, so a shadow over the *stack* id cannot detonate either.
        for bomb_cls in (_EqBombKey, _StrEqBombKey):
            with self.subTest(bomb=bomb_cls.__name__):
                containers_svc._cjobs.clear()
                containers_svc._cjobs[bomb_cls("app-8a44")] = self._base_job()
                self._drive()


class UpdateStatusFunnelPins(unittest.TestCase):
    """The one funnel feeding ``.get`` reads of the update journal re-keys.

    ``list_containers`` probes ``.get("_checked_at")`` and the enrichment
    ``.get(image)`` on whatever ``_load_update_status`` returns; both stay
    hash-table probes, so they are sealed only while every key that funnel
    can emit is an exact str.  Pin that invariant on ``_jsonable`` directly:
    a refactor that stops re-keying the dict branch would silently reopen
    the files13 shadow-key class here.
    """

    def test_jsonable_rekeys_to_exact_str(self):
        from hub.docker_cli import _jsonable

        cleaned = _jsonable({_StrEqBombKey("_checked_at"): "t", "img": {"status": "true"}})
        self.assertIsInstance(cleaned, dict)
        self.assertTrue(all(type(k) is str for k in cleaned))
        # The laundered copy answers the probe the raw key used to detonate.
        self.assertEqual(cleaned.get("_checked_at"), "t")

    def test_load_update_status_survives_junk_journal(self):
        # A journal whose top level is not a mapping degrades to {}; the
        # ``or {}`` caller probe then cannot detonate on anything.
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "docker-update-status.json"
            for body in ("[1, 2, 3]", "42", "\"x\"", "{\"_checked_at\": {\"a\": 1}}"):
                path.write_text(body)
                with mock.patch.object(containers_svc, "UPDATE_STATUS_PATH", path):
                    out = containers_svc._load_update_status()
                self.assertIsInstance(out, dict)
                json.dumps(out.get("_checked_at"))


if __name__ == "__main__":
    unittest.main()
