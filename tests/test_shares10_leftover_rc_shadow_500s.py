"""Tenth leftover-500s sweep of the Shares / share-ACL surfaces.

shares9 sealed the hostname and plist parser contracts and nas9 taught the
shares gates to survive lying ``__class__`` impostors.  This hunt drove the
share *listing* and ACL *listing* seams — ``hub.util.sh``'s tuple, the
``time_machine_records`` table and the privileged-result dicts, all
boundaries this feature does not own (tests and tooling patch them) — over
``create_app()`` + ``TestClient(raise_server_exceptions=False)`` with the
docker10 / json9 zoo: rc bombs, lying impostors, bool-liars and
hash-shadowing keys.  Four leftover classes were live raw HTTP 500s:

* **the raw rc channel** (the docker10 ``_rc_int`` class): an rc-subclass
  whose ``__eq__``/``__ne__`` raises detonated ``rc == 0`` in
  ``list_smb_shares`` — a raw 500 on every share mutation through
  ``_find_share`` — and the bare probes in ``time_machine_records``,
  ``read_acl``, ``local_users`` (GET /api/shares/acl reads the picker
  outside any try) and ``_run_unprivileged``; a poisoned ``du`` rc raised
  inside the fan_out worker and wiped the whole sized listing.  Junk now
  reads as ``-255`` — no honest exit status, distinct from the ``-1``
  spawn sentinel — so junk can never be misread as success or as a
  vanished CLI (the coded 503s still require the message marker plus the
  fresh disk probe);
* **hash-shadow keys** (the compose10 / files13 class): a key whose hash
  collides with the fetched literal and whose ``__eq__`` raises detonates
  the ``.get`` probe *itself*, one seam earlier than any value gate.  A
  shadow over ``ok``/``error``/``message`` in a privileged result blew
  ``_plain_result`` in both services and the router funnels; a shadow over
  a record name in the TM table blew ``list_smb_shares``'s merge and
  ``update_smb_share``'s UUID read; a shadow over ``users`` in an ACL
  state blew the GET route's ``{**plain, ...}`` merge.  ``_str_keyed``
  re-keys (the containers ``_plain_job`` rule): exact-str keys keep their
  values, legible str-subclass keys launder through the unbound
  ``str.__str__`` copy, non-str keys drop;
* **bool-liar reads on the TM merge**: a ``__bool__``-bomb dscl output
  blew ``time_machine_records``'s ``not output`` probe and a
  ``__bool__``-bomb TM record blew the merge's old ``or {}``;
* **a ``__bool__``-bomb backup-set UUID** blew
  ``_time_machine_commands``'s mint-or-keep truthiness read;
  ``_tm_record_uuid`` scrubs it to text so a junk shape can never rotate a
  share's backup-set identity.

The confirmed-vanish 503s and the nas9 ``_isa`` / try-wrapped unbound
conventions are untouched and pinned below.  Product version stays 3.9.3.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from contextlib import ExitStack, contextmanager
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from fastapi.testclient import TestClient  # noqa: E402

from hub import auth, share_acl_svc, shares_svc  # noqa: E402
from hub.app_factory import create_app  # noqa: E402
from hub.auth import require_auth  # noqa: E402
from hub.routers import shares as shares_router  # noqa: E402

_app = None


def _the_app():
    global _app
    if _app is None:
        _app = create_app()
        _app.dependency_overrides[require_auth] = lambda: None
    return _app


def _client() -> TestClient:
    # raise_server_exceptions=False: a real 500 must arrive as HTTP 500 rather
    # than a re-raised exception that would mask which route crashed.
    return TestClient(_the_app(), raise_server_exceptions=False)


@contextmanager
def _admin_browser():
    with ExitStack() as stack:
        stack.enter_context(
            mock.patch.object(auth, "browser_authenticated", return_value=True))
        stack.enter_context(
            mock.patch.object(auth, "request_username", return_value="admin"))
        stack.enter_context(mock.patch.object(auth, "is_admin", return_value=True))
        yield


def _starlette(payload) -> None:
    """What Starlette's JSONResponse does: ensure_ascii=False then UTF-8."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


def _is_coded(response) -> bool:
    """A coded error carries ``detail.code``; a raw 500 is a bare traceback."""
    try:
        body = response.json()
    except Exception:
        return False
    return isinstance(body.get("detail"), dict) and bool(body["detail"].get("code"))


# ── the zoo ───────────────────────────────────────────────────────────────────


class IntEqBomb(int):
    """A real int whose comparison operators raise — the ``rc == 0`` killer."""

    def __eq__(self, other):
        raise RuntimeError("rc eq bomb")

    def __ne__(self, other):
        raise RuntimeError("rc ne bomb")

    __hash__ = int.__hash__


class ClassBomb:
    """Leftover whose ``__class__`` is a raising property."""

    @property
    def __class__(self):
        raise RuntimeError("class bomb")


class BoolBomb:
    def __bool__(self):
        raise RuntimeError("bool bomb")


def _liar(cls, text="liar"):
    """``__class__`` answers *cls* while the real type is a plain object."""

    class Liar:
        __class__ = property(lambda self: cls)

        def __str__(self):
            return text

    return Liar()


class _StrEqBombKey(str):
    """A hash-shadowing str subclass: same hash as its text, raising ``__eq__``.

    Demotes the dict off CPython's exact-str fast path, so the raising
    ``__eq__`` runs during the very ``.get(literal)`` probe.
    """

    def __eq__(self, other):
        raise RuntimeError("shadow key eq bomb")

    def __ne__(self, other):
        raise RuntimeError("shadow key ne bomb")

    def __hash__(self):
        return str.__hash__(str.__str__(self))


class _EqBombKey:
    """The non-str twin: colliding hash, raising ``__eq__``, no str rank."""

    def __init__(self, target: str):
        self._h = hash(target)

    def __eq__(self, other):
        raise RuntimeError("non-str shadow key eq bomb")

    def __hash__(self):
        return self._h


#: rc shapes that each used to 500 at least one shares/ACL route.
_RC_ZOO = (
    ("eq-bomb int subclass", lambda: IntEqBomb(0)),
    ("class-property bomb", ClassBomb),
    ("lying int impostor", lambda: _liar(int)),
    ("over-cap huge int", lambda: 10 ** 4600),
    ("string rc", lambda: "0"),
)

_SHARE_JSON = json.dumps(
    {"Media": {"path": "/tmp", "smb_name": "Media", "smb_shared": True}})


def _sh_shares_only(argv, **kwargs):
    """A healthy ``sharing -l -f json`` listing; everything else fails."""
    a = list(argv)
    if a[:1] == [shares_svc.SHARING] and "-f" in a:
        return (0, _SHARE_JSON, "")
    return (1, "", "")


# ── the rc channel: unit contracts ────────────────────────────────────────────


class RcIntContractTests(unittest.TestCase):
    """Both ``_rc_int`` copies follow the docker10 convention exactly."""

    def test_junk_reads_as_minus_255(self):
        for module in (shares_svc, share_acl_svc):
            for label, make in (
                ("class-property bomb", ClassBomb),
                ("lying int impostor", lambda: _liar(int)),
                ("over-cap huge int", lambda: 10 ** 4600),
                ("non-numeric string", lambda: "junk"),
            ):
                with self.subTest(module=module.__name__, rc=label):
                    self.assertEqual(module._rc_int(make()), -255)

    def test_eq_bomb_subclass_is_defused_and_keeps_its_value(self):
        # The unbound ``int.__index__`` coercion reads the real C-level value
        # without firing the override: the genuine status survives, and the
        # ``== 0`` probe on the laundered copy cannot detonate.
        for module in (shares_svc, share_acl_svc):
            with self.subTest(module=module.__name__):
                self.assertEqual(module._rc_int(IntEqBomb(0)), 0)
                self.assertEqual(module._rc_int(IntEqBomb(5)), 5)
                self.assertTrue(module._rc_int(IntEqBomb(0)) == 0)

    def test_honest_and_stringy_values_keep_their_status(self):
        class QuietSubclass(int):
            """A genuine subclass with no bombs keeps its value."""

        for module in (shares_svc, share_acl_svc):
            with self.subTest(module=module.__name__):
                self.assertEqual(module._rc_int(0), 0)
                self.assertEqual(module._rc_int(-1), -1)
                self.assertEqual(module._rc_int(True), 1)
                self.assertEqual(module._rc_int(QuietSubclass(2)), 2)
                # int("0") parses: a stringy rc from an odd stub stays honest.
                self.assertEqual(module._rc_int("0"), 0)
                self.assertEqual(module._rc_int(None), -255)

    def test_junk_is_distinct_from_the_spawn_sentinel(self):
        # -1 is sh()'s timeout / not-found sentinel; junk must never collide
        # with it, so a bombed rc cannot fake a vanished CLI.
        self.assertNotEqual(shares_svc._rc_int(ClassBomb()), -1)
        self.assertNotEqual(share_acl_svc._rc_int(ClassBomb()), -1)


class StrKeyedContractTests(unittest.TestCase):
    """The three ``_str_keyed`` copies launder exactly like ``_plain_job``."""

    def test_exact_map_returns_as_is(self):
        for module in (shares_svc, share_acl_svc, shares_router):
            with self.subTest(module=module.__name__):
                plain = {"ok": True, "error": "x"}
                self.assertIs(module._str_keyed(plain), plain)

    def test_str_subclass_shadow_key_launders_and_keeps_its_value(self):
        for module in (shares_svc, share_acl_svc, shares_router):
            with self.subTest(module=module.__name__):
                out = module._str_keyed({_StrEqBombKey("ok"): True, "e": 1})
                self.assertEqual(out, {"ok": True, "e": 1})
                self.assertTrue(all(type(k) is str for k in out))
                out.get("ok")  # the probe the shadow key used to detonate

    def test_non_str_and_impostor_keys_drop(self):
        for module in (shares_svc, share_acl_svc, shares_router):
            with self.subTest(module=module.__name__):
                out = module._str_keyed(
                    {_EqBombKey("ok"): True, _liar(str): 2, "keep": 3})
                self.assertEqual(out, {"keep": 3})


# ── the share listing: rc bombs answer coded, never raw ───────────────────────


class ListingRcBombTests(unittest.TestCase):
    """A junk rc from ``sharing -l`` degrades the listing, never 500s."""

    def test_mutations_answer_the_confirmed_vanish_contract(self):
        # Junk rc -> empty listing -> the not-found guard still runs its
        # fresh disk probe: CLI confirmed gone is the coded 503, CLI on disk
        # keeps the honest 404 — never a raw 500 out of the rc probe.
        for label, make in _RC_ZOO:
            for on_disk, status, code in (
                (False, 503, "shares.sharing_missing"),
                (True, 404, "shares.not_found"),
            ):
                with self.subTest(rc=label, sharing_on_disk=on_disk):
                    with _admin_browser(), ExitStack() as stack:
                        stack.enter_context(mock.patch.object(
                            shares_svc, "sh",
                            return_value=(make(), "{}", "")))
                        stack.enter_context(mock.patch.object(
                            shares_svc, "_sharing_on_disk",
                            return_value=on_disk))
                        response = _client().put(
                            "/api/shares/smb/Media", json={"smb_name": "Media"})
                    self.assertEqual(response.status_code, status, response.text[:200])
                    self.assertTrue(_is_coded(response), response.text[:200])
                    self.assertEqual(response.json()["detail"]["code"], code)

    def test_delete_answers_coded_on_a_bombed_rc(self):
        with _admin_browser(), ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                shares_svc, "sh", return_value=(IntEqBomb(0), "{}", "")))
            stack.enter_context(mock.patch.object(
                shares_svc, "_sharing_on_disk", return_value=True))
            response = _client().delete("/api/shares/smb/Media?confirm=true")
        self.assertEqual(response.status_code, 404, response.text[:200])
        self.assertTrue(_is_coded(response), response.text[:200])

    def test_shares_page_stays_200_on_a_bombed_rc(self):
        with _admin_browser(), \
             mock.patch.object(shares_svc, "sh",
                               return_value=(IntEqBomb(0), "{}", "")):
            response = _client().get("/api/shares")
        self.assertEqual(response.status_code, 200, response.text[:200])
        body = response.json()
        _starlette(body)
        self.assertEqual(body["smb"], [])

    def test_bool_bomb_json_output_falls_through_to_legacy(self):
        # ``if rc == 0 and output`` used to detonate the truthiness read.
        def fake_sh(argv, **kwargs):
            a = list(argv)
            if a[:1] == [shares_svc.SHARING] and "-f" in a:
                return (0, BoolBomb(), "")
            if a[:1] == [shares_svc.SHARING]:
                return (0, "", "")
            return (1, "", "")

        with mock.patch.object(shares_svc, "sh", side_effect=fake_sh):
            self.assertEqual(shares_svc.list_smb_shares(include_sizes=False), [])

    def test_du_rc_bomb_costs_only_the_size_column(self):
        # Pre-fix the bomb raised inside the fan_out worker, which re-raises,
        # and the whole sized listing was wiped under shares_overview's rescue.
        # An eq-bomb *subclass* defuses to its genuine status (the size still
        # parses); an unusable rc reads as failure (the size drops alone).
        for label, rc, size in (
            ("eq-bomb subclass keeps its status", IntEqBomb(0), 5.0),
            ("class-property bomb reads as failure", ClassBomb(), None),
        ):
            with self.subTest(rc=label):
                def fake_sh(argv, _rc=rc, **kwargs):
                    a = list(argv)
                    if a[:1] == [shares_svc.SHARING] and "-f" in a:
                        return (0, _SHARE_JSON, "")
                    if a[:1] == ["/usr/bin/du"]:
                        return (_rc, "5 /tmp", "")
                    return (1, "", "")

                with mock.patch.object(shares_svc, "sh", side_effect=fake_sh):
                    rows = shares_svc.list_smb_shares(include_sizes=True)
                self.assertEqual([r["record_name"] for r in rows], ["Media"])
                self.assertEqual(rows[0]["size_mb"], size)
                _starlette(rows)


class TimeMachineRecordsRcBombTests(unittest.TestCase):
    """A junk dscl read costs only the TM columns, never the mutation."""

    def _sh(self, dscl_result):
        def fake_sh(argv, **kwargs):
            a = list(argv)
            if a[:1] == [shares_svc.SHARING] and "-f" in a:
                return (0, _SHARE_JSON, "")
            if a[:1] == [shares_svc.SHARING]:
                return (0, "", "")
            if a[:2] == [shares_svc.DSCL, "-plist"]:
                return dscl_result
            return (1, "", "")
        return fake_sh

    def test_rc_bomb_reads_as_empty_table(self):
        for label, rc in (
            ("class-property bomb", ClassBomb()),
            ("eq-bomb subclass (nonzero)", IntEqBomb(1)),
            ("lying int impostor", _liar(int)),
        ):
            with self.subTest(rc=label):
                with mock.patch.object(
                        shares_svc, "sh", side_effect=self._sh((rc, "x", ""))):
                    self.assertEqual(shares_svc.time_machine_records(), {})

    def test_bool_bomb_output_reads_as_empty_table(self):
        with mock.patch.object(
                shares_svc, "sh", side_effect=self._sh((0, BoolBomb(), ""))):
            self.assertEqual(shares_svc.time_machine_records(), {})

    def test_update_still_succeeds_past_a_bombed_tm_read(self):
        # Pre-fix the raise escaped list_smb_shares' unguarded merge and
        # 500'd PUT /api/shares/smb/{record} out of _find_share.
        with _admin_browser(), ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                shares_svc, "sh", side_effect=self._sh((IntEqBomb(0), "x", ""))))
            stack.enter_context(mock.patch.object(
                shares_svc, "run_admin_sequence", return_value={"ok": True}))
            response = _client().put(
                "/api/shares/smb/Media", json={"smb_name": "Media"})
        self.assertEqual(response.status_code, 200, response.text[:200])
        _starlette(response.json())


# ── the share listing: hash-shadow keys on the TM merge ──────────────────────


class TimeMachineShadowKeyTests(unittest.TestCase):
    """Shadow keys in a poisoned TM table cannot detonate the merge probes."""

    def _rows(self, records):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                shares_svc, "sh", side_effect=_sh_shares_only))
            stack.enter_context(mock.patch.object(
                shares_svc, "time_machine_records", return_value=records))
            return shares_svc.list_smb_shares(include_sizes=False)

    def test_str_subclass_shadow_record_keeps_its_tm_columns(self):
        # The legible impostor key launders to the exact record name, so the
        # genuine TM flag riding it still renders instead of costing the row.
        rows = self._rows({_StrEqBombKey("Media"): {"time_machine": True}})
        self.assertEqual(len(rows), 1)
        self.assertIs(rows[0]["time_machine"], True)
        _starlette(rows)

    def test_non_str_shadow_record_drops_only_the_tm_columns(self):
        rows = self._rows({_EqBombKey("Media"): {"time_machine": True}})
        self.assertEqual(len(rows), 1)
        self.assertIs(rows[0]["time_machine"], False)
        self.assertIsNone(rows[0]["tm_quota_gb"])

    def test_bool_bomb_record_value_drops_only_the_tm_columns(self):
        # The old ``or {}`` detonated the truthiness read one line ahead of
        # the dict gate that already absorbs junk records.
        rows = self._rows({"Media": BoolBomb()})
        self.assertEqual(len(rows), 1)
        self.assertIs(rows[0]["time_machine"], False)

    def test_update_answers_coded_past_a_shadowed_table(self):
        for label, key in (
            ("non-str", _EqBombKey("Media")),
            ("str-subclass", _StrEqBombKey("Media")),
        ):
            with self.subTest(key=label):
                with _admin_browser(), ExitStack() as stack:
                    stack.enter_context(mock.patch.object(
                        shares_svc, "sh", side_effect=_sh_shares_only))
                    stack.enter_context(mock.patch.object(
                        shares_svc, "time_machine_records",
                        return_value={key: {"time_machine": False}}))
                    stack.enter_context(mock.patch.object(
                        shares_svc, "run_admin_sequence",
                        return_value={"ok": True}))
                    response = _client().put(
                        "/api/shares/smb/Media", json={"smb_name": "Media"})
                self.assertEqual(response.status_code, 200, response.text[:200])
                _starlette(response.json())


class TmRecordUuidTests(unittest.TestCase):
    """``_tm_record_uuid`` survives every shape the old bare chain died on."""

    def _uuid(self, records):
        with mock.patch.object(
                shares_svc, "time_machine_records", return_value=records):
            return shares_svc._tm_record_uuid("Media")

    def test_shadowed_record_key_reads_through_the_laundering(self):
        self.assertEqual(
            self._uuid({_StrEqBombKey("Media"): {"uuid": "AAAA"}}), "AAAA")
        self.assertIsNone(self._uuid({_EqBombKey("Media"): {"uuid": "AAAA"}}))

    def test_junk_record_shapes_read_as_no_uuid(self):
        self.assertIsNone(self._uuid({"Media": BoolBomb()}))
        self.assertIsNone(self._uuid({"Media": _liar(dict)}))
        self.assertIsNone(self._uuid(_liar(dict)))
        self.assertIsNone(self._uuid({}))

    def test_shadowed_uuid_field_reads_as_no_uuid(self):
        self.assertIsNone(
            self._uuid({"Media": {_EqBombKey("uuid"): "AAAA"}}))

    def test_bool_bomb_uuid_value_still_reads_as_present(self):
        # The mint-or-keep decision is a truthiness read; a junk-but-legible
        # value must keep answering "a UUID exists" so a leftover can never
        # rotate a share's backup-set identity.
        value = self._uuid({"Media": {"uuid": BoolBomb()}})
        self.assertIsInstance(value, str)
        self.assertTrue(value)

    def test_update_with_tm_survives_a_shadowed_uuid_read(self):
        # Pre-fix the ``.get(record)`` hash probe raised out of
        # update_smb_share and 500'd PUT with time_machine enabled.
        with _admin_browser(), ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                shares_svc, "sh", side_effect=_sh_shares_only))
            stack.enter_context(mock.patch.object(
                shares_svc, "time_machine_records",
                return_value={_StrEqBombKey("Media"): {"uuid": "AAAA"}}))
            stack.enter_context(mock.patch.object(
                shares_svc, "run_admin_sequence", return_value={"ok": True}))
            response = _client().put(
                "/api/shares/smb/Media",
                json={"smb_name": "Media", "time_machine": True})
        # The fresh-read verification honestly reports the flag unset (the
        # stub listing has no TM columns) — coded, never a raw 500.
        self.assertEqual(response.status_code, 409, response.text[:200])
        self.assertTrue(_is_coded(response), response.text[:200])
        self.assertEqual(
            response.json()["detail"]["code"], "shares.verification_failed")


# ── privileged results: shadow keys through the funnels ───────────────────────


class PlainResultShadowKeyTests(unittest.TestCase):
    """Both services' ``_plain_result`` launder shadow keys, keeping values."""

    def test_legible_shadow_ok_keeps_its_value(self):
        for module in (shares_svc, share_acl_svc):
            with self.subTest(module=module.__name__):
                plain = module._plain_result({_StrEqBombKey("ok"): True})
                self.assertIs(plain["ok"], True)

    def test_non_str_shadow_ok_reads_as_failure(self):
        for module in (shares_svc, share_acl_svc):
            with self.subTest(module=module.__name__):
                plain = module._plain_result({_EqBombKey("ok"): True})
                self.assertIs(plain["ok"], False)

    def test_shadowed_admin_result_answers_coded_on_the_share_mutation(self):
        # Pre-fix the ``plain.get("ok")`` probe — and _admin_failure's
        # error/message reads after it — detonated as raw 500s on PUT.
        for label, result, status, code in (
            ("shadow-error", {"ok": False, _StrEqBombKey("error"): "failed"},
             500, "shares.authorization_failed"),
            ("shadow-message",
             {"ok": False, "error": "failed", _StrEqBombKey("message"): "m"},
             500, "shares.authorization_failed"),
        ):
            with self.subTest(shape=label):
                with _admin_browser(), ExitStack() as stack:
                    stack.enter_context(mock.patch.object(
                        shares_svc, "sh", side_effect=_sh_shares_only))
                    stack.enter_context(mock.patch.object(
                        shares_svc, "time_machine_records", return_value={}))
                    stack.enter_context(mock.patch.object(
                        shares_svc, "run_admin_sequence", return_value=result))
                    response = _client().put(
                        "/api/shares/smb/Media", json={"smb_name": "Media"})
                self.assertEqual(response.status_code, status, response.text[:200])
                self.assertTrue(_is_coded(response), response.text[:200])
                self.assertEqual(response.json()["detail"]["code"], code)


class RouterFunnelShadowKeyTests(unittest.TestCase):
    """Shadow keys straight from a patched service answer coded, never raw."""

    def _create(self, result):
        with _admin_browser(), mock.patch.object(
                shares_svc, "create_smb_share", return_value=result):
            return _client().post("/api/shares/smb", json={
                "path": "/tmp", "name": "M", "smb_name": "M"})

    def test_non_str_shadow_ok_maps_to_the_coded_failure(self):
        response = self._create({_EqBombKey("ok"): True, "error": "x"})
        self.assertEqual(response.status_code, 500, response.text[:200])
        self.assertTrue(_is_coded(response), response.text[:200])
        self.assertEqual(
            response.json()["detail"]["code"], "shares.operation_failed")

    def test_legible_shadow_ok_still_renders_its_ok_body(self):
        response = self._create({_StrEqBombKey("ok"): True})
        self.assertEqual(response.status_code, 200, response.text[:200])
        body = response.json()
        _starlette(body)
        self.assertIs(body["ok"], True)

    def test_shadow_error_beside_honest_failure_keeps_its_mapped_code(self):
        # The laundered error string still earns its coded 409 instead of
        # detonating _raise_service_error's mapping probe.
        response = self._create(
            {"ok": False, _StrEqBombKey("error"): "cancelled"})
        self.assertEqual(response.status_code, 409, response.text[:200])
        self.assertTrue(_is_coded(response), response.text[:200])
        self.assertEqual(
            response.json()["detail"]["code"], "shares.authorization_cancelled")


# ── the ACL listing: rc bombs and shadowed states ─────────────────────────────


class _AclSandbox(unittest.TestCase):
    """A real shared directory so ``_share_directory`` resolves honestly."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.share_dir = str(Path(tmp.name).resolve())
        self.row = {
            "record_name": "Media", "name": "Media", "path": self.share_dir,
            "smb_name": "Media", "shared": True, "guest": False,
            "readonly": False, "encrypted": False,
        }
        self.acl_out = (
            f"drwxr-xr-x  2 root  staff  64 Jan  1 00:00 {self.share_dir}\n"
            " 0: user:alice allow read\n"
        )

    def _acl_sh(self, *, ls=None, dscl_list=None, dscl_read=None, chmod=None):
        def fake_sh(argv, **kwargs):
            a = list(argv)
            if a[:1] == [share_acl_svc.LS]:
                return ls or (0, self.acl_out, "")
            if a[:2] == [share_acl_svc.DSCL, "."] and "-list" in a:
                return dscl_list or (0, "alice 501\n", "")
            if a[:2] == [share_acl_svc.DSCL, "."] and "-read" in a:
                return dscl_read or (0, "RealName: Alice", "")
            if a[:1] == [share_acl_svc.CHMOD]:
                return chmod or (1, "", "failed")
            return (1, "", "")
        return fake_sh

    def _get(self, fake_sh):
        with _admin_browser(), ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                shares_svc, "list_smb_shares", return_value=[dict(self.row)]))
            stack.enter_context(mock.patch.object(
                share_acl_svc, "sh", side_effect=fake_sh))
            return _client().get(f"/api/shares/acl?path={self.share_dir}")


class AclRcBombTests(_AclSandbox):
    def test_ls_rc_zoo_answers_the_coded_read_failure(self):
        for label, make in _RC_ZOO[:4]:
            with self.subTest(rc=label):
                response = self._get(self._acl_sh(ls=(make(), "x", "")))
                self.assertEqual(response.status_code, 500, response.text[:200])
                self.assertTrue(_is_coded(response), response.text[:200])
                self.assertEqual(
                    response.json()["detail"]["code"], "shares.acl_read_failed")

    def test_junk_rc_cannot_fake_a_vanished_ls(self):
        # The coded 503 still needs the message marker AND the fresh disk
        # probe; a junk rc with a marker but the tool on disk keeps the
        # honest read failure, and a confirmed vanish earns the 503.
        for on_disk, code in (
            (True, "shares.acl_read_failed"),
            (False, "shares.acl_tool_missing"),
        ):
            with self.subTest(ls_on_disk=on_disk):
                with mock.patch.object(
                        share_acl_svc, "_tool_on_disk", return_value=on_disk):
                    response = self._get(self._acl_sh(
                        ls=(IntEqBomb(1), "", "ls: command not found")))
                self.assertTrue(_is_coded(response), response.text[:200])
                self.assertEqual(response.json()["detail"]["code"], code)
                self.assertEqual(
                    response.status_code,
                    500 if on_disk else 503, response.text[:200])

    def test_picker_rc_bomb_degrades_to_an_empty_picker(self):
        # GET /api/shares/acl reads local_users outside any try; the bomb
        # used to 500 the whole route past the already-parsed ACL.
        response = self._get(self._acl_sh(dscl_list=(IntEqBomb(1), "", "")))
        self.assertEqual(response.status_code, 200, response.text[:200])
        body = response.json()
        _starlette(body)
        self.assertEqual(body["users"], [])
        self.assertEqual(body["entries"][0]["name"], "alice")

    def test_realname_rc_bomb_costs_only_the_display_name(self):
        response = self._get(self._acl_sh(dscl_read=(ClassBomb(), "x", "")))
        self.assertEqual(response.status_code, 200, response.text[:200])
        body = response.json()
        _starlette(body)
        self.assertEqual(body["users"][0]["username"], "alice")
        self.assertEqual(body["users"][0]["real_name"], "")

    def test_chmod_rc_bomb_answers_coded_on_the_grant(self):
        # Owner-run path: the bombed rc used to raise out of
        # _run_unprivileged one line ahead of the failure funnel.
        with _admin_browser(), ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                shares_svc, "list_smb_shares", return_value=[dict(self.row)]))
            stack.enter_context(mock.patch.object(
                share_acl_svc, "sh",
                side_effect=self._acl_sh(
                    chmod=(IntEqBomb(1), "", "chmod: Operation not permitted"))))
            stack.enter_context(mock.patch.object(
                share_acl_svc.os, "getuid",
                return_value=Path(self.share_dir).stat().st_uid))
            stack.enter_context(mock.patch.object(
                share_acl_svc.macos_admin, "run_admin_sequence",
                return_value={"ok": False, "error": "cancelled"}))
            response = _client().put("/api/shares/acl", json={
                "path": self.share_dir, "username": "alice", "level": "readwrite"})
        self.assertEqual(response.status_code, 409, response.text[:200])
        self.assertTrue(_is_coded(response), response.text[:200])
        self.assertEqual(
            response.json()["detail"]["code"], "shares.authorization_cancelled")


class AclShadowKeyTests(_AclSandbox):
    def test_shadowed_admin_result_answers_coded_on_the_grant(self):
        for label, result, status, code in (
            ("shadow-error",
             {"ok": False, _StrEqBombKey("error"): "cancelled"},
             409, "shares.authorization_cancelled"),
            ("shadow-message",
             {"ok": False, "error": "failed", _StrEqBombKey("message"): "m"},
             500, "shares.authorization_failed"),
        ):
            with self.subTest(shape=label):
                with _admin_browser(), ExitStack() as stack:
                    stack.enter_context(mock.patch.object(
                        shares_svc, "list_smb_shares",
                        return_value=[dict(self.row)]))
                    stack.enter_context(mock.patch.object(
                        share_acl_svc, "sh", side_effect=self._acl_sh()))
                    stack.enter_context(mock.patch.object(
                        share_acl_svc.os, "getuid", return_value=99999))
                    stack.enter_context(mock.patch.object(
                        share_acl_svc.macos_admin, "run_admin_sequence",
                        return_value=result))
                    response = _client().put("/api/shares/acl", json={
                        "path": self.share_dir, "username": "alice",
                        "level": "read"})
                self.assertEqual(response.status_code, status, response.text[:200])
                self.assertTrue(_is_coded(response), response.text[:200])
                self.assertEqual(response.json()["detail"]["code"], code)

    def test_shadowed_users_key_in_a_leftover_state_renders(self):
        # Inserting "users" into the response is a hash probe; the shadow
        # key used to detonate the GET route's ``{**plain, ...}`` merge.
        state = {"path": self.share_dir, "mode": "d", "owner": "r",
                 "group": "s", "entries": [], "owned_by_panel": True,
                 _StrEqBombKey("users"): "x"}
        with _admin_browser(), ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                shares_svc, "list_smb_shares", return_value=[dict(self.row)]))
            stack.enter_context(mock.patch.object(
                share_acl_svc, "read_acl", return_value=state))
            stack.enter_context(mock.patch.object(
                share_acl_svc, "local_users", return_value=[]))
            response = _client().get(f"/api/shares/acl?path={self.share_dir}")
        self.assertEqual(response.status_code, 200, response.text[:200])
        body = response.json()
        _starlette(body)
        self.assertEqual(body["users"], [])


# ── stays-immune pins: the nas9 conventions hold through the new laundering ──


class StaysImmunePinTests(unittest.TestCase):
    def test_get_bomb_dict_subclass_result_still_maps_coded(self):
        # The shares9 pin, re-asserted through the new _str_keyed step.
        class GetBomb(dict):
            def get(self, *a, **k):
                raise RuntimeError("bound get landmine")

        with _admin_browser(), mock.patch.object(
                shares_svc, "create_smb_share",
                return_value=GetBomb(ok=False, error="cancelled")):
            response = _client().post("/api/shares/smb", json={
                "path": "/tmp", "name": "M", "smb_name": "M"})
        self.assertEqual(response.status_code, 409, response.text[:200])
        self.assertEqual(
            response.json()["detail"]["code"], "shares.authorization_cancelled")

    def test_liar_tm_table_still_costs_only_the_tm_columns(self):
        # The nas9 pin, re-asserted through _plain_tm_records.
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                shares_svc, "sh", side_effect=_sh_shares_only))
            stack.enter_context(mock.patch.object(
                shares_svc, "time_machine_records", return_value=_liar(dict)))
            rows = shares_svc.list_smb_shares(include_sizes=False)
        self.assertEqual(len(rows), 1)
        self.assertIs(rows[0]["time_machine"], False)

    def test_bytes_liar_failure_message_keeps_the_coded_refusal(self):
        # The nas9 _as_text pin on _admin_failure, through the new funnels.
        with _admin_browser(), ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                shares_svc, "sh", side_effect=_sh_shares_only))
            stack.enter_context(mock.patch.object(
                shares_svc, "time_machine_records", return_value={}))
            stack.enter_context(mock.patch.object(
                shares_svc, "run_admin_sequence",
                return_value={"ok": False, "error": "failed",
                              "message": _liar(bytes)}))
            response = _client().put(
                "/api/shares/smb/Media", json={"smb_name": "Media"})
        self.assertEqual(response.status_code, 500, response.text[:200])
        self.assertEqual(
            response.json()["detail"]["code"], "shares.authorization_failed")

    def test_class_property_bomb_result_is_still_coded(self):
        with _admin_browser(), mock.patch.object(
                shares_svc, "create_smb_share", return_value=ClassBomb()):
            response = _client().post("/api/shares/smb", json={
                "path": "/tmp", "name": "M", "smb_name": "M"})
        self.assertEqual(response.status_code, 500, response.text[:200])
        self.assertEqual(
            response.json()["detail"]["code"], "shares.authorization_failed")


if __name__ == "__main__":
    unittest.main(verbosity=2)
