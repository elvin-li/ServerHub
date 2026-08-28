"""Twelfth Notify-domain leftover sweep: *BaseException-shaped* bombs and
the claimed-base decode gap, over the real app.

Every bomb guard notify6..notify11 built into ``hub.notify_channels``
stopped at ``except Exception``.  A leftover whose hook raises a
*BaseException* subclass instead (the watchdog/timeout shape logs12 just
sealed on the logs routes) sailed past every one of those nets at once.
Driven through ``create_app()`` + ``TestClient(raise_server_exceptions=
False)`` with the hostile store planted as the live ``cfg()`` snapshot,
the pre-fix tree answered raw HTTP 500s (or raised out of never-raises
paths) for:

* a ``__class__``-property bomb raising a BaseException subclass planted
  as a channel row, or as a row's ``id``: all six /api/alerts/channels
  routes and POST /api/alerts/test at once, plus a raise out of
  :func:`hub.notify_channels.dispatch` on the alert engine's single
  thread — ``_isa``'s catch stopped one rank too low;
* a ``__bool__`` bomb raising a BaseException subclass on a row's
  ``enabled`` flag: GET /api/alerts/channels and POST /api/alerts/test
  raw, and the same raise out of dispatch() (``_truthy``'s net);
* the same ``__bool__`` bomb on the legacy ``ha_token`` slot: the global
  test route and the alert thread's sweep (``_legacy_target``'s reads);
* a ``__str__`` bomb raising a BaseException subclass as a row's id: all
  six channel routes (``_id_text``'s trailing net);
* the bomb detonating *inside a real sender's* own truth test
  (``str(ch.get("host") or "")``): it rode the worker future back into
  dispatch(), whose ``fut.result()`` net also stopped at Exception.

Separately, ``_decode_bytes`` picked its decode base off the *claimed*
``__class__``: a genuine ``bytearray`` whose ``__class__`` lied ``bytes``
was handed to ``bytes.decode``, rejected by the descriptor, and its
perfectly decodable name/topic vanished to ``""`` — degrade at the wrong
rank (the modules12/logs12 claimed-base rule).

Fixes, the established conventions: every guard catches ``BaseException``
while re-raising genuine control flow (``KeyboardInterrupt`` /
``SystemExit`` — swallowing a Ctrl-C to save one channel row would turn
the sanitizer into a hang), and ``_decode_bytes`` tries both bases
real-layout-first-come.

Stays-immune pins ride along for the wave-12 shapes the hunt probed and
found already sealed: a dict-subclass ``.get`` BaseException bomb row
(the ``_plain_row`` unbound copy never runs the override), a
list-subclass ``__iter__`` BaseException bomb ``channels:`` (unbound
``list.__iter__``), and a plain-object shadow key whose ``__eq__`` raises
a BaseException subclass (``_plain_row`` drops non-str keys before any
comparison runs).
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

from fastapi.testclient import TestClient  # noqa: E402

from hub import alerts, audit, auth, config, notify_channels  # noqa: E402
from hub.app_factory import create_app  # noqa: E402
from hub.auth import require_auth  # noqa: E402

_APP = None


def app():
    global _APP
    if _APP is None:
        _APP = create_app()
        _APP.dependency_overrides[require_auth] = lambda: True
    return _APP


class LeftoverWatchdogTimeout(BaseException):
    """Not an Exception: the shape that sailed past every pre-fix net."""


class ClassPropBaseExcBomb:
    """``__class__`` property raising a BaseException subclass.

    ``isinstance`` consults ``__class__`` when the exact-type check
    misses, so this used to detonate ``_isa`` itself — one step ahead of
    every scrub in the module.
    """

    @property
    def __class__(self):  # noqa: D105
        raise LeftoverWatchdogTimeout("class-prop base-exc bomb")


class BoolBaseExcBomb:
    def __bool__(self):  # noqa: D105
        raise LeftoverWatchdogTimeout("bool base-exc bomb")


class StrBaseExcBomb:
    def __str__(self):  # noqa: D105
        raise LeftoverWatchdogTimeout("str base-exc bomb")


class GetBaseExcRow(dict):
    """Dict-subclass row whose ``.get`` raises a BaseException subclass."""

    def get(self, *a, **k):  # noqa: D102
        raise LeftoverWatchdogTimeout("get base-exc bomb")


class IterBaseExcList(list):
    """List subclass whose ``__iter__`` raises a BaseException subclass."""

    def __iter__(self):  # noqa: D105
        raise LeftoverWatchdogTimeout("iter base-exc bomb")


class ObjShadowBaseExcKey:
    """Plain-object shadow key whose ``__eq__`` raises a BaseException."""

    def __init__(self, text: str):
        self._t = text

    def __hash__(self):  # noqa: D105
        return hash(self._t)

    def __eq__(self, other):  # noqa: D105
        raise LeftoverWatchdogTimeout("shadow-key base-exc eq bomb")

    __ne__ = __eq__


class LyingBytearray(bytearray):
    """Genuine bytearray storage whose ``__class__`` claims ``bytes``.

    The old ``_decode_bytes`` picked its base off the claim, handed this
    to ``bytes.decode``, and the descriptor's rejection erased perfectly
    decodable content to ``""``.
    """

    @property
    def __class__(self):  # noqa: D105
        return bytes


class CtrlCClassProp:
    """``__class__`` property raising KeyboardInterrupt: real control flow."""

    @property
    def __class__(self):  # noqa: D105
        raise KeyboardInterrupt


class CtrlCBool:
    def __bool__(self):  # noqa: D105
        raise KeyboardInterrupt


class CtrlCStr:
    def __str__(self):  # noqa: D105
        raise KeyboardInterrupt


def _row(**kw):
    base = {"id": "c1", "type": "ntfy", "topic": "t"}
    base.update(kw)
    return base


def _notify_cfg(notify) -> dict:
    return {"settings": {"notify": notify}}


def _stub_sender(*_a, **_k) -> dict:
    return {"ok": True, "message": "sent"}


class _Notify12Sandbox(unittest.TestCase):
    """Scratch state dirs, offline senders, and a hostile live cfg() snapshot."""

    def setUp(self):
        tmp = tempfile.mkdtemp(prefix="serverhub-notify12-")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        self.root = Path(tmp)
        self.data = self.root / "data"
        self.data.mkdir()
        self.yaml_path = self.root / "services.yaml"
        self.secrets_path = self.data / "notify-credentials.json"
        for target, attr, value in (
            (config, "YAML_PATH", self.yaml_path),
            (config, "DATA_DIR", self.data),
            (config, "BASE", self.root),
            (config, "_LOCK_PATH", self.data / ".services.yaml.lock"),
            (alerts, "ALERTS_FILE", self.data / "alerts.jsonl"),
            (alerts, "STATE_FILE", self.data / "alert_state.json"),
            (notify_channels, "SECRETS_FILE", self.secrets_path),
            (audit, "AUDIT_PATH", self.data / "auth-audit.jsonl"),
            (auth, "SECRET_FILE", self.data / ".session-secret"),
        ):
            patched = mock.patch.object(target, attr, value)
            patched.start()
            self.addCleanup(patched.stop)
        # Never a network send: the stubbed types cover every row these
        # suites plant.  ``email`` is deliberately left real for the
        # sender-inner-bomb pins — its host bomb detonates before any
        # socket is opened.
        senders = mock.patch.dict(
            notify_channels._SENDERS,
            {"ntfy": _stub_sender, "home_assistant": _stub_sender},
        )
        senders.start()
        self.addCleanup(senders.stop)
        self.addCleanup(config.reload_cfg)
        self.client = TestClient(app(), raise_server_exceptions=False)

    def plant(self, cfg_data) -> None:
        """Install *cfg_data* as the live cfg() snapshot (the leftover)."""
        patched = mock.patch.object(config, "cfg", lambda: cfg_data)
        patched.start()
        self.addCleanup(patched.stop)

    def assert_renderable(self, resp):
        """The body must be UTF-8 JSON with no lone surrogate leaking out."""
        parsed = resp.json()
        json.dumps(parsed, ensure_ascii=False, allow_nan=False).encode("utf-8")
        return parsed

    def assert_not_500(self, resp, label: str = ""):
        self.assertNotEqual(resp.status_code, 500, f"{label}: {resp.text[:200]}")
        return self.assert_renderable(resp)

    _CREATE = {"type": "ntfy", "id": "px", "config": {"topic": "t"}, "secrets": {}}
    _PUT = {"type": "ntfy", "config": {"topic": "u"}, "secrets": {}}

    def sweep_channel_routes(self, label: str) -> None:
        """Every channel surface plus the global test answer coded, never 500."""
        self.assert_not_500(self.client.get("/api/alerts/channels"),
                            f"{label} GET channels")
        self.assert_not_500(
            self.client.post("/api/alerts/channels", json=self._CREATE),
            f"{label} POST create",
        )
        self.assert_not_500(
            self.client.put("/api/alerts/channels/c1", json=self._PUT),
            f"{label} PUT",
        )
        self.assert_not_500(self.client.post("/api/alerts/channels/c1/test"),
                            f"{label} per-channel test")
        self.assert_not_500(self.client.delete("/api/alerts/channels/c1"),
                            f"{label} DELETE")
        self.assert_not_500(self.client.post("/api/alerts/test"),
                            f"{label} POST alerts test")

    def assert_dispatch_contract(self, label: str) -> dict:
        """dispatch() must never raise — it runs on the alert thread."""
        try:
            out = notify_channels.dispatch("t", "m", level="down", event=None)
        except BaseException as exc:  # pragma: no cover - the pre-fix failure
            self.fail(f"{label}: dispatch raised {exc!r}")
        self.assertIsInstance(out, dict)
        json.dumps(out, ensure_ascii=False, allow_nan=False).encode("utf-8")
        return out

    def listed(self) -> list:
        body = self.assert_not_500(self.client.get("/api/alerts/channels"))
        return body["channels"]


class BaseExcBombRoutePins(_Notify12Sandbox):
    """BaseException-shaped bombs in the stored config cannot 500 any route."""

    def test_class_prop_baseexc_bomb_row_drops_not_the_route(self):
        # Pre-fix: _isa's ``except Exception`` let the property's
        # BaseException subclass straight out of the _plain_row gate — all
        # six routes and POST /api/alerts/test 500'd raw at once, and
        # dispatch() raised on the alert thread.
        self.plant(_notify_cfg({"channels": [
            ClassPropBaseExcBomb(), _row(id="ok1")]}))
        self.sweep_channel_routes("class-prop base-exc row")
        self.assert_dispatch_contract("class-prop base-exc row")
        self.assertEqual([c["id"] for c in self.listed()], ["ok1"])

    def test_class_prop_baseexc_bomb_id_renders_as_text(self):
        # The str() probe still answers this bomb's default repr (only its
        # ``__class__`` hook is poisoned), so the row keeps rendering under
        # that text — the notify9 id-bomb rule.  The pre-fix failure was
        # earlier: _isa detonated on the BaseException one gate ahead.
        self.plant(_notify_cfg({"channels": [
            _row(id=ClassPropBaseExcBomb()), _row(id="ok1")]}))
        self.sweep_channel_routes("class-prop base-exc id")
        self.assert_dispatch_contract("class-prop base-exc id")
        ids = [c["id"] for c in self.listed()]
        self.assertIn("ok1", ids)
        for cid in ids:
            self.assertIsInstance(cid, str)

    def test_str_baseexc_bomb_id_drops_the_row(self):
        # Pre-fix: _id_text's trailing ``except Exception`` let the
        # ``__str__`` bomb's BaseException subclass out of the str() probe.
        self.plant(_notify_cfg({"channels": [
            _row(id=StrBaseExcBomb()), _row(id="ok1")]}))
        self.sweep_channel_routes("str base-exc id")
        self.assert_dispatch_contract("str base-exc id")
        self.assertEqual([c["id"] for c in self.listed()], ["ok1"])

    def test_bool_baseexc_bomb_flags_degrade_field_level(self):
        # Pre-fix: _truthy's net stopped at Exception, so the row's flag
        # bomb 500'd GET /api/alerts/channels and POST /api/alerts/test and
        # raised out of dispatch().  A bomb flag is junk, not consent to
        # notify: it must read False, and the row itself keeps rendering.
        for field in ("enabled", "notify_resolve"):
            with self.subTest(field=field):
                self.plant(_notify_cfg({"channels": [
                    _row(**{field: BoolBaseExcBomb()}), _row(id="ok1")]}))
                self.sweep_channel_routes(f"bool base-exc {field}")
                self.assert_dispatch_contract(f"bool base-exc {field}")
                rows = {c["id"]: c for c in self.listed()}
                self.assertIn("c1", rows)
                self.assertIn("ok1", rows)
                self.assertIs(type(rows["c1"][field]), bool)

    def test_legacy_bool_baseexc_bomb_keeps_the_global_test_alive(self):
        # Pre-fix: _legacy_target's _truthy reads let the ha_token bomb's
        # BaseException subclass out of dispatch() — the global test route
        # 500'd and the alert thread's sweep died.
        self.plant(_notify_cfg({"ha_token": BoolBaseExcBomb()}))
        self.assert_not_500(self.client.post("/api/alerts/test"),
                            "legacy bool base-exc ha_token")
        self.assert_dispatch_contract("legacy bool base-exc ha_token")

    def test_min_level_baseexc_bombs_fall_back_to_warn(self):
        # _pick's truth test and _utf8_text's str() probe both sit on the
        # min_level read inside _min_rank — on dispatch()'s path as well as
        # GET's.  Either bomb must degrade to the "warn" default.
        for bomb in (BoolBaseExcBomb(), StrBaseExcBomb()):
            with self.subTest(bomb=type(bomb).__name__):
                self.plant(_notify_cfg({"channels": [
                    _row(min_level=bomb), _row(id="ok1")]}))
                self.sweep_channel_routes(f"min_level {type(bomb).__name__}")
                self.assert_dispatch_contract(f"min_level {type(bomb).__name__}")
                rows = {c["id"]: c for c in self.listed()}
                self.assertEqual(rows["c1"]["min_level"], "warn")

    def test_nested_config_baseexc_bombs_render_field_level(self):
        # _json_safe's probes (the isoformat getattr, the final _utf8_text)
        # each held only an Exception net; the bomb value must degrade to
        # null/None while the sane siblings keep rendering.
        self.plant(_notify_cfg({"channels": [
            _row(topic=[ClassPropBaseExcBomb(), StrBaseExcBomb(), "ok"])]}))
        rows = {c["id"]: c for c in self.listed()}
        self.assertIn("c1", rows)
        self.assertEqual(rows["c1"]["config"]["topic"][-1], "ok")
        self.sweep_channel_routes("nested base-exc bombs")

    def test_provider_raising_baseexc_reads_as_unconfigured(self):
        # A cfg() snapshot provider raising a BaseException subclass used
        # to sail past _raw_notify_cfg's net AND dispatch()'s own — the one
        # raise the never-raises contract could not hold.
        def bomb_cfg():
            raise LeftoverWatchdogTimeout("provider base-exc bomb")

        patched = mock.patch.object(config, "cfg", bomb_cfg)
        patched.start()
        self.addCleanup(patched.stop)
        self.assertEqual(self.listed(), [])
        out = self.assert_dispatch_contract("provider base-exc bomb")
        self.assertFalse(out.get("ok"))


class SenderInnerBaseExcBombPins(_Notify12Sandbox):
    """A bomb detonating *inside* a real sender cannot ride the future out."""

    def test_email_host_bomb_answers_a_failed_result_not_a_raise(self):
        # ``_send_email`` runs ``str(ch.get("host") or "")``: the ``or``
        # truth test detonates the BaseException bomb inside the worker
        # thread, the future stores it, and ``fut.result()`` re-raised it
        # past dispatch()'s Exception net — a 500 on the per-channel test
        # route and a raise on the alert thread.  No socket is ever opened:
        # the bomb fires before the missing-host check.
        self.plant(_notify_cfg({"channels": [
            _row(id="m1", type="email", host=BoolBaseExcBomb(), to="a@b.c",
                 enabled=True)]}))
        r = self.assert_not_500(self.client.post("/api/alerts/channels/m1/test"),
                                "email host bomb per-channel test")
        self.assertFalse(r.get("ok"))
        self.assertEqual(r.get("failed"), 1)
        out = self.assert_dispatch_contract("email host bomb")
        self.assertFalse(out.get("ok"))

    def test_send_via_shapes_the_baseexc_into_a_result_row(self):
        def bomb_sender(*_a, **_k):
            raise LeftoverWatchdogTimeout("sender base-exc bomb")

        res = notify_channels._send_via(
            bomb_sender, _row(), {}, "t", "m", level="down", event=None)
        self.assertIsInstance(res, dict)
        self.assertIs(res.get("ok"), False)
        self.assertIn("base-exc", res.get("message", ""))


class ClaimedBaseDecodePins(_Notify12Sandbox):
    """A genuine bytearray lying ``bytes`` keeps its decodable content."""

    def test_decode_bytes_tries_both_bases(self):
        self.assertEqual(
            notify_channels._decode_bytes(LyingBytearray(b"hello")), "hello")
        self.assertEqual(notify_channels._decode_bytes(b"plain"), "plain")
        self.assertEqual(
            notify_channels._decode_bytes(bytearray(b"array")), "array")
        # A total impostor (no bytes storage at all) still degrades to "".
        class TotalImpostor:
            @property
            def __class__(self):  # noqa: D105
                return bytes
        self.assertEqual(notify_channels._decode_bytes(TotalImpostor()), "")

    def test_lying_bytearray_name_and_topic_render_their_real_text(self):
        # Pre-fix: the claimed-base pick erased "real-name" to "" and the
        # name fell back to the id — decodable content lost at the wrong
        # rank; the topic vanished the same way.
        self.plant(_notify_cfg({"channels": [
            _row(name=LyingBytearray(b"real-name"),
                 topic=LyingBytearray(b"real-topic"))]}))
        rows = {c["id"]: c for c in self.listed()}
        self.assertEqual(rows["c1"]["name"], "real-name")
        self.assertEqual(rows["c1"]["config"]["topic"], "real-topic")
        self.sweep_channel_routes("lying bytearray fields")


class ControlFlowPassthroughPins(unittest.TestCase):
    """Genuine control flow must keep propagating through every guard."""

    def test_guards_reraise_keyboard_interrupt(self):
        with self.assertRaises(KeyboardInterrupt):
            notify_channels._isa(CtrlCClassProp(), dict)
        with self.assertRaises(KeyboardInterrupt):
            notify_channels._truthy(CtrlCBool())
        with self.assertRaises(KeyboardInterrupt):
            notify_channels._id_text(CtrlCStr())
        with self.assertRaises(KeyboardInterrupt):
            notify_channels._utf8_text(CtrlCStr())
        with self.assertRaises(KeyboardInterrupt):
            notify_channels._json_safe({"k": CtrlCStr()})

    def test_send_via_reraises_control_flow(self):
        def ctrl_c_sender(*_a, **_k):
            raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            notify_channels._send_via(
                ctrl_c_sender, _row(), {}, "t", "m", level=None, event=None)


class StaysImmunePins(_Notify12Sandbox):
    """Wave-12 shapes the hunt probed and found already sealed stay that way."""

    def test_get_baseexc_bomb_subclass_row_keeps_its_sane_data(self):
        # _plain_row's unbound dict.items copy never runs the override, so
        # the BaseException-raising ``.get`` never fires at all.
        self.plant(_notify_cfg({"channels": [
            GetBaseExcRow(_row()), _row(id="ok1")]}))
        self.sweep_channel_routes("get base-exc subclass row")
        self.assert_dispatch_contract("get base-exc subclass row")
        rows = {c["id"]: c for c in self.listed()}
        self.assertIn("c1", rows)
        self.assertEqual(rows["c1"]["config"].get("topic"), "t")

    def test_iter_baseexc_bomb_channels_list_still_walks(self):
        # Unbound list.__iter__ bypasses the override: the real rows walk.
        self.plant(_notify_cfg({"channels": IterBaseExcList([_row()])}))
        self.sweep_channel_routes("iter base-exc channels list")
        self.assertEqual([c["id"] for c in self.listed()], ["c1"])

    def test_shadow_key_with_baseexc_eq_drops_without_comparing(self):
        # Non-str keys drop in _plain_row before any lookup ever compares
        # against the stored key — the BaseException __eq__ never runs.
        row = _row()
        row.pop("id")
        row[ObjShadowBaseExcKey("id")] = "c1"
        self.plant(_notify_cfg({"channels": [row, _row(id="ok1")]}))
        self.sweep_channel_routes("shadow key base-exc eq")
        self.assert_dispatch_contract("shadow key base-exc eq")
        self.assertEqual([c["id"] for c in self.listed()], ["ok1"])


class EverythingAtOncePins(_Notify12Sandbox):
    """All the twelfth-wave shapes in one store: no crack between guards."""

    def test_combined_store_every_route_survives(self):
        row = _row(id="c1")
        row.pop("id")
        row[ObjShadowBaseExcKey("id")] = "c1"
        self.plant(_notify_cfg({
            "ha_token": BoolBaseExcBomb(),
            "channels": IterBaseExcList([
                ClassPropBaseExcBomb(),
                row,
                _row(id="c1", enabled=BoolBaseExcBomb(),
                     min_level=StrBaseExcBomb(),
                     topic=LyingBytearray(b"real-topic")),
                _row(id="ok1", enabled=True),
            ]),
        }))
        self.sweep_channel_routes("combined")
        self.assert_dispatch_contract("combined")
        rows = {c["id"]: c for c in self.listed()}
        self.assertIn("ok1", rows)
        self.assertIn("c1", rows)
        self.assertEqual(rows["c1"]["config"]["topic"], "real-topic")
        self.assertEqual(rows["c1"]["min_level"], "warn")


if __name__ == "__main__":
    unittest.main(verbosity=2)
