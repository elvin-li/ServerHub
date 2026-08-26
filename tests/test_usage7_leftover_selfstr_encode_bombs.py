"""Seventh leftover-500s sweep of the usage / snapshots / Spotlight surfaces.

usage6 sealed the seam-scrub classes (dict-subclass ``.get``/``__setitem__``
/``__bool__`` bombs, unbound ``int.__index__`` / ``float.__float__`` / base
``bytes.decode`` in the nested coercions).  Re-probing ``create_app()`` with
``raise_server_exceptions=False`` found one convention both module ``_as_text``
copies still missed: the unbound ``str.encode`` that ``nas_common._utf8_text``
(the modules6 rule) already carries.  ``str()`` of a subclass whose ``__str__``
answers *self* skips CPython's exact-str copy, so the bound
``value.encode("utf-8", "replace")`` tail ran the subclass override.  Every
shape here was a live unhandled 500 pre-fix:

* ``snapshots_svc._as_text``: an encode-bomb str subclass in sh() output
  raised out of ``_plist`` and 500'd GET /api/snapshots, out of
  ``create_snapshot``'s message join and 500'd POST /api/snapshots/create,
  and — as a nested key *or* value in a run_admin result — out of
  ``_jsonable``'s dict walk and 500'd POST /api/timemachine/action,
  /api/snapshots/delete and /api/snapshots/thin.

* ``usage_svc._as_text``: an encode-bomb error / message string in the raw
  run_admin payload raised out of ``set_spotlight``'s vanish classification
  (which reads both through ``_as_text`` *after* the dict copy) and 500'd
  POST /api/storage/spotlight in place of the coded refusal; an encode
  override that *returned* a hostile buffer walked its own str subclass back
  out of ``_spotlight_query`` and 500'd GET /api/storage/usage one frame
  later, at ``blob.lower()`` in ``spotlight_status``.

* ``usage_svc.scan_roots``: the same bomb as a root id/name fired inside the
  per-row guard, so the row silently vanished from every usage route's roots
  — the silent-loss sibling of the share-name digit-cap drop usage5 fixed.

The base pair ``bytes.decode(str.encode(value, "utf-8", "replace"), "utf-8")``
answers an exact str always, so no override can fire and downstream bound
calls (``.strip()`` / ``.lower()`` / the encoder walk) operate on real text.
The rest pins neighbours the probe proved immune so a regression cannot ship
silently: surrogates inside the subclass scrub to "?", an over-cap
already-int keeps earning its coded refusal, and the confirmed-vanished
mdutil classification still answers its 503 through an encode-bomb message.
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

from hub import snapshots_svc, usage_svc  # noqa: E402
from hub.routers import nas_common, nas_storage  # noqa: E402

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


def _admin_browser(stack: ExitStack) -> None:
    """An administrator browser session, as nas_common resolves one."""
    stack.enter_context(mock.patch.object(
        nas_common.auth, "browser_authenticated", return_value=True))
    stack.enter_context(mock.patch.object(
        nas_common.auth, "request_username", return_value="admin"))
    stack.enter_context(mock.patch.object(
        nas_common.auth, "is_admin", return_value=True))
    stack.enter_context(mock.patch.object(
        nas_common.auth, "request_client_id", return_value="127.0.0.1"))
    stack.enter_context(mock.patch.object(
        nas_storage.audit, "record", lambda *a, **k: {}))


class _SelfStrEncodeBomb(str):
    """``str()`` answers self (subclass survives); the bound ``.encode``
    raises — the modules6 class both ``_as_text`` copies missed."""

    def __str__(self):
        return self

    def encode(self, *args, **kwargs):
        raise RuntimeError("encode bomb")


class _EvilBytes(bytes):
    """The returned buffer of the returns-hostile chain: its ``.decode``
    hands back another hostile str subclass instead of raising."""

    def decode(self, *args, **kwargs):
        return _LowerBombStr(bytes.decode(self, "utf-8", "replace"))


class _LowerBombStr(str):
    """encode *returns* a hostile buffer (no raise inside _spotlight_query's
    guard), strip answers self, and the bomb only fires downstream at the
    unguarded ``blob.lower()``."""

    def __str__(self):
        return self

    def encode(self, *args, **kwargs):
        return _EvilBytes(str.encode(str.__str__(self)[:], "utf-8", "replace"))

    def strip(self, *args):
        return self

    def lower(self):
        raise RuntimeError("lower bomb")


#: A real listSnapshots plist with one deletable snapshot.
_SNAP_PLIST = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Snapshots</key><array>
    <dict>
      <key>SnapshotName</key><string>com.apple.TimeMachine.2026-08-03-160000.local</string>
      <key>SnapshotUUID</key><string>AAAA-BBBB</string>
      <key>SnapshotXID</key><integer>7</integer>
    </dict>
  </array>
</dict></plist>
"""


class SnapshotsEncodeBombHttpTests(unittest.TestCase):
    """snapshots_svc._as_text's bound-encode tail: each shape here raised
    out of the service and 500'd its route unhandled on the pre-fix tree."""

    def test_encode_bomb_plist_output_still_lists_the_snapshot(self):
        with mock.patch.object(
            snapshots_svc, "sh",
            return_value=(0, _SelfStrEncodeBomb(_SNAP_PLIST), ""),
        ):
            resp = _client().get("/api/snapshots", params={"force": "true"})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        names = [
            snap["name"]
            for volume in body["volumes"]
            for snap in volume["snapshots"]
        ]
        self.assertIn("com.apple.TimeMachine.2026-08-03-160000.local", names)

    def _tm_action(self, result):
        with ExitStack() as stack:
            _admin_browser(stack)
            stack.enter_context(mock.patch.object(
                snapshots_svc, "run_admin", return_value=result))
            return _client().post(
                "/api/timemachine/action", json={"action": "enable"})

    def test_nested_encode_bomb_value_keeps_its_real_text(self):
        resp = self._tm_action({"ok": True, "note": _SelfStrEncodeBomb("x")})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["note"], "x")

    def test_nested_encode_bomb_key_keeps_its_real_text(self):
        resp = self._tm_action({"ok": True, _SelfStrEncodeBomb("k"): "v"})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertEqual(resp.json()["k"], "v")

    def test_create_failure_with_encode_bomb_stdout_answers_coded(self):
        """Pre-fix an unhandled 500 with no body; the honest answer is the
        coded admin.failed carrying the command's real text as detail."""
        with ExitStack() as stack:
            _admin_browser(stack)
            stack.enter_context(mock.patch.object(
                snapshots_svc, "sh",
                return_value=(1, _SelfStrEncodeBomb("boom"), "")))
            stack.enter_context(mock.patch.object(
                snapshots_svc, "_tmutil_on_disk", return_value=True))
            resp = _client().post("/api/snapshots/create")
        self.assertEqual(resp.status_code, 500, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["detail"]["code"], "admin.failed")
        self.assertEqual(body["detail"]["params"]["detail"], "boom")

    def test_create_success_with_encode_bomb_stdout_answers_ok(self):
        with ExitStack() as stack:
            _admin_browser(stack)
            stack.enter_context(mock.patch.object(
                snapshots_svc, "sh",
                return_value=(0, _SelfStrEncodeBomb("Created local snapshot"), "")))
            resp = _client().post("/api/snapshots/create")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertIs(body["ok"], True)
        self.assertEqual(body["message"], "Created local snapshot")


class SpotlightEncodeBombHttpTests(unittest.TestCase):
    """usage_svc._as_text's bound-encode tail on the spotlight surfaces."""

    def _toggle(self, result, *, on_disk=True):
        with ExitStack() as stack:
            _admin_browser(stack)
            stack.enter_context(mock.patch.object(
                usage_svc, "spotlight_status",
                return_value=[{"volume": "/"}]))
            stack.enter_context(mock.patch(
                "hub.macos_admin.run_admin", return_value=result))
            stack.enter_context(mock.patch.object(
                usage_svc, "_mdutil_on_disk", return_value=on_disk))
            return _client().post(
                "/api/storage/spotlight", json={"volume": "/", "enabled": True})

    def test_encode_bomb_error_string_keeps_the_coded_shape(self):
        """The vanish classification reads error through _as_text after the
        dict copy; the bomb raised there pre-fix, an unhandled 500."""
        resp = self._toggle({"ok": False, "error": _SelfStrEncodeBomb("failed")})
        self.assertEqual(resp.status_code, 500, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["detail"]["code"], "admin.failed")

    def test_encode_bomb_message_keeps_the_coded_shape(self):
        resp = self._toggle({
            "ok": False, "error": "failed",
            "message": _SelfStrEncodeBomb("boom"),
        })
        self.assertEqual(resp.status_code, 500, resp.text[:200])
        body = resp.json()
        self.assertEqual(body["detail"]["code"], "admin.failed")
        self.assertEqual(body["detail"]["params"]["detail"], "boom")

    def test_vanish_classification_reads_through_the_encode_bomb(self):
        """The marker text inside a bomb subclass still classifies: the
        coded 503 fires once the fresh disk probe confirms mdutil is gone."""
        resp = self._toggle(
            {
                "ok": False, "error": "failed",
                "message": _SelfStrEncodeBomb(
                    "sh: /usr/bin/mdutil: command not found"),
            },
            on_disk=False,
        )
        self.assertEqual(resp.status_code, 503, resp.text[:200])
        self.assertEqual(resp.json()["detail"]["code"], "usage.mdutil_missing")

    def test_returns_hostile_chain_in_sh_output_renders_its_row(self):
        """An encode that *returns* a hostile buffer used to walk its str
        subclass out of _spotlight_query and 500 GET /api/storage/usage at
        the unguarded ``blob.lower()``."""
        with mock.patch.object(
            usage_svc, "sh",
            return_value=(0, _LowerBombStr("Indexing enabled."), ""),
        ):
            resp = _client().get("/api/storage/usage")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        states = {row["volume"]: row["state"] for row in body["spotlight"]}
        self.assertEqual(states["/"], "enabled")

    def test_raising_encode_bomb_sh_output_stays_immune(self):
        with mock.patch.object(
            usage_svc, "sh",
            return_value=(0, _SelfStrEncodeBomb("Indexing disabled."), ""),
        ):
            resp = _client().get("/api/storage/usage")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        states = {r["volume"]: r["state"] for r in resp.json()["spotlight"]}
        self.assertEqual(states["/"], "disabled")


class ScanRootsEncodeBombRowTests(unittest.TestCase):
    """A bomb root id/name used to fire inside the per-row guard and drop
    the whole row from every usage route's roots — silent loss, the
    sibling of the share-name digit-cap drop usage5 fixed."""

    def test_encode_bomb_root_id_row_survives_with_its_text(self):
        with mock.patch.object(
            usage_svc.files_svc, "default_roots",
            return_value=[{
                "id": _SelfStrEncodeBomb("svc"),
                "name": _SelfStrEncodeBomb("Services"),
                "path": "/tmp",
            }],
        ):
            roots = usage_svc.scan_roots()
        _starlette(roots)
        by_path = {r["path"]: r for r in roots}
        self.assertIn("/tmp", by_path)
        self.assertEqual(by_path["/tmp"]["id"], "svc")
        self.assertEqual(by_path["/tmp"]["name"], "Services")

    def test_encode_bomb_share_name_row_survives_with_its_text(self):
        from hub import shares_svc

        with (
            mock.patch.object(
                usage_svc.files_svc, "default_roots", return_value=[]),
            mock.patch.object(
                shares_svc, "list_smb_shares",
                return_value=[{"name": _SelfStrEncodeBomb("media"), "path": "/tmp"}]),
        ):
            roots = usage_svc.scan_roots()
        _starlette(roots)
        self.assertIn("share-media", [r["id"] for r in roots])


class AsTextUnitContractTests(unittest.TestCase):
    """Both module copies answer an exact str for every leftover shape."""

    def test_encode_bomb_subclass_answers_its_exact_text(self):
        for as_text in (usage_svc._as_text, snapshots_svc._as_text):
            with self.subTest(fn=as_text.__module__):
                out = as_text(_SelfStrEncodeBomb("ok"))
                self.assertEqual(out, "ok")
                self.assertIs(type(out), str)

    def test_returns_hostile_chain_answers_an_exact_str(self):
        for as_text in (usage_svc._as_text, snapshots_svc._as_text):
            with self.subTest(fn=as_text.__module__):
                out = as_text(_LowerBombStr("x"))
                self.assertEqual(out, "x")
                self.assertIs(type(out), str)

    def test_surrogate_inside_the_bomb_subclass_scrubs(self):
        for as_text in (usage_svc._as_text, snapshots_svc._as_text):
            with self.subTest(fn=as_text.__module__):
                out = as_text(_SelfStrEncodeBomb("a\ud800b"))
                self.assertEqual(out, "a?b")
                _starlette({"v": out})

    def test_over_cap_already_int_keeps_its_empty_scrub(self):
        for as_text in (usage_svc._as_text, snapshots_svc._as_text):
            with self.subTest(fn=as_text.__module__):
                self.assertEqual(as_text(10 ** 5000), "")

    def test_in_process_encode_bomb_volume_earns_the_coded_refusal(self):
        """set_spotlight is also called in-process: the junk volume earns
        bad_volume (the raid/smart _req_text convention), never a raise."""
        with mock.patch.object(
            usage_svc, "spotlight_status", return_value=[{"volume": "/"}],
        ):
            result = usage_svc.set_spotlight(_SelfStrEncodeBomb("/nope"), True)
        self.assertEqual(result, {"ok": False, "error": "bad_volume"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
