"""Tenth leftover-500s sweep of the usage / Spotlight / stale-runtime surfaces.

Re-probing ``create_app()`` with ``raise_server_exceptions=False`` found two
live families the usage3–usage9 batteries never carried:

* **Hash-shadowing result keys** on POST /api/storage/spotlight: usage6's
  ``dict()`` copy launders a dict-*subclass*, but the plain copy still
  *carries* a hostile key — a leftover str-subclass whose ``__hash__``
  answers a real key's bucket while its ``__eq__`` raises detonated every
  later probe of that bucket.  Five distinct raw 500s, all after run_admin
  had already answered: ``result["volume"] = target`` and the ``enabled``
  write on the ok path, ``result.get("ok")`` (and the ``result["ok"] =
  False`` retry *inside its own except handler*), and the
  ``result.get("error")`` / ``result.get("message")`` reads of the vanish
  classification.  ``set_spotlight`` now rebuilds the copy through
  ``dict.items`` with exact-str keys (``_exact_str``), so every downstream
  bucket probe runs base ``__hash__``/``__eq__`` only.

* **Raising stat descriptors** on the walk routes: usage's digit-catalog pins
  poisoned stat *values* (over-cap ints, inf), but a poisoned entry whose
  ``st_size``/``st_mtime``/``name``/``path`` descriptor *raises
  RuntimeError* sailed past every narrow ``(OSError, ValueError,
  TypeError)`` catch.  On /tree that was a raw 500; on /largest and
  /duplicates it was strictly worse — the raise killed one
  ``_walk_parallel`` worker before it could reach the all-idle rule, the
  surviving workers waited on the condition forever, and the request hung
  past every budget (a deadline cannot fire a thread parked in
  ``cond.wait``).  The per-entry catches are now total, ``_safe_bytes``
  absorbs any raise, ``run()`` carries a ``_stop()`` backstop, and the
  queued path is an exact-str base copy so the sorts and ``Path()`` calls
  downstream run base operations only.

The stale-runtime side degrades field-level too: a listing whose
``pid_for`` raises — or a pid whose ``__int__`` raises RuntimeError — used
to collapse the whole scan (health's guard turned every healthy agent's
row into the generic warn shape); the poisoned agent now drops alone.
"""
from __future__ import annotations

import json
import os
import plistlib
import sys
import tempfile
import time
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from hub import stale_runtime, usage_svc  # noqa: E402
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


class _ShadowKey(str):
    """Occupies a real key's hash bucket; the ``__eq__`` probe raises.

    Every dict lookup or insert whose hash lands in the shadowed bucket must
    compare against this stored key first — and the comparison detonates.
    """

    _h: int

    def __new__(cls, shadow: str):
        self = str.__new__(cls, "\x00shadow:" + shadow)
        self._h = hash(shadow)
        return self

    def __hash__(self):
        return self._h

    def __eq__(self, other):
        raise RuntimeError("shadow eq bomb")


class _IntBomb(int):
    """An int subclass whose conversions raise RuntimeError, the spelling
    the old ``(TypeError, ValueError, OverflowError, OSError)`` catches
    never anticipated."""

    def __int__(self):
        raise RuntimeError("int bomb")

    def __index__(self):
        raise RuntimeError("index bomb")


class _NumBombObj:
    """A leftover stat number whose every numeric probe raises RuntimeError."""

    def __float__(self):
        raise RuntimeError("float bomb")

    def __int__(self):
        raise RuntimeError("int bomb")

    def __index__(self):
        raise RuntimeError("index bomb")


class _LyingIntClass:
    """A lying ``__class__`` claiming int: passes ``_isa`` gates, then blows
    the unbound descriptors of anything that trusts the claim."""

    @property
    def __class__(self):
        return int


class _LtBombStr(str):
    """Passes every str gate; comparison operators raise — the sort bomb."""

    def __lt__(self, other):
        raise RuntimeError("lt bomb")

    def __gt__(self, other):
        raise RuntimeError("gt bomb")


class _PoisonedEntry:
    """Delegates to a real DirEntry but plants chosen stat/path leftovers."""

    def __init__(self, entry, size=None, mtime=None, pathobj=None):
        self._entry = entry
        self._size = size
        self._mtime = mtime
        self._pathobj = pathobj

    def __getattr__(self, name):
        return getattr(self._entry, name)

    @property
    def name(self):
        return self._entry.name

    @property
    def path(self):
        return self._entry.path if self._pathobj is None else self._pathobj

    def stat(self, follow_symlinks=True):
        st = self._entry.stat(follow_symlinks=follow_symlinks)
        return mock.Mock(
            st_size=st.st_size if self._size is None else self._size,
            st_mtime=st.st_mtime if self._mtime is None else self._mtime,
            st_mode=st.st_mode,
        )


class _NamePathBombEntry:
    """A leftover DirEntry whose ``name``/``path`` properties raise."""

    def __init__(self, entry):
        self._entry = entry

    @property
    def name(self):
        raise RuntimeError("name bomb")

    @property
    def path(self):
        raise RuntimeError("path bomb")

    def __getattr__(self, name):
        return getattr(self._entry, name)

    def stat(self, follow_symlinks=True):
        return self._entry.stat(follow_symlinks=follow_symlinks)


class _ScandirResult:
    """os.scandir's return is both a context manager and an iterator."""

    def __init__(self, entries):
        self._entries = entries

    def __enter__(self):
        return iter(self._entries)

    def __exit__(self, *exc):
        return False

    def __iter__(self):
        return iter(self._entries)


_WALK_ROUTES = ("tree", "largest", "duplicates")


class SpotlightHashShadowKeyTests(unittest.TestCase):
    """The five raw 500s: a hash-shadowing key riding a run_admin result
    detonated every later probe of its bucket on POST /api/storage/spotlight."""

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
                "/api/storage/spotlight",
                json={"volume": "/", "enabled": True})

    def test_shadowed_volume_write_keeps_the_ok_contract(self):
        """Pre-fix ``result["volume"] = target`` probed the shadowed bucket
        and 500'd raw after a *successful* toggle."""
        resp = self._toggle({"ok": True, _ShadowKey("volume"): 1})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertIs(body["ok"], True)
        self.assertEqual(body["volume"], "/")
        self.assertIs(body["enabled"], True)

    def test_shadowed_enabled_write_keeps_the_ok_contract(self):
        resp = self._toggle({"ok": True, _ShadowKey("enabled"): 1})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertIs(body["ok"], True)
        self.assertIs(body["enabled"], True)

    def test_shadowed_ok_read_answers_the_coded_admin_failed(self):
        """Pre-fix ``result.get("ok")`` raised, and the ``result["ok"] =
        False`` retry *inside the except handler* raised again — a raw 500
        born inside the guard built to absorb the first one."""
        resp = self._toggle({_ShadowKey("ok"): 1, "other": 2})
        self.assertEqual(resp.status_code, 500, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["detail"]["code"], "admin.failed")

    def test_shadowed_error_read_answers_the_coded_admin_failed(self):
        """Pre-fix the vanish classification's ``result.get("error")`` sat
        outside any try and 500'd the failure path raw."""
        resp = self._toggle({"ok": False, _ShadowKey("error"): 1})
        self.assertEqual(resp.status_code, 500, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["detail"]["code"], "admin.failed")

    def test_shadowed_message_read_answers_the_coded_admin_failed(self):
        """Same seam one read later — and the unreadable message must not
        borrow the vanished-CLI 503 even with mdutil genuinely gone: the
        coded 503 fires only on a confirmed marker *and* disk probe."""
        resp = self._toggle(
            {"ok": False, "error": "failed", _ShadowKey("message"): 1},
            on_disk=False)
        self.assertEqual(resp.status_code, 500, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["detail"]["code"], "admin.failed")

    def test_vanish_classification_still_fires_after_the_laundering(self):
        """The exact-str rebuild must not cost the mdutil_missing 503: a
        genuine vanish-shaped failure with mdutil confirmed gone keeps its
        coded 503 through the laundered copy."""
        resp = self._toggle(
            {"ok": False, "error": "failed",
             "message": "sh: /usr/bin/mdutil: command not found"},
            on_disk=False)
        self.assertEqual(resp.status_code, 503, resp.text[:200])
        self.assertEqual(resp.json()["detail"]["code"], "usage.mdutil_missing")


class _WalkRig(unittest.TestCase):
    """A real two-file root with a poisoned scandir over it."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="usage10-"))
        (self.root / "a.bin").write_bytes(b"x" * 2048)
        (self.root / "b.bin").write_bytes(b"y" * 2048)
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        for child in self.root.iterdir():
            child.unlink()
        self.root.rmdir()

    def _poisoned_scandir(self, only=None, namebomb=False, **kw):
        real_scandir = os.scandir

        def scandir(path):
            with real_scandir(path) as it:
                entries = []
                for e in it:
                    poison = e.is_file(follow_symlinks=False) and (
                        only is None or e.name == only)
                    if poison and namebomb:
                        entries.append(_NamePathBombEntry(e))
                    elif poison:
                        entries.append(_PoisonedEntry(e, **kw))
                    else:
                        entries.append(e)
            return _ScandirResult(entries)

        return mock.patch.object(usage_svc.os, "scandir", scandir)

    def _get(self, route, **poison):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                usage_svc, "_resolve", lambda *a, **k: self.root))
            stack.enter_context(mock.patch.object(
                usage_svc, "scan_roots", lambda: []))
            stack.enter_context(self._poisoned_scandir(**poison))
            started = time.monotonic()
            resp = _client().get(f"/api/storage/usage/{route}")
            elapsed = time.monotonic() - started
        # The pre-fix /largest and /duplicates failure was not a 500 but a
        # *hang*: the raise killed one _walk_parallel worker and the rest
        # waited on the condition forever, past every budget.
        self.assertLess(elapsed, 15.0, f"{route} hung on a poisoned entry")
        return resp


class WalkRaisingStatDescriptorTests(_WalkRig):
    """RuntimeError-raising stat/path descriptors: /tree 500'd raw, /largest
    and /duplicates deadlocked a _walk_parallel worker and hung the request."""

    def _assert_ok(self, resp):
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        return body

    def test_runtime_error_st_size_reads_as_zero_on_every_walk_route(self):
        for route in _WALK_ROUTES:
            with self.subTest(route=route):
                body = self._assert_ok(self._get(route, size=_IntBomb(7)))
                if route == "tree":
                    files = [c for c in body["children"] if c["kind"] == "file"]
                    self.assertEqual(len(files), 2)
                    self.assertEqual({f["bytes"] for f in files}, {0})
                elif route == "largest":
                    self.assertEqual(
                        sorted(i["name"] for i in body["items"]),
                        ["a.bin", "b.bin"])
                    self.assertEqual({i["bytes"] for i in body["items"]}, {0})

    def test_raising_num_object_st_size_degrades_everywhere_too(self):
        for route in _WALK_ROUTES:
            with self.subTest(route=route):
                self._assert_ok(self._get(route, size=_NumBombObj()))

    def test_lying_int_class_st_size_reads_as_zero(self):
        """The impostor passes any isinstance-int gate through its lying
        ``__class__``; the conversion probes reject it and it reads 0."""
        for route in _WALK_ROUTES:
            with self.subTest(route=route):
                self._assert_ok(self._get(route, size=_LyingIntClass()))

    def test_runtime_error_st_mtime_renders_an_empty_stamp(self):
        """time.localtime's old (OverflowError, OSError, ValueError,
        TypeError) catch never anticipated a RuntimeError ``__float__``."""
        body = self._assert_ok(self._get("largest", mtime=_NumBombObj()))
        self.assertEqual(
            sorted(i["name"] for i in body["items"]), ["a.bin", "b.bin"])
        self.assertEqual({i["mtime"] for i in body["items"]}, {""})
        self.assertEqual({i["bytes"] for i in body["items"]}, {2048})

    def test_name_path_property_bomb_drops_its_entry_alone(self):
        """One poisoned entry, one healthy sibling: the sibling keeps
        rendering on every route while the bomb drops row-level."""
        for route in _WALK_ROUTES:
            with self.subTest(route=route):
                body = self._assert_ok(
                    self._get(route, only="a.bin", namebomb=True))
                if route == "tree":
                    files = [c for c in body["children"] if c["kind"] == "file"]
                    self.assertEqual([f["name"] for f in files], ["b.bin"])
                elif route == "largest":
                    self.assertEqual(
                        [i["name"] for i in body["items"]], ["b.bin"])

    def test_lt_bomb_str_path_cannot_blow_the_result_sorts(self):
        """The queued path is an exact-str base copy, so ``found.sort`` and
        ``sorted(matches)`` run base comparisons; the file still renders."""
        body = self._assert_ok(self._get(
            "largest", only="a.bin", pathobj=_LtBombStr("/zz/a.bin")))
        names = sorted(i["name"] for i in body["items"])
        self.assertEqual(names, ["a.bin", "b.bin"])
        self._assert_ok(self._get(
            "duplicates", only="a.bin", pathobj=_LtBombStr("/zz/a.bin")))

    def test_safe_bytes_absorbs_any_raise(self):
        self.assertEqual(usage_svc._safe_bytes(_IntBomb(7)), 0)
        self.assertEqual(usage_svc._safe_bytes(_NumBombObj()), 0)
        self.assertEqual(usage_svc._safe_bytes(_LyingIntClass()), 0)
        self.assertEqual(usage_svc._safe_bytes(2048), 2048)


class ExactStrHelperTests(unittest.TestCase):
    """_exact_str: base copies that keep real bytes and shed overrides."""

    def test_exact_str_passes_through_untouched(self):
        s = "movie \udcff.mkv"  # surrogateescape'd real filename byte
        self.assertIs(usage_svc._exact_str(s), s)

    def test_subclass_copies_to_base_str_preserving_surrogates(self):
        out = usage_svc._exact_str(_LtBombStr("a\udcffb"))
        self.assertIs(type(out), str)
        self.assertEqual(out, "a\udcffb")

    def test_shadow_key_copy_carries_base_hash_and_eq(self):
        out = usage_svc._exact_str(_ShadowKey("volume"))
        self.assertIs(type(out), str)
        d = {out: 1}
        d["volume"] = 2  # same bucket probe that used to detonate
        self.assertEqual(d["volume"], 2)

    def test_non_str_and_lying_class_read_as_none(self):
        self.assertIsNone(usage_svc._exact_str(5))
        self.assertIsNone(usage_svc._exact_str(None))
        self.assertIsNone(usage_svc._exact_str(b"bytes"))


class StaleRuntimeFieldLevelDegradeTests(unittest.TestCase):
    """A poisoned agent drops alone from scan(); its healthy sibling keeps
    its warning row instead of the whole check collapsing to exc detail."""

    class _PidIntBomb:
        def __bool__(self):
            return True

        def __int__(self):
            raise RuntimeError("pid int bomb")

        def __index__(self):
            raise RuntimeError("pid index bomb")

    def _scan(self, listing):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "local.bombed.plist").write_bytes(
                plistlib.dumps({"Label": "local.bombed"}))
            (Path(tmp) / "local.healthy.plist").write_bytes(
                plistlib.dumps({"Label": "local.healthy"}))
            with (
                mock.patch.object(stale_runtime, "AGENTS_DIR", Path(tmp)),
                mock.patch.object(
                    stale_runtime, "launchd_listing", lambda: listing),
                mock.patch.object(
                    stale_runtime, "pid_exe_path",
                    lambda pid: "/gone/python3.12"),
            ):
                return stale_runtime.scan()

    def test_raising_pid_for_drops_the_poisoned_agent_alone(self):
        class _Listing:
            def pid_for(self, label):
                if label == "local.bombed":
                    raise RuntimeError("pid_for bomb")
                return 4242

        rows = self._scan(_Listing())
        _starlette(rows)
        self.assertEqual([r["label"] for r in rows], ["local.healthy"])
        self.assertEqual(rows[0]["pid"], 4242)

    def test_bool_bomb_pid_truthiness_drops_the_agent_alone(self):
        class _BoolBombPid:
            def __bool__(self):
                raise RuntimeError("bool bomb")

        bomb = _BoolBombPid()

        class _Listing:
            def pid_for(self, label):
                return bomb if label == "local.bombed" else 4242

        rows = self._scan(_Listing())
        _starlette(rows)
        self.assertEqual([r["label"] for r in rows], ["local.healthy"])

    def test_runtime_error_pid_int_reads_as_unknown_not_a_raise(self):
        bomb = self._PidIntBomb()

        class _Listing:
            def pid_for(self, label):
                return bomb if label == "local.bombed" else 4242

        rows = self._scan(_Listing())
        _starlette(rows)
        by_label = {r["label"]: r for r in rows}
        # The bombed agent still warns (its exe is confirmed gone); only its
        # unreadable pid degrades to the 0 sentinel.
        self.assertEqual(by_label["local.bombed"]["pid"], 0)
        self.assertEqual(by_label["local.healthy"]["pid"], 4242)

    def test_pid_exe_path_absorbs_a_runtime_error_pid(self):
        self.assertIsNone(stale_runtime.pid_exe_path(self._PidIntBomb()))


if __name__ == "__main__":
    unittest.main(verbosity=2)
