"""Ninth leftover-500s sweep of the usage / Spotlight surfaces.

usage8 sealed ``set_spotlight``'s known-volume gate and nas8 put ``_isa``
under every render probe.  Re-probing ``create_app()`` with
``raise_server_exceptions=False`` found exactly one raw 500 left on the
route: the ``run_admin`` call *itself*.  Every result shape run_admin can
answer is laundered (usage6's ``dict()`` copy, the ``_isa`` result gate,
``_truthy`` on ``ok``), but the call sat outside any guard, so a seam
replacement — or a leftover that slips run_admin's own guards and raises
out of the call — 500'd POST /api/storage/spotlight raw, one seam later
than the ``spotlight_status()`` call usage8 already guards.

The fix is the same guarded-call rule scan_roots applies to
``default_roots`` and usage8 applied to ``spotlight_status``: the raise
becomes the synthesized ``{"ok": False, "error": "failed", "message":
str(exc)}`` failure, which flows into the existing funnel — so a
spawn-of-a-gone-binary raise ("No such file or directory") still earns the
coded 503 *only after* the fresh disk probe confirms mdutil is really
gone, and any other raise keeps the coded ``admin.failed`` shape.

Everything else this sweep probed was already immune and is pinned here so
a regression cannot ship silently:

* a ``__class__``-property bomb result from run_admin answers the coded
  ``admin.failed`` body, never a raw 500 (the ``_isa`` result gate);
* junk *fields* riding an ok result — a nested ``__class__`` bomb, an
  over-cap already-int mapping key, a list-subclass ``__iter__`` bomb, an
  ``isoformat`` that answers ``inf`` — degrade alone through
  nas_common._jsonable while their sibling keys keep serving;
* an rc-*subclass* from sh() whose ``__index__``/``__bool__``/``__eq__``
  raise cannot 500 GET /api/storage/usage: ``_spotlight_query`` base-
  coerces rc under its guard, so the row still renders;
* the FIFO swapped in over a hashed path *after* the walk: ``_hash_file``'s
  O_NONBLOCK + S_ISREG gate answers None promptly instead of parking a
  fan_out worker (and the duplicates request) on a writerless open().
"""
from __future__ import annotations

import json
import os
import stat
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

from hub import usage_svc  # noqa: E402
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


#: An already-int past CPython's int->str digit cap, the way a YAML/plist
#: hex load produces one (``int(x, 16)`` is exempt from the parse cap).
_OVER_CAP_INT = int("9" * 4300, 16)


class _ClassBomb:
    """A leftover whose ``__class__`` is a raising property."""

    @property
    def __class__(self):
        raise RuntimeError("class bomb")


class _IterBombList(list):
    """Passes the isinstance gate; the bound ``__iter__`` raises."""

    def __iter__(self):
        raise RuntimeError("iter bomb")


class _IsoInf:
    """A leftover whose ``isoformat()`` answers ``inf`` instead of text."""

    def isoformat(self):
        return float("inf")


class _RcBombInt(int):
    """An int subclass whose bound probes all raise; only the C-level base
    operations (``int.__index__``, exact-int ``==``) can read it."""

    def __index__(self):
        raise RuntimeError("index bomb")

    def __bool__(self):
        raise RuntimeError("bool bomb")

    def __eq__(self, other):
        raise RuntimeError("eq bomb")

    def __hash__(self):
        return 0


class SpotlightRunAdminSeamTests(unittest.TestCase):
    """The one raw 500 this sweep found: run_admin raising out of the call
    itself, the only unguarded seam left on POST /api/storage/spotlight."""

    def _toggle(self, *, raises, on_disk=False):
        with ExitStack() as stack:
            _admin_browser(stack)
            stack.enter_context(mock.patch.object(
                usage_svc, "spotlight_status",
                return_value=[{"volume": "/"}]))
            stack.enter_context(mock.patch(
                "hub.macos_admin.run_admin", side_effect=raises))
            stack.enter_context(mock.patch.object(
                usage_svc, "_mdutil_on_disk", return_value=on_disk))
            return _client().post(
                "/api/storage/spotlight",
                json={"volume": "/", "enabled": True})

    def test_raising_run_admin_answers_the_coded_admin_failed(self):
        """Pre-fix this was the raw ASGI 500 (a text/plain "Internal Server
        Error"); the guarded call keeps the coded JSON contract."""
        resp = self._toggle(raises=RuntimeError("seam bomb"))
        self.assertEqual(resp.status_code, 500, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["detail"]["code"], "admin.failed")
        self.assertIn("seam bomb", body["detail"]["params"]["detail"])

    def test_spawn_raise_of_a_gone_mdutil_earns_503_after_disk_confirm(self):
        """A FileNotFoundError raised out of the seam reads exactly like the
        sh() sentinel: the vanish markers match and the fresh disk probe
        confirms, so the coded 503 fires — never a raw 500."""
        resp = self._toggle(
            raises=FileNotFoundError(
                2, "No such file or directory", usage_svc.MDUTIL),
            on_disk=False)
        self.assertEqual(resp.status_code, 503, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["detail"]["code"], "usage.mdutil_missing")

    def test_spawn_raise_with_mdutil_still_on_disk_keeps_admin_failed(self):
        """503 only after disk confirm: the same vanish-shaped raise with
        mdutil still present keeps the truthful admin.failed shape."""
        resp = self._toggle(
            raises=FileNotFoundError(
                2, "No such file or directory", usage_svc.MDUTIL),
            on_disk=True)
        self.assertEqual(resp.status_code, 500, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["detail"]["code"], "admin.failed")

    def test_non_vanish_raise_never_reclassifies_to_503(self):
        """A raise whose text carries no spawn marker must not borrow the
        vanished-CLI shape even with mdutil genuinely gone from disk."""
        resp = self._toggle(raises=OSError(12, "Cannot allocate memory"),
                            on_disk=False)
        self.assertEqual(resp.status_code, 500, resp.text[:200])
        self.assertEqual(resp.json()["detail"]["code"], "admin.failed")


class RunAdminResultShapeStaysImmunePins(unittest.TestCase):
    """Result shapes the probe proved immune, pinned against regression."""

    def _toggle(self, result):
        with ExitStack() as stack:
            _admin_browser(stack)
            stack.enter_context(mock.patch.object(
                usage_svc, "spotlight_status",
                return_value=[{"volume": "/"}]))
            stack.enter_context(mock.patch(
                "hub.macos_admin.run_admin", return_value=result))
            return _client().post(
                "/api/storage/spotlight",
                json={"volume": "/", "enabled": True})

    def test_class_bomb_result_answers_the_coded_admin_failed(self):
        """The _isa result gate: a ``__class__``-property bomb result reads
        as not-a-dict and takes the coded failure, never a raw 500."""
        resp = self._toggle(_ClassBomb())
        self.assertEqual(resp.status_code, 500, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["detail"]["code"], "admin.failed")

    def test_junk_fields_on_an_ok_result_degrade_alone(self):
        """nas_common._jsonable per-field: the bombs drop or scrub while
        every sibling key — and the toggle's own contract — keeps serving."""
        resp = self._toggle({
            "ok": True,
            "nested": {"deep": _ClassBomb(), "kept": "yes"},
            "rows": _IterBombList([1, 2]),
            "when": _IsoInf(),
            "surr": "a\ud800b",
        })
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertIs(body["ok"], True)
        self.assertEqual(body["volume"], "/")
        self.assertIs(body["enabled"], True)
        # The class bomb scrubs to text through the final _utf8_text probe;
        # its healthy sibling key survives untouched.
        self.assertEqual(body["nested"]["kept"], "yes")
        self.assertIsInstance(body["nested"]["deep"], str)
        # base.__iter__ walks the bombed subclass's real C-level storage.
        self.assertEqual(body["rows"], [1, 2])
        # isoformat() answering inf lands in the float sanitizer, not the
        # encoder.
        self.assertIsNone(body["when"])
        self.assertNotIn("\ud800", resp.text)

    def test_over_cap_int_mapping_key_drops_its_pair_alone(self):
        """The dict-subclass / hostile mapping-key class: a key past the
        int->str digit cap cannot be rendered, so its pair drops while the
        sibling key keeps serving — never a 500 out of the encoder."""
        resp = self._toggle({"ok": True, _OVER_CAP_INT: "x", "kept": "yes"})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertIs(body["ok"], True)
        self.assertEqual(body["kept"], "yes")
        self.assertNotIn("x", set(body.values()))


class SpotlightRcSubclassStaysImmunePins(unittest.TestCase):
    """rc-subclass probes out of sh(): _spotlight_query base-coerces rc
    under its guard, so GET /api/storage/usage keeps rendering rows."""

    def _overview(self, sh_result):
        with mock.patch.object(usage_svc, "sh", return_value=sh_result):
            return _client().get("/api/storage/usage")

    def test_rc_bomb_subclass_row_still_renders_its_state(self):
        resp = self._overview((_RcBombInt(3), "Indexing enabled.", ""))
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        rows = {row["volume"]: row for row in body["spotlight"]}
        self.assertEqual(rows["/"]["state"], "enabled")
        self.assertIs(rows["/"]["readable"], False)

    def test_rc_bomb_zero_still_reads_as_readable(self):
        """The base coercion keeps a *healthy* subclass zero meaning rc==0,
        so the hardening cannot flip a readable volume to unreadable."""
        resp = self._overview((_RcBombInt(0), "Indexing enabled.", ""))
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        rows = {row["volume"]: row for row in resp.json()["spotlight"]}
        self.assertIs(rows["/"]["readable"], True)

    def test_over_cap_int_rc_never_reaches_the_encoder(self):
        """rc is consumed as ``rc == 0`` only; an over-cap already-int rc
        renders its row without the digit-cap ValueError."""
        resp = self._overview((_OVER_CAP_INT, "Indexing enabled.", ""))
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        rows = {row["volume"]: row for row in body["spotlight"]}
        self.assertIs(rows["/"]["readable"], False)


@unittest.skipUnless(hasattr(os, "mkfifo"), "mkfifo not available")
class FifoHashStageStaysImmunePin(unittest.TestCase):
    """The post-walk FIFO swap: usage5 pinned that a FIFO in the tree is
    never queued, but the hash stages run *after* the walk, and a FIFO
    occupying a queued path by then used to park the plain open() until a
    writer appeared.  The O_NONBLOCK + S_ISREG gate answers None promptly."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="usage9-fifo-"))
        self.fifo = self.root / "swapped.bin"
        os.mkfifo(self.fifo)
        self.assertTrue(stat.S_ISFIFO(os.stat(self.fifo).st_mode))

    def tearDown(self):
        try:
            self.fifo.unlink()
            self.root.rmdir()
        except OSError:
            pass

    def test_hash_file_answers_none_promptly_for_a_fifo(self):
        started = time.monotonic()
        self.assertIsNone(usage_svc._hash_file(self.fifo, partial=True))
        self.assertIsNone(usage_svc._hash_file(self.fifo, partial=False))
        # A blocked open() would sit here until a writer appeared; the
        # budget deadline cannot fire inside a blocked syscall.
        self.assertLess(time.monotonic() - started, 5.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
