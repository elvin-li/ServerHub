"""Eighth leftover-500s sweep of the usage / Spotlight surfaces.

usage7 sealed the self-``__str__`` encode bombs in both ``_as_text`` copies.
Re-probing ``create_app()`` with ``raise_server_exceptions=False`` found one
consumer both it and usage6 missed: ``set_spotlight``'s known-volume gate.
The old set comprehension consumed the status listing raw ::

    known = {v.get("volume") for v in spotlight_status()
             if isinstance(v, dict) and isinstance(v.get("volume"), str)}

so every shape here was a live unhandled 500 on the pre-fix tree, all at
POST /api/storage/spotlight, all one line ahead of the coded ``bad_volume``
refusal the gate exists to answer:

* a list-*subclass* status listing whose ``__iter__`` raises (the iterbomb
  class) detonated the comprehension's implicit iteration;
* a dict-subclass row whose bound ``.get`` raises passed the ``isinstance``
  gate and blew up inside the filter;
* a str-subclass volume value whose ``__hash__`` raises detonated the set
  *build*, and one whose ``__eq__`` raises (with a colliding hash) detonated
  the ``target not in known`` membership probe;
* a status listing that raised outright took the route with it — the same
  raising-call seam class scan_roots already guards for default_roots.

The fix follows the nas_storage._known_mount rule: guarded call, base
``__iter__`` over the real C-level storage so healthy rows still serve,
unbound ``dict.get``, and ``_as_text`` so the set holds exact strs whose
hash/eq are the base ops.  "/" is pinned because spotlight_status always
reports the boot volume first, so it stays toggleable while a hostile
listing drops row by row.

scan_roots itself was probed and stays clean: its raising-call and per-row
bombs are usage5's pins (a hostile row costs itself, never the route) and
are deliberately not reopened here; the rest pins neighbours the probe
proved immune so a regression cannot ship silently.
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


class _IterBombList(list):
    """Passes the isinstance gate; the bound ``__iter__`` raises."""

    def __iter__(self):
        raise RuntimeError("iter bomb")


class _GetBombRow(dict):
    """Passes the isinstance gate; the bound ``.get`` raises."""

    def get(self, *args, **kwargs):
        raise RuntimeError("get bomb")


class _HashBombStr(str):
    """Real text; hashing it (the set *build*) raises."""

    def __hash__(self):
        raise RuntimeError("hash bomb")


class _EqBombStr(str):
    """Collides with "/" so the membership probe runs the raising ``__eq__``."""

    def __hash__(self):
        return hash("/")

    def __eq__(self, other):
        raise RuntimeError("eq bomb")


class SpotlightKnownVolumeBombHttpTests(unittest.TestCase):
    """Every shape here 500'd POST /api/storage/spotlight pre-fix, one line
    ahead of the gate's own coded ``bad_volume`` refusal."""

    def _toggle(self, listing, volume="/", *, call_raises=False):
        with ExitStack() as stack:
            _admin_browser(stack)
            if call_raises:
                stack.enter_context(mock.patch.object(
                    usage_svc, "spotlight_status",
                    side_effect=RuntimeError("status call bomb")))
            else:
                stack.enter_context(mock.patch.object(
                    usage_svc, "spotlight_status", return_value=listing))
            stack.enter_context(mock.patch(
                "hub.macos_admin.run_admin",
                return_value={"ok": True, "message": "done"}))
            return _client().post(
                "/api/storage/spotlight",
                json={"volume": volume, "enabled": True})

    def test_iterbomb_listing_still_serves_its_real_rows(self):
        """base.__iter__ walks the C-level storage: the healthy row inside
        the bombed subclass keeps its volume toggleable."""
        listing = _IterBombList([{"volume": "/Volumes/Media"}])
        resp = self._toggle(listing, "/Volumes/Media")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertIs(body["ok"], True)
        self.assertEqual(body["volume"], "/Volumes/Media")

    def test_get_bomb_row_still_serves_through_the_unbound_read(self):
        """dict.get reads the real storage, so the row's own volume stays
        toggleable instead of 500ing the route."""
        resp = self._toggle(
            [_GetBombRow(volume="/Volumes/Media")], "/Volumes/Media")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertIs(resp.json()["ok"], True)

    def test_hash_bomb_volume_value_still_serves_as_its_text(self):
        """_as_text copies to an exact str before the set add, so the base
        __hash__ runs and the volume stays toggleable."""
        resp = self._toggle(
            [{"volume": _HashBombStr("/Volumes/Media")}], "/Volumes/Media")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertIs(resp.json()["ok"], True)

    def test_eq_bomb_volume_beside_a_healthy_sibling_cannot_500(self):
        """The membership probe collides with the bomb's forged hash; the
        exact-str copy keeps the base __eq__ and the sibling toggles."""
        resp = self._toggle(
            [{"volume": _EqBombStr("/other")}, {"volume": "/"}], "/")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertIs(resp.json()["ok"], True)

    def test_raising_status_listing_keeps_the_boot_volume_operable(self):
        """The pinned "/" (the _known_mount rule): a status listing that
        raises outright used to 500 the route; the boot volume, which
        spotlight_status always reports first, stays toggleable."""
        resp = self._toggle(None, "/", call_raises=True)
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertIs(resp.json()["ok"], True)

    def test_non_list_status_listing_keeps_the_boot_volume_operable(self):
        resp = self._toggle("junk", "/")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertIs(resp.json()["ok"], True)

    def test_unknown_volume_keeps_its_coded_refusal(self):
        """The gate's own contract survives the hardening: a volume the
        listing does not report earns bad_volume, never a raise."""
        resp = self._toggle([{"volume": "/"}], "/Volumes/Nope")
        self.assertEqual(resp.status_code, 400, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["detail"]["code"], "usage.bad_volume")

    def test_hostile_row_cannot_smuggle_a_non_str_volume(self):
        """Only str volumes count, exactly as before the hardening."""
        resp = self._toggle(
            [{"volume": 42}, {"volume": None}], "42")
        self.assertEqual(resp.status_code, 400, resp.text[:200])
        self.assertEqual(resp.json()["detail"]["code"], "usage.bad_volume")


class UsageRoutesStayImmuneTests(unittest.TestCase):
    """Neighbours the probe proved immune, pinned so a regression cannot
    ship silently."""

    def test_usage_overview_renders_through_hostile_sh_output(self):
        with mock.patch.object(
            usage_svc, "sh", return_value=(0, "Indexing enabled.", ""),
        ):
            resp = _client().get("/api/storage/usage")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        states = {row["volume"]: row["state"] for row in body["spotlight"]}
        self.assertEqual(states["/"], "enabled")

    def test_surrogate_volume_row_scrubs_consistently(self):
        """A lone-surrogate volume in the listing scrubs the same way the
        target does, so the toggle still matches its own row."""
        with ExitStack() as stack:
            _admin_browser(stack)
            stack.enter_context(mock.patch.object(
                usage_svc, "spotlight_status",
                return_value=[{"volume": "/Volumes/a\ud800b"}]))
            stack.enter_context(mock.patch(
                "hub.macos_admin.run_admin",
                return_value={"ok": True, "message": "done"}))
            resp = _client().post(
                "/api/storage/spotlight",
                json={"volume": "/Volumes/a?b", "enabled": True})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        _starlette(resp.json())


if __name__ == "__main__":
    unittest.main(verbosity=2)
