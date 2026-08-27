"""Eleventh leftover-500s sweep of the Apps managed/launchd surfaces.

apps9 sealed the ``__class__``-property/impostor bombs around overrides,
action results and listing rows.  What was still live on the pre-fix tree,
driven through ``create_app()`` + ``TestClient(raise_server_exceptions=False)``,
was the *launchd listing object itself* and the two cross-module maps the
native collector builds — seams the earlier waves never planted junk in:

* GET /api/apps/managed/detail?id=launchd:* — ``_launchd_apps`` guards the
  ``launchd_cache.listing()`` *call* but trusts the returned object: a
  leftover listing whose ``pid_for`` raises, whose ``loaded`` carries a
  ``__contains__`` bomb, whose ``jobs.get`` bombs, whose job entry is a
  ``__bool__``/``__getitem__`` bomb, whose last-exit value carries an
  ``__eq__`` bomb (the tuple ``in`` probe runs it), or whose pid /
  last-exit is a >4300-digit int (the f-string ``str()`` is ValueError)
  each raised out of the per-agent loop — a raw 500 on the launchd detail
  route and a silently emptied launchd section of GET /api/apps/managed
  via ``_collect``'s fallback.
* GET /api/apps/managed — the brew/launchd autostart indexes are built
  from another module's rows and probed with a bare ``dict.get``: a
  leftover hash-shadowing str-subclass key (its ``__eq__`` fires during
  the hash probe) raised out of ``_native_apps`` and wiped the whole
  native section.  A junk ``cloudflared_svc.status()`` field detonated
  *outside* the guard: an ``active_tunnel`` whose truthiness or ``str()``
  bombs blew the status-text f-string after the try, and a ``tunnels``
  ``__bool__`` bomb inside the try silently flipped a running tunnel row
  to "down".
* GET /api/apps/managed/logs?id=native:* — the launchctl-print branch
  trusted ``sh()``'s shape: an rc-subclass ``__ne__`` bomb detonated the
  bare ``rc != 0`` probe, a wrong-arity / iterator-bomb return blew the
  tuple unpack, and a str-subclass ``__bool__`` bomb in stdout blew the
  bare ``out or err`` — three raw 500s on a logs modal that already
  answers ``ok: false`` for a *raising* backend.

No new error codes: the locales are untouched.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from hub import apps_manage_svc
from hub.app_factory import create_app
from hub.auth import require_auth

_app = None


def _client() -> TestClient:
    global _app
    if _app is None:
        _app = create_app()
        _app.dependency_overrides[require_auth] = lambda: None
    return TestClient(_app, raise_server_exceptions=False)


def _strict_utf8(resp) -> str:
    """The body must already be valid UTF-8 — decode strictly on purpose."""
    return resp.content.decode("utf-8")


# ─── leftover zoo ─────────────────────────────────────────────────────────────

class _HashWarKey(str):
    """A stored key whose hash shadows a real field and whose ``__eq__`` fires."""

    def __new__(cls, shadow):
        obj = str.__new__(cls, "\x00hash-war")
        obj._shadow = shadow
        return obj

    def __hash__(self):
        return hash(self._shadow)

    def __eq__(self, other):
        raise RuntimeError("leftover key __eq__ bomb")

    __ne__ = __eq__


class _NeBombInt(int):
    """An rc whose ``!=`` probe raises; the real value sits underneath."""

    def __eq__(self, other):
        raise RuntimeError("leftover rc __eq__ bomb")

    __ne__ = __eq__
    __hash__ = int.__hash__


class _EqBombStr(str):
    def __eq__(self, other):
        raise RuntimeError("leftover str __eq__ bomb")

    __ne__ = __eq__
    __hash__ = str.__hash__


class _StrBombInt(int):
    def __str__(self):
        raise RuntimeError("leftover int __str__ bomb")


class _BoolBombStr(str):
    def __bool__(self):
        raise RuntimeError("leftover str __bool__ bomb")


class _BoolBomb:
    def __bool__(self):
        raise RuntimeError("leftover __bool__ bomb")


class _GetItemBombEntry:
    """Truthy job entry whose indexing raises."""

    def __getitem__(self, idx):
        raise RuntimeError("leftover entry __getitem__ bomb")


class _GetBombJobs(dict):
    def get(self, *a, **k):
        raise RuntimeError("leftover jobs .get bomb")


class _ContainsBombLoaded(frozenset):
    def __contains__(self, item):
        raise RuntimeError("leftover loaded __contains__ bomb")


class _IterBombSeq(list):
    def __iter__(self):
        raise RuntimeError("leftover sequence __iter__ bomb")


_HUGE = 16 ** 4400  # str() of this is ValueError past CPython's digit cap


class _FakeListing:
    """A leftover listing object: sane by default, one poisoned reading."""

    def __init__(self, pid=None, loaded=frozenset(), jobs=None,
                 pid_raises=False):
        self._pid = pid
        self._pid_raises = pid_raises
        self.loaded = loaded
        self.jobs = {} if jobs is None else jobs

    def pid_for(self, label):
        if self._pid_raises:
            raise RuntimeError("leftover pid_for bomb")
        return self._pid


# ─── rigs ─────────────────────────────────────────────────────────────────────

class _LaunchdRig(unittest.TestCase):
    """One sane agent plist; the launchd listing is planted per test."""

    LABEL = "local.sane"

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        agents = Path(self._tmp.name) / "agents"
        agents.mkdir()
        (agents / f"{self.LABEL}.plist").write_bytes(
            b"""<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>Label</key><string>local.sane</string>
</dict></plist>
"""
        )
        apps_manage_svc.inventory.invalidate()
        self.addCleanup(apps_manage_svc.inventory.invalidate)
        for target, kwargs in (
            ("hub.paths.AGENTS_DIR", {"new": str(agents)}),
            ("hub.services_uninstall_svc.AGENTS_DIR", {"new": str(agents)}),
            ("hub.config.override", {"return_value": {}}),
            ("hub.services_uninstall_svc.preview", {"return_value": {}}),
            ("hub.containers_svc.list_containers",
             {"return_value": {"containers": []}}),
            ("hub.containers_svc.list_stacks", {"return_value": []}),
            ("hub.vms_svc.list_all_vms", {"return_value": {"vms": []}}),
            ("hub.native_catalog.list_native_apps", {"return_value": []}),
            ("hub.apps_manage_svc.engine_up", {"return_value": False}),
        ):
            patched = mock.patch(target, **kwargs)
            patched.start()
            self.addCleanup(patched.stop)

    def _detail(self, listing):
        with mock.patch("hub.launchd_cache.listing", return_value=listing):
            return _client().get(
                "/api/apps/managed/detail", params={"id": f"launchd:{self.LABEL}"}
            )

    def _inventory(self, listing):
        with mock.patch("hub.launchd_cache.listing", return_value=listing):
            return _client().get("/api/apps/managed", params={"force": "true"})


class LaunchdListingLeftoverHttpTests(_LaunchdRig):
    """A poisoned listing object costs its own readings, never the route."""

    def test_a_raising_pid_for_keeps_the_detail_route(self):
        # The apps8 try covers listing() *raising*; a leftover object whose
        # pid_for raises detonated inside the per-agent loop — a raw 500 on
        # GET /api/apps/managed/detail?id=launchd:*.
        resp = self._detail(_FakeListing(pid_raises=True))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertEqual(payload["source_id"], self.LABEL)

    def test_a_huge_int_pid_keeps_the_detail_route(self):
        # str() of a >4300-digit pid is ValueError, so the f-string in the
        # status text itself was the detonation point.
        resp = self._detail(_FakeListing(pid=_HUGE))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertEqual(payload["source_id"], self.LABEL)
        self.assertIsInstance(payload["status_text"], str)

    def test_a_str_bomb_pid_keeps_the_detail_route(self):
        resp = self._detail(_FakeListing(pid=_StrBombInt(123)))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertEqual(payload["source_id"], self.LABEL)

    def test_a_contains_bomb_loaded_set_keeps_the_detail_route(self):
        resp = self._detail(
            _FakeListing(loaded=_ContainsBombLoaded({self.LABEL}))
        )
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertEqual(payload["source_id"], self.LABEL)

    def test_a_jobs_get_bomb_keeps_the_detail_route(self):
        resp = self._detail(
            _FakeListing(loaded=frozenset({self.LABEL}), jobs=_GetBombJobs())
        )
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertEqual(payload["source_id"], self.LABEL)

    def test_a_bool_bomb_job_entry_keeps_the_detail_route(self):
        # ``entry[1] if entry else None`` runs the entry's own __bool__.
        resp = self._detail(
            _FakeListing(loaded=frozenset({self.LABEL}),
                         jobs={self.LABEL: _BoolBomb()})
        )
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertEqual(payload["source_id"], self.LABEL)

    def test_a_getitem_bomb_job_entry_keeps_the_detail_route(self):
        resp = self._detail(
            _FakeListing(loaded=frozenset({self.LABEL}),
                         jobs={self.LABEL: _GetItemBombEntry()})
        )
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertEqual(payload["source_id"], self.LABEL)

    def test_an_eq_bomb_last_exit_keeps_the_detail_route(self):
        # ``last not in (None, "", "-", "0")`` runs the leftover's __eq__
        # through the tuple probe.
        resp = self._detail(
            _FakeListing(loaded=frozenset({self.LABEL}),
                         jobs={self.LABEL: ("-", _EqBombStr("78"))})
        )
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertEqual(payload["source_id"], self.LABEL)

    def test_a_huge_int_last_exit_keeps_the_detail_route(self):
        resp = self._detail(
            _FakeListing(loaded=frozenset({self.LABEL}),
                         jobs={self.LABEL: ("-", _HUGE)})
        )
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertEqual(payload["source_id"], self.LABEL)
        self.assertIsInstance(payload["status_text"], str)

    def test_a_poisoned_listing_keeps_the_inventory_section(self):
        # The same bombs used to silently empty the whole launchd section of
        # GET /api/apps/managed via _collect's fallback.
        resp = self._inventory(_FakeListing(pid_raises=True))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        ids = [item["id"] for item in payload["items"]]
        self.assertIn(f"launchd:{self.LABEL}", ids)
        self.assertEqual(payload["counts"]["launchd"], 1)

    def test_a_sane_running_listing_stays_intact(self):
        # The new guards must not over-absorb: a real pid keeps its line.
        from hub.launchd_cache import Listing
        resp = self._detail(Listing({self.LABEL: ("123", "0")}))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertEqual(payload["state"], "ok")
        self.assertIn("123", payload["status_text"])

    def test_a_sane_crash_looping_listing_stays_intact(self):
        from hub.launchd_cache import Listing
        resp = self._detail(Listing({self.LABEL: ("-", "78")}))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertEqual(payload["state"], "down")
        self.assertIn("78", payload["status_text"])


class _NativeInventoryRig(unittest.TestCase):
    """Temp SERVICES_ROOT; the native listing carries one installed app."""

    def _mount(self, apps, **kwargs):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        services = Path(self._tmp.name) / "services"
        services.mkdir()
        apps_manage_svc.inventory.invalidate()
        self.addCleanup(apps_manage_svc.inventory.invalidate)
        defaults = {
            "hub.apps_manage_svc.SERVICES_ROOT": {"new": services},
            "hub.containers_svc.list_containers":
                {"return_value": {"containers": []}},
            "hub.containers_svc.list_stacks": {"return_value": []},
            "hub.vms_svc.list_all_vms": {"return_value": {"vms": []}},
            "hub.native_catalog.list_native_apps": {"return_value": apps},
            "hub.apps_manage_svc.engine_up": {"return_value": False},
            "hub.launchd_cache.listing":
                {"side_effect": RuntimeError("no launchd")},
            "hub.autostart_svc._brew_service_items": {"return_value": []},
            "hub.autostart_svc._launchd_items": {"return_value": []},
        }
        defaults.update(kwargs)
        for target, kw in defaults.items():
            patched = mock.patch(target, **kw)
            patched.start()
            self.addCleanup(patched.stop)

    def _get(self):
        return _client().get("/api/apps/managed", params={"force": "true"})


class AutostartIndexHashWarHttpTests(_NativeInventoryRig):
    """A hash-shadowing key in an autostart index costs its field, not the section."""

    def test_a_hash_war_brew_key_keeps_the_native_section(self):
        # ``brew_autostart.get(pkg)`` runs the stored key's __eq__ during the
        # hash probe: one leftover key wiped every native row via _collect.
        self._mount(
            [{"id": "native-ollama", "name": "Ollama (brew)", "installed": True,
              "package": "ollama", "method": "brew_formula", "running": True}],
            **{"hub.autostart_svc._brew_service_items": {"return_value": [
                {"name": _HashWarKey("ollama"), "autostart": True},
            ]}},
        )
        resp = self._get()
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        ids = [item["id"] for item in payload["items"]]
        self.assertIn("native:native-ollama", ids)
        self.assertEqual(payload["counts"]["native"], 1)

    def test_a_hash_war_launchd_key_keeps_the_native_section(self):
        self._mount(
            [{"id": "native-homeassistant", "name": "Home Assistant",
              "installed": True, "launchd_label": "com.homeassistant.core",
              "running": True}],
            **{"hub.autostart_svc._launchd_items": {"return_value": [
                {"label": _HashWarKey("com.homeassistant.core"),
                 "autostart": True},
            ]}},
        )
        resp = self._get()
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        ids = [item["id"] for item in payload["items"]]
        self.assertIn("native:native-homeassistant", ids)
        self.assertEqual(payload["counts"]["native"], 1)

    def test_a_sane_brew_index_still_answers_autostart(self):
        # The guarded lookup must not over-absorb: a real index still maps.
        self._mount(
            [{"id": "native-ollama", "name": "Ollama (brew)", "installed": True,
              "package": "ollama", "method": "brew_formula", "running": True}],
            **{"hub.autostart_svc._brew_service_items": {"return_value": [
                {"name": "ollama", "autostart": True},
            ]}},
        )
        resp = self._get()
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        item = next(i for i in payload["items"]
                    if i["id"] == "native:native-ollama")
        self.assertIs(item["autostart"], True)


class CloudflaredStatusJunkHttpTests(_NativeInventoryRig):
    """Junk cloudflared status fields cost themselves, never the section."""

    _CF = {"id": "native-cloudflared", "name": "Cloudflared (native)",
           "installed": True, "package": "cloudflared",
           "method": "brew_formula", "running": True, "notes": "tunnel"}

    def test_a_str_bomb_active_tunnel_keeps_the_row(self):
        # The status-text f-string ran *outside* the status() try: a junk
        # active_tunnel wiped the whole native section via _collect.
        self._mount([dict(self._CF)], **{"hub.cloudflared_svc.status": {
            "return_value": {"running": True, "logged_in": True,
                             "active_tunnel": _StrBombInt(7), "tunnels": []},
        }})
        resp = self._get()
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        item = next(i for i in payload["items"]
                    if i["id"] == "native:native-cloudflared")
        self.assertIsInstance(item["status_text"], str)

    def test_a_huge_int_active_tunnel_keeps_the_row(self):
        self._mount([dict(self._CF)], **{"hub.cloudflared_svc.status": {
            "return_value": {"running": True, "logged_in": True,
                             "active_tunnel": _HUGE, "tunnels": []},
        }})
        resp = self._get()
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        ids = [item["id"] for item in payload["items"]]
        self.assertIn("native:native-cloudflared", ids)

    def test_a_bool_bomb_active_tunnel_keeps_the_row(self):
        self._mount([dict(self._CF)], **{"hub.cloudflared_svc.status": {
            "return_value": {"running": True, "logged_in": True,
                             "active_tunnel": _BoolBomb(), "tunnels": []},
        }})
        resp = self._get()
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        ids = [item["id"] for item in payload["items"]]
        self.assertIn("native:native-cloudflared", ids)

    def test_a_bool_bomb_tunnels_list_keeps_the_running_state(self):
        # ``cf.get("tunnels") or []`` ran the value's __bool__ inside the
        # try: the absorbed bomb silently flipped a running tunnel to down.
        self._mount([dict(self._CF)], **{"hub.cloudflared_svc.status": {
            "return_value": {"running": True, "logged_in": True,
                             "active_tunnel": "prod", "tunnels": _BoolBomb()},
        }})
        resp = self._get()
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        item = next(i for i in payload["items"]
                    if i["id"] == "native:native-cloudflared")
        self.assertEqual(item["state"], "ok")
        self.assertIn("prod", item["status_text"])

    def test_a_sane_tunnel_status_stays_intact(self):
        self._mount([dict(self._CF)], **{"hub.cloudflared_svc.status": {
            "return_value": {"running": True, "logged_in": True,
                             "active_tunnel": "prod", "tunnels": ["prod"]},
        }})
        resp = self._get()
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        item = next(i for i in payload["items"]
                    if i["id"] == "native:native-cloudflared")
        self.assertEqual(item["state"], "ok")
        self.assertEqual(item["status_text"], "running · prod")
        self.assertEqual(item["cloudflared"]["tunnels"], ["prod"])


class NativeLogsLaunchctlJunkHttpTests(unittest.TestCase):
    """GET logs?id=native:*: a junk ``sh()`` shape answers, never 500s."""

    def _get(self, sh_kwargs):
        apps_manage_svc.inventory.invalidate()
        self.addCleanup(apps_manage_svc.inventory.invalidate)
        with mock.patch("hub.apps_manage_svc.sh", **sh_kwargs):
            return _client().get(
                "/api/apps/managed/logs", params={"id": "native:native-ollama"}
            )

    def test_an_rc_ne_bomb_keeps_the_launchctl_chunk(self):
        # The bare ``rc != 0`` probe ran the subclass __ne__ — a raw 500
        # where the rc really was 0 and the output was already in hand.
        resp = self._get({"return_value": (_NeBombInt(0), "state = running", "")})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertTrue(payload["ok"])
        self.assertIn("state = running", payload["log"])

    def test_a_wrong_arity_sh_return_answers_no_logs(self):
        # The bare 3-tuple unpack blew on a leftover 2-tuple.
        resp = self._get({"return_value": ("only", "two")})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertTrue(payload["ok"])
        self.assertIsInstance(payload["log"], str)

    def test_an_iter_bomb_sh_return_answers_no_logs(self):
        resp = self._get({"return_value": _IterBombSeq([0, "x", ""])})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertTrue(payload["ok"])

    def test_a_bool_bomb_stdout_keeps_its_text(self):
        # ``if out or err`` ran the leftover's __bool__; the text underneath
        # the bombed method is real and must survive.
        resp = self._get({"return_value": (0, _BoolBombStr("printed"), "")})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertTrue(payload["ok"])
        self.assertIn("printed", payload["log"])

    def test_a_sane_launchctl_print_stays_intact(self):
        resp = self._get({"return_value": (0, "pid = 42", "")})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertTrue(payload["ok"])
        self.assertIn("pid = 42", payload["log"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
