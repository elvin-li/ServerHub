"""WireGuard leftover-500 sweep #6: nine live raw 500s found, fixed, pinned.

All reproduced over ``create_app()`` + ``TestClient(raise_server_exceptions=
False)`` before the fixes; each answered ``500 Internal Server Error`` with a
traceback, never a coded JSON body.

The live leftovers
==================
* **A leftover directory occupying ``data/wireguard.lock``.**  ``conf_lock``
  opened the flock file with a bare ``os.open`` — EISDIR raised out of every
  peer mutation (create, batch, delete, import, PSK toggle) *before any
  validation ran*.  The fix mirrors ``hub.config._file_lock``: an empty
  leftover node is cleared so the cross-process flock self-heals, and
  anything that still cannot be opened degrades to an in-process fallback
  lock rather than refusing the change.
* **Dict-subclass ``.get`` bombs in the config root / settings map.**
  ``save_settings`` read ``cfg().get("settings")`` and ``raw.get("wireguard")``
  with bound methods — the exact class ``hub.config.settings_section`` was
  already fixed for.  A bombing ``.get`` 500'd PUT /api/wireguard/settings
  and the remediate paths that save settings (wstunnel uninstall/stabilize).
  Unbound ``dict.get`` reads the C-level storage instead.
* **A leftover non-empty directory at ``wg0.conf``.**  ``_write_conf`` handed
  the rendered config to ``replace_secret_text``, whose final ``os.replace``
  raises IsADirectoryError — a raw 500 out of every peer write after
  validation had already passed.  Empty leftovers are cleared
  (``drop_leftover_nonfile``); a non-empty one is the new coded 503
  ``wg.write_failed`` naming the path, and nothing is persisted, so the
  registry and the config stay consistent.
* **The same class at ``data/<iface>.sync.conf``.**  ``apply_live`` staged
  the stripped config there on every sync; a leftover directory 500'd POST
  /api/wireguard/sync *and* every peer mutation whose apply step runs after
  the change already landed on disk.  Now the stage failure degrades to
  ``{ok: false}`` — peer routes answer 200 with ``applied: false``, and
  /sync answers its coded ``wg.sync_failed``.
* **Five remediation staging paths under data/.**  ``pf-anchor-wireguard``,
  ``pf.conf.check``, ``pf.conf.staged``, ``com.wireguard.<iface>.plist`` and
  ``com.elvin.wstunnel-wg-server.plist`` were all written with a bare
  ``replace_secret_text`` — a leftover directory at any of them 500'd POST
  /api/wireguard/remediate (nat / daemon / wstunnel / wstunnel_stabilize)
  before any privileged step ran.  Every stage write now self-heals an empty
  leftover and reports the coded 503 ``wg.write_failed`` otherwise.

What stays pinned besides the fixes
===================================
* The empty-leftover self-heal: an empty directory or FIFO at the lock path
  is replaced by a regular flock file and the mutation proceeds.
* Stays-immune: a stored ``wireguard`` section that is a dict subclass with
  a bombing ``items()`` keeps GET and PUT /api/wireguard/settings at 200 —
  ``settings_section``'s ``dict(raw)`` launder reads the C-level storage.
* ``wg.write_failed`` is registered in hub/errors.py and carries the same
  key in all three SPA locales.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from hub import wireguard_net_svc, wireguard_svc, wireguard_wstunnel  # noqa: E402
from hub.errors import CODES  # noqa: E402
from hub.paths import DATA_DIR  # noqa: E402

PUB = "A" * 42 + "b="
PRIV = "C" * 42 + "d="

INSTALL = {
    "installed": True, "conf_exists": True, "conf_path": "", "conf_dir": "",
    "wg": "wg", "wg_quick": "wg-quick", "wireguard_go": "",
    "tools_version": "v1", "userspace_version": "", "probe_failed": False,
}


def _no_surrogates(payload) -> None:
    """What Starlette's JSONResponse does to the body (allow_nan=False)."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


def _remove_node(path: Path) -> None:
    """Clear whatever occupies *path* — file, FIFO, or directory tree."""
    try:
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path, ignore_errors=True)
        else:
            path.unlink(missing_ok=True)
    except OSError:
        pass


def _plant_nonempty_dir(path: Path) -> None:
    """A leftover directory ``drop_leftover_nonfile`` cannot rmdir away."""
    _remove_node(path)
    path.mkdir(parents=True)
    (path / "occupant").write_text("x", encoding="utf-8")


class GetBomb(dict):
    """Passes isinstance(x, dict); the bound .get raises."""

    def get(self, *a, **k):
        raise RuntimeError("get bomb")


class ItemsBomb(dict):
    def items(self):
        raise RuntimeError("items bomb")


class _MountedRouteTests(unittest.TestCase):
    """Real app, auth overridden, admin guard and installation patched."""

    def setUp(self):
        from fastapi.testclient import TestClient

        from hub.app_factory import create_app
        from hub.auth import require_auth
        from hub.routers import wireguard_api

        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        app = create_app()
        app.dependency_overrides[require_auth] = lambda: True
        self.addCleanup(app.dependency_overrides.clear)
        self.client = TestClient(app, raise_server_exceptions=False)
        self.stack.enter_context(mock.patch.object(
            wireguard_api, "require_admin_browser", lambda request: "admin"
        ))
        self.stack.enter_context(mock.patch.object(
            wireguard_svc, "installation", lambda: dict(INSTALL)
        ))


class LockPathLeftoverTests(_MountedRouteTests):
    """conf_lock survives a leftover node at data/wireguard.lock."""

    def setUp(self):
        super().setUp()
        self.lock = wireguard_svc._LOCK_PATH
        self.lock.parent.mkdir(parents=True, exist_ok=True)
        _remove_node(self.lock)
        self.addCleanup(lambda: _remove_node(self.lock))

    def _delete(self):
        return self.client.post(
            "/api/wireguard/peers/delete", json={"pubkey": PUB, "confirm": True}
        )

    def test_nonempty_directory_no_longer_500s_peer_mutations(self):
        # The live leftover: EISDIR out of the bare os.open answered a raw
        # 500 before the pubkey was even validated.
        _plant_nonempty_dir(self.lock)
        resp = self._delete()
        self.assertEqual(resp.status_code, 404, resp.text[:300])
        payload = resp.json()
        _no_surrogates(payload)
        self.assertEqual(payload["detail"]["code"], "wg.peer_not_found")

    def test_empty_directory_self_heals_back_to_a_regular_flock_file(self):
        self.lock.mkdir()
        resp = self._delete()
        self.assertEqual(resp.status_code, 404, resp.text[:300])
        self.assertTrue(self.lock.is_file(), "flock file was not restored")

    def test_fifo_at_the_lock_path_answers_coded_not_a_hang(self):
        os.mkfifo(self.lock)
        resp = self._delete()
        self.assertEqual(resp.status_code, 404, resp.text[:300])
        self.assertTrue(self.lock.is_file(), "flock file was not restored")

    def test_conf_lock_unit_degrades_to_the_fallback_without_raising(self):
        _plant_nonempty_dir(self.lock)
        entered = []
        with wireguard_svc.conf_lock():
            entered.append(True)
        self.assertEqual(entered, [True])


class ConfigRootBombTests(_MountedRouteTests):
    """save_settings survives dict-subclass .get bombs in cfg()."""

    def test_bombing_config_root_keeps_put_settings_200(self):
        with mock.patch.object(
            wireguard_svc, "cfg",
            lambda: GetBomb({"settings": {"wireguard": {}}}),
        ):
            resp = self.client.put(
                "/api/wireguard/settings", json={"dns": "1.1.1.1"}
            )
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _no_surrogates(body)
        self.assertEqual(body["settings"]["dns"], "1.1.1.1")

    def test_bombing_settings_map_keeps_put_settings_200(self):
        with mock.patch.object(
            wireguard_svc, "cfg",
            lambda: {"settings": GetBomb({"wireguard": {"mtu": 1400}})},
        ):
            resp = self.client.put(
                "/api/wireguard/settings", json={"dns": "1.1.1.1"}
            )
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _no_surrogates(resp.json())

    def test_items_bomb_stored_section_stays_immune_on_get_and_put(self):
        # settings_section's dict(raw) launder reads the C-level storage, so
        # a bombing items() never fires.  Pinned so it stays that way.
        with mock.patch.object(
            wireguard_svc, "cfg",
            lambda: {"settings": {"wireguard": ItemsBomb({"dns": "9.9.9.9"})}},
        ):
            for method, kwargs in (
                ("GET", {}),
                ("PUT", {"json": {"dns": "1.1.1.1"}}),
            ):
                with self.subTest(method=method):
                    resp = self.client.request(
                        method, "/api/wireguard/settings", **kwargs
                    )
                    self.assertEqual(resp.status_code, 200, resp.text[:300])
                    _no_surrogates(resp.json())


class ConfWriteLeftoverTests(_MountedRouteTests):
    """_write_conf: leftover directory at wg0.conf is the coded 503."""

    def setUp(self):
        super().setUp()
        tmp = tempfile.TemporaryDirectory(prefix="wg6-conf-")
        self.addCleanup(tmp.cleanup)
        self.conf_dir = Path(tmp.name)
        self.conf = self.conf_dir / "wg0.conf"
        for target, value in (
            ("conf_path", lambda interface=None: self.conf),
            ("conf_dir", lambda: self.conf_dir),
            ("generate_keypair", lambda: (PRIV, PUB)),
            ("public_from_private", lambda private: PUB),
        ):
            self.stack.enter_context(
                mock.patch.object(wireguard_svc, target, value)
            )
        wireguard_svc.REGISTRY_PATH.parent.mkdir(parents=True, exist_ok=True)
        _remove_node(wireguard_svc.REGISTRY_PATH)
        self.addCleanup(lambda: _remove_node(wireguard_svc.REGISTRY_PATH))

    def test_nonempty_directory_at_wg0_conf_is_the_coded_503(self):
        _plant_nonempty_dir(self.conf)
        resp = self.client.post("/api/wireguard/peers", json={"name": "phone"})
        self.assertEqual(resp.status_code, 503, resp.text[:300])
        payload = resp.json()
        _no_surrogates(payload)
        self.assertEqual(payload["detail"]["code"], "wg.write_failed")
        self.assertEqual(payload["detail"]["params"]["path"], str(self.conf))
        # Nothing was persisted: the failed write must not leave a registry
        # entry for a peer the config does not carry.
        self.assertNotIn(PUB, wireguard_svc._registry_peers())

    def test_empty_leftover_directory_self_heals_and_the_peer_is_created(self):
        self.conf.mkdir()
        with mock.patch.object(
            wireguard_svc, "apply_live",
            lambda: {"ok": True, "applied": False, "reason": "not_running"},
        ):
            resp = self.client.post(
                "/api/wireguard/peers", json={"name": "phone"}
            )
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertTrue(self.conf.is_file(), "wg0.conf was not restored")
        self.assertIn(PUB, self.conf.read_text(encoding="utf-8"))


class SyncStageLeftoverTests(_MountedRouteTests):
    """apply_live: leftover directory at data/<iface>.sync.conf stays coded."""

    def setUp(self):
        super().setUp()
        tmp = tempfile.TemporaryDirectory(prefix="wg6-sync-")
        self.addCleanup(tmp.cleanup)
        self.conf_dir = Path(tmp.name)
        self.conf = self.conf_dir / "wg0.conf"
        self.conf.write_text(
            f"[Interface]\nPrivateKey = {PRIV}\nAddress = 10.10.0.1/24\n"
            "ListenPort = 51820\n",
            encoding="utf-8",
        )
        self.staged = DATA_DIR / "wg0.sync.conf"
        _plant_nonempty_dir(self.staged)
        self.addCleanup(lambda: _remove_node(self.staged))
        for target, value in (
            ("conf_path", lambda interface=None: self.conf),
            ("conf_dir", lambda: self.conf_dir),
            ("live_interface", lambda interface: ("utun9", [], "")),
        ):
            self.stack.enter_context(
                mock.patch.object(wireguard_svc, target, value)
            )

    def test_post_sync_answers_the_coded_sync_failed(self):
        resp = self.client.post("/api/wireguard/sync")
        self.assertEqual(resp.status_code, 500, resp.text[:300])
        payload = resp.json()
        _no_surrogates(payload)
        self.assertEqual(payload["detail"]["code"], "wg.sync_failed")

    def test_peer_create_still_succeeds_with_applied_false(self):
        # The persisted change must not turn into a 500 because the *apply*
        # step could not stage its file.
        for target, value in (
            ("generate_keypair", lambda: (PRIV, PUB)),
            ("public_from_private", lambda private: PUB),
        ):
            self.stack.enter_context(
                mock.patch.object(wireguard_svc, target, value)
            )
        wireguard_svc.REGISTRY_PATH.parent.mkdir(parents=True, exist_ok=True)
        _remove_node(wireguard_svc.REGISTRY_PATH)
        self.addCleanup(lambda: _remove_node(wireguard_svc.REGISTRY_PATH))
        resp = self.client.post("/api/wireguard/peers", json={"name": "phone"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _no_surrogates(body)
        self.assertTrue(body["ok"])
        self.assertFalse(body["applied"])
        self.assertIn(PUB, self.conf.read_text(encoding="utf-8"))


class RemediateStageLeftoverTests(_MountedRouteTests):
    """Every remediation staging path answers the coded 503, not a raw 500."""

    def setUp(self):
        super().setUp()
        pf_tmp = tempfile.TemporaryDirectory(prefix="wg6-pf-")
        self.addCleanup(pf_tmp.cleanup)
        pf = Path(pf_tmp.name) / "pf.conf"
        pf.write_text("pass all\n", encoding="utf-8")
        for target, value in (
            ("PF_CONF", pf),
            ("wan_interface", lambda: "en0"),
            ("sh", lambda cmd, timeout=10, **kw: (0, "", "")),
            ("run_admin_sequence", lambda cmds, timeout=180: {"ok": True}),
        ):
            self.stack.enter_context(
                mock.patch.object(wireguard_net_svc, target, value)
            )
        self.stack.enter_context(mock.patch.object(
            wireguard_wstunnel, "find_binary",
            lambda: wireguard_wstunnel.ALLOWED_BINARIES[0],
        ))
        self.addCleanup(wireguard_wstunnel.live.invalidate)

    def _remediate(self, target: str):
        return self.client.post(
            "/api/wireguard/remediate", json={"target": target, "enabled": True}
        )

    def _assert_coded(self, resp, staged: Path):
        self.assertEqual(resp.status_code, 503, resp.text[:300])
        payload = resp.json()
        _no_surrogates(payload)
        self.assertEqual(payload["detail"]["code"], "wg.write_failed")
        self.assertEqual(payload["detail"]["params"]["path"], str(staged))

    def test_each_nat_staging_path_is_the_coded_503(self):
        for name in ("pf-anchor-wireguard", "pf.conf.check", "pf.conf.staged"):
            staged = DATA_DIR / name
            with self.subTest(name=name):
                _plant_nonempty_dir(staged)
                try:
                    self._assert_coded(self._remediate("nat"), staged)
                finally:
                    _remove_node(staged)

    def test_daemon_staging_path_is_the_coded_503(self):
        staged = DATA_DIR / "com.wireguard.wg0.plist"
        _plant_nonempty_dir(staged)
        self.addCleanup(lambda: _remove_node(staged))
        self._assert_coded(self._remediate("daemon"), staged)

    def test_wstunnel_and_stabilize_staging_path_is_the_coded_503(self):
        staged = DATA_DIR / f"{wireguard_wstunnel.LABEL}.plist"
        _plant_nonempty_dir(staged)
        self.addCleanup(lambda: _remove_node(staged))
        for target in ("wstunnel", "wstunnel_stabilize"):
            with self.subTest(target=target):
                self._assert_coded(self._remediate(target), staged)

    def test_empty_leftover_at_a_staging_path_self_heals(self):
        staged = DATA_DIR / "com.wireguard.wg0.plist"
        _remove_node(staged)
        staged.mkdir()
        self.addCleanup(lambda: _remove_node(staged))
        resp = self._remediate("daemon")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertTrue(staged.is_file(), "staged plist was not restored")


class ErrorCodeRegistrationTests(unittest.TestCase):
    """wg.write_failed exists in CODES and all three SPA locales."""

    def test_code_is_registered_as_a_503(self):
        self.assertIn("wg.write_failed", CODES)
        self.assertEqual(CODES["wg.write_failed"][0], 503)

    def test_all_three_locales_carry_the_identical_key(self):
        for name in ("en", "ja", "zh-CN"):
            with self.subTest(locale=name):
                text = (BASE / "web" / "src" / "i18n" / f"{name}.js").read_text(
                    encoding="utf-8"
                )
                # Anchor inside the err.wg block: "write_failed" also exists
                # under other feature blocks, but "peer_not_reissuable" is
                # unique to wg and the new key sits a few lines below it.
                anchor = text.find("peer_not_reissuable:")
                self.assertGreater(anchor, -1)
                block = text[anchor:anchor + 1200]
                self.assertIn("write_failed:", block)
                self.assertIn("{path}", block.split("write_failed:")[1][:200])


if __name__ == "__main__":
    unittest.main()
