"""VMs leftover-500 sweep #5: HTTP stays-immune pins.

Fifth sweep over the VM / OrbStack / hypervisor-CLI / console surfaces,
continuing test_leftover_vm_500s, test_vms_leftover_sentinel_surrogate_500s,
test_vms_console_hexint_key_leftover_500s and
test_vms_leftover_dash_uuid_rename_wipe_500s.  This sweep drove the mounted
app (create_app + TestClient, raise_server_exceptions=False) with the whole
hostile-input zoo — surrogate escapes in keys AND values, >4300-digit ints,
huge floats, deep nesting, torn JSON, FIFO/oversize/invalid-UTF-8 configs,
vanished CLIs, WebSocket bridge abuse — and found **no live raw 500 left**.
These pins hold the line at the HTTP layer:

* GET /api/vms answers 200 with a hostile ``orbctl list -f json`` document:
  lone-surrogate JSON escapes in machine keys AND values, a >4300-digit int
  field (``json.loads`` of it is ValueError, not JSONDecodeError — the
  ``_capped_json_int`` hook keeps the row and drops only the field), ``1e999``
  floats, a leftover deeply-nested document (RecursionError, degrading to the
  text listing), torn JSON, and non-string names/states.

* PyYAML accepts ``"\\ud800"`` escapes, so lone surrogates can sit on disk in
  override keys AND values and in the console allowlist key/host/protocol.
  GET /api/vms, GET /api/settings/vms and the console-session mint all answer
  coded/200 with strictly-UTF-8 bodies; a rename through the same config
  still lands.

* The vanished-CLI classification, at the HTTP layer: the ``(-1, "not
  found")`` spawn sentinel answers the coded 503 only after a fresh disk
  probe confirms the binary is gone; a signal-killed CLI still on disk keeps
  its raw ``{ok: false}`` result, and GET /api/vms stays 200 either way.

* The console WebSocket bridge through the mounted route: unauthenticated
  and bad/replayed-ticket upgrades answer coded error frames; a real bridge
  to a loopback TCP endpoint round-trips binary (including invalid-UTF-8
  junk from the VNC side); a client text frame ends the session cleanly.
  The per-user ticket mint rate limit answers the coded 429.

* A FIFO, an over-cap file, or torn invalid-UTF-8 bytes occupying
  services.yaml never cost GET /api/vms; a rename against an unreadable
  config answers the coded 503 settings.config_unreadable, not a raw 500.
"""
from __future__ import annotations

import os
import socket
import threading
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from hub import audit, config, vm_console, vms_svc
from hub.app_factory import create_app
from hub.auth import require_auth

_UUID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
UTM_LISTING = (
    "UUID                                 Status   Name\n"
    f"{_UUID} started  Ubuntu\n"
)
ORB_TEXT_LISTING = "NAME  STATE\nweb  running\n"
#: Built as a literal digit run: the *parse* of this is what the hook guards.
_HUGE_DIGITS = "9" * 5000


def _client() -> TestClient:
    app = create_app()
    app.dependency_overrides[require_auth] = lambda: True
    return TestClient(app, raise_server_exceptions=False)


def _sh_factory(utm_out=UTM_LISTING, orb_json="[]", orb_text=ORB_TEXT_LISTING):
    def fake_sh(cmd, **kw):
        cmd = [str(c) for c in cmd]
        if cmd and "utmctl" in cmd[0]:
            if cmd[1:2] == ["list"]:
                return (0, utm_out, "")
            if cmd[1:2] == ["status"]:
                return (0, "started", "")
            return (0, "done", "")
        if cmd and "orbctl" in cmd[0]:
            if "-f" in cmd:
                return (0, orb_json, "")
            if cmd[1:2] == ["list"]:
                return (0, orb_text, "")
            return (0, "done", "")
        return (0, "", "")
    return fake_sh


class _VmSweepCase(unittest.TestCase):
    """Shared plumbing: hypervisor CLI fakes + services.yaml snapshot."""

    def setUp(self):
        try:
            self._orig_yaml = config.YAML_PATH.read_bytes()
        except OSError:
            self._orig_yaml = None
        self.addCleanup(self._restore_yaml)
        self.client = _client()

    def _restore_yaml(self):
        try:
            config.YAML_PATH.unlink()
        except OSError:
            pass
        if self._orig_yaml is not None:
            config.YAML_PATH.write_bytes(self._orig_yaml)
        config.reload_cfg()
        vms_svc.invalidate_vm_lists()

    def _write_yaml_text(self, text: str):
        config.YAML_PATH.parent.mkdir(parents=True, exist_ok=True)
        config.YAML_PATH.write_text(text, encoding="utf-8")
        config.reload_cfg()
        vms_svc.invalidate_vm_lists()

    def _patched(self, sh):
        return (
            mock.patch.object(vms_svc, "_utm_available", return_value=True),
            mock.patch.object(vms_svc, "_orb_available", return_value=True),
            # shutil.which leaves both None on a Linux CI host; the fake
            # dispatcher matches on the binary name.
            mock.patch.object(vms_svc, "UTMCTL", "/usr/local/bin/utmctl"),
            mock.patch.object(vms_svc, "ORBCTL", "/usr/local/bin/orbctl"),
            mock.patch.object(vms_svc, "sh", side_effect=sh),
            mock.patch.object(audit, "record"),
        )

    def _get_vms(self, sh):
        vms_svc.invalidate_vm_lists()
        p = self._patched(sh)
        with p[0], p[1], p[2], p[3], p[4], p[5]:
            return self.client.get("/api/vms")

    def _assert_clean_utf8(self, resp):
        # A lone surrogate anywhere in the payload would have failed the
        # response encode as a raw 500; double-check the bytes round-trip.
        resp.content.decode("utf-8")


class OrbctlJsonZooTests(_VmSweepCase):
    """GET /api/vms stays 200 across the hostile orbctl JSON zoo."""

    def test_surrogate_escapes_in_keys_and_values(self):
        orb_json = (
            '[{"name":"m\\ud800x","state":"run\\ud800ning",'
            '"id":"i\\ud800d","distro":"d\\ud800","\\ud800key":"\\ud800val"}]'
        )
        resp = self._get_vms(_sh_factory(orb_json=orb_json))
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self._assert_clean_utf8(resp)
        data = resp.json()
        names = {v["name"] for v in data["vms"]}
        # The row survives with the surrogate replaced, never echoed raw.
        self.assertIn("m?x", names)
        self.assertNotIn("\ud800", resp.text)

    def test_over_cap_int_field_costs_only_its_field(self):
        """json.loads of a >4300-digit literal is ValueError, not
        JSONDecodeError; the parse hook must keep the machine row."""
        orb_json = (
            f'[{{"name":"web","state":"running","id":{_HUGE_DIGITS},'
            f'"mem":{_HUGE_DIGITS}}}]'
        )
        resp = self._get_vms(_sh_factory(orb_json=orb_json))
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self._assert_clean_utf8(resp)
        row = next(v for v in resp.json()["vms"] if v["backend"] == "orb")
        self.assertEqual(row["name"], "web")
        # The huge id loads as None and falls back to the machine name.
        self.assertEqual(row["uuid"], "web")

    def test_huge_float_and_nested_and_torn_documents(self):
        cases = {
            "huge-float": '[{"name":"web","state":"running","uptime":1e999}]',
            "deep-nest": "[" * 300 + "]" * 300,
            "torn": '[{"name":"web","state":"run',
            "dict-status": '[{"name":"web","state":{"a":1}}]',
            "non-str-names": '[{"name":true,"state":"running"},'
                             '{"name":["a"],"state":"running"},'
                             '{"name":"web","state":"running"}]',
            "top-level-number": _HUGE_DIGITS,
            "binary-junk": "\x00\x01 not json \x7f",
        }
        for label, orb_json in cases.items():
            with self.subTest(case=label):
                resp = self._get_vms(_sh_factory(orb_json=orb_json))
                self.assertEqual(resp.status_code, 200, resp.text[:200])
                self._assert_clean_utf8(resp)
                data = resp.json()
                # However the JSON leg degrades (skipped fields, text-listing
                # fallback), the orb machine and the UTM row both survive.
                names = {v["name"] for v in data["vms"]}
                self.assertIn("web", names)
                self.assertIn("Ubuntu", names)


class SurrogateYamlEscapeTests(_VmSweepCase):
    """PyYAML accepts ``"\\ud800"`` escapes: lone surrogates in override keys
    AND values, and in the console allowlist key/host/protocol, on disk."""

    SURROGATE_YAML = (
        "settings:\n"
        "  vm_console:\n"
        "    allowlist:\n"
        '      "\\ud800aaa-bbbb-cccc-dddd-eeeeeeeeeeee": {enabled: true, port: 5900}\n'
        f"      {_UUID}:\n"
        "        enabled: true\n"
        '        host: "127.0.0.1\\ud800"\n'
        "        port: 5900\n"
        '        protocol: "vnc\\ud800"\n'
        "overrides:\n"
        '  "Ubuntu\\ud800": {name: shadow}\n'
        "  Ubuntu:\n"
        '    name: "disp\\ud800lay"\n'
        '    group: "grp\\ud800"\n'
        '    url: "http://h\\ud800ost/"\n'
        '  "\\ud800": {name: solo}\n'
        '  web: {name: "orb\\ud800"}\n'
    )

    def test_yaml_really_carries_lone_surrogates(self):
        """The precondition: safe-load of the escape is a real ``\\ud800``."""
        self._write_yaml_text(self.SURROGATE_YAML)
        self.assertEqual(config.override("Ubuntu").get("name"), "disp\ud800lay")

    def test_get_vms_and_settings_stay_200_and_utf8(self):
        self._write_yaml_text(self.SURROGATE_YAML)
        p = self._patched(_sh_factory(orb_json='[{"name":"web","state":"running"}]'))
        with p[0], p[1], p[2], p[3], p[4], p[5]:
            resp = self.client.get("/api/vms")
            settings_resp = self.client.get("/api/settings/vms")
        for r in (resp, settings_resp):
            self.assertEqual(r.status_code, 200, r.text[:200])
            self._assert_clean_utf8(r)
            self.assertNotIn("\ud800", r.text)
        row = next(v for v in resp.json()["vms"] if v["backend"] == "utm")
        # The value survives scrubbed; the row keeps its console capability.
        self.assertEqual(row["name"], "disp?lay")
        self.assertEqual(row["group"], "grp?")

    def test_console_mint_stays_coded_with_surrogate_allowlist(self):
        self._write_yaml_text(self.SURROGATE_YAML)
        resp = self.client.post(f"/api/vms/utm:{_UUID}/console/session")
        self.assertEqual(resp.status_code, 401, resp.text[:200])
        self.assertEqual(
            resp.json()["detail"]["code"], "vm_console.browser_session_required",
        )
        # Authenticated: the surrogate host can never resolve to loopback, so
        # the entry reads unavailable — the coded 404, not a resolver 500.
        with (
            mock.patch("hub.auth.browser_authenticated", return_value=True),
            mock.patch("hub.auth.session_username", return_value="admin"),
            mock.patch.object(vms_svc, "utm_vm_running", return_value=True),
            mock.patch.object(audit, "record"),
        ):
            resp = self.client.post(f"/api/vms/utm:{_UUID}/console/session")
        self.assertEqual(resp.status_code, 404, resp.text[:200])
        self.assertEqual(resp.json()["detail"]["code"], "vm_console.unavailable")

    def test_rename_still_lands_through_the_surrogate_config(self):
        self._write_yaml_text(self.SURROGATE_YAML)
        p = self._patched(_sh_factory())
        with p[0], p[1], p[2], p[3], p[4], p[5]:
            resp = self.client.post(
                f"/api/vms/{_UUID}/action",
                json={"action": "rename", "name": "clean-name"},
            )
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertEqual(resp.json()["name"], "clean-name")
        self.assertEqual(config.override(_UUID).get("name"), "clean-name")


class VanishedCliHttpTests(_VmSweepCase):
    """The sentinel + disk-confirm classification, through the mounted routes."""

    @staticmethod
    def _gone_sh(cmd, **kw):
        return (-1, "", "not found")

    def _gone_patches(self, utmctl="/nonexistent/utmctl", orbctl="/nonexistent/orbctl"):
        return (
            mock.patch.object(vms_svc, "_utm_available", return_value=True),
            mock.patch.object(vms_svc, "_orb_available", return_value=True),
            mock.patch.object(vms_svc, "UTMCTL", utmctl),
            mock.patch.object(vms_svc, "ORBCTL", orbctl),
            mock.patch.object(vms_svc, "sh", side_effect=self._gone_sh),
            mock.patch.object(audit, "record"),
        )

    def test_confirmed_vanished_cli_answers_coded_503(self):
        vms_svc.invalidate_vm_lists()
        p = self._gone_patches()
        with p[0], p[1], p[2], p[3], p[4], p[5]:
            utm = self.client.post(
                f"/api/vms/{_UUID}/action", json={"action": "start"},
            )
            orb = self.client.post(
                "/api/vms/orb:web/action", json={"action": "start"},
            )
            create = self.client.post("/api/vms/create", json={"distro": "ubuntu"})
            listing = self.client.get("/api/vms")
        self.assertEqual(utm.status_code, 503, utm.text[:200])
        self.assertEqual(utm.json()["detail"]["code"], "vms.utm_unavailable")
        self.assertEqual(orb.status_code, 503, orb.text[:200])
        self.assertEqual(orb.json()["detail"]["code"], "vms.orb_unavailable")
        self.assertEqual(create.status_code, 503, create.text[:200])
        self.assertEqual(create.json()["detail"]["code"], "vms.orb_unavailable")
        # The listing never 500s for a vanished CLI; it just goes empty.
        self.assertEqual(listing.status_code, 200, listing.text[:200])
        self.assertEqual(listing.json()["vms"], [])

    def test_signal_killed_cli_still_on_disk_keeps_raw_result(self):
        """rc -1 + "not found" with the binary present is NOT the vanished
        503 — the disk re-check runs only on the failure path."""
        p = self._gone_patches(utmctl=os.__file__)  # any real on-disk file
        with p[0], p[1], p[2], p[3], p[4], p[5]:
            resp = self.client.post(
                f"/api/vms/{_UUID}/action", json={"action": "start"},
            )
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        self.assertFalse(body["ok"])
        self.assertEqual(body["message"], "not found")


class ConsoleWebSocketBridgeTests(_VmSweepCase):
    """The console WS route: coded reject frames, and a real byte bridge."""

    def _start_fake_vnc(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(4)
        self.addCleanup(srv.close)
        port = srv.getsockname()[1]

        def handle(conn):
            try:
                # Greeting plus invalid-UTF-8 junk: RFB is binary and the
                # bridge must never try to decode it.
                conn.sendall(b"RFB 003.008\n\xff\xfe\xed\xa0\x80")
                while True:
                    data = conn.recv(65536)
                    if not data:
                        return
                    conn.sendall(data)
            except OSError:
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

        def loop():
            while True:
                try:
                    conn, _ = srv.accept()
                except OSError:
                    return
                threading.Thread(target=handle, args=(conn,), daemon=True).start()

        threading.Thread(target=loop, daemon=True).start()
        return port

    def _allowlist_yaml(self, port: int) -> str:
        return (
            "settings:\n  vm_console:\n    allowlist:\n"
            f"      {_UUID}: {{enabled: true, host: 127.0.0.1, port: {port}}}\n"
        )

    @staticmethod
    async def _fake_auth(ws):
        return ("session-token", "admin")

    def test_unauthenticated_upgrade_gets_coded_error_frame(self):
        with self.client.websocket_connect(
            f"/api/vms/utm:{_UUID}/console/ws?ticket=x"
        ) as ws:
            self.assertEqual(
                ws.receive_json(), {"type": "error", "code": "auth.login_required"},
            )

    def test_bad_ticket_gets_coded_error_frame(self):
        self._write_yaml_text(self._allowlist_yaml(5900))
        with mock.patch(
            "hub.websocket_security.authenticate_websocket", self._fake_auth,
        ):
            with self.client.websocket_connect(
                f"/api/vms/utm:{_UUID}/console/ws?ticket=bogus"
            ) as ws:
                self.assertEqual(
                    ws.receive_json(),
                    {"type": "error", "code": "vm_console.invalid_ticket"},
                )

    def test_hostile_console_ids_answer_coded_unavailable(self):
        for cid in ("utm:%2e%2e", "utm:" + "f" * 36 + "%00", "x" * 300):
            with self.subTest(cid=cid[:24]):
                with mock.patch(
                    "hub.websocket_security.authenticate_websocket", self._fake_auth,
                ):
                    with self.client.websocket_connect(
                        f"/api/vms/{cid}/console/ws?ticket=x"
                    ) as ws:
                        self.assertEqual(
                            ws.receive_json(),
                            {"type": "error", "code": "vm_console.unavailable"},
                        )

    def test_bridge_round_trips_binary_and_burns_the_ticket(self):
        port = self._start_fake_vnc()
        self._write_yaml_text(self._allowlist_yaml(port))
        target = vm_console.resolve_target(f"utm:{_UUID}")
        self.assertIsNotNone(target)
        with (
            mock.patch("hub.websocket_security.authenticate_websocket", self._fake_auth),
            mock.patch.object(vms_svc, "utm_vm_running", return_value=True),
            mock.patch.object(audit, "record"),
        ):
            issued = vm_console.issue_ticket(
                target, user="admin", session_token="session-token",
            )
            with self.client.websocket_connect(
                f"/api/vms/utm:{_UUID}/console/ws?ticket={issued['ticket']}"
            ) as ws:
                greeting = ws.receive_bytes()
                self.assertTrue(greeting.startswith(b"RFB 003.008\n"))
                # Invalid UTF-8 from the console side travels as raw bytes.
                self.assertIn(b"\xff\xfe\xed\xa0\x80", greeting)
                ws.send_bytes(b"client-bytes")
                self.assertEqual(ws.receive_bytes(), b"client-bytes")
            # Single use: the burned ticket is refused on replay.
            with self.client.websocket_connect(
                f"/api/vms/utm:{_UUID}/console/ws?ticket={issued['ticket']}"
            ) as ws:
                self.assertEqual(
                    ws.receive_json(),
                    {"type": "error", "code": "vm_console.invalid_ticket"},
                )

    def test_ticket_mint_rate_limit_answers_coded_429(self):
        self._write_yaml_text(self._allowlist_yaml(5900))
        user = "vms5-rate-limit-user"
        self.addCleanup(vm_console._ticket_requests.pop, user, None)
        with (
            mock.patch("hub.auth.browser_authenticated", return_value=True),
            mock.patch("hub.auth.session_username", return_value=user),
            mock.patch.object(vms_svc, "utm_vm_running", return_value=True),
            mock.patch.object(audit, "record"),
        ):
            last = None
            for _ in range(vm_console.TICKET_RATE_LIMIT + 2):
                last = self.client.post(f"/api/vms/utm:{_UUID}/console/session")
        self.assertEqual(last.status_code, 429, last.text[:200])
        self.assertEqual(
            last.json()["detail"]["code"], "vm_console.too_many_sessions",
        )


class CorruptConfigVmSurfaceTests(_VmSweepCase):
    """FIFO / oversize / torn-UTF-8 services.yaml never cost the VM surface."""

    def _write_yaml_bytes(self, raw: bytes):
        config.YAML_PATH.parent.mkdir(parents=True, exist_ok=True)
        config.YAML_PATH.write_bytes(raw)
        config.reload_cfg()
        vms_svc.invalidate_vm_lists()

    def test_torn_invalid_utf8_config(self):
        self._write_yaml_bytes(b"overrides:\n  Ubuntu: {name: torn\xed\xa0\x80}\n")
        p = self._patched(_sh_factory())
        with p[0], p[1], p[2], p[3], p[4], p[5]:
            listing = self.client.get("/api/vms")
            rename = self.client.post(
                f"/api/vms/{_UUID}/action",
                json={"action": "rename", "name": "x"},
            )
        self.assertEqual(listing.status_code, 200, listing.text[:200])
        self.assertEqual(rename.status_code, 503, rename.text[:200])
        self.assertEqual(
            rename.json()["detail"]["code"], "settings.config_unreadable",
        )

    def test_oversize_config(self):
        pad = "overrides:\n  pad: " + "p" * (config._YAML_CAP + 1024) + "\n"
        self._write_yaml_bytes(pad.encode("utf-8"))
        p = self._patched(_sh_factory())
        with p[0], p[1], p[2], p[3], p[4], p[5]:
            listing = self.client.get("/api/vms")
            rename = self.client.post(
                f"/api/vms/{_UUID}/action",
                json={"action": "rename", "name": "x"},
            )
        self.assertEqual(listing.status_code, 200, listing.text[:200])
        self.assertEqual(rename.status_code, 503, rename.text[:200])
        self.assertEqual(
            rename.json()["detail"]["code"], "settings.config_unreadable",
        )

    @unittest.skipUnless(hasattr(os, "mkfifo"), "mkfifo unavailable")
    def test_fifo_occupying_the_config(self):
        try:
            config.YAML_PATH.unlink()
        except OSError:
            pass
        os.mkfifo(config.YAML_PATH)
        config.reload_cfg()
        vms_svc.invalidate_vm_lists()
        p = self._patched(_sh_factory())
        with p[0], p[1], p[2], p[3], p[4], p[5]:
            listing = self.client.get("/api/vms")
        self.assertEqual(listing.status_code, 200, listing.text[:200])
        names = {v["name"] for v in listing.json()["vms"]}
        self.assertIn("Ubuntu", names)


class HostileActionBodyTests(_VmSweepCase):
    """Raw hostile POST bodies answer coded 4xx, never a parser 500."""

    def test_hostile_raw_bodies_are_coded(self):
        cases = {
            "huge-int-force": b'{"action": "start", "force": ' + b"9" * 5000 + b"}",
            "huge-float-name": b'{"action": "start", "name": 1e999}',
            "invalid-utf8": b"\xff\xfe not json",
            "surrogate-action": b'{"action": "start\\ud800"}',
        }
        p = self._patched(_sh_factory())
        with p[0], p[1], p[2], p[3], p[4], p[5]:
            for label, raw in cases.items():
                with self.subTest(case=label):
                    resp = self.client.post(
                        f"/api/vms/{_UUID}/action",
                        content=raw,
                        headers={"content-type": "application/json"},
                    )
                    self.assertIn(
                        resp.status_code, (400, 422), (label, resp.text[:200]),
                    )
                    self._assert_clean_utf8(resp)
                    self.assertNotIn("\ud800", resp.text)


if __name__ == "__main__":
    unittest.main()
