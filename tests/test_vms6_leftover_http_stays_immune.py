"""VMs leftover-500 sweep #6: HTTP stays-immune pins.

Sixth sweep over the VM / OrbStack / hypervisor-CLI / console surfaces,
continuing test_leftover_vm_500s through test_vms5_leftover_http_stays_immune.
The sweep drove the mounted app (create_app + TestClient,
raise_server_exceptions=False) with a fresh hostile-input battery — orbctl
JSON envelope shapes, control-character and dash-led utmctl listings, the
whole YAML-typed override zoo, unparseable/FIFO configs on the *mutate*
path, hostile console allowlists, and raw hostile /api/action bodies — and
found **no live raw 500 left**.  These pins hold that line:

* GET /api/vms (plus /api/settings/vms and the Apps inventory that both
  re-read it) answers 200 across orbctl JSON envelope leftovers: dict
  wrappers (``{"machines": …}`` / ``{"items": …}`` with non-list payloads),
  null/scalar rows, duplicate keys, a UTF-16-style BOM prefix, >4300-digit
  object keys, non-string states (int/list/1e999), and id fields that are
  bools or huge floats.

* utmctl listings with NUL/ESC/DEL bytes, 100k-char names, dash-led names
  and digit-run UUIDs never cost GET /api/vms or /api/status.

* The typed-YAML override zoo (numeric keys and values, ``.inf``/``.nan``,
  dates, ``!!binary``, ``!!set``, port lists/maps, merge keys, recursive
  anchors) keeps GET /api/vms, /api/status and /api/bookmarks at 200, and a
  rename through the same config still lands.

* A services.yaml that is genuinely unparseable (a >1024-char plain-scalar
  mapping key trips YAML's scanner limit; a whole-document list paste) keeps
  every read surface at 200 via the ``{}`` fallback, while the rename
  *mutate* refuses with the coded 503 settings.config_unreadable and leaves
  the file byte-identical — never a 200 that rewrote the config from ``{}``.

* A FIFO squatting services.yaml never hangs a read (O_NONBLOCK open) and,
  per the documented _read_disk_for_mutate contract, holds no YAML to lose:
  the rename proceeds, replaces the FIFO with a regular services.yaml, and
  the override lands.

* The console-session mint answers the coded 404 vm_console.unavailable —
  never a resolver 500 — for allowlist leftovers: huge string/hex/date
  ports, torn-IPv6 (``[::1``), zone-suffixed, integer and huge hosts,
  non-dict entries, and non-dict allowlist/section shapes.

* POST /api/action dispatching to VM targets stays coded for raw hostile
  bodies: lone-surrogate targets/actions, >4300-digit int targets, ``1e999``
  and object targets.

* The vanished-CLI classification holds on the ``ip`` and ``info`` reply
  paths (separate ``_cli_missing`` call sites from the action tail): the
  ``(-1, "not found")`` sentinel answers the coded 503 only after the disk
  probe confirms the binary is gone; a signal-killed CLI still on disk keeps
  its raw ``{ok: false}`` result.
"""
from __future__ import annotations

import os
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from hub import audit, config, vms_svc
from hub.app_factory import create_app
from hub.auth import require_auth

_UUID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
UTM_LISTING = (
    "UUID                                 Status   Name\n"
    f"{_UUID} started  Ubuntu\n"
)
ORB_TEXT_LISTING = "NAME  STATE\nweb  running\n"
_HUGE_DIGITS = "9" * 5000
#: Hex dodges CPython's int(str) digit cap at YAML load; as a mapping key it
#: also trips YAML's 1024-char plain-scalar-key scanner limit.
_HEX_HUGE = "0x" + "f" * 5000


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


class _Vms6Case(unittest.TestCase):
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
            mock.patch.object(vms_svc, "UTMCTL", "/usr/local/bin/utmctl"),
            mock.patch.object(vms_svc, "ORBCTL", "/usr/local/bin/orbctl"),
            mock.patch.object(vms_svc, "sh", side_effect=sh),
            mock.patch.object(audit, "record"),
        )

    def _get(self, path, sh):
        vms_svc.invalidate_vm_lists()
        p = self._patched(sh)
        with p[0], p[1], p[2], p[3], p[4], p[5]:
            return self.client.get(path)

    def _assert_clean(self, resp, status=200):
        self.assertEqual(resp.status_code, status, resp.text[:200])
        resp.content.decode("utf-8")
        self.assertNotIn("\ud800", resp.text)


class OrbJsonEnvelopeZooTests(_Vms6Case):
    """orbctl JSON envelope leftovers cost fields or fall back — never a 500."""

    CASES = {
        "machines-dict": '{"machines":{"a":1}}',
        "machines-scalar": '{"machines":"web"}',
        "items-alias": '{"items":[{"name":"web","state":"running"}]}',
        "null-scalar-rows": '[null, 42, "x", {"name":"web","state":"running"}]',
        "duplicate-keys": '[{"name":"a","name":"web","state":"running"}]',
        "bom-prefix": '\ufeff[{"name":"web","state":"running"}]',
        "huge-digit-key": f'[{{"name":"web","state":"running","{_HUGE_DIGITS}":1}}]',
        "int-state": '[{"name":"web","state":42}]',
        "list-state": '[{"name":"web","state":["a"]}]',
        "huge-float-state": '[{"name":"web","state":1e999}]',
        "bool-id": '[{"name":"web","state":"running","id":true}]',
        "huge-float-id": '[{"name":"web","state":"running","id":1e999}]',
        "huge-int-distro": f'[{{"name":"web","state":"running","distro":{_HUGE_DIGITS}}}]',
        "object-distro": '[{"name":"web","state":"running","distro":{"a":[1e999]}}]',
    }

    def test_get_vms_and_downstream_surfaces_stay_200(self):
        for label, orb_json in self.CASES.items():
            sh = _sh_factory(orb_json=orb_json)
            with self.subTest(case=label):
                listing = self._get("/api/vms", sh)
                self._assert_clean(listing)
                names = {v["name"] for v in listing.json()["vms"]}
                # However the JSON leg degrades, both machines survive.
                self.assertIn("web", names)
                self.assertIn("Ubuntu", names)
                self._assert_clean(self._get("/api/settings/vms", sh))
                self._assert_clean(self._get("/api/apps/managed?force=true", sh))

    def test_non_id_leftovers_fall_back_to_the_machine_name(self):
        for label in ("bool-id", "huge-float-id"):
            with self.subTest(case=label):
                resp = self._get("/api/vms", _sh_factory(orb_json=self.CASES[label]))
                self._assert_clean(resp)
                row = next(v for v in resp.json()["vms"] if v["backend"] == "orb")
                self.assertEqual(row["uuid"], "web")


class UtmListingZooTests(_Vms6Case):
    """Hostile utmctl listing text never costs GET /api/vms or /api/status."""

    CASES = {
        "control-bytes": "H\r\n" + _UUID + " started  Ub\x00un\x1btu\x7f\r\n",
        "hundred-k-name": "H\n" + _UUID + " started  " + "n" * 100000 + "\n",
        "dash-led-name": "H\n" + _UUID + " started  --help\n",
        "two-columns-only": "H\n" + _UUID + " started\n",
        "empty-output": "",
        "digit-run-uuid": "H\n" + "9" * 36 + " started  Digits\n",
    }

    def test_listing_and_status_stay_200(self):
        for label, utm_out in self.CASES.items():
            sh = _sh_factory(utm_out=utm_out)
            with self.subTest(case=label):
                self._assert_clean(self._get("/api/vms", sh))
                self._assert_clean(self._get("/api/status?force=true", sh))

    def test_dash_led_listing_name_cannot_ride_into_argv(self):
        """The listed name reads back, but an action on it is refused before
        it can become a ``utmctl`` option."""
        sh = _sh_factory(utm_out=self.CASES["dash-led-name"])
        vms_svc.invalidate_vm_lists()
        p = self._patched(sh)
        with p[0], p[1], p[2], p[3], p[4], p[5]:
            resp = self.client.post(
                "/api/vms/--help/action", json={"action": "start"},
            )
        self.assertEqual(resp.status_code, 400, resp.text[:200])
        self.assertEqual(resp.json()["detail"]["code"], "vms.bad_id")


class TypedYamlOverrideZooTests(_Vms6Case):
    """YAML-typed override leftovers: reads stay 200 and a rename still lands."""

    CASES = {
        "numeric-keys-and-values": (
            "overrides:\n  123: {name: numname}\n"
            "  Ubuntu: {name: 456, group: 789, url: 3.5}\n"
        ),
        "inf-nan": "overrides:\n  Ubuntu: {name: .inf, group: .nan, url: -.inf, port: .inf, hide: .nan}\n",
        "dates": "overrides:\n  Ubuntu: {name: 2026-08-19, group: 2026-08-19T10:00:00Z, port: 2026-08-19}\n",
        "binary": 'overrides:\n  Ubuntu: {name: !!binary "/u3erb5w", group: !!binary "AAAA", url: !!binary "AAAA"}\n',
        "sets": "overrides:\n  Ubuntu:\n    name: !!set {a: null, b: null}\n    group: !!set {}\n",
        "port-list": "overrides:\n  Ubuntu: {name: real, port: [5900, 5901]}\n",
        "port-map": "overrides:\n  Ubuntu: {name: real, port: {a: 1}}\n",
        "hide-map": "overrides:\n  Ubuntu: {hide: {a: 1}}\n",
        "bool-null-keys": "overrides:\n  true: {name: boolkey}\n  ~: {name: nullkey}\n  Ubuntu: {name: real}\n",
        "merge-keys": "base: &b {name: merged}\noverrides:\n  Ubuntu:\n    <<: *b\n    group: g\n",
        "recursive-anchor": "overrides:\n  Ubuntu: &a {name: x, self: *a}\n",
        "hexhuge-values": (
            f"overrides:\n  Ubuntu: {{name: {_HEX_HUGE}, group: {_HEX_HUGE},"
            f" url: {_HEX_HUGE}, port: {_HEX_HUGE}}}\n"
        ),
    }

    def test_reads_stay_200_and_rename_lands(self):
        for label, ytext in self.CASES.items():
            with self.subTest(case=label):
                self._write_yaml_text(ytext)
                sh = _sh_factory(orb_json='[{"name":"web","state":"running"}]')
                self._assert_clean(self._get("/api/vms", sh))
                self._assert_clean(self._get("/api/status?force=true", sh))
                self._assert_clean(self._get("/api/bookmarks", sh))
                vms_svc.invalidate_vm_lists()
                p = self._patched(sh)
                with p[0], p[1], p[2], p[3], p[4], p[5]:
                    rename = self.client.post(
                        f"/api/vms/{_UUID}/action",
                        json={"action": "rename", "name": "zzz"},
                    )
                self._assert_clean(rename)
                self.assertEqual(config.override(_UUID).get("name"), "zzz")
                self._restore_yaml()


class UnparseableConfigMutateTests(_Vms6Case):
    """Unparseable services.yaml: reads fall back to {}, mutate refuses 503,
    and the file stays byte-identical — never a 200 that wiped the config."""

    CASES = {
        # A >1024-char plain-scalar mapping key trips YAML's scanner limit,
        # so this hex-huge override key makes the whole document unparseable.
        "hexhuge-scalar-key": f"overrides:\n  {_HEX_HUGE}: {{name: x}}\n  Ubuntu: {{name: real}}\n",
        "whole-document-list": "- 1\n- 2\n",
    }

    def test_reads_200_mutate_503_file_intact(self):
        for label, ytext in self.CASES.items():
            with self.subTest(case=label):
                self._write_yaml_text(ytext)
                before = config.YAML_PATH.read_bytes()
                sh = _sh_factory()
                self._assert_clean(self._get("/api/vms", sh))
                vms_svc.invalidate_vm_lists()
                p = self._patched(sh)
                with p[0], p[1], p[2], p[3], p[4], p[5]:
                    rename = self.client.post(
                        f"/api/vms/{_UUID}/action",
                        json={"action": "rename", "name": "zzz"},
                    )
                self.assertEqual(rename.status_code, 503, rename.text[:200])
                self.assertEqual(
                    rename.json()["detail"]["code"], "settings.config_unreadable",
                )
                self.assertEqual(config.YAML_PATH.read_bytes(), before)
                self._restore_yaml()


class FifoConfigMutateTests(_Vms6Case):
    """A FIFO squatting services.yaml: reads never hang, and the mutate
    proceeds — the documented ``_read_disk_for_mutate`` contract: a non-file
    node holds no YAML to lose, and the save replaces it."""

    @unittest.skipUnless(hasattr(os, "mkfifo"), "mkfifo unavailable")
    def test_fifo_reads_stay_200_and_rename_replaces_it(self):
        try:
            config.YAML_PATH.unlink()
        except OSError:
            pass
        os.mkfifo(config.YAML_PATH)
        config.reload_cfg()
        vms_svc.invalidate_vm_lists()
        sh = _sh_factory()
        self._assert_clean(self._get("/api/vms", sh))
        self._assert_clean(self._get("/api/settings/vms", sh))
        # The console mint reads the allowlist through the same config; the
        # FIFO reads as {} and the entry is simply unavailable — coded 404.
        with (
            mock.patch("hub.auth.browser_authenticated", return_value=True),
            mock.patch("hub.auth.session_username", return_value="admin"),
            mock.patch.object(vms_svc, "utm_vm_running", return_value=True),
            mock.patch.object(audit, "record"),
        ):
            mint = self.client.post(f"/api/vms/utm:{_UUID}/console/session")
        self.assertEqual(mint.status_code, 404, mint.text[:200])
        self.assertEqual(mint.json()["detail"]["code"], "vm_console.unavailable")
        vms_svc.invalidate_vm_lists()
        p = self._patched(sh)
        with p[0], p[1], p[2], p[3], p[4], p[5]:
            rename = self.client.post(
                f"/api/vms/{_UUID}/action",
                json={"action": "rename", "name": "landed"},
            )
        self._assert_clean(rename)
        # The FIFO is gone; a regular services.yaml carries the override.
        self.assertTrue(config.YAML_PATH.is_file())
        self.assertEqual(config.override(_UUID).get("name"), "landed")


class ConsoleAllowlistZooTests(_Vms6Case):
    """Allowlist leftovers answer the coded 404 mint, never a resolver 500."""

    def _mint(self):
        with (
            mock.patch("hub.auth.browser_authenticated", return_value=True),
            mock.patch("hub.auth.session_username", return_value="admin"),
            mock.patch.object(vms_svc, "utm_vm_running", return_value=True),
            mock.patch.object(audit, "record"),
        ):
            return self.client.post(f"/api/vms/utm:{_UUID}/console/session")

    def _entry(self, fields: str) -> str:
        return (
            "settings:\n  vm_console:\n    allowlist:\n"
            f"      {_UUID}: {fields}\n"
        )

    def test_hostile_allowlists_answer_coded_404(self):
        cases = {
            "port-huge-string": self._entry(f'{{enabled: true, port: "{_HUGE_DIGITS}"}}'),
            "port-hexhuge": self._entry(f"{{enabled: true, port: {_HEX_HUGE}}}"),
            "port-date": self._entry("{enabled: true, port: 2026-08-19}"),
            "host-torn-ipv6": self._entry('{enabled: true, port: 5900, host: "[::1"}'),
            "host-int": self._entry("{enabled: true, port: 5900, host: 2130706433}"),
            "host-hexhuge": self._entry(f"{{enabled: true, port: 5900, host: {_HEX_HUGE}}}"),
            "entry-list": self._entry("[1, 2]"),
            "allowlist-seq": "settings:\n  vm_console:\n    allowlist: [1, 2]\n",
            "vm-console-seq": "settings:\n  vm_console: [1]\n",
            "settings-seq": "settings: [1]\n",
            "protocol-int": self._entry("{enabled: true, port: 5900, protocol: 99}"),
        }
        for label, ytext in cases.items():
            with self.subTest(case=label):
                self._write_yaml_text(ytext)
                mint = self._mint()
                self.assertEqual(mint.status_code, 404, mint.text[:200])
                self.assertEqual(
                    mint.json()["detail"]["code"], "vm_console.unavailable",
                )
                listing = self._get("/api/vms", _sh_factory())
                self._assert_clean(listing)
                row = next(v for v in listing.json()["vms"] if v["backend"] == "utm")
                self.assertFalse(row["console"]["available"])
                self._restore_yaml()


class ApiActionVmDispatchTests(_Vms6Case):
    """POST /api/action VM dispatch stays coded for raw hostile bodies."""

    def test_raw_hostile_bodies_are_coded(self):
        cases = {
            "surrogate-target": (b'{"target": "\\ud800", "action": "start"}', (400, 404, 422)),
            "surrogate-action": (b'{"target": "Ubuntu", "action": "\\ud800"}', (400, 404, 422)),
            "huge-int-target": (b'{"target": ' + b"9" * 5000 + b', "action": "start"}', (400, 422)),
            "huge-float-target": (b'{"target": 1e999, "action": "start"}', (400, 422)),
            "object-target": (b'{"target": {"a": 1}, "action": "start"}', (400, 422)),
        }
        sh = _sh_factory(orb_json='[{"name":"web","state":"running"}]')
        vms_svc.invalidate_vm_lists()
        p = self._patched(sh)
        with p[0], p[1], p[2], p[3], p[4], p[5]:
            for label, (raw, allowed) in cases.items():
                with self.subTest(case=label):
                    resp = self.client.post(
                        "/api/action",
                        content=raw,
                        headers={"content-type": "application/json"},
                    )
                    self.assertIn(resp.status_code, allowed, (label, resp.text[:200]))
                    resp.content.decode("utf-8")
                    self.assertNotIn("\ud800", resp.text)

    def test_vm_targets_dispatch_and_unknowns_stay_coded(self):
        sh = _sh_factory(orb_json='[{"name":"web","state":"running","id":"mid"}]')
        vms_svc.invalidate_vm_lists()
        p = self._patched(sh)
        with p[0], p[1], p[2], p[3], p[4], p[5]:
            ok = self.client.post(
                "/api/action", json={"target": "orb:web", "action": "restart"},
            )
            self._assert_clean(ok)
            bad = self.client.post(
                "/api/action", json={"target": "orb:--evil", "action": "start"},
            )
        self.assertEqual(bad.status_code, 404, bad.text[:200])
        self.assertEqual(bad.json()["detail"]["code"], "actions.unknown_target")


class VanishedCliReplyPathTests(_Vms6Case):
    """The disk-confirmed vanished-CLI 503 on the ``ip`` / ``info`` reply
    paths — separate ``_cli_missing`` call sites from the action tail."""

    @staticmethod
    def _gone_sh(cmd, **kw):
        cmd = [str(c) for c in cmd]
        if cmd[1:2] == ["list"]:
            out = UTM_LISTING if "utmctl" in cmd[0] else ORB_TEXT_LISTING
            return (0, out, "")
        return (-1, "", "not found")

    def _run(self, utmctl, orbctl):
        vms_svc.invalidate_vm_lists()
        with (
            mock.patch.object(vms_svc, "_utm_available", return_value=True),
            mock.patch.object(vms_svc, "_orb_available", return_value=True),
            mock.patch.object(vms_svc, "UTMCTL", utmctl),
            mock.patch.object(vms_svc, "ORBCTL", orbctl),
            mock.patch.object(vms_svc, "sh", side_effect=self._gone_sh),
            mock.patch.object(audit, "record"),
        ):
            ip = self.client.post(
                f"/api/vms/{_UUID}/action", json={"action": "ip"},
            )
            info = self.client.post(
                "/api/vms/orb:web/action", json={"action": "info"},
            )
        return ip, info

    def test_confirmed_gone_answers_coded_503(self):
        ip, info = self._run("/nonexistent/utmctl", "/nonexistent/orbctl")
        self.assertEqual(ip.status_code, 503, ip.text[:200])
        self.assertEqual(ip.json()["detail"]["code"], "vms.utm_unavailable")
        self.assertEqual(info.status_code, 503, info.text[:200])
        self.assertEqual(info.json()["detail"]["code"], "vms.orb_unavailable")

    def test_still_on_disk_keeps_the_raw_result(self):
        ip, info = self._run(os.__file__, os.__file__)
        self.assertEqual(ip.status_code, 200, ip.text[:200])
        self.assertFalse(ip.json()["ok"])
        self.assertEqual(info.status_code, 200, info.text[:200])
        body = info.json()
        self.assertFalse(body["ok"])
        self.assertEqual(body["message"], "not found")


if __name__ == "__main__":
    unittest.main()
