"""Leftover VMs-domain injection/wipe + HTTP-layer stays-immune pins.

Fourth sweep over the VM paths, continuing test_leftover_vm_500s,
test_vms_leftover_sentinel_surrogate_500s and
test_vms_console_hexint_key_leftover_500s:

* ``_parse_id`` matched the UUID shape *before* refusing a leading hyphen,
  and ``-`` is inside the ``[0-9A-Fa-f-]{36}`` class — so a 36-char dash-led
  id (all dashes, or ``-`` plus hex) rode straight into
  ``utmctl start {ident}`` argv as an option: the exact argument-injection
  class ``_argv_name`` closes for every non-uuid name.  A real UUID starts
  with a hex digit, never a hyphen.

* ``rename_vm_display`` persisted an unbounded display name into the
  services.yaml override.  One 2MB rename answered 200 and grew the file
  past ``config._YAML_CAP`` — after which every ``cfg()`` read answered
  ``{}`` (the admin account and every sibling key vanished from the panel's
  view) and the next ``mutate()`` rewrote services.yaml from that emptiness,
  persisting the wipe.  Capped at 64, matching accounts/apikeys/disk names.

* ``_argv_name`` had no length bound, so a multi-KB id/name reached
  utmctl/orbctl argv (and, through rename, became a services.yaml override
  key).  Bounded at 255 — cli_args.MAX_POSITIONAL_LEN.

Stays-immune pins (behaviour already correct, pinned at the HTTP layer
through the real on-disk services.yaml rather than mocked ``override`` /
``_allowlist`` internals):

* GET /api/vms answers 200 with a leftover hex-int override key/value, a
  numeric override key, ``!!binary`` / ``.inf`` / date override fields, and
  a hex-int console allowlist key sitting in the parsed config.
* POST /api/vms/{id}/action with a JSON ``"\\ud800"`` action escape answers
  the coded 400 (no raw surrogate in the response bytes).
"""
from __future__ import annotations

import json
import unittest
from unittest import mock

from fastapi import HTTPException
from fastapi.testclient import TestClient

from hub import audit, config, vms_svc
from hub.app_factory import create_app
from hub.auth import require_auth

_UUID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
_DASHES = "-" * 36
_DASH_LED = "-aaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
UTM_LISTING = (
    "UUID                                 Status   Name\n"
    f"{_UUID} started  Ubuntu\n"
)


def _detail(ctx) -> dict:
    detail = ctx.exception.detail
    return detail if isinstance(detail, dict) else {"code": str(detail)}


def _client() -> TestClient:
    app = create_app()
    app.dependency_overrides[require_auth] = lambda: True
    return TestClient(app, raise_server_exceptions=False)


class _YamlSandbox(unittest.TestCase):
    """Snapshot/restore the suite's shared on-disk services.yaml."""

    def setUp(self):
        try:
            self._orig = config.YAML_PATH.read_bytes()
        except OSError:
            self._orig = None
        self.addCleanup(self._restore)

    def _restore(self):
        if self._orig is None:
            try:
                config.YAML_PATH.unlink()
            except OSError:
                pass
        else:
            config.YAML_PATH.write_bytes(self._orig)
        config.reload_cfg()
        vms_svc.invalidate_vm_lists()

    def _write(self, text: str):
        config.YAML_PATH.parent.mkdir(parents=True, exist_ok=True)
        config.YAML_PATH.write_text(text, encoding="utf-8")
        config.reload_cfg()
        vms_svc.invalidate_vm_lists()


class DashLedUuidShapeTests(unittest.TestCase):
    """A dash-led 36-char id matched the uuid branch and became utmctl argv."""

    def test_dash_led_uuid_shapes_are_coded_not_argv(self):
        for vm_id in (_DASHES, _DASH_LED):
            with self.subTest(vm_id=vm_id):
                with (
                    mock.patch.object(vms_svc, "_utm_available", return_value=True),
                    mock.patch.object(vms_svc, "sh") as sh,
                    mock.patch.object(vms_svc, "_invalidate"),
                ):
                    with self.assertRaises(HTTPException) as ctx:
                        vms_svc.vm_action(vm_id, "start")
                self.assertEqual(ctx.exception.status_code, 400)
                self.assertEqual(_detail(ctx)["code"], "vms.bad_id")
                sh.assert_not_called()

    def test_real_uuid_still_parses_as_utm(self):
        backend, ident = vms_svc._parse_id(_UUID)
        self.assertEqual((backend, ident), ("utm", _UUID))

    def test_dash_led_uuid_route_is_coded_400(self):
        """Through POST /api/vms/{vm_id}/action — the mounted entry point."""
        client = _client()
        with (
            mock.patch.object(vms_svc, "_utm_available", return_value=True),
            mock.patch.object(vms_svc, "sh") as sh,
            mock.patch.object(audit, "record"),
        ):
            resp = client.post(f"/api/vms/{_DASHES}/action", json={"action": "start"})
        self.assertEqual(resp.status_code, 400, resp.text[:200])
        self.assertEqual(resp.json()["detail"]["code"], "vms.bad_id")
        sh.assert_not_called()


class OverlongIdAndNameTests(unittest.TestCase):
    """No listed machine has a 256+ char name; refuse before argv."""

    def test_overlong_id_is_coded_not_argv(self):
        with (
            mock.patch.object(vms_svc, "list_orb_machines", return_value=[]),
            mock.patch.object(vms_svc, "_utm_available", return_value=True),
            mock.patch.object(vms_svc, "sh") as sh,
            mock.patch.object(vms_svc, "_invalidate"),
        ):
            with self.assertRaises(HTTPException) as ctx:
                vms_svc.vm_action("a" * 256, "start")
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(_detail(ctx)["code"], "vms.bad_id")
        sh.assert_not_called()

    def test_overlong_clone_name_is_coded_not_argv(self):
        with (
            mock.patch.object(vms_svc, "_utm_available", return_value=True),
            mock.patch.object(vms_svc, "sh") as sh,
        ):
            with self.assertRaises(HTTPException) as ctx:
                vms_svc._utm_action("Ubuntu", "clone", name="c" * 256)
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(_detail(ctx)["code"], "vms.bad_machine_name")
        sh.assert_not_called()

    def test_255_char_name_still_passes(self):
        """The bound must not tighten below cli_args.MAX_POSITIONAL_LEN."""
        self.assertEqual(vms_svc._argv_name("n" * 255), "n" * 255)


class RenameCapTests(unittest.TestCase):
    """The persisted display name is bounded so one rename cannot outgrow
    config._YAML_CAP and blank the whole panel config."""

    def test_overlong_rename_is_coded_before_persisting(self):
        with mock.patch.object(vms_svc, "set_override", create=True) as so:
            with self.assertRaises(HTTPException) as ctx:
                vms_svc.rename_vm_display(_UUID, "N" * 65)
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(_detail(ctx)["code"], "vms.name_too_long")
        so.assert_not_called()

    def test_64_char_rename_still_lands(self):
        stored = {}
        with mock.patch.object(
            config, "set_override", lambda key, p: stored.update({key: dict(p)}),
        ):
            out = vms_svc.rename_vm_display(_UUID, "N" * 64)
        self.assertTrue(out["ok"])
        self.assertEqual(stored[_UUID]["name"], "N" * 64)


class RenameWipeRegressionTests(_YamlSandbox):
    """End to end: the 2MB rename that used to answer 200 and wipe cfg()."""

    def test_huge_rename_cannot_blank_the_config(self):
        self._write(
            "settings:\n"
            "  auth: {enabled: true, username: admin}\n"
            "overrides:\n"
            "  Ubuntu: {group: UTM}\n"
        )
        client = _client()
        with (
            mock.patch.object(vms_svc, "_utm_available", return_value=True),
            mock.patch.object(audit, "record"),
        ):
            resp = client.post(
                f"/api/vms/{_UUID}/action",
                json={"action": "rename", "name": "N" * (2 * 1024 * 1024)},
            )
        self.assertEqual(resp.status_code, 400, resp.text[:200])
        self.assertEqual(resp.json()["detail"]["code"], "vms.name_too_long")
        # The config must still parse whole: the 200-then-{} wipe is the bug.
        self.assertLess(config.YAML_PATH.stat().st_size, config._YAML_CAP)
        data = config.reload_cfg()
        self.assertEqual(
            (data.get("settings") or {}).get("auth", {}).get("username"), "admin",
        )
        self.assertEqual(config.override("Ubuntu"), {"group": "UTM"})


class HttpStaysImmuneTests(_YamlSandbox):
    """Already-correct behaviour, pinned through the mounted routes with the
    hostile leftovers on disk (the real config parse), not mocked internals."""

    #: PyYAML's scanner refuses simple keys longer than 1024 chars (the whole
    #: document then follows the corrupt-config {} path, covered elsewhere), so
    #: hex-int *keys* stay under that; the over-cap already-int (str() blows
    #: CPython's 4300-digit cap) can only enter on disk as a *value*.
    HOSTILE_YAML = (
        "settings:\n"
        "  vm_console:\n"
        "    allowlist:\n"
        "      0x" + "f" * 400 + ": {enabled: true}\n"
        f"      {_UUID}: {{enabled: true, host: 127.0.0.1, port: 5900}}\n"
        "overrides:\n"
        "  2024: {name: numbered}\n"
        "  Ubuntu:\n"
        "    name: .inf\n"
        "    group: 2026-08-19\n"
        "    url: !!binary aGVsbG8=\n"
        "    port: 0x" + "d" * 4400 + "\n"
    )

    def _fake_sh(self, cmd, **kw):
        cmd = [str(c) for c in cmd]
        if cmd and "utmctl" in cmd[0] and cmd[1:2] == ["list"]:
            return (0, UTM_LISTING, "")
        if cmd and "orbctl" in cmd[0]:
            if "-f" in cmd:
                return (0, '[{"name":"web","state":"running","id":"abc"}]', "")
            return (0, "NAME  STATE\nweb  running\n", "")
        return (0, "done", "")

    def test_get_vms_answers_200_with_hostile_config_on_disk(self):
        self._write(self.HOSTILE_YAML)
        client = _client()
        with (
            mock.patch.object(vms_svc, "_utm_available", return_value=True),
            mock.patch.object(vms_svc, "_orb_available", return_value=True),
            # shutil.which leaves ORBCTL None on a Linux CI host; the fake
            # dispatcher matches on the binary name.
            mock.patch.object(vms_svc, "UTMCTL", "/usr/local/bin/utmctl"),
            mock.patch.object(vms_svc, "ORBCTL", "/usr/local/bin/orbctl"),
            mock.patch.object(vms_svc, "sh", side_effect=self._fake_sh),
        ):
            resp = client.get("/api/vms")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        data = resp.json()
        names = {v["name"] for v in data["vms"]}
        # The hex-int allowlist key must not wipe the UTM row, and the ``.inf``
        # override name must fall back to the utmctl name.
        self.assertIn("Ubuntu", names)
        self.assertIn("web", names)
        row = next(v for v in data["vms"] if v["name"] == "Ubuntu")
        self.assertTrue(row["console"]["available"])
        self.assertEqual(row["group"], "2026-08-19")
        # The over-cap hex ``port:`` override reads as unreachable ("warn"),
        # exercised through the real port_open, not a mock.
        self.assertEqual(row["state"], "warn")
        json.dumps(data, ensure_ascii=False, allow_nan=False).encode("utf-8")

    def test_surrogate_action_escape_is_coded_400_over_http(self):
        client = _client()
        with (
            mock.patch.object(vms_svc, "_utm_available", return_value=True),
            mock.patch.object(vms_svc, "sh") as sh,
            mock.patch.object(audit, "record"),
        ):
            resp = client.post(
                f"/api/vms/{_UUID}/action",
                content=b'{"action": "bogus\\ud800"}',
                headers={"content-type": "application/json"},
            )
        self.assertEqual(resp.status_code, 400, resp.text[:200])
        self.assertEqual(resp.json()["detail"]["code"], "vms.utm_unsupported_action")
        self.assertNotIn("\\ud800", resp.text)
        sh.assert_not_called()

    def test_console_session_stays_coded_with_hostile_allowlist_on_disk(self):
        """Unauthenticated mint answers its coded 401 while the hex-int key
        sits in the parsed allowlist — never a 500."""
        self._write(self.HOSTILE_YAML)
        client = _client()
        resp = client.post(f"/api/vms/utm:{_UUID}/console/session")
        self.assertEqual(resp.status_code, 401, resp.text[:200])
        self.assertEqual(
            resp.json()["detail"]["code"], "vm_console.browser_session_required",
        )


if __name__ == "__main__":
    unittest.main()
