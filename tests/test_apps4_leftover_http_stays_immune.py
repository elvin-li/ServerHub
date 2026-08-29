"""Fourth leftover-500s sweep of the Apps *managed* surface, over the real app.

The hunted classes (lone UTF-8 surrogates in keys AND values, the CPython
4300-digit int cap — including the uncapped YAML/plist hex form that arrives
already-int — huge-number JSON documents being ValueError not JSONDecodeError,
vanished-CLI / engine-down 503-vs-500, and empty ids acting on everything)
were re-reproduced against every route the Apps managed tab mounts:

    GET  /api/apps/managed           GET  /api/apps/managed/detail
    GET  /api/apps/managed/logs      POST /api/apps/managed/action

Three live leftovers were found and fixed:

* ``apps_manage_svc.logs`` / ``action`` skipped the bare-id guard ``detail``
  already has: an empty source (``id=docker`` / ``id=docker:``) fell through
  as ``source_id ""`` — ``_docker_logs("")`` prefix-matched *every*
  container, so a query that names nothing answered the whole fleet's logs
  concatenated, and ``action`` composed against the Services root itself.
  Both now answer the coded 400 ``apps.bad_id``
  (:class:`BareIdHttpTests` fails on the pre-fix tree);
* ``_vm_logs`` swallowed the coded ``apps.vm_not_found`` HTTPException into
  ``str(e)`` — the Python dict repr ``404: {'code': …}`` that the logs modal
  rendered verbatim as the "log".  The coded 404 now propagates, exactly as
  the launchd branch answers for a vanished agent
  (:class:`VmLogsVanishedHttpTests` fails on the pre-fix tree);
* ``vms_svc._list_orb_machines_uncached`` decoded ``orbctl list -f json``
  without a ``parse_int`` hook.  ``json.loads`` of a >4300-digit number is
  the digit-cap *ValueError* (not JSONDecodeError) for the whole document,
  so one leftover huge field threw away every machine's JSON row and fell to
  the degraded text listing — or to nothing when that second spawn failed
  too.  The huge field now loads as None and its siblings survive
  (:class:`OrbHugeIntJsonTests` fails on the pre-fix tree).

Everything else was already immune at the service level (apps3's
``_field_text`` / ``_safe_payload`` / ``_as_text`` probes, the launchd-logs
over-cap-path handler, the ``_compose_cmd`` failure-path engine probe) — but
those pins call service functions directly.  This battery pins the whole
cycle through ``create_app()``: request routing, Pydantic body parsing,
app_factory's sanitizing handlers, and Starlette's strict UTF-8 render.
"""
from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi import HTTPException

from hub import apps_manage_svc, vms_svc
from hub.app_factory import create_app
from hub.auth import require_auth

#: Hex spelling dodges CPython's int(str) parse cap, so plistlib really can
#: mint an int whose str() raises the 4300-digit ValueError.
_HEX_HUGE = "0x" + "f" * 4400

#: The decimal spelling that makes json.loads itself raise ValueError.
_HUGE_DIGITS = "9" * 5000

_POISON_PLIST = f"""<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>Label</key><integer>{_HEX_HUGE}</integer>
  <key>ProgramArguments</key><array><integer>{_HEX_HUGE}</integer></array>
  <key>WorkingDirectory</key><integer>{_HEX_HUGE}</integer>
  <key>KeepAlive</key><integer>{_HEX_HUGE}</integer>
  <key>StandardOutPath</key><integer>{_HEX_HUGE}</integer>
  <key>StandardErrorPath</key><integer>{_HEX_HUGE}</integer>
</dict></plist>
""".encode()

_app = None


def _the_app():
    global _app
    if _app is None:
        _app = create_app()
        _app.dependency_overrides[require_auth] = lambda: None
    return _app


async def _asgi_request(method, path, *, body=None, raw_body=None, query=b""):
    """Drive the full panel app (middleware + handlers) through one cycle."""
    app = _the_app()
    payload = raw_body if raw_body is not None else (
        b"{}" if body is None else json.dumps(body).encode("utf-8")
    )
    sent = False
    messages: list[dict] = []

    async def receive():
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": payload, "more_body": False}
        return {"type": "http.disconnect"}

    async def send(message):
        messages.append(message)

    scope = {
        "type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1", "method": method, "scheme": "http",
        "path": path, "raw_path": path.encode(), "query_string": query,
        "root_path": "",
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(payload)).encode()),
            (b"host", b"localhost:8086"),
        ],
        "server": ("localhost", 8086), "client": ("127.0.0.1", 1), "state": {},
    }
    await app(scope, receive, send)
    status = next(m["status"] for m in messages if m["type"] == "http.response.start")
    raw = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
    # The body must already be valid UTF-8 — decode strictly on purpose.
    return status, raw.decode("utf-8")


def request(method, path, *, body=None, raw_body=None, query=b""):
    return asyncio.run(_asgi_request(method, path, body=body, raw_body=raw_body, query=query))


def _code(text: str) -> str:
    detail = json.loads(text).get("detail")
    return detail.get("code") if isinstance(detail, dict) else str(detail)


class _AppsSandbox(unittest.TestCase):
    """Poisoned AGENTS_DIR + sandboxed SERVICES_ROOT, cheap sibling collectors."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        tmp = Path(self._tmp.name)
        self.agents = tmp / "agents"
        self.agents.mkdir()
        self.services = tmp / "services"
        self.services.mkdir()
        (self.agents / "local.poison.plist").write_bytes(_POISON_PLIST)
        self.sane_log = self.agents / "out.log"
        self.sane_log.write_text("alpha\nbeta\n")
        (self.agents / "local.sane.plist").write_bytes(
            f"""<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>Label</key><string>local.sane</string>
  <key>StandardOutPath</key><string>{self.sane_log}</string>
</dict></plist>
""".encode()
        )
        apps_manage_svc.inventory.invalidate()
        self.addCleanup(apps_manage_svc.inventory.invalidate)
        # services_uninstall_svc copies AGENTS_DIR at import time — patch both
        # bindings so detail (which merges the uninstall preview) stays local.
        for target, value in (
            ("hub.paths.AGENTS_DIR", str(self.agents)),
            ("hub.services_uninstall_svc.AGENTS_DIR", str(self.agents)),
        ):
            patched = mock.patch(target, value)
            patched.start()
            self.addCleanup(patched.stop)
        patched = mock.patch.object(apps_manage_svc, "SERVICES_ROOT", self.services)
        patched.start()
        self.addCleanup(patched.stop)
        # launchctl is absent on the test host; force the empty-listing branch
        # deterministically, and keep the sibling collectors cheap and hermetic.
        for target, kwargs in (
            ("hub.launchd_cache.listing", {"side_effect": RuntimeError("no launchd")}),
            ("hub.native_catalog.list_native_apps", {"return_value": []}),
            ("hub.containers_svc.list_stacks", {"return_value": []}),
            ("hub.containers_svc.list_containers",
             {"return_value": {"engine_up": False, "containers": []}}),
            ("hub.vms_svc.list_all_vms", {"return_value": {"vms": []}}),
            ("hub.apps_manage_svc.engine_up", {"return_value": False}),
        ):
            patched = mock.patch(target, **kwargs)
            patched.start()
            self.addCleanup(patched.stop)


class ManagedInventoryHostileHttpTests(_AppsSandbox):
    """GET /api/apps/managed with the launchd leftover zoo on disk."""

    def test_inventory_renders_the_zoo_and_keeps_every_row(self):
        status, text = request("GET", "/api/apps/managed", query=b"force=true")
        self.assertEqual(status, 200, text[:300])
        payload = json.loads(text)
        ids = {r["source_id"] for r in payload["items"] if r["kind"] == "launchd"}
        # The over-cap hex Label degrades to the filename stem; the row and
        # its sane sibling both survive the strict UTF-8 render.
        self.assertEqual(ids, {"local.poison", "local.sane"})
        self.assertEqual(payload["counts"]["launchd"], 2)
        self.assertNotIn("\ud800", text)

    def test_detail_of_the_poisoned_agent_is_200(self):
        status, text = request(
            "GET", "/api/apps/managed/detail", query=b"id=launchd:local.poison"
        )
        self.assertEqual(status, 200, text[:300])
        self.assertEqual(json.loads(text)["source_id"], "local.poison")

    def test_logs_report_both_unusable_keys_instead_of_raising(self):
        # StandardOutPath AND StandardErrorPath carry the already-int hex
        # leftover: each must cost its own section, never the endpoint.
        status, text = request(
            "GET", "/api/apps/managed/logs", query=b"id=launchd:local.poison"
        )
        self.assertEqual(status, 200, text[:300])
        payload = json.loads(text)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["log"].count("(invalid path)"), 2)
        self.assertNotIn("Exceeds the limit", text)

    def test_the_sane_agent_still_tails_its_log(self):
        status, text = request(
            "GET", "/api/apps/managed/logs", query=b"id=launchd:local.sane"
        )
        self.assertEqual(status, 200, text[:300])
        self.assertIn("beta", json.loads(text)["log"])


class BareIdHttpTests(_AppsSandbox):
    """The fixed leak: an id that names nothing must not act on everything.

    Fails on the pre-fix tree: ``logs`` answered 200 with every container's
    logs concatenated, and ``action`` ran compose against the Services root.
    """

    def test_bare_kind_logs_are_the_coded_400(self):
        for q in (b"id=docker", b"id=docker:", b"id=launchd:", b"id=vm:", b"id=native:"):
            with self.subTest(query=q):
                status, text = request("GET", "/api/apps/managed/logs", query=q)
                self.assertEqual(status, 400, text[:300])
                self.assertEqual(_code(text), "apps.bad_id")

    def test_bare_kind_action_is_the_coded_400(self):
        spawn = mock.patch.object(apps_manage_svc, "run_capped")
        with spawn as run:
            status, text = request(
                "POST", "/api/apps/managed/action",
                body={"id": "docker:", "action": "start"},
            )
        self.assertEqual(status, 400, text[:300])
        self.assertEqual(_code(text), "apps.bad_id")
        # Nothing was spawned against the Services root.
        run.assert_not_called()

    def test_detail_parity_is_unchanged(self):
        status, text = request("GET", "/api/apps/managed/detail", query=b"id=docker:")
        self.assertEqual(status, 400, text[:300])
        self.assertEqual(_code(text), "apps.bad_id")

    def test_bare_native_ids_still_work_everywhere(self):
        # The one legitimate colon-less spelling must keep working.
        status, text = request(
            "GET", "/api/apps/managed/logs", query=b"id=native-filebrowser"
        )
        self.assertEqual(status, 200, text[:300])
        status, text = request(
            "GET", "/api/apps/managed/detail", query=b"id=native-filebrowser"
        )
        self.assertEqual(status, 200, text[:300])

    def test_unknown_kind_stays_the_coded_400(self):
        status, text = request("GET", "/api/apps/managed/logs", query=b"id=weird:x")
        self.assertEqual(status, 400, text[:300])
        self.assertEqual(_code(text), "apps.unknown_kind")


class VmLogsVanishedHttpTests(_AppsSandbox):
    """The fixed leak: a vanished VM's logs are the coded 404, not a dict repr.

    Fails on the pre-fix tree: the body was HTTP 200 with
    ``"log": "404: {'code': 'apps.vm_not_found', …}"`` — a Python dict repr
    the logs modal rendered verbatim and no locale could translate.
    """

    def test_vanished_vm_logs_are_the_coded_404(self):
        status, text = request("GET", "/api/apps/managed/logs", query=b"id=vm:gone")
        self.assertEqual(status, 404, text[:300])
        self.assertEqual(_code(text), "apps.vm_not_found")
        self.assertNotIn("{'code'", text)

    def test_a_present_vm_still_answers_its_status_dump(self):
        with mock.patch(
            "hub.vms_svc.list_all_vms",
            return_value={"vms": [{
                "id": "box", "name": "box", "state": "running",
                "backend": "orb", "ips": ["198.51.100.7"], "actions": ["stop"],
            }]},
        ):
            status, text = request("GET", "/api/apps/managed/logs", query=b"id=vm:box")
        self.assertEqual(status, 200, text[:300])
        payload = json.loads(text)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["source"], "vm-status")
        self.assertIn("198.51.100.7", payload["log"])

    def test_a_non_http_backend_failure_keeps_a_clean_dict(self):
        # The residual broad except: a backend raise that is NOT the coded
        # HTTPException still answers the ok:false dict, with the exception
        # text scrubbed of leftover surrogates (exc_detail, not bare str).
        with mock.patch.object(
            apps_manage_svc, "_vm_detail",
            side_effect=ValueError("boom\ud800tail"),
        ):
            status, text = request("GET", "/api/apps/managed/logs", query=b"id=vm:box")
        self.assertEqual(status, 200, text[:300])
        payload = json.loads(text)
        self.assertFalse(payload["ok"])
        self.assertIn("boom", payload["log"])
        self.assertNotIn("\ud800", text)


class OrbHugeIntJsonTests(unittest.TestCase):
    """The fixed leak: one huge orbctl JSON field must cost itself, never the
    machine list.

    Fails on the pre-fix tree: ``json.loads`` raised the digit-cap ValueError
    for the whole document, the JSON listing fell to the degraded text
    listing, and with that second spawn failing too the entire OrbStack
    section of the Apps page vanished.
    """

    ORB_JSON = (
        '[{"name": "web", "state": "running", "distro": "ubuntu",'
        ' "memory": ' + _HUGE_DIGITS + '},'
        ' {"name": "db", "state": "stopped", "distro": "alpine", "id": "u-2"}]'
    )

    def _machines(self, json_rc=0, json_out=None, text_rc=1, text_out=""):
        calls = []

        def fake_sh(cmd, timeout=0, **kwargs):
            calls.append(list(cmd))
            if "-f" in cmd:
                return json_rc, self.ORB_JSON if json_out is None else json_out, ""
            return text_rc, text_out, ""

        with (
            mock.patch.object(vms_svc, "_orb_available", return_value=True),
            mock.patch.object(vms_svc, "sh", side_effect=fake_sh),
            mock.patch.object(vms_svc, "override", return_value={}),
        ):
            items = vms_svc._list_orb_machines_uncached()
        return items, calls

    def test_huge_field_keeps_both_machines_from_the_json_listing(self):
        items, calls = self._machines()
        self.assertEqual([m["orb_name"] for m in items], ["web", "db"])
        # The JSON listing answered; the degraded text fallback never ran.
        self.assertEqual(len(calls), 1)
        # The sibling machine keeps its JSON-only metadata.
        self.assertEqual(items[1]["distro"], "alpine")
        self.assertEqual(items[1]["uuid"], "u-2")

    def test_the_rows_encode_for_starlette(self):
        items, _ = self._machines()
        json.dumps(vms_svc._jsonable(items), ensure_ascii=False, allow_nan=False).encode("utf-8")

    def test_a_surrogate_escape_name_is_scrubbed_not_a_500(self):
        items, _ = self._machines(
            json_out='[{"name": "x\\ud800y", "state": "running"}]'
        )
        self.assertEqual(len(items), 1)
        self.assertNotIn("\ud800", items[0]["orb_name"])

    def test_a_sane_json_listing_is_unchanged(self):
        items, _ = self._machines(
            json_out='[{"name": "web", "state": "running", "distro": "ubuntu"}]'
        )
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["distro"], "ubuntu")

    def test_true_garbage_still_falls_to_the_text_listing(self):
        items, calls = self._machines(
            json_out="{not json", text_rc=0, text_out="NAME STATE\nweb running\n"
        )
        self.assertEqual([m["orb_name"] for m in items], ["web"])
        self.assertEqual(len(calls), 2)


class BodyParseGuardHttpTests(_AppsSandbox):
    """Hostile action bodies through the real app's parse + 422 handler."""

    def test_huge_int_literal_in_the_body_is_400_not_500(self):
        # json.loads raises the digit-cap ValueError, not JSONDecodeError;
        # FastAPI's body-parse guard must map it to 400.
        status, text = request(
            "POST", "/api/apps/managed/action",
            raw_body=b'{"id": "docker:x", "action": "start", "remove_data": '
                     + _HUGE_DIGITS.encode() + b"}",
        )
        self.assertEqual(status, 400, text[:300])

    def test_surrogate_escape_in_a_str_field_is_422_with_a_clean_body(self):
        # Pydantic refuses the lone surrogate (string_unicode) and the 422
        # body echoes the input; app_factory's sanitizing handler must keep
        # scrubbing it (the stock FastAPI handler 500s on the UTF-8 encode).
        status, text = request(
            "POST", "/api/apps/managed/action",
            raw_body=b'{"id": 42, "action": "st\\ud800art"}',
        )
        self.assertEqual(status, 422, text[:300])
        self.assertNotIn("\ud800", text)

    def test_surrogate_id_from_json_is_the_coded_400(self):
        # dict-free str fields accept the escape; require_positional refuses
        # it before it can reach an argv or the audit journal.
        status, text = request(
            "POST", "/api/apps/managed/action",
            raw_body=b'{"id": "docker:x\\ud800", "action": "start"}',
        )
        self.assertEqual(status, 400, text[:300])
        self.assertEqual(_code(text), "cli.invalid_value")
        self.assertNotIn("\ud800", text)

    def test_surrogate_action_name_is_a_scrubbed_400(self):
        status, text = request(
            "POST", "/api/apps/managed/action",
            raw_body=b'{"id": "docker:x", "action": "st\\ud800art"}',
        )
        self.assertEqual(status, 400, text[:300])
        self.assertEqual(_code(text), "apps.docker_action_unsupported")
        self.assertNotIn("\ud800", text)


class ComposeActionEngineDownHttpTests(_AppsSandbox):
    """Vanished-CLI / engine-down keep their coded shapes through the route."""

    def setUp(self):
        super().setUp()
        stack = self.services / "mystack"
        stack.mkdir()
        (stack / "docker-compose.yml").write_text("services: {}\n")
        # The up-front presence gate must pass: point DOCKER at a real file.
        import sys
        patched = mock.patch.object(apps_manage_svc, "DOCKER", sys.executable)
        patched.start()
        self.addCleanup(patched.stop)
        # cli_on_disk stubbed: the sentinel only classifies once the binary
        # is confirmed gone from disk (the compose_svc convention), and the
        # verdict must not depend on the suite machine's own docker binary.
        patched = mock.patch.object(
            apps_manage_svc, "cli_on_disk", return_value=False
        )
        patched.start()
        self.addCleanup(patched.stop)

    def _action(self, rc, msg, engine_up_answer, action="stop"):
        probe = mock.Mock(return_value=engine_up_answer)
        with (
            mock.patch.object(apps_manage_svc, "run_capped", return_value=(rc, msg)),
            mock.patch.object(apps_manage_svc, "engine_up", probe),
        ):
            status, text = request(
                "POST", "/api/apps/managed/action",
                body={"id": "docker:mystack", "action": action},
            )
        return status, text, probe

    def test_vanished_cli_sentinel_is_the_coded_soft_fail(self):
        status, text, probe = self._action(-1, "not found", engine_up_answer=False)
        self.assertEqual(status, 200, text[:300])
        payload = json.loads(text)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["code"], "container.engine_down")
        probe.assert_called_once_with(force=True)

    def test_a_timeout_keeps_its_original_shape(self):
        status, text, probe = self._action(124, "command timed out after 180s", True)
        self.assertEqual(status, 200, text[:300])
        payload = json.loads(text)
        self.assertNotIn("code", payload)
        self.assertIn("timed out", payload["message"])
        probe.assert_not_called()

    def test_sentinel_while_the_engine_answers_up_stays_raw(self):
        status, text, _ = self._action(-1, "not found", engine_up_answer=True)
        self.assertEqual(status, 200, text[:300])
        self.assertNotIn("code", json.loads(text))

    def test_stack_logs_carry_the_same_coded_shape(self):
        with (
            mock.patch.object(apps_manage_svc, "run_capped", return_value=(-1, "not found")),
            mock.patch.object(apps_manage_svc, "engine_up", return_value=False),
        ):
            status, text = request(
                "GET", "/api/apps/managed/logs", query=b"id=docker:mystack"
            )
        self.assertEqual(status, 200, text[:300])
        payload = json.loads(text)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["code"], "container.engine_down")


class ServiceLevelBareIdParityTests(unittest.TestCase):
    """The service functions agree with detail() on what a bad id is."""

    def _code_of(self, fn, *args):
        with self.assertRaises(HTTPException) as ctx:
            fn(*args)
        detail = ctx.exception.detail
        return detail["code"] if isinstance(detail, dict) else str(detail)

    def test_logs_and_action_refuse_the_empty_source(self):
        self.assertEqual(self._code_of(apps_manage_svc.logs, "docker:"), "apps.bad_id")
        self.assertEqual(self._code_of(apps_manage_svc.logs, "docker"), "apps.bad_id")
        self.assertEqual(
            self._code_of(apps_manage_svc.action, "vm:", "start"), "apps.bad_id"
        )

    def test_bare_native_ids_keep_dispatching(self):
        # Regression guard for the tightened guard: the colon-less native
        # spelling still lands in the native branch, not in bad_id.
        out = apps_manage_svc.logs("native-filebrowser")
        self.assertIsInstance(out, dict)
        self.assertIn("log", out)


if __name__ == "__main__":
    unittest.main()
