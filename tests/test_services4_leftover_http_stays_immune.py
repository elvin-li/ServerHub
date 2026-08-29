"""Fourth leftover-500s sweep of the Services page, over the real mounted app.

The hunted classes (lone UTF-8 surrogates in keys AND values, the CPython
4300-digit int cap — including the plist/YAML hex form that loads uncapped
through ``int(x, 16)`` and so arrives *already-int* — numeric YAML ids,
huge-number JSON bodies where ``json.loads`` raises ValueError not
JSONDecodeError, vanished-CLI 503-vs-500) were re-reproduced against the
routes the Services page mounts.  Three live leaks were found and fixed:

* **fixed** — ``services_manage_svc.service_logs`` formatted the raw plist
  ``StandardOutPath`` / ``StandardErrorPath`` value into its section header
  with ``f"===== {p} ====="``.  plistlib resolves a hex
  ``<integer>0x…</integer>`` through ``int(raw, 16)``, which CPython's
  4300-digit int(str) cap does not police, so a LaunchAgent whose log path
  was an over-cap hex integer raised the digit-cap ValueError there and
  500'd GET /api/services/{sid}/logs — in the launchd-kind branch AND in the
  unknown-kind fallback branch.  The exact sibling of the
  ``apps_manage_svc._launchd_logs`` leftover fixed earlier; the header now
  renders through the scrub and reports ``(unprintable)``.

* **fixed** — ``services_manage_svc._taken_service_ids`` coerced configured
  ids with a bare ``str(entry["id"])``.  One over-cap hex YAML id
  (``id: 0xfff…`` in *any* apps/scripts/stacks entry) raised the digit-cap
  ValueError and 500'd POST /api/services/{sid}/adopt and the detail of
  every auto-discovered row (both call ``adopt_defaults`` →
  ``suggest_id(taken=…)``).  The poisoned entry now costs only itself, the
  same drop the collectors already apply.

* **fixed** — numeric YAML ids on managed entries.  ``id: 8080`` loads as
  int; the collectors coerce it (``discovery.apps._entry_id``) so the page
  renders the row — with edit/forget buttons — under ``"8080"``, but
  ``update_script`` / ``forget_script`` / the detail app+script branches
  compared ``entry.get("id") == sid`` (int vs str) and answered the coded
  404 ``services.script_not_found`` for a row the page itself offered.  The
  compares now go through the same str()-probe coercion, so the edit lands
  and an over-cap hex id can never raise mid-compare.

The rest of the battery pins classes that are already immune, at the HTTP
layer (request routing, Pydantic body parsing, app_factory's handlers, and
Starlette's strict UTF-8 render), so they cannot silently regress:

* a >4300-digit int literal in a JSON body is the parse 400 (ValueError,
  not JSONDecodeError — FastAPI's body guard, never a 500);
* a ``\\ud800`` escape in a bulk-action id echoes back scrubbed in a clean
  200 per-id result, and a surrogate path param is the coded 400;
* an over-cap ``?lines=`` query is Pydantic's 422;
* a docker CLI that vanished mid-request answers the coded 503
  ``container.engine_down`` on GET logs — and rides inside the bulk-action
  200 as a per-id coded failure — only after the disk confirm; the same
  sentinel with the CLI still on disk keeps the raw uncoded answer.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from hub import actions, services_manage_svc as sms
from hub.app_factory import create_app
from hub.auth import require_auth

#: The hex spelling parses uncapped (``int(x, 16)``), so a live over-cap int
#: really can exist in memory; only rendering it back is impossible.
_HUGE_HEX = "0x" + "f" * 5000
_HUGE_INT = int("f" * 5000, 16)

_app = None


def _the_app():
    global _app
    if _app is None:
        _app = create_app()
        _app.dependency_overrides[require_auth] = lambda: None
    return _app


def _client() -> TestClient:
    # raise_server_exceptions=False: a real 500 must arrive as HTTP 500, not
    # as a re-raised exception that would mask which route crashed.
    return TestClient(_the_app(), raise_server_exceptions=False)


def _write_hex_logpath_plist(agents: Path, label: str = "local.hexlog") -> None:
    # plistlib.dumps refuses over-cap ints on *write*; a hand-edited XML
    # plist parses them fine on *read* — exactly the hostile leftover.
    (agents / f"{label}.plist").write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<plist version="1.0"><dict>'
        f"<key>Label</key><string>{label}</string>"
        "<key>ProgramArguments</key><array><string>/bin/true</string></array>"
        f"<key>StandardOutPath</key><integer>{_HUGE_HEX}</integer>"
        f"<key>StandardErrorPath</key><integer>{_HUGE_HEX}</integer>"
        "</dict></plist>",
        encoding="utf-8",
    )


class HexPlistLogPathTests(unittest.TestCase):
    """GET /api/services/{sid}/logs with an over-cap hex plist log path."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.agents = Path(self._tmp.name)
        _write_hex_logpath_plist(self.agents)

    def test_launchd_kind_branch_reports_unprintable_not_500(self):
        svc = {"id": "local.hexlog", "kind": "launchd", "name": "hexlog"}
        with (
            mock.patch.object(sms, "AGENTS_DIR", str(self.agents)),
            mock.patch.object(sms, "find_service", return_value=svc),
        ):
            r = _client().get("/api/services/local.hexlog/logs")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["kind"], "launchd")
        self.assertIn("(unprintable)", body["log"])

    def test_unknown_kind_fallback_branch_is_also_immune(self):
        """The second copy of the f-string, behind the plist-path fallback."""
        with (
            mock.patch.object(sms, "AGENTS_DIR", str(self.agents)),
            mock.patch.object(sms, "DOCKER", ""),
            mock.patch.object(sms, "find_service", return_value=None),
        ):
            r = _client().get("/api/services/local.hexlog/logs")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["kind"], "launchd")
        self.assertIn("(unprintable)", body["log"])

    def test_real_log_paths_keep_their_verbatim_header(self):
        """The scrub must not eat the ordinary path an operator debugs with."""
        log = self.agents / "svc.out.log"
        log.write_text("line one\n", encoding="utf-8")
        (self.agents / "local.plain.plist").write_text(
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<plist version="1.0"><dict>'
            "<key>Label</key><string>local.plain</string>"
            "<key>ProgramArguments</key><array><string>/bin/true</string></array>"
            f"<key>StandardOutPath</key><string>{log}</string>"
            "</dict></plist>",
            encoding="utf-8",
        )
        svc = {"id": "local.plain", "kind": "launchd", "name": "plain"}
        with (
            mock.patch.object(sms, "AGENTS_DIR", str(self.agents)),
            mock.patch.object(sms, "find_service", return_value=svc),
        ):
            r = _client().get("/api/services/local.plain/logs")
        self.assertEqual(r.status_code, 200)
        self.assertIn(f"===== {log} =====", r.json()["log"])
        self.assertIn("line one", r.json()["log"])


class AdoptTakenIdsOverCapTests(unittest.TestCase):
    """One over-cap hex YAML id used to 500 adopt and every auto detail."""

    _AUTO = {
        "id": "auto:1", "name": "node", "kind": "auto",
        "state": "ok", "actions": [],
        "meta": {"pid": 0, "process": "node", "ports": [3000]},
    }

    def _poisoned_cfg(self) -> dict:
        return {
            "apps": [{"id": _HUGE_INT, "name": "poisoned"}],
            "scripts": [{"id": "keep-me", "name": "keeper", "ports": [3000]}],
            "stacks": [],
        }

    def test_adopt_route_survives_a_poisoned_sibling_id(self):
        data = self._poisoned_cfg()

        def fake_mutate(fn):
            fn(data)
            return data

        with (
            mock.patch.object(sms, "find_service", return_value=self._AUTO),
            mock.patch.object(sms, "cfg", return_value=data),
            mock.patch.object(sms.config, "mutate", fake_mutate),
            mock.patch.object(sms, "invalidate_status"),
        ):
            r = _client().post("/api/services/auto:1/adopt", json={"remember": False})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["id"], "node")
        # The healthy sibling still reserved its id through the probe.
        with mock.patch.object(sms, "cfg", return_value=data):
            self.assertIn("keep-me", sms._taken_service_ids())

    def test_auto_detail_route_survives_a_poisoned_sibling_id(self):
        """service_detail of an auto row calls the same taken-ids path."""
        with (
            mock.patch.object(sms, "find_service", return_value=self._AUTO),
            mock.patch.object(sms, "cfg", return_value=self._poisoned_cfg()),
        ):
            r = _client().get("/api/services/auto:1/detail")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertTrue(body.get("can_adopt"))
        self.assertEqual(body["adopt_defaults"]["ports"], [3000])

    def test_taken_ids_probe_semantics(self):
        """Renderable int coerces; over-cap drops itself; bool never "True"."""
        data = {
            "apps": [{"id": 8080}, {"id": _HUGE_INT}, {"id": True}],
            "scripts": [{"id": "plain"}],
            "stacks": [],
        }
        with mock.patch.object(sms, "cfg", return_value=data):
            taken = sms._taken_service_ids()
        self.assertEqual(taken, {"8080", "plain"})


class NumericScriptIdTests(unittest.TestCase):
    """A numeric YAML id renders on the page; its edit must land, not 404."""

    def _cfg(self) -> dict:
        return {"scripts": [{"id": 8080, "name": "num", "ports": [3000]}]}

    def test_put_script_route_finds_the_numeric_row(self):
        data = self._cfg()

        def fake_mutate(fn):
            fn(data)
            return data

        with (
            mock.patch.object(sms, "cfg", return_value=data),
            mock.patch.object(sms.config, "mutate", fake_mutate),
            mock.patch.object(sms, "invalidate_status"),
        ):
            r = _client().put("/api/services/8080/script", json={"name": "renamed"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["entry"]["name"], "renamed")
        self.assertEqual(data["scripts"][0]["name"], "renamed")

    def test_delete_script_route_forgets_the_numeric_row(self):
        data = self._cfg()

        def fake_mutate(fn):
            fn(data)
            return data

        with (
            mock.patch.object(sms, "cfg", return_value=data),
            mock.patch.object(sms.config, "mutate", fake_mutate),
            mock.patch.object(sms, "invalidate_status"),
        ):
            r = _client().delete("/api/services/8080/script")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(data["scripts"], [])

    def test_detail_script_branch_populates_for_the_numeric_row(self):
        svc = {
            "id": "8080", "name": "num", "kind": "script",
            "state": "ok", "actions": [],
        }
        with (
            mock.patch.object(sms, "find_service", return_value=svc),
            mock.patch.object(sms, "cfg", return_value=self._cfg()),
        ):
            r = _client().get("/api/services/8080/detail")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertTrue(body.get("can_edit_script"))
        self.assertEqual(body["script_defaults"]["ports"], [3000])

    def test_unknown_id_still_answers_the_coded_404(self):
        with mock.patch.object(sms, "cfg", return_value=self._cfg()):
            r = _client().put("/api/services/nope/script", json={"name": "x"})
        self.assertEqual(r.status_code, 404)
        self.assertEqual(r.json()["detail"]["code"], "services.script_not_found")


class HttpLayerStaysImmunePins(unittest.TestCase):
    """Classes already immune, pinned through the full request cycle."""

    def test_huge_int_json_body_is_the_parse_400_not_500(self):
        """json.loads raises ValueError (not JSONDecodeError) past the digit
        cap; FastAPI's body guard must keep it a 4xx."""
        body = '{"ids": ["a"], "action": "start", "x": ' + "9" * 5000 + "}"
        r = _client().post(
            "/api/services/bulk-action",
            content=body.encode(),
            headers={"content-type": "application/json"},
        )
        self.assertEqual(r.status_code, 400)

    def test_surrogate_bulk_id_echoes_scrubbed_in_a_clean_200(self):
        r = _client().post(
            "/api/services/bulk-action",
            content=b'{"ids": ["x\\ud800y"], "action": "start"}',
            headers={"content-type": "application/json"},
        )
        self.assertEqual(r.status_code, 200)
        row = r.json()["results"][0]
        self.assertFalse(row["ok"])
        self.assertEqual(row["code"], "actions.unknown_target")
        # Scrubbed, not the raw surrogate — the body already round-tripped
        # Starlette's strict UTF-8 encode to reach us.
        self.assertNotIn("\ud800", row["id"])

    def test_surrogate_path_param_is_the_coded_400(self):
        with mock.patch.object(sms, "find_service", return_value=None):
            r = _client().get("/api/services/x%ED%A0%80y/detail")
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.json()["detail"]["code"], "cli.invalid_value")

    def test_over_cap_lines_query_is_pydantic_422(self):
        with (
            mock.patch.object(sms, "find_service", return_value=None),
            mock.patch.object(sms, "DOCKER", ""),
        ):
            r = _client().get("/api/services/nope/logs?lines=" + "9" * 5000)
        self.assertEqual(r.status_code, 422)

    def test_logs_vanished_cli_is_the_coded_503_after_disk_confirm(self):
        svc = {"id": "web", "kind": "container", "name": "web"}
        with (
            mock.patch.object(sms, "find_service", return_value=svc),
            mock.patch.object(sms, "DOCKER", "/usr/local/bin/docker"),
            mock.patch.object(sms, "sh", return_value=(-1, "", "not found")),
            mock.patch.object(sms, "engine_up", return_value=False),
            mock.patch.object(sms, "cli_on_disk", return_value=False),
        ):
            r = _client().get("/api/services/web/logs")
        self.assertEqual(r.status_code, 503)
        self.assertEqual(r.json()["detail"]["code"], "container.engine_down")

    def test_logs_sentinel_with_cli_on_disk_keeps_the_raw_answer(self):
        """No disk confirm, no 503: ENOENT fires for present-but-broken too."""
        svc = {"id": "web", "kind": "container", "name": "web"}
        with (
            mock.patch.object(sms, "find_service", return_value=svc),
            mock.patch.object(sms, "DOCKER", "/usr/local/bin/docker"),
            mock.patch.object(sms, "sh", return_value=(-1, "", "not found")),
            mock.patch.object(sms, "engine_up", return_value=True),
            mock.patch.object(sms, "cli_on_disk", return_value=True),
        ):
            r = _client().get("/api/services/web/logs")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["log"], "not found")

    def test_bulk_action_vanished_cli_rides_as_a_coded_per_id_failure(self):
        """run_action's 503 must land in the per-id result, not 500 the bulk."""
        with (
            mock.patch.object(actions, "registry",
                              return_value={"web": ("container", {})}),
            mock.patch.object(actions, "sh", return_value=(-1, "", "not found")),
            mock.patch("hub.actions.engine_up", return_value=False),
            mock.patch("hub.actions.cli_on_disk", return_value=False),
        ):
            r = _client().post(
                "/api/services/bulk-action",
                json={"ids": ["web"], "action": "stop"},
            )
        self.assertEqual(r.status_code, 200)
        row = r.json()["results"][0]
        self.assertFalse(row["ok"])
        self.assertEqual(row["code"], "container.engine_down")


if __name__ == "__main__":
    unittest.main()
