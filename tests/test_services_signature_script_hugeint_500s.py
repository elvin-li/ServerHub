"""Services sweep 3 leftovers: over-cap hex ints in signatures, script argv, app process.

CPython's int->str digit cap (4300) makes ``str()`` / f-strings / ``json.dumps``
raise ValueError on any int that YAML/plist hex loading (exempt from the
``int(str)`` parse cap) smuggled in.  Three spots on the Services surface still
called bare ``str()`` on such config-loaded values:

* **``service_signatures.parse_signature``** used ``str(raw["slug"])`` /
  ``str(raw["brew"])``.  One hand-edited ``service_signatures:`` row with
  ``slug: 0xfff…`` 500'd GET /api/services/signatures, 500'd PUT/DELETE of
  every *other* slug (remember_into / remove_from re-parse each stored row),
  and silently wiped every discovery row that reads
  ``configured_signatures()`` (the collectors are exception-isolated, so the
  whole collector's rows vanished rather than the poisoned one).

* **``actions._script_argv``** used ``str(part)`` on YAML list commands, so a
  ``start: [cmd, 0xfff…]`` leftover 500'd POST /api/action instead of the
  coded 400 the scalar path already answers for the same leftover.

* **``actions._app_process_name``** used bare ``str(name)``, so an app entry
  with ``process: 0xfff…`` 500'd POST /api/action instead of the coded 400
  ``actions.bad_process_name``.

* **``discovery.apps.collect_apps``** used ``str(a["process"])`` before its
  safety filter, so one poisoned app entry killed the collector and every app
  row silently vanished from /api/status.

All fixes are str() probes, not ``isinstance(x, str)`` gates: numeric YAML
values (``slug: 123``, ``start: [echo, 3000]``) must keep coercing.
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi import HTTPException  # noqa: E402

from hub import actions  # noqa: E402
from hub import service_signatures as ss  # noqa: E402
from hub import services_manage_svc as sms  # noqa: E402
from hub.discovery import apps as apps_discovery  # noqa: E402

#: Parses uncapped through YAML/plist hex loading, unrenderable by str().
OVER_CAP_INT = int("f" * 5000, 16)


def _starlette(payload) -> None:
    """Starlette's exact JSON render — raises on anything unencodable."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class ParseSignatureOverCapTests(unittest.TestCase):
    def test_over_cap_slug_drops_only_its_row(self):
        """``slug: 0xfff…`` used to raise the digit-cap ValueError here."""
        self.assertIsNone(ss.parse_signature({"slug": OVER_CAP_INT, "name": "x"}))

    def test_numeric_slug_still_coerces(self):
        """The str() probe rule: ``slug: 123`` must not be silently dropped."""
        parsed = ss.parse_signature({"slug": 123, "name": "My Svc"})
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["slug"], "123")

    def test_over_cap_brew_drops_the_field_not_the_row(self):
        parsed = ss.parse_signature({"slug": "ok", "name": "n", "brew": OVER_CAP_INT})
        self.assertIsNotNone(parsed)
        self.assertIsNone(parsed["brew"])
        _starlette(ss.yaml_signature(parsed))

    def test_configured_signatures_survive_a_poisoned_sibling(self):
        """One poisoned yaml row used to wipe every discovery signature."""
        rows = [
            {"slug": "good", "name": "Good", "procs": ["goodproc"]},
            {"slug": OVER_CAP_INT, "name": "Bad"},
        ]
        with patch("hub.config.cfg", return_value={"service_signatures": rows}):
            out = ss.configured_signatures()
        self.assertEqual([s["slug"] for s in out], ["good"])
        _starlette([ss.yaml_signature(s) for s in out])

    def test_list_signatures_with_poisoned_row_is_encodable_not_500(self):
        rows = [
            {"slug": "good", "name": "Good"},
            {"slug": OVER_CAP_INT, "name": "Bad"},
        ]
        with patch("hub.config.cfg", return_value={"service_signatures": rows}):
            out = sms.list_signatures()
        self.assertEqual([s["slug"] for s in out["signatures"]], ["good"])
        _starlette(out)

    def test_upsert_signature_survives_a_poisoned_stored_sibling(self):
        """remember_into re-parses each stored row; one leftover 500'd every PUT."""
        applied: dict = {"service_signatures": [{"slug": OVER_CAP_INT, "name": "Bad"}]}

        def fake_mutate(fn):
            fn(applied)
            return applied

        with (
            patch.object(sms.config, "mutate", fake_mutate),
            patch.object(sms, "invalidate_status"),
        ):
            out = sms.upsert_signature({"slug": "my-app", "name": "My App"})
        self.assertTrue(out["ok"])
        self.assertEqual(out["signature"]["slug"], "my-app")
        _starlette(out)

    def test_remove_from_survives_a_poisoned_stored_sibling(self):
        """remove_from re-parses each stored row; one leftover 500'd every DELETE."""
        data = {"service_signatures": [
            {"slug": OVER_CAP_INT, "name": "Bad"},
            {"slug": "gone", "name": "Gone"},
        ]}
        removed = ss.remove_from(data, "gone")
        self.assertIsNotNone(removed)
        self.assertEqual(removed["slug"], "gone")


class ScriptArgvOverCapTests(unittest.TestCase):
    def test_over_cap_list_part_is_coded_400_not_500(self):
        """``start: [echo, 0xfff…]`` used to raise the digit-cap ValueError."""
        with self.assertRaises(HTTPException) as ctx:
            actions._script_argv(["echo", OVER_CAP_INT])
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail.get("code"), "actions.empty_script")

    def test_numeric_list_part_still_coerces(self):
        """The str() probe rule: ``[echo, 3000]`` keeps working."""
        self.assertEqual(actions._script_argv(["echo", 3000]), ["echo", "3000"])

    def test_binary_list_part_keeps_its_repr(self):
        """The deliberate str()-not-_as_text contract stays: no option decode."""
        argv = actions._script_argv(["echo", b"--all"])
        self.assertEqual(argv, ["echo", "b'--all'"])

    def test_run_action_script_with_poisoned_start_is_coded_400(self):
        """POST /api/action on the poisoned script used to answer a bare 500."""
        meta = {"start": ["run-me", OVER_CAP_INT]}
        with patch.object(actions, "registry", return_value={"svc": ("script", meta)}):
            with self.assertRaises(HTTPException) as ctx:
                actions.run_action("svc", "start")
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail.get("code"), "actions.empty_script")


class AppProcessOverCapTests(unittest.TestCase):
    def test_over_cap_process_is_coded_400_not_500(self):
        with self.assertRaises(HTTPException) as ctx:
            actions._app_process_name(OVER_CAP_INT)
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail.get("code"), "actions.bad_process_name")

    def test_normal_process_name_still_passes(self):
        self.assertEqual(actions._app_process_name("Plex Media Server"), "Plex Media Server")

    def test_run_action_app_with_poisoned_process_is_coded_400(self):
        meta = {"process": OVER_CAP_INT}
        with patch.object(actions, "registry", return_value={"app1": ("app", meta)}):
            with self.assertRaises(HTTPException) as ctx:
                actions.run_action("app1", "start")
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail.get("code"), "actions.bad_process_name")


class CollectAppsOverCapProcessTests(unittest.TestCase):
    def test_poisoned_process_drops_only_its_entry(self):
        """One ``process: 0xfff…`` app used to wipe every app row silently."""
        cfg_data = {"apps": [
            {"id": "good", "name": "Good", "process": "goodproc"},
            {"id": "bad", "name": "Bad", "process": OVER_CAP_INT},
        ]}
        with (
            patch.object(apps_discovery, "cfg", return_value=cfg_data),
            patch.object(apps_discovery, "sh", return_value=(1, "", "")),
            patch.object(apps_discovery, "port_open", return_value=False),
            patch.object(apps_discovery, "configured_group_rules", return_value=[]),
        ):
            items = apps_discovery.collect_apps(False)
        self.assertEqual([i["id"] for i in items], ["good"])
        _starlette(items)


class DockerInspectHugeNumberStaysImmuneTests(unittest.TestCase):
    """json.loads of a >4300-digit number is ValueError, not JSONDecodeError.

    ``_docker_inspect`` already catches bare ValueError, so a poisoned
    ``docker inspect`` document degrades to {} instead of 500ing GET detail.
    Pinned so a future narrowing to JSONDecodeError re-fails here.
    """

    def test_huge_number_in_inspect_json_degrades_to_empty(self):
        out = '{"Config": {"n": ' + "9" * 5000 + "}}"
        with (
            patch.object(sms, "DOCKER", "/usr/local/bin/docker"),
            patch.object(sms.Path, "exists", return_value=True),
            patch.object(sms, "sh", return_value=(0, out, "")),
        ):
            self.assertEqual(sms._docker_inspect("web"), {})


if __name__ == "__main__":
    unittest.main()
