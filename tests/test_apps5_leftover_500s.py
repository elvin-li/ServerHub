"""Fifth leftover sweep of the Apps / fleet surfaces, over the real app.

The hunted classes (leftover FIFOs that must not hang, oversize / torn /
over-cap-hex plists, UTF-8 surrogates in keys and values, huge-number JSON
bodies being ValueError not JSONDecodeError, option-shaped and
surrogate-bearing ids) were re-reproduced against the surfaces the prior
apps/apps2/apps3/apps4 sweeps had not finished:

    GET  /api/apps/managed            (launchd inventory plist reads)
    GET  /api/catalog                 (host-language preference plist read)
    GET  /api/apps/autostart          POST /api/apps/autostart
    POST /api/apps/autostart/docker-policy

Two live leftovers were found and fixed — both hangs, which are worse than
the 500s the sweeps hunt because no error handler ever runs:

* ``apps_manage_svc._plist_dict`` read ``LaunchAgents/*.plist`` with a bare
  ``path.open("rb")``.  A plain open of a FIFO parks until a writer appears,
  so one leftover FIFO named ``*.plist`` hung GET /api/apps/managed (and
  detail / logs, which walk ``_launchd_apps`` too) forever — the Apps page
  simply never loaded again.  The reader is now ``util.read_bytes_capped``
  (O_NONBLOCK + regular-file check), whose OSError the call site already
  degrades to "no plist" (:class:`FifoPlistHttpTests` hangs on the pre-fix
  tree);
* ``catalog.host_languages`` read ``.GlobalPreferences.plist`` the same way
  after a ``stat()`` that answers fine for a FIFO, hanging GET /api/catalog
  — the whole App Store tab — on a leftover FIFO occupying the preferences
  path (:class:`FifoGlobalPrefsHttpTests` hangs on the pre-fix tree).

Everything else probed here was already immune; those probes are kept as
stays-immune pins over the full ``create_app()`` cycle, because the
``/api/apps/autostart`` console had service-level hardening but no HTTP
battery: hostile brew rows (lone-surrogate names, bytes files, huge-int
fields, non-dict rows), the launchd plist zoo (torn XML, empty file,
over-cap hex ``<integer>``, oversize, FIFO), and hostile action bodies
(huge-int literals, surrogate ids, option-shaped ``--all`` names).
"""
from __future__ import annotations

import errno
import json
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from fastapi.testclient import TestClient  # noqa: E402

from hub import apps_manage_svc, autostart_svc, catalog  # noqa: E402
from hub.app_factory import create_app  # noqa: E402
from hub.auth import require_auth  # noqa: E402

#: Hex spelling dodges CPython's int(str) parse cap, so plistlib really can
#: mint an int whose str() raises the 4300-digit ValueError.
_HEX_HUGE = "0x" + "f" * 4400

#: The decimal spelling that makes json.loads itself raise ValueError.
_HUGE_DIGITS = "9" * 5000

#: Generous bound: every request below answers in well under a second on the
#: fixed tree; the pre-fix tree parks forever on the FIFO open.
_DEADLINE = 15.0

_app = None


def _client() -> TestClient:
    global _app
    if _app is None:
        _app = create_app()
        _app.dependency_overrides[require_auth] = lambda: None
    return TestClient(_app, raise_server_exceptions=False)


def _bounded(fn):
    """Run *fn* with a watchdog: a hang must fail the test, not the runner.

    The pre-fix FIFO reads block inside ``open()`` with no timeout anywhere
    above them, so a plain request would hang unittest forever.  The worker
    is a daemon thread: on the pre-fix tree it stays parked and the test
    *fails* instead.
    """
    box: dict = {}

    def work():
        try:
            box["result"] = fn()
        except BaseException as exc:  # noqa: BLE001 - report, don't swallow
            box["error"] = exc

    t = threading.Thread(target=work, daemon=True)
    t.start()
    t.join(_DEADLINE)
    if "error" in box:
        raise box["error"]
    if "result" not in box:
        raise AssertionError(
            f"request did not answer within {_DEADLINE}s — a leftover FIFO hang"
        )
    return box["result"]


def _request(method: str, path: str, *, params=None, body=None, raw_body=None):
    def go():
        client = _client()
        if method == "GET":
            r = client.get(path, params=params)
        else:
            if raw_body is not None:
                r = client.post(
                    path, content=raw_body,
                    headers={"content-type": "application/json"},
                )
            else:
                r = client.post(path, json=body)
        # The body must already be valid UTF-8 — decode strictly on purpose.
        return r.status_code, r.content.decode("utf-8")

    return _bounded(go)


def _code(text: str) -> str:
    detail = json.loads(text).get("detail")
    return detail.get("code") if isinstance(detail, dict) else str(detail)


_POISON_PLIST = f"""<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>Label</key><integer>{_HEX_HUGE}</integer>
  <key>RunAtLoad</key><true/>
  <key>ProgramArguments</key><array><integer>{_HEX_HUGE}</integer></array>
</dict></plist>
""".encode()


class _AgentsZoo(unittest.TestCase):
    """A LaunchAgents directory holding every leftover plist shape at once."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        tmp = Path(self._tmp.name)
        self.agents = tmp / "agents"
        self.agents.mkdir()
        self.services = tmp / "services"
        self.services.mkdir()
        (self.agents / "local.sane.plist").write_bytes(
            b"""<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>Label</key><string>local.sane</string>
  <key>RunAtLoad</key><true/>
</dict></plist>
"""
        )
        (self.agents / "local.poison.plist").write_bytes(_POISON_PLIST)
        (self.agents / "local.torn.plist").write_bytes(b"<?xml \xff\xfe garbage")
        (self.agents / "local.empty.plist").write_bytes(b"")
        (self.agents / "local.oversize.plist").write_bytes(
            b"<!-- " + b"x" * (300 * 1024) + b" -->"
        )
        os.mkfifo(self.agents / "local.fifo.plist")


class _AppsSandbox(_AgentsZoo):
    """The zoo mounted where /api/apps/managed reads, siblings hermetic."""

    def setUp(self):
        super().setUp()
        apps_manage_svc.inventory.invalidate()
        self.addCleanup(apps_manage_svc.inventory.invalidate)
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


class FifoPlistHttpTests(_AppsSandbox):
    """The fixed hang: a FIFO named *.plist must cost itself, never the page.

    Hangs (and so fails on the watchdog) on the pre-fix tree: ``_plist_dict``'s
    bare ``open()`` parked forever inside GET /api/apps/managed.
    """

    def test_inventory_answers_with_the_fifo_on_disk(self):
        status, text = _request(
            "GET", "/api/apps/managed", params={"force": "true"}
        )
        self.assertEqual(status, 200, text[:300])
        payload = json.loads(text)
        ids = {r["source_id"] for r in payload["items"] if r["kind"] == "launchd"}
        # The FIFO degrades to its filename stem like every unreadable plist;
        # the whole zoo renders and the sane sibling keeps its parsed label.
        self.assertEqual(
            ids,
            {"local.sane", "local.poison", "local.torn",
             "local.empty", "local.oversize", "local.fifo"},
        )
        self.assertNotIn("\ud800", text)

    def test_fifo_detail_is_a_coded_404_not_a_hang(self):
        status, text = _request(
            "GET", "/api/apps/managed/detail", params={"id": "launchd:local.fifo"}
        )
        # The row lists (filename stem), but the uninstall preview the detail
        # merges refuses a path that is not a regular plist file.
        self.assertEqual(status, 404, text[:300])
        self.assertEqual(_code(text), "services.uninstall_unknown")

    def test_fifo_logs_are_a_coded_404_not_a_hang(self):
        status, text = _request(
            "GET", "/api/apps/managed/logs", params={"id": "launchd:local.fifo"}
        )
        self.assertEqual(status, 404, text[:300])
        self.assertEqual(_code(text), "apps.launchd_not_found")

    def test_the_sane_agent_still_parses_after_the_reader_swap(self):
        status, text = _request(
            "GET", "/api/apps/managed/detail", params={"id": "launchd:local.sane"}
        )
        self.assertEqual(status, 200, text[:300])
        self.assertEqual(json.loads(text)["source_id"], "local.sane")


class PlistDictUnitTests(_AgentsZoo):
    """_plist_dict's contract for every leftover shape, called direct."""

    def test_fifo_returns_none_promptly(self):
        out = _bounded(lambda: apps_manage_svc._plist_dict(self.agents / "local.fifo.plist"))
        self.assertIsNone(out)

    def test_oversize_returns_none(self):
        self.assertIsNone(
            apps_manage_svc._plist_dict(self.agents / "local.oversize.plist")
        )

    def test_torn_and_empty_return_none(self):
        self.assertIsNone(apps_manage_svc._plist_dict(self.agents / "local.torn.plist"))
        self.assertIsNone(apps_manage_svc._plist_dict(self.agents / "local.empty.plist"))

    def test_missing_returns_none(self):
        self.assertIsNone(apps_manage_svc._plist_dict(self.agents / "local.gone.plist"))

    def test_sane_still_parses(self):
        data = apps_manage_svc._plist_dict(self.agents / "local.sane.plist")
        self.assertEqual(data["Label"], "local.sane")

    def test_over_cap_hex_int_still_loads_as_a_dict(self):
        # The already-int leftover parses; its str() blowing up later is the
        # callers' problem and their _as_text probes already absorb it.
        data = apps_manage_svc._plist_dict(self.agents / "local.poison.plist")
        self.assertIsInstance(data, dict)


class FifoGlobalPrefsHttpTests(unittest.TestCase):
    """The fixed hang: a FIFO occupying .GlobalPreferences.plist must not
    park GET /api/catalog (the store overview reads the host languages).

    Hangs (and so fails on the watchdog) on the pre-fix tree.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.prefs = Path(self._tmp.name) / ".GlobalPreferences.plist"
        os.mkfifo(self.prefs)
        patched = mock.patch.object(catalog, "_GLOBAL_PREFS", self.prefs)
        patched.start()
        self.addCleanup(patched.stop)
        self._saved_cache = catalog._lang_cache
        catalog._lang_cache = None
        self.addCleanup(lambda: setattr(catalog, "_lang_cache", self._saved_cache))

    def test_store_overview_answers_with_the_fifo_on_disk(self):
        status, text = _request("GET", "/api/catalog")
        self.assertEqual(status, 200, text[:300])
        self.assertIn("templates", json.loads(text))

    def test_host_languages_degrade_to_english(self):
        langs = _bounded(catalog.host_languages)
        self.assertEqual(langs, ("en",))

    def test_read_bytes_capped_is_what_refuses_the_fifo(self):
        # The guard the fix leans on: non-regular files are OSError(EINVAL).
        from hub.util import read_bytes_capped
        with self.assertRaises(OSError) as ctx:
            _bounded(lambda: read_bytes_capped(self.prefs, 1024))
        self.assertEqual(ctx.exception.errno, errno.EINVAL)


class AutostartOverviewHostileHttpTests(_AgentsZoo):
    """GET /api/apps/autostart stays immune with hostile brew rows and the
    launchd plist zoo on disk (stays-immune pins: this surface had no HTTP
    battery, only service-level hardening)."""

    HOSTILE_BREW = [
        {"name": "x\ud800y", "status": None, "file": b"\xff\xfe"},
        {"name": 10 ** 5000, "status": {"a": 1}, "file": ["x"]},
        "not-a-dict",
        {"name": "good", "status": "started", "file": ""},
    ]

    def setUp(self):
        super().setUp()
        autostart_svc.overview.invalidate()
        self.addCleanup(autostart_svc.overview.invalidate)
        for target, kwargs in (
            ("hub.autostart_svc.AGENTS_DIR", {"new": self.agents}),
            ("hub.autostart_svc.engine_up", {"return_value": False}),
            ("hub.autostart_svc.brew_services_list", {"return_value": self.HOSTILE_BREW}),
            # A real file, so the BREW presence gate passes deterministically.
            ("hub.autostart_svc.BREW", {"new": sys.executable}),
            ("hub.autostart_svc.loaded_labels", {"return_value": frozenset()}),
            ("hub.autostart_svc.sh", {"return_value": (1, "", "")}),
        ):
            patched = mock.patch(target, **kwargs)
            patched.start()
            self.addCleanup(patched.stop)

    def test_overview_renders_the_zoo_with_a_clean_utf8_body(self):
        status, text = _request(
            "GET", "/api/apps/autostart", params={"force": "true"}
        )
        self.assertEqual(status, 200, text[:300])
        self.assertNotIn("\ud800", text)
        payload = json.loads(text)
        brew_names = [
            i.get("name") for i in payload["items"] if i.get("kind") == "brew"
        ]
        # The sane brew row survives its hostile siblings.
        self.assertIn("good", brew_names)
        launchd_ids = {
            i.get("label") for i in payload["items"] if i.get("kind") == "launchd"
        }
        # The FIFO plist degrades to its stem instead of hanging the page,
        # and the sane agent keeps its parsed label.
        self.assertIn("local.sane", launchd_ids)
        self.assertIn("local.fifo", launchd_ids)

    def test_counts_stay_renderable(self):
        status, text = _request("GET", "/api/apps/autostart", params={"force": "true"})
        self.assertEqual(status, 200, text[:300])
        counts = json.loads(text)["counts"]
        self.assertEqual(counts["total"], len(json.loads(text)["items"]))


class AutostartActionHostileHttpTests(unittest.TestCase):
    """Hostile POST /api/apps/autostart bodies through the real app."""

    def setUp(self):
        autostart_svc.overview.invalidate()
        self.addCleanup(autostart_svc.overview.invalidate)

    def test_bare_id_is_the_coded_400(self):
        status, text = _request(
            "POST", "/api/apps/autostart", body={"id": "nocolon", "enabled": True}
        )
        self.assertEqual(status, 400, text[:300])
        self.assertEqual(_code(text), "autostart.bad_id")

    def test_surrogate_kind_is_a_scrubbed_coded_400(self):
        status, text = _request(
            "POST", "/api/apps/autostart",
            raw_body=b'{"id": "wei\\ud800rd:x", "enabled": true}',
        )
        self.assertEqual(status, 400, text[:300])
        self.assertEqual(_code(text), "autostart.unknown_kind")
        self.assertNotIn("\ud800", text)

    def test_surrogate_launchd_label_is_the_coded_400(self):
        status, text = _request(
            "POST", "/api/apps/autostart",
            raw_body=b'{"id": "launchd:x\\ud800", "enabled": false}',
        )
        self.assertEqual(status, 400, text[:300])
        self.assertEqual(_code(text), "cli.invalid_value")
        self.assertNotIn("\ud800", text)

    def test_option_shaped_brew_name_is_refused_before_any_spawn(self):
        with mock.patch.object(autostart_svc, "run_capped") as spawn:
            status, text = _request(
                "POST", "/api/apps/autostart",
                body={"id": "brew:--all", "enabled": False},
            )
        self.assertEqual(status, 400, text[:300])
        self.assertEqual(_code(text), "cli.invalid_value")
        spawn.assert_not_called()

    def test_huge_int_literal_in_the_body_is_400_not_500(self):
        # json.loads raises the digit-cap ValueError, not JSONDecodeError;
        # the body-parse guard must map it to 400.
        status, text = _request(
            "POST", "/api/apps/autostart",
            raw_body=b'{"id": "launchd:x", "enabled": '
                     + _HUGE_DIGITS.encode() + b"}",
        )
        self.assertEqual(status, 400, text[:300])

    def test_surrogate_in_a_bool_field_is_422_with_a_clean_body(self):
        status, text = _request(
            "POST", "/api/apps/autostart",
            raw_body=b'{"id": "launchd:x", "enabled": "y\\ud800es"}',
        )
        self.assertEqual(status, 422, text[:300])
        self.assertNotIn("\ud800", text)


class DockerPolicyHostileHttpTests(unittest.TestCase):
    """Hostile POST /api/apps/autostart/docker-policy bodies."""

    def test_surrogate_policy_is_the_coded_400_scrubbed(self):
        status, text = _request(
            "POST", "/api/apps/autostart/docker-policy",
            raw_body=b'{"name": "web", "policy": "alw\\ud800ays"}',
        )
        self.assertEqual(status, 400, text[:300])
        self.assertEqual(_code(text), "container.bad_policy")
        self.assertNotIn("\ud800", text)

    def test_surrogate_name_is_refused_before_any_docker_spawn(self):
        with mock.patch("hub.containers_svc.docker") as spawn:
            status, text = _request(
                "POST", "/api/apps/autostart/docker-policy",
                raw_body=b'{"name": "we\\ud800b", "policy": "always"}',
            )
        self.assertEqual(status, 400, text[:300])
        self.assertEqual(_code(text), "cli.invalid_value")
        self.assertNotIn("\ud800", text)
        spawn.assert_not_called()

    def test_option_shaped_name_is_refused_before_any_docker_spawn(self):
        with mock.patch("hub.containers_svc.docker") as spawn:
            status, text = _request(
                "POST", "/api/apps/autostart/docker-policy",
                body={"name": "--privileged", "policy": "always"},
            )
        self.assertEqual(status, 400, text[:300])
        self.assertEqual(_code(text), "cli.invalid_value")
        spawn.assert_not_called()


if __name__ == "__main__":
    unittest.main()
