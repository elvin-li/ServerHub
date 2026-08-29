"""Fifth leftover-500s sweep of the Dashboard, over the real mounted app.

The hunted classes (lone UTF-8 surrogates in keys AND values, the CPython
4300-digit int cap — including plist/YAML hex forms that parse uncapped
through ``int(x, 16)`` and arrive *already-int* — huge-number JSON bodies
where ``json.loads`` raises ValueError not JSONDecodeError, numeric YAML ids
that must coerce through the str() probe, vanished-CLI degradation,
iterbombs, torn-IPv6 urlsplit ValueError, and the plist
ExpatError/AttributeError/IndexError trio) were re-hunted against every read
the Dashboard page mounts — /api/status, /api/health, /api/health/checks,
/api/system/sensors (full + light), /api/system/host, /api/system/power,
/api/ollama/status, /api/storage (full + light), /api/ups, /api/bookmarks,
/api/containers, /api/tools/ports, /api/alerts, /api/metrics (legacy +
range), /api/adaptive/compose-scan, /api/maintenance — plus the mutation
routes the page's widgets call.

**No live leak was found.**  The dash/dash2/dash3/dash4 service-layer and
HTTP-layer hardening covers every vector this sweep could produce.  What
was NOT yet pinned is what this battery adds:

* **The subprocess choke point.**  Every prior pin mocks each module's own
  ``sh`` import, so a collector that grew a direct ``subprocess`` call (or a
  new pool leg) would sit outside every existing mock.  The choke-point
  battery fakes ``subprocess.run`` / ``subprocess.check_output`` themselves
  — under every payload class at once, across the whole tile set, in a
  throwaway subprocess so the poisoned process-global caches cannot leak
  into this suite.  (This probing is also what exposed that
  ``platform.processor()`` reaches ``check_output(text=True)`` outside
  ``hub.util.sh`` entirely — exactly the kind of bypass a per-module mock
  can never see.)

* **The poisoned services.yaml zoo across the whole page**, not just
  /api/status (dash4's scope): a torn-IPv6 ``settings.ollama.url`` must be
  *visibly* rejected (url_rejected, loopback default) instead of raising
  urlsplit's ValueError into GET /api/ollama/status; a surrogate
  ``ui.locale`` falls back instead of echoing; an over-cap hex
  ``metrics_interval`` (already-int) cannot 500 GET /api/metrics; a numeric
  Maintenance task id coerces through the str() probe and stays runnable
  while its over-cap hex sibling drops alone.

* **Widget-route input contracts**: the huge-int JSON body on
  POST /api/system/power/action is the parse 400 (the ValueError-not-
  JSONDecodeError guard), a surrogate-escape action echoes back scrubbed in
  the coded 400, surrogate/huge-digit Maintenance task ids answer the coded
  404 / the empty 200 log, and the boolean/int query params of every tile
  answer 422 with a UTF-8-renderable body.
"""
from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from hub import bookmarks_svc, config, ollama_svc, status
from hub.app_factory import create_app
from hub.auth import require_auth

BASE = Path(__file__).resolve().parent.parent
DRIVER = Path(__file__).resolve().parent / "dash5_choke_driver.py"

#: The hex spelling parses uncapped (``int(x, 16)``): a live over-cap int
#: really can exist in memory; only rendering it back is impossible.
_HUGE_HEX = "0x" + "F" * 5000

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


def _assert_clean_utf8(testcase: unittest.TestCase, response) -> None:
    testcase.assertNotIn("\ud800", response.text)
    testcase.assertNotIn("\udfff", response.text)
    response.text.encode("utf-8")


class ChokePointPayloadTests(unittest.TestCase):
    """Every Dashboard tile, one hostile payload class per subprocess.

    The driver fakes ``subprocess.run``/``check_output`` (NOT per-module
    ``sh``), so every collector — pool legs, direct spawns, stdlib helpers —
    sees the payload.  A raw 5xx (503 excepted), a lone surrogate, or an
    unrenderable body anywhere in the tile set fails the run.
    """

    def _drive(self, payload: str) -> None:
        proc = subprocess.run(
            [sys.executable, str(DRIVER), payload],
            capture_output=True, text=True, timeout=300, cwd=str(BASE),
        )
        self.assertEqual(
            proc.returncode, 0,
            f"payload {payload!r} leaked:\n{proc.stdout}\n{proc.stderr[-2000:]}",
        )

    def test_surrogate_output_everywhere(self):
        self._drive("surrogate")

    def test_binary_output_everywhere(self):
        self._drive("binary")

    def test_over_cap_digit_run_everywhere(self):
        self._drive("hugeint")

    def test_json_scalar_where_objects_are_expected(self):
        self._drive("json_scalar")

    def test_torn_plist_everywhere(self):
        self._drive("plist_torn")

    def test_string_root_plist_everywhere(self):
        self._drive("plist_string_root")

    def test_already_int_over_cap_plist_hex_integer(self):
        self._drive("plist_hexint")

    def test_failing_probe_with_surrogate_stderr(self):
        self._drive("fail_surrogate")

    def test_every_cli_vanished_from_disk(self):
        self._drive("vanished")

    def test_torn_ipv6_authority_output(self):
        self._drive("torn_ipv6")

    def test_iterbomb_output(self):
        self._drive("iterbomb")


#: services.yaml as an operator's hand-edit could leave it.  Double-quoted
#: YAML ``\\ud800`` escapes decode to real lone surrogates; ``0xF…`` loads
#: through ``int(x, 16)`` past the digit cap; ``.inf`` is a float; the bare
#: timestamp loads as a datetime; the torn IPv6 URL raises in urlsplit.
_POISONED_YAML = """\
settings:
  adaptive: false
  metrics_interval: %(huge)s
  alert_interval: 2023-01-02 03:04:05
  resource_mode: "hi\\ud800gh"
  ui:
    locale: "j\\ud800a"
    theme: 2024
  ollama:
    url: "http://[::1"
    label: "la\\ud800bel"
  thresholds:
    cpu_pct: .inf
    "k\\ud800ey": "v\\ud800al"
quick_links:
  - name: "L\\ud800ink"
    url: "http://[::1"
    port: %(huge)s
maintenance:
  - id: 99999
    name: "s\\ud800cript"
    cmd: "echo hi"
  - id: %(huge)s
    name: over
    cmd: "echo no"
  - id: "ok/task"
    name: fine
    cmd: "echo ok"
apps: []
scripts: []
""" % {"huge": _HUGE_HEX}


class PoisonedConfigDashboardTests(unittest.TestCase):
    """The on-disk zoo, read by every config-backed Dashboard surface."""

    def setUp(self):
        try:
            self._previous = config.YAML_PATH.read_bytes()
        except OSError:
            self._previous = None
        config.YAML_PATH.parent.mkdir(parents=True, exist_ok=True)
        config.YAML_PATH.write_text(_POISONED_YAML, encoding="utf-8")
        config.reload_cfg()
        self.addCleanup(self._restore)
        self._reset_caches()
        self.addCleanup(self._reset_caches)

    def _restore(self):
        if self._previous is None:
            try:
                config.YAML_PATH.unlink()
            except OSError:
                pass
        else:
            config.YAML_PATH.write_bytes(self._previous)
        config.reload_cfg()

    @staticmethod
    def _reset_caches():
        status.invalidate_status()
        with status._lock:
            status._status_cache.update(t=0.0, v=None)
        bookmarks_svc.list_bookmarks.cache_clear()
        ollama_svc.status.cache_clear()

    def test_settings_render_clean_and_the_surrogate_locale_falls_back(self):
        response = _client().get("/api/settings")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _assert_clean_utf8(self, response)
        payload = response.json()
        # ``"j\ud800a"`` is not an allowed locale; the reader falls back to
        # the default instead of echoing the surrogate into the SPA boot.
        self.assertEqual(payload["ui"]["locale"], "zh-CN")

    def test_torn_ipv6_ollama_url_is_visibly_rejected_not_a_500(self):
        # urlsplit("http://[::1") raises ValueError on 3.12; the guard must
        # refuse the origin (url_rejected) and serve the loopback default,
        # never let the ValueError wipe GET /api/ollama/status.
        response = _client().get("/api/ollama/status?force=true")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _assert_clean_utf8(self, response)
        payload = response.json()
        self.assertEqual(payload["url"], "http://127.0.0.1:11434")
        self.assertIs(payload["url_rejected"], True)

    def test_over_cap_hex_metrics_interval_cannot_500_the_metrics_read(self):
        # settings.metrics_interval arrived already-int and over-cap: the
        # sampling-interval reader must degrade, not ValueError the render.
        client = _client()
        for path in ("/api/metrics", "/api/metrics?range=48h"):
            response = client.get(path)
            self.assertEqual(response.status_code, 200, response.text[:300])
            _assert_clean_utf8(self, response)

    def test_numeric_maintenance_id_coerces_and_over_cap_hex_drops_alone(self):
        response = _client().get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _assert_clean_utf8(self, response)
        rows = {row["id"]: row for row in response.json()}
        # The YAML int 99999 coerced through the str() probe (the list id IS
        # the id the run/log routes can find); the over-cap hex sibling
        # dropped without costing its neighbours; the surrogate name scrubbed.
        self.assertEqual(sorted(rows), ["99999", "ok/task"])
        self.assertEqual(rows["99999"]["name"], "s?cript")

    def test_the_numeric_id_the_list_serves_is_runnable(self):
        response = _client().post("/api/maintenance/99999/run")
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertTrue(response.json()["ok"])

    def test_status_and_bookmarks_survive_the_torn_ipv6_quick_link(self):
        client = _client()
        response = client.get("/api/status")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _assert_clean_utf8(self, response)
        links = response.json()["links"]
        self.assertEqual(links[0]["name"], "L?ink")
        self.assertIsNone(links[0]["port"])

        response = client.get("/api/bookmarks?force=true")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _assert_clean_utf8(self, response)

    def test_adaptive_scan_stays_a_200_under_the_zoo(self):
        response = _client().get("/api/adaptive/compose-scan")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _assert_clean_utf8(self, response)


class WidgetInputContractTests(unittest.TestCase):
    """Hostile HTTP inputs on the routes the Dashboard's widgets call."""

    def test_huge_int_power_body_is_the_parse_400_not_500(self):
        # json.loads raises the digit-cap ValueError (not JSONDecodeError);
        # the body-parse guard must map it to 400, never a 500.
        response = _client().post(
            "/api/system/power/action",
            content=b'{"action": ' + b"9" * 5000 + b"}",
            headers={"content-type": "application/json"},
        )
        self.assertEqual(response.status_code, 400, response.text[:300])
        _assert_clean_utf8(self, response)

    def test_surrogate_escape_action_echoes_back_scrubbed_in_the_coded_400(self):
        response = _client().post(
            "/api/system/power/action",
            content=b'{"action": "sl\\ud800eep", "confirm": true}',
            headers={"content-type": "application/json"},
        )
        self.assertEqual(response.status_code, 400, response.text[:300])
        _assert_clean_utf8(self, response)
        detail = response.json()["detail"]
        self.assertEqual(detail["code"], "power.unknown_action")
        self.assertEqual(detail["params"]["action"], "sl?eep")

    def test_hostile_maintenance_task_ids_answer_the_coded_404(self):
        client = _client()
        for tid in ("%ED%A0%80", "9" * 4400):
            with self.subTest(tid=tid[:12]):
                response = client.post(f"/api/maintenance/{tid}/run")
                self.assertEqual(response.status_code, 404, response.text[:300])
                _assert_clean_utf8(self, response)
                self.assertEqual(
                    response.json()["detail"]["code"],
                    "maintenance.unknown_task",
                )

    def test_huge_digit_maintenance_log_poll_is_the_empty_200(self):
        response = _client().get("/api/maintenance/" + "9" * 4400 + "/log")
        self.assertEqual(response.status_code, 200, response.text[:300])
        payload = response.json()
        self.assertIs(payload["running"], False)
        self.assertIsNone(payload["rc"])

    def test_hostile_query_params_answer_422_with_renderable_bodies(self):
        # %ED%A0%80 is the UTF-8 spelling of a lone surrogate; the huge digit
        # run is past the str->int cap.  Every tile's bool/int param must
        # answer the validation 422 and the body must render as UTF-8.
        surrogate = "%ED%A0%80"
        huge = "9" * 5000
        client = _client()
        for path in (
            f"/api/system/sensors?force={surrogate}",
            f"/api/system/sensors?light={huge}",
            f"/api/storage?light={huge}",
            f"/api/ups?force={surrogate}",
            f"/api/containers?stats={surrogate}",
            f"/api/tools/ports?limit={huge}",
            f"/api/alerts?limit={surrogate}",
            f"/api/bookmarks?force={huge}",
            f"/api/status?force={surrogate}",
            f"/api/ollama/status?force={huge}",
            f"/api/system/host?force={surrogate}",
        ):
            with self.subTest(path=path[:40]):
                response = client.get(path)
                self.assertEqual(response.status_code, 422, response.text[:300])
                _assert_clean_utf8(self, response)


if __name__ == "__main__":
    unittest.main()
