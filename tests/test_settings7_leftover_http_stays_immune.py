"""Settings7 leftover sweep: stays-immune HTTP pins over the mounted app.

A hostile sweep of the Settings surfaces (PUT /api/settings, PUT
/api/identity, POST /api/settings/power, the notify-channel CRUD, alert
test/check, export, diagnostics) over the real ``create_app()`` found one
live leftover — the lazy-port URL gate, fixed and pinned in
test_settings7_leftover_badport_url_500s — and everything below already
degrading to a 200, a coded 4xx, or the coded 503.  Each pin names a
regression a single dropped guard would silently re-open:

* **Over-cap decimal ints in JSON bodies.**  ``json.loads`` of a
  >4300-digit literal raises CPython's digit-cap *ValueError*, not
  JSONDecodeError; only FastAPI's catch-all body handler turns that into
  the coded 400.  Narrowing that except to JSONDecodeError re-opens a raw
  500 on every JSON mutate route at once.

* **Wire-level CESU-8 surrogates.**  ``json.loads`` decodes request bytes
  with ``surrogatepass``, so ``\\xed\\xa0\\x80`` in the body arrives as a
  real lone surrogate — not as the ``\\ud800`` escape prior sweeps pinned.
  The unconstrained ``host_ip`` write must land and every later read must
  scrub at the edge.

* **Hostile power prefs.**  The soft-fail dict contract: a surrogate key
  answers ``{ok: false, code: power.bad_key}`` whose body must survive the
  UTF-8 encode; a >4300-digit ``value`` is the body-parse 400.

* **Leftover FIFOs must not hang.**  A FIFO squatting services.yaml makes
  auth fail closed (401, the config is unreadable) — but the request must
  *terminate*: every read goes through O_NONBLOCK + S_ISREG.  A FIFO on
  the lock file is cleared and the save still lands.  FIFOs on the
  data-dir stores (alerts.jsonl, metrics.jsonl, diagnostics-latest.json,
  notify-credentials.json) cost only their own feature, never the route,
  and the export answers its coded refusal when CONFIG_FILE is a FIFO.

* **Alert dispatch over poisoned notify config.**  Torn-IPv6 ha_url,
  surrogate token, bad-port webhook_url, channels whose topic/server/
  min_level are over-cap hex ints or lone surrogates: POST
  /api/alerts/test and the per-channel tests answer 200 with encodable
  bodies (dispatch never raises), and GET /api/alerts/channels scrubs.

* **The scalar host_ip save-cap branch.**  settings6 pinned the section
  merge (ips list); the direct scalar patch rides a different branch of
  ``put_settings``.  An over-cap value is the coded 503 with the on-disk
  file byte-identical, and the refusal must not wedge the next save.
"""
from __future__ import annotations

import json
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import yaml
from fastapi.testclient import TestClient

from hub import auth, config
from hub.app_factory import create_app

PASSWORD = "correct-horse-battery"
HUGE_HEX = "0x" + "F" * 5000
JSON_HDR = {"content-type": "application/json"}

_APP = None


def app():
    global _APP
    if _APP is None:
        _APP = create_app()
    return _APP


def _starlette_encode(body) -> str:
    """Starlette's exact response encode; raises where a 500 would happen."""
    text = json.dumps(body, ensure_ascii=False, allow_nan=False)
    text.encode("utf-8")
    return text


class _AppSandbox(unittest.TestCase):
    """Scratch services.yaml + data dir; a fresh authenticated client per test."""

    #: Appended after the auth block, inside the settings mapping (2-space indent).
    settings_extra = ""

    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.data = self.root / "data"
        self.data.mkdir()
        self.yaml_path = self.root / "services.yaml"
        for target, attr, value in (
            (config, "YAML_PATH", self.yaml_path),
            (config, "DATA_DIR", self.data),
            (config, "BASE", self.root),
            (config, "_LOCK_PATH", self.data / ".services.yaml.lock"),
            (auth, "SECRET_FILE", self.data / ".session-secret"),
            (auth, "SETUP_TOKEN_FILE", self.data / ".setup-token"),
            (auth, "LOCAL_TOKEN_FILE", self.data / ".local-client-token"),
        ):
            patcher = mock.patch.object(target, attr, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.addCleanup(config.reload_cfg)
        auth._secret_cache = None
        auth._login_attempts.clear()
        self.yaml_path.write_text(
            "settings:\n"
            "  auth:\n"
            "    enabled: true\n"
            "    username: admin\n"
            f'    password_hash: "{auth.hash_password(PASSWORD)}"\n'
            + self.settings_extra
        )
        config.reload_cfg()
        self.client = TestClient(app(), raise_server_exceptions=False)
        response = self.client.post(
            "/api/auth/login", json={"username": "admin", "password": PASSWORD}
        )
        assert response.status_code == 200, response.text

    def stored_settings(self) -> dict:
        return (yaml.safe_load(self.yaml_path.read_text()) or {}).get("settings") or {}

    def assert_coded_not_500(self, response, status=None):
        if status is not None:
            self.assertEqual(response.status_code, status, response.text[:300])
        else:
            self.assertLess(response.status_code, 500, response.text[:300])
        _starlette_encode(response.json())
        return response.json()


class OverCapJsonIntBodyTests(_AppSandbox):
    """>4300-digit JSON int literals are the body-parse 400, never a raw 500.

    ``json.loads`` raises the digit-cap ValueError — not JSONDecodeError —
    so these ride FastAPI's catch-all body handler.  One pin per mutate
    route shape: a top-level int field, a nested section int, a typed int
    body param, and a str-typed field handed an int literal.
    """

    def test_every_settings_mutate_route_answers_400(self):
        huge = b"9" * 5000
        for label, method, path, body in (
            ("settings top-level int", "PUT", "/api/settings",
             b'{"metrics_interval": ' + huge + b"}"),
            ("settings nested int", "PUT", "/api/settings",
             b'{"thresholds": {"cpu_pct": ' + huge + b"}}"),
            ("settings int for str field", "PUT", "/api/settings",
             b'{"host_ip": ' + huge + b"}"),
            ("power value", "POST", "/api/settings/power",
             b'{"key": "sleep", "value": ' + huge + b"}"),
            ("identity comment", "PUT", "/api/identity",
             b'{"comment": ' + huge + b"}"),
            ("channel config value", "POST", "/api/alerts/channels",
             b'{"type": "ntfy", "config": {"topic": ' + huge + b"}}"),
            ("bare huge int body", "PUT", "/api/settings", huge),
        ):
            with self.subTest(label=label):
                response = self.client.request(
                    method, path, content=body, headers=JSON_HDR
                )
                self.assert_coded_not_500(response, 400)
        # Nothing landed on disk from any of the refused bodies.
        stored = self.stored_settings()
        self.assertEqual(sorted(stored), ["auth"])


class WireCesu8SurrogateBodyTests(_AppSandbox):
    """Raw CESU-8 surrogate *bytes* in the body (json.loads surrogatepass)."""

    def test_host_ip_round_trips_and_reads_scrub(self):
        response = self.client.put(
            "/api/settings",
            content=b'{"host_ip": "10.0.0.9' + b"\xed\xa0\x80" + b'"}',
            headers=JSON_HDR,
        )
        self.assert_coded_not_500(response, 200)
        # The wire bytes decoded to a real lone surrogate and were persisted;
        # yaml.safe_dump escaped it rather than UnicodeEncodeError'ing.
        self.assertEqual(self.stored_settings()["host_ip"], "10.0.0.9\ud800")
        body = self.assert_coded_not_500(self.client.get("/api/settings"), 200)
        self.assertNotIn("\ud800", _starlette_encode(body))


class HostilePowerPrefTests(_AppSandbox):
    """POST /api/settings/power keeps its soft-fail dict contract."""

    def test_surrogate_key_is_a_coded_soft_fail(self):
        response = self.client.post(
            "/api/settings/power",
            content=b'{"key": "sl\\ud800eep", "value": 1}',
            headers=JSON_HDR,
        )
        body = self.assert_coded_not_500(response, 200)
        self.assertFalse(body["ok"])
        self.assertEqual(body["code"], "power.bad_key")

    def test_inf_and_string_values_are_422(self):
        for body in (
            b'{"key": "sleep", "value": 1e999}',
            b'{"key": "sleep", "value": "' + b"9" * 5000 + b'"}',
        ):
            with self.subTest(body=body[:40]):
                response = self.client.post(
                    "/api/settings/power", content=body, headers=JSON_HDR
                )
                self.assert_coded_not_500(response, 422)


class FifoServicesYamlTests(_AppSandbox):
    """A FIFO squatting services.yaml: auth fails closed, nothing hangs."""

    def test_routes_terminate_with_the_coded_401(self):
        self.yaml_path.unlink()
        os.mkfifo(self.yaml_path)
        config.reload_cfg()
        for method, path in (
            ("GET", "/api/settings"),
            ("PUT", "/api/settings"),
            ("GET", "/api/settings/system"),
        ):
            with self.subTest(path=f"{method} {path}"):
                response = self.client.request(
                    method, path,
                    content=b'{"ui": {"theme": "nord"}}' if method == "PUT" else None,
                    headers=JSON_HDR if method == "PUT" else None,
                )
                # The config is unreadable, so the panel cannot prove an
                # admin exists: fail closed — but coded, and *terminating*
                # (the read is O_NONBLOCK; a plain open would park forever).
                body = self.assert_coded_not_500(response, 401)
                self.assertTrue(
                    body["detail"]["code"].startswith("auth."), body
                )

    def test_fifo_on_the_lock_file_does_not_block_the_save(self):
        os.mkfifo(self.data / ".services.yaml.lock")
        response = self.client.put("/api/settings", json={"ui": {"theme": "nord"}})
        self.assert_coded_not_500(response, 200)
        self.assertEqual(self.stored_settings()["ui"]["theme"], "nord")

    def test_export_over_a_fifo_config_is_the_coded_refusal(self):
        import hub.paths as paths

        fifo = self.root / "export-config.yaml"
        os.mkfifo(fifo)
        with mock.patch.object(paths, "CONFIG_FILE", fifo):
            response = self.client.get("/api/export/services-yaml")
        body = self.assert_coded_not_500(response, 500)
        self.assertEqual(body["detail"]["code"], "system_settings.export_failed")


class DataDirFifoTests(_AppSandbox):
    """FIFOs on the data-dir stores cost their feature, never the route."""

    def setUp(self):
        super().setUp()
        for name in (
            "alerts.jsonl", "metrics.jsonl", "alerts-state.json",
            "diagnostics-latest.json", "notify-credentials.json",
        ):
            os.mkfifo(self.data / name)

    def test_settings_surfaces_stay_up_over_the_fifos(self):
        for method, path in (
            ("GET", "/api/settings"),
            ("GET", "/api/alerts"),
            ("GET", "/api/metrics"),
            ("GET", "/api/metrics?range=48h"),
            ("GET", "/api/diagnostics"),
            ("POST", "/api/alerts/check"),
        ):
            with self.subTest(path=f"{method} {path}"):
                response = self.client.request(method, path)
                self.assert_coded_not_500(response, 200)

    def test_settings_save_and_channel_create_still_land(self):
        response = self.client.put("/api/settings", json={"ui": {"theme": "nord"}})
        self.assert_coded_not_500(response, 200)
        self.assertEqual(self.stored_settings()["ui"]["theme"], "nord")
        # The credentials store is a FIFO: the secrets write cannot land, but
        # the route must answer coded — created without secrets or refused —
        # never hang on the open and never a raw 500.
        response = self.client.post("/api/alerts/channels", json={
            "type": "ntfy",
            "config": {"topic": "t", "server": "https://ntfy.sh"},
        })
        self.assert_coded_not_500(response)


class PoisonedNotifyDispatchTests(_AppSandbox):
    """Alert test/check over hostile stored notify config never raise."""

    settings_extra = (
        "  notify:\n"
        "    enabled: true\n"
        "    include_warn: true\n"
        '    ha_url: "http://[::1"\n'
        '    ha_token: "tok\\uD800"\n'
        "    ha_service: 2026-08-19\n"
        '    webhook_url: "http://127.0.0.1:99999"\n'
        "    channels:\n"
        "      - id: c1\n"
        "        type: webhook\n"
        "        name: w1\n"
        "        enabled: true\n"
        "        min_level: info\n"
        "      - id: c2\n"
        "        type: ntfy\n"
        '        topic: "t\\uD800"\n'
        '        server: "http://[::1"\n'
        "        enabled: true\n"
        "      - id: c3\n"
        "        type: ntfy\n"
        f"        topic: {HUGE_HEX}\n"
        f"        server: {HUGE_HEX}\n"
        "        enabled: true\n"
        f"        min_level: {HUGE_HEX}\n"
    )

    def test_alert_test_and_check_answer_200(self):
        for method, path in (
            ("POST", "/api/alerts/test"),
            ("POST", "/api/alerts/check"),
        ):
            with self.subTest(path=path):
                response = self.client.request(method, path)
                self.assert_coded_not_500(response, 200)

    def test_each_hostile_channel_test_answers_200(self):
        for cid in ("c1", "c2", "c3"):
            with self.subTest(cid=cid):
                response = self.client.post(f"/api/alerts/channels/{cid}/test")
                body = self.assert_coded_not_500(response, 200)
                # Every one of these channels is undeliverable; the failure
                # must be reported in-band, not raised.
                self.assertFalse(body.get("ok"), body)

    def test_channel_listing_scrubs_the_poison(self):
        response = self.client.get("/api/alerts/channels")
        body = self.assert_coded_not_500(response, 200)
        self.assertNotIn("\ud800", _starlette_encode(body))
        ids = [c.get("id") for c in body["channels"]]
        self.assertIn("c1", ids)


class ScalarHostIpSaveCapTests(_AppSandbox):
    """The direct scalar patch branch of the save cap (settings6 pinned the
    section-merge branch): coded 503, file byte-identical, next save lands."""

    def test_oversized_host_ip_is_refused_and_does_not_wedge(self):
        before = self.yaml_path.read_bytes()
        response = self.client.put(
            "/api/settings",
            content=json.dumps({"host_ip": "x" * (1024 * 1024 + 500)}).encode(),
            headers=JSON_HDR,
        )
        body = self.assert_coded_not_500(response, 503)
        self.assertEqual(body["detail"]["code"], "settings.save_failed")
        self.assertEqual(self.yaml_path.read_bytes(), before)
        follow_up = self.client.put("/api/settings", json={"ui": {"theme": "nord"}})
        self.assert_coded_not_500(follow_up, 200)
        self.assertEqual(self.stored_settings()["ui"]["theme"], "nord")

    def test_oversized_identity_comment_is_the_coded_400(self):
        response = self.client.put(
            "/api/identity",
            content=json.dumps({"comment": "y" * (1024 * 1024)}).encode(),
            headers=JSON_HDR,
        )
        body = self.assert_coded_not_500(response, 400)
        self.assertEqual(body["detail"]["code"], "identity.value_too_long")


if __name__ == "__main__":
    unittest.main()
