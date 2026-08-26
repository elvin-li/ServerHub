"""Settings6 leftover sweep: stays-immune HTTP pins over the mounted app.

A hostile sweep of the Settings routes (GET/PUT /api/settings,
GET /api/export/services-yaml, GET /api/metrics, GET /api/alerts) over the
real ``create_app()`` found no live 500s left — every class below already
degrades to a 200, a coded 4xx, or the coded settings.save_failed 503.
These pins hold that line, because each one names a regression that a
single dropped guard would silently re-open:

* **Wire surrogates in unconstrained PUT fields.**  Pydantic only rejects
  lone surrogates on *constrained* str fields (max_length / Field(...)).
  ``host_ip``, every ``notify`` field, ``terminal.shell``/``cwd`` and
  ``ip_aliases.ips``/``netmask`` are unconstrained, so a JSON body carrying
  the raw ``\\ud800`` escape lands in services.yaml verbatim.  That is fine
  *only* because yaml.safe_dump escapes it (``"\\uD800"``) and every read
  scrubs at the edge (settings _utf8_text, export _redact_export) — drop
  either and the PUT or every later GET/export 500s at Starlette's UTF-8
  encode.  host_ip alone was pinned before; the other three sections ride
  different merge branches (``settings_section(...)`` + ``cur.update``).

* **Constrained-field surrogates stay 4xx.**  ollama.url / ollama.label /
  resource_mode answer pydantic's 422; a surrogate ui.locale answers the
  coded 400 whose *error body* itself must survive the UTF-8 encode
  (error_payload scrubs params).

* **Explicit-key over-cap hex ints inside each merged section.**  The
  ``? 0xF…`` YAML form bypasses the 1024-char simple-key scanner limit, and
  ``int(x, 16)`` is exempt from CPython's 4300-digit cap, so an
  already-parsed unrenderable int can sit *inside* thresholds /
  ip_aliases / terminal / ollama / ui.  Each section's PUT copies the
  poisoned mapping into the patch (``dict(settings_section(...))``), so
  each save depends on the ``_dump`` retry dropping the node — a top-level
  poison was pinned before, the per-section merge branches were not.

* **JSON NaN / Infinity / 1e999 literals.**  pydantic-core's parser accepts
  them (allow_inf_nan), so they reach field validation rather than the body
  parser; the finite_number 422 — not an inf riding into services.yaml and
  not a 500 — is the contract.

* **Iterbomb bodies.**  A 5000-deep JSON array nests without RecursionError
  and answers a validation 4xx; a 100k-entry ip_aliases.ips passes
  validation and must be refused by the save cap as the coded 503 *with the
  on-disk file untouched* (the cap exists so an oversized write can never
  make every later cfg() read {} and let the next mutate persist the wipe).
  The refused save must not wedge the file: the next normal PUT lands.

* **Hostile metrics/alerts query params.**  Values past pydantic's own
  digit cap are its 422; values inside it (300 digits) must be clamped or
  windowed, never OverflowError'd; a %ED%A0%80 range answers the coded 400.

* **Weird-typed sections on disk.**  ``!!set`` thresholds, list ip_aliases,
  str terminal, int ollama, float notify, ``!!binary`` ui, ``.inf``/
  ``.nan`` intervals, a date host_ip, dict groups_order and str stacks:
  GET defaults every one of them, and each section's PUT merge still lands
  (settings_section answers {} for a non-dict section).
"""
from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import yaml
from fastapi.testclient import TestClient

from hub import auth, config
from hub.app_factory import create_app

PASSWORD = "correct-horse-battery"
#: Explicit-key spelling: bypasses the scanner's 1024-char simple-key limit.
HUGE_HEX = "0x" + "F" * 5000
HUGE_INT = int("F" * 5000, 16)
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
    #: Appended at top level, after the settings mapping.
    top_extra = ""

    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        data = self.root / "data"
        data.mkdir()
        self.yaml_path = self.root / "services.yaml"
        for target, attr, value in (
            (config, "YAML_PATH", self.yaml_path),
            (config, "DATA_DIR", data),
            (config, "BASE", self.root),
            (config, "_LOCK_PATH", data / ".services.yaml.lock"),
            (auth, "SECRET_FILE", data / ".session-secret"),
            (auth, "SETUP_TOKEN_FILE", data / ".setup-token"),
            (auth, "LOCAL_TOKEN_FILE", data / ".local-client-token"),
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
            + self.top_extra
        )
        config.reload_cfg()
        self.client = TestClient(app(), raise_server_exceptions=False)
        response = self.client.post(
            "/api/auth/login", json={"username": "admin", "password": PASSWORD}
        )
        assert response.status_code == 200, response.text

    def stored(self) -> dict:
        return yaml.safe_load(self.yaml_path.read_text())

    def put_raw(self, body: bytes):
        """PUT raw JSON bytes so ``\\ud800`` escapes reach the server intact.

        ``client.put(json=...)`` encodes in the *test client* and raises
        there; the server must be probed with the wire form.
        """
        return self.client.put("/api/settings", content=body, headers=JSON_HDR)

    def assert_reads_stay_clean(self):
        """GET /api/settings answers 200 and its body survives the encode."""
        response = self.client.get("/api/settings")
        self.assertEqual(response.status_code, 200, response.text[:200])
        text = _starlette_encode(response.json())
        self.assertNotIn("\ud800", text)
        return response.json()


class WireSurrogateUnconstrainedPutTests(_AppSandbox):
    """Surrogates in unconstrained PUT fields round-trip without any 500."""

    def test_notify_fields_round_trip(self):
        response = self.put_raw(
            b'{"notify": {"ha_url": "http://x\\ud800", "ha_token": "tok\\ud800",'
            b' "ha_service": "svc\\ud800", "webhook_url": "http://w\\ud800"}}'
        )
        self.assertEqual(response.status_code, 200, response.text[:200])
        self.assertNotIn("\ud800", _starlette_encode(response.json()))
        notify = self.stored()["settings"]["notify"]
        # The write keeps the raw value (reads scrub at the edge); the YAML
        # escape must round-trip rather than UnicodeEncodeError the save.
        self.assertEqual(notify["ha_url"], "http://x\ud800")
        self.assertEqual(notify["ha_token"], "tok\ud800")
        body = self.assert_reads_stay_clean()
        self.assertTrue(body["notify"]["has_token"])
        self.assertTrue(body["notify"]["has_webhook"])

    def test_terminal_fields_round_trip(self):
        response = self.put_raw(
            b'{"terminal": {"shell": "/bin/z\\ud800", "cwd": "/tmp\\ud800"}}'
        )
        self.assertEqual(response.status_code, 200, response.text[:200])
        self.assertEqual(self.stored()["settings"]["terminal"]["shell"], "/bin/z\ud800")
        self.assert_reads_stay_clean()

    def test_ip_aliases_fields_round_trip(self):
        response = self.put_raw(
            b'{"ip_aliases": {"ips": ["10.0.0.\\ud800", "10.0.0.9"],'
            b' "netmask": "255.\\ud800"}}'
        )
        self.assertEqual(response.status_code, 200, response.text[:200])
        aliases = self.stored()["settings"]["ip_aliases"]
        self.assertEqual(aliases["ips"], ["10.0.0.\ud800", "10.0.0.9"])
        body = self.assert_reads_stay_clean()
        # The scrubbed read keeps the clean sibling entry.
        self.assertIn("10.0.0.9", body["ip_aliases"]["ips"])

    def test_export_scrubs_persisted_surrogates(self):
        """After surrogate writes land, the backup download must stream 200
        with the surrogates replaced, not refuse or 500 mid-encode."""
        import hub.paths as paths

        for body in (
            b'{"host_ip": "10.0.0.\\ud800"}',
            b'{"notify": {"ha_url": "http://x\\ud800", "ha_token": "tok\\ud800"}}',
            b'{"terminal": {"shell": "/bin/z\\ud800"}}',
        ):
            self.assertEqual(self.put_raw(body).status_code, 200)
        with mock.patch.object(paths, "CONFIG_FILE", self.yaml_path):
            response = self.client.get("/api/export/services-yaml")
        self.assertEqual(response.status_code, 200, response.text[:200])
        self.assertNotIn("\ud800", response.text)
        response.text.encode("utf-8")
        exported = yaml.safe_load(response.text)
        # Secrets stay redacted on the surviving nodes.
        self.assertEqual(exported["settings"]["notify"]["ha_token"], "***redacted***")
        self.assertEqual(
            exported["settings"]["auth"]["password_hash"], "***redacted***"
        )


class WireSurrogateConstrainedFieldTests(_AppSandbox):
    """Constrained fields refuse wire surrogates with a 4xx, never a 500."""

    def test_constrained_fields_answer_4xx(self):
        for body in (
            b'{"ollama": {"label": "com.x\\ud800"}}',
            b'{"ollama": {"url": "http://127.0.0.1:114\\ud800"}}',
            b'{"resource_mode": "\\ud800hi"}',
        ):
            with self.subTest(body=body):
                response = self.put_raw(body)
                self.assertEqual(response.status_code, 422, response.text[:200])
                _starlette_encode(response.json())

    def test_surrogate_locale_is_coded_400_with_encodable_body(self):
        """The coded invalid_locale error interpolates the poisoned value
        into its own body; error_payload must scrub it before the encode."""
        response = self.put_raw(b'{"ui": {"locale": "\\ud800"}}')
        self.assertEqual(response.status_code, 400, response.text[:200])
        body = response.json()
        self.assertEqual(body["detail"]["code"], "settings.invalid_locale")
        self.assertNotIn("\ud800", _starlette_encode(body))
        # Nothing landed on disk.
        self.assertNotIn("ui", self.stored()["settings"])


class SectionExplicitHexKeyMergeTests(_AppSandbox):
    """An unrenderable ``? 0x…`` key inside each merged section must not
    wedge that section's save: the merge copies the poisoned mapping into
    the patch, and only the ``_dump`` retry drop lets the write land."""

    settings_extra = (
        "  thresholds:\n"
        "    cpu_pct: 90\n"
        f"    ? {HUGE_HEX}\n"
        "    : keyed\n"
        "  ip_aliases:\n"
        "    netmask: 255.255.255.0\n"
        f"    ? {HUGE_HEX}\n"
        "    : keyed\n"
        "  terminal:\n"
        "    host_enabled: true\n"
        f"    ? {HUGE_HEX}\n"
        "    : keyed\n"
        "  ollama:\n"
        "    label: com.ollama\n"
        f"    ? {HUGE_HEX}\n"
        "    : keyed\n"
        "  ui:\n"
        "    theme: omv\n"
        f"    ? {HUGE_HEX}\n"
        "    : keyed\n"
    )

    def _assert_section_saved(self, section: str, expect: dict, keep: dict):
        on_disk = self.stored()["settings"][section]
        self.assertNotIn(HUGE_INT, on_disk)
        for key, value in {**keep, **expect}.items():
            self.assertEqual(on_disk.get(key), value)

    def test_thresholds_merge_unsticks(self):
        response = self.client.put("/api/settings", json={"thresholds": {"cpu_pct": 80}})
        self.assertEqual(response.status_code, 200, response.text[:200])
        self._assert_section_saved("thresholds", {"cpu_pct": 80}, {})

    def test_ip_aliases_merge_unsticks(self):
        response = self.client.put(
            "/api/settings", json={"ip_aliases": {"auto_bind": True}}
        )
        self.assertEqual(response.status_code, 200, response.text[:200])
        self._assert_section_saved(
            "ip_aliases", {"auto_bind": True}, {"netmask": "255.255.255.0"}
        )

    def test_terminal_merge_unsticks(self):
        response = self.client.put(
            "/api/settings", json={"terminal": {"host_enabled": False}}
        )
        self.assertEqual(response.status_code, 200, response.text[:200])
        self._assert_section_saved("terminal", {"host_enabled": False}, {})

    def test_ollama_merge_unsticks(self):
        response = self.client.put("/api/settings", json={"ollama": {"label": ""}})
        self.assertEqual(response.status_code, 200, response.text[:200])
        self._assert_section_saved("ollama", {"label": ""}, {})

    def test_ui_merge_unsticks_and_keeps_theme(self):
        response = self.client.put("/api/settings", json={"ui": {"locale": "ja"}})
        self.assertEqual(response.status_code, 200, response.text[:200])
        self._assert_section_saved("ui", {"locale": "ja"}, {"theme": "omv"})

    def test_reads_stay_clean_over_the_poison(self):
        body = self.assert_reads_stay_clean()
        self.assertEqual(body["thresholds"]["cpu_pct"], 90)
        self.assertEqual(body["ollama"]["label"], "com.ollama")


class JsonNumericLiteralTests(_AppSandbox):
    """NaN / Infinity / 1e999 parse (allow_inf_nan) and must die in field
    validation as 422 — never a 500 and never an inf inside services.yaml."""

    def test_non_finite_literals_are_422(self):
        for body in (
            b'{"metrics_interval": NaN}',
            b'{"metrics_interval": Infinity}',
            b'{"alert_interval": -Infinity}',
            b'{"thresholds": {"cpu_pct": 1e999}}',
            b'{"ip_aliases": {"interval": Infinity}}',
        ):
            with self.subTest(body=body):
                response = self.put_raw(body)
                self.assertEqual(response.status_code, 422, response.text[:200])
                _starlette_encode(response.json())
        # Nothing non-finite landed on disk.
        text = self.yaml_path.read_text()
        self.assertNotIn(".inf", text)
        self.assertNotIn(".nan", text)


class IterbombBodyTests(_AppSandbox):
    def test_deep_array_body_is_4xx_not_500(self):
        body = b'{"ui": {"locale": ' + b"[" * 5000 + b"1" + b"]" * 5000 + b"}}"
        response = self.put_raw(body)
        self.assertEqual(response.status_code, 422, response.text[:200])
        _starlette_encode(response.json())

    def test_deep_object_body_never_500s(self):
        body = b'{"notify": ' + b'{"a":' * 3000 + b"1" + b"}" * 3000 + b"}"
        response = self.put_raw(body)
        self.assertLess(response.status_code, 500, response.text[:200])
        _starlette_encode(response.json())
        # The nested junk is undeclared and must not reach services.yaml.
        self.assertNotIn('"a"', self.yaml_path.read_text())

    def test_oversized_ips_list_is_coded_503_and_file_untouched(self):
        """An ips list that dumps past the 1MB read cap must be *refused*:
        writing it would make every later cfg() answer {} (admin account
        gone from the panel's view) and the next mutate persist that wipe."""
        before = self.yaml_path.read_bytes()
        body = (
            b'{"ip_aliases": {"ips": ['
            + b'"10.0.0.9",' * 100000
            + b'"10.0.0.9"]}}'
        )
        response = self.put_raw(body)
        self.assertEqual(response.status_code, 503, response.text[:200])
        self.assertEqual(response.json()["detail"]["code"], "settings.save_failed")
        self.assertEqual(self.yaml_path.read_bytes(), before)
        # The refusal must not wedge the file: the next normal save lands.
        follow_up = self.client.put("/api/settings", json={"ui": {"theme": "nord"}})
        self.assertEqual(follow_up.status_code, 200, follow_up.text[:200])
        self.assertEqual(self.stored()["settings"]["ui"]["theme"], "nord")


class HostileQueryParamTests(_AppSandbox):
    """Metrics/alerts query params never 500 for any spelling of hostile."""

    def test_metrics_and_alerts_params_never_500(self):
        big300 = "9" * 300  # inside pydantic's own digit cap, past any epoch
        for path in (
            "/api/metrics?minutes=-99999",
            f"/api/metrics?minutes={big300}",
            "/api/metrics?range=" + "z" * 10000,
            "/api/metrics?range=0h",
            "/api/metrics?range=999y",
            "/api/metrics?since=-1&until=0",
            f"/api/metrics?since=1&until={big300}",
            f"/api/metrics?since={big300}",
            "/api/metrics?range=48h&points=-5",
            f"/api/metrics?range=1y&points={big300}",
            "/api/metrics?range=%ED%A0%80",
            "/api/metrics?since=abc",
            "/api/alerts?limit=-1",
            f"/api/alerts?limit={big300}",
        ):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertLess(response.status_code, 500, f"{path}: {response.text[:200]}")
                _starlette_encode(response.json())

    def test_over_pydantic_cap_int_param_is_422(self):
        response = self.client.get("/api/metrics?since=1&until=" + "9" * 4400)
        self.assertEqual(response.status_code, 422, response.text[:200])
        _starlette_encode(response.json())


class WeirdTypedSectionsTests(_AppSandbox):
    """Every settings section holding the wrong YAML type: GET defaults,
    and each section's PUT merge still lands over the junk."""

    settings_extra = (
        "  thresholds: !!set {a: null, b: null}\n"
        "  ip_aliases: [1, 2]\n"
        "  terminal: text\n"
        "  ollama: 2023\n"
        "  notify: 3.5\n"
        "  ui: !!binary aGVsbG8=\n"
        "  metrics_interval: .inf\n"
        "  alert_interval: .nan\n"
        "  resource_mode: [x]\n"
        "  adaptive: {}\n"
        "  host_ip: 2026-08-19\n"
    )
    top_extra = (
        "groups_order: {a: 1}\n"
        'stacks: "notalist"\n'
    )

    def test_get_settings_defaults_every_section(self):
        body = self.assert_reads_stay_clean()
        self.assertEqual(body["metrics_interval"], 90)
        self.assertEqual(body["alert_interval"], 90)
        self.assertEqual(body["resource_mode"], "low")
        self.assertIs(body["adaptive"], True)
        self.assertEqual(body["ui"]["theme"], "system")
        self.assertEqual(body["thresholds"]["cpu_pct"], 90)
        self.assertEqual(body["ip_aliases"], {})
        self.assertIs(body["terminal"]["host_enabled"], False)
        self.assertEqual(body["groups_order"], [])
        self.assertEqual(body["stacks"], [])

    def test_each_section_put_lands_over_the_junk(self):
        for body, section, key, expected in (
            ({"ui": {"theme": "nord"}}, "ui", "theme", "nord"),
            ({"thresholds": {"cpu_pct": 80}}, "thresholds", "cpu_pct", 80),
            ({"ip_aliases": {"auto_bind": True}}, "ip_aliases", "auto_bind", True),
            ({"terminal": {"host_enabled": True}}, "terminal", "host_enabled", True),
            ({"ollama": {"label": "com.x"}}, "ollama", "label", "com.x"),
            ({"notify": {"enabled": True}}, "notify", "enabled", True),
        ):
            with self.subTest(section=section):
                response = self.client.put("/api/settings", json=body)
                self.assertEqual(response.status_code, 200, response.text[:200])
                self.assertEqual(self.stored()["settings"][section][key], expected)


if __name__ == "__main__":
    unittest.main()
