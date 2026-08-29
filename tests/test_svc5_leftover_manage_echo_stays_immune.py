"""Fifth leftover-500s sweep — Services management echo paths stay immune.

Companion to ``test_svc5_leftover_launchd_plist_stays_immune``.  Where that
file drives the plist ingest, this one drives the write/echo routes the
Services page mounts — adopt, script edit/forget, signatures, group rules and
bulk-action — with the hunted leftover classes planted in the config the
route reads back and echoes:

* lone UTF-8 surrogates in **values** (name/group/url) and the stored entry;
* a **torn IPv6 URL** (``http://[::1``) whose ``urlsplit`` raises ValueError
  inside ``normalize_local_url`` — the "torn IPv6 urlsplit ValueError"
  invariant;
* a **numeric YAML id** (``id: 8080`` loads as int) whose edit/forget must
  land on the row the page renders under ``"8080"``, not 404;
* a start command carrying a lone surrogate → the coded 400
  ``services.bad_command`` (a surrogate can never be spawned), never a 500;
* a huge ``json.loads`` int literal in a signature body → the parse 400
  (ValueError, not JSONDecodeError), never a 500;
* a ``run_action`` that returns a huge int rc / a surrogate message, or
  raises ``RecursionError``, riding inside the bulk-action 200 as a per-id
  failure rather than 500ing the batch.

Every route below already answers cleanly; these are stays-immune pins.
"""
from __future__ import annotations

import os
import tempfile
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from hub import actions
from hub import services_manage_svc as sms
from hub.app_factory import create_app
from hub.auth import require_auth

_HUGE_INT = int("f" * 5000, 16)
_SURR = "a\ud800b"

_app = None


def _the_app():
    global _app
    if _app is None:
        _app = create_app()
        _app.dependency_overrides[require_auth] = lambda: None
    return _app


def _client() -> TestClient:
    return TestClient(_the_app(), raise_server_exceptions=False)


def _is_leftover_500(r) -> bool:
    if r.status_code != 500:
        return False
    try:
        body = r.json()
    except Exception:
        return True
    detail = body.get("detail") if isinstance(body, dict) else None
    if isinstance(detail, dict) and detail.get("code"):
        return False
    if isinstance(body, dict) and "ok" in body and "message" in body:
        return False
    return True


def _mutate_into(data):
    def fake_mutate(fn):
        fn(data)
        return data

    return fake_mutate


class AdoptEchoStaysImmune(unittest.TestCase):
    _AUTO = {
        "id": "auto:1", "name": _SURR, "kind": "auto", "state": "ok",
        "actions": [], "meta": {"pid": 0, "process": _SURR, "ports": [3000]},
    }

    def _cfg(self):
        return {"apps": [], "scripts": [], "stacks": [], "service_signatures": []}

    def test_adopt_scrubs_surrogate_name_group_and_torn_ipv6_url(self):
        data = self._cfg()
        with (
            mock.patch.object(sms, "find_service", return_value=self._AUTO),
            mock.patch.object(sms, "cfg", return_value=data),
            mock.patch.object(sms.config, "mutate", _mutate_into(data)),
            mock.patch.object(sms, "invalidate_status"),
        ):
            r = _client().post(
                "/api/services/auto:1/adopt",
                # torn IPv6 URL + surrogate name/group, remember stores a sig.
                content=(b'{"name":"n\\ud800","group":"g\\ud800",'
                         b'"url":"http://[::1:99","ports":[3000],"remember":true}'),
                headers={"content-type": "application/json"},
            )
        self.assertFalse(_is_leftover_500(r), r.text[:300])
        self.assertEqual(r.status_code, 200)
        entry = r.json()["entry"]
        self.assertNotIn("\ud800", entry["name"])
        self.assertNotIn("\ud800", entry["group"])
        # The torn IPv6 authority is stored verbatim (urlsplit refused it),
        # and the whole echo still round-tripped Starlette's UTF-8 encode.
        self.assertEqual(entry["url"], "http://[::1:99")

    def test_adopt_surrogate_start_command_is_the_coded_400(self):
        data = self._cfg()
        with (
            mock.patch.object(sms, "find_service", return_value=self._AUTO),
            mock.patch.object(sms, "cfg", return_value=data),
            mock.patch.object(sms.config, "mutate", _mutate_into(data)),
            mock.patch.object(sms, "invalidate_status"),
        ):
            r = _client().post(
                "/api/services/auto:1/adopt",
                content=b'{"ports":[3000],"start":"run\\ud800me"}',
                headers={"content-type": "application/json"},
            )
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.json()["detail"]["code"], "services.bad_command")

    def test_auto_detail_survives_over_cap_hex_sibling_id(self):
        data = {
            "apps": [{"id": _HUGE_INT, "name": "poison"}],
            "scripts": [], "stacks": [],
        }
        with (
            mock.patch.object(sms, "find_service", return_value=self._AUTO),
            mock.patch.object(sms, "cfg", return_value=data),
        ):
            r = _client().get("/api/services/auto:1/detail")
        self.assertFalse(_is_leftover_500(r), r.text[:200])
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json().get("can_adopt"))


class NumericScriptRowStaysImmune(unittest.TestCase):
    def _cfg(self):
        return {"scripts": [{"id": 8080, "name": _SURR, "ports": [3000],
                             "url": "http://[::1", "group": _SURR}]}

    def test_forget_numeric_row_scrubs_the_echo(self):
        data = self._cfg()
        with (
            mock.patch.object(sms, "cfg", return_value=data),
            mock.patch.object(sms.config, "mutate", _mutate_into(data)),
            mock.patch.object(sms, "invalidate_status"),
        ):
            r = _client().delete("/api/services/8080/script")
        self.assertFalse(_is_leftover_500(r), r.text[:200])
        self.assertEqual(r.status_code, 200)
        removed = r.json()["removed"]
        self.assertNotIn("\ud800", removed["name"])
        self.assertEqual(data["scripts"], [])

    def test_update_numeric_row_surrogate_start_is_coded_400(self):
        data = self._cfg()
        with (
            mock.patch.object(sms, "cfg", return_value=data),
            mock.patch.object(sms.config, "mutate", _mutate_into(data)),
            mock.patch.object(sms, "invalidate_status"),
        ):
            r = _client().put(
                "/api/services/8080/script",
                content=b'{"start":"x\\ud800y"}',
                headers={"content-type": "application/json"},
            )
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.json()["detail"]["code"], "services.bad_command")


class SignatureAndBulkStayImmune(unittest.TestCase):
    def test_signature_body_with_huge_int_port_is_the_parse_400(self):
        data = {"service_signatures": []}
        with (
            mock.patch.object(sms, "cfg", return_value=data),
            mock.patch.object(sms.config, "mutate", _mutate_into(data)),
            mock.patch.object(sms, "invalidate_status"),
        ):
            body = ('{"slug":"sig","name":"n","ports":[3000,' + "9" * 5000 + "]}")
            r = _client().put(
                "/api/services/signatures",
                content=body.encode(),
                headers={"content-type": "application/json"},
            )
        self.assertEqual(r.status_code, 400)
        self.assertFalse(_is_leftover_500(r), r.text[:200])

    def test_bulk_action_huge_rc_and_surrogate_message_ride_as_per_id(self):
        with mock.patch.object(actions, "run_action",
                               return_value=(_HUGE_INT, _SURR, _SURR)):
            r = _client().post(
                "/api/services/bulk-action",
                json={"ids": ["a", "b"], "action": "start"},
            )
        self.assertFalse(_is_leftover_500(r), r.text[:200])
        self.assertEqual(r.status_code, 200)
        rows = r.json()["results"]
        self.assertEqual(len(rows), 2)
        for row in rows:
            self.assertFalse(row["ok"])
            self.assertNotIn("\ud800", row["message"])

    def test_bulk_action_run_action_recursionerror_rides_as_per_id(self):
        with mock.patch.object(actions, "run_action", side_effect=RecursionError()):
            r = _client().post(
                "/api/services/bulk-action",
                json={"ids": ["a"], "action": "stop"},
            )
        self.assertFalse(_is_leftover_500(r), r.text[:200])
        self.assertEqual(r.status_code, 200)
        self.assertFalse(r.json()["results"][0]["ok"])


if __name__ == "__main__":
    unittest.main()
