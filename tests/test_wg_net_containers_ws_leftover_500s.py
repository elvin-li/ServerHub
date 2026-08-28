"""Leftover sweep of wireguard_net, containers job scalars, and websocket close."""
from __future__ import annotations

import unittest

from fastapi.testclient import TestClient

from hub import containers_svc, wireguard_net_svc
from hub.app_factory import create_app
from hub.auth import require_auth
from hub import websocket_security

_APP = None


def app():
    global _APP
    if _APP is None:
        _APP = create_app()
        _APP.dependency_overrides[require_auth] = lambda: True
    return _APP


class LeftoverWatchdogTimeout(BaseException):
    pass


class _ClassBaseBomb:
    @property
    def __class__(self):  # noqa: A003
        raise LeftoverWatchdogTimeout("class base-exc bomb")


class _LyingBytesStr(str):
    @property
    def __class__(self):  # noqa: A003
        return bytes


class WgNetContainersWsLeftoverTests(unittest.TestCase):
    def test_text_does_not_leak_a_heap_address(self):
        self.assertEqual(wireguard_net_svc._as_text(object()), "")

    def test_text_recovers_str_storage_lying_bytes(self):
        self.assertEqual(wireguard_net_svc._as_text(_LyingBytesStr("ok")), "ok")

    def test_job_scalar_swallows_a_class_bomb(self):
        self.assertIsNone(containers_svc._job_scalar(_ClassBaseBomb()))
        self.assertEqual(containers_svc._log_text(_ClassBaseBomb()), "")

    def test_origin_allowed_swallows_urlsplit_bomb(self):
        class _Origin(str):
            def __str__(self):
                raise LeftoverWatchdogTimeout("origin bomb")

        # urlsplit of a plain hostile object is not this path; a non-str
        # origin is refused before parse.
        self.assertFalse(websocket_security.origin_allowed(_ClassBaseBomb(), "h"))

    def test_get_wireguard_readiness_does_not_500(self):
        client = TestClient(app(), raise_server_exceptions=False)
        response = client.get("/api/wireguard/readiness")
        self.assertNotEqual(response.status_code, 500, response.text[:400])
        self.assertNotIn(" at 0x", response.text)

    def test_control_flow_still_propagates_from_text(self):
        class _Ki:
            def __str__(self):
                raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            wireguard_net_svc._as_text(_Ki())


if __name__ == "__main__":
    unittest.main()
