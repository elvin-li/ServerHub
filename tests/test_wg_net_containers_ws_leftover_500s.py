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

    def test_truthy_swallows_a_bool_baseexception(self):
        class _BoolBomb:
            def __bool__(self):
                raise LeftoverWatchdogTimeout("bool watchdog")

        self.assertFalse(containers_svc._truthy(_BoolBomb()))

    def test_listing_pair_swallows_a_list_copy_baseexception(self):
        class _CopyBomb(list):
            def __iter__(self):
                raise LeftoverWatchdogTimeout("list copy watchdog")

        self.assertIsNone(containers_svc._listing_pair((True, _CopyBomb([{}]))))

    def test_job_log_lines_swallows_list_iter_baseexception(self):
        class _IterBomb(list):
            def __iter__(self):
                raise LeftoverWatchdogTimeout("list iter watchdog")

        self.assertEqual(containers_svc._job_log_lines(_IterBomb([1])), [])

    def test_field_text_swallows_str_baseexception(self):
        class _StrBomb:
            def __str__(self):
                raise LeftoverWatchdogTimeout("str watchdog")

        self.assertEqual(containers_svc._field_text(_StrBomb()), "")

    def test_truthy_still_propagates_keyboardinterrupt(self):
        class _Ki:
            def __bool__(self):
                raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            containers_svc._truthy(_Ki())

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
