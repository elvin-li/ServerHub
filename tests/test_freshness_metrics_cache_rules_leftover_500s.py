"""Leftover sweep of freshness, metrics, proc/launchd caches, and group_rules.

Text launderers still stopped at ``except Exception`` and coerced default
object ``__repr__`` heap addresses into JSON.
"""
from __future__ import annotations

import unittest

from fastapi.testclient import TestClient

from hub import freshness_svc, group_rules, launchd_cache, metrics, proc_cache
from hub.app_factory import create_app
from hub.auth import require_auth

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


class FreshnessMetricsCacheRulesLeftoverTests(unittest.TestCase):
    def test_text_does_not_leak_a_heap_address(self):
        self.assertEqual(freshness_svc._utf8_text(object()), "")
        self.assertEqual(metrics._utf8_text(object()), "")
        self.assertEqual(proc_cache._as_text(object()), "")
        self.assertEqual(launchd_cache._as_text(object()), "")
        self.assertEqual(group_rules._utf8_text(object()), "")

    def test_text_recovers_str_storage_lying_bytes(self):
        self.assertEqual(freshness_svc._utf8_text(_LyingBytesStr("ok")), "ok")
        self.assertEqual(metrics._utf8_text(_LyingBytesStr("ok")), "ok")
        self.assertEqual(proc_cache._as_text(_LyingBytesStr("ok")), "ok")
        self.assertEqual(launchd_cache._as_text(_LyingBytesStr("ok")), "ok")
        self.assertEqual(group_rules._utf8_text(_LyingBytesStr("ok")), "ok")

    def test_as_int_recovers_lying_bytes_digits(self):
        self.assertEqual(group_rules._as_int(_LyingBytesStr("443")), 443)

    def test_plain_dict_swallows_a_baseexception_items_bomb(self):
        class _ItemsBomb(dict):
            def keys(self):
                raise LeftoverWatchdogTimeout("keys bomb")

            def __iter__(self):
                raise LeftoverWatchdogTimeout("iter bomb")

        self.assertIsNone(metrics._plain_dict(_ItemsBomb(a=1)))

    def test_get_metrics_does_not_500(self):
        client = TestClient(app(), raise_server_exceptions=False)
        response = client.get("/api/metrics")
        self.assertNotEqual(response.status_code, 500, response.text[:400])
        self.assertNotIn(" at 0x", response.text)

    def test_control_flow_still_propagates_from_text(self):
        class _Ki:
            def __str__(self):
                raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            freshness_svc._utf8_text(_Ki())
        with self.assertRaises(KeyboardInterrupt):
            metrics._utf8_text(_Ki())
        with self.assertRaises(KeyboardInterrupt):
            proc_cache._as_text(_Ki())


if __name__ == "__main__":
    unittest.main()
