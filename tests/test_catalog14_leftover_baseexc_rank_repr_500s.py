"""Fourteenth leftover sweep of the Apps catalog surface.

catalog13 sealed the host-ip seam and native row-shadow 500s.  The
helpers still stopped at ``except Exception``, trusted a claimed
``__class__`` for the decode base, and the free-text coercion arm ran
``str()`` on default-render objects — a raw heap address on the wire.

Driven through ``create_app()`` + ``TestClient(raise_server_exceptions=
False)`` plus unit pins on ``catalog._plain_str`` / ``_rc_int`` /
``_safe_host_ip`` and ``native_catalog._as_text``.
"""
from __future__ import annotations

import unittest
from unittest import mock

from fastapi.testclient import TestClient

from hub import catalog, native_catalog
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
    """Watchdog/timeout shape that sails past ``except Exception``."""


class _ClassBaseBomb:
    @property
    def __class__(self):  # noqa: A003
        raise LeftoverWatchdogTimeout("class base-exc bomb")


class _LyingBytesStr(str):
    @property
    def __class__(self):  # noqa: A003
        return bytes


class _LyingStrInt(int):
    @property
    def __class__(self):  # noqa: A003
        return bool


class Catalog14LeftoverTests(unittest.TestCase):
    def test_plain_str_does_not_leak_a_heap_address(self):
        text = catalog._plain_str(object())
        self.assertNotIn(" at 0x", text)
        self.assertEqual(text, "")

    def test_plain_str_recovers_str_storage_lying_bytes(self):
        self.assertEqual(catalog._plain_str(_LyingBytesStr("hello")), "hello")

    def test_plain_str_honest_str_stays_verbatim(self):
        self.assertEqual(catalog._plain_str(" at 0xdeadbeef>"), " at 0xdeadbeef>")

    def test_isinst_swallows_a_baseexception_class_bomb(self):
        self.assertFalse(catalog._isinst(_ClassBaseBomb(), str))
        self.assertFalse(native_catalog._isinst(_ClassBaseBomb(), bytes))

    def test_rc_int_does_not_treat_a_lying_bool_int_as_bool(self):
        self.assertEqual(catalog._rc_int(_LyingStrInt(7)), 7)
        self.assertEqual(native_catalog._rc_int(_LyingStrInt(7)), 7)

    def test_rc_int_junk_is_minus_255_never_minus_1(self):
        self.assertEqual(catalog._rc_int(object()), -255)

    def test_safe_host_ip_degrades_a_baseexception_provider(self):
        def boom():
            raise LeftoverWatchdogTimeout("host_ip watchdog")

        with mock.patch.object(catalog, "host_ip", boom):
            self.assertEqual(catalog._safe_host_ip(), "")

    def test_native_as_text_does_not_leak_a_heap_address(self):
        self.assertEqual(native_catalog._as_text(object()), "")

    def test_get_catalog_stays_200_when_host_ip_raises_baseexception(self):
        def boom():
            raise LeftoverWatchdogTimeout("host_ip watchdog")

        client = TestClient(app(), raise_server_exceptions=False)
        with mock.patch.object(catalog, "host_ip", boom):
            response = client.get("/api/catalog")
        self.assertEqual(response.status_code, 200, response.text[:400])
        self.assertNotIn(" at 0x", response.text)

    def test_control_flow_still_propagates_from_isinst(self):
        class _Ki:
            @property
            def __class__(self):  # noqa: A003
                raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            catalog._isinst(_Ki(), str)

    def test_register_stack_swallows_mutate_baseexception(self):
        def boom(_apply):
            raise LeftoverWatchdogTimeout("mutate watchdog")

        with mock.patch("hub.config.mutate", boom):
            catalog._register_stack("demo", "Demo", catalog.SERVICES_ROOT / "demo")

    def test_unregister_stack_swallows_mutate_baseexception(self):
        def boom(_apply):
            raise LeftoverWatchdogTimeout("mutate watchdog")

        with mock.patch("hub.config.mutate", boom):
            catalog._unregister_stack("demo", catalog.SERVICES_ROOT / "demo")

    def test_register_stack_still_propagates_keyboardinterrupt(self):
        def boom(_apply):
            raise KeyboardInterrupt

        with mock.patch("hub.config.mutate", boom):
            with self.assertRaises(KeyboardInterrupt):
                catalog._register_stack("demo", "Demo", catalog.SERVICES_ROOT / "demo")


if __name__ == "__main__":
    unittest.main()
