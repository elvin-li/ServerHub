"""Leftover sweep of system_extra and ups_policy helpers."""
from __future__ import annotations

import unittest

from fastapi.testclient import TestClient

from hub import ups_policy
from hub.app_factory import create_app
from hub.auth import require_auth
from hub.routers import system_extra

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


class SystemExtraUpsPolicyLeftoverTests(unittest.TestCase):
    def test_isa_swallows_a_baseexception_class_bomb(self):
        self.assertFalse(system_extra._isa(_ClassBaseBomb(), str))
        self.assertFalse(ups_policy._isa(_ClassBaseBomb(), str))

    def test_text_does_not_leak_a_heap_address(self):
        self.assertEqual(system_extra._as_text(object()), "")
        self.assertEqual(ups_policy._as_text(object()), "")

    def test_text_recovers_str_storage_lying_bytes(self):
        self.assertEqual(system_extra._as_text(_LyingBytesStr("ok")), "ok")
        self.assertEqual(ups_policy._as_text(_LyingBytesStr("ok")), "ok")

    def test_rc_int_junk_is_minus_255(self):
        self.assertEqual(system_extra._rc_int(_ClassBaseBomb()), -255)

    def test_raising_runner_is_minus_255_not_spawn_minus_one(self):
        def _boom(*_a, **_k):
            raise LeftoverWatchdogTimeout("runner bomb")

        from hub.util import run_capped as real

        import hub.util as util_mod

        util_mod.run_capped = _boom
        try:
            rc, out, err = ups_policy._run_argv(["/bin/true"], timeout=1)
        finally:
            util_mod.run_capped = real
        self.assertEqual(rc, -255)
        self.assertEqual(out, "")
        self.assertNotEqual(rc, -1)

    def test_get_system_host_does_not_500(self):
        client = TestClient(app(), raise_server_exceptions=False)
        response = client.get("/api/system/host")
        self.assertNotEqual(response.status_code, 500, response.text[:400])
        self.assertNotIn(" at 0x", response.text)

    def test_control_flow_still_propagates_from_isa(self):
        class _Ki:
            @property
            def __class__(self):  # noqa: A003
                raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            system_extra._isa(_Ki(), dict)
        with self.assertRaises(KeyboardInterrupt):
            ups_policy._isa(_Ki(), dict)


if __name__ == "__main__":
    unittest.main()
