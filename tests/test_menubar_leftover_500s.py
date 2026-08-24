"""Leftover inf/bytes/\\ud800 crashes in the menu-bar client and its polls.

``_menu_signature`` dumped without ``allow_nan=False``, so leftover Infinity
or ``bytes`` from a status peek took the rumps timer down. The same leftover
``\\ud800`` still 500'd GET /api/status, GET /api/maintenance, and
GET /api/system/sensors?light=1 (peek cache) under Starlette's UTF-8 encoder.
"""
from __future__ import annotations

import importlib
import json
import sys
import unittest
from unittest import mock


def _starlette(payload) -> None:
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


def _load_menubar():
    try:
        import menubar
    except ModuleNotFoundError as exc:
        if exc.name != "rumps":
            raise
        menubar = None
    else:
        bar_cls = getattr(menubar, "ServerHubBar", None)
        tick = getattr(bar_cls, "tick", None) if isinstance(bar_cls, type) else None
        if callable(tick) and not isinstance(tick, mock.Mock):
            return menubar

    # Linux CI has no rumps. MagicMock() as rumps.App makes ServerHubBar
    # unusable (not a type, no tick); give App a real base so the class
    # statement in menubar.py still defines tick.
    class _FakeApp:
        def __init__(self, *args, **kwargs):
            self.menu = {}
            self.title = ""

    fake = mock.MagicMock()
    fake.App = _FakeApp
    sys.modules["rumps"] = fake
    sys.modules["rumps.rumps"] = fake
    if "menubar" in sys.modules:
        del sys.modules["menubar"]
    return importlib.import_module("menubar")


class _Recursing:
    """Leftover recursive ``__format__``/``__str__`` — not a ValueError."""

    def __format__(self, spec):
        raise RecursionError("nested")

    def __str__(self):
        raise RecursionError("nested")


class MenuBarDumpsLeftoverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mb = _load_menubar()

    def _status(self, **extra):
        row = {
            "id": "panel",
            "name": "Panel",
            "state": "ok",
            "url": "http://localhost:8086",
            "actions": ["restart"],
            "links": [],
        }
        row.update(extra)
        return {
            "counts": {"ok": 1, "warn": 0, "down": 0},
            "groups": [{"group": "Core", "services": [row]}],
            "problems": [],
            "links": [],
        }

    def test_leftover_inf_port_does_not_crash_signature(self):
        """``json.dumps`` without allow_nan=False used to emit Infinity."""
        sig = self.mb._menu_signature(self._status(port=float("inf")), [])
        self.assertNotIn("Infinity", sig)
        json.loads(sig)
        _starlette(json.loads(sig))

    def test_leftover_bytes_name_does_not_crash_signature(self):
        """``bytes`` in a service name used to TypeError the menu signature."""
        sig = self.mb._menu_signature(self._status(name=b"Panel"), [])
        data = json.loads(sig)
        self.assertEqual(data["groups"][0]["services"][0]["name"], "Panel")
        _starlette(data)

    def test_leftover_surrogate_name_does_not_crash_signature(self):
        """Leftover ``\\ud800`` used to fail UTF-8 encode of the signature."""
        sig = self.mb._menu_signature(self._status(name="Panel\ud800"), [])
        data = json.loads(sig)
        self.assertNotIn("\ud800", data["groups"][0]["services"][0]["name"])
        _starlette(data)
        sig.encode("utf-8")

    def test_leftover_non_dict_rows_do_not_crash_signature(self):
        """A leftover string group / task used to AttributeError ``.get``."""
        status = {
            "counts": float("inf"),
            "groups": ["nope", {"group": "Core", "services": ["x", {
                "id": "ok", "name": "ok", "state": "ok",
            }]}],
            "problems": ["x", {"id": "p1"}],
            "links": ["x", {"name": "Lab", "url": "http://x"}],
        }
        sig = self.mb._menu_signature(status, ["nope", {"id": "t", "name": b"T"}])
        data = json.loads(sig)
        self.assertEqual(data["groups"][0]["services"][0]["id"], "ok")
        self.assertEqual(data["tasks"][0]["name"], "T")
        _starlette(data)

    def test_leftover_post_body_does_not_crash_dumps(self):
        """Action POST ``json.dumps`` used to TypeError leftover bytes / inf."""
        import io

        captured = {}

        def fake_urlopen(req, timeout=10):
            captured["body"] = req.data
            return io.BytesIO(b'{"ok": true}')

        from pathlib import Path

        with mock.patch.object(self.mb.urllib.request, "urlopen", fake_urlopen), \
             mock.patch.object(self.mb, "LOCAL_TOKEN_FILE", Path("/no/such/token")):
            out = self.mb._json(
                "http://127.0.0.1/api/action",
                method="POST",
                data={"target": b"panel", "action": "restart\ud800",
                      "n": float("inf")},
            )
        self.assertEqual(out, {"ok": True})
        body = json.loads(captured["body"].decode("utf-8"))
        self.assertEqual(body["target"], "panel")
        self.assertNotIn("\ud800", body["action"])
        self.assertIsNone(body["n"])

    def test_huge_token_file_does_not_oom_poll(self):
        """``Path.read_text()`` of leftover multi-MB token used to OOM rumps."""
        import io
        import tempfile
        from pathlib import Path

        tmp = Path(tempfile.mkdtemp()) / "token"
        tmp.write_bytes(b"x" * (2 * 1024 * 1024))

        def fake_urlopen(req, timeout=10):
            self.assertNotIn("X-ServerHub-Local-Token", req.headers)
            return io.BytesIO(b'{"ok": true}')

        with mock.patch.object(self.mb.urllib.request, "urlopen", fake_urlopen), \
             mock.patch.object(self.mb, "LOCAL_TOKEN_FILE", tmp):
            out = self.mb._json("http://127.0.0.1/api/status")
        self.assertEqual(out, {"ok": True})

    def test_nested_status_json_does_not_crash_poll(self):
        import io

        nested = '{"k":' * 12000 + "1" + "}" * 12000

        def fake_urlopen(req, timeout=10):
            return io.BytesIO(nested.encode())

        from pathlib import Path
        with mock.patch.object(self.mb.urllib.request, "urlopen", fake_urlopen), \
             mock.patch.object(self.mb, "LOCAL_TOKEN_FILE", Path("/no/such/token")):
            out = self.mb._json("http://127.0.0.1/api/status")
        self.assertEqual(out, {})

    def test_huge_status_body_does_not_oom_poll(self):
        """``json.load(urlopen(...))`` of leftover multi-MB /api/status used
        to OOM the rumps timer the same way the uncapped token file did."""
        import io

        huge = b'{"ok": true, "pad": "' + b"x" * (2 * 1024 * 1024) + b'"}'

        def fake_urlopen(req, timeout=10):
            return io.BytesIO(huge)

        from pathlib import Path
        with mock.patch.object(self.mb.urllib.request, "urlopen", fake_urlopen), \
             mock.patch.object(self.mb, "LOCAL_TOKEN_FILE", Path("/no/such/token")):
            out = self.mb._json("http://127.0.0.1/api/status")
        self.assertEqual(out, {})


class ActionMessageLeftoverTests(unittest.TestCase):
    def test_leftover_bytes_inf_surrogate_do_not_500_action(self):
        """Leftover action ``message`` used to 500 the menubar POST /api/action."""
        from hub.routers import api as api_mod

        class _Req:
            state = type("S", (), {"serverhub_auth_kind": "session"})()

        for leftover in (b"done", float("inf"), "ok\ud800"):
            with mock.patch.object(api_mod.actions, "run_action", return_value=(0, leftover, "")), \
                 mock.patch.object(api_mod, "invalidate_status"):
                resp = api_mod.api_action(
                    api_mod.Action(target="panel", action="restart"), _Req(),
                )
            payload = json.loads(resp.body)
            _starlette(payload)
            self.assertTrue(payload["ok"])
            self.assertNotIn("\ud800", payload["message"])
            self.assertNotIn("Infinity", json.dumps(payload, allow_nan=False))


class MenuBarTranslateLeftoverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mb = _load_menubar()

    def _safe(self, text):
        self.assertIsInstance(text, str)
        text.encode("utf-8")
        json.dumps(text, ensure_ascii=False).encode("utf-8")
        self.assertNotIn("\ud800", text)
        return text

    def test_happy_path_summary_still_fills(self):
        self.assertEqual(
            self.mb._t("en", "summary", ok=1, warn=0, down=0),
            "1 OK · 0 warnings · 0 down",
        )

    def test_recursing_format_param_does_not_raise(self):
        """Leftover recursive ``__format__``/``__str__`` used to RecursionError
        ``_t`` during tick after api_status already succeeded."""
        text = self.mb._t("en", "notify_fail", message=_Recursing())
        self._safe(text)
        text = self.mb._t("en", "maint_start_fail", e=_Recursing())
        self._safe(text)
        text = self.mb._t(
            "en", "group_counts",
            head="🟢", group=_Recursing(), ok=1, total=2,
        )
        self._safe(text)

    def test_leftover_ud800_bytes_inf_params_do_not_raise(self):
        for leftover in (b"done", float("inf"), "ok\ud800"):
            text = self.mb._t("en", "notify_done", message=leftover)
            self._safe(text)
            text = self.mb._t("en", "docker_error", e=leftover)
            self._safe(text)

    def test_missing_format_key_does_not_raise(self):
        text = self.mb._t("en", "summary", ok=1)
        self._safe(text)
        text = self.mb._t("en", "group_counts", head="🟢")
        self._safe(text)


class TickRebuildLeftoverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mb = _load_menubar()

    def _status(self, **extra):
        row = {
            "id": "panel",
            "name": "Panel",
            "state": "ok",
            "url": "http://localhost:8086",
            "actions": ["restart"],
            "links": [],
        }
        row.update(extra)
        return {
            "counts": {"ok": 1, "warn": 0, "down": 0},
            "groups": [{"group": "Core", "services": [row]}],
            "problems": [],
            "links": [],
        }

    def test_leftover_rebuild_after_status_does_not_kill_timer(self):
        """A leftover RecursionError in the rebuild half used to escape tick
        and take the 30s rumps timer down; status had already arrived, so the
        last menu must stay (not flip to offline)."""
        bar = object.__new__(self.mb.ServerHubBar)
        bar._menu_state = "kept"
        bar._summary_item = object()
        bar._locale = "en"
        bar.title = "🖥"
        bar.replace_menu = mock.Mock()

        status = self._status(name=_Recursing())
        with mock.patch.object(self.mb, "api_status", return_value=status), \
             mock.patch.object(self.mb, "_json", return_value=[]), \
             mock.patch.object(
                 self.mb, "_menu_signature", side_effect=RecursionError("nested"),
             ):
            self.mb.ServerHubBar.tick(bar, None)
        self.assertEqual(bar._menu_state, "kept")
        for call in bar.replace_menu.call_args_list:
            args = call.args
            state = args[1] if len(args) > 1 else call.kwargs.get("state")
            self.assertNotEqual(state, "offline")
        bar.replace_menu.assert_not_called()
