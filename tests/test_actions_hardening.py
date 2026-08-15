"""Native app/script actions must not go through a shell."""
from __future__ import annotations

import unittest
from unittest.mock import patch

from fastapi import HTTPException

from hub import actions


class ProcessNameTests(unittest.TestCase):
    def test_ordinary_names_are_accepted(self):
        self.assertEqual(actions._app_process_name("OrbStack"), "OrbStack")
        self.assertEqual(actions._app_process_name("Home Assistant"), "Home Assistant")

    def test_quoted_or_option_shaped_names_are_refused(self):
        for name in ('Evil"; do evil', "--all", "", "a" * 80, "app$(id)"):
            with self.subTest(name=name):
                with self.assertRaises(HTTPException) as raised:
                    actions._app_process_name(name)
                self.assertEqual(raised.exception.status_code, 400)


class ScriptActionTests(unittest.TestCase):
    def test_start_uses_argv_without_a_shell(self):
        with (
            patch.object(actions, "registry", return_value={
                "backup": ("script", {"start": "/usr/bin/true --flag"}),
            }),
            patch.object(actions.subprocess, "Popen") as popen,
        ):
            rc, _out, _err = actions.run_action("backup", "start")
        self.assertEqual(rc, 0)
        popen.assert_called_once()
        self.assertEqual(popen.call_args.args[0], ["/usr/bin/true", "--flag"])
        self.assertTrue(popen.call_args.kwargs["start_new_session"])

    def test_stop_does_not_use_shell_true(self):
        with (
            patch.object(actions, "registry", return_value={
                "backup": ("script", {"stop": "/usr/bin/true"}),
            }),
            patch.object(actions, "sh") as sh,
            patch.object(actions.time, "sleep"),
        ):
            actions.run_action("backup", "stop")
        sh.assert_called_once()
        self.assertEqual(sh.call_args.args[0], ["/usr/bin/true"])
        self.assertNotIn("shell", sh.call_args.kwargs)

    def test_actions_module_has_no_shell_true(self):
        from pathlib import Path

        source = Path(actions.__file__).read_text(encoding="utf-8")
        self.assertNotIn("shell=True", source)


if __name__ == "__main__":
    unittest.main()
