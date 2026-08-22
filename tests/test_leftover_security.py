"""Leftover security holes after the notify/O_NOFOLLOW/denylist pass.

Each test pins one confirmed remaining bug: catalog-remote SSRF, YAML
``!!python`` tags from ``yaml.dump``, HTTP Origin/Host compared only by
netloc, leftover non-str (``!!binary``) in argv, log tails that followed
last-component symlinks, and bookmark/adaptive probes that still honoured
``HTTP_PROXY`` / followed 30x.
"""
from __future__ import annotations

import errno
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml
from fastapi import HTTPException

from hub import (
    catalog,
    cli_args,
    compose_svc,
    config,
    files_svc,
    jobs,
    logs_svc,
    scheduler_svc,
    util,
    websocket_security,
)


class CatalogRemoteSsrfTests(unittest.TestCase):
    def test_opener_still_ignores_env_proxy(self):
        from hub import catalog_remote

        src = Path(catalog_remote.__file__).read_text(encoding="utf-8")
        self.assertIn("ProxyHandler({})", src)
        self.assertIn("redirect left origin", src)


class YamlPythonTagTests(unittest.TestCase):
    def test_config_dump_does_not_emit_python_tuple_tags(self):
        text = config._dump({"ports": (80, 443)})
        self.assertNotIn("!!python", text)
        self.assertEqual(yaml.safe_load(text), {"ports": [80, 443]})

    def test_compose_validate_refuses_python_tags(self):
        out = compose_svc.validate_compose_text(
            "services:\n  x:\n    image: !!python/object/apply:os.system ['id']\n"
        )
        self.assertFalse(out["ok"])
        self.assertIn("python YAML", out["message"])


class HttpOriginHostTests(unittest.TestCase):
    def test_javascript_scheme_is_not_same_origin(self):
        self.assertFalse(
            websocket_security.origin_allowed("javascript://panel.example", "panel.example")
        )

    def test_http_middleware_uses_the_shared_origin_check(self):
        src = Path(__file__).resolve().parent.parent.joinpath(
            "hub", "app_factory.py"
        ).read_text(encoding="utf-8")
        self.assertIn("origin_allowed", src)
        self.assertNotIn("urlsplit(origin).netloc.lower() != host.lower()", src)


class LeftoverNonStrArgvTests(unittest.TestCase):
    def test_as_argv_rejects_yaml_binary_leftover(self):
        self.assertIsNone(cli_args.as_argv(["docker", "stop", b"--all"]))
        self.assertIsNone(cli_args.as_argv(["dig", b"-f/etc/passwd"]))
        self.assertIsNone(cli_args.as_argv(["echo", True]))
        self.assertEqual(cli_args.as_argv(["docker", "stop", "nginx"]), ["docker", "stop", "nginx"])

    def test_sh_does_not_exec_leftover_bytes(self):
        rc, out, err = util.sh(["/bin/echo", b"--all"])
        self.assertEqual(rc, -1)
        self.assertEqual(err, "invalid argv")
        self.assertEqual(out, "")

    def test_run_watchdog_does_not_exec_leftover_bytes(self):
        log: list[str] = []
        rc = jobs.run_watchdog(["/bin/echo", b"--all"], timeout=2, log=log)
        self.assertEqual(rc, -1)
        self.assertTrue(any("invalid argv" in line for line in log))

    def test_scheduler_command_ignores_leftover_non_str(self):
        self.assertEqual(scheduler_svc._command_text(b"rm -rf /"), "")
        self.assertEqual(scheduler_svc._command_text([b"rm", b"-rf", "/"]), "")
        self.assertEqual(scheduler_svc._command_text(["echo", "ok"]), "echo ok")

    def test_as_argv_rejects_leftover_surrogate(self):
        self.assertIsNone(cli_args.as_argv(["/bin/echo", "ok\ud800"]))

    def test_sh_drops_leftover_surrogate_env_instead_of_500(self):
        """Leftover ``\\ud800`` in env UnicodeEncodeError'd ``subprocess.run``."""
        rc, out, err = util.sh(
            ["/bin/echo", "ok"],
            timeout=2,
            env={"PATH": "/bin:/usr/bin", "LEFTOVER": "x\ud800"},
        )
        self.assertEqual(rc, 0)
        self.assertEqual(out, "ok")
        self.assertEqual(err, "")

    def test_run_capped_drops_leftover_surrogate_env_instead_of_500(self):
        rc, text = util.run_capped(
            ["/bin/echo", "ok"],
            timeout=2,
            env={"PATH": "/bin:/usr/bin", "LEFTOVER": "x\ud800"},
            cap=64,
        )
        self.assertEqual(rc, 0)
        self.assertIn("ok", text)

    def test_run_capped_surrogate_cwd_is_not_500(self):
        rc, text = util.run_capped(
            ["/bin/echo", "ok"],
            timeout=2,
            cwd="\ud800",
            cap=64,
        )
        self.assertEqual(rc, -1)
        self.assertIsInstance(text, str)

    def test_run_watchdog_leftover_surrogate_env_is_not_500(self):
        log: list[str] = []
        rc = jobs.run_watchdog(
            ["/bin/echo", "ok"],
            timeout=2,
            log=log,
            env={"PATH": "/bin:/usr/bin", "LEFTOVER": "x\ud800"},
        )
        self.assertEqual(rc, 0)
        self.assertTrue(any("ok" in line for line in log))

    def test_utf8_env_drops_nul_and_surrogate(self):
        cleaned = util.utf8_env({
            "OK": "yes",
            "BAD": "x\ud800",
            "NUL": "a\x00b",
            1: "nope",
        })
        self.assertEqual(cleaned, {"OK": "yes"})

    def test_rsync_macos_brew_wg_popen_pass_utf8_env(self):
        """Leftover inherit ``\\ud800`` env UnicodeEncodeError is ValueError, not OSError."""
        from hub import brew_cache, macos_admin, rsync_svc, service_credentials, wireguard_svc

        self.assertIn("env=utf8_env()", Path(rsync_svc.__file__).read_text(encoding="utf-8"))
        self.assertIn("env=utf8_env()", Path(macos_admin.__file__).read_text(encoding="utf-8"))
        self.assertIn("env=utf8_env()", Path(brew_cache.__file__).read_text(encoding="utf-8"))
        self.assertIn("env=utf8_env()", Path(wireguard_svc.__file__).read_text(encoding="utf-8"))
        self.assertIn("env=utf8_env()", Path(service_credentials.__file__).read_text(encoding="utf-8"))

    def test_run_watchdog_str_recursion_is_not_500(self):
        class Boom(Exception):
            def __str__(self):
                raise RecursionError("leftover")

        log: list[str] = []
        with mock.patch.object(jobs.subprocess, "Popen", side_effect=Boom()):
            rc = jobs.run_watchdog(["/bin/echo", "ok"], timeout=2, log=log)
        self.assertEqual(rc, -1)
        self.assertTrue(any("Boom" in line or "error" in line for line in log))


class LogSymlinkFollowTests(unittest.TestCase):
    def test_tail_file_lines_still_reads_a_rotation_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            real = Path(tmp) / "app.log"
            real.write_text("one\ntwo\n", encoding="utf-8")
            link = Path(tmp) / "current"
            link.symlink_to(real)
            self.assertEqual(util.tail_file_lines(link, 2), ["one", "two"])

    def test_tail_file_lines_refuses_a_swapped_resolved_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            victim = Path(tmp) / "secret"
            victim.write_text("TOKEN\n", encoding="utf-8")
            target = Path(tmp) / "app.log"
            target.write_text("ok\n", encoding="utf-8")
            target.unlink()
            target.symlink_to(victim)
            with mock.patch("os.path.realpath", return_value=str(target)):
                with self.assertRaises(OSError) as caught:
                    util.tail_file_lines(target, 2)
            self.assertEqual(caught.exception.errno, errno.ELOOP)

    def test_logs_tail_refuses_a_symlink_to_a_protected_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            secret = Path(tmp) / "service-credentials.json"
            secret.write_text("secret\n", encoding="utf-8")
            link = Path(tmp) / "app.log"
            link.symlink_to(secret)
            with mock.patch.object(
                logs_svc,
                "log_sources",
                return_value=[{
                    "id": "app",
                    "name": "app",
                    "path": str(link),
                    "exists": True,
                    "size": 7,
                }],
            ):
                with self.assertRaises(HTTPException) as raised:
                    logs_svc.tail_log("app")
            detail = raised.exception.detail
            code = detail.get("code") if isinstance(detail, dict) else detail
            self.assertEqual(code, "logs.protected")


class BookmarkAndAdaptiveProxyTests(unittest.TestCase):
    def test_bookmark_probe_disables_env_proxy(self):
        from hub import bookmarks_svc

        src = Path(bookmarks_svc.__file__).read_text(encoding="utf-8")
        self.assertIn("ProxyHandler({})", src)

    def test_adaptive_https_probe_does_not_follow_redirects_or_env_proxy(self):
        from hub import adaptive

        src = Path(adaptive.__file__).read_text(encoding="utf-8")
        self.assertIn("ProxyHandler({})", src)
        self.assertIn("NoRedirect", src)
        self.assertIn("RedirectRefused", src)
        self.assertNotIn("urlopen(req, timeout=0.8, context=ctx)", src)


class FilesOpenedPathTests(unittest.TestCase):
    def test_download_refuses_when_the_opened_fd_is_a_protected_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            allowed = Path(tmp) / "notes.txt"
            allowed.write_text("ok", encoding="utf-8")
            secret = Path(tmp) / "service-credentials.json"
            secret.write_text("token", encoding="utf-8")
            with (
                mock.patch.object(files_svc, "_resolve_safe", side_effect=[allowed, HTTPException(status_code=403, detail={"code": "files.path_protected"})]),
                mock.patch.object(files_svc, "_path_of_fd", return_value=str(secret)),
            ):
                with self.assertRaises(HTTPException) as ctx:
                    files_svc.download(str(allowed), "downloads")
            detail = ctx.exception.detail
            code = detail.get("code") if isinstance(detail, dict) else detail
            self.assertEqual(code, "files.path_protected")

    def test_download_source_rechecks_f_getpath(self):
        src = Path(files_svc.__file__).read_text(encoding="utf-8")
        self.assertIn("F_GETPATH", src)
        self.assertIn("_reject_opened_outside", src)


class CatalogRenderStillWorks(unittest.TestCase):
    def test_ordinary_password_still_renders(self):
        out = catalog.render_template("p={{P}}", {"P": "s3cret!value"})
        self.assertEqual(out, "p=s3cret!value")


if __name__ == "__main__":
    unittest.main()
