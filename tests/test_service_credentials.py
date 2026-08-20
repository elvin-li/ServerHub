import json
import stat
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException

from hub import service_credentials as creds


class ServiceCredentialTests(unittest.TestCase):
    def test_keychain_password_uses_interactive_hex_without_argv_secret(self):
        with patch.object(
            creds.subprocess,
            "run",
            return_value=types.SimpleNamespace(returncode=0, stdout="", stderr=""),
        ) as run:
            creds._security(["add-generic-password", "-w"], password_input="secret-password")

        self.assertEqual(run.call_args.args[0], [creds.SECURITY, "-i"])
        payload = run.call_args.kwargs["input"]
        if isinstance(payload, bytes):
            payload = payload.decode()
        self.assertNotIn("secret-password", payload)
        self.assertIn("7365637265742d70617373776f7264", payload)
        self.assertNotIn("secret-password", run.call_args.args[0])

    def test_store_keeps_secret_out_of_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            index = Path(tmp) / "service-credentials.json"

            def fake_security(args, timeout=15, password_input=None):
                if args and args[0] == "add-generic-password":
                    self.assertEqual(password_input, "secret-password")
                    self.assertNotIn("secret-password", args)
                return (0, "ok")

            with patch.object(creds, "INDEX_FILE", index), patch.object(creds, "_security", fake_security):
                item = creds.store(
                    "native:native-filebrowser",
                    display_name="FileBrowser",
                    username="admin",
                    password="secret-password",
                    url="http://host:8125",
                    adapter="filebrowser",
                    applied=True,
                )
                loaded = creds.get("native:native-filebrowser")

            raw = index.read_text(encoding="utf-8")
            payload = json.loads(raw)
            self.assertNotIn("secret-password", raw)
            self.assertNotIn("password", payload["native:native-filebrowser"])
            self.assertTrue(item["has_password"])
            self.assertTrue(loaded["has_password"])
            self.assertEqual(stat.S_IMODE(index.stat().st_mode), 0o600)

    def test_filebrowser_is_an_apply_adapter(self):
        self.assertEqual(creds.adapter_for("native:native-filebrowser"), "filebrowser")
        self.assertEqual(creds.adapter_for("docker:teslamate"), "teslamate-basic-auth")
        self.assertEqual(creds.adapter_for("docker:other-app"), "generic")

    def test_isoformat_inf_does_not_500_json_safe(self):
        """A leftover ``isoformat()`` returning inf used to 500 GET /api/apps/credentials."""
        class _Stamp:
            def isoformat(self):
                return float("inf")

        self.assertIsNone(creds._json_safe(_Stamp()))
        out = creds._json_safe({"display_name": _Stamp(), "username": "admin"})
        json.dumps(out, allow_nan=False)
        json.dumps(out, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertIsNone(out["display_name"])
        self.assertEqual(out["username"], "admin")

    def test_store_inf_clock_does_not_500(self):
        """``int(time.time())`` OverflowError on leftover inf used to 500 PUT credentials."""
        with tempfile.TemporaryDirectory() as tmp:
            index = Path(tmp) / "service-credentials.json"
            with (
                patch.object(creds, "INDEX_FILE", index),
                patch.object(creds, "_security", return_value=(0, "ok")),
                patch.object(creds.time, "time", return_value=float("inf")),
            ):
                item = creds.store(
                    "native:native-filebrowser",
                    display_name="FileBrowser",
                    username="admin",
                    password="secret-password",
                )
            json.dumps(item, allow_nan=False)
            self.assertEqual(item.get("updated_at"), 0)

    def test_invalid_service_id_is_rejected(self):
        with self.assertRaises(HTTPException):
            creds.get("../not-allowed")

    def test_filebrowser_apply_restores_running_service(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "filebrowser-bin"
            database = Path(tmp) / "filebrowser.db"
            binary.touch()
            database.touch()
            calls = []

            def fake_sh(command, timeout=30):
                calls.append(command)
                return 0, "updated", ""

            with (
                patch("hub.files_svc.FB_BIN", binary),
                patch("hub.files_svc.FB_DB", database),
                patch("hub.files_svc.filebrowser_status", return_value={"running": True}),
                patch("hub.files_svc.stop_filebrowser", return_value={"running": False}),
                patch("hub.files_svc.ensure_filebrowser") as restart,
                patch("hub.util.sh", fake_sh),
            ):
                result = creds.apply_filebrowser("admin", "new-password")

            self.assertTrue(result["ok"])
            self.assertIn("users", calls[0])
            self.assertIn("update", calls[0])
            restart.assert_called_once()

    def test_teslamate_apply_hashes_password_and_reloads_nginx(self):
        with tempfile.TemporaryDirectory() as tmp:
            password_file = Path(tmp) / ".htpasswd"
            nginx_site = Path(tmp) / "20-teslamate.conf"
            nginx_site.touch()

            def fake_run(command, **kwargs):
                self.assertEqual(command, [creds.HTPASSWD, "-ni", "teslamate"])
                payload = kwargs["input"]
                if isinstance(payload, bytes):
                    payload = payload.decode()
                self.assertEqual(payload, "new-password\n")
                self.assertNotIn("new-password", command)
                return types.SimpleNamespace(
                    returncode=0,
                    stdout="teslamate:$apr1$abcdefgh$abcdefghijklmnopqrstuv\n",
                    stderr="",
                )

            with (
                patch.object(creds, "TESLAMATE_HTPASSWD", password_file),
                patch.object(creds, "TESLAMATE_NGINX_SITE", nginx_site),
                patch.object(creds.subprocess, "run", side_effect=fake_run),
                patch("hub.nginx_svc.reload_nginx", return_value={"ok": True}),
            ):
                result = creds.apply_teslamate("teslamate", "new-password")

            self.assertTrue(result["ok"])
            self.assertNotIn("new-password", password_file.read_text(encoding="utf-8"))
            self.assertEqual(stat.S_IMODE(password_file.stat().st_mode), 0o600)

    def test_teslamate_nginx_failure_restores_the_previous_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            password_file = Path(tmp) / ".htpasswd"
            password_file.write_text("teslamate:oldhash\n", encoding="utf-8")
            nginx_site = Path(tmp) / "20-teslamate.conf"
            nginx_site.touch()

            def fake_run(command, **kwargs):
                return types.SimpleNamespace(
                    returncode=0,
                    stdout="teslamate:$apr1$new$newhash\n",
                    stderr="",
                )

            with (
                patch.object(creds, "TESLAMATE_HTPASSWD", password_file),
                patch.object(creds, "TESLAMATE_NGINX_SITE", nginx_site),
                patch.object(creds.subprocess, "run", side_effect=fake_run),
                patch("hub.nginx_svc.reload_nginx", return_value={"ok": False, "message": "bad"}),
            ):
                with self.assertRaises(HTTPException) as raised:
                    creds.apply_teslamate("teslamate", "new-password")
            self.assertEqual(
                raised.exception.detail["code"], "credentials.teslamate_apply_failed"
            )
            self.assertEqual(password_file.read_text(encoding="utf-8"), "teslamate:oldhash\n")
            self.assertEqual(stat.S_IMODE(password_file.stat().st_mode), 0o600)

    def test_teslamate_rejects_unsafe_username(self):
        with self.assertRaises(HTTPException):
            creds.apply_teslamate("bad:user", "new-password")

    def test_teslamate_huge_htpasswd_does_not_oom_apply(self):
        """``Path.read_bytes()`` of leftover multi-MB .htpasswd used to OOM PUT credentials."""
        with tempfile.TemporaryDirectory() as tmp:
            password_file = Path(tmp) / ".htpasswd"
            password_file.write_bytes(b"x" * (2 * 1024 * 1024))
            nginx_site = Path(tmp) / "20-teslamate.conf"
            nginx_site.touch()

            def fake_run(command, **kwargs):
                return types.SimpleNamespace(
                    returncode=0,
                    stdout="teslamate:$apr1$abcdefgh$abcdefghijklmnopqrstuv\n",
                    stderr="",
                )

            with (
                patch.object(creds, "TESLAMATE_HTPASSWD", password_file),
                patch.object(creds, "TESLAMATE_NGINX_SITE", nginx_site),
                patch.object(creds.subprocess, "run", side_effect=fake_run),
                patch("hub.nginx_svc.reload_nginx", return_value={"ok": True}),
            ):
                result = creds.apply_teslamate("teslamate", "new-password")

            self.assertTrue(result["ok"])
            self.assertTrue(password_file.read_text(encoding="utf-8").startswith("teslamate:"))
            self.assertLess(password_file.stat().st_size, 1024)
        src = Path(creds.__file__).read_text(encoding="utf-8")
        body = src[src.index("def apply_teslamate"): src.index("\ndef apply(")]
        self.assertIn("read_bytes_capped", body)
        self.assertNotIn(".read_bytes()", body)

    def test_teslamate_htpasswd_missing_is_coded(self):
        with tempfile.TemporaryDirectory() as tmp:
            nginx_site = Path(tmp) / "20-teslamate.conf"
            nginx_site.touch()
            with (
                patch.object(creds, "TESLAMATE_NGINX_SITE", nginx_site),
                patch.object(
                    creds.subprocess, "run",
                    side_effect=FileNotFoundError("htpasswd"),
                ),
            ):
                with self.assertRaises(HTTPException) as raised:
                    creds.apply_teslamate("teslamate", "new-password")
        self.assertEqual(raised.exception.detail["code"], "credentials.htpasswd_failed")

    def test_recursing_index_save_is_coded_not_500(self):
        """leftover ``str(exc)`` RecursionError used to 500 PUT /api/apps/credentials."""
        class Recursing(OSError):
            def __str__(self):
                raise RecursionError("nested")

        with tempfile.TemporaryDirectory() as tmp:
            index = Path(tmp) / "service-credentials.json"
            with (
                patch.object(creds, "INDEX_FILE", index),
                patch.object(creds, "_security", return_value=(0, "ok")),
                patch.object(creds, "_save", side_effect=Recursing(28, "No space")),
                patch.object(creds, "_delete_keychain"),
            ):
                with self.assertRaises(HTTPException) as raised:
                    creds.store(
                        "native:native-filebrowser",
                        display_name="FileBrowser",
                        username="admin",
                        password="secret-password",
                        url="http://host:8125",
                        adapter="filebrowser",
                    )
        self.assertEqual(raised.exception.detail["code"], "credentials.index_save_failed")
        json.dumps(raised.exception.detail, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertEqual(raised.exception.detail["params"]["error"], "Recursing")

    def test_recursing_htpasswd_oserror_is_coded_not_500(self):
        """leftover ``str(exc)`` RecursionError used to 500 TeslaMate htpasswd spawn."""
        class Recursing(OSError):
            def __str__(self):
                raise RecursionError("nested")

        with tempfile.TemporaryDirectory() as tmp:
            nginx_site = Path(tmp) / "20-teslamate.conf"
            nginx_site.touch()
            with (
                patch.object(creds, "TESLAMATE_NGINX_SITE", nginx_site),
                patch.object(
                    creds, "_run_with_input",
                    side_effect=Recursing(2, "htpasswd"),
                ),
            ):
                with self.assertRaises(HTTPException) as raised:
                    creds.apply_teslamate("teslamate", "new-password")
        self.assertEqual(raised.exception.detail["code"], "credentials.htpasswd_failed")
        json.dumps(raised.exception.detail, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertEqual(raised.exception.detail["params"]["error"], "Recursing")

    def test_credential_clis_do_not_capture_unbounded_output(self):
        import inspect
        for fn in (creds._security, creds.apply_teslamate, creds._run_with_input):
            src = inspect.getsource(fn)
            impl = src.split('"""', 2)[-1]
            self.assertNotIn("capture_output=True", impl, fn.__name__)
        self.assertIn("TemporaryFile", inspect.getsource(creds._run_with_input))


if __name__ == "__main__":
    unittest.main()
