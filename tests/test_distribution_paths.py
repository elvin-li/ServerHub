from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parent.parent


class DistributionPathTests(unittest.TestCase):
    def test_source_checkout_keeps_state_beside_runtime_by_default(self):
        from hub import paths

        self.assertEqual(paths.STATE_ROOT, paths.RUNTIME_ROOT)
        self.assertEqual(paths.CONFIG_FILE, paths.RUNTIME_ROOT / "services.yaml")
        self.assertEqual(paths.DATA_DIR, paths.RUNTIME_ROOT / "data")

    def test_packaged_runtime_keeps_all_mutable_state_outside_bundle(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runtime = root / "ServerHub.app" / "Contents" / "Resources" / "ServerHubRuntime"
            state = root / "home" / "Library" / "Application Support" / "ServerHub"
            home = root / "home"
            runtime.mkdir(parents=True)
            home.mkdir(exist_ok=True)
            runtime.chmod(0o555)

            script = r"""
import json
from hub import alerts, audit, auth, containers_svc, files_svc, metrics
from hub import service_credentials, services_uninstall_svc, terminal_svc
from hub.config import DATA_DIR, YAML_PATH, cfg
from hub.paths import BASE, CONFIG_FILE, RUNTIME_ROOT, STATE_ROOT

cfg()
setup_token = auth.setup_token()
local_token = auth.local_client_token()
paths = {
    "runtime": RUNTIME_ROOT,
    "base": BASE,
    "state": STATE_ROOT,
    "config": CONFIG_FILE,
    "yaml": YAML_PATH,
    "data": DATA_DIR,
    "setup": auth.SETUP_TOKEN_FILE,
    "local": auth.LOCAL_TOKEN_FILE,
    "session": auth.SECRET_FILE,
    "alerts": alerts.ALERTS_FILE,
    "alert_state": alerts.STATE_FILE,
    "metrics": metrics.METRICS_FILE,
    "auth_audit": audit.AUDIT_PATH,
    "terminal_audit": terminal_svc.AUDIT_PATH,
    "credentials": service_credentials.INDEX_FILE,
    "container_status": containers_svc.UPDATE_STATUS_PATH,
    "uninstalled_agents": services_uninstall_svc.BACKUP_DIR,
}
print(json.dumps({
    "paths": {key: str(value) for key, value in paths.items()},
    "state_mode": STATE_ROOT.stat().st_mode & 0o777,
    "data_mode": DATA_DIR.stat().st_mode & 0o777,
    "config_mode": YAML_PATH.stat().st_mode & 0o777,
    "setup_mode": auth.SETUP_TOKEN_FILE.stat().st_mode & 0o777,
    "local_mode": auth.LOCAL_TOKEN_FILE.stat().st_mode & 0o777,
    "tokens_distinct": setup_token != local_token,
    "state_protected": files_svc.is_protected(STATE_ROOT / "data" / ".local-client-token"),
}))
"""
            env = os.environ.copy()
            env.update({
                "HOME": str(home),
                "PYTHONPATH": str(ROOT),
                "SERVERHUB_RUNTIME_DIR": str(runtime),
                "SERVERHUB_STATE_DIR": str(state),
            })
            result = subprocess.run(
                [sys.executable, "-c", script],
                cwd=root,
                env=env,
                capture_output=True,
                text=True,
                timeout=20,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            report = json.loads(result.stdout)

            resolved_runtime = str(runtime.resolve())
            resolved_state = state.resolve()
            self.assertEqual(report["paths"]["runtime"], resolved_runtime)
            self.assertEqual(report["paths"]["base"], resolved_runtime)
            self.assertEqual(report["paths"]["state"], str(resolved_state))
            self.assertEqual(report["paths"]["config"], str(resolved_state / "services.yaml"))
            self.assertEqual(report["paths"]["yaml"], str(resolved_state / "services.yaml"))
            self.assertEqual(report["paths"]["data"], str(resolved_state / "data"))
            for name, value in report["paths"].items():
                if name in {"runtime", "base"}:
                    continue
                self.assertTrue(
                    Path(value).resolve().is_relative_to(state.resolve()),
                    f"{name} escaped mutable state: {value}",
                )
            self.assertEqual(report["state_mode"], 0o700)
            self.assertEqual(report["data_mode"], 0o700)
            self.assertEqual(report["config_mode"], 0o600)
            self.assertEqual(report["setup_mode"], 0o600)
            self.assertEqual(report["local_mode"], 0o600)
            self.assertTrue(report["tokens_distinct"])
            self.assertTrue(report["state_protected"])
            self.assertEqual(list(runtime.iterdir()), [])

    def test_diagnostics_persistence_reports_write_failure(self):
        from hub import system_settings_svc

        with patch("hub.system_settings_svc.DATA_DIR") as data_dir:
            data_dir.mkdir.side_effect = PermissionError("read-only state directory")
            saved_path, save_error = system_settings_svc._persist_diagnostics({
                "generated_at": "2026-07-30T00:00:00+0000",
            })

        self.assertIsNone(saved_path)
        self.assertIn("read-only state directory", save_error)


if __name__ == "__main__":
    unittest.main(verbosity=2)
