from __future__ import annotations

import re
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "macos" / "build_distribution.sh"
LOCK = ROOT / "macos" / "requirements-distribution.txt"


class MacOSDistributionBuildTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.script = SCRIPT.read_text(encoding="utf-8")
        cls.lock = LOCK.read_text(encoding="utf-8")
        cls.packages = [
            line.strip()
            for line in cls.lock.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]

    def test_script_has_valid_bash_syntax(self):
        result = subprocess.run(
            ["/bin/bash", "-n", str(SCRIPT)],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_python_runtime_is_immutable_and_checksum_pinned(self):
        self.assertIn('PYTHON_VERSION="3.12.13"', self.script)
        self.assertIn('PYTHON_RELEASE="20260728"', self.script)
        self.assertIn(
            'PYTHON_SHA256="2f18cdef4125ca1440dd1ba00ebcb267526efb532138c0860438f755ea4eebac"',
            self.script,
        )
        self.assertIn('ACTUAL_SHA256="$(archive_sha256 "$ARCHIVE_PATH")"', self.script)
        self.assertIn('if [[ "$ACTUAL_SHA256" != "$PYTHON_SHA256" ]]', self.script)

    def test_backend_lock_is_exact_and_excludes_menu_dependencies(self):
        self.assertGreaterEqual(len(self.packages), 16)
        self.assertTrue(all(re.fullmatch(r"[A-Za-z0-9_-]+==[^=<>~!]+", item) for item in self.packages))
        names = {item.split("==", 1)[0].lower().replace("_", "-") for item in self.packages}
        self.assertIn("fastapi", names)
        self.assertIn("uvicorn", names)
        self.assertIn("websockets", names)
        self.assertNotIn("rumps", names)
        self.assertNotIn("pyobjc-core", names)
        self.assertIn("--no-deps", self.script)
        self.assertIn("--only-binary=:all:", self.script)

    def test_generated_console_scripts_with_build_shebangs_are_removed(self):
        for command in ("fastapi", "idna", "uvicorn", "websockets"):
            self.assertIn(f'"$RUNTIME/python/bin/{command}"', self.script)
        self.assertIn("rm -f", self.script)

    def test_native_shell_is_built_before_runtime_is_injected(self):
        build = self.script.index('"$BUILD_APP" "$APP"')
        extract = self.script.index('"$TAR" -xzf "$ARCHIVE_PATH" -C "$RUNTIME"')
        self.assertLess(build, extract)
        self.assertIn('mkdir -p "$RUNTIME"', self.script[build:extract])

    def test_runtime_copy_uses_an_explicit_allowlist(self):
        self.assertIn(
            "for path in app.py hub static templates services.yaml.example; do",
            self.script,
        )
        self.assertNotIn('"$ROOT/services.yaml"', self.script)
        self.assertNotIn('"$ROOT/data"', self.script)
        for forbidden in (
            ".setup-token",
            ".local-client-token",
            ".session-secret",
            "services.yaml.bak.*",
            "node_modules",
        ):
            self.assertIn(forbidden, self.script)

    def test_runtime_state_is_smoke_tested_outside_bundle(self):
        self.assertNotIn('PYTHONPATH="$RUNTIME"', self.script)
        self.assertIn('PYTHONDONTWRITEBYTECODE=1', self.script)
        self.assertIn('"$PYTHON" -I -B - "$RUNTIME"', self.script)
        self.assertIn('sys.path.insert(0, sys.argv[1])', self.script)
        self.assertIn('SERVERHUB_RUNTIME_DIR="$RUNTIME"', self.script)
        self.assertIn('SERVERHUB_STATE_DIR="$STATE"', self.script)
        self.assertIn('[[ ! -e "$RUNTIME/services.yaml" && ! -e "$RUNTIME/data" ]]', self.script)
        self.assertIn('auth.local_client_token()', self.script)
        self.assertIn('auth.setup_token()', self.script)

    def test_distribution_checks_architecture_target_and_signature(self):
        self.assertIn('arches != ["arm64"]', self.script)
        self.assertIn('max(versions) > (13, 0)', self.script)
        self.assertIn('"$PYTHON" -I -B - "$RUNTIME"', self.script)
        self.assertEqual(
            self.script.count('PYTHONDONTWRITEBYTECODE=1 "$PYTHON" -I -B -'),
            2,
        )
        self.assertIn("-type d -name __pycache__", self.script)
        self.assertIn("-name '*.pyc'", self.script)
        cache_check = self.script.index("-type d -name __pycache__")
        signing = self.script.index('"$CODESIGN" --force --deep --sign -')
        self.assertLess(cache_check, signing)
        self.assertIn('CODESIGN" --force --deep --sign -', self.script)
        self.assertIn('CODESIGN" --verify --deep --strict', self.script)

    def test_test_dmg_contains_install_help_and_applications_link(self):
        self.assertIn('DMG_NAME="ServerHub-${VERSION}-arm64-test.dmg"', self.script)
        self.assertIn('ln -s /Applications "$DMG_ROOT/Applications"', self.script)
        self.assertIn('安装说明-INSTALL.txt', self.script)
        self.assertIn('"$SHASUM" -a 256 "$DMG_NAME"', self.script)
        self.assertIn('未经过 Apple 公证', self.script)

    def test_setup_token_is_not_added_to_a_url_or_log(self):
        self.assertNotRegex(self.script, r"https?[^\n]*setup-token")
        self.assertNotRegex(self.script, r"(printf|echo)[^\n]*setup_token")


if __name__ == "__main__":
    unittest.main()
