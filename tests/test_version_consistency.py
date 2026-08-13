"""Every stated product version equals hub.__version__.

hub/__init__.py is the single source of truth: the backend APIs and the SPA
already read it instead of carrying release constants.  The places that
cannot import it -- the README headline and the macOS build scripts -- carry
a literal copy, and nothing kept those copies honest: a bump that missed one
file shipped an app bundle or a README claiming the wrong release.  This
file makes that drift a test failure instead of a support ticket.
"""
import unittest
from pathlib import Path

from hub import __version__

BASE = Path(__file__).resolve().parent.parent


class VersionStatementsAgree(unittest.TestCase):
    def test_readme_headline(self):
        first_line = (BASE / "README.md").read_text().splitlines()[0]
        self.assertEqual(
            first_line, f"# ServerHub v{__version__}",
            "README.md's title must state the hub.__version__ release",
        )

    def test_macos_app_bundle_versions(self):
        body = (BASE / "macos" / "build_app.sh").read_text()
        for key in ("CFBundleShortVersionString", "CFBundleVersion"):
            self.assertIn(
                f"<key>{key}</key><string>{__version__}</string>", body,
                f"build_app.sh stamps {key} into ServerHub.app",
            )

    def test_macos_distribution_build(self):
        body = (BASE / "macos" / "build_distribution.sh").read_text()
        self.assertIn(f'VERSION="{__version__}"', body)
        self.assertIn(
            f"ServerHub {__version__}", body,
            "the distribution notes must name the same release",
        )

    def test_distribution_requirements_header(self):
        first_line = (
            (BASE / "macos" / "requirements-distribution.txt")
            .read_text().splitlines()[0]
        )
        self.assertIn(f"ServerHub {__version__}", first_line)


if __name__ == "__main__":
    unittest.main()
