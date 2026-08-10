import unittest

from hub import __version__
from hub.app_factory import create_app
from hub.routers.settings_api import _public_settings
from hub.system_settings_svc import get_management_access
from hub.tools_svc import about_info, diagnostics


class VersionConsistencyTests(unittest.TestCase):
    def test_backend_surfaces_use_package_version(self):
        self.assertEqual(create_app().version, __version__)
        self.assertEqual(get_management_access()["version"], __version__)
        self.assertEqual(_public_settings()["version"], __version__)
        self.assertEqual(about_info()["version"], __version__)
        self.assertEqual(diagnostics()["version"], __version__)


if __name__ == "__main__":
    unittest.main()
