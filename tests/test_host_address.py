import unittest
from unittest.mock import patch

from hub import host_address


class HostAddressTests(unittest.TestCase):
    def tearDown(self):
        host_address._detect_cache.update(t=0.0, value=None)

    def test_auto_host_uses_route_detection(self):
        with (
            patch.object(host_address, "configured_host", return_value="auto"),
            patch.object(host_address, "detect_lan_ip", return_value="10.20.30.40"),
        ):
            self.assertEqual(host_address.host_ip(), "10.20.30.40")

    def test_explicit_host_override_is_preserved(self):
        with patch.object(host_address, "configured_host", return_value="server.local"):
            self.assertEqual(host_address.host_ip(), "server.local")

    def test_url_template_expansion(self):
        with (
            patch.object(host_address, "host_ip", return_value="10.20.30.40"),
            patch("hub.config.cfg", return_value={
                "settings": {"address_book": {"backup": "backup.local"}}
            }),
        ):
            self.assertEqual(
                host_address.resolve_template("http://{host}:8086"),
                "http://10.20.30.40:8086",
            )
            self.assertEqual(
                host_address.resolve_template("https://${backup}:8443"),
                "https://backup.local:8443",
            )

    def test_recursive_expansion_keeps_unknown_variables(self):
        with patch.object(host_address, "host_ip", return_value="server.local"):
            value = host_address.resolve_value({
                "url": "http://{host}:8123",
                "unknown": "{other}",
            })
        self.assertEqual(value["url"], "http://server.local:8123")
        self.assertEqual(value["unknown"], "{other}")

    def test_local_url_is_normalized_before_storage(self):
        with patch.object(host_address, "host_ip", return_value="10.20.30.40"):
            self.assertEqual(
                host_address.normalize_local_url("http://10.20.30.40:4000/path?q=1"),
                "http://{host}:4000/path?q=1",
            )
            self.assertEqual(
                host_address.normalize_local_url("https://external.example:8443"),
                "https://external.example:8443",
            )


if __name__ == "__main__":
    unittest.main()
