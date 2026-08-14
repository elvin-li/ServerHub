import unittest
from unittest.mock import patch

from hub import host_address


class HostAddressTests(unittest.TestCase):
    def tearDown(self):
        host_address._detect_cache.update(t=0.0, value=None)

    def test_auto_host_uses_route_detection(self):
        with (
            patch.object(host_address, "configured_host", return_value="auto"),
            patch.object(host_address, "detect_lan_ip", return_value="192.0.2.40"),
        ):
            self.assertEqual(host_address.host_ip(), "192.0.2.40")

    def test_explicit_host_override_is_preserved(self):
        with patch.object(host_address, "configured_host", return_value="server.local"):
            self.assertEqual(host_address.host_ip(), "server.local")

    def test_url_template_expansion(self):
        with (
            patch.object(host_address, "host_ip", return_value="192.0.2.40"),
            patch("hub.config.cfg", return_value={
                "settings": {"address_book": {"backup": "backup.local"}}
            }),
        ):
            self.assertEqual(
                host_address.resolve_template("http://{host}:8086"),
                "http://192.0.2.40:8086",
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

    def test_loopback_bind_is_not_an_advertised_host(self):
        with (
            patch.dict("os.environ", {
                "SERVERHUB_HOST": "127.0.0.1",
                "SERVERHUB_HOST_IP": "",
            }, clear=False),
            patch("hub.config.cfg", return_value={"settings": {"host_ip": "auto"}}),
        ):
            self.assertEqual(host_address.configured_host(), "auto")

    def test_unspecified_bind_is_not_an_advertised_host(self):
        with (
            patch.dict("os.environ", {
                "SERVERHUB_HOST": "0.0.0.0",
                "SERVERHUB_HOST_IP": "",
            }, clear=False),
            patch("hub.config.cfg", return_value={"settings": {"host_ip": "auto"}}),
        ):
            self.assertEqual(host_address.configured_host(), "auto")

    def test_explicit_lan_bind_is_still_advertised(self):
        with patch.dict("os.environ", {
            "SERVERHUB_HOST": "192.0.2.40",
            "SERVERHUB_HOST_IP": "",
        }, clear=False):
            self.assertEqual(host_address.configured_host(), "192.0.2.40")

    def test_local_url_is_normalized_before_storage(self):
        with patch.object(host_address, "host_ip", return_value="192.0.2.40"):
            self.assertEqual(
                host_address.normalize_local_url("http://192.0.2.40:4000/path?q=1"),
                "http://{host}:4000/path?q=1",
            )
            self.assertEqual(
                host_address.normalize_local_url("https://external.example:8443"),
                "https://external.example:8443",
            )


if __name__ == "__main__":
    unittest.main()
