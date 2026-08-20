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

    def test_list_address_book_does_not_500(self):
        with (
            patch.object(host_address, "host_ip", return_value="192.0.2.40"),
            patch("hub.config.cfg", return_value={
                "settings": {"address_book": ["oops"]}
            }),
        ):
            self.assertEqual(
                host_address.resolve_template("http://{host}:8086"),
                "http://192.0.2.40:8086",
            )

    def test_list_extra_does_not_500(self):
        with patch.object(host_address, "host_ip", return_value="192.0.2.40"):
            self.assertEqual(
                host_address.resolve_template("http://{host}:8086", extra=["oops"]),
                "http://192.0.2.40:8086",
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

    def test_normalize_local_url_leftovers_do_not_500(self):
        """Leftover ``\\ud800`` / bytes / gethostname OSError used to 500 writes."""
        import json

        def starlette(payload):
            json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")

        with patch.object(host_address, "host_ip", return_value="192.0.2.40"):
            cleaned = host_address.normalize_local_url("http://example.com/\ud800")
            starlette(cleaned)
            self.assertNotIn("\ud800", cleaned)
            self.assertEqual(
                host_address.normalize_local_url(b"http://192.0.2.40:4000/path"),
                "http://{host}:4000/path",
            )
            with patch(
                "hub.host_address.socket.gethostname", side_effect=OSError("boom")
            ):
                self.assertEqual(
                    host_address.normalize_local_url("http://192.0.2.40:4000/"),
                    "http://{host}:4000/",
                )

    def test_int_none_bytes_route_payloads_do_not_500(self):
        for payload in (None, 123, b"gateway: 1.1.1.1\ninterface: en0\n"):
            host_address.invalidate_routing()
            with patch.object(host_address, "sh", return_value=(0, payload, "")):
                route = host_address.default_route()
            self.assertIsInstance(route.get("raw"), dict)
        host_address.invalidate_routing()
        with patch.object(
            host_address, "sh",
            return_value=(0, b"gateway: 1.1.1.1\ninterface: en0\n", ""),
        ):
            route = host_address.default_route()
        self.assertEqual(route["interface"], "en0")
        self.assertEqual(route["gateway"], "1.1.1.1")

    def test_int_none_bytes_ifaddr_do_not_500(self):
        for payload in (None, 123, b"192.0.2.40"):
            host_address.invalidate_routing()
            with patch.object(host_address, "sh", return_value=(0, payload, "")):
                addr = host_address.interface_address("en0")
            self.assertIsInstance(addr, str)
        host_address.invalidate_routing()
        with patch.object(host_address, "sh", return_value=(0, b"192.0.2.40", "")):
            self.assertEqual(host_address.interface_address("en0"), "192.0.2.40")


if __name__ == "__main__":
    unittest.main()
