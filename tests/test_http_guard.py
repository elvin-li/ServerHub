"""Local-origin and no-redirect guards used by Ollama, Immich, PhotosHub, notify."""
from __future__ import annotations

import unittest

from hub.http_guard import (
    NoRedirect,
    RedirectRefused,
    is_allowed_webhook_url,
    is_local_http_origin,
    local_http_origin,
)


class LocalOriginTests(unittest.TestCase):
    def test_loopback_and_lan_are_allowed(self):
        for url in (
            "http://127.0.0.1:11434",
            "http://[::1]:11434",
            "http://[0:0:0:0:0:0:0:1]:2283",
            "http://192.168.1.206:2283",
            "http://10.0.0.2:11434",
            "http://immich:2283",
            "http://nas.local:2283",
        ):
            with self.subTest(url=url):
                self.assertEqual(local_http_origin(url), url)

    def test_public_and_metadata_are_rejected(self):
        for url in (
            "https://ollama.example.com",
            "http://8.8.8.8:11434",
            "http://[2001:4860:4860::8888]:11434",
            "http://169.254.169.254/latest/meta-data",
            "http://[fd00:ec2::254]/",
            "http://metadata/",
            "file:///etc/passwd",
            "javascript:alert(1)",
            # Decimal / hex IPv4 used to pass as single-label hostnames.
            "http://2852039166/",          # 169.254.169.254
            "http://134744072/",           # 8.8.8.8
            "http://0x08080808/",          # 8.8.8.8
            "http://[::ffff:169.254.169.254]/",
            "http://[::ffff:8.8.8.8]/",
        ):
            with self.subTest(url=url):
                self.assertFalse(is_local_http_origin(url))

    def test_encoded_loopback_and_lan_ips_are_still_local(self):
        for url in (
            "http://2130706433:11434",           # 127.0.0.1
            "http://0x7f000001:11434",           # 127.0.0.1
            "http://[::ffff:127.0.0.1]:11434",
            "http://[::ffff:192.168.1.1]:11434",
        ):
            with self.subTest(url=url):
                self.assertEqual(local_http_origin(url), url)

    def test_trailing_slash_is_stripped(self):
        self.assertEqual(
            local_http_origin("http://127.0.0.1:11434/"),
            "http://127.0.0.1:11434",
        )


class WebhookUrlTests(unittest.TestCase):
    """Notify webhooks may be public; metadata and link-local must not."""

    def test_public_and_lan_webhooks_are_allowed(self):
        for url in (
            "https://hooks.slack.com/services/x",
            "https://discord.com/api/webhooks/1/x",
            "https://ntfy.sh/topic",
            "http://ha.lan:8123/api/webhook/x",
            "http://192.168.1.2:8123/api/webhook/x",
            "http://127.0.0.1:8123/api/webhook/x",
        ):
            with self.subTest(url=url):
                self.assertTrue(is_allowed_webhook_url(url))

    def test_metadata_and_link_local_are_blocked(self):
        for url in (
            "http://169.254.169.254/latest/meta-data",
            "http://[fd00:ec2::254]/",
            "http://metadata/",
            "http://metadata.google.internal/",
            "http://169.254.1.1/",
            "http://[fe80::1]/",
            "http://2852039166/",          # 169.254.169.254
            "http://0xa9fea9fe/",          # 169.254.169.254
            "http://[::ffff:169.254.169.254]/",
            "file:///etc/passwd",
            "gopher://x",
        ):
            with self.subTest(url=url):
                self.assertFalse(is_allowed_webhook_url(url))


class NoRedirectTests(unittest.TestCase):
    def test_any_redirect_is_refused(self):
        handler = NoRedirect()
        with self.assertRaises(RedirectRefused):
            handler.redirect_request(
                None, None, 302, "Found", {}, "http://169.254.169.254/",
            )


if __name__ == "__main__":
    unittest.main()
