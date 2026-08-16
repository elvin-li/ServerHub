"""Local-origin and no-redirect guards used by Ollama, Immich, PhotosHub, notify."""
from __future__ import annotations

import unittest

from hub.http_guard import (
    NoRedirect,
    RedirectRefused,
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
        ):
            with self.subTest(url=url):
                self.assertFalse(is_local_http_origin(url))

    def test_trailing_slash_is_stripped(self):
        self.assertEqual(
            local_http_origin("http://127.0.0.1:11434/"),
            "http://127.0.0.1:11434",
        )


class NoRedirectTests(unittest.TestCase):
    def test_any_redirect_is_refused(self):
        handler = NoRedirect()
        with self.assertRaises(RedirectRefused):
            handler.redirect_request(
                None, None, 302, "Found", {}, "http://169.254.169.254/",
            )


if __name__ == "__main__":
    unittest.main()
