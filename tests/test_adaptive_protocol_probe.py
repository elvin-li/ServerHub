"""Adaptive URL detection must not pay a TLS timeout for non-web ports.

`guess_http_url` probed every detected port with plaintext HTTP and then fell
back to HTTPS.  Against a port that accepts TCP but speaks a non-HTTP protocol
that waits for more input -- Redis on 6380 was the live case -- the plaintext
attempt fails in ~12ms and the TLS handshake then runs to its full timeout,
because the peer never sends a ServerHello.  That measured 802ms for one port,
inside a status refresh that is supposed to complete in well under a second.

The old guard was a hardcoded port set, `_NON_HTTP_PORTS`.  It cannot fix this
class: it listed 6379 and the live Redis was on 6380.  The fix identifies what
the port actually speaks in one round trip, so a service is judged by its
protocol rather than by whether someone remembered its port number.

These tests bind real sockets on ephemeral ports, so they exercise the probe
end to end without depending on anything installed on the host.

Written as unittest.TestCase rather than bare pytest-style functions: the
project's gate is `python -m unittest discover`, which silently collects nothing
from a module of module-level `def test_*` functions.  These nine tests existed
but had never once run in the gate.
"""
from __future__ import annotations

import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import adaptive  # noqa: E402

# Generous enough to absorb CI jitter, far below the ~1.6s of timeouts the
# two-scheme urllib fallback costs when a port answers neither probe.
BUDGET_S = 0.75


class _FakeServer:
    """A raw TCP listener on an ephemeral port, driven by a reply callback."""

    def __init__(self, handler):
        self._handler = handler
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self.port = self._sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(
                target=self._handle, args=(conn,), daemon=True
            ).start()

    def _handle(self, conn):
        try:
            self._handler(conn)
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def close(self):
        self._stop.set()
        try:
            self._sock.close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def _redis_like(conn):
    """Accept, read whatever arrives, answer with a Redis protocol error.

    Redis parses the plaintext `GET / HTTP/1.1` as a command and replies with
    `-ERR`, then keeps the connection open waiting for the next command.  A TLS
    handshake against it therefore blocks until the client gives up.
    """
    conn.recv(4096)
    conn.sendall(b"-ERR wrong number of arguments for 'get' command\r\n")
    time.sleep(3.0)


def _silent(conn):
    """Accept the connection and never say anything."""
    time.sleep(3.0)


def _plain_400(conn):
    """Replies 400 to anything and does not speak TLS at all."""
    conn.recv(4096)
    conn.sendall(
        b"HTTP/1.1 400 Bad Request\r\nServer: test\r\nConnection: close\r\n\r\n"
    )


def _make_selfsigned(dirpath: Path) -> Path | None:
    """A throwaway cert for the TLS server below, or None if openssl is absent."""
    pem = dirpath / "test.pem"
    rc = subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(pem), "-out", str(pem), "-days", "1",
            "-subj", "/CN=localhost",
        ],
        capture_output=True,
    ).returncode
    return pem if rc == 0 and pem.exists() else None


class _NginxLikeTLSServer:
    """Answers plaintext with 400 and real TLS with 200 -- nginx's actual behaviour.

    nginx listening with `ssl` sniffs the first byte.  A plaintext `GET /` is a
    malformed TLS ClientHello, so it replies `HTTP/1.1 400 Bad Request` *in
    plaintext* and closes.  That means an `HTTP/` status line is not proof the
    port serves plaintext, which is what broke live port 8281.
    """

    def __init__(self, pem: Path):
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.load_cert_chain(str(pem))
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self.port = self._sock.getsockname()[1]
        self._stop = threading.Event()
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        body = (
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
            b"Connection: close\r\n\r\nok"
        )
        try:
            first = conn.recv(1, socket.MSG_PEEK)
            if first == b"\x16":  # TLS handshake record
                with self._ctx.wrap_socket(conn, server_side=True) as tls:
                    tls.recv(4096)
                    tls.sendall(body)
                return
            conn.recv(4096)
            conn.sendall(
                b"HTTP/1.1 400 Bad Request\r\nServer: test\r\n"
                b"Connection: close\r\n\r\n"
            )
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def close(self):
        self._stop.set()
        try:
            self._sock.close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class NonWebPortTests(unittest.TestCase):
    """A port that is not a web UI must yield nothing, and must do it quickly."""

    def test_redis_like_port_is_not_probed_as_https(self):
        """A port that answers with a non-HTTP, non-TLS reply yields no URL, fast."""
        with _FakeServer(_redis_like) as srv:
            t0 = time.perf_counter()
            url = adaptive.guess_http_url(srv.port)
            elapsed = time.perf_counter() - t0
        self.assertIsNone(url, f"non-web port produced a URL: {url!r}")
        self.assertLess(
            elapsed,
            BUDGET_S,
            f"probe took {elapsed * 1000:.1f}ms; a TLS handshake timeout is being "
            "paid for a port that does not speak TLS",
        )

    def test_silent_port_is_not_probed_as_https(self):
        """A port that accepts TCP but never replies yields no URL, fast."""
        with _FakeServer(_silent) as srv:
            t0 = time.perf_counter()
            url = adaptive.guess_http_url(srv.port)
            elapsed = time.perf_counter() - t0
        self.assertIsNone(url, f"silent port produced a URL: {url!r}")
        self.assertLess(
            elapsed,
            BUDGET_S,
            f"probe took {elapsed * 1000:.1f}ms; a silent port should not cost two "
            "protocol timeouts",
        )

    def test_closed_port_yields_no_url(self):
        """Nothing listening means no URL, without waiting on timeouts."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        t0 = time.perf_counter()
        url = adaptive.guess_http_url(port)
        elapsed = time.perf_counter() - t0
        self.assertIsNone(url)
        self.assertLess(elapsed, BUDGET_S, f"closed port took {elapsed * 1000:.1f}ms")

    def test_known_non_http_ports_short_circuit(self):
        """The existing port blocklist still applies before any socket work."""
        for port in (5432, 3306, 1883):
            with self.subTest(port=port):
                self.assertIsNone(adaptive.guess_http_url(port))

    def test_plain_400_without_tls_yields_no_url(self):
        """A 400 with no working TLS behind it is not a linkable web UI."""
        with _FakeServer(_plain_400) as srv:
            t0 = time.perf_counter()
            url = adaptive.guess_http_url(srv.port)
            elapsed = time.perf_counter() - t0
        self.assertIsNone(url, f"a bare 400 produced a URL: {url!r}")
        self.assertLess(elapsed, BUDGET_S, f"took {elapsed * 1000:.1f}ms")


class WebPortTests(unittest.TestCase):
    def test_real_http_server_is_still_detected(self):
        """The fast path must not regress: a plain HTTP server still yields a URL."""

        class _Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *a):
                pass

        httpd = HTTPServer(("127.0.0.1", 0), _Handler)
        port = httpd.server_address[1]
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        try:
            url = adaptive.guess_http_url(port)
        finally:
            httpd.shutdown()
            httpd.server_close()
        self.assertIsNotNone(url, "a live HTTP server was not detected as a web UI")
        self.assertTrue(url.startswith("http://"), url)
        self.assertTrue(url.endswith(f":{port}"), url)

    def test_https_port_answering_400_in_plaintext_is_detected_as_https(self):
        """The live 8281 regression: an HTTP/ status line can still mean TLS-only."""
        with tempfile.TemporaryDirectory() as tmp:
            pem = _make_selfsigned(Path(tmp))
            if pem is None:
                self.skipTest("openssl unavailable")
            with _NginxLikeTLSServer(pem) as srv:
                url = adaptive.guess_http_url(srv.port)
                port = srv.port
        self.assertIsNotNone(url, "an HTTPS-only nginx port produced no URL")
        self.assertTrue(
            url.startswith("https://"),
            f"got {url!r}; a plaintext 400 must not be trusted as a plaintext service",
        )
        self.assertTrue(url.endswith(f":{port}"), url)


class HeadClassifierTests(unittest.TestCase):
    def test_head_classifier_recognises_the_three_cases(self):
        """The wire-format classifier is what makes the decision falsifiable."""
        self.assertEqual(adaptive._classify_head(b"HTTP/1.1 200 OK"), "http")
        self.assertEqual(adaptive._classify_head(b"HTTP/1.0 401 Unauthorized"), "http")
        # TLS handshake record, then TLS alert record: both mean "speaks TLS".
        self.assertEqual(
            adaptive._classify_head(b"\x16\x03\x03\x00\x40\x02\x00\x00"), "tls"
        )
        self.assertEqual(adaptive._classify_head(b"\x15\x03\x01\x00\x02\x02\x28"), "tls")
        # Redis, and anything else that is neither.
        self.assertEqual(adaptive._classify_head(b"-ERR unknown command"), "")
        self.assertEqual(adaptive._classify_head(b""), "")
        self.assertEqual(adaptive._classify_head(b"SSH-2.0-OpenSSH_9.0"), "")


if __name__ == "__main__":
    unittest.main()
