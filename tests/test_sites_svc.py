"""Sites discovery: parsers, source tolerance, merge, probing and the API.

Every external command and socket is stubbed; nothing here reaches launchctl,
docker, lsof or the network, so the suite behaves the same on Linux CI.
"""
from __future__ import annotations

import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from hub import sites_svc


def _write(root: Path, rel: str, text: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


class _TmpTree(unittest.TestCase):
    def setUp(self):
        super().setUp()
        self._td = tempfile.TemporaryDirectory()
        self.root = Path(self._td.name)
        self.addCleanup(self._td.cleanup)


class NginxParserTests(_TmpTree):
    def test_server_blocks_through_include_globs(self):
        conf = _write(self.root, "nginx.conf", """
            events {}
            http {
                include mime.types;
                include servers/*.conf;  # site dir
                server { listen 8080; server_name _; root /srv/www; }
            }
        """)
        _write(self.root, "mime.types", "types { text/html html; }")
        _write(self.root, "servers/app.conf", """
            server {
                listen 443 ssl;
                listen [::]:443 ssl;
                server_name app.example.com www.app.example.com;
                location / { proxy_pass http://127.0.0.1:3000; }
            }
        """)
        sites = sites_svc.parse_nginx_conf(conf, reloadable=True)
        by_port = {(s["host"], s["port"]): s for s in sites}
        local = by_port[("localhost", 8080)]
        self.assertEqual(local["root"], "/srv/www")
        self.assertEqual(local["url"], "http://localhost:8080")
        self.assertIn("reload", local["actions"])
        app = by_port[("app.example.com", 443)]
        self.assertEqual(app["scheme"], "https")
        self.assertEqual(app["url"], "https://app.example.com")
        self.assertEqual(app["upstream"], "http://127.0.0.1:3000")
        self.assertTrue(app["config_path"].endswith("servers/app.conf"))
        # listen 443 + listen [::]:443 produce the same id and merge to one.
        merged = sites_svc.merge_sites({"nginx": sites})
        self.assertEqual(sum(1 for s in merged if s["host"] == "app.example.com"), 1)

    def test_conf_d_scanned_without_include_line(self):
        conf = _write(self.root, "nginx.conf", "http { }")
        _write(self.root, "conf.d/x.conf", "server { listen 9000; return 301 https://x; }")
        sites = sites_svc.parse_nginx_conf(conf)
        self.assertEqual([s["port"] for s in sites], [9000])
        self.assertTrue(sites[0]["detail"].startswith("redirect: 301"))

    def test_comments_and_quotes(self):
        conf = _write(self.root, "nginx.conf",
                      "http { server { listen 81; # listen 99;\n"
                      " server_name \"a.example.org\"; root '/srv/#x'; } }")
        (site,) = sites_svc.parse_nginx_conf(conf)
        self.assertEqual(site["port"], 81)
        self.assertEqual(site["host"], "a.example.org")
        self.assertEqual(site["root"], "/srv/#x")

    def test_missing_conf_and_include_loop(self):
        self.assertEqual(sites_svc.parse_nginx_conf(self.root / "nope.conf"), [])
        conf = _write(self.root, "nginx.conf", "http { include nginx.conf; include a.conf; }")
        _write(self.root, "a.conf", "include a.conf; server { listen 82; }")
        self.assertEqual([s["port"] for s in sites_svc.parse_nginx_conf(conf)], [82])

    def test_unix_listen_skipped_and_ip_listen_probed_on_ip(self):
        conf = _write(self.root, "nginx.conf",
                      "http { server { listen unix:/tmp/x.sock; listen 10.0.0.5:8088; } }")
        (site,) = sites_svc.parse_nginx_conf(conf)
        self.assertEqual(site["_probe"][0], "10.0.0.5")


class CaddyParserTests(_TmpTree):
    def test_blocks_snippets_and_globals(self):
        path = _write(self.root, "Caddyfile", """
            { admin off }
            (common) { encode gzip }
            example.com, www.example.com {
                reverse_proxy localhost:8000
            }
            :8081 {
                root * /srv/static
                file_server
            }
            http://plain.test {
                respond "hi"
            }
        """)
        sites = {s["server_names"][0]: s for s in sites_svc.parse_caddyfile(path)}
        self.assertEqual(set(sites), {"example.com", "www.example.com", ":8081", "http://plain.test"})
        self.assertEqual(sites["example.com"]["url"], "https://example.com")
        self.assertEqual(sites["example.com"]["upstream"], "localhost:8000")
        self.assertEqual(sites[":8081"]["url"], "http://localhost:8081")
        self.assertEqual(sites[":8081"]["root"], "/srv/static")
        self.assertEqual(sites["http://plain.test"]["port"], 80)

    def test_single_site_without_braces(self):
        path = _write(self.root, "Caddyfile", "localhost:2015\nfile_server\n")
        (site,) = sites_svc.parse_caddyfile(path)
        self.assertEqual((site["host"], site["port"], site["scheme"]), ("localhost", 2015, "https"))


class ApacheParserTests(_TmpTree):
    def test_vhosts_via_include(self):
        conf = _write(self.root, "httpd/httpd.conf",
                      f"ServerRoot \"{self.root}\"\nListen 8080\nInclude httpd/extra/*.conf\n")
        _write(self.root, "httpd/extra/v.conf", """
            <VirtualHost *:8080>
                ServerName shop.example.net
                ServerAlias alt.example.net
                DocumentRoot "/srv/shop"
            </VirtualHost>
            <VirtualHost *:8443>
                SSLEngine on
                ProxyPass / http://127.0.0.1:5000/
            </VirtualHost>
        """)
        sites = sites_svc.parse_httpd_conf(conf)
        by_port = {s["port"]: s for s in sites}
        self.assertEqual(by_port[8080]["host"], "shop.example.net")
        self.assertEqual(by_port[8080]["server_names"], ["shop.example.net", "alt.example.net"])
        self.assertEqual(by_port[8080]["root"], "/srv/shop")
        self.assertEqual(by_port[8443]["scheme"], "https")
        self.assertEqual(by_port[8443]["upstream"], "http://127.0.0.1:5000/")
        self.assertTrue(all(s["_optional"] for s in sites))

    def test_main_server_without_vhosts(self):
        conf = _write(self.root, "httpd.conf",
                      "Listen 8090\nServerName www.example.com:8090\nDocumentRoot \"/Library/WebServer\"\n")
        (site,) = sites_svc.parse_httpd_conf(conf)
        self.assertEqual((site["host"], site["port"], site["root"]),
                         ("www.example.com", 8090, "/Library/WebServer"))


class CloudflaredParserTests(_TmpTree):
    def test_ingress_rules(self):
        path = _write(self.root, "config.yml", """
tunnel: abc
ingress:
  - hostname: app.example.com
    path: ^/api/.*$
    service: http://localhost:8080
  - hostname: ssh.example.com
    service: ssh://localhost:22
  - hostname: secure.example.com
    service: https://192.168.1.5:8443
  - service: http_status:404
""")
        sites = {s["host"]: s for s in sites_svc.parse_cloudflared_config(path)}
        self.assertEqual(set(sites), {"app.example.com", "ssh.example.com", "secure.example.com"})
        app = sites["app.example.com"]
        self.assertEqual(app["url"], "https://app.example.com")
        self.assertEqual(app["_probe"], ("127.0.0.1", 8080, False, None))
        self.assertEqual(sites["secure.example.com"]["_probe"], ("192.168.1.5", 8443, True, None))
        self.assertEqual(sites["ssh.example.com"]["_probe"][1], 22)

    def test_bad_yaml_and_missing(self):
        path = _write(self.root, "config.yml", "ingress: [unclosed")
        self.assertEqual(sites_svc.parse_cloudflared_config(path), [])
        self.assertEqual(sites_svc.parse_cloudflared_config(self.root / "none.yml"), [])
        path = _write(self.root, "c2.yml", "ingress: notalist")
        self.assertEqual(sites_svc.parse_cloudflared_config(path), [])


class DockerAndLaunchdTests(unittest.TestCase):
    def test_parse_docker_ps(self):
        out = ("web\t0.0.0.0:8080->80/tcp, [::]:8080->80/tcp\tnginx:latest\n"
               "multi\t127.0.0.1:9000->9000/tcp, 0.0.0.0:9443->443/tcp\tminio\n"
               "noports\t\tbusybox\n"
               "udp\t0.0.0.0:53->53/udp\tdns\n")
        sites = sites_svc.parse_docker_ps(out)
        self.assertEqual([(s["name"], s["port"], s["scheme"]) for s in sites],
                         [("web", 8080, "http"), ("multi", 9000, "http"), ("multi:9443", 9443, "https")])
        self.assertTrue(all(s["_http_only"] for s in sites))

    def test_docker_absent_or_failing(self):
        with mock.patch.object(sites_svc, "DOCKER", "/nonexistent/docker"):
            self.assertEqual(sites_svc._docker_source(), [])
        with mock.patch.object(sites_svc.os.path, "isfile", return_value=True), \
                mock.patch.object(sites_svc, "sh", return_value=(1, "", "daemon down")) as sh:
            self.assertEqual(sites_svc._docker_source(), [])
            self.assertLessEqual(sh.call_args.kwargs["timeout"], 5)

    def test_launchd_rows_from_status_groups(self):
        status = {"groups": [
            {"group": "Apps", "services": [
                {"kind": "launchd", "id": "local.web", "name": "Web", "url": "http://192.168.1.2:8125", "port": None},
                {"kind": "launchd", "id": "local.daemon", "name": "Daemon", "port": None},
                {"kind": "docker", "id": "c1", "name": "c1", "url": "http://x:1", "port": 1},
                {"kind": "launchd", "id": "local.sig", "name": "Sig", "port": 7000, "signature": {"http": True}},
            ]},
            "junk",
        ]}
        with mock.patch("hub.status.full_status", return_value=status):
            sites = sites_svc._launchd_source()
        self.assertEqual([(s["name"], s["port"]) for s in sites], [("Web", 8125), ("Sig", 7000)])
        self.assertEqual(sites[0]["url"], "http://192.168.1.2:8125")


class ProbeTests(unittest.TestCase):
    def _server(self, reply: bytes | None):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(4)
        port = srv.getsockname()[1]

        def serve():
            try:
                conn, _ = srv.accept()
                conn.recv(256)
                if reply is not None:
                    conn.sendall(reply)
                else:
                    time.sleep(1.2)
                conn.close()
            except OSError:
                pass

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        self.addCleanup(srv.close)
        return port

    def test_http_ok_5xx_tcp_only_and_refused(self):
        port = self._server(b"HTTP/1.1 302 Found\r\n\r\n")
        self.assertEqual(sites_svc._http_head("127.0.0.1", port, False, None), ("ok", "HTTP 302"))
        port = self._server(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        self.assertEqual(sites_svc._http_head("127.0.0.1", port, False, None)[0], "warn")
        port = self._server(None)
        self.assertEqual(sites_svc._http_head("127.0.0.1", port, False, None, timeout=0.3),
                         ("warn", "TCP open, no HTTP answer"))
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        free = s.getsockname()[1]
        s.close()
        self.assertEqual(sites_svc._http_head("127.0.0.1", free, False, None)[0], "down")


def _site(source, host, port, **kw):
    return sites_svc._make_site(source, name=f"{source}-{port}", host=host, port=port, **kw)


class CollectTests(unittest.TestCase):
    def test_merge_priority_and_also_seen(self):
        merged = sites_svc.merge_sites({
            "docker": [_site("docker", "localhost", 8080)],
            "nginx": [_site("nginx", "127.0.0.1", 8080), _site("nginx", "a.example.com", 8080)],
            "launchd": [_site("launchd", "localhost", 8080)],
        })
        self.assertEqual([(s["source"], s["host"]) for s in merged],
                         [("nginx", "127.0.0.1"), ("nginx", "a.example.com")])
        self.assertEqual(merged[0]["also_seen_in"], ["launchd", "docker"])
        self.assertEqual(merged[1]["also_seen_in"], [])

    def _collect(self, sources, probe=None, speaks=None):
        probe = probe or (lambda host, port, tls, hh, timeout=0: ("ok", "HTTP 200"))
        with mock.patch.object(sites_svc, "_sources", return_value=sources), \
                mock.patch.object(sites_svc, "_http_head", side_effect=probe):
            if speaks is not None:
                with mock.patch.object(sites_svc, "_speaks_http", side_effect=speaks):
                    return sites_svc._collect()
            return sites_svc._collect()

    def test_source_failures_and_timeouts_are_notes_not_errors(self):
        def boom():
            raise RuntimeError("nope")

        def slow():
            time.sleep(1.0)
            return [_site("caddy", "localhost", 1)]

        with mock.patch.object(sites_svc, "_SOURCE_DEADLINE", 0.3):
            t0 = time.monotonic()
            out = self._collect({"nginx": lambda: [_site("nginx", "localhost", 80)],
                                 "caddy": slow, "apache": boom, "listener": lambda: []})
            self.assertLess(time.monotonic() - t0, 0.9)
        notes = {n["id"]: n for n in out["sources"]}
        self.assertEqual(notes["caddy"]["error"], "timeout")
        self.assertEqual(notes["apache"]["error"], "RuntimeError")
        self.assertTrue(notes["nginx"]["ok"])
        self.assertEqual(out["count"], 1)
        self.assertNotIn("_probe", out["sites"][0])

    def test_filters_optional_down_and_non_http_containers(self):
        def probe(host, port, tls, hh, timeout=0):
            return {1: ("down", "connection refused"), 2: ("warn", "TCP open, no HTTP answer"),
                    3: ("ok", "HTTP 200"), 4: ("down", "connection refused")}[port]
        out = self._collect({
            "apache": lambda: [_site("apache", "localhost", 1, optional=True)],
            "docker": lambda: [_site("docker", "localhost", 2, http_only=True),
                               _site("docker", "localhost", 3, http_only=True),
                               _site("docker", "localhost", 4, http_only=True)],
            "listener": lambda: [],
        }, probe=probe)
        self.assertEqual([(s["port"], s["status"]) for s in out["sites"]], [(3, "ok"), (4, "down")])

    def test_listeners_skip_covered_ports_and_non_http(self):
        cands = [{"port": p, "proc": "node", "probe_host": "127.0.0.1"} for p in (80, 3000, 5000, 6000)]
        out = self._collect({
            "nginx": lambda: [_site("nginx", "localhost", 80, upstream="http://127.0.0.1:3000")],
            "listener": lambda: cands,
        }, speaks=lambda c: ("ok", "HTTP 200") if c["port"] == 5000 else None)
        self.assertEqual([(s["source"], s["port"]) for s in out["sites"]], [("nginx", 80), ("listener", 5000)])
        self.assertEqual({n["id"]: n["count"] for n in out["sources"]}["listener"], 1)

    def test_real_sources_tolerate_absent_tools(self):
        """Every built-in source returns a list with no tools/configs present."""
        empty = Path(tempfile.mkdtemp())
        with mock.patch.object(sites_svc, "HOMEBREW_PREFIXES", (str(empty),)), \
                mock.patch.object(sites_svc.nginx_svc, "NGINX_CONF", empty / "nginx.conf"), \
                mock.patch.object(sites_svc, "_httpd_confs", return_value=[empty / "httpd.conf"]), \
                mock.patch.object(sites_svc, "_caddyfiles", return_value=[empty / "Caddyfile"]), \
                mock.patch.object(sites_svc, "_cloudflared_configs", return_value=[empty / "c.yml"]), \
                mock.patch.object(sites_svc, "DOCKER", str(empty / "docker")), \
                mock.patch("hub.status.full_status", return_value={}), \
                mock.patch("hub.adaptive.lsof_listen_snapshot", return_value=[]):
            for name, fn in sites_svc._sources().items():
                self.assertEqual(fn(), [], name)

    def test_list_sites_caches_and_force_rescans(self):
        calls = []

        def fake():
            calls.append(1)
            return {"sites": [], "sources": [], "count": len(calls), "generated_at": 0}

        sites_svc._cached.invalidate()
        self.addCleanup(sites_svc._cached.invalidate)
        with mock.patch.object(sites_svc, "_collect", side_effect=fake):
            self.assertEqual(sites_svc.list_sites()["count"], 1)
            self.assertEqual(sites_svc.list_sites()["count"], 1)
            self.assertEqual(sites_svc.list_sites(force=True)["count"], 2)
        sites_svc._cached.invalidate()
        with mock.patch.object(sites_svc, "_collect", side_effect=RuntimeError("x")):
            self.assertEqual(sites_svc.list_sites()["error"], "discovery failed")


class ApiTests(_TmpTree):
    @classmethod
    def setUpClass(cls):
        from fastapi import FastAPI
        from hub.routers import sites_api
        app = FastAPI()
        app.include_router(sites_api.router)
        cls.client = TestClient(app, raise_server_exceptions=False)

    def test_list_and_config(self):
        conf = _write(self.root, "x.conf", "server { listen 80; }")
        site = _site("nginx", "localhost", 80, config_path=str(conf), extra_actions=("view_config",))
        site.pop("_probe")
        bare = _site("docker", "localhost", 81)
        bare.pop("_probe")
        payload = {"sites": [site, bare], "sources": [], "count": 2, "generated_at": 0}
        with mock.patch.object(sites_svc, "list_sites", return_value=payload) as ls:
            r = self.client.get("/api/sites?force=true")
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.json()["count"], 2)
            ls.assert_called_with(force=True)
            r = self.client.get(f"/api/sites/{site['id']}/config")
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.json()["content"], "server { listen 80; }")
            # A site without view_config, or an unknown id, never reads a file.
            self.assertEqual(self.client.get(f"/api/sites/{bare['id']}/config").status_code, 404)
            self.assertEqual(self.client.get("/api/sites/..%2f..%2fetc%2fpasswd/config").status_code, 404)
            conf.unlink()
            self.assertEqual(self.client.get(f"/api/sites/{site['id']}/config").status_code, 404)

    def test_routes_require_auth_in_real_app(self):
        from hub.app_factory import create_app
        client = TestClient(create_app(), raise_server_exceptions=False)
        with mock.patch.object(sites_svc, "list_sites", return_value={"sites": []}):
            self.assertEqual(client.get("/api/sites").status_code, 401)


if __name__ == "__main__":
    unittest.main()
