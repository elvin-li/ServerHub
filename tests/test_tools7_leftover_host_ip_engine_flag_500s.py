"""Tools leftover sweep #7: raw host_ip echoes, the engine_up flag, and the
self-``__str__`` encode bomb.

A fresh hunt over the mounted Tools routes (create_app + TestClient,
raise_server_exceptions=False) after the tools6 DNS-echo / ps-table wave
found three live leftover classes:

* ``diagnostics()`` and ``about_info()`` echoed ``host_ip()`` raw while every
  sibling field goes through ``_as_text``.  ``host_address`` sanitizes its
  own answer today, but the boundary trusted that cross-module contract
  wholesale: a leftover lone-surrogate address 500'd the UTF-8 encode and a
  >4300-digit int ValueError'd Starlette's json.dumps (CPython's int->str
  digit cap) on GET /api/system/diagnostics and GET /api/tools/about.

* the three docker views read ``engine_up()`` through a bare ``if not`` —
  a cross-module ``__bool__`` bomb riding the answer raised out of the flag
  read and 500'd GET /api/docker/df, GET /api/docker/sizes and
  POST /api/tools/docker/prune; the forced ``engine_up(force=True)`` probe
  inside ``_docker_gone`` blew the same way on the failure path.
  ``_safe_flag`` (the tools5 guard, already applied to the disk-row flags)
  degrades an unanswerable flag to engine-down — df/sizes answer their
  engine-down shapes and prune the coded ``container.engine_down``.
  diagnostics' probe_docker was already guarded and stays pinned.

* ``_as_text``'s final re-encode dispatched into the value's *bound*
  ``encode``: a ``__str__`` override that returns a str subclass whose
  ``encode`` bombs degraded a perfectly readable cross-module answer — a
  DNS ip, a whole ps row — to "" (silent loss, the row vanished).  Unbound
  ``str.encode`` (the storage7 rule) reads the real char storage, so the
  text now survives the bomb.

Stays-immune pins ride along for the vectors this sweep re-tested and found
already dead: bytes / plain-subclass host_ip answers (FastAPI's
jsonable_encoder), the engine_up bomb on diagnostics (probe_docker's guard),
GitHub release payloads carrying huge-float / surrogate-escape fields
through the parse_int_capped reader, a huge-digit lsof port row (dropped,
siblings survive), and a surrogate syslog level echo (replaced at the query
decode, never a raw surrogate).
"""
from __future__ import annotations

import json
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from hub import tools_svc
from hub.app_factory import create_app
from hub.auth import require_auth

#: Built arithmetically: int("9" * 5000) itself trips the digit cap.
_HUGE_INT = 10 ** 5000

_APP = None


def _client() -> TestClient:
    global _APP
    if _APP is None:
        _APP = create_app()
        _APP.dependency_overrides[require_auth] = lambda: None
    return TestClient(_APP, raise_server_exceptions=False)


def _starlette(payload) -> None:
    """What Starlette's JSONResponse does: ensure_ascii=False then UTF-8."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class _BoolBomb:
    def __bool__(self):
        raise RuntimeError("bool bomb")


class _SelfStr(str):
    """``__str__`` returns itself; the bound ``encode`` bombs."""

    def __str__(self):
        return self

    def encode(self, *args, **kwargs):
        raise RuntimeError("encode bomb")


_NO_SH = mock.patch.object(tools_svc, "sh", lambda *a, **k: (0, "", ""))


class HostIpEchoLeftoverTests(unittest.TestCase):
    """``host_ip()`` echoed raw used to 500 diagnostics and about."""

    def _get(self, path: str, ip):
        with (
            mock.patch.object(tools_svc, "host_ip", lambda: ip),
            _NO_SH,
        ):
            response = _client().get(path)
        self.assertEqual(response.status_code, 200, response.text[:300])
        body = response.json()
        _starlette(body)
        return body

    def test_huge_int_host_ip_degrades_on_diagnostics(self):
        body = self._get("/api/system/diagnostics", _HUGE_INT)
        self.assertEqual(body["host_ip"], "")

    def test_surrogate_host_ip_is_scrubbed_on_diagnostics(self):
        body = self._get("/api/system/diagnostics", "1.2.\ud800.4")
        self.assertEqual(body["host_ip"], "1.2.?.4")

    def test_huge_int_host_ip_degrades_on_about(self):
        body = self._get("/api/tools/about", _HUGE_INT)
        self.assertEqual(body["host_ip"], "")

    def test_surrogate_host_ip_is_scrubbed_on_about(self):
        body = self._get("/api/tools/about", "1.2.\ud800.4")
        self.assertEqual(body["host_ip"], "1.2.?.4")

    def test_selfstr_encode_bomb_host_ip_keeps_its_text(self):
        """The unbound str.encode salvage: the address survives the bomb."""
        for path in ("/api/system/diagnostics", "/api/tools/about"):
            body = self._get(path, _SelfStr("1.2.3.4"))
            self.assertEqual(body["host_ip"], "1.2.3.4", path)

    def test_bytes_host_ip_stays_immune(self):
        body = self._get("/api/tools/about", b"1.2.3.4")
        self.assertEqual(body["host_ip"], "1.2.3.4")


class EngineFlagBombTests(unittest.TestCase):
    """A ``__bool__`` bomb on ``engine_up()`` used to 500 the docker views."""

    def setUp(self):
        tools_svc.docker_disk_usage.invalidate()
        self.addCleanup(tools_svc.docker_disk_usage.invalidate)

    def test_df_answers_the_engine_down_shape(self):
        with mock.patch.object(tools_svc, "engine_up",
                               lambda force=False: _BoolBomb()):
            response = _client().get("/api/docker/df")
        self.assertEqual(response.status_code, 200, response.text[:300])
        body = response.json()
        _starlette(body)
        self.assertEqual(body, {"engine_up": False, "raw": "", "lines": []})

    def test_sizes_answer_empty(self):
        with mock.patch.object(tools_svc, "engine_up",
                               lambda force=False: _BoolBomb()):
            response = _client().get("/api/docker/sizes")
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertEqual(response.json(), {"containers": []})

    def test_prune_answers_the_coded_engine_down(self):
        with mock.patch.object(tools_svc, "engine_up",
                               lambda force=False: _BoolBomb()):
            response = _client().post(
                "/api/tools/docker/prune",
                json={"what": "dangling", "confirm": True},
            )
        self.assertEqual(response.status_code, 200, response.text[:300])
        body = response.json()
        _starlette(body)
        self.assertFalse(body["ok"])
        self.assertEqual(body["code"], "container.engine_down")

    def test_forced_probe_bomb_keeps_the_engine_down_classification(self):
        """``_docker_gone``'s failure-path probe: bomb counts as down."""

        def two_faced(force=False):
            if force:
                return _BoolBomb()
            return True

        daemon_gone = mock.patch.object(
            tools_svc, "docker",
            lambda *a, **k: (1, "", "Cannot connect to the Docker daemon"),
        )
        with mock.patch.object(tools_svc, "engine_up", two_faced), daemon_gone:
            df = _client().get("/api/docker/df")
            tools_svc.docker_disk_usage.invalidate()
            prune = _client().post(
                "/api/tools/docker/prune",
                json={"what": "dangling", "confirm": True},
            )
        self.assertEqual(df.status_code, 200, df.text[:300])
        self.assertEqual(df.json(), {"engine_up": False, "raw": "", "lines": []})
        self.assertEqual(prune.status_code, 200, prune.text[:300])
        body = prune.json()
        _starlette(body)
        self.assertEqual(body["code"], "container.engine_down")
        self.assertEqual(body["what"], "dangling")
        self.assertIsNone(body["df"])

    def test_diagnostics_probe_docker_stays_guarded(self):
        with (
            mock.patch.object(tools_svc, "engine_up",
                              lambda force=False: _BoolBomb()),
            _NO_SH,
        ):
            response = _client().get("/api/system/diagnostics")
        self.assertEqual(response.status_code, 200, response.text[:300])
        body = response.json()
        _starlette(body)
        self.assertFalse(body["orbstack"])
        self.assertEqual(body["docker_df"], {})


class SelfStrEncodeBombSalvageTests(unittest.TestCase):
    """The unbound str.encode salvage on the routes that used to lose rows."""

    def test_as_text_reads_through_the_base_storage(self):
        self.assertEqual(tools_svc._as_text(_SelfStr("abc")), "abc")
        self.assertEqual(tools_svc._as_text(_SelfStr("a\ud800b")), "a?b")

    def test_dns_ip_wearing_the_bomb_keeps_its_row(self):
        def gai(name, port):
            return [(2, 1, 6, "", (_SelfStr("1.2.3.4"), 0))]

        with (
            mock.patch.object(tools_svc.socket, "getaddrinfo", gai),
            mock.patch.object(tools_svc, "sh", lambda *a, **k: (1, "", "")),
        ):
            response = _client().post(
                "/api/tools/net/dns", json={"name": "example.com"},
            )
        self.assertEqual(response.status_code, 200, response.text[:300])
        body = response.json()
        _starlette(body)
        self.assertEqual(
            body["results"], [{"ip": "1.2.3.4", "family": "IPv4"}],
        )

    def test_ps_row_wearing_the_bomb_still_parses(self):
        tools_svc._proc_cache.update(t=0.0, v=None, limit=0)
        self.addCleanup(tools_svc._proc_cache.update, t=0.0, v=None, limit=0)
        row = "u 1 1.0 2.0 10 20 tt s 3 0:00 cmd arg"
        with mock.patch.object(
            tools_svc, "ps_lines", lambda: ["HDR", _SelfStr(row)],
        ):
            response = _client().get("/api/system/processes")
        self.assertEqual(response.status_code, 200, response.text[:300])
        body = response.json()
        _starlette(body)
        self.assertEqual(body["processes"], [{
            "user": "u", "pid": "1", "cpu": 1.0, "mem": 2.0, "vsz": "10",
            "rss": "20", "stat": "s", "time": "0:00", "command": "cmd arg",
        }])


class _FakeResp:
    def __init__(self, body: bytes):
        self._body = body

    def read(self, n=-1):
        return self._body

    def close(self):
        pass


class GithubPayloadStaysImmuneTests(unittest.TestCase):
    """Huge-float / surrogate-escape release fields stay a rendered card."""

    def setUp(self):
        tools_svc._github_cache.update(t=0.0, v=None)
        self.addCleanup(tools_svc._github_cache.update, t=0.0, v=None)

    def _github(self, body: bytes) -> dict:
        class Opener:
            def open(self, req, timeout=None):
                return _FakeResp(body)

        with mock.patch("hub.http_guard.no_redirect_opener", lambda: Opener()):
            snap = tools_svc._github_latest(force=True)
        _starlette(snap)
        return snap

    def test_huge_float_published_at_renders_as_text(self):
        snap = self._github(
            b'{"tag_name": "v9.9.9", "published_at": 1e999, "body": "x"}',
        )
        self.assertTrue(snap["ok"])
        self.assertEqual(snap["tag"], "v9.9.9")
        self.assertEqual(snap["published_at"], "inf")

    def test_surrogate_escape_html_url_is_scrubbed(self):
        snap = self._github(
            b'{"tag_name": "v9.9.9", "html_url": "https://github.com/\\ud800"}',
        )
        self.assertTrue(snap["ok"])
        self.assertEqual(snap["html_url"], "https://github.com/?")

    def test_huge_float_tag_name_renders_as_its_text(self):
        snap = self._github(b'{"tag_name": 1e999}')
        self.assertTrue(snap["ok"])
        self.assertEqual(snap["tag"], "inf")


class LsofAndSyslogStaysImmuneTests(unittest.TestCase):
    def test_huge_digit_lsof_port_costs_its_row_only(self):
        out = (
            "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n"
            "bad 1 root 6u IPv4 0x1 0t0 TCP *:" + "9" * 5000 + " (LISTEN)\n"
            "ok 2 root 6u IPv4 0x1 0t0 TCP *:8080 (LISTEN)"
        )
        with mock.patch.object(tools_svc, "sh", lambda *a, **k: (0, out, "")):
            response = _client().get("/api/tools/ports")
        self.assertEqual(response.status_code, 200, response.text[:300])
        body = response.json()
        _starlette(body)
        self.assertEqual([p["port"] for p in body["ports"]], [8080])

    def test_surrogate_syslog_level_echo_is_replaced_at_the_decode(self):
        tools_svc._syslog_cache.clear()
        self.addCleanup(tools_svc._syslog_cache.clear)
        with mock.patch.object(tools_svc, "sh", lambda *a, **k: (1, "", "no log")):
            response = _client().get(
                "/api/tools/syslog?level=%ED%A0%80bad&force=true",
            )
        self.assertEqual(response.status_code, 200, response.text[:300])
        body = response.json()
        _starlette(body)
        self.assertFalse(body["ok"])
        self.assertNotIn("\ud800", body["level"])


if __name__ == "__main__":
    unittest.main()
