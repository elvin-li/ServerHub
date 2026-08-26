"""Tools leftover sweep #6: raw DNS echoes and the shared ps-table subclass.

A fresh hunt over the mounted Tools routes (create_app + TestClient,
raise_server_exceptions=False) found two live leftover classes the earlier
tools sweeps missed:

* POST /api/tools/net/dns echoed ``sockaddr[0]`` raw into ``results``.  A
  leftover >4300-digit int 500'd Starlette's render at CPython's int->str
  digit cap (ValueError, not TypeError), a lone-surrogate str 500'd the
  UTF-8 encode, and a non-finite float 500'd the allow_nan=False encoder.
  The fix scrubs through ``_as_text`` *after* the raw dedupe membership, so
  the unhashable-ip leftover keeps its coded failure while an unrenderable
  ip now costs its own row, never the lookup.

* GET /api/system/processes trusted the shared ps table wholesale: a
  list-subclass ``ps_lines()`` return whose bound ``__len__`` or
  ``__getitem__`` raises passed the implicit list contract and blew
  ``len(lines)`` / ``lines[1:]`` — the same unbound-read class tools sweep
  #5 fixed on the hardware tab (an ``__iter__`` bomb was already
  neutralized by the slice; these two were not).  The fix copies through
  ``list.__getitem__(lines, slice(None))``, so the rows survive and parse.

Stays-immune pins ride along for the vectors this sweep re-tested and found
already dead: a >4300-digit JSON body literal (FastAPI's body reader turns
the digit-cap ValueError into the coded 400, never a 500), ``\\ud800``
escapes in ping/dns/prune bodies (coded soft-fails with scrubbed echoes),
the plist calendar zoo (hex-int past the digit cap, binary-plist UID,
datetime, >8-deep nesting) on the scheduler/agents routes, a FIFO occupying
/var/log/system.log on the syslog fallback (O_NONBLOCK EINVAL, not a hang),
numeric/torn-IPv6/huge-int/get-bomb ``updates.github_repo`` settings (pinned
default repo), huge-digit query ints (parse 422), and a lone surrogate in
the dig output (scrubbed by ``_sh``).
"""
from __future__ import annotations

import json
import os
import plistlib
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

import hub.config as hub_config
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


def _gai(*rows):
    def fake(name, port):
        return list(rows)
    return fake


_NO_DIG = mock.patch.object(tools_svc, "sh", lambda *a, **k: (1, "", ""))


class DnsEchoLeftoverTests(unittest.TestCase):
    """``sockaddr[0]`` echoed raw used to 500 the render — now scrubbed."""

    def _dns(self, *rows):
        with (
            mock.patch.object(tools_svc.socket, "getaddrinfo", _gai(*rows)),
            _NO_DIG,
        ):
            response = _client().post(
                "/api/tools/net/dns", json={"name": "example.com"},
            )
        self.assertEqual(response.status_code, 200, response.text[:300])
        body = response.json()
        _starlette(body)
        return body

    def test_huge_int_ip_costs_its_row_not_the_lookup(self):
        body = self._dns(
            (2, 1, 6, "", (_HUGE_INT, 0)),
            (2, 1, 6, "", ("1.2.3.4", 0)),
        )
        self.assertTrue(body["ok"])
        self.assertEqual(
            body["results"], [{"ip": "1.2.3.4", "family": "IPv4"}],
        )

    def test_lone_surrogate_ip_is_scrubbed_not_500(self):
        body = self._dns((2, 1, 6, "", ("1.2.\ud800.4", 0)))
        self.assertTrue(body["ok"])
        self.assertEqual(body["results"][0]["ip"], "1.2.?.4")

    def test_nonfinite_float_ips_render_as_text(self):
        body = self._dns(
            (2, 1, 6, "", (float("nan"), 0)),
            (2, 1, 6, "", (float("inf"), 0)),
        )
        self.assertTrue(body["ok"])
        self.assertEqual([r["ip"] for r in body["results"]], ["nan", "inf"])

    def test_bytes_ip_decodes_and_family_survives(self):
        body = self._dns((tools_svc.socket.AF_INET6, 1, 6, "", (b"::1", 0, 0, 0)))
        self.assertEqual(
            body["results"], [{"ip": "::1", "family": "IPv6"}],
        )

    def test_unhashable_ip_keeps_the_coded_failure(self):
        """The raw dedupe membership stays first: the tools sweep #5 pin."""
        body = self._dns((2, 1, 6, "", (["unhashable"], 0)))
        self.assertFalse(body["ok"])
        self.assertEqual(body["results"], [])

    def test_oversize_ip_is_capped(self):
        body = self._dns((2, 1, 6, "", ("a" * 5000, 0)))
        self.assertEqual(body["results"][0]["ip"], "a" * 64)


class PsTableSubclassLeftoverTests(unittest.TestCase):
    """Bound ``__len__`` / ``__getitem__`` bombs on ``ps_lines()`` used to
    500 GET /api/system/processes."""

    _ROW = "u 1 1.0 2.0 10 20 tt s 3 0:00 cmd arg"
    _PARSED = {
        "user": "u", "pid": "1", "cpu": 1.0, "mem": 2.0, "vsz": "10",
        "rss": "20", "stat": "s", "time": "0:00", "command": "cmd arg",
    }

    def setUp(self):
        tools_svc._proc_cache.update(t=0.0, v=None, limit=0)
        self.addCleanup(tools_svc._proc_cache.update, t=0.0, v=None, limit=0)

    def _processes(self, lines):
        with mock.patch.object(tools_svc, "ps_lines", lambda: lines):
            response = _client().get("/api/system/processes")
        self.assertEqual(response.status_code, 200, response.text[:300])
        body = response.json()
        _starlette(body)
        return body["processes"]

    def test_len_bomb_table_still_parses(self):
        class LenBomb(list):
            def __len__(self):
                raise RuntimeError("len bomb")

        rows = self._processes(LenBomb(["HDR", self._ROW]))
        self.assertEqual(rows, [self._PARSED])

    def test_getitem_bomb_table_still_parses(self):
        class GetItemBomb(list):
            def __getitem__(self, item):
                raise RuntimeError("getitem bomb")

        rows = self._processes(GetItemBomb(["HDR", self._ROW]))
        self.assertEqual(rows, [self._PARSED])

    def test_iter_bomb_table_stays_neutralized(self):
        class IterBomb(list):
            def __iter__(self):
                raise RuntimeError("iter bomb")

        rows = self._processes(IterBomb(["HDR", self._ROW]))
        self.assertEqual(rows, [self._PARSED])

    def test_non_list_iterbomb_degrades_to_empty(self):
        class IterBombTuple(tuple):
            def __iter__(self):
                raise RuntimeError("iter bomb")

        rows = self._processes(IterBombTuple(("HDR", self._ROW)))
        self.assertEqual(rows, [])

    def test_bytes_rows_still_decode(self):
        rows = self._processes(["HDR", self._ROW.encode()])
        self.assertEqual(rows, [self._PARSED])

    def test_cache_after_a_bomb_table_serves_plain_rows(self):
        class LenBomb(list):
            def __len__(self):
                raise RuntimeError("len bomb")

        self._processes(LenBomb(["HDR", self._ROW]))

        def boom():
            raise AssertionError("a cache hit must not re-read the table")

        with mock.patch.object(tools_svc, "ps_lines", boom):
            response = _client().get("/api/system/processes")
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertEqual(response.json()["processes"], [self._PARSED])


class BodyLiteralStaysImmuneTests(unittest.TestCase):
    """>4300-digit JSON body literals: json.loads raises ValueError (the
    digit cap), not JSONDecodeError — the body reader must answer the coded
    400, never a 500."""

    def _post(self, path: str, raw: str):
        return _client().post(
            path, content=raw.encode(),
            headers={"content-type": "application/json"},
        )

    def test_huge_ping_count_literal_is_the_coded_400(self):
        response = self._post(
            "/api/tools/net/ping",
            '{"host": "example.com", "count": ' + "9" * 5000 + "}",
        )
        self.assertEqual(response.status_code, 400, response.text[:300])

    def test_huge_prune_confirm_literal_is_the_coded_400(self):
        response = self._post(
            "/api/tools/docker/prune",
            '{"what": "dangling", "confirm": ' + "9" * 5000 + "}",
        )
        self.assertEqual(response.status_code, 400, response.text[:300])


class SurrogateBodyStaysImmuneTests(unittest.TestCase):
    """``\\ud800`` escapes decode to lone surrogates server-side; every echo
    stays a scrubbed coded soft-fail."""

    def _post(self, path: str, raw: str):
        response = _client().post(
            path, content=raw.encode(),
            headers={"content-type": "application/json"},
        )
        self.assertEqual(response.status_code, 200, response.text[:300])
        payload = response.json()
        _starlette(payload)
        return payload

    def test_surrogate_ping_host_is_the_coded_bad_host(self):
        payload = self._post("/api/tools/net/ping", '{"host": "\\ud800bad"}')
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["code"], "tools.bad_host")

    def test_surrogate_dns_name_is_the_coded_bad_host(self):
        payload = self._post("/api/tools/net/dns", '{"name": "\\ud800bad"}')
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["code"], "tools.bad_host")

    def test_surrogate_prune_what_is_the_scrubbed_bad_prune(self):
        with mock.patch.object(tools_svc, "engine_up", lambda force=False: True):
            payload = self._post(
                "/api/tools/docker/prune",
                '{"what": "\\ud800bad", "confirm": true}',
            )
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["code"], "tools.bad_prune")
        self.assertEqual(payload["params"]["what"], "?bad")


class PlistCalendarZooStaysImmuneTests(unittest.TestCase):
    """Fresh calendar shapes on the scheduler/agents routes stay 200."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _write(self, name: str, obj, fmt=plistlib.FMT_XML) -> None:
        (Path(self.tmp.name) / name).write_bytes(plistlib.dumps(obj, fmt=fmt))

    def test_calendar_zoo_renders_per_field(self):
        # Hex integer past the digit cap: plistlib loads <integer>0x…</integer>
        # through int(raw, 16), which the conversion limit exempts.
        (Path(self.tmp.name) / "hex.plist").write_bytes(
            b'<?xml version="1.0" encoding="UTF-8"?>\n'
            b'<plist version="1.0"><dict>'
            b"<key>Label</key><string>hex.job</string>"
            b"<key>StartCalendarInterval</key><dict><key>Minute</key>"
            b"<integer>0x" + b"1" * 4400 + b"</integer></dict>"
            b"</dict></plist>"
        )
        self._write("uid.plist", {
            "Label": "uid.job",
            "StartCalendarInterval": {"U": plistlib.UID(5)},
        }, fmt=plistlib.FMT_BINARY)
        self._write("date.plist", {
            "Label": "date.job",
            "StartCalendarInterval": {"When": datetime(2026, 1, 1)},
        })
        deep: dict = {"Minute": 1}
        for _ in range(20):
            deep = {"n": deep}
        self._write("deep.plist", {
            "Label": "deep.job", "StartCalendarInterval": deep,
        })

        client = _client()
        with mock.patch.object(
            tools_svc.os.path, "expanduser", return_value=self.tmp.name,
        ):
            scheduler = client.get("/api/system/scheduler")
            agents = client.get("/api/tools/agents")
        self.assertEqual(scheduler.status_code, 200, scheduler.text[:300])
        self.assertEqual(agents.status_code, 200, agents.text[:300])
        _starlette(scheduler.json())
        _starlette(agents.json())
        timers = {t["label"]: t for t in scheduler.json()["timers"]}
        # The over-cap hex minute drops to None; the row itself survives.
        self.assertEqual(timers["hex.job"]["calendar"], {"Minute": None})
        self.assertEqual(
            timers["date.job"]["calendar"], {"When": "2026-01-01T00:00:00"},
        )
        self.assertIn("uid.job", timers)
        self.assertIn("deep.job", timers)


class SyslogFallbackFifoStaysImmuneTests(unittest.TestCase):
    """A FIFO occupying /var/log/system.log neither hangs nor 500s the
    fallback (tail_file_lines opens O_NONBLOCK and refuses non-regular
    files with the OSError the caller already handles)."""

    def test_fifo_system_log_is_the_coded_failure_not_a_hang(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        fifo = Path(tmp.name) / "system.log"
        os.mkfifo(fifo)
        real_path = tools_svc.Path

        def fake_path(p, *parts):
            if str(p) == "/var/log/system.log":
                return real_path(fifo)
            return real_path(p, *parts)

        tools_svc._syslog_cache.clear()
        self.addCleanup(tools_svc._syslog_cache.clear)
        with (
            mock.patch.object(tools_svc, "Path", fake_path),
            mock.patch.object(tools_svc, "sh", lambda *a, **k: (1, "", "log broke")),
        ):
            response = _client().get("/api/tools/syslog?force=true")
        self.assertEqual(response.status_code, 200, response.text[:300])
        payload = response.json()
        _starlette(payload)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["lines"], [])
        self.assertIn("not a regular file", payload["message"])


class GithubRepoSettingStaysImmuneTests(unittest.TestCase):
    """Leftover ``updates.github_repo`` settings shapes pin the default."""

    def test_leftover_repo_settings_fall_back_to_the_default(self):
        class GetBomb(dict):
            def get(self, *a, **k):
                raise RuntimeError("get bomb")

        for label, section in (
            ("numeric YAML id", {"github_repo": 123}),
            ("over the digit cap", {"github_repo": _HUGE_INT}),
            ("torn IPv6", {"github_repo": "[::1/x"}),
            ("lone surrogate", {"github_repo": "a\ud800/b"}),
            ("dict-subclass .get bomb", GetBomb()),
            ("non-dict section", 5),
            ("missing section", None),
        ):
            with mock.patch.object(
                hub_config, "settings_section", lambda name, s=section: s,
            ):
                self.assertEqual(
                    tools_svc._github_repo(), tools_svc._GITHUB_REPO_DEFAULT,
                    msg=label,
                )


class QueryDigitCapStaysImmuneTests(unittest.TestCase):
    """Huge-digit query ints stay the parse 422, never the digit-cap 500."""

    def test_huge_digit_query_ints_are_422(self):
        for path in (
            "/api/tools/syslog?minutes=" + "9" * 5000,
            "/api/system/processes?limit=" + "9" * 5000,
        ):
            response = _client().get(path)
            self.assertEqual(response.status_code, 422, path[:60])


class DigOutputStaysImmuneTests(unittest.TestCase):
    """A lone surrogate in the dig output is scrubbed by ``_sh``."""

    def test_surrogate_dig_output_is_scrubbed(self):
        with (
            mock.patch.object(tools_svc.socket, "getaddrinfo",
                              _gai((2, 1, 6, "", ("1.1.1.1", 0)))),
            mock.patch.object(tools_svc, "sh",
                              lambda *a, **k: (0, "an\ud800swer", "")),
            mock.patch.object(tools_svc.shutil, "which",
                              lambda *_a: "/usr/bin/dig"),
            mock.patch.object(tools_svc.Path, "is_file", lambda self: True),
        ):
            response = _client().post(
                "/api/tools/net/dns", json={"name": "example.com"},
            )
        self.assertEqual(response.status_code, 200, response.text[:300])
        payload = response.json()
        _starlette(payload)
        self.assertEqual(payload["dig"], "an?swer")


if __name__ == "__main__":
    unittest.main()
