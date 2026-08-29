"""Leftover >4300-digit numbers in the Ollama / health / usage / gateway parsers.

Prior passes guarded the SMART/top/pmset, sysctl, share-ACL, network/WireGuard
and PhotosHub/files/shares digit parsers against CPython's 4300-digit str->int
ValueError (and the inf shapes ``float()`` makes of the same leftovers).  A
fresh hunt across the remaining corners — hub/ollama_svc.py, hub/health_svc.py,
hub/usage_svc.py, and the gateway-side parsers (hub/adaptive.py's plist/lsof/
nginx port scans behind the "Gateway" group, hub/launchd_cache.py's pid
columns) — found every unbounded conversion already wrapped or regex-bounded,
so this battery pins the survivors instead of fixing anything:

* Ollama's tag/ps parses (``parse_tags`` / ``parse_ps`` via ``_safe_int``):
  over-cap ``size`` / ``size_vram`` strings from a lying daemon answer 0, and
  the keep-alive-forever probe (``_expires_forever``) is bounded at ``\\d{4}``
  so an over-cap ``expires_at`` year never reaches ``int()`` at all — GET
  /api/ollama/status renders instead of 500ing;
* Ollama's throughput math (``_tokens_per_s``): a 400-digit ``eval_count``
  whose ``int()`` succeeds still OverflowErrors the float division, and an
  over-cap ``eval_duration`` reads as 0 — both answer None past POST
  /api/ollama/test and /api/ollama/chat, never inf into Starlette's
  ``allow_nan=False`` encoder;
* the daemon URL's port is validated since the settings7 sweep:
  ``http_guard._url_parts`` probes ``SplitResult.port`` (which raises
  ValueError for both over-cap and out-of-range ports), so an
  operator-edited ``settings.ollama.url`` carrying one is rejected by the
  origin gate and ``base_url()`` falls back to the loopback default —
  ``status()`` reports the default URL unreachable and
  ``ollama_svc.health_checks``'s bare ``urlsplit(base_url()).port`` read
  can no longer raise, so GET /api/ollama/status and GET
  /api/health/checks both stay 200-shaped with their rows intact;
* the health page's own port read (``_panel_port``): an over-cap or
  out-of-range ``SERVERHUB_PORT`` answers the 8086 default;
* the usage explorer's request bounds: an over-cap ``limit`` caps at 50 and an
  inf / overflow-adjacent ``min_mb`` falls back to the 1 MB floor, so GET
  /api/storage/usage/largest and /duplicates render;
* the Gateway-group discovery parses: over-cap ports in a LaunchAgent plist
  (flag args, PORT env, Sockets) are dropped by ``ports_from_plist``, an
  over-cap lsof NAME column is skipped by ``_parse_lsof_listen``, an over-cap
  nginx ``listen`` directive is skipped by ``_nginx_listen_ports``, and the
  HTTP status sniff (``_status_from_head``) is bounded at ``\\d{3}`` — none of
  them can 500 GET /api/status or GET /api/nginx.
"""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hub import adaptive, health_svc, ollama_svc, usage_svc

#: Past CPython's default 4300-digit str<->int conversion limit.
_HUGE_DIGITS = "9" * 5000
#: Under the cap: ``int()`` succeeds, but the int/float division OverflowErrors.
_BIG_DIGITS = "9" * 400


def _starlette(payload) -> None:
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class OllamaModelSizeDigitPinTests(unittest.TestCase):
    """GET /api/ollama/status renders every model through these parses."""

    def test_huge_tag_size_answers_zero_not_a_500(self):
        out = ollama_svc.parse_tags({
            "models": [{
                "name": "qwen3:4b",
                "size": _HUGE_DIGITS,
                "details": {"family": "qwen3"},
                "modified_at": "2026-08-13T20:27:24Z",
            }],
        })
        self.assertEqual(out[0]["size"], 0)
        self.assertEqual(out[0]["name"], "qwen3:4b")
        _starlette(out)

    def test_huge_ps_sizes_and_expiry_render_not_a_500(self):
        # The forever probe is bounded at \d{4}: 5000 nines never match the
        # ``(\d{4})-`` prefix, so int() is never called on the leftover.
        out = ollama_svc.parse_ps({
            "models": [{
                "name": "qwen3:4b",
                "size": _HUGE_DIGITS,
                "size_vram": float("inf"),
                "expires_at": f"{_HUGE_DIGITS}-01-01T00:00:00Z",
            }],
        })
        self.assertEqual(out[0]["size"], 0)
        self.assertEqual(out[0]["size_vram"], 0)
        self.assertFalse(out[0]["forever"])
        _starlette(out)

    def test_sane_sizes_and_forever_expiry_still_parse(self):
        out = ollama_svc.parse_ps({
            "models": [{
                "name": "qwen3:4b",
                "size": 3413361762,
                "size_vram": 3413361762,
                "expires_at": "2318-06-20T09:00:00Z",
            }],
        })
        self.assertEqual(out[0]["size"], 3413361762)
        self.assertTrue(out[0]["forever"])


class OllamaTokensPerSecondDigitPinTests(unittest.TestCase):
    """POST /api/ollama/test and /api/ollama/chat report through this math."""

    def test_400_digit_eval_count_survives_the_float_division(self):
        # int() succeeds under the cap; eval_count / (eval_ns / 1e9) is the
        # "int too large to convert to float" OverflowError the guard eats.
        rate = ollama_svc._tokens_per_s({
            "eval_count": int(_BIG_DIGITS),
            "eval_duration": 1_000_000_000,
        })
        self.assertIsNone(rate)

    def test_huge_eval_duration_answers_none_not_a_500(self):
        rate = ollama_svc._tokens_per_s({
            "eval_count": 100,
            "eval_duration": _HUGE_DIGITS,
        })
        self.assertIsNone(rate)

    def test_sane_counters_still_compute_a_rate(self):
        rate = ollama_svc._tokens_per_s({
            "eval_count": 100,
            "eval_duration": 2_000_000_000,
        })
        self.assertEqual(rate, 50.0)


class OllamaHugePortUrlPinTests(unittest.TestCase):
    """An operator-edited ``settings.ollama.url`` with an over-cap or
    out-of-range port (``SplitResult.port`` raises ValueError for both) is
    rejected by the origin gate since the settings7 sweep, so ``base_url()``
    falls back to the loopback default instead of carrying the poison into
    every probe."""

    def _cfg(self, url: str):
        return mock.patch.object(
            ollama_svc, "cfg", lambda: {"settings": {"ollama": {"url": url}}}
        )

    def test_status_reports_the_default_url_unreachable_over_a_huge_port(self):
        # The origin gate rejects the >4300-digit port, base_url() falls
        # back to the default, and status() folds the (refused) probe of
        # that default into the unreachable shape.
        self.addCleanup(ollama_svc.status.invalidate)
        with (
            self._cfg(f"http://127.0.0.1:{_HUGE_DIGITS}"),
            mock.patch.object(ollama_svc, "binary_path", return_value=None),
            mock.patch.object(ollama_svc, "_candidate_labels", return_value=[]),
            mock.patch.object(
                ollama_svc, "_api",
                side_effect=ConnectionRefusedError(61, "refused"),
            ),
        ):
            snap = ollama_svc.status(force=True)
        self.assertFalse(snap["reachable"])
        self.assertTrue(snap["error"])
        self.assertEqual(snap["url"], ollama_svc.DEFAULT_URL)
        self.assertTrue(snap["url_rejected"])
        _starlette(snap)

    def test_health_page_keeps_the_named_ollama_row_over_the_leftover(self):
        # ollama_svc.health_checks reads ``urlsplit(base_url()).port`` bare.
        # Before the settings7 sweep the bad-port URL survived the origin
        # gate and that read ValueError'd — health_svc._ollama_checks then
        # collapsed every Ollama row into one generic "check failed" row.
        # The gate now rejects the URL, base_url() falls back to the
        # default, and the row keeps its name and the real probe failure.
        for port in (_HUGE_DIGITS, "99999"):
            with (
                self.subTest(port=port[:12]),
                self._cfg(f"http://127.0.0.1:{port}"),
                mock.patch.object(
                    ollama_svc, "_candidate_labels",
                    return_value=["local.ollama.serve"],
                ),
                mock.patch.object(
                    ollama_svc, "_api",
                    side_effect=ConnectionRefusedError(61, "refused"),
                ),
            ):
                rows = health_svc._ollama_checks()
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]["id"], "ollama_api")
                self.assertEqual(rows[0]["level"], "warn")
                self.assertFalse(rows[0]["ok"])
                self.assertEqual(rows[0]["name"], "Ollama local LLM API :11434")
                self.assertIn("API unreachable", rows[0]["detail"])
                _starlette(rows)

    def test_a_sane_port_still_names_the_health_row(self):
        def fake_api(path, payload=None, timeout=None):
            if path == "/api/version":
                return {"version": "0.32.9"}
            return {"models": []}

        with (
            self._cfg("http://127.0.0.1:18080"),
            mock.patch.object(ollama_svc, "_api", side_effect=fake_api),
            mock.patch.object(
                ollama_svc, "_candidate_labels",
                return_value=["local.ollama.serve"],
            ),
            mock.patch.object(ollama_svc, "_agent_origins", return_value="*"),
        ):
            rows = ollama_svc.health_checks()
        self.assertEqual(rows[0]["name"], "Ollama local LLM API :18080")
        self.assertTrue(rows[0]["ok"])
        _starlette(rows)


class HealthPanelPortDigitPinTests(unittest.TestCase):
    """GET /api/health/checks names the panel row through this env read."""

    def _port_for(self, value: str) -> int:
        with mock.patch.dict(os.environ, {"SERVERHUB_PORT": value}):
            return health_svc._panel_port()

    def test_huge_env_port_answers_the_default_not_a_500(self):
        self.assertEqual(self._port_for(_HUGE_DIGITS), 8086)

    def test_out_of_range_env_port_answers_the_default(self):
        self.assertEqual(self._port_for("99999"), 8086)

    def test_a_sane_env_port_still_parses(self):
        self.assertEqual(self._port_for("8123"), 8123)


class UsageRequestBoundsDigitPinTests(unittest.TestCase):
    """GET /api/storage/usage/largest and /duplicates parse these bounds."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="usage-pin-"))
        (self.root / "movie.mkv").write_bytes(b"x" * 2048)
        self.addCleanup(self._cleanup)
        patched = mock.patch.object(
            usage_svc, "_resolve", return_value=self.root
        )
        patched.start()
        self.addCleanup(patched.stop)

    def _cleanup(self):
        for child in self.root.iterdir():
            child.unlink()
        self.root.rmdir()

    def test_huge_limit_caps_at_fifty_not_a_500(self):
        out = usage_svc.largest_files(limit=_HUGE_DIGITS)
        self.assertEqual(out["items"][0]["name"], "movie.mkv")
        self.assertEqual(out["scanned"], 1)
        _starlette(out)

    def test_inf_limit_caps_at_fifty_not_a_500(self):
        out = usage_svc.largest_files(limit=float("inf"))
        self.assertEqual(len(out["items"]), 1)
        _starlette(out)

    def test_inf_min_mb_falls_back_to_the_floor(self):
        out = usage_svc.duplicates(min_mb=float("inf"))
        self.assertEqual(out["min_mb"], 1.0)
        self.assertEqual(out["groups"], [])
        _starlette(out)

    def test_overflow_adjacent_min_mb_falls_back_to_the_floor(self):
        # float() succeeds at 1e308; the * 1024 * 1024 then overflows to inf
        # and int(inf) is the OverflowError the guard eats.
        out = usage_svc.duplicates(min_mb=1e308)
        self.assertEqual(out["min_mb"], 1.0)
        _starlette(out)


class GatewayPlistPortDigitPinTests(unittest.TestCase):
    """GET /api/status scans every LaunchAgent through this parse."""

    def test_huge_ports_are_dropped_not_a_500(self):
        ports = adaptive.ports_from_plist({
            "ProgramArguments": [
                "/opt/homebrew/bin/nginx",
                "-p", _HUGE_DIGITS,          # flag arg: int() ValueError eaten
                f"--port={_HUGE_DIGITS}",    # bounded \d{2,5} never matches
                f"listen:{_HUGE_DIGITS}",    # bounded \d{4,5} never matches
            ],
            "EnvironmentVariables": {"PORT": _HUGE_DIGITS},
            "Sockets": {"Listeners": {"SockServiceName": _HUGE_DIGITS}},
        })
        self.assertEqual(ports, [])

    def test_sane_ports_still_parse(self):
        ports = adaptive.ports_from_plist({
            "ProgramArguments": ["/usr/bin/thing", "--port=8281"],
            "EnvironmentVariables": {"PORT": "8123"},
        })
        self.assertEqual(ports, [8281, 8123])


class GatewayLsofPortDigitPinTests(unittest.TestCase):
    """GET /api/status discovers orphan listeners through this parse."""

    _HEADER = "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n"

    def test_huge_listen_port_skips_the_row_not_the_listing(self):
        out = (
            self._HEADER
            + f"nginx 123 me 6u IPv4 0x0 0t0 TCP *:{_HUGE_DIGITS} (LISTEN)\n"
            + "nginx 124 me 6u IPv4 0x0 0t0 TCP *:8281 (LISTEN)\n"
        )
        rows = adaptive._parse_lsof_listen(out)
        self.assertEqual([r["port"] for r in rows], [8281])
        _starlette(rows)


class GatewayNginxListenDigitPinTests(unittest.TestCase):
    """GET /api/nginx inventories conf.d sites through this parse."""

    def test_huge_listen_directive_is_skipped_not_a_500(self):
        conf = (
            f"server {{\n    listen {_HUGE_DIGITS};\n"
            "    listen 127.0.0.1:8281 ssl;\n}\n"
        )
        self.assertEqual(adaptive._nginx_listen_ports(conf), [8281])

    def test_huge_status_line_stays_bounded(self):
        # The sniff captures exactly three digits, so an absurd status line
        # parses (uselessly but safely) instead of feeding int() 5000 digits.
        head = b"HTTP/1.1 " + _HUGE_DIGITS.encode()
        self.assertEqual(adaptive._status_from_head(head), 999)


if __name__ == "__main__":
    unittest.main()
