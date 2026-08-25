"""Brew page leftovers: one over-cap number must not wipe the brew snapshot.

CPython's int(str) digit cap makes ``json.loads`` of a >4300-digit literal
raise the plain *ValueError* (never JSONDecodeError), so decode sites that
"only" meant to catch corrupt JSON dropped the whole document.  Every sibling
store (docker_cli, notify_channels, service_credentials, catalog_remote, ...)
already decodes through a ``parse_int`` hook; ``hub.brew_cache`` had the two
unhooked sites left:

* **fixed** — ``_services_from_output``: one poisoned ``exit_code`` in the
  live `brew services list --json` output made the parse return None, so
  ``_load`` silently discarded the *fresh* snapshot and republished the stale
  last-good with a brand-new TTL (and rewrote it to disk).  A start/stop
  performed while brew printed that number never became visible on the Brew
  page — GET /api/brew/services kept answering the pre-action state;
* **fixed** — ``_read_disk_file``: the same literal in
  brew-services.cache.json made the whole on-disk journal read as corrupt,
  so a cold start (or the post-invalidate busy-brew path) lost its last-good
  and rendered zero brew rows instead of the surviving siblings.

The rest of the sweep's classes were already immune here and are pinned
below so they stay that way: lone surrogates in row keys AND values are
scrubbed before Starlette's UTF-8 encode; an already-int over-cap leftover
(minted via the hex spelling, which dodges the cap at parse time) drops to
None through the ``str()`` probe instead of blowing the JSON encoder; and
the vanished-brew coded 503 on the action failure path is pinned by
tests/test_cli_missing_leftover_503.py.  The brew domain has no os.kill /
pid paths (its only process probe is pgrep), so that class does not apply.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import brew_cache, brew_svc  # noqa: E402

#: Past CPython's default 4300-digit str<->int conversion limit.
_HUGE_DIGITS = "9" * 5000
#: The hex spelling parses fine (no cap in int(x, 16)), so a live over-cap
#: int really can exist in memory; only rendering it back is impossible.
_HUGE_INT = int("f" * 4000, 16)


def _starlette(payload) -> None:
    """Exactly what Starlette's JSONResponse does to the payload."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


def _no_surrogates(text: str, where: str) -> None:
    if any("\ud800" <= ch <= "\udfff" for ch in text):
        raise AssertionError(f"surrogate survived into {where}: {text!r}")


class _CacheSandbox(unittest.TestCase):
    """Every test starts and ends with an empty snapshot and a private disk."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.disk = Path(self._tmp.name) / "brew-services.cache.json"
        patched = mock.patch.object(brew_cache, "_DISK", self.disk)
        patched.start()
        self.addCleanup(patched.stop)
        brew_cache.invalidate_brew_services()
        self.addCleanup(brew_cache.invalidate_brew_services)


class FreshSnapshotHugeIntTests(_CacheSandbox):
    """One poisoned number in live brew output must not hide fresh state."""

    FRESH = (
        '[{"name":"syncthing","status":"stopped","exit_code":%s},'
        ' {"name":"redis","status":"started","exit_code":0}]' % _HUGE_DIGITS
    )

    def test_one_poisoned_exit_code_keeps_every_row(self):
        rows = brew_cache._services_from_output(self.FRESH)
        self.assertIsNotNone(
            rows, "one over-cap exit_code discarded the whole fresh snapshot"
        )
        by_name = {r["name"]: r for r in rows}
        self.assertEqual(sorted(by_name), ["redis", "syncthing"])
        # The poisoned number drops to None; its siblings keep their values.
        self.assertIsNone(by_name["syncthing"]["exit_code"])
        self.assertEqual(by_name["redis"]["exit_code"], 0)

    def test_load_publishes_the_fresh_state_not_the_stale_snapshot(self):
        # The user-visible symptom: syncthing was just stopped, brew reports
        # it stopped, and the page kept saying "started" for another TTL.
        with brew_cache._lock:
            brew_cache._cache["t"] = 1.0
            brew_cache._cache["v"] = [{"name": "syncthing", "status": "started"}]
        with (
            mock.patch.object(brew_cache, "_brew_busy", return_value=False),
            mock.patch.object(brew_cache, "sh", return_value=(0, self.FRESH, "")),
        ):
            got = brew_cache._load()
        by_name = {r["name"]: r for r in got}
        self.assertEqual(by_name["syncthing"]["status"], "stopped")
        _starlette(got)

    def test_the_poisoned_fresh_snapshot_still_reaches_the_disk(self):
        with (
            mock.patch.object(brew_cache, "_brew_busy", return_value=False),
            mock.patch.object(brew_cache, "sh", return_value=(0, self.FRESH, "")),
        ):
            brew_cache._load()
        on_disk = json.loads(self.disk.read_text(encoding="utf-8"))
        self.assertEqual(
            sorted(r["name"] for r in on_disk), ["redis", "syncthing"]
        )

    def test_list_services_answers_the_rows_not_an_empty_page(self):
        # End to end through GET /api/brew/services' service layer: cold
        # cache, live brew prints the poisoned list, both rows render.
        with (
            mock.patch("os.path.isfile", return_value=True),
            mock.patch.object(brew_cache, "_brew_busy", return_value=False),
            mock.patch.object(brew_cache, "sh", return_value=(0, self.FRESH, "")),
            mock.patch.object(brew_svc, "sh", return_value=(1, "", "")),
        ):
            items = brew_svc.list_services()
        by_id = {i["id"]: i for i in items}
        self.assertIn("syncthing", by_id)
        self.assertIn("redis", by_id)
        self.assertEqual(by_id["syncthing"]["status"], "stopped")
        self.assertIsNone(by_id["syncthing"]["exit_code"])
        _starlette({"services": items})


class DiskSnapshotHugeIntTests(_CacheSandbox):
    """The on-disk journal survives one poisoned number too."""

    def test_read_disk_file_keeps_the_journal(self):
        self.disk.write_text(
            '[{"name":"x","status":"started","exit_code":%s},'
            ' {"name":"y","status":"stopped"}]' % _HUGE_DIGITS,
            encoding="utf-8",
        )
        rows = brew_cache._read_disk_file()
        self.assertIsNotNone(
            rows, "one over-cap number read the whole disk journal as corrupt"
        )
        self.assertEqual(sorted(r["name"] for r in rows), ["x", "y"])

    def test_busy_cold_start_serves_the_poisoned_disk_as_last_good(self):
        # invalidate + a still-held Homebrew lock: _keep_last_good must find
        # the disk copy instead of publishing emptiness.
        self.disk.write_text(
            '[{"name":"x","status":"started","exit_code":%s}]' % _HUGE_DIGITS,
            encoding="utf-8",
        )
        with (
            mock.patch.object(brew_cache, "_brew_busy", return_value=True),
            mock.patch.object(
                brew_cache, "sh",
                side_effect=AssertionError("busy brew must not spawn"),
            ),
        ):
            got = brew_cache._load()
        self.assertEqual([r["name"] for r in got], ["x"])
        _starlette(got)

    def test_a_sane_disk_snapshot_round_trips_with_its_ints(self):
        self.disk.write_text(
            '[{"name":"x","status":"started","exit_code":0}]', encoding="utf-8"
        )
        rows = brew_cache._read_disk_file()
        self.assertEqual(rows[0]["exit_code"], 0)
        self.assertIsInstance(rows[0]["exit_code"], int)


class GarbageStillFailsClosedTests(_CacheSandbox):
    """The hook must not widen what counts as a successful list."""

    def test_non_json_output_is_still_not_a_list(self):
        self.assertIsNone(brew_cache._services_from_output("{not json"))

    def test_a_json_object_is_still_not_a_list(self):
        self.assertIsNone(brew_cache._services_from_output('{"name":"x"}'))

    def test_a_truly_corrupt_disk_file_still_reads_as_missing(self):
        self.disk.write_text("{not json", encoding="utf-8")
        self.assertIsNone(brew_cache._read_disk_file())

    def test_in_cap_ints_still_parse_as_ints(self):
        rows = brew_cache._services_from_output(
            '[{"name":"x","status":"started","exit_code":-15}]'
        )
        self.assertEqual(rows[0]["exit_code"], -15)
        self.assertIsInstance(rows[0]["exit_code"], int)


class SurrogateRowsStayImmuneTests(_CacheSandbox):
    """json.loads happily mints lone-surrogate KEYS and values from escaped
    ``\\ud800`` sequences; the publish path scrubs both before Starlette."""

    LIVE = (
        '[{"name":"syncthing","status":"started",'
        ' "\\ud800meta":"\\ud800boom"}]'
    )

    def test_surrogate_key_and_value_in_live_output_publish_clean(self):
        rows = brew_cache._services_from_output(self.LIVE)
        published = brew_cache._publish(rows, write_disk=False)
        _starlette(published)
        for row in published:
            for key, value in row.items():
                _no_surrogates(key, "row key")
                if isinstance(value, str):
                    _no_surrogates(value, f"row value for {key!r}")

    def test_surrogate_disk_snapshot_reads_and_encodes(self):
        self.disk.write_text(
            '[{"name":"x","status":"started","\\ud800k":"\\ud800v"}]',
            encoding="utf-8",
        )
        with brew_cache._lock:
            brew_cache._disk_ok = True
        rows = brew_cache._read_disk()
        self.assertEqual(rows[0]["name"], "x")
        _starlette(rows)
        for key in rows[0]:
            _no_surrogates(key, "disk row key")


class AlreadyIntLeftoverStaysImmuneTests(_CacheSandbox):
    """A live over-cap int (hex-minted) drops through the str() probe."""

    def test_primed_over_cap_int_drops_to_none_not_a_500(self):
        with brew_cache._lock:
            brew_cache._cache["t"] = float("inf")
            brew_cache._cache["v"] = [
                {"name": "syncthing", "status": "started", "exit_code": _HUGE_INT},
            ]
        got = brew_cache.brew_services()
        self.assertIsNone(got[0]["exit_code"])
        _starlette(got)

    def test_list_services_drops_the_field_and_keeps_the_sibling_row(self):
        rows = [
            {"name": "syncthing", "status": "started", "exit_code": _HUGE_INT},
            {"name": "redis", "status": "stopped", "exit_code": 0},
        ]
        with (
            mock.patch("os.path.isfile", return_value=True),
            mock.patch.object(brew_svc, "brew_services_list", return_value=rows),
        ):
            items = brew_svc.list_services()
        by_id = {i["id"]: i for i in items}
        self.assertIsNone(by_id["syncthing"]["exit_code"])
        self.assertEqual(by_id["redis"]["exit_code"], 0)
        _starlette({"services": items})


if __name__ == "__main__":
    unittest.main(verbosity=2)
