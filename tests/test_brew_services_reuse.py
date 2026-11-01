"""`brew services list --json` is reused while nothing it reads has changed.

The command costs about 1.7 s of CPU (ruby plus a launchctl probe per label),
and the shared snapshot re-ran it on every expiry even when no service, plist
or formula had changed.  ``brew_cache._load`` now fingerprints brew's inputs
before each run and serves the last answer while the fingerprint matches.

These tests drive ``_load`` against a fake prefix, fake plist directories and
a fake launchd listing.  Each input brew reads must force a fresh run when it
changes, and anything that makes the listing an unreliable proxy for brew's
own launchd view (an empty listing, a disagreeing one, a change mid-run) must
turn reuse off.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import brew_cache, launchd_cache  # noqa: E402


def _bump(path: Path) -> None:
    """Move *path*'s mtime one second forward."""
    st = os.stat(path)
    os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000_000))


class BrewServicesReuseTests(unittest.TestCase):
    def setUp(self):
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.prefix = root / "brew"
        (self.prefix / "bin").mkdir(parents=True)
        (self.prefix / "bin" / "brew").write_text("#!/bin/sh\n")
        for sub in ("opt", "Cellar", ".git", "Library/Taps/me/homebrew-tap/.git"):
            (self.prefix / sub).mkdir(parents=True)
        (self.prefix / ".git" / "HEAD").write_text("ref: refs/heads/stable\n")
        self.tap_fetch = self.prefix / "Library/Taps/me/homebrew-tap/.git/FETCH_HEAD"
        self.tap_fetch.write_text("a\n")
        self.cache = root / "cache"
        (self.cache / "api" / "internal").mkdir(parents=True)
        (self.cache / "api" / "internal" / "packages.jws.json").write_text("{}")
        self.agents = root / "LaunchAgents"
        self.agents.mkdir()
        self.daemons = root / "LaunchDaemons"
        self.daemons.mkdir()
        (self.agents / "com.example.other.plist").write_text("<plist/>")
        self.grafana = self.agents / "homebrew.mxcl.grafana.plist"
        self.grafana.write_text("<plist>grafana</plist>")
        self.postgres = self.agents / "homebrew.mxcl.postgresql@17.plist"
        self.postgres.write_text("<plist>postgres</plist>")
        # name -> plist path brew reports for it
        self.formulae = {
            "grafana": str(self.grafana),
            "postgresql@17": str(self.postgres),
            "redis": str(self.prefix / "opt" / "redis" / "sh.brew.redis.plist"),
        }
        # The panel's `launchctl list`, and what brew itself finds in launchd.
        # The same dict unless a test makes them disagree.
        self.jobs = {
            "homebrew.mxcl.grafana": ("123", "0"),
            "homebrew.mxcl.postgresql@17": ("456", "0"),
            "com.apple.Finder": ("99", "0"),
        }
        self.brew_jobs = self.jobs
        self.runs = 0
        self.during_run = None
        self.forced = []

        # Restored on exit, including the key popped below.
        self.enterContext(mock.patch.dict(os.environ, {"HOMEBREW_CACHE": str(self.cache)}))
        os.environ.pop("SERVERHUB_NO_BREW_REUSE", None)
        for name, value in (
            ("BREW", str(self.prefix / "bin" / "brew")),
            ("AGENTS_DIR", self.agents),
            ("_ROOT_AGENTS_DIR", str(self.daemons)),
            ("_DISK", root / "brew-services.cache.json"),
        ):
            self.enterContext(mock.patch.object(brew_cache, name, value))
        self.enterContext(mock.patch.object(brew_cache, "_brew_busy", return_value=False))
        self.enterContext(mock.patch.object(brew_cache, "sh", side_effect=self._brew))
        self.enterContext(mock.patch.object(launchd_cache, "listing", side_effect=self._listing))
        brew_cache.invalidate_brew_services()
        self.addCleanup(brew_cache.invalidate_brew_services)

    # -- fakes ---------------------------------------------------------------
    def _listing(self, force=False):
        self.forced.append(force)
        return launchd_cache.Listing(dict(self.jobs))

    def _brew(self, argv, timeout=None, env=None):
        self.assertEqual(list(argv[1:]), ["services", "list", "--json"])
        self.runs += 1
        if self.during_run is not None:
            self.during_run()
        items = []
        for name, path in sorted(self.formulae.items()):
            label = os.path.basename(path)[: -len(".plist")]
            job = self.brew_jobs.get(label)
            if job is None:
                status = "none"
            elif job[0].isdigit():
                status = "started"
            else:
                status = "stopped" if job[1] == "0" else "error"
            items.append({"name": name, "status": status, "user": "me",
                          "file": path, "exit_code": None})
        return 0, json.dumps(items), ""

    def load_twice(self, change=None):
        first = brew_cache._load()
        if change is not None:
            change()
        second = brew_cache._load()
        return first, second

    # -- reuse ---------------------------------------------------------------
    def test_unchanged_inputs_reuse_the_last_answer(self):
        first, second = self.load_twice()
        self.assertEqual(self.runs, 1)
        self.assertEqual(first, second)
        self.assertEqual({r["name"]: r["status"] for r in second}["grafana"], "started")
        # A fresh listing each time, so a reused answer is as current as a run.
        self.assertTrue(self.forced and all(self.forced))

    def test_a_reused_answer_is_fresh_and_leaves_the_disk_copy_alone(self):
        brew_cache._load()
        before = brew_cache._stat_key(brew_cache._DISK)
        with brew_cache._lock:
            brew_cache._cache["t"] = 1.0  # expired
        brew_cache._load()
        self.assertEqual(self.runs, 1)
        self.assertIsNotNone(brew_cache._fresh())
        self.assertEqual(brew_cache._stat_key(brew_cache._DISK), before)

    def test_reuse_returns_copies(self):
        brew_cache._load()
        brew_cache._load()[0]["status"] = "scribbled"
        self.assertNotEqual(brew_cache._load()[0]["status"], "scribbled")
        self.assertEqual(self.runs, 1)

    # -- every input brew reads forces a run ---------------------------------
    def test_a_launchd_change_runs_brew(self):
        changes = {
            "restart": lambda: self.jobs.update({"homebrew.mxcl.grafana": ("777", "0")}),
            "stop": lambda: self.jobs.pop("homebrew.mxcl.grafana"),
            "crash": lambda: self.jobs.update({"homebrew.mxcl.grafana": ("-", "1")}),
            "start": lambda: self.jobs.update({"sh.brew.redis": ("888", "0")}),
            "start legacy": lambda: self.jobs.update({"homebrew.mxcl.redis": ("889", "0")}),
        }
        for name, change in changes.items():
            with self.subTest(name):
                self.setUp()
                self.load_twice(change)
                self.assertEqual(self.runs, 2)

    def test_a_file_change_runs_brew(self):
        changes = {
            "plist edit": lambda: _bump(self.grafana),
            "plist rewrite": lambda: self.grafana.write_text("<plist>UserName</plist>"),
            "plist added": lambda: (self.agents / "sh.brew.redis.plist").write_text("x"),
            "agents dir": lambda: _bump(self.agents),
            "root plist added": lambda: _bump(self.daemons),
            "install or upgrade": lambda: _bump(self.prefix / "opt"),
            "new rack": lambda: _bump(self.prefix / "Cellar"),
            "brew update": lambda: (self.prefix / ".git" / "FETCH_HEAD").write_text("x"),
            "brew checkout": lambda: _bump(self.prefix / ".git" / "HEAD"),
            "tap update": lambda: _bump(self.tap_fetch),
            "api refresh": lambda: _bump(self.cache / "api" / "internal" / "packages.jws.json"),
            "api file added": lambda: (self.cache / "api" / "formula.jws.json").write_text("{}"),
        }
        for name, change in changes.items():
            with self.subTest(name):
                self.setUp()
                self.load_twice(change)
                self.assertEqual(self.runs, 2)

    def test_an_unrelated_plist_does_not_run_brew(self):
        self.load_twice(lambda: _bump(self.agents / "com.example.other.plist"))
        self.assertEqual(self.runs, 1)

    # -- explicit refreshes ----------------------------------------------------
    def test_invalidate_runs_brew(self):
        self.load_twice(brew_cache.invalidate_brew_services)
        self.assertEqual(self.runs, 2)

    def test_force_runs_brew(self):
        brew_cache._load()
        brew_cache.brew_services(force=True)
        self.assertEqual(self.runs, 2)

    def test_the_backstop_runs_brew(self):
        with mock.patch.object(brew_cache, "_REUSE_MAX", 0.0):
            self.load_twice()
        self.assertEqual(self.runs, 2)

    def test_the_env_flag_turns_reuse_off(self):
        os.environ["SERVERHUB_NO_BREW_REUSE"] = "1"
        self.load_twice()
        self.assertEqual(self.runs, 2)

    # -- when the listing cannot stand in for brew's view ----------------------
    def test_an_empty_listing_turns_reuse_off(self):
        self.brew_jobs = dict(self.jobs)
        self.jobs.clear()
        self.load_twice()
        self.assertEqual(self.runs, 2)

    def test_a_listing_that_disagrees_with_brew_turns_reuse_off(self):
        views = {
            # brew finds grafana in a launchd domain this listing does not show
            "other domain": {"homebrew.mxcl.postgresql@17": ("456", "0")},
            "no pid here": {"homebrew.mxcl.grafana": ("-", "0"),
                            "homebrew.mxcl.postgresql@17": ("456", "0")},
            "loaded only here": {"homebrew.mxcl.grafana": ("123", "0"),
                                 "homebrew.mxcl.postgresql@17": ("456", "0"),
                                 "sh.brew.redis": ("-", "0")},
        }
        for name, listed in views.items():
            with self.subTest(name):
                self.setUp()
                self.brew_jobs = dict(self.jobs)
                self.jobs.clear()
                self.jobs.update(listed)
                self.load_twice()
                brew_cache._load()
                self.assertEqual(self.runs, 3)

    def test_nothing_loaded_turns_reuse_off(self):
        self.jobs.pop("homebrew.mxcl.grafana")
        self.jobs.pop("homebrew.mxcl.postgresql@17")
        self.load_twice()
        self.assertEqual(self.runs, 2)

    def test_a_change_while_brew_runs_is_not_reused(self):
        self.during_run = lambda: self.jobs.pop("homebrew.mxcl.grafana", None)
        brew_cache._load()
        self.during_run = None
        brew_cache._load()
        brew_cache._load()
        self.assertEqual(self.runs, 2)

    def test_an_answer_without_plist_paths_is_never_reused(self):
        self.formulae["grafana"] = "/nowhere/grafana.service"
        self.load_twice()
        brew_cache._load()
        self.assertEqual(self.runs, 3)

    def test_a_custom_label_is_watched_from_the_next_run(self):
        custom = self.agents / "com.example.foo.plist"
        custom.write_text("<plist>foo</plist>")
        self.formulae["foo"] = str(custom)
        self.jobs["com.example.foo"] = ("321", "0")
        brew_cache._load()  # its label was not watched before this run
        brew_cache._load()
        brew_cache._load()
        self.assertEqual(self.runs, 2)
        _bump(custom)
        brew_cache._load()
        self.assertEqual(self.runs, 3)
        self.jobs["com.example.foo"] = ("-", "0")
        brew_cache._load()
        self.assertEqual(self.runs, 4)


if __name__ == "__main__":
    unittest.main()
