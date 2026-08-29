"""Sixth leftover-500s sweep of the Maintenance page, over the real mounted app.

The hunted classes were re-driven against the three routes the page mounts —

    GET  /api/maintenance
    POST /api/maintenance/{tid:path}/run
    GET  /api/maintenance/{tid:path}/log

— through ``create_app()`` with ``raise_server_exceptions=False``.  One live
leftover family was found and is fixed with this battery:

* **Self-``__str__`` str-subclass bombs** (the modules5 unbound-convention
  class, one ring further in).  ``jobs._utf8_text`` scrubbed via
  ``str(value)`` and then called the *bound* ``text.encode(...)`` outside
  every net — but ``str()`` only checks the type, it does not copy, so a
  leftover str-subclass whose ``__str__`` returns ``self`` handed its own
  bombing ``encode`` to the scrub: a poisoned job-row ``finished`` 500'd
  both GET /api/maintenance and the log route, and a poisoned task id or
  name in the cfg snapshot 500'd the list AND the run route (which walks
  ``maintenance_tasks()`` first).  ``config._env_text`` had the same bound
  ``decode``/``encode`` calls, so a bomb entry in ``maintenance_env`` blew
  the job thread *before* its try block instead of degrading that one
  entry.  And ``start_job``'s ``not tid`` emptiness probe plus the
  ``_jobs[tid]`` insert let a ``__bool__``/``__hash__``-bomb subclass id
  raise straight into the calling route (tools_svc hands start_job its own
  dicts).  All three now go through unbound base methods
  (``str.encode`` / ``bytes.decode`` — the audit._utf8_text convention),
  which also guarantees an *exact* ``str`` so downstream ``.strip()`` /
  ``.replace()`` / truth tests cannot hit an override either
  (:class:`EncodeBombRowsHttpTests`, :class:`EncodeBombConfigHttpTests`,
  :class:`SubclassIdStartJobTests`, :class:`EnvTextBombTests` fail on the
  pre-fix tree).

Plus stays-immune pins for the neighbours that were probed and found
already coded: a plain ``__str__`` bomb (not returning self) degrades to
``""`` through the existing net, a bytes-subclass ``decode`` bomb in a log
list still serves through the unbound ``_decode_bytes``, and the scrub's
return type really is exact ``str`` for subclass input.
"""
from __future__ import annotations

import time
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from hub import config, jobs
from hub.app_factory import create_app
from hub.auth import require_auth

_app = None


def _the_app():
    global _app
    if _app is None:
        _app = create_app()
        _app.dependency_overrides[require_auth] = lambda: None
    return _app


def _client() -> TestClient:
    # raise_server_exceptions=False: a real 500 must arrive as HTTP 500, not
    # as a re-raised exception that would mask which route crashed.
    return TestClient(_the_app(), raise_server_exceptions=False)


def _clean(response) -> None:
    """The body decoded, carries no lone surrogate, and re-encodes as UTF-8."""
    text = response.text
    assert "\ud800" not in text, text[:300]
    text.encode("utf-8")


def _wait_finished(tid: str, timeout: float = 20.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        row = jobs._jobs.get(tid) or {}
        if isinstance(row, dict) and not row.get("running"):
            return row
        time.sleep(0.05)
    raise AssertionError(f"job {tid!r} did not finish")


class _SelfStrEncodeBomb(str):
    """``str()`` hands this back uncopied; the bound ``encode`` then raises.

    The exact shape that used to blow ``jobs._utf8_text`` / ``config._env_text``
    from outside their nets.
    """

    def __str__(self):
        return self

    def encode(self, *a, **k):  # noqa: D102
        raise RuntimeError("leftover encode bomb")


class _BoolBombStr(str):
    def __bool__(self):
        raise RuntimeError("leftover bool bomb id")


class _HashBombStr(str):
    def __hash__(self):
        raise RuntimeError("leftover hash bomb id")


class _DecodeBombBytes(bytes):
    def decode(self, *a, **k):  # noqa: D102
        raise RuntimeError("leftover decode bomb")


class _StrBomb:
    """Plain ``__str__`` bomb — the neighbour the existing net already drops."""

    def __str__(self):
        raise RuntimeError("leftover str bomb")


class _DiskYamlSandbox(unittest.TestCase):
    """One plain task on the REAL config path — the request walks
    disk → load_yaml_int_capped → _as_config → route, like maint4/maint5."""

    YAML_TEXT = "maintenance:\n  - id: plain\n    name: Plain\n    command: 'true'\n    timeout: 10\n"

    def setUp(self):
        try:
            self._original = config.YAML_PATH.read_bytes()
        except FileNotFoundError:
            self._original = None
        config.YAML_PATH.parent.mkdir(parents=True, exist_ok=True)
        config.YAML_PATH.write_text(self.YAML_TEXT, encoding="utf-8")
        config.reload_cfg()
        self.addCleanup(self._restore)
        jobs._jobs.clear()
        self.addCleanup(jobs._jobs.clear)

    def _restore(self):
        if self._original is None:
            try:
                config.YAML_PATH.unlink()
            except FileNotFoundError:
                pass
        else:
            config.YAML_PATH.write_bytes(self._original)
        config.reload_cfg()


class EncodeBombRowsHttpTests(_DiskYamlSandbox):
    """The fixed leak, job-row side: a self-``__str__`` encode-bomb value in
    a leftover ``_jobs`` row answered a raw HTTP 500 on the pre-fix tree."""

    def test_encode_bomb_finished_keeps_the_list_route_up(self):
        jobs._jobs["plain"] = {
            "running": False, "rc": 0, "log": [],
            "finished": _SelfStrEncodeBomb("12:00:00"),
        }
        response = _client().get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        row = next(r for r in response.json() if r["id"] == "plain")
        # The unbound scrub reads the real character storage.
        self.assertEqual(row["finished"], "12:00:00")

    def test_encode_bomb_started_keeps_the_log_route_up(self):
        jobs._jobs["plain"] = {
            "running": False, "rc": 0, "log": ["done"],
            "started": _SelfStrEncodeBomb("11:59:00"),
        }
        response = _client().get("/api/maintenance/plain/log")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        payload = response.json()
        self.assertEqual(payload["started"], "11:59:00")
        self.assertEqual(payload["log"], "done")

    def test_encode_bomb_log_line_still_serves(self):
        # str.join reads C-level storage, so the joined text is exact — but
        # the joined *result* then rides _jsonable's str branch; pre-fix a
        # bomb line only survived because join copies.  Pin the whole trip.
        jobs._jobs["plain"] = {
            "running": False, "rc": 0,
            "log": [_SelfStrEncodeBomb("line one"), "line two"],
        }
        response = _client().get("/api/maintenance/plain/log")
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertEqual(response.json()["log"], "line one\nline two")

    def test_decode_bomb_bytes_log_line_stays_immune(self):
        # Stays-immune: _log_lines already decodes through the unbound base.
        jobs._jobs["plain"] = {
            "running": False, "rc": 0, "log": [_DecodeBombBytes(b"raw"), "ok"],
        }
        response = _client().get("/api/maintenance/plain/log")
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertEqual(response.json()["log"], "raw\nok")

    def test_plain_str_bomb_value_stays_dropped(self):
        # Stays-immune: a __str__ bomb that does NOT return self was already
        # caught by the net and degrades to "".
        jobs._jobs["plain"] = {
            "running": False, "rc": 0, "log": [], "finished": _StrBomb(),
        }
        response = _client().get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        row = next(r for r in response.json() if r["id"] == "plain")
        self.assertEqual(row["finished"], "")

    def test_utf8_text_returns_an_exact_str_for_subclass_input(self):
        out = jobs._utf8_text(_SelfStrEncodeBomb("abc"))
        self.assertIs(type(out), str)
        self.assertEqual(out, "abc")
        # A subclass carrying a lone surrogate is scrubbed, not re-raised.
        out = jobs._utf8_text(_SelfStrEncodeBomb("a\ud800b"))
        self.assertIs(type(out), str)
        self.assertEqual(out, "a?b")


class EncodeBombConfigHttpTests(_DiskYamlSandbox):
    """The fixed leak, cfg-snapshot side: an encode-bomb task id or name in a
    poisoned in-process cfg cache 500'd the list AND the run route (which
    walks maintenance_tasks() before matching the id)."""

    POISONED = {
        "maintenance": [
            {"id": _SelfStrEncodeBomb("enc-id"), "command": "echo enc-ok",
             "name": _SelfStrEncodeBomb("Enc name"), "timeout": 10},
            {"id": "sib", "command": "true"},
        ]
    }

    def test_encode_bomb_id_and_name_keep_the_list_route_up(self):
        with mock.patch.object(jobs, "cfg", return_value=self.POISONED):
            response = _client().get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        rows = {r["id"]: r for r in response.json()}
        # The unbound scrub keeps the real content, so the task survives
        # alongside its sibling instead of costing the whole route.
        self.assertEqual(sorted(rows), ["enc-id", "sib"])
        self.assertEqual(rows["enc-id"]["name"], "Enc name")

    def test_the_listed_encode_bomb_id_is_runnable_and_loggable(self):
        client = _client()
        with mock.patch.object(jobs, "cfg", return_value=self.POISONED):
            response = client.post("/api/maintenance/enc-id/run")
            self.assertEqual(response.status_code, 200, response.text[:300])
            self.assertEqual(response.json(), {"ok": True, "message": "Task started"})
            _wait_finished("enc-id")
        response = client.get("/api/maintenance/enc-id/log")
        self.assertEqual(response.status_code, 200, response.text[:300])
        payload = response.json()
        self.assertEqual(payload["rc"], 0)
        self.assertIn("enc-ok", payload["log"])


class SubclassIdStartJobTests(_DiskYamlSandbox):
    """The fixed leak, start_job side: a str-subclass id whose ``__bool__``
    or ``__hash__`` raised blew the emptiness probe / the ``_jobs`` insert
    straight into the calling route (tools_svc hands start_job its own
    dicts)."""

    def test_bool_bomb_id_runs_under_the_scrubbed_key(self):
        jobs.start_job({"id": _BoolBombStr("bb"), "command": "echo bb-ok", "timeout": 10})
        row = _wait_finished("bb")
        self.assertEqual(row.get("rc"), 0)
        self.assertIn("bb-ok", row.get("log"))

    def test_hash_bomb_id_runs_under_the_scrubbed_key(self):
        jobs.start_job({"id": _HashBombStr("hb"), "command": "echo hb-ok", "timeout": 10})
        row = _wait_finished("hb")
        self.assertEqual(row.get("rc"), 0)

    def test_encode_bomb_id_runs_under_the_scrubbed_key(self):
        jobs.start_job({"id": _SelfStrEncodeBomb("eb"), "command": "echo eb-ok", "timeout": 10})
        row = _wait_finished("eb")
        self.assertEqual(row.get("rc"), 0)
        # The mapping key is the exact-str scrub — pollable by plain text.
        self.assertIn("eb", jobs._jobs)
        self.assertIs(type(next(iter(k for k in jobs._jobs if k == "eb"))), str)

    def test_whitespace_only_id_still_drops_cleanly(self):
        # The scrub must not have loosened the emptiness probe.
        self.assertIsNone(jobs.start_job({"id": _SelfStrEncodeBomb(""), "command": "true"}))
        self.assertEqual(jobs._jobs, {})


class EnvTextBombTests(_DiskYamlSandbox):
    """The fixed leak, env side: ``config._env_text``'s bound ``decode`` /
    ``encode`` let a bomb entry in ``maintenance_env`` kill the job thread
    before its try block instead of degrading that one entry."""

    def test_env_text_neutralizes_the_bomb_family(self):
        # Unbound base decode reads the real byte storage.
        self.assertEqual(config._env_text(_DecodeBombBytes(b"v")), "v")
        out = config._env_text(_SelfStrEncodeBomb("w"))
        self.assertEqual(out, "w")
        self.assertIs(type(out), str)
        # The plain __str__ bomb neighbour stays dropped.
        self.assertEqual(config._env_text(_StrBomb()), "")

    def test_maintenance_env_degrades_per_entry(self):
        poisoned = {
            "settings": {
                "maintenance_env": {
                    "MAINT6_OK": "yes",
                    _SelfStrEncodeBomb("MAINT6_BOMB"): _DecodeBombBytes(b"v"),
                    "MAINT6_JUNK": _StrBomb(),
                }
            }
        }
        with mock.patch.object(config, "cfg", return_value=poisoned):
            env = config.maintenance_env()
        self.assertEqual(env["MAINT6_OK"], "yes")
        self.assertEqual(env["MAINT6_BOMB"], "v")
        self.assertEqual(env["MAINT6_JUNK"], "")
        for key, value in env.items():
            self.assertIs(type(key), str)
            self.assertIs(type(value), str)

    def test_run_route_survives_a_poisoned_maintenance_env(self):
        # The whole cycle: POST run merges the poisoned env in the job
        # thread; the command must still execute and see the good entry.
        poisoned = {
            "maintenance": [
                {"id": "plain", "name": "Plain",
                 "command": 'echo "env=$MAINT6_OK"', "timeout": 10},
            ],
            "settings": {
                "maintenance_env": {
                    "MAINT6_OK": "yes",
                    _SelfStrEncodeBomb("MAINT6_BOMB"): _DecodeBombBytes(b"v"),
                }
            },
        }
        with mock.patch.object(jobs, "cfg", return_value=poisoned), \
                mock.patch.object(config, "cfg", return_value=poisoned):
            response = _client().post("/api/maintenance/plain/run")
            self.assertEqual(response.status_code, 200, response.text[:300])
            row = _wait_finished("plain")
        self.assertEqual(row.get("rc"), 0)
        self.assertIn("env=yes", "\n".join(row.get("log")))


if __name__ == "__main__":
    unittest.main()
