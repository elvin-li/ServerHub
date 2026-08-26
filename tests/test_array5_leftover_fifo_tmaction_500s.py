"""Fifth leftover sweep of the Main Array page's backend: FIFOs and the TM verb.

The hunted classes (sibling vanished-CLI lies, plist ExpatError, leftover
FIFOs, iterbombs, non-str in-process arguments) were re-reproduced over the
real mounted app (``create_app()``, ``TestClient`` with
``raise_server_exceptions=False``) against every route the Main Array /
RAID / diskutil surfaces answer.  The vanished-CLI, plist and iterbomb
classes were found sealed by the array2/3/4 and nas3/4 and pool5 sweeps.
Two live leftovers survived, both fixed alongside this file:

* ``usage_svc._hash_file`` still opened candidates with a plain
  ``open(path, "rb")``.  The duplicate scanner's walk only queues regular
  files, but the hash stages run *after* the whole walk finished, and a
  leftover FIFO occupying a candidate path by then parked the open() until
  a writer appeared — hanging a fan_out worker and
  GET /api/storage/usage/duplicates with it, past every budget (the
  deadline cannot fire inside a blocked syscall).  files_svc fixed this
  exact class for its own reads (O_NONBLOCK + the S_ISREG refusal); the
  usage explorer missed it.  A non-regular occupant now costs its own
  hash, exactly like an unreadable file, never the request.
* ``snapshots_svc.time_machine_action`` still spelled the verb
  ``(action or "").strip().lower()``: a leftover non-str in-process action
  AttributeError'd (a 500) where the coded ``bad_action`` refusal is the
  contract — the raid_svc._req_text / smart_test_svc._schedule_text
  convention this module already applies to delete_snapshot's token, and
  the exact class the array3 sweep fixed in disk_manage_svc.disk_action,
  disk_power_svc.disk_power_action and smart_test_svc.set_schedule.

The rest pins the stays-immune corners at the HTTP layer: a leftover FIFO
sitting in a scanned tree costs nothing on tree/largest/duplicates, and the
Time Machine route keeps its coded 400 for hostile verb strings.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import tempfile
import threading
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from hub import snapshots_svc, usage_svc  # noqa: E402
from hub.routers import nas_common, nas_storage  # noqa: E402

#: Built arithmetically: int("9" * 5000) itself trips the parse cap.
_HUGE_INT = 10 ** 5000

_APP = None


def _client():
    global _APP
    from fastapi.testclient import TestClient

    if _APP is None:
        from hub.app_factory import create_app
        from hub.auth import require_auth

        _APP = create_app()
        _APP.dependency_overrides[require_auth] = lambda: True
    return TestClient(_APP, raise_server_exceptions=False)


def _starlette(payload) -> None:
    """What Starlette's JSONResponse does: ensure_ascii=False then UTF-8."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


def _admin_browser(stack: ExitStack) -> None:
    """An administrator browser session, as nas_common resolves one."""
    stack.enter_context(mock.patch.object(
        nas_common.auth, "browser_authenticated", return_value=True))
    stack.enter_context(mock.patch.object(
        nas_common.auth, "request_username", return_value="admin"))
    stack.enter_context(mock.patch.object(
        nas_common.auth, "is_admin", return_value=True))
    stack.enter_context(mock.patch.object(
        nas_common.auth, "request_client_id", return_value="127.0.0.1"))
    stack.enter_context(mock.patch.object(
        nas_storage.audit, "record", lambda *a, **k: {}))


def _watchdog(fn, timeout: float = 10.0):
    """Run *fn* on a reaper-safe thread; fail the test instead of hanging it.

    The pre-fix FIFO leftover parks the caller in an ``open()`` syscall
    forever, so a plain call would hang the whole test run rather than
    fail it.
    """
    box: dict = {}

    def run():
        try:
            box["value"] = fn()
        except BaseException as exc:  # noqa: BLE001 — re-raised below
            box["error"] = exc

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    thread.join(timeout)
    if thread.is_alive():
        raise AssertionError(
            f"call hung past {timeout:.0f}s — the pre-fix FIFO park")
    if "error" in box:
        raise box["error"]
    return box["value"]


class HashFileLeftoverFifoTests(unittest.TestCase):
    """_hash_file must refuse a non-regular occupant, never block on it."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="array5-fifo-"))
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)

    def test_leftover_fifo_costs_its_own_hash_not_the_request(self):
        """Pre-fix: open() of the FIFO blocked until a writer appeared,
        parking the fan_out worker (and the duplicates request) forever."""
        fifo = self.dir / "leftover.fifo"
        os.mkfifo(fifo)
        for partial in (True, False):
            self.assertIsNone(
                _watchdog(lambda p=partial: usage_svc._hash_file(fifo, partial=p),
                          timeout=5.0))

    def test_regular_file_still_hashes_both_stages(self):
        """The O_NONBLOCK flag changes nothing for a regular file's read."""
        blob = b"x" * (usage_svc._HASH_CHUNK + 17)
        path = self.dir / "a.bin"
        path.write_bytes(blob)
        self.assertEqual(
            usage_svc._hash_file(path, partial=True),
            hashlib.sha256(blob[:usage_svc._HASH_CHUNK]).hexdigest(),
        )
        self.assertEqual(
            usage_svc._hash_file(path, partial=False),
            hashlib.sha256(blob).hexdigest(),
        )

    def test_symlink_swapped_in_after_the_walk_is_refused(self):
        """The walk never follows symlinks; one swapped in over the
        walk-to-hash window must not smuggle another file's bytes in."""
        target = self.dir / "real.bin"
        target.write_bytes(b"y" * 4096)
        link = self.dir / "swap.bin"
        os.symlink(target, link)
        self.assertIsNone(usage_svc._hash_file(link, partial=True))

    def test_vanished_and_unencodable_names_stay_none(self):
        self.assertIsNone(
            usage_svc._hash_file(self.dir / "gone.bin", partial=True))
        # Leftover lone surrogate in a FUSE name: os.open encodes strictly.
        self.assertIsNone(
            usage_svc._hash_file(self.dir / "bad\ud800name", partial=True))


class DuplicatesRouteFifoTests(unittest.TestCase):
    """GET /api/storage/usage/duplicates over the real mounted app."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="array5-dup-"))
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)

    def _get(self, sink):
        def fake_walk(target, budget, make_sink, on_file, **kw):
            return [sink]

        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                usage_svc, "_resolve", return_value=self.dir))
            stack.enter_context(mock.patch.object(
                usage_svc, "_walk_parallel", fake_walk))
            return _watchdog(
                lambda: _client().get("/api/storage/usage/duplicates"),
                timeout=15.0,
            )

    def test_fifo_candidate_drops_alone_and_the_group_survives(self):
        """A leftover FIFO occupying a candidate path by hash time must
        cost its own hash only.  Pre-fix the request parked on the plain
        open() forever — no budget could fire inside the blocked syscall."""
        blob = os.urandom(1024) * 1024  # 1 MiB, over the duplicate floor
        a = self.dir / "a.bin"
        b = self.dir / "b.bin"
        a.write_bytes(blob)
        b.write_bytes(blob)
        fifo = self.dir / "swapped.fifo"
        os.mkfifo(fifo)
        size = len(blob)
        resp = self._get({size: [str(a), str(b), str(fifo)]})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["group_count"], 1)
        group = body["groups"][0]
        self.assertEqual(group["count"], 2)
        self.assertEqual(sorted(group["paths"]), sorted([str(a), str(b)]))
        self.assertEqual(body["reclaimable_bytes"], size)

    def test_all_candidates_fifos_answers_the_empty_report(self):
        f1 = self.dir / "one.fifo"
        f2 = self.dir / "two.fifo"
        os.mkfifo(f1)
        os.mkfifo(f2)
        resp = self._get({2 * 1024 * 1024: [str(f1), str(f2)]})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["group_count"], 0)
        self.assertEqual(body["reclaimable_bytes"], 0)


class UsageWalkFifoStaysImmuneTests(unittest.TestCase):
    """A FIFO sitting in the scanned tree itself was already skipped by the
    walk (``entry.is_file`` refuses it); pinned so it stays that way."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="array5-tree-"))
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        (self.dir / "data.bin").write_bytes(b"z" * 2048)
        os.mkfifo(self.dir / "leftover.fifo")

    def _get(self, url):
        with mock.patch.object(usage_svc, "_resolve", return_value=self.dir):
            return _watchdog(lambda: _client().get(url), timeout=15.0)

    def test_tree_renders_around_the_fifo(self):
        resp = self._get("/api/storage/usage/tree")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        names = {c["name"] for c in body["children"]}
        self.assertIn("data.bin", names)
        self.assertNotIn("leftover.fifo", names)

    def test_largest_renders_around_the_fifo(self):
        resp = self._get("/api/storage/usage/largest")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual([i["name"] for i in body["items"]], ["data.bin"])

    def test_duplicates_real_walk_skips_the_fifo(self):
        resp = self._get("/api/storage/usage/duplicates")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["group_count"], 0)


class TimeMachineActionProbeTests(unittest.TestCase):
    """time_machine_action must refuse a non-str verb, never AttributeError."""

    def test_non_str_leftovers_earn_the_coded_refusal(self):
        """Pre-fix: ``(action or "").strip()`` AttributeError'd (a 500 for
        in-process callers) on every one of these."""
        for probe in (_HUGE_INT, 5, ["start"], {"a": 1}, None, True):
            with self.subTest(probe=type(probe).__name__):
                result = snapshots_svc.time_machine_action(probe)
                self.assertEqual(
                    result, {"ok": False, "error": "bad_action"})
                _starlette(result)

    def test_a_valid_verb_still_reaches_run_admin_unchanged(self):
        with (
            mock.patch.object(
                snapshots_svc, "run_admin",
                return_value={"ok": True}) as admin,
            mock.patch.object(snapshots_svc, "invalidate", lambda: None),
        ):
            result = snapshots_svc.time_machine_action("  Start ")
        self.assertIs(result["ok"], True)
        admin.assert_called_once_with(
            [snapshots_svc.TMUTIL, "startbackup"], timeout=180)

    def test_junk_strings_keep_the_coded_refusal(self):
        for probe in ("", "reboot", "9" * 5000):
            with self.subTest(probe=probe[:12]):
                self.assertEqual(
                    snapshots_svc.time_machine_action(probe),
                    {"ok": False, "error": "bad_action"})


class TimeMachineRouteStaysImmuneTests(unittest.TestCase):
    """POST /api/timemachine/action over the real mounted app."""

    def _post(self, action):
        with ExitStack() as stack:
            _admin_browser(stack)
            stack.enter_context(mock.patch.object(
                nas_storage.snapshots_svc, "run_admin",
                return_value={"ok": True}))
            # Raw bytes, not the json= kwarg: httpx encodes ensure_ascii=False
            # and refuses a lone surrogate before it ever leaves the client,
            # while the \\uXXXX-escaped form rides plain ASCII and the
            # *server's* JSON decoder is the one that materializes it.
            return _client().post(
                "/api/timemachine/action",
                content=json.dumps(
                    {"action": action}, ensure_ascii=True).encode("ascii"),
                headers={"content-type": "application/json"},
            )

    def test_huge_digit_verb_is_the_coded_400(self):
        resp = self._post("9" * 5000)
        self.assertEqual(resp.status_code, 400, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["detail"]["code"], "snapshot.bad_action")

    def test_lone_surrogate_verb_is_the_coded_400_and_utf8_clean(self):
        resp = self._post("sta\ud800rt")
        self.assertEqual(resp.status_code, 400, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["detail"]["code"], "snapshot.bad_action")
        self.assertNotIn("\ud800", resp.text)

    def test_a_valid_verb_still_answers_ok(self):
        resp = self._post("stop")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertIs(body["ok"], True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
