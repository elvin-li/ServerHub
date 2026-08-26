"""Ninth leftover-500s sweep of the Files page, over the real mounted app.

The known zoo (dict/list-subclass bombs, unbound-int bombs, huge-int JSON
bodies, FIFO/socket/surrogate/symlink-loop filesystem leftovers, plist
ExpatError/AttributeError/IndexError, vanished-binary spawns, deep trees)
was re-driven through ``create_app()`` + ``TestClient(
raise_server_exceptions=False)`` against every mounted Files route.  Five
live leftovers were found and fixed:

* **A failing disk write mid-upload was a raw 500.**  ``OSError`` out of
  ``f.write`` (ENOSPC on a full volume, EIO on a dying FUSE/SMB mount)
  matched none of ``upload()``'s except arms: the cleanup arm re-raised it
  uncoded, so POST /api/files/upload answered a bare ``Internal Server
  Error`` after validation had already passed.  Now the coded 503
  ``files.upload_write_failed`` (the compose.save_failed shape: a disk
  that cannot be written is a dependency state, not an input defect).

* **ENOSPC at the flush-inside-close was the same raw 500 — and left the
  torn file behind.**  The final ``f.close()`` sat *outside* the guarded
  region, so the buffered tail's write error skipped the unlink cleanup
  entirely: the route 500'd raw and the partial upload stayed on disk as
  a plausible-looking file.  The close now lives inside the guarded
  region; both failures answer the coded 503 with the partial removed.

* **A roots list-subclass ``__iter__`` bomb 500'd every Files route.**
  ``settings_section()`` launders the section mapping but not the values
  inside it, so a leftover ``roots`` list subclass whose ``__iter__``
  raises blew up ``for r in custom`` in ``default_roots()`` — which
  ``_resolve_safe()`` runs first for *every* list/download/upload/mkdir/
  rename/delete call, plus GET /api/files itself.

* **The same list's ``__len__`` bomb 500'd through the truthiness test.**
  ``if isinstance(custom, list) and custom:`` calls ``__len__`` on a list
  subclass.  Both are now materialised once under a guard and degrade to
  the default root candidates, like an absent key.

* **A ``show_hidden`` ``__bool__`` bomb / ``max_upload_mb`` int-subclass
  ``__int__`` bomb 500'd list and upload.**  ``bool(...)`` raised out of
  ``list_dir()`` after the directory was already read, and ``int(...)``
  inside ``_finite_int`` only caught the (TypeError, ValueError,
  OverflowError, OSError) conversion failures — a bombing ``__int__`` /
  ``__index__`` (the modules5 class) escaped and 500'd the upload.

The stays-immune batteries pin neighbours probed and found already coded:
bombing dict rows and row values inside roots, huge-int JSON bodies (the
``json.loads`` ValueError-not-JSONDecodeError class), and leftover unix
sockets in a browsable root.
"""
from __future__ import annotations

import os
import shutil
import socket as socketmod
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from hub import files_svc
from hub.app_factory import create_app
from hub.auth import require_auth

_client = None


def client() -> TestClient:
    global _client
    if _client is None:
        app = create_app()
        app.dependency_overrides[require_auth] = lambda: None
        # The SPA's failure mode is what is under test, not exception
        # propagation into the test process.
        _client = TestClient(app, raise_server_exceptions=False)
    return _client


def _assert_clean(test: unittest.TestCase, resp) -> None:
    """The body must be strictly renderable UTF-8 with no lone surrogates."""
    text = resp.text
    test.assertFalse(
        any("\ud800" <= ch <= "\udfff" for ch in text),
        "lone surrogate survived into the HTTP body",
    )
    text.encode("utf-8")


def _code(test: unittest.TestCase, resp) -> str:
    """The machine-readable error code — a raw 500 body has none."""
    _assert_clean(test, resp)
    try:
        detail = resp.json()["detail"]
    except (ValueError, KeyError, TypeError):
        test.fail(f"uncoded body: {resp.status_code} {resp.text[:200]!r}")
    test.assertIsInstance(detail, dict, f"uncoded detail: {detail!r}")
    return detail.get("code", "")


# ── The leftover bomb classes (the bookmarks5 / modules5 shapes) ─────────────

class IterBombList(list):
    def __iter__(self):
        raise RuntimeError("iter bomb")


class LenBombList(list):
    def __len__(self):
        raise RuntimeError("len bomb")


class GetBombRow(dict):
    def get(self, *a, **k):
        raise RuntimeError("get bomb")


class BoolBomb:
    def __bool__(self):
        raise RuntimeError("bool bomb")


class IntBomb(int):
    def __index__(self):
        raise RuntimeError("index bomb")

    def __int__(self):
        raise RuntimeError("int bomb")

    def __str__(self):
        raise RuntimeError("str bomb")


class _FilesSandbox(unittest.TestCase):
    """One temp browsable root, patched in as the only configured root.

    ``settings_section`` is patched with a *plain dict* carrying the bombs:
    that models the real laundering exactly — the section mapping is
    re-dicted by hub.config, but the values inside it are the original
    leftover objects.
    """

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.root = self.tmp / "root"
        self.root.mkdir()
        self.settings = {"roots": [{"id": "r", "path": str(self.root)}]}
        patched = mock.patch.object(
            files_svc, "settings_section", side_effect=lambda *_: self.settings
        )
        patched.start()
        self.addCleanup(patched.stop)

    def _upload(self, name: str = "probe.bin", body: bytes = b"hello world"):
        return client().post(
            "/api/files/upload",
            data={"path": str(self.root), "root_id": "r"},
            files={"file": (name, body)},
        )


# ── Fixed leak 1+2: OSError out of the upload write / flush-at-close ────────

class _WriteBomb:
    """A file object whose write raises; close still closes the raw file."""

    def __init__(self, f, err):
        self._f = f
        self._err = err

    def write(self, data):
        raise self._err

    def close(self):
        self._f.close()


class _CloseBomb:
    """BufferedWriter semantics for a flush failure at close: the raw file
    is closed even though close() raises, and a second close() is a no-op."""

    def __init__(self, f, err):
        self._f = f
        self._err = err
        self._raised = False

    def write(self, data):
        return self._f.write(data)

    def close(self):
        if not self._raised:
            self._raised = True
            self._f.close()
            raise self._err


class UploadDiskWriteFailureTests(_FilesSandbox):
    """The fixed leak: a failing disk write answers the coded 503, clean.

    On the pre-fix tree every one of these answered a raw uncoded
    ``Internal Server Error``, and the flush-at-close case additionally
    left the torn partial file on disk.
    """

    def _post_with_fdopen(self, wrapper, err):
        real_fdopen = os.fdopen

        def fdopen(fd, *a, **k):
            return wrapper(real_fdopen(fd, *a, **k), err)

        with mock.patch.object(files_svc.os, "fdopen", side_effect=fdopen):
            return self._upload()

    def _assert_coded_503(self, resp):
        self.assertEqual(resp.status_code, 503, resp.text[:300])
        self.assertEqual(_code(self, resp), "files.upload_write_failed")
        detail = resp.json()["detail"]
        self.assertNotIn("{error}", detail["message"])
        self.assertFalse(
            (self.root / "probe.bin").exists(),
            "the torn partial upload was left on disk",
        )

    def test_enospc_during_write_is_the_coded_503_not_a_raw_500(self):
        resp = self._post_with_fdopen(
            _WriteBomb, OSError(28, "No space left on device")
        )
        self._assert_coded_503(resp)

    def test_eio_during_write_is_the_coded_503(self):
        resp = self._post_with_fdopen(_WriteBomb, OSError(5, "Input/output error"))
        self._assert_coded_503(resp)

    def test_enospc_at_the_flush_inside_close_is_the_coded_503(self):
        # The buffered tail's write error surfaces at close(); pre-fix this
        # skipped the unlink cleanup entirely.
        resp = self._post_with_fdopen(
            _CloseBomb, OSError(28, "No space left on device")
        )
        self._assert_coded_503(resp)

    def test_unlink_also_failing_on_the_dying_mount_stays_coded(self):
        real_fdopen = os.fdopen

        def fdopen(fd, *a, **k):
            return _WriteBomb(real_fdopen(fd, *a, **k), OSError(5, "io"))

        with (
            mock.patch.object(files_svc.os, "fdopen", side_effect=fdopen),
            mock.patch.object(
                Path, "unlink", side_effect=OSError(5, "io"), autospec=True
            ),
        ):
            resp = self._upload()
        self.assertEqual(resp.status_code, 503, resp.text[:300])
        self.assertEqual(_code(self, resp), "files.upload_write_failed")

    def test_happy_path_upload_still_lands_intact(self):
        resp = self._upload(body=b"payload bytes")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _assert_clean(self, resp)
        self.assertEqual((self.root / "probe.bin").read_bytes(), b"payload bytes")

    def test_upload_too_large_is_still_the_coded_400_with_cleanup(self):
        self.settings["max_upload_mb"] = 1
        resp = self._upload(name="big.bin", body=b"z" * (2 * 1024 * 1024))
        self.assertEqual(resp.status_code, 400, resp.text[:300])
        self.assertEqual(_code(self, resp), "files.upload_too_large")
        self.assertFalse((self.root / "big.bin").exists())


# ── Fixed leaks 3+4: roots list-subclass __iter__ / __len__ bombs ───────────

class RootsListSubclassBombTests(_FilesSandbox):
    """The fixed leak: a bombing roots list degrades to the default roots.

    Pre-fix, every route 500'd raw because _resolve_safe() runs
    default_roots() first — the whole Files page was down, not one row.
    """

    def _set_roots(self, bomb):
        self.settings["roots"] = bomb

    def test_iter_bomb_roots_list_answers_a_coded_response_not_a_500(self):
        self._set_roots(IterBombList([{"id": "r", "path": str(self.root)}]))
        resp = client().get("/api/files/list")
        _assert_clean(self, resp)
        self.assertLess(resp.status_code, 500, resp.text[:300])
        if resp.status_code != 200:
            self.assertEqual(_code(self, resp), "files.no_roots")

    def test_iter_bomb_roots_list_keeps_the_overview_rendering(self):
        self._set_roots(IterBombList([{"id": "r", "path": str(self.root)}]))
        resp = client().get("/api/files")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _assert_clean(self, resp)
        self.assertIsInstance(resp.json()["roots"], list)

    def test_len_bomb_roots_list_answers_a_coded_response_not_a_500(self):
        self._set_roots(LenBombList([{"id": "r", "path": str(self.root)}]))
        resp = client().get("/api/files/list")
        _assert_clean(self, resp)
        self.assertLess(resp.status_code, 500, resp.text[:300])

    def test_iter_bomb_does_not_take_down_the_write_routes_either(self):
        self._set_roots(IterBombList([{"id": "r", "path": str(self.root)}]))
        resp = client().post(
            "/api/files/mkdir",
            json={"path": str(self.root), "name": "x", "root_id": "r"},
        )
        _assert_clean(self, resp)
        self.assertLess(resp.status_code, 500, resp.text[:300])

    def test_unit_default_roots_survives_both_bombs(self):
        for bomb in (IterBombList(), LenBombList()):
            self.settings["roots"] = bomb
            self.assertIsInstance(files_svc.default_roots(), list)


# ── Fixed leak 5: show_hidden __bool__ / max_upload_mb __int__ bombs ─────────

class SettingsValueBombTests(_FilesSandbox):
    def test_bool_bomb_show_hidden_keeps_the_listing_rendering(self):
        (self.root / "visible.txt").write_text("x")
        (self.root / ".hidden.txt").write_text("y")
        self.settings["show_hidden"] = BoolBomb()
        resp = client().get(
            "/api/files/list", params={"path": str(self.root), "root_id": "r"}
        )
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _assert_clean(self, resp)
        names = [i["name"] for i in resp.json()["items"]]
        # The bomb degrades to the default (hidden files omitted).
        self.assertIn("visible.txt", names)
        self.assertNotIn(".hidden.txt", names)

    def test_int_bomb_max_upload_mb_keeps_uploads_working(self):
        self.settings["max_upload_mb"] = IntBomb(5)
        resp = self._upload(body=b"x")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _assert_clean(self, resp)
        self.assertTrue((self.root / "probe.bin").is_file())

    def test_unit_finite_int_drops_the_bomb_to_the_default(self):
        self.assertEqual(files_svc._finite_int(IntBomb(5), 7), 7)

    def test_unit_max_upload_mb_falls_back_to_512_on_the_bomb(self):
        self.settings["max_upload_mb"] = IntBomb(5)
        self.assertEqual(files_svc._max_upload_mb(), 512)


# ── Stays-immune pins: neighbours probed and found already coded ────────────

class BombRowsStayImmuneTests(_FilesSandbox):
    """Bombing rows and row values inside a plain roots list stay coded."""

    def test_get_bomb_row_is_skipped_and_the_good_row_serves(self):
        self.settings["roots"] = [
            GetBombRow({"id": "bad", "path": str(self.root)}),
            {"id": "r", "path": str(self.root)},
        ]
        resp = client().get("/api/files/list", params={"root_id": "r"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _assert_clean(self, resp)

    def test_bomb_id_and_name_values_degrade_to_the_basename(self):
        self.settings["roots"] = [
            {"id": IntBomb(5), "name": IntBomb(6), "path": str(self.root)},
        ]
        resp = client().get("/api/files")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _assert_clean(self, resp)
        roots = resp.json()["roots"]
        self.assertEqual(len(roots), 1)
        self.assertEqual(roots[0]["id"], self.root.name)

    def test_bomb_path_value_drops_the_row(self):
        self.settings["roots"] = [{"id": "r", "path": IntBomb(5)}]
        resp = client().get("/api/files/list")
        _assert_clean(self, resp)
        self.assertEqual(resp.status_code, 400, resp.text[:300])
        self.assertEqual(_code(self, resp), "files.no_roots")


class HugeIntJsonBodyStaysImmuneTests(_FilesSandbox):
    """A >4300-digit int in the request JSON raises bare ValueError (not
    JSONDecodeError) out of ``json.loads``; the app-level parse guard must
    keep answering 4xx, never a raw 500."""

    def _raw(self, route: str, body: str):
        return client().post(
            route, content=body, headers={"content-type": "application/json"}
        )

    def test_huge_int_bodies_are_the_parser_4xx_on_every_write_route(self):
        big = "1" * 5000
        for route, body in [
            ("/api/files/delete", '{"path": %s}' % big),
            ("/api/files/mkdir", '{"path": "/x", "name": %s}' % big),
            ("/api/files/rename", '{"path": %s, "new_name": "x"}' % big),
            ("/api/files/delete", '{"path": "/x", "root_id": %s}' % big),
        ]:
            resp = self._raw(route, body)
            _assert_clean(self, resp)
            self.assertLess(resp.status_code, 500, f"{route}: {resp.text[:200]}")
            self.assertGreaterEqual(resp.status_code, 400)


class UnixSocketLeftoverStaysImmuneTests(_FilesSandbox):
    """A leftover unix socket in a browsable root: coded answers, no hangs."""

    def _bind(self) -> Path:
        sockpath = self.root / "leftover.sock"
        s = socketmod.socket(socketmod.AF_UNIX)
        self.addCleanup(s.close)
        s.bind(str(sockpath))
        return sockpath

    def test_listing_a_root_holding_a_socket_renders(self):
        self._bind()
        resp = client().get(
            "/api/files/list", params={"path": str(self.root), "root_id": "r"}
        )
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _assert_clean(self, resp)

    def test_downloading_the_socket_is_a_coded_answer_not_a_hang(self):
        sockpath = self._bind()
        resp = client().get(
            "/api/files/download",
            params={"path": str(sockpath), "root_id": "r"},
        )
        _assert_clean(self, resp)
        self.assertIn(resp.status_code, (400, 403), resp.text[:300])
        self.assertIn(
            _code(self, resp), ("files.file_only", "files.permission_denied")
        )

    def test_deleting_the_socket_succeeds_without_opening_it(self):
        sockpath = self._bind()
        resp = client().post(
            "/api/files/delete", json={"path": str(sockpath), "root_id": "r"}
        )
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertFalse(sockpath.exists())


if __name__ == "__main__":
    unittest.main()
