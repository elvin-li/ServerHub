"""Eighth leftover-500s sweep of the Files page, over the real mounted app.

The hunted classes (deep-tree iterbombs, leftover FIFOs, UTF-8 surrogates,
over-cap ints, torn multiparts, vanished-path races) were re-driven through
``create_app()`` + ``TestClient(raise_server_exceptions=False)`` against
every mounted Files route.  Two live leftovers were found and fixed:

* **Deep-tree delete was a raw 500.**  CPython 3.12 ``shutil.rmtree``
  descends one Python frame per directory level, so POST /api/files/delete
  on a ~1000-deep tree — buildable one level at a time through
  POST /api/files/mkdir, or dropped by a runaway script or a tar bomb of
  relative paths — raised RecursionError mid-walk.  RecursionError is not
  OSError, so it escaped ``delete_path()``'s except arms and answered a raw
  ``Internal Server Error`` after part of the tree was already gone; every
  retry 500'd the same way, leaving the tree undeletable through the panel.
  ``_rmtree_iterative()`` keeps shutil's safe-fd walk shape (``O_NOFOLLOW``
  descent via ``dir_fd``, parent fds held open) with an explicit stack.

* **The vanished-path 404 leaked its raw ``{path}`` placeholder.**
  ``delete_path()`` and ``rename_path()`` raised ``files.not_found`` bare,
  but the CODES template is ``"not found: {path}"`` — ``error_payload``'s
  KeyError fallback kept the literal placeholder in the message.  There is
  no ``err.files.not_found`` locale key, so that English fallback is
  exactly the string the SPA shows the operator.

The stays-immune batteries pin what was probed and found already coded:
FIFO write-op corners (rename / mkdir-under / upload-onto), filebrowser
status against over-cap and surrogate-bearing process listings, and the
multipart edges files7 did not reach (empty filename, file part without a
filename, a part with no Content-Disposition, and the 1000-field cap).
"""
from __future__ import annotations

import os
import shutil
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


class _FilesSandbox(unittest.TestCase):
    """One temp browsable root, patched in as the only configured root."""

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

    def _delete(self, path: str):
        return client().post(
            "/api/files/delete", json={"path": path, "root_id": "r"}
        )


class DeepTreeDeleteTests(_FilesSandbox):
    """The fixed leak: a tree deeper than the recursion limit deletes clean.

    On the pre-fix tree the first two cases answered a raw
    ``Internal Server Error`` (RecursionError escaping ``except OSError``)
    with part of the tree already unlinked.
    """

    def _grow(self, base: Path, depth: int) -> Path:
        cur = base
        for _ in range(depth):
            cur = cur / "a"
            os.mkdir(cur)
        return cur

    def test_1500_deep_tree_delete_is_ok_not_a_raw_500(self):
        self._grow(self.root, 1500)
        resp = self._delete(str(self.root / "a"))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _assert_clean(self, resp)
        self.assertTrue(resp.json()["ok"])
        self.assertFalse((self.root / "a").exists())

    def test_deep_tree_with_leaves_and_fifos_is_removed_without_a_hang(self):
        bottom = self._grow(self.root, 1200)
        (bottom / "leaf.txt").write_text("x")
        ((self.root / "a") / "shallow.txt").write_text("y")
        if hasattr(os, "mkfifo"):
            # A leftover FIFO mid-tree must be unlinked, never opened.
            os.mkfifo(bottom / "pipe.fifo")
        resp = self._delete(str(self.root / "a"))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertFalse((self.root / "a").exists())

    def test_the_mkdir_route_builds_such_trees_one_level_at_a_time(self):
        # Reachability: the deep tree is not a filesystem hypothetical —
        # this is exactly the loop a client (or a stuck SPA retry) runs.
        cur = self.root
        for _ in range(5):
            resp = client().post(
                "/api/files/mkdir",
                json={"path": str(cur), "name": "a", "root_id": "r"},
            )
            self.assertEqual(resp.status_code, 200, resp.text[:300])
            cur = cur / "a"
        self.assertTrue(cur.is_dir())
        resp = self._delete(str(self.root / "a"))
        self.assertEqual(resp.status_code, 200, resp.text[:300])

    def test_symlink_inside_the_tree_is_unlinked_not_followed(self):
        outside = self.tmp / "outside"
        outside.mkdir()
        canary = outside / "canary.txt"
        canary.write_text("keep me")
        d = self.root / "victim"
        sub = d / "sub"
        sub.mkdir(parents=True)
        (sub / "link").symlink_to(outside)
        resp = self._delete(str(d))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertFalse(d.exists())
        self.assertEqual(canary.read_text(), "keep me")

    def test_a_wide_directory_still_deletes(self):
        d = self.root / "wide"
        d.mkdir()
        for i in range(200):
            (d / f"f{i}.txt").write_text("x")
            if i % 20 == 0:
                (d / f"d{i}").mkdir()
        resp = self._delete(str(d))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertFalse(d.exists())

    @unittest.skipIf(os.geteuid() == 0, "root ignores directory modes")
    def test_unreadable_subdir_is_the_coded_403_and_leaks_no_fds(self):
        d = self.root / "locked"
        sub = d / "sub"
        sub.mkdir(parents=True)
        (sub / "inner.txt").write_text("x")
        os.chmod(sub, 0)
        self.addCleanup(os.chmod, sub, 0o755)
        fd_dir = Path("/proc/self/fd")
        before = len(list(fd_dir.iterdir())) if fd_dir.is_dir() else None
        resp = self._delete(str(d))
        self.assertEqual(resp.status_code, 403, resp.text[:300])
        self.assertEqual(_code(self, resp), "files.permission_denied")
        if before is not None:
            self.assertLessEqual(len(list(fd_dir.iterdir())), before)

    def test_service_level_walk_survives_the_recursion_limit(self):
        # Direct pin on the helper: at 1500 levels the old shutil.rmtree
        # call raised RecursionError from this exact call site.
        bottom = self._grow(self.root, 1500)
        (bottom / "leaf").write_text("x")
        files_svc._rmtree_iterative(self.root / "a")
        self.assertFalse((self.root / "a").exists())


class NotFoundInterpolationTests(_FilesSandbox):
    """The fixed leak: the 404 body carries the path, not ``{path}``.

    On the pre-fix tree these bodies read ``"not found: {path}"`` with no
    ``params`` — the raw template placeholder, verbatim, in the message the
    SPA shows (there is no err.files.not_found locale key to hide it).
    """

    def _assert_interpolated(self, resp, path: str):
        self.assertEqual(resp.status_code, 404, resp.text[:300])
        self.assertEqual(_code(self, resp), "files.not_found")
        detail = resp.json()["detail"]
        self.assertNotIn("{path}", detail["message"])
        self.assertEqual(detail["params"]["path"], path)
        self.assertIn(path, detail["message"])

    def test_delete_of_a_file_vanishing_mid_request_names_the_path(self):
        victim = self.root / "gone.txt"
        victim.write_text("x")
        orig_unlink = Path.unlink

        def racing_unlink(p, *a, **k):
            orig_unlink(p)
            raise FileNotFoundError(2, "No such file or directory", str(p))

        with mock.patch.object(Path, "unlink", racing_unlink):
            resp = self._delete(str(victim))
        self._assert_interpolated(resp, str(victim))

    def test_rename_of_a_file_vanishing_mid_request_names_the_path(self):
        victim = self.root / "gone2.txt"
        victim.write_text("x")
        with mock.patch.object(
            files_svc, "_rename_no_clobber",
            side_effect=FileNotFoundError(2, "vanished"),
        ):
            resp = client().post(
                "/api/files/rename",
                json={"path": str(victim), "new_name": "n.txt", "root_id": "r"},
            )
        self._assert_interpolated(resp, str(victim))

    def test_rename_enoent_oserror_arm_names_the_path_too(self):
        import errno as _errno

        victim = self.root / "gone3.txt"
        victim.write_text("x")
        with mock.patch.object(
            files_svc, "_rename_no_clobber",
            side_effect=OSError(_errno.ENOENT, "vanished"),
        ):
            resp = client().post(
                "/api/files/rename",
                json={"path": str(victim), "new_name": "n.txt", "root_id": "r"},
            )
        self._assert_interpolated(resp, str(victim))


@unittest.skipUnless(hasattr(os, "mkfifo"), "platform has no mkfifo")
class FifoWriteOpsStayImmuneTests(_FilesSandbox):
    """Leftover FIFOs through the write routes: coded answers, no hangs.

    files6 pinned the download/read side; these are the mutation corners.
    """

    def test_rename_of_a_fifo_succeeds_without_opening_it(self):
        fifo = self.root / "pipe.fifo"
        os.mkfifo(fifo)
        resp = client().post(
            "/api/files/rename",
            json={"path": str(fifo), "new_name": "pipe2.fifo", "root_id": "r"},
        )
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertTrue((self.root / "pipe2.fifo").is_fifo())

    def test_delete_of_a_fifo_succeeds_without_opening_it(self):
        fifo = self.root / "pipe.fifo"
        os.mkfifo(fifo)
        resp = self._delete(str(fifo))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertFalse(fifo.exists())

    def test_mkdir_under_a_fifo_parent_is_the_coded_400(self):
        fifo = self.root / "pfifo"
        os.mkfifo(fifo)
        resp = client().post(
            "/api/files/mkdir",
            json={"path": str(fifo), "name": "x", "root_id": "r"},
        )
        self.assertEqual(resp.status_code, 400, resp.text[:300])
        self.assertEqual(_code(self, resp), "files.parent_not_a_dir")

    def test_upload_into_a_fifo_parent_is_the_coded_400(self):
        fifo = self.root / "pfifo"
        os.mkfifo(fifo)
        resp = client().post(
            "/api/files/upload",
            data={"path": str(fifo), "root_id": "r"},
            files={"file": ("a.txt", b"x")},
        )
        self.assertEqual(resp.status_code, 400, resp.text[:300])
        self.assertEqual(_code(self, resp), "files.dest_not_a_dir")

    def test_upload_onto_an_existing_fifo_name_is_the_coded_409(self):
        os.mkfifo(self.root / "pfifo")
        resp = client().post(
            "/api/files/upload",
            data={"path": str(self.root), "root_id": "r"},
            files={"file": ("pfifo", b"x")},
        )
        self.assertEqual(resp.status_code, 409, resp.text[:300])
        self.assertEqual(_code(self, resp), "files.upload_would_overwrite")


class FilebrowserStatusStaysImmuneTests(unittest.TestCase):
    """Hostile process listings behind GET /api/files/filebrowser."""

    def _status(self, sh):
        with mock.patch.object(files_svc, "sh", side_effect=sh):
            return client().get("/api/files/filebrowser")

    def test_over_cap_digit_pgrep_pid_stays_null_not_500(self):
        # int("9"*4400) trips CPython's 4300-digit parse limit — ValueError,
        # already caught; the body must render clean with pid null.
        def sh(cmd, timeout=10):
            return (0, "9" * 4400, "") if "pgrep" in cmd[0] else (1, "", "")

        resp = self._status(sh)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _assert_clean(self, resp)
        self.assertIsNone(resp.json()["pid"])

    def test_4000_digit_pgrep_pid_still_renders_under_the_digit_cap(self):
        # Below the parse cap the junk int survives into the payload; both
        # the parse and the render limits are 4300 digits, so there is no
        # gap where json.dumps raises after int() accepted — pin that.
        def sh(cmd, timeout=10):
            return (0, "9" * 4000, "") if "pgrep" in cmd[0] else (1, "", "")

        resp = self._status(sh)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _assert_clean(self, resp)
        self.assertEqual(resp.json()["pid"], int("9" * 4000))

    def test_surrogate_bearing_launchctl_output_renders_clean(self):
        resp = self._status(
            lambda cmd, timeout=10: (0, "state = running\npid = 12\udc80\n", "")
        )
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _assert_clean(self, resp)
        self.assertTrue(resp.json()["running"])
        self.assertIsNone(resp.json()["pid"])


class UploadMultipartEdgesStayImmuneTests(_FilesSandbox):
    """The multipart shapes the files7 battery did not reach."""

    BOUNDARY = "files8boundary"

    def _multipart(self, parts):
        b = self.BOUNDARY.encode()
        out = b""
        for headers, body in parts:
            out += b"--" + b + b"\r\n" + headers + b"\r\n\r\n" + body + b"\r\n"
        out += b"--" + b + b"--\r\n"
        return out, f"multipart/form-data; boundary={self.BOUNDARY}"

    def _post(self, parts):
        body, ctype = self._multipart(parts)
        return client().post(
            "/api/files/upload", content=body, headers={"content-type": ctype}
        )

    def _field(self, name: str, value: bytes) -> tuple[bytes, bytes]:
        return (
            b'Content-Disposition: form-data; name="' + name.encode() + b'"',
            value,
        )

    def test_empty_filename_falls_back_to_upload_bin(self):
        resp = self._post([
            self._field("path", str(self.root).encode()),
            self._field("root_id", b"r"),
            (b'Content-Disposition: form-data; name="file"; filename=""', b"x"),
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _assert_clean(self, resp)
        self.assertEqual(resp.json()["name"], "upload.bin")
        self.assertTrue((self.root / "upload.bin").is_file())

    def test_file_part_without_a_filename_is_a_clean_422(self):
        # Starlette parses it as a plain form field, so UploadFile
        # validation refuses it — must stay a coded 422, not a 500.
        resp = self._post([
            self._field("path", str(self.root).encode()),
            self._field("file", b"x"),
        ])
        self.assertEqual(resp.status_code, 422, resp.text[:300])
        _assert_clean(self, resp)

    def test_part_with_no_content_disposition_is_a_400(self):
        resp = self._post([(b"Content-Type: text/plain", b"x")])
        self.assertEqual(resp.status_code, 400, resp.text[:300])
        _assert_clean(self, resp)

    def test_field_count_bomb_is_the_parser_400_not_a_500(self):
        parts = [
            self._field("f%d" % i, b"x") for i in range(1100)
        ]
        resp = self._post(parts)
        self.assertEqual(resp.status_code, 400, resp.text[:300])
        _assert_clean(self, resp)


if __name__ == "__main__":
    unittest.main()
