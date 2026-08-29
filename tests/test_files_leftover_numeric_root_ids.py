"""Leftover Files silent-loss: numeric YAML root ids dropped by isinstance gates.

Prior passes pinned the Files 500 classes (surrogate names, over-cap hex
ints, the vanished-FileBrowser 503 — see test_files_leftover_fb_hex_surrogate_503s
and test_files_logs_tools_leftover_500s).  A fresh hunt over what was left
found one live silent-loss and pins the neighbouring stays-immune states:

* ``default_roots``: YAML parses ``id: 2`` / ``name: 2024`` as ints, and the
  ``isinstance(rid, str)`` gate silently replaced both with the directory
  basename.  Two configured roots whose directories share a basename then
  collapsed onto one id — the SPA's root picker showed two identical entries
  and ``GET /api/files/list?root_id=2`` (the id the YAML author wrote)
  answered ``files.unknown_root`` with the directory sitting right there.
  The fix probes with ``str()`` instead of the isinstance gate.
* stays-immune pins on the new probe: an over-cap hex int id (already an
  int — YAML's power-of-two base dodges CPython's 4300-digit parse cap, and
  ``str()`` of it raises ValueError) must fall back to the basename rather
  than 500 or leak into the JSON body; bools (YAML's ``id: yes`` footgun)
  fall back; lone-surrogate ids/names are scrubbed before Starlette's UTF-8
  encode.
* stays-immune pins on ``filebrowser_status``: an over-cap decimal pid in
  launchctl output and hex pgrep text each stay ``pid: None`` and JSON-safe
  (``int()`` of a >4300-digit decimal is ValueError, which the parse
  already eats — pinned so a refactor to ``int(x, 0)`` cannot regress it).
"""
from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml
from fastapi import HTTPException

from hub import files_svc

#: Loaded through a power-of-two base, so already an int past the digit cap.
_HUGE_HEX = int("F" * 5000, 16)


def _starlette(payload) -> None:
    """What Starlette's JSONResponse does to every payload."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


def _code(exc: HTTPException) -> str:
    detail = exc.detail
    return detail["code"] if isinstance(detail, dict) else str(detail)


class NumericYamlRootIdTests(unittest.TestCase):
    """GET /api/files (overview) and /api/files/list scope on these ids."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        # Two roots whose directories share a basename — the shape that made
        # the basename fallback a collision, not just a rename.
        self.a = self.tmp / "a" / "data"
        self.b = self.tmp / "b" / "data"
        self.a.mkdir(parents=True)
        self.b.mkdir(parents=True)
        (self.a / "only-in-a.txt").write_text("A", encoding="utf-8")
        (self.b / "only-in-b.txt").write_text("B", encoding="utf-8")

    def _patch(self, roots):
        return mock.patch.object(
            files_svc, "settings_section", return_value={"roots": roots}
        )

    def _numeric_cfg(self):
        # Through yaml.safe_load, exactly as services.yaml would carry it:
        # ids and names arrive as ints, not strings.
        return yaml.safe_load(
            "roots:\n"
            f'  - {{path: "{self.a}", id: 1, name: 2024}}\n'
            f'  - {{path: "{self.b}", id: 2, name: 2025}}\n'
        )["roots"]

    def test_numeric_ids_and_names_are_kept_not_swallowed(self):
        with self._patch(self._numeric_cfg()):
            roots = files_svc.default_roots()
        # Used to be [("data", "data"), ("data", "data")]: both configured
        # ids silently replaced by the shared basename.
        self.assertEqual([r["id"] for r in roots], ["1", "2"])
        self.assertEqual([r["name"] for r in roots], ["2024", "2025"])
        _starlette(roots)

    def test_configured_numeric_root_id_round_trips_to_list_dir(self):
        with self._patch(self._numeric_cfg()):
            # The id the YAML author wrote used to answer files.unknown_root.
            out = files_svc.list_dir(path=None, root_id="2")
        self.assertEqual(out["path"], str(self.b))
        self.assertEqual([i["name"] for i in out["items"]], ["only-in-b.txt"])
        _starlette(out)

    def test_duplicate_basename_roots_stay_distinct(self):
        with self._patch(self._numeric_cfg()):
            first = files_svc.list_dir(path=None, root_id="1")
            second = files_svc.list_dir(path=str(self.b), root_id="2")
        self.assertEqual([i["name"] for i in first["items"]], ["only-in-a.txt"])
        self.assertEqual([i["name"] for i in second["items"]], ["only-in-b.txt"])

    def test_unknown_root_id_is_still_a_coded_400(self):
        with self._patch(self._numeric_cfg()):
            with self.assertRaises(HTTPException) as ctx:
                files_svc.list_dir(path=None, root_id="99")
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(_code(ctx.exception), "files.unknown_root")

    def test_over_cap_hex_int_id_falls_back_not_500(self):
        # str() of this raises ValueError past CPython's digit cap; the probe
        # must eat it and fall back to the basename instead of 500ing the
        # overview or leaking a 15000-digit id into the JSON body.
        with self._patch([{"path": str(self.a), "id": _HUGE_HEX, "name": _HUGE_HEX}]):
            roots = files_svc.default_roots()
        self.assertEqual([(r["id"], r["name"]) for r in roots], [("data", "data")])
        _starlette(roots)

    def test_bool_id_falls_back_to_basename(self):
        # YAML's ``id: yes`` footgun: a root addressable only as "True" is
        # never what the author meant.
        with self._patch([{"path": str(self.a), "id": True, "name": False}]):
            roots = files_svc.default_roots()
        self.assertEqual([(r["id"], r["name"]) for r in roots], [("data", "data")])
        _starlette(roots)

    def test_surrogate_id_and_name_are_scrubbed_json_safe(self):
        cfg = yaml.safe_load(
            'roots:\n  - {path: "%s", id: "r\\ud800x", name: "n\\ud800m"}' % self.a
        )["roots"]
        with self._patch(cfg):
            roots = files_svc.default_roots()
        self.assertEqual(roots[0]["id"], "r?x")
        self.assertEqual(roots[0]["name"], "n?m")
        _starlette(roots)  # used to be the Starlette UTF-8 encode 500 class


class FileBrowserPidDigitPinTests(unittest.TestCase):
    """GET /api/files renders filebrowser_status on every page load."""

    def _status(self, sh_results):
        with (
            mock.patch.object(files_svc, "sh", side_effect=sh_results),
            mock.patch.object(files_svc, "host_ip", return_value="127.0.0.1"),
            mock.patch.object(files_svc, "_exists", lambda p: False),
        ):
            return files_svc.filebrowser_status()

    def test_over_cap_decimal_launchctl_pid_stays_none(self):
        out = "state = running\n\tpid = " + "9" * 5000 + "\n"
        state = self._status([(0, out, ""), (1, "", "")])
        self.assertTrue(state["running"])
        self.assertIsNone(state["pid"])
        _starlette(state)

    def test_hex_pgrep_text_stays_none(self):
        state = self._status([(1, "", ""), (0, "0x" + "F" * 5000, "")])
        self.assertTrue(state["running"])
        self.assertIsNone(state["pid"])
        _starlette(state)


if __name__ == "__main__":
    unittest.main()
