"""Third leftover-500s sweep of the usage / disk-usage routes, over real ASGI.

The hunted classes (lone UTF-8 surrogates in keys AND values, the CPython
4300-digit int cap — including the uncapped YAML/plist hex form that arrives
already-int — vanished-CLI 503-vs-500) were re-reproduced against
GET /api/storage/usage, /usage/tree, /usage/largest, /usage/duplicates and
POST /api/storage/spotlight in ``hub/routers/nas_storage.py``.  One live
leak was found and is fixed alongside this file:

* ``usage_svc.scan_roots`` rendered each SMB share's name with a bare
  f-string / ``str()`` inside the single try that wraps the *whole* share
  loop.  A leftover share name that is already a >4300-digit int (plist/YAML
  hex loads with ``int(x, 16)``, exempt from the int(str) parse cap) raised
  the digit-cap ValueError into that loop-wide except — which silently
  dropped every share after it from the usage scan roots on
  GET /api/storage/usage (and from ``_resolve``'s allowlist, so the surviving
  shares' trees answered files.path_outside_root instead of listing).  The
  name now routes through ``_as_text``'s str() probe: the unrenderable name
  scrubs to "" and takes the same fallback a None name always took, and the
  siblings survive.  The sibling pins here fail on the pre-fix tree.

Everything else in the blast radius was found immune, so the rest of this
file pins the stays-immune corners at the HTTP layer — request routing,
query-param parsing, response rendering and the strict UTF-8 decode of the
body:

* a poisoned over-cap ``st_size`` riding a real walk out of
  GET /api/storage/usage/tree (0 bytes, HTTP 200 — Starlette's ``json.dumps``
  int->str digit cap is ValueError);
* query-param leftovers: a NUL ``path`` answers the coded 404, an over-cap
  digit ``limit`` is pydantic's 422 (never a 500), ``min_mb`` of
  Infinity / NaN / 1e400 / 5000 digits falls back to the 1 MB floor, and an
  over-cap digit ``root_id`` answers the coded files.unknown_root 400;
* a >4300-digit integer literal in the POST /api/storage/spotlight body:
  ``json.loads`` raises ValueError (NOT JSONDecodeError) for the whole
  document, and FastAPI's body-parse guard answers the coded 400, never a
  500;
* a lone-surrogate volume (``json.loads`` happily builds one from a
  ``\\ud800`` escape) answers the coded usage.bad_volume 400 with a strictly
  UTF-8 body;
* the vanished-mdutil coded 503 across a real ASGI cycle (disk confirm on
  the failure path only — with mdutil still on disk the raw failure shape
  survives, never the tool-absent 503);
* an ok spotlight payload carrying a surrogate message and an over-cap int
  through the ``raise_service_error`` funnel (the int drops like inf, the
  surrogate is scrubbed).
"""
from __future__ import annotations

import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from urllib.parse import quote

from fastapi import FastAPI

from hub import files_svc, usage_svc
from hub.routers import nas_common, nas_storage

#: Parsed from real plist bytes: plistlib's ``<integer>`` handler runs
#: ``int(x, 16)`` for the ``0x`` form, which CPython's 4300-digit str->int
#: parse cap does not bound, so the leftover arrives *already-int* and only
#: fails at render time (``str()`` / ``json.dumps``).
_HUGE_INT = int("F" * 4400, 16)


async def _asgi_request(method, path, *, query=b"", body=None, raw_body=None):
    """Drive the nas_storage router through a real ASGI cycle."""
    app = FastAPI()
    app.include_router(nas_storage.router)
    if raw_body is not None:
        payload = raw_body
    else:
        payload = b"" if body is None else json.dumps(body).encode("utf-8")
    sent = False
    messages: list[dict] = []

    async def receive():
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": payload, "more_body": False}
        return {"type": "http.disconnect"}

    async def send(message):
        messages.append(message)

    scope = {
        "type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1", "method": method, "scheme": "http",
        "path": path, "raw_path": quote(path, safe="/").encode(),
        "query_string": query, "root_path": "",
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(payload)).encode()),
        ],
        "server": ("localhost", 8086), "client": ("127.0.0.1", 1), "state": {},
    }
    await app(scope, receive, send)
    status = next(m["status"] for m in messages if m["type"] == "http.response.start")
    raw = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
    # The body must already be valid UTF-8 — decode strictly on purpose.
    return status, raw.decode("utf-8")


def request(method, path, *, query=b"", body=None, raw_body=None):
    return asyncio.run(
        _asgi_request(method, path, query=query, body=body, raw_body=raw_body)
    )


def _admin_browser():
    """An administrator browser session, as nas_common resolves one."""
    return (
        mock.patch.object(nas_common.auth, "browser_authenticated", return_value=True),
        mock.patch.object(nas_common.auth, "request_username", return_value="admin"),
        mock.patch.object(nas_common.auth, "is_admin", return_value=True),
        mock.patch.object(nas_common.auth, "request_client_id", return_value="127.0.0.1"),
    )


class _TempRoot(unittest.TestCase):
    """A real walkable root, with default_roots / shares pinned hermetic."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="usage3-pin-"))
        (self.root / "a.bin").write_bytes(b"x" * 2048)
        (self.root / "sub").mkdir()
        (self.root / "sub" / "b.bin").write_bytes(b"y" * 4096)
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        for child in sorted(self.root.rglob("*"), reverse=True):
            child.unlink() if child.is_file() else child.rmdir()
        self.root.rmdir()

    def _roots(self):
        return [{"id": "t", "name": "t", "path": str(self.root)}]

    def _pinned(self, shares=()):
        return (
            mock.patch.object(files_svc, "default_roots", return_value=self._roots()),
            mock.patch("hub.shares_svc.list_smb_shares", return_value=list(shares)),
        )


class ShareSiblingSurvivesHugeIntNamePinTests(unittest.TestCase):
    """The live leak — these fail on the pre-fix tree."""

    def setUp(self):
        self.share_a = Path(tempfile.mkdtemp(prefix="usage3-share-a-"))
        self.share_b = Path(tempfile.mkdtemp(prefix="usage3-share-b-"))
        self.addCleanup(self.share_a.rmdir)
        self.addCleanup(self.share_b.rmdir)
        self.shares = [
            # The hostile record first, so the pre-fix loop-wide except is
            # what would have to eat its ValueError — dropping its sibling.
            {"name": _HUGE_INT, "path": str(self.share_a)},
            {"name": "good", "path": str(self.share_b)},
        ]

    def _pinned(self):
        return (
            mock.patch.object(files_svc, "default_roots", return_value=[]),
            mock.patch("hub.shares_svc.list_smb_shares", return_value=self.shares),
        )

    def test_sibling_share_survives_an_unrenderable_name(self):
        with self._pinned()[0], self._pinned()[1]:
            roots = usage_svc.scan_roots()
        json.dumps(roots, ensure_ascii=False, allow_nan=False).encode("utf-8")
        by_path = {r["path"]: r for r in roots}
        self.assertIn(str(self.share_b), by_path)
        self.assertEqual(by_path[str(self.share_b)]["id"], "share-good")

    def test_unrenderable_name_takes_the_none_name_fallback(self):
        """The hostile share itself stays too: same shape a None name takes."""
        with self._pinned()[0], self._pinned()[1]:
            roots = usage_svc.scan_roots()
        by_path = {r["path"]: r for r in roots}
        self.assertIn(str(self.share_a), by_path)
        self.assertEqual(by_path[str(self.share_a)]["id"], "share-share")
        self.assertEqual(by_path[str(self.share_a)]["name"], str(self.share_a))

    def test_get_usage_overview_renders_both_roots(self):
        patches = self._pinned() + (
            mock.patch.object(usage_svc, "spotlight_status", return_value=[]),
        )
        with patches[0], patches[1], patches[2]:
            status, raw = request("GET", "/api/storage/usage")
        self.assertEqual(status, 200)
        paths = {r["path"] for r in json.loads(raw)["roots"]}
        self.assertEqual(paths, {str(self.share_a), str(self.share_b)})

    def test_sibling_share_tree_is_walkable_again(self):
        """Pre-fix the sibling vanished from the allowlist too, so its tree
        answered files.path_outside_root instead of listing."""
        (self.share_b / "data.bin").write_bytes(b"z" * 1024)
        self.addCleanup((self.share_b / "data.bin").unlink)
        with self._pinned()[0], self._pinned()[1]:
            status, raw = request(
                "GET", "/api/storage/usage/tree",
                query=b"path=" + quote(str(self.share_b)).encode(),
            )
        self.assertEqual(status, 200)
        body = json.loads(raw)
        self.assertEqual([c["name"] for c in body["children"]], ["data.bin"])

    def test_numeric_and_surrogate_names_keep_their_string_form(self):
        """The str() probe coerces, never gates: sane leftovers still name
        their root, and the surrogate scrubs instead of 500ing the body."""
        self.shares = [
            {"name": 123, "path": str(self.share_a)},
            {"name": "s\ud800", "path": str(self.share_b)},
        ]
        with self._pinned()[0], self._pinned()[1]:
            status, raw = request("GET", "/api/storage/usage")
        self.assertEqual(status, 200)
        ids = {r["id"] for r in json.loads(raw)["roots"]}
        self.assertIn("share-123", ids)
        self.assertIn("share-s?", ids)
        self.assertNotIn("\ud800", raw)


class _PoisonedEntry:
    """Delegates to a real DirEntry but reports a chosen ``st_size``."""

    def __init__(self, entry, size):
        self._entry = entry
        self._size = size

    def __getattr__(self, name):
        return getattr(self._entry, name)

    def stat(self, follow_symlinks=True):
        st = self._entry.stat(follow_symlinks=follow_symlinks)
        return mock.Mock(st_size=self._size, st_mtime=st.st_mtime, st_mode=st.st_mode)


class _ScandirResult:
    def __init__(self, entries):
        self._entries = entries

    def __enter__(self):
        return iter(self._entries)

    def __exit__(self, *exc):
        return False

    def __iter__(self):
        return iter(self._entries)


class TreeHugeStSizeHttpStaysImmunePins(_TempRoot):
    """The unit pins live in test_leftover_usage_catalog_digit_500s; this one
    rides the poisoned walk through routing and Starlette's encoder."""

    def _poisoned_scandir(self):
        real_scandir = os.scandir

        def scandir(path):
            with real_scandir(path) as it:
                entries = [
                    _PoisonedEntry(e, _HUGE_INT)
                    if e.is_file(follow_symlinks=False) else e
                    for e in it
                ]
            return _ScandirResult(entries)

        return mock.patch.object(usage_svc.os, "scandir", scandir)

    def test_get_tree_stays_http_200_with_an_over_cap_st_size(self):
        patches = self._pinned() + (self._poisoned_scandir(),)
        with patches[0], patches[1], patches[2]:
            status, raw = request("GET", "/api/storage/usage/tree")
        self.assertEqual(status, 200)
        body = json.loads(raw)
        files = [c for c in body["children"] if c["kind"] == "file"]
        self.assertEqual([f["name"] for f in files], ["a.bin"])
        self.assertEqual(files[0]["bytes"], 0)
        self.assertEqual(body["own_bytes"], 0)


class UsageQueryParamStaysImmunePins(_TempRoot):
    """Hostile query strings on the mounted routes: coded 4xx, never a 500."""

    def _get(self, path, query):
        pinned = self._pinned()
        with pinned[0], pinned[1]:
            return request("GET", path, query=query)

    def test_nul_path_is_the_coded_404(self):
        status, raw = self._get("/api/storage/usage/tree", b"path=%00")
        self.assertEqual(status, 404)
        self.assertEqual(json.loads(raw)["detail"]["code"], "files.not_found")

    def test_over_cap_digit_limit_is_pydantic_422_not_500(self):
        status, raw = self._get(
            "/api/storage/usage/largest", b"limit=" + b"9" * 5000,
        )
        self.assertEqual(status, 422)
        self.assertIn("limit", raw)

    def test_min_mb_junk_falls_back_to_the_floor(self):
        for value in (b"Infinity", b"nan", b"1e400", b"9" * 5000, b"-5"):
            with self.subTest(value=value[:12]):
                status, raw = self._get(
                    "/api/storage/usage/duplicates", b"min_mb=" + value,
                )
                self.assertEqual(status, 200)
                self.assertEqual(json.loads(raw)["min_mb"], 1.0)

    def test_over_cap_digit_root_id_is_the_coded_400(self):
        status, raw = self._get(
            "/api/storage/usage/tree", b"root_id=" + b"9" * 5000,
        )
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(raw)["detail"]["code"], "files.unknown_root")


class SpotlightBodyAndFunnelStaysImmunePins(unittest.TestCase):
    def _post(self, raw_body, *, run_admin=None, on_disk=True):
        patches = _admin_browser() + (
            mock.patch.object(nas_storage.audit, "record", lambda *a, **k: {}),
            mock.patch.object(
                usage_svc, "spotlight_status", return_value=[{"volume": "/"}],
            ),
            mock.patch(
                "hub.macos_admin.run_admin",
                return_value=dict(run_admin or {"ok": True}),
            ),
            mock.patch.object(usage_svc, "_mdutil_on_disk", return_value=on_disk),
        )
        with (
            patches[0], patches[1], patches[2], patches[3],
            patches[4], patches[5], patches[6], patches[7],
        ):
            return request("POST", "/api/storage/spotlight", raw_body=raw_body)

    def test_over_cap_int_body_literal_is_the_coded_400_not_500(self):
        """json.loads raises ValueError, NOT JSONDecodeError, for the whole
        document; FastAPI's body-parse guard answers 400 before the handler."""
        raw = b'{"volume": ' + b"9" * 5000 + b', "enabled": true}'
        status, body = self._post(raw)
        self.assertEqual(status, 400)
        self.assertIn("error parsing the body", body)

    def test_lone_surrogate_volume_is_the_coded_400(self):
        raw = b'{"volume": "/Volumes/D\\ud800", "enabled": true}'
        status, body = self._post(raw)
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(body)["detail"]["code"], "usage.bad_volume")
        self.assertNotIn("\ud800", body)

    def test_vanished_mdutil_answers_the_coded_503_over_asgi(self):
        status, body = self._post(
            b'{"volume": "/", "enabled": true}',
            run_admin={
                "ok": False, "error": "failed",
                "message": "sh: /usr/bin/mdutil: command not found",
            },
            on_disk=False,
        )
        self.assertEqual(status, 503)
        self.assertEqual(json.loads(body)["detail"]["code"], "usage.mdutil_missing")

    def test_mdutil_still_on_disk_keeps_the_raw_failure_shape(self):
        """execve also ENOENTs for a still-present binary whose loader is
        broken: with mdutil confirmably on disk the raw failure is the truth,
        never the tool-absent 503."""
        status, body = self._post(
            b'{"volume": "/", "enabled": true}',
            run_admin={
                "ok": False, "error": "failed",
                "message": "sh: /usr/bin/mdutil: command not found",
            },
            on_disk=True,
        )
        self.assertNotEqual(status, 503)
        self.assertNotIn("usage.mdutil_missing", body)

    def test_ok_payload_surrogate_and_over_cap_int_render_scrubbed(self):
        """raise_service_error -> nas_common._jsonable: the over-cap int
        drops like inf, the surrogate scrubs, across a real ASGI cycle."""
        status, body = self._post(
            b'{"volume": "/", "enabled": true}',
            run_admin={"ok": True, "message": "done\ud800", "minutes": _HUGE_INT},
        )
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["message"], "done?")
        self.assertIsNone(payload["minutes"])
        self.assertEqual(payload["volume"], "/")


if __name__ == "__main__":
    unittest.main()
