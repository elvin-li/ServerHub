"""Leftover Tools updates-card silent-loss and docker failure-shape pins.

The Tools hex-int/surrogate/vanish battery
(test_tools_leftover_hexint_surrogate_vanish_500s) pinned the plist paths and
the vanished-CLI df/prune classification.  This sweep covers what it left:

* ``_github_get_json`` decoded the release payload without an int hook.  A
  leftover >4300-digit numeric literal anywhere in it (a release ``id``, say)
  makes ``json.loads`` itself raise ValueError — CPython's str->int digit cap,
  not JSONDecodeError — so the whole updates card fell to
  ``"invalid github json"``: latest/tag/notes wiped by one number the card
  never renders.  The tags fallback died the same way, since both routes share
  the reader.  ``parse_int_capped`` loads the huge literal as None and the
  fields the card actually shows survive;
* failure shapes that must NOT be reclassified: a ``docker system df`` /
  ``prune`` timeout (rc -1, the exact "timeout" sentinel) and a real exit
  whose stderr reads like a permission problem keep their original result —
  no ``container.engine_down`` code, no on-disk CLI probe.  The disk stat is
  a failure-path-only confirm (the ``looks_cli_vanished`` contract), so
  neither of these may pay for or trigger it;
* plist ids that happen to be numeric: an integer ``Label`` falls back to the
  filename stem instead of dropping the row, and an over-cap int inside
  ``ProgramArguments`` renders as an empty token instead of ValueError'ing
  Starlette's encoder.
"""
from __future__ import annotations

import io
import json
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

from hub import tools_svc

#: Built as a literal string: int("1" * 5000) itself trips the digit cap.
_HUGE_JSON_INT = "1" * 5000
#: Built arithmetically for the already-int shapes.
_HUGE_INT = 16 ** 5000


def _starlette(payload) -> None:
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class _FakeResp:
    def __init__(self, body: bytes):
        self._body = body

    def read(self, n=-1):
        return self._body

    def close(self):
        pass


class _FakeOpener:
    """Route ``/releases/latest`` and ``/tags`` to canned bodies."""

    def __init__(self, latest=None, tags=None):
        self._latest = latest
        self._tags = tags

    def open(self, req, timeout=None):
        url = req.full_url
        body = self._latest if "/releases/latest" in url else self._tags
        if body is None:
            raise urllib.error.HTTPError(url, 404, "Not Found", {}, io.BytesIO(b"404"))
        return _FakeResp(body)


class GithubHugeIntPayloadTests(unittest.TestCase):
    """One unrenderable number must not wipe the whole updates card."""

    def setUp(self):
        tools_svc._github_cache.update(t=0.0, v=None)
        self.addCleanup(tools_svc._github_cache.update, t=0.0, v=None)

    def _latest(self, opener) -> dict:
        with mock.patch("hub.http_guard.no_redirect_opener", return_value=opener):
            return tools_svc._github_latest(force=True)

    def test_huge_release_id_does_not_wipe_updates_card(self):
        """json.loads of the huge ``id`` is ValueError not JSONDecodeError;
        the card used to answer "invalid github json" with latest: None."""
        body = (
            '{"tag_name": "v9.9.9",'
            ' "html_url": "https://github.com/elvin-li/ServerHub/releases/tag/v9.9.9",'
            ' "body": "notes", "published_at": "2026-01-01",'
            ' "id": ' + _HUGE_JSON_INT + "}"
        ).encode()
        snap = self._latest(_FakeOpener(latest=body))
        _starlette(snap)
        self.assertTrue(snap["ok"])
        self.assertEqual(snap["tag"], "v9.9.9")
        self.assertEqual(snap["latest"], "9.9.9")
        self.assertEqual(snap["notes"], "notes")
        self.assertEqual(snap["error"], "")

    def test_huge_int_in_tags_fallback_survives(self):
        """No releases published + a huge tag ``id``: the fallback shares the
        same reader and used to die the same way."""
        tags = (
            '[{"name": "v2.0.0", "id": ' + _HUGE_JSON_INT + "}]"
        ).encode()
        snap = self._latest(_FakeOpener(latest=None, tags=tags))
        _starlette(snap)
        self.assertTrue(snap["ok"])
        self.assertEqual(snap["tag"], "v2.0.0")
        self.assertEqual(snap["source"], "tag")

    def test_surrogate_escape_in_notes_is_scrubbed(self):
        """A ``\\ud800`` JSON escape decodes to a lone surrogate; the card
        fields must be replace-encoded, never served raw to the UTF-8
        encoder."""
        body = (
            '{"tag_name": "v9.9.9",'
            ' "html_url": "https://github.com/elvin-li/ServerHub/releases/tag/v9.9.9",'
            ' "body": "a\\ud800b", "published_at": "2026-01-01"}'
        ).encode()
        snap = self._latest(_FakeOpener(latest=body))
        _starlette(snap)
        self.assertTrue(snap["ok"])
        self.assertNotIn("\ud800", snap["notes"])

    def test_truly_corrupt_json_still_reports_the_error(self):
        """The huge-int hook must not soften a genuinely torn payload."""
        snap = self._latest(_FakeOpener(latest=b'{"tag_name": "v9'))
        _starlette(snap)
        self.assertFalse(snap["ok"])
        self.assertIn("invalid github json", snap["error"])

    def test_parse_version_survives_over_cap_component(self):
        """A >4300-digit version chunk is ValueError inside int(); the
        compare must degrade to (0,) instead of raising."""
        self.assertEqual(tools_svc.parse_version("v" + _HUGE_JSON_INT + ".1"), (0,))
        self.assertEqual(tools_svc.parse_version("v3.9.1"), (3, 9, 1))


class DockerFailureShapeTests(unittest.TestCase):
    """Timeouts and permission failures keep their original result: no
    engine_down code, and the on-disk CLI probe stays failure-pattern-only."""

    def setUp(self):
        tools_svc.docker_disk_usage.invalidate()
        self.addCleanup(tools_svc.docker_disk_usage.invalidate)

    def _run(self, fn, docker_result):
        probe = mock.Mock(return_value=False)
        with (
            mock.patch.object(tools_svc, "engine_up", return_value=True),
            mock.patch.object(tools_svc, "docker", return_value=docker_result),
            mock.patch.object(tools_svc, "cli_on_disk", probe),
        ):
            return fn(), probe

    def test_df_timeout_keeps_raw_shape(self):
        df, probe = self._run(tools_svc.docker_disk_usage, (-1, "", "timeout"))
        _starlette(df)
        self.assertTrue(df["engine_up"])
        self.assertEqual(df["raw"], "timeout")
        probe.assert_not_called()

    def test_prune_timeout_keeps_uncoded_failure(self):
        out, probe = self._run(
            lambda: tools_svc.docker_prune("dangling", True), (-1, "", "timeout"),
        )
        _starlette(out)
        self.assertFalse(out["ok"])
        self.assertNotIn("code", out)
        self.assertEqual(out["message"], "timeout")
        probe.assert_not_called()

    def test_prune_permission_failure_keeps_uncoded_failure(self):
        out, probe = self._run(
            lambda: tools_svc.docker_prune("dangling", True),
            (1, "", "permission denied while trying to prune"),
        )
        _starlette(out)
        self.assertFalse(out["ok"])
        self.assertNotIn("code", out)
        self.assertIn("permission denied", out["message"])
        probe.assert_not_called()


class PlistNumericLeftoverTests(unittest.TestCase):
    """Numeric plist ids degrade per-field; the row itself survives."""

    def _timers(self, leftover: dict) -> list:
        import plistlib

        with (
            mock.patch.object(
                tools_svc.os.path, "expanduser", return_value="/tmp/agents",
            ),
            mock.patch.object(
                tools_svc.glob, "glob", return_value=["/tmp/agents/x.plist"],
            ),
            mock.patch.object(tools_svc, "read_bytes_capped", return_value=b""),
            mock.patch.object(plistlib, "loads", return_value=leftover),
        ):
            return tools_svc.launchd_timers()

    def test_integer_label_falls_back_to_stem_not_dropped(self):
        timers = self._timers({
            "Label": 42, "StartInterval": 60, "ProgramArguments": ["true"],
        })
        _starlette(timers)
        self.assertEqual(len(timers), 1)
        self.assertEqual(timers[0]["label"], "x")
        self.assertEqual(timers[0]["interval_sec"], 60)

    def test_over_cap_int_program_argument_does_not_500(self):
        """``" ".join(_as_text(a) …)`` must render the huge token as empty
        instead of letting str() ValueError the payload."""
        timers = self._timers({
            "Label": "job",
            "StartInterval": 60,
            "ProgramArguments": ["true", _HUGE_INT],
        })
        _starlette(timers)
        self.assertEqual(len(timers), 1)
        self.assertEqual(timers[0]["program"].split(), ["true"])
        path = Path("/tmp/agents/x.plist")
        self.assertEqual(timers[0]["path"], str(path))


if __name__ == "__main__":
    unittest.main()
