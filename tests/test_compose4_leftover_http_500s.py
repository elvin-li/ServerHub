"""Leftover 500 on PUT /api/compose/{id}: the *live* write was unguarded.

Reproduced before the fix: ``compose_svc.save_compose`` guards the backup
write (``FileNotFoundError`` pass, ``EFBIG`` skip, other ``OSError`` coded)
but the one line the whole request exists for —
``secure_io.replace_secret_text(p, content)`` — had no handler.
``replace_secret_text`` re-raises every failure after cleaning up its temp
file, so ENOSPC / EROFS / a dying FUSE EIO on the live write escaped as a
raw HTTP 500 *after* validation had already passed and the backup was
already written.  Fixed with the coded 503 ``compose.save_failed`` (same
convention as ``settings.save_failed``: a disk that cannot be written is a
dependency state, not a defect in the operator's YAML).

The rest of this module pins the Compose page's other leftover classes
stays-immune at the HTTP layer, through the real ``create_app`` wiring
(prior passes fixed them at the service layer; nothing exercised the
mounted routes):

* numeric YAML ``id: 42`` in services.yaml stacks resolves via the str()
  probe — GET /api/compose/42 answers 200, not 404/500;
* UTF-8 lone surrogates in stack names (keys AND values) and in the PUT
  body's compose content are scrubbed, never a Starlette encode 500;
* a leftover >4300-digit already-int ``st_mtime`` renders as 0;
* JSON bodies whose numbers are past CPython's int(str) digit cap are a
  4xx from the sanitizing validation handler (``json.loads`` raises plain
  ValueError, not JSONDecodeError, while *parsing*);
* engine-down validation on save is the coded 503, decided by a forced
  probe — and the ``(-1, "not found")`` vanished-CLI sentinel is only read
  as unreachable after the binary is confirmed gone from disk, because a
  vanished *cwd* raises the identical sentinel.
"""
from __future__ import annotations

import errno
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from hub import compose_svc, containers_svc  # noqa: E402

#: A JSON literal past CPython's 4300-digit int(str) cap.
_HUGE_JSON_INT = "1" * 5000
#: Past the digit cap as an *already-int* (stat leftover, never parsed).
_HUGE_INT = 10 ** 5000
#: What the docker CLI prints on stderr when the daemon socket is gone.
ENGINE_DOWN_ERR = (
    "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. "
    "Is the docker daemon running?"
)
VALID_COMPOSE = "services:\n  web:\n    image: nginx:alpine\n"


class _ComposeHttpSandbox(unittest.TestCase):
    """Real app wiring + a real stack on disk under a temp home."""

    @classmethod
    def setUpClass(cls):
        from fastapi.testclient import TestClient
        from hub.app_factory import create_app
        from hub.auth import require_auth

        cls._app = create_app()
        cls._app.dependency_overrides[require_auth] = lambda: True
        cls.client = TestClient(cls._app, raise_server_exceptions=False)

    @classmethod
    def tearDownClass(cls):
        cls._app.dependency_overrides.clear()

    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix="compose4-http-1a5c-"))
        self.addCleanup(lambda: shutil.rmtree(self.home, ignore_errors=True))
        self.stack_dir = self.home / "Services" / "app-1a5c"
        self.stack_dir.mkdir(parents=True)
        self.compose = self.stack_dir / "docker-compose.yml"
        self.compose.write_text(VALID_COMPOSE)
        patches = [
            # The scan branch of _stack_paths is skipped (containers_svc
            # user_home -> None); the config branch serves the fixture stack.
            mock.patch.object(containers_svc, "user_home", return_value=None),
            mock.patch.object(
                containers_svc, "cfg",
                return_value={"stacks": [self._cfg_stack()]},
            ),
            # save_compose's ~/Services containment check resolves against
            # compose_svc's own user_home.
            mock.patch.object(compose_svc, "user_home", return_value=self.home),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def _cfg_stack(self) -> dict:
        return {"id": "app-1a5c", "name": "App", "path": str(self.stack_dir)}

    def _put(self, body: str):
        return self.client.put(
            "/api/compose/app-1a5c",
            content=body,
            headers={"Content-Type": "application/json"},
        )


class SaveComposeWriteFailure503Tests(_ComposeHttpSandbox):
    """The reproduced leftover: a failed live write is a coded 503, not 500."""

    def _put_with_failing_live_write(self, exc: OSError):
        real_replace = compose_svc.secure_io.replace_secret_text

        def fake_replace(path, content, **kwargs):
            if str(path).endswith(".bak"):
                return real_replace(path, content, **kwargs)
            raise exc

        body = json.dumps({"content": VALID_COMPOSE + "# edited\n", "check": False})
        with mock.patch.object(
            compose_svc.secure_io, "replace_secret_text", fake_replace,
        ):
            return self._put(body)

    def test_enospc_on_the_live_write_is_a_coded_503_not_a_500(self):
        resp = self._put_with_failing_live_write(
            OSError(errno.ENOSPC, "No space left on device")
        )
        self.assertEqual(resp.status_code, 503)
        detail = resp.json()["detail"]
        self.assertEqual(detail["code"], "compose.save_failed")
        self.assertIn("No space left", detail["message"])

    def test_erofs_and_eio_map_to_the_same_coded_503(self):
        for exc in (
            OSError(errno.EROFS, "Read-only file system"),
            OSError(errno.EIO, "Input/output error"),
            PermissionError(errno.EACCES, "Permission denied"),
        ):
            with self.subTest(errno=exc.errno):
                resp = self._put_with_failing_live_write(exc)
                self.assertEqual(resp.status_code, 503)
                self.assertEqual(
                    resp.json()["detail"]["code"], "compose.save_failed"
                )

    def test_a_healthy_save_still_answers_200_and_writes_the_file(self):
        new_content = VALID_COMPOSE + "# edited-1a5c\n"
        resp = self._put(json.dumps({"content": new_content, "check": False}))
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.json()["ok"])
        self.assertEqual(self.compose.read_text(encoding="utf-8"), new_content)
        # The pre-write backup still holds the previous content.
        bak = self.stack_dir / "docker-compose.yml.bak"
        self.assertEqual(bak.read_text(encoding="utf-8"), VALID_COMPOSE)


class NumericYamlStackIdHttpTests(_ComposeHttpSandbox):
    """YAML ``id: 42`` loads as int; the str() probe keeps the stack reachable."""

    def _cfg_stack(self) -> dict:
        return {"id": 42, "path": str(self.stack_dir)}

    def test_get_compose_by_the_rendered_numeric_id_answers_200(self):
        resp = self.client.get("/api/compose/42")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["id"], "42")
        self.assertEqual(data["content"], VALID_COMPOSE)

    def test_save_by_the_rendered_numeric_id_answers_200(self):
        body = json.dumps({"content": VALID_COMPOSE + "# num\n", "check": False})
        resp = self.client.put(
            "/api/compose/42",
            content=body,
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIn("# num", self.compose.read_text(encoding="utf-8"))


class SurrogateAndDigitLeftoverHttpTests(_ComposeHttpSandbox):
    """Surrogates (keys AND values) and huge ints stay scrubbed end to end."""

    def _cfg_stack(self) -> dict:
        # Lone surrogates in the stack *name* (a YAML value) — the id must
        # stay clean or the fixture could not be addressed by URL.
        return {
            "id": "app-1a5c",
            "name": "App\ud800Name",
            "path": str(self.stack_dir),
        }

    def test_surrogate_stack_name_does_not_500_get_compose(self):
        resp = self.client.get("/api/compose/app-1a5c")
        self.assertEqual(resp.status_code, 200)
        payload = resp.json()
        self.assertNotIn("\ud800", json.dumps(payload))
        self.assertEqual(payload["content"], VALID_COMPOSE)

    def test_surrogate_put_body_content_is_scrubbed_not_a_500(self):
        # json.loads accepts the lone escape; the raw form used to
        # UnicodeEncodeError Starlette's response encode and persist the
        # surrogate into the compose on disk.
        body = (
            '{"content": "services:\\n  x:\\n    image: a:1\\n# \\ud800\\n",'
            ' "check": false}'
        )
        resp = self._put(body)
        self.assertEqual(resp.status_code, 200)
        self.assertNotIn("\ud800", json.dumps(resp.json()))
        raw = self.compose.read_text(encoding="utf-8")
        self.assertNotIn("\ud800", raw)
        self.assertIn("image: a:1", raw)

    def test_overcap_json_int_bodies_are_4xx_not_500(self):
        # json.loads raises plain ValueError (not JSONDecodeError) while
        # *parsing* these; the sanitizing handler registered by create_app
        # must keep answering 4xx.
        for body in (
            '{"content": ' + _HUGE_JSON_INT + "}",
            '{"content": "services: {}", "check": ' + _HUGE_JSON_INT + "}",
            '{"content": Infinity}',
        ):
            with self.subTest(body=body[:24]):
                resp = self._put(body)
                self.assertGreaterEqual(resp.status_code, 400)
                self.assertLess(resp.status_code, 500)
                resp.json()

    def test_huge_already_int_st_mtime_renders_as_zero(self):
        # int(huge) succeeds — no conversion to trip on — so only the
        # float() junk test in _finite_mtime keeps json.dumps' int->str
        # digit cap (ValueError) out of the response encode.
        real_stat = Path.stat

        def fake_stat(p, *a, **k):
            st = real_stat(p, *a, **k)
            if p.name == "docker-compose.yml":
                return mock.Mock(
                    st_mode=st.st_mode, st_size=st.st_size, st_mtime=_HUGE_INT,
                )
            return st

        with mock.patch.object(Path, "stat", fake_stat):
            resp = self.client.get("/api/compose/app-1a5c")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["mtime"], 0)
        self.assertEqual(data["content"], VALID_COMPOSE)

    def test_unknown_stack_is_a_coded_404_whose_body_renders(self):
        resp = self.client.get("/api/compose/no-such-stack-1a5c")
        self.assertEqual(resp.status_code, 404)
        detail = resp.json()["detail"]
        self.assertEqual(detail["code"], "compose.unknown_stack")
        self.assertEqual(detail["params"]["stack"], "no-such-stack-1a5c")


class SaveValidationEngineDownHttpTests(_ComposeHttpSandbox):
    """check=true saves: engine off is the coded 503, decided by the probe."""

    def test_engine_down_validation_fails_the_save_with_the_coded_503(self):
        with (
            mock.patch.object(
                compose_svc, "run_capped", return_value=(1, ENGINE_DOWN_ERR),
            ),
            mock.patch.object(compose_svc, "engine_up", return_value=False),
        ):
            resp = self._put(json.dumps({"content": VALID_COMPOSE, "check": True}))
        self.assertEqual(resp.status_code, 503)
        self.assertEqual(resp.json()["detail"]["code"], "container.engine_down")
        # The refused save must not have touched the file.
        self.assertEqual(self.compose.read_text(encoding="utf-8"), VALID_COMPOSE)

    def test_engine_down_looking_output_with_a_live_engine_stays_a_400(self):
        # ``docker compose config`` is mostly client-side: a genuine YAML
        # error with the engine coincidentally off keeps blaming the YAML.
        probe = mock.Mock(return_value=True)
        with (
            mock.patch.object(
                compose_svc, "run_capped", return_value=(1, ENGINE_DOWN_ERR),
            ),
            mock.patch.object(compose_svc, "engine_up", probe),
        ):
            resp = self._put(json.dumps({"content": VALID_COMPOSE, "check": True}))
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.json()["detail"]["code"], "compose.invalid")
        # The classification must not trust the 5s memoised answer.
        probe.assert_called_once_with(force=True)

    def test_a_plain_yaml_error_never_probes_the_engine(self):
        probe = mock.Mock(return_value=True)
        with mock.patch.object(compose_svc, "engine_up", probe):
            resp = self._put(
                json.dumps({"content": "not: [valid", "check": True})
            )
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.json()["detail"]["code"], "compose.invalid")
        probe.assert_not_called()


class ValidateVanishedCliDiskConfirmHttpTests(_ComposeHttpSandbox):
    """The ``(-1, "not found")`` sentinel needs the on-disk confirm.

    Any FileNotFoundError spawn collapses into the same sentinel — a *cwd*
    that vanished between the mkdir and the spawn raises exactly like a
    vanished docker binary — so the coded engine-down answer is only
    allowed once the binary is confirmed gone from disk.
    """

    def _validate(self, cli_present: bool, probe):
        body = json.dumps(
            {"content": VALID_COMPOSE, "cwd": str(self.stack_dir)}
        )
        with (
            mock.patch.object(
                compose_svc, "run_capped", return_value=(-1, "not found"),
            ),
            mock.patch.object(
                compose_svc, "cli_on_disk", return_value=cli_present,
            ),
            mock.patch.object(compose_svc, "engine_up", probe),
        ):
            return self.client.post(
                "/api/compose/validate",
                content=body,
                headers={"Content-Type": "application/json"},
            )

    def test_sentinel_with_the_cli_still_on_disk_is_engine_down(self):
        probe = mock.Mock(return_value=False)
        resp = self._validate(cli_present=True, probe=probe)
        self.assertEqual(resp.status_code, 200)
        out = resp.json()
        self.assertFalse(out["ok"])
        self.assertEqual(out["code"], "container.engine_down")

    def test_sentinel_with_the_cli_gone_and_engine_down_carries_the_code(self):
        probe = mock.Mock(return_value=False)
        resp = self._validate(cli_present=False, probe=probe)
        self.assertEqual(resp.status_code, 200)
        out = resp.json()
        self.assertFalse(out["ok"])
        self.assertEqual(out["code"], "container.engine_down")
        probe.assert_called_once_with(force=True)


class CreateStackSurrogateNameHttpTests(_ComposeHttpSandbox):
    """POST /api/compose: a surrogate display name never reaches services.yaml."""

    def test_surrogate_name_is_scrubbed_before_registration(self):
        captured: dict = {}

        def fake_mutate(fn):
            data = {"stacks": []}
            fn(data)
            captured["stacks"] = data["stacks"]

        body = (
            '{"id": "new-1a5c", "name": "My\\ud800App",'
            ' "content": "services:\\n  x:\\n    image: a:1\\n"}'
        )
        with (
            mock.patch("hub.config.mutate", fake_mutate),
            mock.patch.object(
                compose_svc, "validate_compose_text", return_value={"ok": True},
            ),
        ):
            resp = self.client.post(
                "/api/compose",
                content=body,
                headers={"Content-Type": "application/json"},
            )
        self.assertEqual(resp.status_code, 200)
        self.assertNotIn("\ud800", json.dumps(resp.json()))
        registered = captured["stacks"][0]
        self.assertEqual(registered["id"], "new-1a5c")
        self.assertNotIn("\ud800", registered["name"])
        self.assertTrue(registered["name"])
        compose = self.home / "Services" / "new-1a5c" / "docker-compose.yml"
        self.assertTrue(compose.is_file())


if __name__ == "__main__":
    unittest.main()
