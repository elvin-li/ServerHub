"""Leftover notify growth wipes: unbounded values used to destroy sibling rows.

Reproduced through the real mounted app (create_app + TestClient,
raise_server_exceptions=False) before the fix:

* **One POST /api/alerts/channels bricked the whole panel config.**  A 2MB
  ``topic`` (or a 200k-entry ``to`` list) answered **200**, wrote a
  services.yaml larger than config's 1MB read cap, and every later
  ``cfg()``/``_read_disk()`` answered ``{}``: the admin account and every
  sibling setting vanished from the panel's view, and the very next
  ``mutate()`` — any settings save at all — rewrote services.yaml from the
  empty snapshot (33 bytes on disk), making the wipe permanent.  Values are
  now capped at the API boundary (``notify.value_too_long`` /
  ``notify.list_too_long`` / a whole-record backstop / ``notify.too_many``),
  and ``config._save_full_locked`` refuses to persist any document its own
  reader would reject (coded 503, file untouched) — for every route, not
  just notify.

* **One oversized secret wiped every sibling channel's secrets.**
  ``set_channel_secrets`` had no length cap: a 300KB "webhook URL" pushed
  notify-credentials.json past its 256KB read cap, after which every
  ``_load_secrets`` answered ``{}`` (all channels lost their has_* flags and
  their sends) and the next innocent channel edit rewrote the file from that
  empty snapshot — permanently.  Values are now capped
  (``notify.value_too_long``), the merged document is size-checked before it
  is written (``notify.secrets_too_large``), and a *present-but-unreadable*
  file (oversized / torn / corrupt JSON) refuses secret **writes** with a
  coded 503 (``notify.secrets_unreadable``) instead of merging onto ``{}``.
  Read paths (GET list, dispatch, DELETE's prune) keep degrading to ``{}``:
  they can never destroy anything.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from hub import config, notify_channels  # noqa: E402
from hub.routers import notify_api  # noqa: E402


class _Sandbox(unittest.TestCase):
    """Scratch services.yaml + secrets file, so no test touches a real install."""

    def setUp(self):
        root = Path(os.environ.get("TMPDIR", "/tmp")) / (
            f"serverhub-notify-oversize-{os.getpid()}-{id(self)}"
        )
        data = root / "data"
        data.mkdir(parents=True, exist_ok=True)
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        self.root = root
        self.data = data
        self.secrets = data / "notify-credentials.json"
        for target, value in (
            ("YAML_PATH", root / "services.yaml"),
            ("DATA_DIR", data),
            ("BASE", root),
        ):
            patched = mock.patch.object(config, target, value)
            patched.start()
            self.addCleanup(patched.stop)
        self.addCleanup(config.reload_cfg)
        config.reload_cfg()
        patched = mock.patch.object(notify_channels, "SECRETS_FILE", self.secrets)
        patched.start()
        self.addCleanup(patched.stop)

    def client(self):
        """The real app: routing, the validation handler and Starlette's
        encoder are part of what these pins assert."""
        from fastapi.testclient import TestClient
        from hub.app_factory import create_app
        from hub.auth import require_auth

        app = create_app()
        app.dependency_overrides[require_auth] = lambda: True
        self.addCleanup(app.dependency_overrides.clear)
        return TestClient(app, raise_server_exceptions=False)

    def seed_sibling_setting(self):
        config.mutate(
            lambda d: d.setdefault("settings", {}).update({"host_ip": "10.0.0.7"})
        )
        self.assertEqual(config.cfg()["settings"]["host_ip"], "10.0.0.7")

    def assert_config_survives(self):
        """The sibling key is still there — on disk and after a later write."""
        config.reload_cfg()
        self.assertEqual(
            config.cfg().get("settings", {}).get("host_ip"), "10.0.0.7",
            "services.yaml became unreadable: cfg() lost every sibling key",
        )
        # The next unrelated mutate() used to persist the wipe permanently.
        config.mutate(
            lambda d: d.setdefault("settings", {}).update({"metrics_interval": 91})
        )
        config.reload_cfg()
        self.assertEqual(config.cfg()["settings"]["host_ip"], "10.0.0.7")


class OversizeConfigValueTests(_Sandbox):
    """One request used to write a services.yaml no reader could load back."""

    def test_multi_mb_config_value_is_coded_400_and_config_survives(self):
        self.seed_sibling_setting()
        r = self.client().post("/api/alerts/channels", json={
            "id": "big", "type": "ntfy",
            "config": {"topic": "x" * (2 * 1024 * 1024)},
        })
        self.assertEqual(r.status_code, 400, r.text[:300])
        self.assertEqual(r.json()["detail"]["code"], "notify.value_too_long")
        self.assertLess(config.YAML_PATH.stat().st_size, config._YAML_CAP)
        self.assert_config_survives()

    def test_huge_recipient_list_is_coded_400(self):
        self.seed_sibling_setting()
        r = self.client().post("/api/alerts/channels", json={
            "id": "biglist", "type": "email",
            "config": {"host": "smtp.example.com", "to": ["a@b.c"] * 200000},
        })
        self.assertEqual(r.status_code, 400, r.text[:300])
        self.assertEqual(r.json()["detail"]["code"], "notify.list_too_long")
        self.assert_config_survives()

    def test_oversized_list_element_is_coded_400(self):
        r = self.client().post("/api/alerts/channels", json={
            "id": "fat-el", "type": "email",
            "config": {"host": "smtp.example.com", "to": ["a" * 5000]},
        })
        self.assertEqual(r.status_code, 400, r.text[:300])
        self.assertEqual(r.json()["detail"]["code"], "notify.value_too_long")

    def test_whole_record_backstop_catches_at_cap_fields_that_add_up(self):
        """100 entries each under the per-value cap still must not stack into
        an unbounded record."""
        r = self.client().post("/api/alerts/channels", json={
            "id": "stacked", "type": "email",
            "config": {"host": "smtp.example.com",
                       "to": [("u" * 200) + f"@{i}.example" for i in range(100)]},
        })
        self.assertEqual(r.status_code, 400, r.text[:300])
        detail = r.json()["detail"]
        self.assertEqual(detail["code"], "notify.value_too_long")
        self.assertEqual(detail["params"]["field"], "config")

    def test_channel_count_is_capped(self):
        rows = [{"id": f"c{i}", "type": "slack"} for i in range(notify_api._MAX_CHANNELS)]
        with mock.patch.object(notify_channels, "_raw_notify_cfg",
                               lambda: {"channels": rows}):
            r = self.client().post("/api/alerts/channels", json={
                "id": "one-more", "type": "ntfy", "config": {"topic": "t"},
            })
        self.assertEqual(r.status_code, 400, r.text[:300])
        self.assertEqual(r.json()["detail"]["code"], "notify.too_many")

    def test_a_reasonable_channel_still_saves(self):
        """The caps must not refuse real-world channels."""
        r = self.client().post("/api/alerts/channels", json={
            "id": "fine", "type": "email",
            "config": {"host": "smtp.example.com", "port": 587,
                       "to": [f"user{i}@example.com" for i in range(50)]},
        })
        self.assertEqual(r.status_code, 200, r.text[:300])
        self.assertEqual(notify_channels.get_channel("fine")["host"],
                         "smtp.example.com")

    def test_mutate_refuses_any_config_its_own_reader_would_reject(self):
        """The config-level backstop covers every route, not just notify."""
        from fastapi import HTTPException

        self.seed_sibling_setting()
        before = config.YAML_PATH.read_text(encoding="utf-8")

        def grow(d):
            d.setdefault("settings", {})["leftover"] = "y" * (2 * 1024 * 1024)

        with self.assertRaises(HTTPException) as ctx:
            config.mutate(grow)
        self.assertEqual(ctx.exception.detail["code"], "settings.save_failed")
        self.assertEqual(config.YAML_PATH.read_text(encoding="utf-8"), before,
                         "the refused save must leave the on-disk file intact")
        self.assert_config_survives()


class OversizeSecretValueTests(_Sandbox):
    """A 300KB secret used to make the whole credentials file unreadable."""

    def _sibling(self):
        r = self.client().post("/api/alerts/channels", json={
            "id": "sib", "type": "telegram", "config": {"chat_id": "1"},
            "secrets": {"bot_token": "sibling-token"},
        })
        self.assertEqual(r.status_code, 200, r.text[:300])

    def test_oversized_secret_is_coded_400_and_nothing_lands_on_disk(self):
        self._sibling()
        before = self.secrets.read_text(encoding="utf-8")
        r = self.client().post("/api/alerts/channels", json={
            "id": "fat", "type": "webhook",
            "secrets": {"url": "https://example.com/" + "y" * (300 * 1024)},
        })
        self.assertEqual(r.status_code, 400, r.text[:300])
        self.assertEqual(r.json()["detail"]["code"], "notify.value_too_long")
        self.assertEqual(self.secrets.read_text(encoding="utf-8"), before,
                         "a refused secret must not poison the store")
        self.assertEqual(notify_channels.channel_secrets("sib"),
                         {"bot_token": "sibling-token"})

    def test_merged_document_is_never_written_past_its_own_read_cap(self):
        """Many per-value-legal secrets must not stack the file unreadable."""
        from fastapi import HTTPException

        data: dict = {}
        chunk = "a" * notify_channels._SECRET_VALUE_MAX
        i = 0
        while True:
            probe = dict(data)
            probe[f"c{i}"] = {"token": chunk}
            if len(json.dumps(probe, ensure_ascii=False, indent=2)) + 1 \
                    > notify_channels._SECRETS_CAP - 2048:
                break
            data = probe
            i += 1
        self.secrets.write_text(
            json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        before = self.secrets.read_text(encoding="utf-8")
        with self.assertRaises(HTTPException) as ctx:
            notify_channels.set_channel_secrets("overflow", {"token": chunk})
        self.assertEqual(ctx.exception.detail["code"], "notify.secrets_too_large")
        self.assertEqual(self.secrets.read_text(encoding="utf-8"), before)
        # The store is still fully readable: no sibling lost anything.
        self.assertEqual(notify_channels.channel_secrets("c0"), {"token": chunk})


class UnreadableSecretsFileTests(_Sandbox):
    """A present-but-unreadable store must refuse writes, not merge onto {}."""

    def _seed_channel(self):
        notify_channels.save_channel({"id": "sib", "type": "telegram",
                                      "name": "sib", "chat_id": "1"})

    def _oversized_store(self) -> str:
        body = json.dumps({
            "sib": {"bot_token": "tok"},
            "other": {"url": "https://example.com/hook"},
            "pad": {"p": "z" * (300 * 1024)},
        })
        self.secrets.write_text(body, encoding="utf-8")
        return body

    def test_secret_write_over_an_oversized_store_is_coded_503(self):
        """set_channel_secrets used to rewrite the whole file from {} here,
        silently wiping every sibling channel's secrets."""
        self._seed_channel()
        before = self._oversized_store()
        r = self.client().put("/api/alerts/channels/sib", json={
            "type": "telegram", "config": {"chat_id": "1"},
            "secrets": {"bot_token": "replacement"},
        })
        self.assertEqual(r.status_code, 503, r.text[:300])
        self.assertEqual(r.json()["detail"]["code"], "notify.secrets_unreadable")
        self.assertEqual(self.secrets.read_text(encoding="utf-8"), before,
                         "the refused write must leave every sibling row on disk")

    def test_secret_write_over_a_corrupt_store_is_coded_503(self):
        """Torn JSON still holds recoverable tokens; merging onto {} wiped them."""
        from fastapi import HTTPException

        self.secrets.write_text('{"sib": {"bot_token": "tok"', encoding="utf-8")
        before = self.secrets.read_text(encoding="utf-8")
        with self.assertRaises(HTTPException) as ctx:
            notify_channels.set_channel_secrets("sib", {"bot_token": "new"})
        self.assertEqual(ctx.exception.detail["code"], "notify.secrets_unreadable")
        self.assertEqual(self.secrets.read_text(encoding="utf-8"), before)

    def test_reads_keep_degrading_and_delete_still_works(self):
        """GET stays 200 (has_* false) and DELETE removes the row without
        rewriting — and therefore without wiping — the unreadable store."""
        self._seed_channel()
        before = self._oversized_store()
        client = self.client()
        r = client.get("/api/alerts/channels")
        self.assertEqual(r.status_code, 200, r.text[:300])
        row = next(c for c in r.json()["channels"] if c["id"] == "sib")
        self.assertFalse(row["has"]["bot_token"])
        r = client.delete("/api/alerts/channels/sib")
        self.assertEqual(r.status_code, 200, r.text[:300])
        self.assertIsNone(notify_channels.get_channel("sib"))
        self.assertEqual(self.secrets.read_text(encoding="utf-8"), before,
                         "the prune must not rewrite a store it could not read")

    def test_missing_and_leftover_nonfile_stores_still_accept_writes(self):
        """The strict gate only guards rows that exist: a missing file and a
        leftover directory occupying the path keep working as before."""
        notify_channels.set_channel_secrets("fresh", {"token": "abc"})
        self.assertEqual(notify_channels.channel_secrets("fresh"), {"token": "abc"})
        self.secrets.unlink()
        self.secrets.mkdir()
        notify_channels.set_channel_secrets("re-made", {"token": "def"})
        self.assertEqual(notify_channels.channel_secrets("re-made"), {"token": "def"})


if __name__ == "__main__":
    unittest.main()
