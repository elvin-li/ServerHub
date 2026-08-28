"""WireGuard leftover-500 sweep #12: write-path rows, provider answer shapes.

wg11 sealed the hash-shadow keys on the *read* pulls and the ``sh()``
answer shapes.  Re-running the same batteries over the mutation and apply
seams (real ``create_app()`` + ``TestClient(raise_server_exceptions=False)``)
surfaced NEW leftover families that still 500'd JSON routes:

* **Write-path peer rows.**  :func:`hub.wireguard_svc._peers_for_write`
  indexed every field bare (``record["public_key"]``), so a partial row
  KeyError'd, a hash-shadow stored key detonated the C-level probe loop,
  and a dict-subclass row bombed its own ``__getitem__`` — a raw 500 on
  POST /api/wireguard/peers, /peers/batch, /peers/delete, /peers/import
  and /peers/psk before any coded error could answer.  The membership
  probes downstream ran stored *values*' own methods too: ``del_peer``'s
  ``!=`` scan reflected into a value's ``__ne__``, ``import_peer``'s set
  build hashed it, ``toggle_psk``'s ``==`` scan compared it.  Rows now
  leave the launder as exact strings; a row with no public key drops
  (the ``peer_records`` empty-row rule) and a missing target answers the
  coded 404.
* **Apply-step answer shapes.**  ``apply_live().get("ok", False)`` in
  ``add_peer``/``batch_add`` — and the bare ``apply_live()`` calls in
  ``del_peer``/``import_peer``/``toggle_psk`` — detonated on a junk or
  raising patched apply step *after the change was already persisted*.
  ``apply_live`` itself read ``run_admin``'s answer bare (``result.get``,
  plus the reflected-``__bool__`` ``or`` on the error field).
  :func:`hub.wireguard_svc._apply_after_write` reads junk as
  "not applied"; the sync route keeps its coded ``wg.sync_failed``.
* **Resolver / snapshot answer shapes.**  The bare 3-way unpack of
  ``live_interface(...)`` (``_dump`` under GET /api/wireguard,
  ``apply_live`` under POST /sync), the bare 2-way unpack of ``fan_out``
  in ``installation()`` (GET /api/wireguard, GET /api/wireguard/settings,
  and the route guard on every mutation), the bare ``install["installed"]``
  pull in ``status()``, the bare ``state["stale"]``/``state["live"]``/
  ``state["name_file"]`` pulls in ``interface_action`` and the verbatim
  ``run_admin_sequence`` answer all 500'd on shapes the read-path launders
  already absorb.  :func:`hub.wireguard_svc._live_answer`,
  :func:`hub.wireguard_svc._runtime_view` and
  :func:`hub.wireguard_svc._admin_sequence_answer` read junk as the
  conservative degrade (not running / not stale / coded failure).

Conflict pins kept from earlier sweeps and re-asserted below: the
``wg.ping_missing`` 503 stays disk-confirmed only and still fires through
the union of guards in ``ping_peers``/``_ping_deadline``/``_ping_targets``;
``_sh_answer`` keeps reading junk as ``(-255, "", "")`` and passing the
honest vanished sentinel through; ``_mapping_get`` keeps shadowed lookups
absent; ``_isa``, the ``type``-identity bool gates and the guarded-decode
``_as_text`` stay as wg10/wg11 pinned them.  No new error codes and no
product-version bump: 3.9.3 stays.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from hub import wireguard_svc  # noqa: E402

#: The real snapshot builder, captured before route tests patch it away.
_REAL_INSTALLATION = wireguard_svc.installation

PUB = "A" * 42 + "b="
PUB2 = "C" * 42 + "d="
PRIV = "B" * 42 + "c="

INSTALL = {
    "installed": True, "conf_exists": True, "conf_path": "", "conf_dir": "",
    "wg": "wg", "wg_quick": "wg-quick", "wireguard_go": "",
    "tools_version": "v1", "userspace_version": "", "probe_failed": False,
}

#: sh()'s exact FileNotFoundError sentinel for a vanished binary.
_VANISHED = (-1, "", "not found")

#: Answers no honest provider ever gives: not the expected sequence shape.
_JUNK_ANSWERS = (None, "junk", (0, ""), ("a", "b", "c", "d"), object(), 7)


def _no_surrogates(payload) -> None:
    """What Starlette's JSONResponse does to the body (allow_nan=False)."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class _ShadowKey(str):
    """A stored key that hash-collides with *target* and bombs the probe loop."""

    armed = False

    def __new__(cls, target):
        self = str.__new__(cls, "\x00shadow:" + target)
        self._target_hash = hash(target)
        return self

    def __hash__(self):
        return self._target_hash

    def __eq__(self, other):
        if _ShadowKey.armed:
            raise RuntimeError("hash-shadow eq bomb")
        return str.__eq__(self, other)

    def __ne__(self, other):
        if _ShadowKey.armed:
            raise RuntimeError("hash-shadow ne bomb")
        return str.__ne__(self, other)


def _shadowed(base: dict, *targets: str) -> dict:
    """*base* plus one shadow key per absent *target*, armed on return."""
    _ShadowKey.armed = False
    out = dict(base)
    for target in targets:
        out[_ShadowKey(target)] = "shadow-junk"
    _ShadowKey.armed = True
    return out


class _CmpBombStr(str):
    """A stored value whose comparison hooks raise; ``__str__`` stays honest."""

    def __eq__(self, other):
        raise RuntimeError("value eq bomb")

    def __ne__(self, other):
        raise RuntimeError("value ne bomb")

    def __hash__(self):
        raise RuntimeError("value hash bomb")


class _BoolBomb:
    def __bool__(self):
        raise RuntimeError("bool bomb")


class PeersForWriteUnitTests(unittest.TestCase):
    def _rows(self, rows):
        with mock.patch.object(wireguard_svc, "peer_records", lambda: rows):
            return wireguard_svc._peers_for_write()

    def test_honest_rows_pass_through_as_exact_strings(self):
        rows = [{
            "public_key": PUB, "ip": "10.9.0.2/32", "preshared_key": "",
            "name": "phone", "keepalive": "25", "known": True,
        }]
        peers = self._rows(rows)
        self.assertEqual(peers, [{
            "public_key": PUB, "ip": "10.9.0.2/32", "preshared_key": "",
            "name": "phone", "keepalive": "25",
        }])
        for value in peers[0].values():
            self.assertIs(type(value), str)

    def test_partial_and_shadow_rows_drop_alone(self):
        rows = [
            {"ip": "10.9.0.9/32"},                       # no public key at all
            _shadowed({"ip": "10.9.0.8/32"}, "public_key"),
            {"public_key": PUB, "ip": "10.9.0.2/32"},    # honest, partial rest
        ]
        peers = self._rows(rows)
        self.assertEqual([p["public_key"] for p in peers], [PUB])
        self.assertEqual(peers[0]["preshared_key"], "")

    def test_value_bombs_leave_as_plain_text(self):
        rows = [{"public_key": _CmpBombStr(PUB), "ip": "10.9.0.2/32"}]
        peers = self._rows(rows)
        self.assertEqual(peers[0]["public_key"], PUB)
        self.assertIs(type(peers[0]["public_key"]), str)
        # The live leftover: the membership probes ran these very hooks.
        self.assertFalse(peers[0]["public_key"] != PUB)
        self.assertIn(peers[0]["public_key"], {PUB})

    def test_junk_listings_read_as_empty(self):
        for junk in (None, "junk", 7, object()):
            self.assertEqual(self._rows(junk), [])
        with mock.patch.object(
            wireguard_svc, "peer_records",
            mock.Mock(side_effect=RuntimeError("listing bomb")),
        ):
            self.assertEqual(wireguard_svc._peers_for_write(), [])


class LiveAnswerUnitTests(unittest.TestCase):
    def _run(self, answer):
        with mock.patch.object(
            wireguard_svc, "live_interface", lambda interface: answer
        ):
            return wireguard_svc._live_answer("wg0")

    def test_junk_shapes_read_as_not_running(self):
        for junk in _JUNK_ANSWERS:
            self.assertEqual(self._run(junk), ("", [], ""))

    def test_a_raising_resolver_reads_as_not_running(self):
        with mock.patch.object(
            wireguard_svc, "live_interface",
            mock.Mock(side_effect=RuntimeError("resolver bomb")),
        ):
            self.assertEqual(wireguard_svc._live_answer("wg0"), ("", [], ""))

    def test_honest_answers_pass_through(self):
        head = [PRIV, PUB2, "51820", "off"]
        self.assertEqual(
            self._run(("utun8", [head], "")), ("utun8", [head], "")
        )
        self.assertEqual(self._run(("", [], "not running")), ("", [], "not running"))

    def test_junk_rows_drop_alone(self):
        head = [PRIV, PUB2, "51820", "off"]
        device, rows, error = self._run(("utun8", [head, "junk", 7, None], ""))
        self.assertEqual(device, "utun8")
        self.assertEqual(rows, [head])
        self.assertEqual(error, "")


class ApplyAfterWriteUnitTests(unittest.TestCase):
    def test_junk_answers_read_as_not_applied(self):
        for junk in (*_JUNK_ANSWERS, {"error": "x"}, _shadowed({}, "ok")):
            with mock.patch.object(wireguard_svc, "apply_live", lambda j=junk: j):
                self.assertFalse(wireguard_svc._apply_after_write())

    def test_a_raising_apply_step_reads_as_not_applied(self):
        with mock.patch.object(
            wireguard_svc, "apply_live",
            mock.Mock(side_effect=RuntimeError("apply bomb")),
        ):
            self.assertFalse(wireguard_svc._apply_after_write())

    def test_bool_bomb_ok_costs_only_itself(self):
        with mock.patch.object(
            wireguard_svc, "apply_live", lambda: {"ok": _BoolBomb()}
        ):
            self.assertFalse(wireguard_svc._apply_after_write())

    def test_honest_answers_pass_through(self):
        with mock.patch.object(
            wireguard_svc, "apply_live", lambda: {"ok": True, "applied": True}
        ):
            self.assertTrue(wireguard_svc._apply_after_write())
        with mock.patch.object(
            wireguard_svc, "apply_live",
            lambda: {"ok": True, "applied": False, "reason": "not_running"},
        ):
            self.assertTrue(wireguard_svc._apply_after_write())


class RuntimeViewUnitTests(unittest.TestCase):
    def test_junk_snapshots_read_as_idle(self):
        for junk in (*_JUNK_ANSWERS, {"stale": True}):
            stale, live, name_file = wireguard_svc._runtime_view(junk)
            if not isinstance(junk, dict):
                self.assertEqual((stale, live, name_file), (False, False, ""))
        self.assertEqual(
            wireguard_svc._runtime_view({"stale": True}),
            (True, False, ""),
        )

    def test_shadow_keys_read_as_absent(self):
        snapshot = _shadowed({"interface": "wg0"}, "stale", "live", "name_file")
        self.assertEqual(
            wireguard_svc._runtime_view(snapshot), (False, False, "")
        )

    def test_honest_snapshots_pass_through(self):
        self.assertEqual(
            wireguard_svc._runtime_view({
                "stale": True, "live": False, "name_file": "/var/run/wg0.name",
            }),
            (True, False, "/var/run/wg0.name"),
        )

    def test_bool_bombs_cost_only_their_field(self):
        snapshot = {"stale": _BoolBomb(), "live": True, "name_file": "n"}
        self.assertEqual(wireguard_svc._runtime_view(snapshot), (False, True, "n"))


class AdminSequenceAnswerUnitTests(unittest.TestCase):
    def _run(self, answer):
        with mock.patch.object(
            wireguard_svc, "run_admin_sequence", lambda commands, timeout: answer
        ):
            return wireguard_svc._admin_sequence_answer([["x"]], timeout=1)

    def test_junk_answers_read_as_the_coded_failure(self):
        for junk in (*_JUNK_ANSWERS, _shadowed({}, "ok", "error")):
            self.assertEqual(self._run(junk), {"ok": False, "error": "failed"})

    def test_a_raising_helper_reads_as_the_coded_failure(self):
        with mock.patch.object(
            wireguard_svc, "run_admin_sequence",
            mock.Mock(side_effect=RuntimeError("helper bomb")),
        ):
            self.assertEqual(
                wireguard_svc._admin_sequence_answer([["x"]], timeout=1),
                {"ok": False, "error": "failed"},
            )

    def test_honest_answers_keep_their_coded_error(self):
        # Pin: the password_required refusal must survive so the SPA can
        # still raise its password prompt.
        self.assertEqual(
            self._run({"ok": False, "error": "password_required"}),
            {"ok": False, "error": "password_required"},
        )
        self.assertEqual(self._run({"ok": True}), {"ok": True})


class InstallationShapeUnitTests(unittest.TestCase):
    def test_junk_fan_out_answers_keep_the_snapshot_shape(self):
        for junk in (*_JUNK_ANSWERS, ["only-one"], ["a", "b", "c"]):
            with mock.patch.object(
                wireguard_svc, "fan_out", lambda *a, j=junk, **k: j
            ), mock.patch.object(wireguard_svc, "_path_exists", lambda p: True):
                snapshot = wireguard_svc.installation()
            self.assertTrue(snapshot["installed"])
            self.assertEqual(snapshot["tools_version"], "")
            self.assertTrue(snapshot["probe_failed"])
            _no_surrogates(snapshot)

    def test_a_raising_fan_out_keeps_the_snapshot_shape(self):
        with mock.patch.object(
            wireguard_svc, "fan_out",
            mock.Mock(side_effect=RuntimeError("pool bomb")),
        ), mock.patch.object(wireguard_svc, "_path_exists", lambda p: True):
            snapshot = wireguard_svc.installation()
        self.assertTrue(snapshot["installed"])
        self.assertEqual(snapshot["userspace_version"], "")

    def test_honest_versions_pass_through(self):
        with mock.patch.object(
            wireguard_svc, "fan_out", lambda *a, **k: ("v1.0", "go-0.0.20")
        ), mock.patch.object(wireguard_svc, "_path_exists", lambda p: True):
            snapshot = wireguard_svc.installation()
        self.assertEqual(snapshot["tools_version"], "v1.0")
        self.assertEqual(snapshot["userspace_version"], "go-0.0.20")
        self.assertFalse(snapshot["probe_failed"])


class _MountedRouteTests(unittest.TestCase):
    """Real app, auth overridden, admin guard and installation patched."""

    def setUp(self):
        from fastapi.testclient import TestClient

        from hub.app_factory import create_app
        from hub.auth import require_auth
        from hub.routers import wireguard_api

        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        app = create_app()
        app.dependency_overrides[require_auth] = lambda: True
        self.addCleanup(app.dependency_overrides.clear)
        self.client = TestClient(app, raise_server_exceptions=False)
        self.stack.enter_context(mock.patch.object(
            wireguard_api, "require_admin_browser", lambda request: "admin"
        ))
        self.stack.enter_context(mock.patch.object(
            wireguard_svc, "installation", lambda: dict(INSTALL)
        ))

    def get_ok(self, path):
        resp = self.client.get(path)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _no_surrogates(body)
        return body


class MutationRowRouteTests(_MountedRouteTests):
    """Write-path rows: the five peer mutations survive poisoned listings."""

    def _persist_patches(self):
        return (
            mock.patch.object(
                wireguard_svc, "_write_conf", lambda peers: Path("/tmp/wg12")
            ),
            mock.patch.object(
                wireguard_svc, "_load_registry", lambda: {"peers": {}}
            ),
            mock.patch.object(wireguard_svc, "_save_registry", lambda data: None),
            mock.patch.object(
                wireguard_svc, "apply_live", lambda: {"ok": True, "applied": True}
            ),
        )

    def test_delete_shadow_pubkey_row_answers_the_coded_404(self):
        rows = [_shadowed({"ip": "10.10.0.2/32"}, "public_key")]
        with mock.patch.object(wireguard_svc, "peer_records", lambda: rows):
            resp = self.client.post(
                "/api/wireguard/peers/delete",
                json={"pubkey": PUB, "confirm": True},
            )
        self.assertEqual(resp.status_code, 404, resp.text[:300])
        self.assertEqual(resp.json()["detail"]["code"], "wg.peer_not_found")

    def test_delete_value_bomb_row_still_deletes_the_peer(self):
        # The live leftover: ``p["public_key"] != public`` reflected into
        # the stored value's own ``__ne__`` and 500'd the route.
        rows = [{"public_key": _CmpBombStr(PUB), "ip": "10.10.0.2/32"}]
        with ExitStack() as stack:
            for patch in self._persist_patches():
                stack.enter_context(patch)
            stack.enter_context(
                mock.patch.object(wireguard_svc, "peer_records", lambda: rows)
            )
            resp = self.client.post(
                "/api/wireguard/peers/delete",
                json={"pubkey": PUB, "confirm": True},
            )
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _no_surrogates(body)
        self.assertEqual(body["remaining"], 0)

    def test_psk_partial_row_answers_the_coded_404(self):
        with mock.patch.object(
            wireguard_svc, "peer_records", lambda: [{"ip": "10.10.0.2/32"}]
        ):
            resp = self.client.post(
                "/api/wireguard/peers/psk", json={"pubkey": PUB, "op": "remove"}
            )
        self.assertEqual(resp.status_code, 404, resp.text[:300])
        self.assertEqual(resp.json()["detail"]["code"], "wg.peer_not_found")

    def test_psk_value_bomb_row_still_toggles(self):
        rows = [{
            "public_key": _CmpBombStr(PUB), "ip": "10.10.0.2/32",
            "preshared_key": "x", "name": "phone", "keepalive": "25",
        }]
        with ExitStack() as stack:
            for patch in self._persist_patches():
                stack.enter_context(patch)
            stack.enter_context(
                mock.patch.object(wireguard_svc, "peer_records", lambda: rows)
            )
            resp = self.client.post(
                "/api/wireguard/peers/psk", json={"pubkey": PUB, "op": "remove"}
            )
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(resp.json()["psk"], "")

    def test_import_shadow_row_costs_only_that_row(self):
        # The set build hashed every stored public key; the shadow slot
        # detonated it after validation had already passed.
        rows = [_shadowed({"ip": "10.10.0.2/32"}, "public_key")]
        with ExitStack() as stack:
            for patch in self._persist_patches():
                stack.enter_context(patch)
            stack.enter_context(
                mock.patch.object(wireguard_svc, "peer_records", lambda: rows)
            )
            resp = self.client.post(
                "/api/wireguard/peers/import",
                json={"pubkey": PUB2, "ip": "10.10.0.9", "name": "box"},
            )
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _no_surrogates(body)
        self.assertEqual(body["ip"], "10.10.0.9/32")

    def test_import_duplicate_still_answers_the_coded_409(self):
        # Pin: laundering the membership probe must not blunt the honest
        # duplicate check.
        rows = [{"public_key": PUB2, "ip": "10.10.0.2/32"}]
        with mock.patch.object(wireguard_svc, "peer_records", lambda: rows):
            resp = self.client.post(
                "/api/wireguard/peers/import",
                json={"pubkey": PUB2, "ip": "10.10.0.9", "name": "box"},
            )
        self.assertEqual(resp.status_code, 409, resp.text[:300])
        self.assertEqual(resp.json()["detail"]["code"], "wg.peer_exists")


class ApplyStepRouteTests(_MountedRouteTests):
    ENTRY = {
        "public_key": PUB, "ip": "10.10.0.2/32", "preshared_key": "",
        "name": "phone", "keepalive": 25,
    }
    META = {"name": "phone", "ip": "10.10.0.2/32", "mode": "split", "created": 1}
    RESULT = {
        "ok": True, "name": "phone", "ip": "10.10.0.2/32", "pub": PUB,
        "mode": "split", "psk": "", "client_conf": "[Interface]\n",
        "reissuable": True, "applied": False, "endpoint_configured": False,
    }

    def _add(self, apply_answer, *, body=None, path="/api/wireguard/peers"):
        def mint(**kwargs):
            return dict(self.ENTRY), dict(self.META), dict(self.RESULT)

        with mock.patch.object(
            wireguard_svc, "used_addresses", lambda: set()
        ), mock.patch.object(
            wireguard_svc, "_mint_peer", mint
        ), mock.patch.object(
            wireguard_svc, "_peers_for_write", lambda: []
        ), mock.patch.object(
            wireguard_svc, "_write_conf", lambda peers: Path("/tmp/wg12")
        ), mock.patch.object(
            wireguard_svc, "_load_registry", lambda: {"peers": {}}
        ), mock.patch.object(
            wireguard_svc, "_save_registry", lambda data: None
        ), mock.patch.object(wireguard_svc, "apply_live", apply_answer):
            return self.client.post(path, json=body or {"name": "phone"})

    def test_junk_apply_answers_keep_the_create_200(self):
        for junk in _JUNK_ANSWERS:
            resp = self._add(lambda j=junk: j)
            self.assertEqual(resp.status_code, 200, resp.text[:300])
            body = resp.json()
            _no_surrogates(body)
            self.assertFalse(body["applied"])

    def test_a_raising_apply_step_keeps_the_create_200(self):
        resp = self._add(mock.Mock(side_effect=RuntimeError("apply bomb")))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertFalse(resp.json()["applied"])

    def test_honest_apply_answer_still_reports_applied(self):
        # Pin: the launder must not blunt a healthy apply step.
        resp = self._add(lambda: {"ok": True, "applied": True, "device": "utun8"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertTrue(resp.json()["applied"])

    def test_batch_junk_apply_answer_keeps_the_200(self):
        resp = self._add(
            lambda: None,
            body={"count": 2, "prefix": "peer"},
            path="/api/wireguard/peers/batch",
        )
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _no_surrogates(body)
        self.assertEqual(body["created"], 2)

    def _sync(self, sh_answer, run_admin):
        staged = Path(tempfile.mkdtemp(prefix="wg12-conf-")) / "wg0.conf"
        staged.write_text("[Interface]\nListenPort = 51820\n")
        with mock.patch.object(
            wireguard_svc, "live_interface", lambda interface: ("utun8", [], "")
        ), mock.patch.object(
            wireguard_svc, "conf_path", lambda interface=None: staged
        ), mock.patch.object(
            wireguard_svc, "sh", lambda *a, **k: sh_answer
        ), mock.patch.object(wireguard_svc, "run_admin", run_admin):
            return self.client.post("/api/wireguard/sync")

    def test_junk_run_admin_answers_keep_the_coded_sync_error(self):
        for junk in _JUNK_ANSWERS:
            resp = self._sync((1, "", "boom"), lambda *a, j=junk, **k: j)
            self.assertEqual(resp.status_code, 500, resp.text[:300])
            self.assertEqual(resp.json()["detail"]["code"], "wg.sync_failed")

    def test_a_raising_run_admin_keeps_the_coded_sync_error(self):
        resp = self._sync(
            (1, "", "boom"), mock.Mock(side_effect=RuntimeError("admin bomb"))
        )
        self.assertEqual(resp.status_code, 500, resp.text[:300])
        self.assertEqual(resp.json()["detail"]["code"], "wg.sync_failed")

    def test_honest_run_admin_success_still_syncs(self):
        # Pin: a healthy escalated retry keeps answering 200.
        resp = self._sync((1, "", "boom"), lambda *a, **k: {"ok": True})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertTrue(resp.json()["applied"])


class ResolverShapeRouteTests(_MountedRouteTests):
    def test_junk_live_interface_answers_keep_status_200(self):
        for junk in _JUNK_ANSWERS:
            with mock.patch.object(
                wireguard_svc, "live_interface", lambda interface, j=junk: j
            ):
                body = self.get_ok("/api/wireguard")
            self.assertFalse(body["running"])

    def test_a_raising_live_interface_keeps_status_200(self):
        with mock.patch.object(
            wireguard_svc, "live_interface",
            mock.Mock(side_effect=RuntimeError("resolver bomb")),
        ):
            body = self.get_ok("/api/wireguard")
        self.assertFalse(body["running"])

    def test_junk_live_interface_answer_keeps_sync_a_clean_noop(self):
        with mock.patch.object(
            wireguard_svc, "live_interface", lambda interface: "junk"
        ):
            resp = self.client.post("/api/wireguard/sync")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        self.assertFalse(body["applied"])
        self.assertEqual(body["reason"], "not_running")

    def test_honest_dump_rows_still_render_the_live_table(self):
        # Pin: the launder must not blunt a healthy resolver answer.
        head = [PRIV, PUB2, "51820", "off"]
        peer = [PUB, "(none)", "1.2.3.4:5", "10.10.0.2/32", "0", "5", "6", "off"]
        conf = {
            "interface": {},
            "peers": [{"PublicKey": PUB, "AllowedIPs": "10.10.0.2/32"}],
        }
        with mock.patch.object(
            wireguard_svc, "live_interface",
            lambda interface: ("utun8", [head, "junk-row", peer], ""),
        ), mock.patch.object(
            wireguard_svc, "read_conf", lambda interface=None: conf
        ):
            body = self.get_ok("/api/wireguard")
        self.assertTrue(body["running"])
        self.assertEqual(body["listen_port"], 51820)
        self.assertEqual(body["public_key"], PUB2)
        self.assertEqual(body["peers"][0]["endpoint"], "1.2.3.4:5")

    def test_junk_fan_out_answers_keep_both_reads_200(self):
        for junk in _JUNK_ANSWERS:
            with ExitStack() as stack:
                # Drop the class-level installation patch: this battery
                # exercises the real snapshot builder over a junk pool.
                stack.enter_context(mock.patch.object(
                    wireguard_svc, "fan_out", lambda *a, j=junk, **k: j
                ))
                stack.enter_context(mock.patch.object(
                    wireguard_svc, "_path_exists", lambda p: True
                ))
                stack.enter_context(mock.patch.object(
                    wireguard_svc, "installation", _REAL_INSTALLATION
                ))
                body = self.get_ok("/api/wireguard")
                self.get_ok("/api/wireguard/settings")
            self.assertTrue(body["installed"])
            self.assertEqual(body["install"]["tools_version"], "")

    def test_partial_installation_snapshot_keeps_status_200(self):
        with mock.patch.object(
            wireguard_svc, "installation", lambda: {"conf_exists": True}
        ):
            body = self.get_ok("/api/wireguard")
        self.assertFalse(body["installed"])

    def test_shadow_installation_snapshot_keeps_status_200(self):
        snapshot = _shadowed({"conf_exists": True}, "installed")
        with mock.patch.object(wireguard_svc, "installation", lambda: snapshot):
            body = self.get_ok("/api/wireguard")
        self.assertFalse(body["installed"])


class InterfaceRouteTests(_MountedRouteTests):
    HEALTHY = {
        "stale": False, "live": False, "name_file": "/tmp/wg0.name",
        "interface": "wg0", "name_file_present": False,
        "sockets": [], "real_interface": "",
    }

    def _act(self, state, sh_answer, *, action="up", seq=None):
        patches = [
            mock.patch.object(wireguard_svc, "_path_exists", lambda p: True),
            mock.patch.object(
                wireguard_svc, "runtime_state",
                state if callable(state) else (lambda iface=None, s=state: s),
            ),
            mock.patch.object(wireguard_svc, "sh", lambda *a, **k: sh_answer),
        ]
        if seq is not None:
            patches.append(
                mock.patch.object(wireguard_svc, "run_admin_sequence", seq)
            )
        with ExitStack() as stack:
            for patch in patches:
                stack.enter_context(patch)
            return self.client.post(
                "/api/wireguard/interface", json={"action": action}
            )

    def test_junk_runtime_snapshots_keep_the_action_answering(self):
        for junk in _JUNK_ANSWERS:
            resp = self._act(junk, (0, "", ""))
            self.assertEqual(resp.status_code, 200, resp.text[:300])
            self.assertTrue(resp.json()["ok"])

    def test_shadow_runtime_snapshot_keeps_the_action_answering(self):
        state = _shadowed({"interface": "wg0"}, "stale", "live", "name_file")
        resp = self._act(state, (0, "", ""))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertTrue(resp.json()["ok"])

    def test_a_raising_runtime_state_keeps_the_action_answering(self):
        resp = self._act(
            mock.Mock(side_effect=RuntimeError("snapshot bomb")), (0, "", "")
        )
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertTrue(resp.json()["ok"])

    def test_honest_live_snapshot_still_short_circuits_up(self):
        # Pin: the launder must not blunt "already running".
        state = dict(self.HEALTHY, live=True)
        resp = self._act(state, (0, "", ""))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertTrue(resp.json()["already_running"])

    def test_junk_sequence_answers_keep_the_coded_admin_error(self):
        for junk in _JUNK_ANSWERS:
            resp = self._act(
                dict(self.HEALTHY),
                (1, "", "sudo: a password is required"),
                seq=lambda *a, j=junk, **k: j,
            )
            self.assertEqual(resp.status_code, 500, resp.text[:300])
            self.assertEqual(resp.json()["detail"]["code"], "admin.failed")

    def test_honest_password_refusal_keeps_its_coded_answer(self):
        # Pin: the coded password_required refusal must survive the
        # answer launder so the SPA can raise its prompt.
        resp = self._act(
            dict(self.HEALTHY),
            (1, "", "sudo: a password is required"),
            seq=lambda *a, **k: {"ok": False, "error": "password_required"},
        )
        self.assertEqual(resp.status_code, 409, resp.text[:300])
        self.assertEqual(
            resp.json()["detail"]["code"], "admin.password_required"
        )


class ConflictPinTests(_MountedRouteTests):
    """The wg10/wg11 union guards this wave must not weaken."""

    CLEAN = {"public_key": PUB2, "ip": "10.9.0.3/32", "name": "ok"}

    def _ping(self, records, sh_answer):
        with mock.patch.object(
            wireguard_svc, "peer_records", lambda: records
        ), mock.patch.object(wireguard_svc, "sh", lambda *a, **k: sh_answer):
            return self.client.post("/api/wireguard/ping")

    def test_ping_missing_503_stays_disk_confirmed(self):
        with mock.patch.object(wireguard_svc, "_ping_cli_gone", lambda: True):
            resp = self._ping([dict(self.CLEAN)], _VANISHED)
        self.assertEqual(resp.status_code, 503, resp.text[:300])
        self.assertEqual(resp.json()["detail"]["code"], "wg.ping_missing")

    def test_ping_sentinel_without_disk_confirm_stays_200(self):
        with mock.patch.object(wireguard_svc, "_ping_cli_gone", lambda: False):
            resp = self._ping([dict(self.CLEAN)], _VANISHED)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertFalse(resp.json()["results"][0]["reachable"])

    def test_ping_junk_rows_still_drop_alone(self):
        rows = [_shadowed({"public_key": PUB, "name": "junk"}, "ip"),
                dict(self.CLEAN)]
        resp = self._ping(rows, (0, "", ""))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(resp.json()["total"], 1)

    def test_sh_answer_and_mapping_get_keep_their_pinned_shapes(self):
        self.assertEqual(
            wireguard_svc._sh_answer(lambda argv, timeout: None, [], timeout=1),
            (-255, "", ""),
        )
        self.assertEqual(
            wireguard_svc._sh_answer(
                lambda argv, timeout: _VANISHED, [], timeout=1
            ),
            _VANISHED,
        )
        self.assertIsNone(
            wireguard_svc._mapping_get(_shadowed({}, "ip"), "ip")
        )
        self.assertEqual(wireguard_svc._ping_deadline(_BoolBomb()), 800)

    def test_product_version_stays_pinned(self):
        from hub import __version__

        self.assertEqual(__version__, "3.9.4")


if __name__ == "__main__":
    unittest.main()
