"""Thirteenth leftover-500s sweep of the Apps managed surfaces:
BaseException-shaped bombs past ``except Exception``, plus decode fidelity.

apps12 sealed the junk rc/shape family on the ``docker()`` / ``run_capped``
seams, but every guard in ``hub.apps_manage_svc`` stopped at
``except Exception``.  What was still live on the pre-fix tree, driven
through ``create_app()`` + ``TestClient(raise_server_exceptions=False)``:

* A leftover whose hooks raise a *BaseException* subclass (the
  modules12/logs12/jobs13 watchdog/timeout shape) sailed past every catch at
  once: a ``__class__``-property bomb blew ``_isa`` — the gate every
  sanitizer arm stands on — and ``_rc_int``'s bare isinstance probes;
  shadow-key ``__eq__`` bombs blew ``_mapping_get`` past its net;
  ``__bool__`` / ``__str__`` / ``__iter__`` bombs blew ``_truthy`` /
  ``_utf8_text`` / ``_sh_triple`` / ``_run_capped_pair``; and because
  ``_collect``, ``action()`` and every collector seam stopped at
  ``Exception`` too, each detonation rode raw out of GET /api/apps/managed,
  its detail and logs routes, and POST /api/apps/managed/action.
* ``docker_cli._jsonable`` is another module's funnel whose own nets stop at
  ``Exception``, so one nested BaseException-shaped value detonated the
  launder itself — out of ``_clean_rows`` (wiping a whole inventory section)
  and out of ``_safe_payload`` (a raw 500 *after* the action had run).
  ``_safe_payload`` now falls to a per-field salvage: the bombed field
  costs itself, its siblings render.
* ``_inspect`` hands the ``docker inspect`` stdout slot back verbatim and
  ``inspect_object`` names only the parse errors, so a junk out whose type
  gates raise blew the parse itself — a raw 500 on the docker detail route.
* The claimed-base decode gap (the jobs13/modules12 ``_decode_bytes``
  rule): the arm picked the base off the *claimed* ``__class__``, so a
  genuine ``bytearray`` whose ``__class__`` lied ``bytes`` fell through to
  the ``str()`` scrub and rendered as a ``bytearray(b'…')`` repr.

The fixes are the module-local ``_CONTROL_FLOW`` convention (every guard
re-raises KeyboardInterrupt / SystemExit and launders everything else
BaseException-shaped exactly like its Exception twin), the fenced
``_jsonable_safe`` + ``_salvage_dict``, the guarded inspect parse, and the
both-bases first-come decode.  No new error codes: the locales are
untouched.  These tests plant each bomb against our own handlers
in-process and assert 200 / coded 4xx bodies with valid UTF-8 JSON, never
a raw raise — and pin control flow still propagating, because swallowing a
Ctrl-C to save one JSON field would turn the sanitizer into a hang.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from fastapi.testclient import TestClient  # noqa: E402

from hub import apps_manage_svc  # noqa: E402
from hub.app_factory import create_app  # noqa: E402
from hub.auth import require_auth  # noqa: E402

_app = None


def _client() -> TestClient:
    global _app
    if _app is None:
        _app = create_app()
        _app.dependency_overrides[require_auth] = lambda: None
    return TestClient(_app, raise_server_exceptions=False)


def _strict_utf8(resp) -> str:
    """The body must already be valid UTF-8 — decode strictly on purpose."""
    return resp.content.decode("utf-8")


# ─── leftover zoo ─────────────────────────────────────────────────────────────

class LeftoverBaseBomb(BaseException):
    """BaseException-shaped, but *not* control flow — a bomb like any other."""


def _base_raising_property():
    return property(
        lambda self: (_ for _ in ()).throw(LeftoverBaseBomb("leftover base bomb")))


class _ClassPropBaseBomb:
    """``__class__`` property raising BaseException — blew ``_isa`` itself,
    the gate every sanitizer arm in this module stands on, and ``_rc_int``'s
    bare isinstance probes."""

    __class__ = _base_raising_property()

    def __str__(self):
        return "still-renderable"


class _BoolBaseBomb:
    """A flag whose ``__bool__`` raises BaseException (engine probe)."""

    def __bool__(self):
        raise LeftoverBaseBomb("bool base bomb")


class _StrBaseBomb:
    """A field whose ``__str__`` raises BaseException (status f-string)."""

    def __str__(self):
        raise LeftoverBaseBomb("str base bomb")


class _ShadowBaseStr(str):
    """Same text and hash as a real field name, ``__eq__`` raising a
    BaseException subclass — the hash probe of ``dict.get`` dispatches into
    it reflected, past the apps9 Exception-shaped seal."""

    def __eq__(self, other):  # noqa: D105
        raise LeftoverBaseBomb("leftover shadow eq base bomb")

    __ne__ = __eq__

    def __hash__(self):  # noqa: D105
        return str.__hash__(self)


class _IterBaseBombTuple(tuple):
    """A spawn return whose bound ``__iter__`` raises BaseException — blew
    the ``rc, out, err = …`` unpack past ``_sh_triple``'s old catch."""

    def __iter__(self):
        raise LeftoverBaseBomb("iter base bomb")


class _NeExcBombInt(int):
    """The apps12 pin: an Exception-shaped rc ``__eq__``/``__ne__`` bomb.

    Kept here so the widened guards demonstrably did not weaken the
    Exception-shaped seals."""

    def __eq__(self, other):  # noqa: D105
        raise RuntimeError("leftover rc __eq__ bomb")

    __ne__ = __eq__
    __hash__ = int.__hash__


class _ShadowExcStr(str):
    """Exception-shaped shadow key (the apps9 seal, pinned unweakened)."""

    def __eq__(self, other):  # noqa: D105
        raise RuntimeError("leftover shadow eq bomb")

    __ne__ = __eq__

    def __hash__(self):  # noqa: D105
        return str.__hash__(self)


class _BytesLiarBytearray(bytearray):
    """A genuine bytearray whose ``__class__`` lies ``bytes``.

    The old claimed-base pick handed the operand to ``bytes.decode``, the
    descriptor refused it, and the perfectly decodable content fell to the
    ``str()`` scrub — a ``bytearray(b'…')`` repr in a name/ports field.
    """

    @property
    def __class__(self):
        return bytes


class _DictLiar:
    """A lying ``__class__`` claiming dict — the unlaunderable-shape
    contract: ``_safe_payload`` hands it back as-is for the caller to own."""

    @property
    def __class__(self):
        return dict


# ─── guard contracts ──────────────────────────────────────────────────────────

class GuardContractTests(unittest.TestCase):
    """The shared guards degrade a BaseException-shaped bomb exactly like
    its Exception twin."""

    def test_isa_reads_a_class_prop_base_bomb_as_no_match(self):
        self.assertIs(apps_manage_svc._isa(_ClassPropBaseBomb(), dict), False)

    def test_truthy_reads_a_bool_base_bomb_as_false(self):
        self.assertIs(apps_manage_svc._truthy(_BoolBaseBomb()), False)

    def test_utf8_text_reads_a_str_base_bomb_as_empty(self):
        self.assertEqual(apps_manage_svc._utf8_text(_StrBaseBomb()), "")

    def test_rc_int_reads_a_class_prop_base_bomb_as_no_exit_status(self):
        self.assertEqual(apps_manage_svc._rc_int(_ClassPropBaseBomb()), -255)

    def test_mapping_get_degrades_a_base_bomb_shadow_key(self):
        row = {_ShadowBaseStr("vms"): "junk"}
        self.assertIsNone(apps_manage_svc._mapping_get(row, "vms"))

    def test_sh_triple_reads_an_iter_base_bomb_shape_as_failure(self):
        bomb = _IterBaseBombTuple(("x", "y", "z"))
        with mock.patch("hub.apps_manage_svc.sh", return_value=bomb):
            self.assertEqual(
                apps_manage_svc._sh_triple(["/bin/true"], 5), (-255, "", ""))

    def test_run_capped_pair_reads_an_iter_base_bomb_shape_as_failure(self):
        bomb = _IterBaseBombTuple(("x", "y"))
        with mock.patch("hub.apps_manage_svc.run_capped", return_value=bomb):
            self.assertEqual(
                apps_manage_svc._run_capped_pair(
                    ["/bin/true"], cwd=None, timeout=5, env=None, cap=100),
                (-255, ""),
            )

    def test_jsonable_safe_reads_a_nested_base_bomb_as_unlaunderable(self):
        self.assertIsNone(
            apps_manage_svc._jsonable_safe({"x": _ClassPropBaseBomb()}))

    def test_clean_rows_drops_only_the_bombed_row(self):
        rows = [{"id": "ok"}, {"id": "junk", "name": _ClassPropBaseBomb()}]
        self.assertEqual(apps_manage_svc._clean_rows(rows), [{"id": "ok"}])

    def test_safe_payload_salvages_around_a_base_bomb_field(self):
        out = apps_manage_svc._safe_payload(
            {"ok": True, "message": "restarted", "detail": _ClassPropBaseBomb()})
        self.assertEqual(out, {"ok": True, "message": "restarted",
                               "detail": None})

    def test_safe_payload_keeps_the_impostor_contract(self):
        # A lying-``__class__`` dict impostor is still handed back as-is:
        # action() / the logs branches own the answer for an unusable shape.
        imp = _DictLiar()
        self.assertIs(apps_manage_svc._safe_payload(imp), imp)


class DecodeFidelityTests(unittest.TestCase):
    """A genuine bytearray whose ``__class__`` lies ``bytes`` decodes
    through its real layout instead of degrading to its repr."""

    def test_decode_bytes_reads_the_honest_content(self):
        liar = _BytesLiarBytearray(b"honest content")
        self.assertEqual(apps_manage_svc._decode_bytes(liar), "honest content")
        # Honest operands keep decoding first-come.
        self.assertEqual(apps_manage_svc._decode_bytes(b"plain"), "plain")
        self.assertEqual(
            apps_manage_svc._decode_bytes(bytearray(b"plain")), "plain")
        # A total liar (real type is neither base) still degrades.
        self.assertIsNone(apps_manage_svc._decode_bytes("not bytes"))

    def test_field_and_text_ranks_keep_the_honest_content(self):
        liar = _BytesLiarBytearray(b"8080")
        self.assertEqual(apps_manage_svc._field_text(liar, ""), "8080")
        self.assertEqual(apps_manage_svc._as_text(liar), "8080")
        self.assertEqual(apps_manage_svc._utf8_text(liar), "8080")


class ControlFlowPassthroughTests(unittest.TestCase):
    """Genuine control flow keeps propagating through every guard."""

    def test_isa_reraises_control_flow(self):
        for kind in (KeyboardInterrupt, SystemExit):
            class Bomb:
                __class__ = property(
                    lambda self, _kind=kind: (_ for _ in ()).throw(_kind()))

            with self.subTest(kind=kind.__name__):
                with self.assertRaises(kind):
                    apps_manage_svc._isa(Bomb(), dict)

    def test_truthy_reraises_control_flow(self):
        for kind in (KeyboardInterrupt, SystemExit):
            class Bomb:
                def __bool__(self, _kind=kind):
                    raise _kind()

            with self.subTest(kind=kind.__name__):
                with self.assertRaises(kind):
                    apps_manage_svc._truthy(Bomb())

    def test_utf8_text_reraises_control_flow(self):
        for kind in (KeyboardInterrupt, SystemExit):
            class Bomb:
                def __str__(self, _kind=kind):
                    raise _kind()

            with self.subTest(kind=kind.__name__):
                with self.assertRaises(kind):
                    apps_manage_svc._utf8_text(Bomb())

    def test_action_seam_reraises_control_flow(self):
        for kind in (KeyboardInterrupt, SystemExit):
            with self.subTest(kind=kind.__name__), \
                    mock.patch("hub.vms_svc.vm_action", side_effect=kind()):
                with self.assertRaises(kind):
                    apps_manage_svc.action("vm:vm1", "restart")


# ─── rigs ─────────────────────────────────────────────────────────────────────

class _InventoryRig(unittest.TestCase):
    """Every collaborator planted empty; each test poisons exactly one."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        services = Path(self._tmp.name) / "services"
        services.mkdir()
        agents = Path(self._tmp.name) / "agents"
        agents.mkdir()
        apps_manage_svc.inventory.invalidate()
        self.addCleanup(apps_manage_svc.inventory.invalidate)
        for target, kwargs in (
            ("hub.apps_manage_svc.SERVICES_ROOT", {"new": services}),
            ("hub.paths.AGENTS_DIR", {"new": str(agents)}),
            ("hub.containers_svc.list_stacks", {"return_value": []}),
            ("hub.containers_svc.list_containers",
             {"return_value": {"containers": []}}),
            ("hub.native_catalog.list_native_apps", {"return_value": []}),
            ("hub.vms_svc.list_all_vms", {"return_value": {"vms": []}}),
            ("hub.apps_manage_svc.engine_up", {"return_value": False}),
            ("hub.apps_manage_svc.host_ip", {"return_value": "127.0.0.1"}),
        ):
            patched = mock.patch(target, **kwargs)
            patched.start()
            self.addCleanup(patched.stop)

    def _inventory(self):
        resp = _client().get("/api/apps/managed", params={"force": "true"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        return json.loads(_strict_utf8(resp))


class InventoryBaseBombHttpTests(_InventoryRig):
    """BaseException-shaped bombs cost their section or row, never the page."""

    def test_a_class_prop_base_bomb_listing_costs_its_section_only(self):
        # _isa detonated on the listing gate itself, then rode every
        # Exception-only seam (_clean_rows → _docker_stacks → _collect)
        # straight out of GET /api/apps/managed as a raw 500.
        with mock.patch("hub.containers_svc.list_stacks",
                        return_value=_ClassPropBaseBomb()):
            payload = self._inventory()
        self.assertEqual(payload["counts"]["docker"], 0)

    def test_a_nested_base_bomb_row_costs_itself_not_its_siblings(self):
        # The row's nested value blew docker_cli._jsonable past its own
        # Exception-only nets and wiped the whole docker section.
        rows = [{"id": "junk", "name": _ClassPropBaseBomb()},
                {"id": "ok", "name": "OK Stack"}]
        with mock.patch("hub.containers_svc.list_stacks", return_value=rows):
            payload = self._inventory()
        ids = {item.get("id") for item in payload["items"]}
        self.assertIn("docker:ok", ids)
        self.assertNotIn("docker:junk", ids)

    def test_a_bool_base_bomb_engine_probe_reads_as_down(self):
        # _truthy's old catch stopped at Exception: the bombed flag raised
        # out of inventory() itself — a raw 500 on GET /api/apps/managed.
        with mock.patch("hub.apps_manage_svc.engine_up",
                        return_value=_BoolBaseBomb()):
            payload = self._inventory()
        self.assertIs(payload["engine_up"], False)

    def test_a_sane_inventory_stays_intact(self):
        rows = [{"id": "web", "name": "Web", "status": "ok"}]
        with mock.patch("hub.containers_svc.list_stacks", return_value=rows):
            payload = self._inventory()
        self.assertEqual(payload["counts"]["docker"], 1)
        by_id = {item.get("id"): item for item in payload["items"]}
        self.assertEqual(by_id["docker:web"]["name"], "Web")


class VmDetailBaseBombHttpTests(unittest.TestCase):
    """The VM detail route answers its coded 404, never a raw 500."""

    def test_a_base_bomb_shadow_vms_key_answers_the_coded_404(self):
        # dict.get's hash probe ran the stored key's __eq__ reflected: the
        # BaseException subclass sailed past _mapping_get and _vm_detail's
        # own net — a raw 500 on GET /api/apps/managed/detail?id=vm:*.
        payload = {_ShadowBaseStr("vms"): [{"id": "vm1"}]}
        with mock.patch("hub.vms_svc.list_all_vms", return_value=payload):
            resp = _client().get(
                "/api/apps/managed/detail", params={"id": "vm:vm1"})
        self.assertEqual(resp.status_code, 404, resp.text[:300])
        body = json.loads(_strict_utf8(resp))
        self.assertEqual(body["detail"]["code"], "apps.vm_not_found")

    def test_a_sane_vm_detail_stays_intact(self):
        payload = {"vms": [{"id": "vm1", "name": "Test VM",
                            "state": "running", "ips": ["192.168.64.2"]}]}
        with mock.patch("hub.vms_svc.list_all_vms", return_value=payload):
            resp = _client().get(
                "/api/apps/managed/detail", params={"id": "vm:vm1"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = json.loads(_strict_utf8(resp))
        self.assertEqual(body["name"], "Test VM")
        self.assertEqual(body["ips"], ["192.168.64.2"])


class ActionBaseBombHttpTests(unittest.TestCase):
    """POST /api/apps/managed/action launders BaseException-shaped bombs on
    both sides of the collaborator seam — the call and the returned payload."""

    def _action(self, vm_action_kwargs):
        with mock.patch("hub.vms_svc.vm_action", **vm_action_kwargs):
            return _client().post(
                "/api/apps/managed/action",
                json={"id": "vm:vm1", "action": "restart"},
            )

    def test_a_base_bomb_raising_collaborator_answers_ok_false(self):
        resp = self._action(
            {"side_effect": LeftoverBaseBomb("vm backend base bomb")})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertFalse(payload["ok"])
        self.assertIn("vm backend base bomb", payload["message"])

    def test_a_base_bomb_field_in_the_result_costs_itself_only(self):
        # The launder ran *outside* action()'s seam: the nested bomb blew
        # _safe_payload's _jsonable raw — a 500 after the restart had run.
        resp = self._action({"return_value": {
            "ok": True, "message": "restarted",
            "detail": _ClassPropBaseBomb(),
        }})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["message"], "restarted")
        self.assertIsNone(payload["detail"])

    def test_a_sane_action_result_stays_intact(self):
        resp = self._action(
            {"return_value": {"ok": True, "message": "restarted"}})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["message"], "restarted")


class NativeLogsBaseBombHttpTests(unittest.TestCase):
    """The launchctl branch of the native logs degrades a BaseException-shaped
    spawn shape to "no logs", never a raw 500."""

    def test_an_iter_base_bomb_sh_shape_keeps_the_logs_route(self):
        bomb = _IterBaseBombTuple(("x", "y", "z"))
        with mock.patch("hub.apps_manage_svc.sh", return_value=bomb):
            resp = _client().get(
                "/api/apps/managed/logs", params={"id": "native:native-redis"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertTrue(payload["ok"])
        self.assertIn("No dedicated log file found", payload["log"])


class ComposeRcBaseBombHttpTests(unittest.TestCase):
    """A compose rc whose ``__class__`` property raises BaseException reads
    as failure with the output text kept — the apps12 contract, one
    exception rank over."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        services = Path(self._tmp.name) / "services"
        web = services / "web"
        web.mkdir(parents=True)
        (web / "docker-compose.yml").write_text("services: {}\n")
        apps_manage_svc.inventory.invalidate()
        self.addCleanup(apps_manage_svc.inventory.invalidate)
        for target, kwargs in (
            ("hub.apps_manage_svc.SERVICES_ROOT", {"new": services}),
            ("hub.apps_manage_svc.DOCKER", {"new": "/bin/ls"}),
        ):
            patched = mock.patch(target, **kwargs)
            patched.start()
            self.addCleanup(patched.stop)

    def test_a_class_prop_base_bomb_rc_keeps_the_compose_log_text(self):
        # _rc_int's bare isinstance probes read the raising __class__: the
        # BaseException subclass rode past _rc_int, _run_capped_pair and
        # _compose_cmd's Exception-only seam — a raw 500 on the logs route.
        with mock.patch("hub.apps_manage_svc.run_capped",
                        return_value=(_ClassPropBaseBomb(), "compose log text")):
            resp = _client().get(
                "/api/apps/managed/logs", params={"id": "docker:web"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertFalse(payload["ok"])
        self.assertIn("compose log text", payload["log"])


class DockerDetailJunkInspectOutTests(unittest.TestCase):
    """A junk inspect stdout slot costs its own reading, never the route."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        services = Path(self._tmp.name) / "services"
        services.mkdir()
        apps_manage_svc.inventory.invalidate()
        self.addCleanup(apps_manage_svc.inventory.invalidate)
        for target, kwargs in (
            ("hub.apps_manage_svc.SERVICES_ROOT", {"new": services}),
            ("hub.containers_svc.list_stacks", {"return_value": []}),
            ("hub.containers_svc.list_containers", {"return_value": {
                "containers": [{"id": "web1", "project": "web",
                                "state": "ok",
                                "ports": "0.0.0.0:8080->80/tcp"}],
            }}),
        ):
            patched = mock.patch(target, **kwargs)
            patched.start()
            self.addCleanup(patched.stop)

    def test_a_class_prop_base_bomb_out_slot_keeps_the_detail_route(self):
        # _inspect hands the out slot back verbatim; the parser's type
        # gates read the raising __class__ and the BaseException subclass
        # escaped inspect_object's named catches — a raw 500 on
        # GET /api/apps/managed/detail?id=docker:* after every inspect ran.
        with mock.patch("hub.apps_manage_svc.docker",
                        return_value=(0, _ClassPropBaseBomb(), "")):
            resp = _client().get(
                "/api/apps/managed/detail", params={"id": "docker:web"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertEqual(payload["source_id"], "web")
        # Junk inspect output reads as "no inspect data": the container
        # keeps its listing row, the tables stay empty.
        self.assertEqual(payload["containers"][0]["name"], "web1")


class CloudflaredDetailBaseBombHttpTests(unittest.TestCase):
    """A bombed status field costs the cloudflared section, never the
    native detail route."""

    def test_a_str_base_bomb_tunnel_name_costs_the_section_only(self):
        status = {"running": True, "active_tunnel": _StrBaseBomb()}
        with mock.patch("hub.cloudflared_svc.status", return_value=status), \
                mock.patch("hub.native_catalog.list_native_apps",
                           return_value=[]), \
                mock.patch("hub.tools_svc.listening_ports",
                           return_value={"ports": []}):
            resp = _client().get(
                "/api/apps/managed/detail",
                params={"id": "native:native-cloudflared"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertEqual(payload["source_id"], "native-cloudflared")
        self.assertIs(payload["cloudflared"]["ok"], False)


class StaysImmunePins(unittest.TestCase):
    """The apps12-era Exception-shaped seals must not have weakened."""

    def test_an_exception_shaped_rc_eq_bomb_still_reads_exact(self):
        self.assertEqual(apps_manage_svc._rc_int(_NeExcBombInt(0)), 0)
        self.assertEqual(apps_manage_svc._rc_int(_NeExcBombInt(3)), 3)

    def test_an_exception_shaped_shadow_key_still_degrades(self):
        self.assertIsNone(
            apps_manage_svc._mapping_get({_ShadowExcStr("vms"): "x"}, "vms"))

    def test_genuine_values_still_round_trip(self):
        self.assertEqual(apps_manage_svc._rc_int(0), 0)
        self.assertEqual(apps_manage_svc._rc_int(True), 1)
        self.assertEqual(apps_manage_svc._mapping_get({"k": 7}, "k"), 7)
        self.assertIs(apps_manage_svc._truthy([1]), True)
        self.assertEqual(apps_manage_svc._utf8_text("häl√"), "häl√")
        self.assertEqual(
            apps_manage_svc._safe_payload({"ok": True, "n": 3}),
            {"ok": True, "n": 3})


class ProductVersionPin(unittest.TestCase):
    def test_product_version_stays_pinned(self):
        from hub import __version__

        self.assertEqual(__version__, "3.9.3")


if __name__ == "__main__":
    unittest.main(verbosity=2)
