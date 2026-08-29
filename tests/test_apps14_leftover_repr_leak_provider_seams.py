"""Fourteenth leftover sweep of the Apps managed surfaces: the default
``object.__repr__`` heap-address leak, lying-``__class__`` wrong-rank
recovery, and the ``host_ip`` / ``user_home`` provider seams.

apps13 sealed the BaseException-shaped bomb family; what was still live on
the pre-fix tree, driven through ``create_app()`` +
``TestClient(raise_server_exceptions=False)``:

* **The heap-address leak** (the audit14/modules14 family, never applied
  here).  ``_utf8_text``'s free-text coercion arm ran ``str()`` on any
  leftover shape, and for a type that never overrode
  ``__str__``/``__repr__`` the answer is the default ``object.__repr__`` —
  ``<X object at 0x7f...>``, a raw heap address.  A junk config-override
  value (name/port/group/url) carried it verbatim onto
  GET /api/apps/managed and the launchd detail; a junk cloudflared
  ``active_tunnel`` rode the bare f-string into the native detail's
  ``status_text`` *and* the verbatim ``cloudflared`` hand-off — an
  ASLR-defeating primitive on the Apps page.  ``_field_text``'s own tail
  ran ``str(value)`` first, so the exact-str repr then rode
  ``_utf8_text``'s verbatim data branch past any scrub (the audit14
  ``str(k)`` shape).
* **Wrong-rank drops** (the modules14/files16 shape).  ``isinstance``
  checks the real MRO first and consults ``__class__`` only after it
  misses, so a lying ``__class__`` steered honest storage into the arm of
  its *claim*: the unbound descriptor there refused the real layout and an
  early ``return fallback`` threw renderable content away — a genuine
  override ``port: 8080`` whose ``__class__`` lied float rendered as the
  fallback, and a genuine dict claiming str rendered its repr blob.
* **The provider seams**.  ``host_address``'s and ``paths.user_home``'s
  own nets stop at ``except Exception`` / the typed ``Path.home()`` trio,
  and this module read both providers bare where no seam stands behind
  ``detail()`` / ``logs()``: a leftover raising anything else out of
  ``host_ip()`` was a raw 500 on GET /api/apps/managed/detail for all
  three kinds, and out of ``user_home()`` a raw 500 on the native detail
  and logs routes.
* **Whole-section / whole-preview degrades where a field should cost
  itself.**  A junk cloudflared ``notes`` TypeError'd the bare ``+``
  concat and absorbed the entire (sane) status section into ``ok: false``;
  one nested BaseException-shaped preview value blanked every
  ``_launchd_detail`` preview field at once past the bare ``_jsonable``.

The fixes: the slot probe on the real ``type(value)`` plus the
``_ADDR_REPR_RE`` belt on the coercion arms only (real str/bytes storage
is data — a docker log line may contain the pattern — and stays verbatim);
refused claimed arms fall through to the arm the real storage matches;
fenced ``_host_ip`` / ``_user_home`` wrappers; the sanitized cloudflared
scalar reads and the per-field preview salvage.  No new error codes: the
locales are untouched.  These tests plant each leftover against our own
handlers in-process and assert 200 / coded bodies with no ``at 0x``
address, never a raw raise — and pin control flow still propagating.
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


class _Junk:
    """Never overrode ``__str__``/``__repr__`` — coercing it answers the
    default ``object.__repr__``, a raw heap address."""


class _EmbedsRepr:
    """A custom ``__str__`` whose *rendering* embeds a default repr — what
    the slot probe cannot see and the regex belt exists for."""

    def __str__(self):
        return f"state={object.__repr__(self)}"


class _Renders:
    """A leftover that renders itself: honest coercion text must be kept."""

    def __str__(self):
        return "tunnel-a"


class _IntLiarFloat(int):
    """Genuine int storage whose ``__class__`` lies float — the claimed
    arm's ``float.__float__`` refuses the real layout."""

    @property
    def __class__(self):
        return float


class _StrLiarFloat(str):
    """Genuine str storage claiming float."""

    @property
    def __class__(self):
        return float


class _JunkLiarStr:
    """No usable layout underneath a str claim — must keep the fallback,
    not leak its default repr through the str arm."""

    @property
    def __class__(self):
        return str


class _DictLiarStr(dict):
    """Genuine dict storage claiming str — a container is junk for a
    scalar field, never a ``{'a': 1}`` repr blob."""

    @property
    def __class__(self):
        return str


class _ClassPropBaseBomb:
    """``__class__`` property raising a BaseException subclass (apps13)."""

    __class__ = property(
        lambda self: (_ for _ in ()).throw(LeftoverBaseBomb("cls bomb")))


def _module_fn():
    """A function leftover: C-level ``__repr__`` carries an address."""


# ─── coercion-arm scrub (unit) ────────────────────────────────────────────────

class ReprAddressScrubTests(unittest.TestCase):
    """The coercion arms drop a default-repr leftover instead of leaking
    its heap address; real str/bytes storage stays verbatim data."""

    def test_default_repr_junk_coerces_to_nothing(self):
        self.assertEqual(apps_manage_svc._utf8_text(_Junk()), "")
        self.assertEqual(apps_manage_svc._as_text(_Junk()), "")
        self.assertEqual(apps_manage_svc._field_text(_Junk(), "fb"), "fb")

    def test_function_leftover_hits_the_belt(self):
        # The slot probe cannot see a C-level ``__repr__`` override; the
        # regex belt on the coercion arm drops the address anyway.
        self.assertEqual(apps_manage_svc._utf8_text(_module_fn), "")
        self.assertEqual(apps_manage_svc._as_text(_module_fn), "")

    def test_custom_str_embedding_a_default_repr_hits_the_belt(self):
        self.assertEqual(apps_manage_svc._utf8_text(_EmbedsRepr()), "")
        self.assertEqual(apps_manage_svc._field_text(_EmbedsRepr(), "fb"), "fb")

    def test_self_rendering_coercion_keeps_its_text(self):
        self.assertEqual(apps_manage_svc._utf8_text(_Renders()), "tunnel-a")
        self.assertEqual(apps_manage_svc._as_text(_Renders()), "tunnel-a")
        self.assertEqual(
            apps_manage_svc._field_text(_Renders(), "fb"), "tunnel-a")

    def test_real_str_and_bytes_storage_stay_verbatim_data(self):
        # A docker log line may legitimately contain the pattern: data is
        # never belted, only the coercion arm is.
        line = "worker died at 0xdeadbeef> restarting"
        self.assertEqual(apps_manage_svc._utf8_text(line), line)
        self.assertEqual(apps_manage_svc._as_text(line), line)
        self.assertEqual(apps_manage_svc._field_text(line, ""), line)
        self.assertEqual(
            apps_manage_svc._as_text(line.encode("utf-8")), line)

    def test_recursing_str_still_answers_the_type_name(self):
        class Recursing:
            def __str__(self):
                return str(self)

        self.assertEqual(apps_manage_svc._utf8_text(Recursing()), "Recursing")


# ─── wrong-rank recovery (unit) ───────────────────────────────────────────────

class WrongRankRecoveryTests(unittest.TestCase):
    """A refused claimed arm falls through to the arm the *real* storage
    matches instead of throwing honest content away."""

    def test_an_int_claiming_float_keeps_its_honest_port(self):
        self.assertEqual(
            apps_manage_svc._field_text(_IntLiarFloat(8080), "fb"), "8080")
        self.assertEqual(apps_manage_svc._as_text(_IntLiarFloat(8080)), "8080")

    def test_a_str_claiming_float_keeps_its_honest_text(self):
        self.assertEqual(
            apps_manage_svc._field_text(_StrLiarFloat("Example"), "fb"),
            "Example")

    def test_a_junk_str_claim_keeps_the_fallback_not_its_repr(self):
        self.assertEqual(
            apps_manage_svc._field_text(_JunkLiarStr(), "fb"), "fb")

    def test_a_dict_claiming_str_is_junk_not_a_repr_blob(self):
        self.assertEqual(
            apps_manage_svc._field_text(_DictLiarStr({"a": 1}), "fb"), "fb")

    def test_honest_ranks_stay_pinned(self):
        # The apps9/apps13 fidelity pins must not weaken.
        self.assertEqual(apps_manage_svc._field_text(8080, ""), "8080")
        self.assertEqual(apps_manage_svc._field_text(8080.5, ""), "8080.5")
        self.assertEqual(apps_manage_svc._field_text(True, "fb"), "fb")
        self.assertEqual(apps_manage_svc._field_text(None, "fb"), "fb")
        self.assertEqual(apps_manage_svc._field_text({"a": 1}, "fb"), "fb")
        huge = 10 ** 5000  # past the int->str digit cap: str() ValueErrors
        self.assertEqual(apps_manage_svc._field_text(huge, "fb"), "fb")
        self.assertEqual(apps_manage_svc._field_text("web", "fb"), "web")


# ─── provider seams (unit) ────────────────────────────────────────────────────

class ProviderSeamGuardTests(unittest.TestCase):
    """``_host_ip`` / ``_user_home`` fence providers this module does not
    own; control flow keeps propagating."""

    def test_host_ip_bomb_reads_as_no_address(self):
        for boom in (LeftoverBaseBomb("host bomb"), RuntimeError("torn cfg")):
            with self.subTest(kind=type(boom).__name__), \
                    mock.patch("hub.apps_manage_svc.host_ip",
                               side_effect=boom):
                self.assertEqual(apps_manage_svc._host_ip(), "")

    def test_a_junk_host_ip_return_cannot_leak_its_repr(self):
        with mock.patch("hub.apps_manage_svc.host_ip",
                        return_value=_Junk()):
            self.assertEqual(apps_manage_svc._host_ip(), "")

    def test_an_honest_host_ip_still_answers(self):
        with mock.patch("hub.apps_manage_svc.host_ip",
                        return_value="10.0.0.5"):
            self.assertEqual(apps_manage_svc._host_ip(), "10.0.0.5")

    def test_user_home_bomb_and_junk_read_as_none(self):
        with mock.patch("hub.apps_manage_svc.user_home",
                        side_effect=LeftoverBaseBomb("home bomb")):
            self.assertIsNone(apps_manage_svc._user_home())
        with mock.patch("hub.apps_manage_svc.user_home",
                        return_value="/not/a/path-object"):
            self.assertIsNone(apps_manage_svc._user_home())

    def test_an_honest_user_home_still_answers(self):
        home = Path("/Users/example")
        with mock.patch("hub.apps_manage_svc.user_home", return_value=home):
            self.assertEqual(apps_manage_svc._user_home(), home)

    def test_provider_guards_reraise_control_flow(self):
        for kind in (KeyboardInterrupt, SystemExit):
            with self.subTest(kind=kind.__name__):
                with mock.patch("hub.apps_manage_svc.host_ip",
                                side_effect=kind()):
                    with self.assertRaises(kind):
                        apps_manage_svc._host_ip()
                with mock.patch("hub.apps_manage_svc.user_home",
                                side_effect=kind()):
                    with self.assertRaises(kind):
                        apps_manage_svc._user_home()


# ─── rigs ─────────────────────────────────────────────────────────────────────

class _LaunchdRig(unittest.TestCase):
    """One sane LaunchAgent plist; collaborators stubbed (the apps9 rig)."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        agents = Path(self._tmp.name) / "agents"
        agents.mkdir()
        (agents / "local.sane.plist").write_bytes(
            b"""<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>Label</key><string>local.sane</string>
</dict></plist>
"""
        )
        apps_manage_svc.inventory.invalidate()
        self.addCleanup(apps_manage_svc.inventory.invalidate)
        for target, kwargs in (
            ("hub.paths.AGENTS_DIR", {"new": str(agents)}),
            ("hub.services_uninstall_svc.AGENTS_DIR", {"new": str(agents)}),
            ("hub.launchd_cache.listing",
             {"side_effect": RuntimeError("no launchd")}),
            ("hub.services_uninstall_svc.preview", {"return_value": {}}),
            ("hub.containers_svc.list_containers",
             {"return_value": {"containers": []}}),
            ("hub.containers_svc.list_stacks", {"return_value": []}),
            ("hub.vms_svc.list_all_vms", {"return_value": {"vms": []}}),
            ("hub.native_catalog.list_native_apps", {"return_value": []}),
            ("hub.apps_manage_svc.engine_up", {"return_value": False}),
            ("hub.apps_manage_svc.host_ip", {"return_value": "127.0.0.1"}),
        ):
            patched = mock.patch(target, **kwargs)
            patched.start()
            self.addCleanup(patched.stop)


class OverrideReprLeakHttpTests(_LaunchdRig):
    """A junk config-override value costs its cosmetic field — it never
    carries a heap address onto the wire."""

    def test_junk_override_values_leak_no_address(self):
        override = {"name": _Junk(), "port": _Junk(),
                    "group": _Junk(), "url": _Junk()}
        with mock.patch("hub.config.override", return_value=override):
            resp = _client().get("/api/apps/managed", params={"force": "true"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = _strict_utf8(resp)
        self.assertNotIn(" at 0x", body)
        payload = json.loads(body)
        item = next(i for i in payload["items"]
                    if i["id"] == "launchd:local.sane")
        # Each junk field degrades to its fallback, never its repr.
        self.assertEqual(item["name"], "local.sane")
        self.assertEqual(item["ports_summary"], "")
        self.assertEqual(item["category"], "other")
        self.assertIsNone(item["url"])

    def test_a_renderable_override_still_renders(self):
        override = {"name": _Renders(), "port": 8080}
        with mock.patch("hub.config.override", return_value=override):
            resp = _client().get("/api/apps/managed", params={"force": "true"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        item = next(i for i in payload["items"]
                    if i["id"] == "launchd:local.sane")
        self.assertEqual(item["name"], "tunnel-a")
        self.assertEqual(item["ports_summary"], "8080")


class LaunchdPreviewSalvageHttpTests(_LaunchdRig):
    """One bombed preview field costs itself, never every preview field."""

    def test_a_nested_base_bomb_preview_field_costs_itself_only(self):
        preview = {"program": "/usr/local/bin/thing", "workdir": "/srv",
                   "plist": "/agents/local.sane.plist",
                   "junk": _ClassPropBaseBomb()}
        with mock.patch("hub.services_uninstall_svc.preview",
                        return_value=preview), \
                mock.patch("hub.config.override", return_value={}):
            resp = _client().get(
                "/api/apps/managed/detail", params={"id": "launchd:local.sane"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        # The sane siblings keep answering; the bomb cost its field only.
        self.assertEqual(payload["program"], "/usr/local/bin/thing")
        self.assertEqual(payload["workdir"], "/srv")
        self.assertEqual(payload["plist"], "/agents/local.sane.plist")


class CloudflaredDetailFieldRankHttpTests(unittest.TestCase):
    """The native-cloudflared detail reads the status payload sanitized:
    junk costs its field, and no default repr reaches the wire."""

    def _detail(self, status):
        with mock.patch("hub.cloudflared_svc.status", return_value=status), \
                mock.patch("hub.native_catalog.list_native_apps",
                           return_value=[]), \
                mock.patch("hub.tools_svc.listening_ports",
                           return_value={"ports": []}), \
                mock.patch("hub.apps_manage_svc.host_ip",
                           return_value="127.0.0.1"):
            return _client().get(
                "/api/apps/managed/detail",
                params={"id": "native:native-cloudflared"})

    def test_a_junk_active_tunnel_leaks_no_address(self):
        resp = self._detail({"running": True, "active_tunnel": _Junk()})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = _strict_utf8(resp)
        self.assertNotIn(" at 0x", body)
        payload = json.loads(body)
        self.assertEqual(payload["cloudflared"]["active_tunnel"], "")
        self.assertIs(payload["cloudflared"]["running"], True)

    def test_a_junk_notes_field_costs_itself_not_the_section(self):
        resp = self._detail(
            {"running": True, "active_tunnel": "tun-a", "notes": _Junk()})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        # The bare ``+`` concat used to TypeError and absorb the whole
        # (sane) section into ``ok: false``.
        self.assertIs(payload["cloudflared"]["running"], True)
        self.assertEqual(payload["cloudflared"]["active_tunnel"], "tun-a")
        self.assertEqual(payload["state"], "ok")
        self.assertEqual(payload["status_text"], "running · tun-a")
        self.assertNotIn(" at 0x", _strict_utf8(resp))

    def test_a_sane_status_stays_intact(self):
        resp = self._detail({"running": True, "active_tunnel": "tun-a",
                             "logged_in": True, "notes": "healthy"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertEqual(payload["status_text"], "running · tun-a")
        self.assertEqual(payload["cloudflared"]["active_tunnel"], "tun-a")
        self.assertEqual(payload["cloudflared"]["notes"], "healthy")
        self.assertEqual(payload["state"], "ok")


class ProviderSeamHttpTests(unittest.TestCase):
    """A raising provider costs its address fields, never a detail/logs
    route — where the pre-fix tree answered raw 500s."""

    def test_a_host_ip_bomb_keeps_the_vm_detail_route(self):
        vms = {"vms": [{"id": "vm1", "name": "Test VM", "state": "running"}]}
        with mock.patch("hub.vms_svc.list_all_vms", return_value=vms), \
                mock.patch("hub.apps_manage_svc.host_ip",
                           side_effect=LeftoverBaseBomb("host bomb")):
            resp = _client().get(
                "/api/apps/managed/detail", params={"id": "vm:vm1"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertEqual(payload["name"], "Test VM")
        self.assertEqual(payload["host_ip"], "")

    def test_a_host_ip_bomb_keeps_the_docker_detail_route(self):
        with mock.patch("hub.containers_svc.list_containers",
                        return_value={"containers": []}), \
                mock.patch("hub.containers_svc.list_stacks",
                           return_value=[]), \
                mock.patch("hub.apps_manage_svc.host_ip",
                           side_effect=LeftoverBaseBomb("host bomb")):
            resp = _client().get(
                "/api/apps/managed/detail", params={"id": "docker:web"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertEqual(payload["source_id"], "web")
        self.assertEqual(payload["host_ip"], "")

    def test_a_user_home_bomb_keeps_the_native_logs_route(self):
        with mock.patch("hub.apps_manage_svc.user_home",
                        side_effect=LeftoverBaseBomb("home bomb")):
            resp = _client().get(
                "/api/apps/managed/logs",
                params={"id": "native:native-redis"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertTrue(payload["ok"])

    def test_a_user_home_bomb_keeps_the_native_detail_route(self):
        with mock.patch("hub.apps_manage_svc.user_home",
                        side_effect=LeftoverBaseBomb("home bomb")), \
                mock.patch("hub.native_catalog.list_native_apps",
                           return_value=[]), \
                mock.patch("hub.tools_svc.listening_ports",
                           return_value={"ports": []}), \
                mock.patch("hub.apps_manage_svc.host_ip",
                           return_value="127.0.0.1"):
            resp = _client().get(
                "/api/apps/managed/detail",
                params={"id": "native:native-redis"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertEqual(payload["source_id"], "native-redis")

    def test_control_flow_still_propagates_through_the_detail_seam(self):
        vms = {"vms": [{"id": "vm1", "name": "Test VM", "state": "running"}]}
        for kind in (KeyboardInterrupt, SystemExit):
            with self.subTest(kind=kind.__name__), \
                    mock.patch("hub.vms_svc.list_all_vms", return_value=vms), \
                    mock.patch("hub.apps_manage_svc.host_ip",
                               side_effect=kind()):
                with self.assertRaises(kind):
                    apps_manage_svc.detail("vm:vm1")


class StaysImmunePins(unittest.TestCase):
    """The apps13-era seals must not have weakened."""

    def test_a_base_bomb_class_property_still_reads_as_no_match(self):
        self.assertIs(apps_manage_svc._isa(_ClassPropBaseBomb(), dict), False)

    def test_the_both_bases_decode_still_reads_honest_content(self):
        class _BytesLiarBytearray(bytearray):
            @property
            def __class__(self):
                return bytes

        liar = _BytesLiarBytearray(b"8080")
        self.assertEqual(apps_manage_svc._field_text(liar, ""), "8080")
        self.assertEqual(apps_manage_svc._as_text(liar), "8080")
        self.assertEqual(apps_manage_svc._utf8_text(liar), "8080")

    def test_genuine_values_still_round_trip(self):
        self.assertEqual(apps_manage_svc._utf8_text("häl√"), "häl√")
        self.assertEqual(apps_manage_svc._as_text(b"plain"), "plain")
        self.assertEqual(
            apps_manage_svc._safe_payload({"ok": True, "n": 3}),
            {"ok": True, "n": 3})


class ProductVersionPin(unittest.TestCase):
    def test_product_version_stays_pinned(self):
        from hub import __version__

        self.assertEqual(__version__, "3.9.5")


if __name__ == "__main__":
    unittest.main(verbosity=2)
