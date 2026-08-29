"""Twelfth leftover-500s sweep of the VMs surfaces, over the real app.

vms11 sealed the *runner* seam: every ``sh()`` spawn funnels through
``_spawn``, so a raising runner reads as ``(-255, "", "")`` instead of
500ing the routes.  This sweep hunted the sibling seam those spawns fan
out on: the **pool**.  ``hub.util.fan_out`` maps guarded workers in order
and never raises past them — but ``vms_svc`` does not own it (tests and
tooling patch it, the ``wireguard_svc.installation`` rule), and two call
sites trusted its answer bare:

* **GET /api/vms** — ``list_all_vms`` unpacked ``fan_out(...)`` with a
  bare 2-way unpack *outside every listing catch*.  A pool that raises,
  answers None / a scalar / a wrong-length batch, a tuple-subclass whose
  ``__iter__`` bombs, or a right-length pair of non-list junk each 500'd
  the route raw — and, through the same call, the Apps inventory and the
  settings export that embed it.  Junk now reads as two empty
  inventories via ``_listing_pair``: a pool that cannot answer loses that
  refresh, never the route.

* **The UTM port-probe fan-out** — ``_list_utm_vms_uncached`` called the
  pool bare for its per-row TCP probes and ``zip``'d the answer against
  the parsed rows.  A raising pool threw every already-parsed row away
  through the ``_listing_rows`` catch, and a junk-shaped answer silently
  *truncated the rows to its own length*.  A poisoned pool now loses only
  the port probes (each row reads as unprobed, exactly like a row with no
  configured port), never the inventory.

One degrade regression fell to the same sweep: the ``orbctl list -f
json`` parse caught only ``(TypeError, ValueError, RecursionError)``, so
a JSON loader raising outside that set — another seam this module does
not own — skipped the degraded ``orbctl list`` *text* fallback entirely
and emptied the OrbStack inventory when the text listing would still
have answered.

Do-not-weaken pins ride along: ``_rc_int`` junk still reads -255 and
never the ``-1`` spawn sentinel, ``_spawn`` still degrades a raising
runner to ``(-255, "", "")``, ``_sh3`` still launders answer shapes, and
``_listing_rows`` still absorbs a raising probe — the vms10/vms11 union
guards this sweep composes with, pinned so they cannot be traded away.
"""
from __future__ import annotations

import unittest
from unittest import mock

from fastapi.testclient import TestClient

from hub import audit, vms_svc
from hub.app_factory import create_app
from hub.auth import require_auth

_UUID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
UTM_LISTING = (
    "UUID                                 Status   Name\n"
    f"{_UUID} started  Ubuntu\n"
)
ORB_JSON = '[{"name": "ubuntu", "state": "running"}]'
ORB_TEXT = "NAME STATE\nubuntu running\n"

_app = None


def _client() -> TestClient:
    global _app
    if _app is None:
        _app = create_app()
        _app.dependency_overrides[require_auth] = lambda: None
    return TestClient(_app, raise_server_exceptions=False)


def _raising_pool(*args, **kwargs):
    raise RuntimeError("leftover pool bomb")


def _inline_pool(probe, items, **kwargs):
    """A healthy pool: maps the workers inline, in order."""
    return [probe(item) for item in items]


class _IterBombTuple(tuple):
    """tuple-subclass pool answer whose bound ``__iter__`` raises; the
    real storage underneath is honest."""

    def __iter__(self):
        raise RuntimeError("leftover __iter__ bomb")


class _Liar:
    """Lying ``__class__`` impostor: passes ``_isa`` for the claimed
    builtin but carries none of its real storage, so the unbound base
    read one line past the gate TypeErrors instead of iterating."""

    __slots__ = ("_claim",)

    def __init__(self, claim):
        object.__setattr__(self, "_claim", claim)

    @property
    def __class__(self):
        return self._claim


def _sh_utm(cmd, **kw):
    cmd = [str(c) for c in cmd]
    if "utmctl" in cmd[0] and cmd[1:2] == ["list"]:
        return (0, UTM_LISTING, "")
    return (0, "", "")


class ListingPoolSeamTests(unittest.TestCase):
    """GET /api/vms over a poisoned listing pool: empty inventories,
    never a raw 500."""

    def setUp(self):
        self.client = _client()
        vms_svc.invalidate_vm_lists()
        self.addCleanup(vms_svc.invalidate_vm_lists)

    def _get(self, pool_patch):
        with mock.patch.object(vms_svc, "_utm_available", return_value=True), \
             mock.patch.object(vms_svc, "_orb_available", return_value=False), \
             mock.patch.object(vms_svc, "UTMCTL", "/usr/local/bin/utmctl"), \
             mock.patch.object(vms_svc, "sh", side_effect=_sh_utm), \
             pool_patch, mock.patch.object(audit, "record"):
            return self.client.get("/api/vms")

    def test_a_raising_pool_answers_empty_inventories(self):
        # Pre-fix a raw 500: the bare 2-way unpack sat outside every catch.
        resp = self._get(mock.patch.object(vms_svc, "fan_out",
                                           side_effect=_raising_pool))
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        self.assertEqual(body["vms"], [])
        self.assertEqual(body["utm_count"], 0)
        self.assertEqual(body["orb_count"], 0)

    def test_junk_shaped_pool_answers_stay_a_200(self):
        # Each of these shapes blew the bare unpack (or the ``+`` concat /
        # ``len`` one line later) into a raw 500 pre-fix.
        shapes = (
            None,
            "junk",
            [[], [], []],
            [[]],
            _IterBombTuple(("junk", 7)),
            _Liar(list),
            ["not-a-list", 7],
        )
        for shape in shapes:
            with self.subTest(shape=type(shape).__name__ + repr(shape)[:30]):
                vms_svc.invalidate_vm_lists()
                resp = self._get(mock.patch.object(vms_svc, "fan_out",
                                                   return_value=shape))
                self.assertEqual(resp.status_code, 200, resp.text[:200])
                body = resp.json()
                self.assertEqual(body["vms"], [])
                self.assertEqual(body["utm_count"], 0)
                self.assertEqual(body["orb_count"], 0)
                resp.content.decode("utf-8")

    def test_a_healthy_pool_still_carries_the_rows_through(self):
        # The launder must pass an honest batch untouched: an inline pool
        # (order-preserving, guarded workers) keeps the UTM row.
        resp = self._get(mock.patch.object(vms_svc, "fan_out",
                                           side_effect=_inline_pool))
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        self.assertEqual(body["utm_count"], 1)
        self.assertIn("Ubuntu", [v["name"] for v in body["vms"]])


class ProbePoolSeamTests(unittest.TestCase):
    """The UTM port-probe fan-out: a poisoned pool loses only the probes,
    never the already-parsed rows."""

    def setUp(self):
        self.client = _client()
        vms_svc.invalidate_vm_lists()
        self.addCleanup(vms_svc.invalidate_vm_lists)

    def test_a_probe_pool_raise_keeps_the_rows_on_the_route(self):
        # The listing pool stays healthy; only the port-probe call bombs.
        # Pre-fix the raise rode the ``_listing_rows`` catch and emptied
        # the whole UTM inventory.
        def _selective(probe, items, **kw):
            if probe is vms_svc._listing_rows:
                return [probe(item) for item in items]
            raise RuntimeError("leftover probe-pool bomb")

        with mock.patch.object(vms_svc, "_utm_available", return_value=True), \
             mock.patch.object(vms_svc, "_orb_available", return_value=False), \
             mock.patch.object(vms_svc, "UTMCTL", "/usr/local/bin/utmctl"), \
             mock.patch.object(vms_svc, "sh", side_effect=_sh_utm), \
             mock.patch.object(vms_svc, "fan_out", side_effect=_selective), \
             mock.patch.object(audit, "record"):
            resp = self.client.get("/api/vms")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        self.assertEqual(body["utm_count"], 1)
        row = body["vms"][0]
        self.assertEqual(row["name"], "Ubuntu")
        # Unprobed reads exactly like a row with no configured port.
        self.assertEqual(row["state"], "ok")

    def test_a_junk_probe_answer_no_longer_truncates_the_rows(self):
        # A wrong-length probes batch used to ``zip``-truncate the rows to
        # its own length — zero rows for an empty junk answer.
        for junk in ([], None, "junk", [True, False, None, None]):
            with self.subTest(junk=repr(junk)[:30]):
                vms_svc.invalidate_vm_lists()
                with mock.patch.object(vms_svc, "_utm_available",
                                       return_value=True), \
                     mock.patch.object(vms_svc, "UTMCTL",
                                       "/usr/local/bin/utmctl"), \
                     mock.patch.object(vms_svc, "sh", side_effect=_sh_utm), \
                     mock.patch.object(vms_svc, "fan_out",
                                       return_value=junk):
                    rows = vms_svc.list_utm_vms(force=True)
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]["name"], "Ubuntu")

    def test_a_raising_probe_pool_keeps_the_direct_listing(self):
        with mock.patch.object(vms_svc, "_utm_available", return_value=True), \
             mock.patch.object(vms_svc, "UTMCTL", "/usr/local/bin/utmctl"), \
             mock.patch.object(vms_svc, "sh", side_effect=_sh_utm), \
             mock.patch.object(vms_svc, "fan_out",
                               side_effect=_raising_pool):
            rows = vms_svc.list_utm_vms(force=True)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["state"], "ok")


class OrbJsonLoaderSeamTests(unittest.TestCase):
    """A JSON loader raising outside the typed set degrades to the
    ``orbctl list`` text fallback instead of emptying the inventory."""

    def setUp(self):
        self.client = _client()
        vms_svc.invalidate_vm_lists()
        self.addCleanup(vms_svc.invalidate_vm_lists)

    def _sh_orb(self, cmd, **kw):
        cmd = [str(c) for c in cmd]
        if "orbctl" in cmd[0] and "-f" in cmd:
            return (0, ORB_JSON, "")
        if "orbctl" in cmd[0]:
            return (0, ORB_TEXT, "")
        return (1, "", "")

    def _get(self, loader_effect):
        with mock.patch.object(vms_svc, "_utm_available", return_value=False), \
             mock.patch.object(vms_svc, "_orb_available", return_value=True), \
             mock.patch.object(vms_svc, "ORBCTL", "/usr/local/bin/orbctl"), \
             mock.patch.object(vms_svc, "sh", side_effect=self._sh_orb), \
             mock.patch.object(vms_svc, "safe_json_loads",
                               side_effect=loader_effect), \
             mock.patch.object(audit, "record"):
            return self.client.get("/api/vms")

    def test_a_raising_loader_falls_back_to_the_text_listing(self):
        # RuntimeError is outside the (TypeError, ValueError,
        # RecursionError) set; pre-fix it skipped the text fallback and
        # answered zero OrbStack rows.
        resp = self._get(RuntimeError("leftover loader bomb"))
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        self.assertEqual(body["orb_count"], 1)
        self.assertIn("orb:ubuntu", [v["id"] for v in body["vms"]])

    def test_the_typed_degrades_still_answer_the_text_listing(self):
        # Pin: the pre-existing typed catch keeps the same fallback.
        for exc in (ValueError("bad json"), RecursionError("deep json"),
                    TypeError("junk document")):
            with self.subTest(exc=type(exc).__name__):
                vms_svc.invalidate_vm_lists()
                resp = self._get(exc)
                self.assertEqual(resp.status_code, 200, resp.text[:200])
                self.assertEqual(resp.json()["orb_count"], 1)


class PoolLaunderUnitPins(unittest.TestCase):
    """Direct pins for the pool launder and the union guards it composes
    with (do not weaken)."""

    def test_rows_list_launders_junk_and_keeps_honest_sequences(self):
        self.assertEqual(vms_svc._rows_list([1, 2]), [1, 2])
        self.assertEqual(vms_svc._rows_list(("a",)), ["a"])
        self.assertEqual(vms_svc._rows_list(None), [])
        self.assertEqual(vms_svc._rows_list("junk"), [])
        # Unbound base iteration (the _listing_rows/_jsonable rule): an
        # iter-bomb *subclass* keeps its honest C-level storage; only a
        # lying impostor with no storage to read degrades.
        self.assertEqual(vms_svc._rows_list(_IterBombTuple((1, 2))), [1, 2])
        self.assertEqual(vms_svc._rows_list(_Liar(list)), [])
        self.assertEqual(vms_svc._rows_list(_Liar(tuple)), [])

    def test_listing_pair_requires_exactly_two_row_lists(self):
        self.assertEqual(vms_svc._listing_pair(([1], [2])), ([1], [2]))
        self.assertEqual(vms_svc._listing_pair([[1], [2]]), ([1], [2]))
        self.assertEqual(vms_svc._listing_pair(None), ([], []))
        self.assertEqual(vms_svc._listing_pair([[1]]), ([], []))
        self.assertEqual(vms_svc._listing_pair([[1], [2], [3]]), ([], []))
        # Right length, junk halves: each half launders independently.
        self.assertEqual(vms_svc._listing_pair(["junk", [2]]), ([], [2]))
        self.assertEqual(vms_svc._listing_pair([_Liar(list), (3,)]), ([], [3]))

    def test_listing_rows_still_absorbs_a_raising_probe(self):
        # vms9 pin: the probe-level catch stays in front of the launder.
        def _bomb():
            raise RuntimeError("leftover probe bomb")

        self.assertEqual(vms_svc._listing_rows(_bomb), [])
        self.assertEqual(vms_svc._listing_rows(lambda: [1]), [1])
        self.assertEqual(vms_svc._listing_rows(lambda: "junk"), [])

    def test_spawn_and_rc_pins_stay_in_force(self):
        # vms10/vms11 do-not-weaken pins: junk rc reads -255, never the -1
        # spawn sentinel; a raising runner degrades to the junk triple;
        # answer shapes still launder through _sh3.
        self.assertEqual(vms_svc._rc_int("junk"), -255)
        self.assertEqual(vms_svc._rc_int(10 ** 5000), -255)
        self.assertEqual(vms_svc._rc_int(-1), -1)
        with mock.patch.object(vms_svc, "sh",
                               side_effect=RuntimeError("runner bomb")):
            self.assertEqual(vms_svc._spawn(["x"], 5), (-255, "", ""))
        self.assertEqual(vms_svc._sh3("junk"), (-255, "", ""))
        self.assertEqual(vms_svc._sh3((0, "only-two")), (-255, "", ""))
        self.assertEqual(vms_svc._sh3((0, "out", "err")), (0, "out", "err"))
        with mock.patch.object(vms_svc, "_bin_present", return_value=False):
            self.assertFalse(vms_svc._cli_missing("junk", "not found", "/x"))
            self.assertTrue(vms_svc._cli_missing(-1, "not found", "/x"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
