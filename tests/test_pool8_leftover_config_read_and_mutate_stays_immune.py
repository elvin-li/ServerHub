"""Eighth leftover-500s sweep of the storage-pool routes, over the real app.

Pool through pool7 hardened every seam this sweep re-reproduced against
``create_app()`` with ``raise_server_exceptions=False``: the config-read
subclass-protocol bombs (pool7), the ``_candidates`` call/row guards and
the ``config._file_lock`` / retention-glob degrades (pool5), the
oversize-name 400 (pool6), and the huge-int JSON body 400 (pool5/pool7).
The pool8 battery re-ran the whole zoo one more time — an exhaustive matrix
of exotic leftover *types* through ``storage_pool_svc.cfg`` (config-read),
hostile ``df`` tables through the real ``storage_svc.list_volumes``
(listing), and unreadable services.yaml under the save/clear mutate path —
and found **no remaining bare 500s**.  What survived pool7 is now pinned
here so a regression in any of it cannot ship silently.

The three seams pinned:

* **Config-read (the pool7 convention).**  A leftover value wearing an
  exotic type — a naive ``datetime`` / ``date`` (rendered through
  ``isoformat``), a leftover ``isoformat`` that returns ``inf`` or is a
  raising *property*, a ``__str__`` self-recursion, an int-subclass whose
  ``__index__`` *and* ``__str__`` both bomb (the unbound ``int.__index__``
  still reads the real digits), a ``complex`` / ``memoryview`` / ``set`` /
  nested list, a ``bytearray``, an over-digit-cap int, a lone surrogate, or
  a ``float`` subclass whose ``__eq__`` bombs the nan/inf probes — placed in
  the pool ``name`` / a ``members`` entry / ``policy`` / ``min_free_gb``
  must degrade *field-level*: the route answers 200 with a strictly-valid
  UTF-8 body and the healthy sibling member still renders.

* **Listing.**  A hostile ``df`` row (a lone-surrogate mount, an over-cap
  block count, an ``inf%`` capacity) read through the real
  ``list_volumes`` must land the pool overview at 200 with the sane sibling
  mount still listed, not 500 the route.

* **Config mutate.**  ``save`` / ``clear`` re-read services.yaml through
  ``_read_disk_for_mutate``; a file that is merely *unreadable* (grown past
  the 1MB read cap, torn to non-UTF-8 bytes, genuinely unparseable, or
  replaced whole by a bare list) must answer the coded
  ``settings.config_unreadable`` 503 and leave the file **byte-identical**
  on disk — never a bare 500, and never the silent ``{}``-plus-patch wipe.

These pins pass on the current tree (they lock the pool7-era hardening in
place); each fails if its seam regresses — the coercer dropping the unbound
base call, the mutate re-read losing its refuse-don't-wipe guard, or the
listing guard collapsing a hostile row into a 500.
"""
from __future__ import annotations

import datetime
import unittest
from unittest import mock

from hub import config, disk_snapshot, storage_pool_svc, storage_svc

_APP = None

#: Past CPython's default 4300-digit int<->str conversion limit.
_HUGE_DIGITS = "9" * 5000


def _client():
    global _APP
    from fastapi.testclient import TestClient

    if _APP is None:
        from hub.app_factory import create_app
        from hub.auth import require_auth

        _APP = create_app()
        _APP.dependency_overrides[require_auth] = lambda: True
    return TestClient(_APP, raise_server_exceptions=False)


#: A complete, well-formed poolable volume row: every pin below asserts that
#: *this* healthy candidate keeps rendering next to the poisoned field.
_VAULT = {
    "device": "/dev/disk6s1",
    "mount": "/Volumes/Vault",
    "kind": "external",
    "total_gb": 10.0,
    "used_gb": 1.0,
    "avail_gb": 9.0,
    "pct": 10,
    "disk_id": "disk6",
    "filesystem": "apfs",
}

_POOL = {
    "name": "media",
    "members": ["/Volumes/Vault"],
    "policy": "most-free",
    "min_free_gb": 0,
}


class _IsoInf:
    """A leftover whose ``isoformat`` returns ``inf`` (not the usual str)."""

    def isoformat(self):
        return float("inf")


class _IsoBomb:
    def isoformat(self):
        raise RuntimeError("leftover isoformat bomb")


class _IsoProp:
    """``isoformat`` is a *raising property* — ``getattr`` itself detonates."""

    @property
    def isoformat(self):
        raise RuntimeError("leftover isoformat property bomb")


class _StrRecursion:
    def __str__(self):
        return str(self)


class _IndexAndStrBombInt(int):
    """Both ``__index__`` and ``__str__`` bomb; the unbound ``int.__index__``
    reads the real C-level digits underneath the overrides anyway."""

    def __index__(self):
        raise RuntimeError("leftover __index__ bomb")

    def __str__(self):
        raise RuntimeError("leftover __str__ bomb")


class _FloatEqBomb(float):
    def __eq__(self, other):
        raise RuntimeError("leftover float __eq__ bomb")

    __hash__ = float.__hash__


def _exotic_values():
    """The exotic-type zoo, each a leftover that must degrade field-level."""
    return {
        "naive_datetime": datetime.datetime(2020, 1, 1),
        "date": datetime.date(2020, 1, 2),
        "isoformat_inf": _IsoInf(),
        "isoformat_bomb": _IsoBomb(),
        "isoformat_property_bomb": _IsoProp(),
        "str_recursion": _StrRecursion(),
        "index_and_str_bomb_int": _IndexAndStrBombInt(5),
        "over_cap_int": 10 ** 5000,
        "complex": complex(1, 2),
        "memoryview": memoryview(b"x"),
        "set": {"/Volumes/Vault"},
        "dict": {"a": 1},
        "nested_list": [["/Volumes/Vault"]],
        "bytearray": bytearray(b"/Volumes/Vault"),
        "surrogate_str": "a\ud800b",
        "float_eq_bomb": _FloatEqBomb(3.5),
        "true": True,
        "none": None,
    }


class _PoolConfigSeam(unittest.TestCase):
    def setUp(self):
        storage_pool_svc.invalidate_pool()
        self.addCleanup(storage_pool_svc.invalidate_pool)

    def _overview(self, pool_block):
        with (
            mock.patch.object(storage_svc, "list_volumes",
                              return_value=[dict(_VAULT)]),
            mock.patch.object(storage_pool_svc, "cfg",
                              return_value={"settings":
                                            {"storage_pool": pool_block}}),
        ):
            resp = _client().get("/api/storage/pool?force=true")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        # The body must already be valid UTF-8 — decode strictly on purpose.
        resp.content.decode("utf-8")
        return resp.json()


class PoolConfigExoticTypeStaysImmuneTests(_PoolConfigSeam):
    """Every exotic leftover type, in every pool config field, degrades
    field-level: the route answers 200 with a valid UTF-8 body and the
    healthy sibling member keeps rendering."""

    def test_exotic_member_never_costs_the_healthy_sibling(self):
        for label, value in _exotic_values().items():
            with self.subTest(value=label):
                body = self._overview(
                    dict(_POOL, members=[value, "/Volumes/Vault"])
                )
                self.assertIn(
                    "/Volumes/Vault",
                    [m["mount"] for m in body["members"]],
                )

    def test_exotic_name_renders_a_string_or_the_default(self):
        for label, value in _exotic_values().items():
            with self.subTest(value=label):
                body = self._overview(dict(_POOL, name=value))
                self.assertIsInstance(body["name"], str)
                self.assertTrue(body["name"])  # never "" — defaults to "pool"

    def test_exotic_policy_falls_back_to_a_valid_placement(self):
        for label, value in _exotic_values().items():
            with self.subTest(value=label):
                body = self._overview(dict(_POOL, policy=value))
                self.assertIn(body["policy"],
                              storage_pool_svc.PLACEMENT_POLICIES)

    def test_exotic_min_free_never_500s_the_overview(self):
        for label, value in _exotic_values().items():
            with self.subTest(value=label):
                body = self._overview(dict(_POOL, min_free_gb=value))
                self.assertIs(body["configured"], True)

    def test_datetime_name_renders_through_isoformat(self):
        body = self._overview(dict(_POOL, name=datetime.date(2020, 1, 2)))
        self.assertEqual(body["name"], "2020-01-02")

    def test_index_and_str_bomb_int_member_reads_the_real_digits(self):
        body = self._overview(
            dict(_POOL, members=[_IndexAndStrBombInt(7), "/Volumes/Vault"])
        )
        self.assertEqual([m["mount"] for m in body["members"]],
                         ["/Volumes/Vault"])
        # The unbound ``int.__index__`` launders the double-bombed subclass:
        # the real digit renders as a missing member, not a 500 or a vanish.
        self.assertEqual(body["missing_members"], ["7"])


class PoolTextExoticUnitPins(unittest.TestCase):
    """Direct ``_text`` pins for the exotic-type coercions above."""

    def test_isoformat_shapes(self):
        self.assertEqual(
            storage_pool_svc._text(datetime.datetime(2020, 1, 1)),
            "2020-01-01T00:00:00")
        self.assertEqual(
            storage_pool_svc._text(datetime.date(2020, 1, 2)), "2020-01-02")
        # inf / raising / raising-property isoformat all degrade to "".
        self.assertEqual(storage_pool_svc._text(_IsoInf()), "")
        self.assertEqual(storage_pool_svc._text(_IsoBomb()), "")
        self.assertEqual(storage_pool_svc._text(_IsoProp()), "")

    def test_str_recursion_and_double_bombed_int(self):
        self.assertEqual(storage_pool_svc._text(_StrRecursion()), "")
        # Unbound ``int.__index__`` reads real digits past both overrides.
        self.assertEqual(storage_pool_svc._text(_IndexAndStrBombInt(5)), "5")

    def test_bytearray_and_over_cap_int_and_exotics(self):
        self.assertEqual(storage_pool_svc._text(bytearray(b"ok")), "ok")
        self.assertEqual(storage_pool_svc._text(10 ** 5000), "")
        self.assertEqual(storage_pool_svc._text(complex(1, 2)), "")
        self.assertEqual(storage_pool_svc._text(memoryview(b"x")), "")
        self.assertEqual(storage_pool_svc._text(_FloatEqBomb(3.5)), "")


class PoolListingHostileDfStaysImmuneTests(unittest.TestCase):
    """A hostile ``df`` row read through the real ``list_volumes`` lands the
    pool overview at 200 with the sane sibling mount still listed."""

    def setUp(self):
        storage_pool_svc.invalidate_pool()
        self.addCleanup(storage_pool_svc.invalidate_pool)
        disk_snapshot._df_table.invalidate()
        self.addCleanup(disk_snapshot._df_table.invalidate)

    def _overview_over_df(self, table):
        with mock.patch.object(disk_snapshot, "sh", return_value=(0, table, "")):
            resp = _client().get("/api/storage/pool?force=true")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        resp.content.decode("utf-8")
        return resp.json()

    def test_surrogate_mount_row_renders_the_sane_sibling(self):
        table = (
            "Filesystem 1024-blocks Used Avail Capacity Mounted on\n"
            "/dev/disk6s1 1048576000 104857600 943718400 10% /Volumes/\ud800X\n"
            "/dev/disk7s1 1048576000 104857600 943718400 10% /Volumes/OK\n"
        )
        body = self._overview_over_df(table)
        self.assertIn("/Volumes/OK",
                      [c["mount"] for c in body["unassigned"]])

    def test_over_cap_block_count_row_is_skipped_not_500(self):
        table = (
            "Filesystem 1024-blocks Used Avail Capacity Mounted on\n"
            "/dev/disk6s1 " + ("9" * 400) + " 1 1 10% /Volumes/Huge\n"
            "/dev/disk7s1 1048576000 104857600 943718400 10% /Volumes/OK\n"
        )
        body = self._overview_over_df(table)
        self.assertIn("/Volumes/OK",
                      [c["mount"] for c in body["unassigned"]])

    def test_inf_pct_row_keeps_rendering(self):
        table = (
            "Filesystem 1024-blocks Used Avail Capacity Mounted on\n"
            "/dev/disk6s1 1048576000 104857600 943718400 inf% /Volumes/OK\n"
        )
        body = self._overview_over_df(table)
        self.assertIn("/Volumes/OK",
                      [c["mount"] for c in body["unassigned"]])


class PoolMutateUnreadableConfigStaysImmuneTests(unittest.TestCase):
    """save / clear over an *unreadable* services.yaml answer the coded
    ``settings.config_unreadable`` 503 and leave the file byte-identical —
    never a bare 500, never the silent ``{}``-plus-patch wipe."""

    def setUp(self):
        storage_pool_svc.invalidate_pool()
        self.addCleanup(storage_pool_svc.invalidate_pool)
        try:
            self._saved = config.YAML_PATH.read_bytes()
        except OSError:
            self._saved = None

        def restore():
            if self._saved is None:
                try:
                    config.YAML_PATH.unlink()
                except OSError:
                    pass
            else:
                config.YAML_PATH.write_bytes(self._saved)
            config.reload_cfg()

        self.addCleanup(restore)
        patcher = mock.patch.object(
            storage_svc, "list_volumes", return_value=[dict(_VAULT)]
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def _write(self, payload):
        if isinstance(payload, bytes):
            config.YAML_PATH.write_bytes(payload)
        else:
            config.YAML_PATH.write_text(payload, encoding="utf-8")
        config.reload_cfg()
        storage_pool_svc.invalidate_pool()

    #: Each is unreadable for a different reason, but all must refuse-not-wipe.
    def _unreadable_payloads(self):
        return {
            "oversize": "settings:\n  x: '" + ("a" * (config._YAML_CAP + 8)) + "'\n",
            "torn_nonutf8": b"settings:\n  a: \xff\xfe\xff\n  b: \x80\x81\n",
            "unparseable": "settings: {a: [unclosed\n",
            "bare_list": "- a\n- b\n- c\n",
        }

    def test_save_refuses_and_leaves_the_file_intact(self):
        for label, payload in self._unreadable_payloads().items():
            with self.subTest(payload=label):
                self._write(payload)
                on_disk_before = config.YAML_PATH.read_bytes()
                resp = _client().post(
                    "/api/storage/pool/save",
                    json={"mounts": ["/Volumes/Vault"], "policy": "most-free",
                          "name": "media"},
                )
                self.assertEqual(resp.status_code, 503, resp.text[:200])
                self.assertEqual(resp.json()["detail"]["code"],
                                 "settings.config_unreadable")
                self.assertEqual(config.YAML_PATH.read_bytes(), on_disk_before)

    def test_clear_refuses_and_leaves_the_file_intact(self):
        for label, payload in self._unreadable_payloads().items():
            with self.subTest(payload=label):
                self._write(payload)
                on_disk_before = config.YAML_PATH.read_bytes()
                resp = _client().post("/api/storage/pool/clear")
                self.assertEqual(resp.status_code, 503, resp.text[:200])
                self.assertEqual(resp.json()["detail"]["code"],
                                 "settings.config_unreadable")
                self.assertEqual(config.YAML_PATH.read_bytes(), on_disk_before)


class PoolHugeIntBodyStaysImmuneTests(unittest.TestCase):
    """json.loads of a >4300-digit number literal raises ValueError, NOT
    JSONDecodeError; FastAPI's generic body-parse guard answers 400 on the
    pool mutation routes — never a 500 from a bespoke body reader."""

    def setUp(self):
        storage_pool_svc.invalidate_pool()
        self.addCleanup(storage_pool_svc.invalidate_pool)

    def test_over_cap_int_bodies_are_400_not_500(self):
        client = _client()
        payload = ('{"mounts": ["/x"], "policy": ' + _HUGE_DIGITS + "}").encode()
        for path in ("/api/storage/pool/plan", "/api/storage/pool/save"):
            with self.subTest(path=path):
                resp = client.post(
                    path, content=payload,
                    headers={"content-type": "application/json"},
                )
                self.assertEqual(resp.status_code, 400, resp.text[:200])
                resp.content.decode("utf-8")


if __name__ == "__main__":
    unittest.main(verbosity=2)
