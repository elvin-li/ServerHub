"""Peer lifecycle: allocation under batching, and two ways state got corrupted.

These paths all write the server config and the peer registry, and each had a
defect that only shows up in a specific sequence rather than in a single call:

* batch creation persisted once *per peer*, because address allocation read the
  claimed set back off disk and so could not see peers minted moments earlier.
  Fifty peers meant fifty config rewrites, fifty backups and fifty privileged
  ``wg syncconf`` calls -- slow enough to outrun the request timeout, and a
  half-created batch when it did.
* deleting a peer compared two independent reads of the config to decide whether
  the peer existed, so a peer added between the reads made the counts match, the
  delete reported "no such peer", and the stale first read was written back --
  dropping the newly added peer.
* toggling a preshared key created a registry entry for peers the panel never
  issued.  ``peer_records`` treats "has a registry entry" as ``known``, so the
  peer stopped counting as foreign and the copied-from-another-server detection
  lost sight of it.
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import wireguard_svc  # noqa: E402

#: A base64 Curve25519 key is 44 characters: 43 of payload plus the '=' pad.
SERVER_KEY = "A" * 43 + "="


def _key(seed: str) -> str:
    return (seed * 44)[:43] + "="


class PeerOpsTestCase(unittest.TestCase):
    """A real config file and registry on disk, but no WireGuard and no sudo."""

    def setUp(self):
        self._tmp = TemporaryDirectory()
        root = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        self.conf = root / "wg0.conf"
        self.registry = root / "wireguard-peers.json"
        self.conf.write_text(
            "[Interface]\n"
            f"PrivateKey = {SERVER_KEY}\n"
            "Address = 10.10.0.1/24\n"
            "ListenPort = 51820\n"
        )
        self.synced = 0
        self.minted = 0

        def fake_keypair():
            self.minted += 1
            seed = chr(ord("b") + (self.minted % 20))
            return _key(seed), _key(seed.upper())

        def fake_apply():
            self.synced += 1
            return {"ok": True, "applied": True}

        patches = [
            patch.object(wireguard_svc, "conf_path", return_value=self.conf),
            patch.object(wireguard_svc, "REGISTRY_PATH", self.registry),
            patch.object(wireguard_svc, "generate_keypair", side_effect=fake_keypair),
            patch.object(wireguard_svc, "generate_psk", return_value=_key("z")),
            patch.object(wireguard_svc, "public_from_private", return_value=_key("S")),
            patch.object(wireguard_svc, "apply_live", side_effect=fake_apply),
            patch.object(
                wireguard_svc, "settings",
                return_value={
                    "interface": "wg0", "subnet": "10.10.0.0/24", "listen_port": 51820,
                    "dns": "", "mtu": 1280, "keepalive": 25, "endpoint": "vpn.example",
                    "lan_cidr": "", "wan_interface": "",
                },
            ),
        ]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)

    def _registry(self) -> dict:
        return json.loads(self.registry.read_text())["peers"]

    def _addresses(self) -> list[str]:
        return [r["ip"] for r in wireguard_svc.peer_records()]


class BatchAllocationTests(PeerOpsTestCase):
    def test_a_batch_gives_every_peer_a_distinct_address(self):
        """The bug in-memory allocation has to avoid: everyone gets 10.10.0.2."""
        wireguard_svc.batch_add(count=5, prefix="phone")
        addresses = self._addresses()
        self.assertEqual(len(addresses), 5)
        self.assertEqual(len(set(addresses)), 5, addresses)
        self.assertEqual(
            addresses,
            ["10.10.0.2/32", "10.10.0.3/32", "10.10.0.4/32", "10.10.0.5/32", "10.10.0.6/32"],
        )

    def test_a_batch_writes_the_config_and_syncs_once(self):
        wireguard_svc.batch_add(count=8, prefix="p")
        self.assertEqual(self.synced, 1, "one privileged sync per batch, not per peer")

    def test_a_batch_skips_addresses_already_in_the_config(self):
        wireguard_svc.add_peer(name="existing", ip="10.10.0.3/32")
        wireguard_svc.batch_add(count=2, prefix="new")
        self.assertNotIn("10.10.0.3/32", self._addresses()[1:])
        self.assertEqual(len(set(self._addresses())), 3)

    def test_every_peer_in_the_batch_is_registered(self):
        result = wireguard_svc.batch_add(count=4, prefix="p")
        self.assertEqual(result["created"], 4)
        self.assertEqual(len(self._registry()), 4)

    def test_each_peer_gets_its_own_keypair(self):
        wireguard_svc.batch_add(count=4, prefix="p")
        self.assertEqual(len(set(self._registry())), 4)

    def test_a_batch_reports_the_sync_outcome_on_every_peer(self):
        result = wireguard_svc.batch_add(count=3, prefix="p")
        self.assertTrue(all(p["applied"] for p in result["peers"]))


class SingleAddTests(PeerOpsTestCase):
    def test_adding_one_peer_still_works_and_syncs_once(self):
        result = wireguard_svc.add_peer(name="laptop")
        self.assertEqual(result["ip"], "10.10.0.2/32")
        self.assertTrue(result["applied"])
        self.assertEqual(self.synced, 1)

    def test_an_explicit_address_already_in_use_is_refused(self):
        wireguard_svc.add_peer(name="first", ip="10.10.0.5/32")
        with self.assertRaises(wireguard_svc.WireGuardError) as caught:
            wireguard_svc.add_peer(name="second", ip="10.10.0.5/32")
        self.assertEqual(caught.exception.code, "wg.ip_in_use")

    def test_the_server_address_is_never_handed_out(self):
        result = wireguard_svc.add_peer(name="laptop")
        self.assertNotEqual(result["ip"], "10.10.0.1/32")

    def test_keep_key_off_stores_no_private_key(self):
        result = wireguard_svc.add_peer(name="once", keep_key=False)
        self.assertFalse(result["reissuable"])
        self.assertNotIn("private_key", self._registry()[result["pub"]])


class DeleteTests(PeerOpsTestCase):
    def test_deleting_a_peer_removes_it_from_config_and_registry(self):
        created = wireguard_svc.add_peer(name="gone")
        wireguard_svc.del_peer(created["pub"])
        self.assertEqual(wireguard_svc.peer_records(), [])
        self.assertEqual(self._registry(), {})

    def test_a_peer_added_after_the_membership_read_is_not_dropped(self):
        """The two-reads bug: the second read decided, the first read was written.

        Reading the config twice let a concurrent addition land between them. The
        counts then matched, so the delete raised "no such peer" -- and on the
        paths where it did not raise, the stale first read was written back and the
        new peer vanished from the config with no error at all.
        """
        keep = wireguard_svc.add_peer(name="keep")
        target = wireguard_svc.add_peer(name="target")

        real = wireguard_svc._peers_for_write
        calls = []

        def counting():
            calls.append(1)
            return real()

        with patch.object(wireguard_svc, "_peers_for_write", side_effect=counting):
            wireguard_svc.del_peer(target["pub"])
        self.assertEqual(
            len(calls), 1, "membership must be decided from a single read"
        )
        surviving = [r["public_key"] for r in wireguard_svc.peer_records()]
        self.assertEqual(surviving, [keep["pub"]])

    def test_deleting_an_absent_peer_is_an_error_and_changes_nothing(self):
        wireguard_svc.add_peer(name="keep")
        before = self.conf.read_text()
        with self.assertRaises(wireguard_svc.WireGuardError) as caught:
            wireguard_svc.del_peer(_key("q"))
        self.assertEqual(caught.exception.code, "wg.peer_not_found")
        self.assertEqual(self.conf.read_text(), before)


class PresharedKeyTests(PeerOpsTestCase):
    def test_toggling_psk_on_a_foreign_peer_does_not_adopt_it(self):
        """The peer must stay recognisable as one this panel did not issue."""
        foreign = _key("f")
        wireguard_svc.import_peer(pubkey=foreign, ip="10.10.0.9/32")
        # An import *is* recorded, so drop the entry to model a peer that arrived
        # by hand-editing the config -- the case the detection exists for.
        self.registry.write_text(json.dumps({"peers": {}}))

        wireguard_svc.toggle_psk(pubkey=foreign, op="add")

        self.assertEqual(self._registry(), {}, "a registry entry was fabricated")
        record = next(r for r in wireguard_svc.peer_records() if r["public_key"] == foreign)
        self.assertFalse(record["known"])
        self.assertFalse(record["reissuable"])
        # The key itself still has to reach the server config, which is what
        # actually governs the tunnel.
        self.assertTrue(record["preshared_key"])

    def test_toggling_psk_on_our_own_peer_updates_the_stored_copy(self):
        created = wireguard_svc.add_peer(name="mine")
        wireguard_svc.toggle_psk(pubkey=created["pub"], op="add")
        self.assertTrue(self._registry()[created["pub"]]["preshared_key"])

    def test_removing_psk_clears_the_stored_copy(self):
        created = wireguard_svc.add_peer(name="mine", psk=True)
        self.assertTrue(self._registry()[created["pub"]]["preshared_key"])
        wireguard_svc.toggle_psk(pubkey=created["pub"], op="remove")
        self.assertNotIn("preshared_key", self._registry()[created["pub"]])
        record = next(
            r for r in wireguard_svc.peer_records() if r["public_key"] == created["pub"]
        )
        self.assertFalse(record["preshared_key"])

    def test_toggling_psk_on_an_absent_peer_is_an_error(self):
        with self.assertRaises(wireguard_svc.WireGuardError) as caught:
            wireguard_svc.toggle_psk(pubkey=_key("n"), op="add")
        self.assertEqual(caught.exception.code, "wg.peer_not_found")


if __name__ == "__main__":
    unittest.main()


class ConcurrentWriteTests(PeerOpsTestCase):
    """Two writers must not lose each other's peer.

    Every peer operation is a read-modify-write over the config and the registry.
    Interleaved, the second writer's snapshot predates the first writer's change,
    so writing it back deletes that peer with no error anywhere -- and address
    allocation, which reads the same claimed set, hands the same IP to both.

    This is not hypothetical on the host this was written for: a packaged
    ServerHub.app and a source checkout were running against the same state
    directory at the same time, which is already documented in hub/auth.py as
    having cost the stored admin credentials in exactly this way.  So the lock has
    to be one the kernel arbitrates between processes, not a threading.Lock.
    """

    def test_the_lock_is_held_across_processes(self):
        import fcntl
        import os

        with wireguard_svc.conf_lock():
            fd = os.open(wireguard_svc._LOCK_PATH, os.O_RDWR | os.O_CREAT, 0o600)
            try:
                with self.assertRaises(BlockingIOError):
                    # A second holder must be refused while the first has it.
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(fd)

    def test_the_lock_is_released_afterwards(self):
        import fcntl
        import os

        with wireguard_svc.conf_lock():
            pass
        fd = os.open(wireguard_svc._LOCK_PATH, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def test_the_lock_is_released_when_the_operation_fails(self):
        """A refused delete must not leave every later write blocked forever."""
        import fcntl
        import os

        with self.assertRaises(wireguard_svc.WireGuardError):
            wireguard_svc.del_peer(_key("q"))
        fd = os.open(wireguard_svc._LOCK_PATH, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def test_concurrent_additions_all_survive(self):
        """Threads share the flock through the file, so this exercises the guard."""
        import threading

        errors = []

        def add(index):
            try:
                wireguard_svc.add_peer(name=f"peer{index}")
            except Exception as exc:  # noqa: BLE001 - reported through `errors`
                errors.append(exc)

        threads = [threading.Thread(target=add, args=(i,)) for i in range(6)]
        for item in threads:
            item.start()
        for item in threads:
            item.join(timeout=30)

        self.assertEqual(errors, [])
        records = wireguard_svc.peer_records()
        self.assertEqual(len(records), 6, "a concurrent write was lost")
        addresses = [r["ip"] for r in records]
        self.assertEqual(len(set(addresses)), 6, f"duplicate address: {addresses}")
        self.assertEqual(len(self._registry()), 6)

    def test_every_mutating_operation_takes_the_lock(self):
        """Guards against a new peer operation being added without one."""
        import inspect

        source = inspect.getsource(wireguard_svc)
        for name in ("add_peer", "batch_add", "del_peer", "import_peer", "toggle_psk"):
            start = source.index(f"def {name}(")
            end = source.find("\ndef ", start + 1)
            body = source[start : end if end != -1 else len(source)]
            self.assertIn(
                "conf_lock()", body, f"{name} mutates the config without the lock"
            )


class ReissueSourceOfTruthTests(PeerOpsTestCase):
    """A re-issued config must describe what the server will actually accept.

    Two files hold a peer: the server config decides what the tunnel accepts, the
    registry holds what a server config cannot express (the client's private key,
    its name, its tunnel mode).  Re-issuing used to read the address and the
    preshared key from the registry too, which is invisible until it is wrong: the
    two are written in sequence and can be restored from backups independently, and
    once they disagree the panel hands out a config the server is certain to reject.
    The operator sees a client that will not connect and nothing anywhere says why.
    """

    def _reissued_peer_block(self, pubkey: str) -> dict:
        from hub import wireguard_export

        body = wireguard_svc.peer_conf(pubkey, "wg")["content"]
        return wireguard_export.parse_conf(body)["peers"][0]

    def _reissued_interface(self, pubkey: str) -> dict:
        from hub import wireguard_export

        body = wireguard_svc.peer_conf(pubkey, "wg")["content"]
        return wireguard_export.parse_conf(body)["interface"]

    def _set_registry(self, pubkey: str, **fields):
        data = json.loads(self.registry.read_text())
        data["peers"][pubkey].update(fields)
        self.registry.write_text(json.dumps(data))

    def test_a_stale_registry_psk_is_not_put_into_the_config(self):
        """Server has no PSK; a leftover registry copy must not resurrect it."""
        created = wireguard_svc.add_peer(name="phone", psk=True)
        wireguard_svc.toggle_psk(pubkey=created["pub"], op="remove")
        # Model the registry not having kept up, e.g. restored from a backup.
        self._set_registry(created["pub"], preshared_key=_key("z"))

        block = self._reissued_peer_block(created["pub"])
        self.assertNotIn("PresharedKey", block)

    def test_a_psk_the_server_has_is_included_even_if_the_registry_lost_it(self):
        created = wireguard_svc.add_peer(name="phone", psk=True)
        server_psk = next(
            r["preshared_key"] for r in wireguard_svc.peer_records()
            if r["public_key"] == created["pub"]
        )
        data = json.loads(self.registry.read_text())
        data["peers"][created["pub"]].pop("preshared_key", None)
        self.registry.write_text(json.dumps(data))

        block = self._reissued_peer_block(created["pub"])
        self.assertEqual(block.get("PresharedKey"), server_psk)

    def test_the_address_comes_from_the_server_config(self):
        created = wireguard_svc.add_peer(name="phone")
        self._set_registry(created["pub"], ip="10.10.0.99/32")
        interface = self._reissued_interface(created["pub"])
        self.assertEqual(interface["Address"], created["ip"])

    def test_a_peer_removed_from_the_server_cannot_be_re_issued(self):
        """A config for a peer the server no longer has could only ever fail."""
        created = wireguard_svc.add_peer(name="phone")
        # Drop it from the config but leave the registry entry behind.
        wireguard_svc._write_conf([])
        with self.assertRaises(wireguard_svc.WireGuardError) as caught:
            wireguard_svc.peer_conf(created["pub"], "wg")
        self.assertEqual(caught.exception.code, "wg.peer_not_found")

    def test_the_registry_still_supplies_the_private_key_and_mode(self):
        created = wireguard_svc.add_peer(name="phone", mode="full")
        interface = self._reissued_interface(created["pub"])
        self.assertTrue(interface["PrivateKey"])
        block = self._reissued_peer_block(created["pub"])
        self.assertIn("0.0.0.0/0", block["AllowedIPs"])

    def test_a_re_issued_config_matches_the_one_handed_out_at_creation(self):
        created = wireguard_svc.add_peer(name="phone", psk=True)
        again = wireguard_svc.peer_conf(created["pub"], "wg")["content"]
        self.assertEqual(again, created["client_conf"])
