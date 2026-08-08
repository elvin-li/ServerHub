"""`wg` must be addressed by the device name, not the wg-quick interface name.

macOS has no kernel WireGuard driver.  wg-quick starts wireguard-go on a
kernel-assigned ``utunN``, records the mapping in ``/var/run/wireguard/wg0.name``
and thereafter hands *that* name to every ``wg`` subcommand.  ``wg`` performs no
such translation itself -- it builds the UAPI socket path directly from whatever
name it is given -- so ``wg show wg0 dump`` looks for a ``wg0.sock`` that by
construction never exists.

Observed on the real host: a healthy tunnel serving utun8, and

    $ sudo wg show wg0 dump
    Unable to access interface: No such file or directory

The panel therefore reported "not running" permanently, the peer table never
showed a handshake or a byte count, and -- the expensive part -- ``wg syncconf wg0``
failed on every peer change, so adding or revoking a peer rewrote the config file
and never reached the running tunnel.  Nothing surfaced any of it; the sync result
was discarded by its callers.

These tests pin the resolution, including the two cases where guessing would be
worse than admitting ignorance.
"""
from __future__ import annotations

import os
import re
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import wireguard_svc  # noqa: E402


class ResolutionTests(unittest.TestCase):
    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.run_dir = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        patcher = patch.object(wireguard_svc, "WG_RUN_DIR", self.run_dir)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _socket(self, name: str, mtime: float | None = None) -> Path:
        path = self.run_dir / f"{name}.sock"
        path.write_text("")
        if mtime is not None:
            os.utime(path, (mtime, mtime))
        return path

    def _record(self, iface: str, device: str, mtime: float | None = None) -> Path:
        path = self.run_dir / f"{iface}.name"
        path.write_text(f"{device}\n")
        if mtime is not None:
            os.utime(path, (mtime, mtime))
        return path

    def test_a_socket_under_the_interface_name_is_the_device(self):
        """The Linux shape, where the interface name *is* the kernel device."""
        self._socket("wg0")
        self.assertEqual(wireguard_svc.real_interface("wg0"), "wg0")

    def test_a_readable_record_is_followed(self):
        self._record("wg0", "utun8")
        self._socket("utun8")
        self.assertEqual(wireguard_svc.real_interface("wg0"), "utun8")

    def test_an_unreadable_record_is_paired_by_timestamp(self):
        """The record is mode 0400 root, so its contents are normally unavailable.

        wg-quick accepts a record only when the socket it names was created within
        a couple of seconds of it, and that same rule identifies the device from
        the outside without reading anything.
        """
        self._record("wg0", "utun8", mtime=1000.0)
        self._socket("utun8", mtime=1000.5)
        with patch.object(Path, "read_text", side_effect=PermissionError):
            self.assertEqual(wireguard_svc.real_interface("wg0"), "utun8")

    def test_a_socket_from_an_unrelated_time_is_not_paired(self):
        self._record("wg0", "utun8", mtime=1000.0)
        self._socket("utun3", mtime=50.0)
        with patch.object(Path, "read_text", side_effect=PermissionError):
            self.assertEqual(wireguard_svc.real_interface("wg0"), "")

    def test_two_contemporaneous_sockets_are_not_guessed_between(self):
        """Reporting "unknown" is recoverable; picking the wrong one is not.

        The device resolved here is handed to ``wg syncconf``, which would push
        this server's config onto whatever interface it names.  A coin flip
        between two candidates could therefore reconfigure somebody else's tunnel.
        """
        self._record("wg0", "utun8", mtime=1000.0)
        self._socket("utun8", mtime=1000.2)
        self._socket("utun9", mtime=1000.3)
        with patch.object(Path, "read_text", side_effect=PermissionError):
            self.assertEqual(wireguard_svc.real_interface("wg0"), "")

    def test_a_lone_unclaimed_socket_is_ours(self):
        self._socket("utun8")
        self.assertEqual(wireguard_svc.real_interface("wg0"), "utun8")

    def test_a_socket_claimed_by_another_interface_is_not_ours(self):
        self._record("wg1", "utun8")
        self._socket("utun8")
        self.assertEqual(wireguard_svc.real_interface("wg0"), "")

    def test_nothing_running_resolves_to_nothing(self):
        self.assertEqual(wireguard_svc.real_interface("wg0"), "")


class StalenessTests(unittest.TestCase):
    """Staleness is about *this* record's socket, not about any socket at all."""

    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.run_dir = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        patcher = patch.object(wireguard_svc, "WG_RUN_DIR", self.run_dir)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_another_tunnels_socket_does_not_mask_a_stale_record(self):
        """The regression this rewrite exists for.

        The old test was "record present and no ``*.sock`` anywhere".  On a machine
        running a second userspace tunnel -- a VPN client, say -- that tunnel's
        socket made a genuinely stale record look healthy: the automatic cleanup
        never fired and ``up`` failed forever with a message about the interface
        already existing.
        """
        (self.run_dir / "wg0.name").write_text("utun8\n")
        (self.run_dir / "utun3.sock").write_text("")  # somebody else's tunnel
        state = wireguard_svc.runtime_state("wg0")
        self.assertTrue(state["stale"])
        self.assertFalse(state["live"])

    def test_our_own_socket_means_live(self):
        (self.run_dir / "wg0.name").write_text("utun8\n")
        (self.run_dir / "utun8.sock").write_text("")
        state = wireguard_svc.runtime_state("wg0")
        self.assertFalse(state["stale"])
        self.assertTrue(state["live"])
        self.assertEqual(state["real_interface"], "utun8")


class DumpParsingTests(unittest.TestCase):
    """`wg show all dump` prefixes every row with the device; single-interface does not."""

    def test_single_interface_rows_are_left_alone(self):
        text = "priv\tpub\t51820\toff\npeerpub\t(none)\t1.2.3.4:1\t10.0.0.2/32\t99\t1\t2\t25"
        rows = wireguard_svc._dump_rows(text)
        self.assertEqual(rows[0], ["priv", "pub", "51820", "off"])
        self.assertEqual(rows[1][0], "peerpub")

    def test_the_all_form_has_its_device_column_removed(self):
        text = (
            "utun8\tpriv\tpub\t51820\toff\n"
            "utun8\tpeerpub\t(none)\t1.2.3.4:1\t10.0.0.2/32\t99\t1\t2\t25"
        )
        rows = wireguard_svc._dump_rows(text, "utun8")
        self.assertEqual(rows[0], ["priv", "pub", "51820", "off"])
        self.assertEqual(rows[1][0], "peerpub")

    def test_other_interfaces_are_filtered_out(self):
        text = "utun8\tpriv\tpub\t51820\toff\nutun3\tother\totherpub\t51821\toff"
        rows = wireguard_svc._dump_rows(text, "utun8")
        self.assertEqual(len(rows), 1)


class IdentifyTests(unittest.TestCase):
    """When the filesystem cannot say, the server's own public key can."""

    def test_the_interface_is_recognised_by_its_public_key(self):
        grouped = {
            "utun3": [["otherpriv", "OTHERPUB", "51820", "off"]],
            "utun8": [["ourpriv", "OURPUB", "51821", "off"]],
        }
        with patch.object(
            wireguard_svc, "read_conf",
            return_value={"interface": {"PrivateKey": "x", "ListenPort": "51821"}, "peers": []},
        ), patch.object(wireguard_svc, "public_from_private", return_value="OURPUB"):
            self.assertEqual(wireguard_svc._identify(grouped), "utun8")

    def test_the_listen_port_is_the_fallback_when_the_key_moved_on(self):
        """An operator can change the key on disk without restarting the tunnel."""
        grouped = {
            "utun3": [["p", "A", "51820", "off"]],
            "utun8": [["p", "B", "51821", "off"]],
        }
        with patch.object(
            wireguard_svc, "read_conf",
            return_value={"interface": {"PrivateKey": "x", "ListenPort": "51821"}, "peers": []},
        ), patch.object(wireguard_svc, "public_from_private", return_value="NOMATCH"):
            self.assertEqual(wireguard_svc._identify(grouped), "utun8")

    def test_identification_does_not_mint_a_server_key(self):
        """`server_identity` generates a keypair when the config has none.

        That is a write-shaped side effect, and status is polled every 20 seconds,
        so identification reads the config directly instead.
        """
        with patch.object(
            wireguard_svc, "read_conf",
            return_value={"interface": {}, "peers": []},
        ), patch.object(wireguard_svc, "generate_keypair") as keygen:
            wireguard_svc._identify({"utun8": [["p", "A", "51820", "off"]]})
            keygen.assert_not_called()


class SudoersCoverageTests(unittest.TestCase):
    """The rules have to cover the *shape* of what the code runs.

    Asserted against whichever directory the policy grants rather than a literal
    ``/opt/homebrew/bin``: which binary is safe to grant is a separate question
    being settled separately (the Homebrew path is writable by the granted account,
    so a root-owned copy is preferable), and pinning it here would make this file
    fight that change while testing nothing extra.  Whether the granted binary is
    the one the code actually calls is its own invariant, checked below.
    """

    def setUp(self):
        self.text = (BASE / "deploy" / "sudoers.d" / "serverhub").read_text()
        self.prefixes = sorted({
            match.group(1)
            for match in re.finditer(
                r"^\s+(\S+)/wg (?:show|syncconf) ", self.text, re.MULTILINE
            )
        })

    def test_some_wg_binary_is_granted_at_all(self):
        self.assertTrue(self.prefixes, "no `wg` rule at all; the page cannot work")

    def test_the_real_device_reads_are_granted(self):
        # Without one of these the page cannot read state at all: the utun number
        # is assigned at runtime, so `wg show wg0 dump` is not a usable rule.
        for prefix in self.prefixes:
            self.assertIn(f"{prefix}/wg show all dump", self.text)
            self.assertIn(f"{prefix}/wg show utun[0-9] dump", self.text)

    def test_syncconf_on_the_real_device_is_granted_and_path_pinned(self):
        for prefix in self.prefixes:
            self.assertIn(
                f"{prefix}/wg syncconf utun[0-9] "
                "__SERVERHUB_STATE__/data/wg0.sync.conf",
                self.text,
            )
        # A wildcard path would let any file on disk be loaded as an interface
        # config; the device may vary, the config must not.
        self.assertNotIn("wg syncconf utun[0-9] *", self.text)

    # Whether the granted binary is the one the code actually resolves is a
    # cross-cutting invariant that already has a home in
    # tests/test_sudoers_covers_call_sites.py, where it is checked for every
    # privileged binary at once rather than just this feature's.  Restating it here
    # would report the same inconsistency twice and make the suite noisier without
    # making it stricter.

    def test_no_rule_ends_in_a_bare_wildcard(self):
        """A trailing `*` matches every remaining argument, so it is a prefix grant."""
        offenders = [
            line.strip().rstrip(", \\").rstrip()
            for line in self.text.splitlines()
            if line.strip().startswith("/") and line.strip().rstrip(", \\").endswith("*")
        ]
        self.assertEqual(offenders, [], "\n".join(offenders))


if __name__ == "__main__":
    unittest.main()


class EndpointFormTests(unittest.TestCase):
    """An IPv6 literal endpoint has to be configurable and survive round-tripping.

    The old validator was ``^[A-Za-z0-9._-]{1,253}(?::\\d{1,5})?$``, which admits no
    colons except before a port.  That made an IPv6 endpoint impossible to save --
    and on a connection where IPv4 sits behind carrier NAT while IPv6 is publicly
    routable, the v6 address is the only one that can ever work.  The panel simply
    refused to accept it.

    The parsing is equally load-bearing.  "Contains a colon" cannot mean "has a
    port" when the address is mostly colons: splitting on the last one turns
    ``2408:8248::215`` into host ``2408:8248:`` port ``215``, which is a silently
    wrong address in every generated client config.
    """

    def test_hostnames_and_v4_split_as_before(self):
        self.assertEqual(wireguard_svc.split_endpoint("vpn.example"), ("vpn.example", ""))
        self.assertEqual(
            wireguard_svc.split_endpoint("vpn.example:51821"), ("vpn.example", "51821")
        )
        self.assertEqual(wireguard_svc.split_endpoint("1.2.3.4:51821"), ("1.2.3.4", "51821"))

    def test_a_bare_v6_literal_is_all_host(self):
        self.assertEqual(
            wireguard_svc.split_endpoint("2408:8248:1e43:8080::215"),
            ("2408:8248:1e43:8080::215", ""),
        )

    def test_a_bracketed_v6_literal_keeps_its_port(self):
        self.assertEqual(
            wireguard_svc.split_endpoint("[2408:8248:1e43:8080::215]:51821"),
            ("2408:8248:1e43:8080::215", "51821"),
        )

    def test_formatting_brackets_a_v6_host(self):
        self.assertEqual(
            wireguard_svc.format_endpoint("2408:8248:1e43:8080::215", 51821),
            "[2408:8248:1e43:8080::215]:51821",
        )
        self.assertEqual(
            wireguard_svc.format_endpoint("vpn.example", 51821), "vpn.example:51821"
        )

    def test_a_v6_endpoint_round_trips_through_split_and_format(self):
        original = "[2408:8248:1e43:8080::215]:51821"
        host, port = wireguard_svc.split_endpoint(original)
        self.assertEqual(wireguard_svc.format_endpoint(host, port), original)

    def test_the_validator_accepts_every_dialable_form(self):
        for value in (
            "vpn.example",
            "vpn.example:51821",
            "1.2.3.4",
            "1.2.3.4:51821",
            "2408:8248:1e43:8080::215",
            "[2408:8248:1e43:8080::215]:51821",
        ):
            self.assertTrue(wireguard_svc._valid_endpoint(value), value)

    def test_the_validator_still_rejects_junk(self):
        for value in (
            "",
            "bad host",
            "vpn.example:abc",
            "1.2.3.4:99999",
            "-leading.dash",
            "trailing.dash-",
        ):
            self.assertFalse(wireguard_svc._valid_endpoint(value), value)


class DumpShapeContractTests(unittest.TestCase):
    """Exactly one layer may know that ``wg show all dump`` prefixes its rows.

    That layer is :func:`_dump_rows`, which removes the device column so every
    consumer sees one canonical shape.  Compensating for the prefix a second time
    in :func:`status` produced a page that was wrong in two ways at once: the
    listen port appeared where the server's public key belongs, and *every* peer
    was reported as never having handshaked, because a 9-field guard rejected the
    8-field rows that a de-prefixed peer line actually has.  Both symptoms came
    from indices being one to the left, and neither is obvious by inspection --
    the port and the key are both plausible-looking strings.

    So the contract is pinned from the outside: whichever command produced the
    output, ``status`` has to report the same key, port and handshake.
    """

    INTERFACE = ["PRIVKEY", "SERVERPUB", "51821", "off"]
    PEER = [
        "PEERPUB", "(none)", "203.0.113.9:4466", "10.10.0.2/32",
        "1786081224", "13056", "7996", "25",
    ]

    def _status(self, dump_text: str):
        record = {
            "public_key": "PEERPUB", "ip": "10.10.0.2/32", "preshared_key": "",
            "keepalive": "25", "name": "phone", "mode": "split", "created": 0,
            "reissuable": True, "known": True,
        }
        with (
            patch.object(wireguard_svc, "real_interface", return_value="utun8"),
            patch.object(wireguard_svc, "sh", return_value=(0, dump_text, "")),
            patch.object(wireguard_svc, "peer_records", return_value=[record]),
            patch.object(
                wireguard_svc, "read_conf",
                return_value={
                    "interface": {"Address": "10.10.0.1/24", "ListenPort": "51821"},
                    "peers": [],
                },
            ),
            patch.object(wireguard_svc, "public_from_private", return_value="SERVERPUB"),
            patch.object(
                wireguard_svc, "installation",
                return_value={
                    "installed": True, "conf_exists": True, "tools_version": "v1",
                    "conf_path": "/x", "conf_dir": "/x",
                },
            ),
        ):
            return wireguard_svc.status()

    def _single_interface_dump(self) -> str:
        return "\t".join(self.INTERFACE) + "\n" + "\t".join(self.PEER) + "\n"

    def _all_dump(self) -> str:
        return (
            "\t".join(["utun8", *self.INTERFACE]) + "\n"
            + "\t".join(["utun8", *self.PEER]) + "\n"
        )

    def test_single_interface_dump_is_read_correctly(self):
        result = self._status(self._single_interface_dump())
        self.assertEqual(result["public_key"], "SERVERPUB")
        self.assertEqual(result["listen_port"], 51821)

    def test_the_all_form_gives_identical_results(self):
        """The whole point of normalising at the parser."""
        one = self._status(self._single_interface_dump())
        every = self._status(self._all_dump())
        for key in ("public_key", "listen_port", "active_count", "peer_count"):
            self.assertEqual(one[key], every[key], key)
        self.assertEqual(one["peers"][0], every["peers"][0])

    def test_the_port_is_never_reported_as_the_public_key(self):
        for dump in (self._single_interface_dump(), self._all_dump()):
            result = self._status(dump)
            self.assertNotEqual(result["public_key"], "51821")
            self.assertNotEqual(result["public_key"], str(result["listen_port"]))

    def test_a_peer_row_is_not_discarded_by_a_field_count_guard(self):
        """The guard has to match the de-prefixed width, or every peer vanishes."""
        for dump in (self._single_interface_dump(), self._all_dump()):
            result = self._status(dump)
            peer = result["peers"][0]
            self.assertEqual(peer["last_handshake"], 1786081224, dump)
            self.assertEqual(peer["rx"], 13056)
            self.assertEqual(peer["tx"], 7996)
            self.assertEqual(peer["endpoint"], "203.0.113.9:4466")

    def test_wg_placeholders_do_not_reach_the_page(self):
        """`wg` prints the literal "(none)" for a field it has no value for."""
        idle = list(self.PEER)
        idle[1] = "(none)"   # no preshared key
        idle[2] = "(none)"   # never connected
        idle[4] = "0"
        dump = "\t".join(self.INTERFACE) + "\n" + "\t".join(idle) + "\n"
        peer = self._status(dump)["peers"][0]
        self.assertEqual(peer["endpoint"], "")
        self.assertFalse(peer["psk"])


class ErrorDisclosureTests(unittest.TestCase):
    """A failure message must not carry the server's private key.

    The first field of every ``wg show ... dump`` line is the interface's *private
    key*.  Sourcing an error string from ``stderr or stdout`` therefore publishes it
    whenever the command exits non-zero after writing part of a dump -- and that
    string is returned by the status endpoint, which any signed-in session can read,
    and rendered into the readiness table on the page.
    """

    #: 44 characters, the real shape: 43 of base64 payload plus the '=' pad.
    PRIVATE = "kPrivateKeyMaterial" + "A" * 24 + "="
    PUBLIC = "kPublicKeyMaterial" + "B" * 25 + "="

    def _status_with_failing_dump(self, stdout: str, stderr: str) -> dict:
        with (
            patch.object(wireguard_svc, "real_interface", return_value="utun8"),
            patch.object(wireguard_svc, "sh", return_value=(1, stdout, stderr)),
            patch.object(wireguard_svc, "sudo_capture", return_value=(1, stdout, stderr)),
            patch.object(wireguard_svc, "peer_records", return_value=[]),
            patch.object(
                wireguard_svc, "read_conf",
                return_value={"interface": {"ListenPort": "51820"}, "peers": []},
            ),
            patch.object(wireguard_svc, "public_from_private", return_value="PUB"),
            patch.object(
                wireguard_svc, "installation",
                return_value={
                    "installed": True, "conf_exists": True, "tools_version": "v1",
                    "conf_path": "/x", "conf_dir": "/x",
                },
            ),
        ):
            return wireguard_svc.status()

    def test_a_partial_dump_on_failure_is_not_reported(self):
        partial = f"{self.PRIVATE}\t{self.PUBLIC}\t51820\toff\n"
        result = self._status_with_failing_dump(partial, "")
        self.assertNotIn(self.PRIVATE, result["state_error"])
        self.assertNotIn(self.PRIVATE, repr(result))

    def test_stderr_is_still_reported(self):
        """Suppressing stdout must not leave the operator with no diagnosis."""
        result = self._status_with_failing_dump("", "Unable to access interface")
        self.assertIn("Unable to access interface", result["state_error"])

    def test_a_key_in_stderr_is_redacted(self):
        result = self._status_with_failing_dump("", f"broke on {self.PRIVATE} sorry")
        self.assertNotIn(self.PRIVATE, result["state_error"])
        self.assertIn("[redacted]", result["state_error"])

    def test_there_is_always_some_diagnosis(self):
        result = self._status_with_failing_dump("", "")
        self.assertTrue(result["state_error"].strip())

    def test_wg_quick_output_is_redacted_before_it_reaches_the_browser(self):
        noisy = (
            "[#] wireguard-go utun\n"
            f"[#] wg set utun8 private-key {self.PRIVATE}\n"
            "wg-quick: `wg0' already exists as `utun8'\n"
        )
        reason = wireguard_svc._wg_quick_reason(noisy)
        self.assertNotIn(self.PRIVATE, reason)
        self.assertIn("already exists", reason)

    def test_the_redactor_leaves_ordinary_text_alone(self):
        text = "Unable to access interface: No such file or directory"
        self.assertEqual(wireguard_svc._redact_keys(text), text)
