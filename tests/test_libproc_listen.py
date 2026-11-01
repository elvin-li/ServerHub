"""The shared listener snapshot is read through libproc, not by spawning lsof.

`lsof -nP -iTCP -sTCP:LISTEN` reads the same libproc calls with the same
permission checks, so hub/libproc_listen.py can give its rows in-process
(about 8 ms against 50-80 ms of child CPU and two temp files per snapshot).
These tests check that its rows are lsof's rows on a Mac, that its COMMAND
and NAME text follow lsof's rules (seen on this host with crafted process
names), and that the snapshot still runs lsof whenever the read cannot
answer exactly.
"""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import adaptive, libproc_listen, network_svc, tools_svc  # noqa: E402
from hub.libproc_listen import Listener  # noqa: E402

_ON_MAC = sys.platform == "darwin" and os.path.exists("/usr/sbin/lsof")

LSOF_OUT = """COMMAND     PID  USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
postgres    902 a0000    5u  IPv4 0x11e5fc567e5a7d11      0t0  TCP 127.0.0.1:5432 (LISTEN)
"""


def _lsof_rows():
    out = subprocess.run(
        ["/usr/sbin/lsof", "-nP", "-iTCP", "-sTCP:LISTEN"],
        capture_output=True, text=True, timeout=30, check=False,
    ).stdout
    return [(r["proc"], r["pid"], r["bind"], r["port"]) for r in adaptive._parse_lsof_listen(out)]


def _snapshot_rows():
    adaptive.invalidate_lsof_snapshot()
    return [(r["proc"], r["pid"], r["bind"], r["port"]) for r in adaptive.lsof_listen_snapshot()]


class _NativeOn(unittest.TestCase):
    def setUp(self):
        self.enterContext(mock.patch.dict(os.environ))
        os.environ.pop("SERVERHUB_NO_NATIVE_LSOF", None)
        adaptive.invalidate_lsof_snapshot()
        self.addCleanup(adaptive.invalidate_lsof_snapshot)


@unittest.skipUnless(_ON_MAC, "needs macOS lsof")
class SameRowsAsLsofTests(_NativeOn):
    def test_the_snapshot_holds_lsofs_rows_without_spawning_it(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.addCleanup(listener.close)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        spawned = []
        real_sh = adaptive.sh

        def recording_sh(cmd, *args, **kwargs):
            spawned.append(list(cmd))
            return real_sh(cmd, *args, **kwargs)

        attempts = []
        with mock.patch.object(adaptive, "sh", side_effect=recording_sh):
            for _ in range(3):
                native, reference = _snapshot_rows(), _lsof_rows()
                attempts.append((native, reference))
                # Two reads a moment apart: equal unless a listener came or went.
                if native == reference:
                    break
        native, reference = attempts[-1]
        self.assertEqual(native, reference)
        self.assertFalse(any("lsof" in argv[0] for argv in spawned), spawned)
        mine = [row for row in native if row[1] == str(os.getpid())]
        self.assertIn(f"127.0.0.1:{port}", [row[2] for row in mine])


@unittest.skipUnless(_ON_MAC, "needs macOS lsof")
class ReadersParseTheSameTextTests(_NativeOn):
    """/api/tools/ports and the Network page parse lsof_text() like lsof's."""

    def _compare(self, read):
        spawned = []
        real_sh = tools_svc.sh

        def recording_sh(cmd, *args, **kwargs):
            spawned.append(list(cmd))
            return real_sh(cmd, *args, **kwargs)

        attempts = []
        for _ in range(3):
            with mock.patch.object(tools_svc, "sh", side_effect=recording_sh), \
                    mock.patch.object(network_svc, "sh", side_effect=recording_sh):
                native = read()
            self.assertFalse(any("lsof" in argv[0] for argv in spawned), spawned)
            with mock.patch.dict(os.environ, {"SERVERHUB_NO_NATIVE_LSOF": "1"}):
                reference = read()
            attempts.append((native, reference))
            if native == reference:
                break
        native, reference = attempts[-1]
        self.assertEqual(native, reference)
        return native

    def test_tools_ports(self):
        got = self._compare(lambda: tools_svc.listening_ports(100))
        self.assertTrue(got["ok"])
        self.assertTrue(got["ports"])

    def test_network_listening_ports(self):
        self.assertTrue(self._compare(lambda: network_svc.listening_ports(100)))


class LsofTextTests(_NativeOn):
    ROWS = [
        Listener("Plex\\x20M", 77, 501, 9, 2, "*:32400", 32400),
        Listener("node", 901, 501, 12, 30, "[::1]:3000", 3000),
    ]

    def _user(self, uid):
        if uid != 501:
            raise KeyError(uid)
        return mock.Mock(pw_name="a0000")

    def test_rows_render_in_lsofs_columns(self):
        with mock.patch.object(libproc_listen, "listen_rows", return_value=self.ROWS), \
                mock.patch.object(libproc_listen.pwd, "getpwuid", side_effect=self._user):
            text = libproc_listen.lsof_text()
        lines = text.splitlines()
        self.assertEqual(lines[0].split(), [
            "COMMAND", "PID", "USER", "FD", "TYPE", "DEVICE", "SIZE/OFF", "NODE", "NAME",
        ])
        self.assertEqual(lines[1].split(), [
            "Plex\\x20M", "77", "a0000", "9u", "IPv4", "0x0", "0t0", "TCP", "*:32400", "(LISTEN)",
        ])
        self.assertEqual(lines[2].split()[4], "IPv6")
        rows = tools_svc.parse_lsof_listen_line(lines[1])
        self.assertEqual((rows["command"], rows["user"], rows["address"], rows["port"]),
                         ("Plex M", "a0000", "*", 32400))

    def test_a_user_name_lsof_may_print_otherwise_gives_no_text(self):
        for user in ({"side_effect": KeyError(501)},
                     {"return_value": mock.Mock(pw_name="averyverylongname")},
                     {"return_value": mock.Mock(pw_name="has space")}):
            with self.subTest(user=user), \
                    mock.patch.object(libproc_listen, "listen_rows", return_value=self.ROWS), \
                    mock.patch.object(libproc_listen.pwd, "getpwuid", **user):
                self.assertIsNone(libproc_listen.lsof_text())

    def test_no_text_makes_the_readers_run_lsof(self):
        out = "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n" \
              "postgres 902 a0000 5u IPv4 0x1 0t0 TCP 127.0.0.1:5432 (LISTEN)\n"
        spawned = []

        def fake_sh(cmd, *args, **kwargs):
            spawned.append(list(cmd))
            return 0, out, ""

        with mock.patch.object(tools_svc, "lsof_text", return_value=None), \
                mock.patch.object(network_svc, "lsof_text", return_value=None), \
                mock.patch.object(tools_svc, "sh", side_effect=fake_sh), \
                mock.patch.object(network_svc, "sh", side_effect=fake_sh):
            tools = tools_svc.listening_ports(40)
            net = network_svc.listening_ports(100)
        self.assertEqual(len(spawned), 2)
        self.assertEqual([r["port"] for r in tools["ports"]], [5432])
        self.assertEqual([r["port"] for r in net], ["5432"])


class CommandTextTests(unittest.TestCase):
    """COMMAND as lsof printed it for crafted process names on macOS."""

    def test_lsofs_text_for_names_it_was_checked_against(self):
        cases = {
            b"ab cdefgh": "ab\\x20cde",
            b"abcdef gh": "abcdef",  # the escape does not fit: dropped, not cut
            b"abcde fgh": "abcde\\x20",
            b"abcdefgh i": "abcdefgh",
            b"a  b": "a\\x20\\x20",
            b"abcdefghijklmnop": "abcdefghi",
            b"Plex Media Serv": "Plex\\x20M",
            b"python3.14": "python3.1",
            b"node": "node",
        }
        for name, text in cases.items():
            with self.subTest(name=name):
                self.assertEqual(libproc_listen._lsof_command(name), text)

    def test_names_lsof_escapes_otherwise_are_not_reproduced(self):
        for name in (b"back\\sl", "\u00e9-test".encode(), b"tab\tx", b"del\x7f"):
            with self.subTest(name=name):
                self.assertIsNone(libproc_listen._lsof_command(name))


class AddressTextTests(unittest.TestCase):
    def _info(self, laddr: bytes) -> bytes:
        base = libproc_listen._OFF_LADDR
        return bytes(base) + laddr + bytes(16)

    def test_lsofs_text_for_the_addresses_it_prints_plainly(self):
        v4, v6 = libproc_listen._AF_INET, libproc_listen._AF_INET6
        self.assertEqual(libproc_listen._address(v4, self._info(bytes(16))), "*")
        self.assertEqual(
            libproc_listen._address(v4, self._info(bytes(12) + bytes([127, 0, 0, 1]))),
            "127.0.0.1",
        )
        self.assertEqual(libproc_listen._address(v6, self._info(bytes(16))), "*")
        self.assertEqual(libproc_listen._address(v6, self._info(bytes(15) + b"\1")), "[::1]")

    def test_other_ipv6_addresses_are_not_reproduced(self):
        v6 = libproc_listen._AF_INET6
        for raw in (
            socket.inet_pton(socket.AF_INET6, "fe80::1"),
            socket.inet_pton(socket.AF_INET6, "::ffff:127.0.0.1"),
            socket.inet_pton(socket.AF_INET6, "2001:db8::1"),
        ):
            with self.subTest(raw=raw):
                self.assertIsNone(libproc_listen._address(v6, self._info(raw)))


class SnapshotFallbackTests(_NativeOn):
    def _snapshot(self, native):
        spawned = []

        def fake_sh(cmd, *args, **kwargs):
            spawned.append(list(cmd))
            return 0, LSOF_OUT, ""

        with mock.patch.object(adaptive, "sh", side_effect=fake_sh), \
                mock.patch.object(adaptive, "listen_rows", **native):
            rows = adaptive.lsof_listen_snapshot()
        return rows, spawned

    def test_native_rows_become_snapshot_rows(self):
        rows, spawned = self._snapshot({"return_value": [
            Listener("Plex\\x20M", 77, 501, 9, 2, "*:32400", 32400),
            Listener("node", 901, 501, 12, 30, "[::1]:3000", 3000),
        ]})
        self.assertEqual(spawned, [])
        self.assertEqual(rows, [
            {"proc": "Plex M", "pid": "77", "bind": "*:32400", "port": 32400},
            {"proc": "node", "pid": "901", "bind": "[::1]:3000", "port": 3000},
        ])
        self.assertEqual(adaptive.ports_for_pid(901), [3000])

    def test_an_empty_native_answer_is_an_answer(self):
        rows, spawned = self._snapshot({"return_value": []})
        self.assertEqual((rows, spawned), ([], []))

    def test_no_native_answer_runs_lsof(self):
        for native in ({"return_value": None}, {"side_effect": RuntimeError("boom")}):
            with self.subTest(native=native):
                adaptive.invalidate_lsof_snapshot()
                rows, spawned = self._snapshot(native)
                self.assertEqual(len(spawned), 1)
                self.assertIn("lsof", spawned[0][0])
                self.assertEqual([r["port"] for r in rows], [5432])

    def test_the_env_flag_turns_the_read_off(self):
        os.environ["SERVERHUB_NO_NATIVE_LSOF"] = "1"
        with mock.patch.object(libproc_listen, "_load") as load:
            self.assertIsNone(libproc_listen.listen_rows())
        load.assert_not_called()


@unittest.skipUnless(sys.platform == "darwin", "needs libproc")
class ReadFailureTests(_NativeOn):
    def test_an_unreproducible_row_gives_no_answer(self):
        with mock.patch.object(libproc_listen, "_address", return_value=None):
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.addCleanup(listener.close)
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            self.assertIsNone(libproc_listen.listen_rows())

    def test_a_failing_pid_list_gives_no_answer(self):
        lib = mock.Mock()
        lib.proc_listallpids.return_value = 0
        with mock.patch.object(libproc_listen, "_load", return_value=lib):
            self.assertIsNone(libproc_listen.listen_rows())


if __name__ == "__main__":
    unittest.main()
