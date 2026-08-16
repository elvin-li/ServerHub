"""Parser tests for /api/tools/ports (hub.tools_svc.parse_lsof_listen_line).

These feed captured `lsof -nP -iTCP -sTCP:LISTEN` text through the parser only —
no real lsof is invoked.
"""
import unittest

from hub.tools_svc import parse_lsof_listen_line

HEADER = (
    "COMMAND     PID  USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME"
)

SAMPLE = [
    # IPv4 wildcard
    "rapportd    381 exampleuser   13u  IPv4 0x6506e3e09df2f774      0t0  TCP *:49152 (LISTEN)",
    # IPv6 wildcard
    "rapportd    381 exampleuser   14u  IPv6 0x2bbd7b74598a4e40      0t0  TCP *:49152 (LISTEN)",
    # IPv4 loopback, bracketless
    "Python    36756 exampleuser    6u  IPv4 0x1c0a3e2f9b8d1a55      0t0  TCP 127.0.0.1:8086 (LISTEN)",
    # IPv6 literal — address itself contains colons
    "Python    36756 exampleuser    7u  IPv6 0x9f11cc02de44ab31      0t0  TCP [::1]:8086 (LISTEN)",
    # full IPv6 literal
    "nginx      1234 root    20u  IPv6 0x5e0778eb2fb07067      0t0  TCP [fe80::1c2d:3e4f]:443 (LISTEN)",
    # bound to a LAN address
    "docker     2222 exampleuser   30u  IPv4 0x4d95b576810a1f56      0t0  TCP 192.0.2.20:5432 (LISTEN)",
]


class TestParseLsofListenLine(unittest.TestCase):
    def test_ipv4_wildcard(self):
        row = parse_lsof_listen_line(SAMPLE[0])
        self.assertEqual(row["address"], "*")
        self.assertEqual(row["port"], 49152)
        self.assertEqual(row["command"], "rapportd")
        self.assertEqual(row["process"], "rapportd")
        self.assertEqual(row["pid"], "381")
        self.assertEqual(row["user"], "exampleuser")
        self.assertEqual(row["name"], "*:49152")

    def test_ipv6_wildcard(self):
        row = parse_lsof_listen_line(SAMPLE[1])
        self.assertEqual(row["address"], "*")
        self.assertEqual(row["port"], 49152)

    def test_ipv4_loopback(self):
        row = parse_lsof_listen_line(SAMPLE[2])
        self.assertEqual(row["address"], "127.0.0.1")
        self.assertEqual(row["port"], 8086)

    def test_ipv6_loopback_splits_on_last_colon(self):
        row = parse_lsof_listen_line(SAMPLE[3])
        self.assertEqual(row["address"], "[::1]")
        self.assertEqual(row["port"], 8086)

    def test_ipv6_literal_with_many_colons(self):
        row = parse_lsof_listen_line(SAMPLE[4])
        self.assertEqual(row["address"], "[fe80::1c2d:3e4f]")
        self.assertEqual(row["port"], 443)

    def test_lan_address(self):
        row = parse_lsof_listen_line(SAMPLE[5])
        self.assertEqual(row["address"], "192.0.2.20")
        self.assertEqual(row["port"], 5432)

    def test_port_is_int_for_every_sample_row(self):
        for line in SAMPLE:
            row = parse_lsof_listen_line(line)
            self.assertIsNotNone(row, line)
            self.assertIsInstance(row["port"], int, line)
            self.assertGreater(row["port"], 0, line)
            # regression: the old parser returned "(LISTEN)" as the address
            self.assertNotIn("LISTEN", row["address"], line)
            self.assertNotIn("LISTEN", row["name"], line)

    def test_no_state_column(self):
        """lsof may omit the trailing (LISTEN) token; NAME is then last."""
        row = parse_lsof_listen_line(
            "Python    36756 exampleuser    6u  IPv4 0x1c0a3e2f9b8d1a55      0t0  TCP 0.0.0.0:9000"
        )
        self.assertEqual(row["address"], "0.0.0.0")
        self.assertEqual(row["port"], 9000)

    def test_header_and_junk_rejected(self):
        for bad in (
            HEADER,
            "",
            "   ",
            "too few fields here",
            # NAME with no port
            "foo 1 root 1u IPv4 0x0 0t0 TCP somehost (LISTEN)",
            # non-numeric port (lsof without -P resolves service names)
            "foo 1 root 1u IPv4 0x0 0t0 TCP *:https (LISTEN)",
        ):
            self.assertIsNone(parse_lsof_listen_line(bad), bad)

    def test_hex_escaped_command_is_unescaped(self):
        row = parse_lsof_listen_line(
            r"Plex\x20M    900 exampleuser   13u  IPv4 0xabc      0t0  "
            "TCP *:32400 (LISTEN)"
        )
        self.assertEqual(row["command"], "Plex M")
        self.assertEqual(row["process"], "Plex M")
        self.assertEqual(row["port"], 32400)

    def test_conflict_precheck_shape(self):
        """A caller can now detect a port conflict by integer compare."""
        rows = [parse_lsof_listen_line(x) for x in SAMPLE]
        busy = {r["port"] for r in rows if r}
        self.assertIn(8086, busy)
        self.assertIn(5432, busy)
        self.assertNotIn(9999, busy)


if __name__ == "__main__":
    unittest.main()
