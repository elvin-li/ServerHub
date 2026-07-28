"""Guards the per-container size table on the Tools page.

``docker ps`` only populates ``{{.Size}}`` when ``-s``/``--size`` is passed.
OrbStack happens to fill it in regardless, which is why this went unnoticed on
the development host, but stock Docker Engine leaves the column empty -- so the
Size column silently renders blank for every container.

The other trap here is the header line.  ``docker ps`` with ``--format`` emits
no header, so slicing ``[1:]`` off the output drops a real container.
"""
from __future__ import annotations

import unittest
from unittest import mock

from hub import tools_svc


#: Four containers, no header line -- this is what `--format` actually emits.
PS_OUTPUT = (
    "immich_server\t238kB (virtual 1.46GB)\tghcr.io/immich/server\tUp 3 days\n"
    "immich_redis\t651kB (virtual 157MB)\tredis:7\tUp 3 days\n"
    "teslamate\t12.3MB (virtual 253MB)\tteslamate/teslamate\tUp 2 weeks\n"
    "music-assistant\t63.4MB (virtual 2.44GB)\tmusic-assistant\tExited (0)\n"
)


class ContainerSizesTests(unittest.TestCase):
    def _call(self, output: str = PS_OUTPUT, rc: int = 0):
        """Run container_sizes() against canned docker output.

        Returns (rows, argv) so a test can assert on either the parsed result or
        the exact command that was issued.
        """
        seen: dict = {}

        def fake_docker(*args, **kwargs):
            seen["argv"] = args
            return (rc, output, "")

        with mock.patch.object(tools_svc, "engine_up", return_value=True), \
                mock.patch.object(tools_svc, "docker", side_effect=fake_docker):
            rows = tools_svc.container_sizes()
        return rows, seen.get("argv", ())

    def test_size_is_requested_explicitly_with_dash_s(self):
        """The whole point: without -s the Size column is empty on real Docker."""
        _, argv = self._call()
        self.assertIn(
            "-s",
            argv,
            "docker ps only populates {{.Size}} when -s/--size is passed; "
            "stock Docker Engine leaves the column empty without it",
        )

    def test_no_row_is_dropped_as_a_phantom_header(self):
        """`--format` emits no header, so every line is a container."""
        rows, _ = self._call()
        self.assertEqual(
            len(rows),
            4,
            "docker ps --format prints no header line; slicing it off loses a "
            "real container",
        )
        self.assertEqual(rows[0]["name"], "immich_server")

    def test_every_row_carries_the_four_fields_the_table_renders(self):
        rows, _ = self._call()
        for r in rows:
            for key in ("name", "size", "image", "status"):
                self.assertIn(key, r)
                self.assertTrue(r[key], f"{key} is empty for {r.get('name')!r}")

    def test_a_row_with_only_a_name_is_skipped(self):
        """A truncated line must not become a row with a blank size."""
        rows, _ = self._call(output="lonely-name\n" + PS_OUTPUT)
        self.assertTrue(all(r["size"] for r in rows))

    def test_engine_down_yields_an_empty_list_not_an_error(self):
        with mock.patch.object(tools_svc, "engine_up", return_value=False):
            self.assertEqual(tools_svc.container_sizes(), [])

    def test_a_failed_docker_call_yields_an_empty_list(self):
        rows, _ = self._call(output="", rc=1)
        self.assertEqual(rows, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
