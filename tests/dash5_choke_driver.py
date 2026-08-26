"""Subprocess driver for the dash5 choke-point sweep (not a test module).

Feeds ONE hostile payload class to *every* shell probe the Dashboard's tile
set makes — by faking ``subprocess.run`` / ``subprocess.check_output``
themselves rather than per-module ``sh`` imports — then drives the whole
tile set over the real mounted app and reports any raw 5xx (503 excepted),
lone surrogate, or unrenderable body.

Run in a subprocess so the poisoned process-global caches (status snapshot,
sensors, host snapshot, health, bookmarks, engine probe, sysctl statics …)
die with the process instead of leaking into the rest of the suite.

Usage: python tests/dash5_choke_driver.py <payload-name>
Exit 0 = every route held; exit 1 = a leak, printed one per line.
"""
from __future__ import annotations

import os
import sys
import tempfile

# python tests/dash5_choke_driver.py puts tests/ (not the repo root) first on
# sys.path; hub/ lives at the root.
sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent.parent))

# A fresh, private state dir: the parent suite's SERVERHUB_STATE_DIR is
# inherited through the environment and must not be written by this process.
os.environ["SERVERHUB_STATE_DIR"] = tempfile.mkdtemp(prefix="dash5-drv-state-")
os.environ["HOME"] = tempfile.mkdtemp(prefix="dash5-drv-home-")

import subprocess

_HUGE = b"9" * 6000
_PLIST_HEAD = b'<?xml version="1.0" encoding="UTF-8"?><plist version="1.0">'

#: rc, stdout bytes, stderr bytes.  rc=None means the binary vanished
#: (FileNotFoundError), the confirmed-missing-CLI class.
PAYLOADS: dict[str, tuple[int | None, bytes, bytes]] = {
    # Lone UTF-8 surrogates (ed a0 80 / ed b0 80) in every column of every
    # probe: the Starlette strict-UTF-8 500 class.
    "surrogate": (0, b"na\xed\xa0\x80me co\xed\xb0\x80l 12 34\n" * 3, b"er\xed\xa0\x80r"),
    # NUL / bare continuation bytes: the surrogateescape-decode class.
    "binary": (0, b"\x00\xff\xfe\x80 garbage \x9f\n" * 4, b"\xff\x00"),
    # One >4300-digit run: CPython's int->str / str->int digit-cap ValueError.
    "hugeint": (0, _HUGE + b"\n", b""),
    # A bare JSON scalar where parsers expect an object: the .get()
    # AttributeError class.
    "json_scalar": (0, b"12345\n", b""),
    # plist torn mid-document: the ExpatError/ValueError parse class.
    "plist_torn": (0, _PLIST_HEAD + b"<dict><key>x</key>", b""),
    # plist whose root is a string, not the expected dict/array: the
    # AttributeError/IndexError class from the known plist invariants.
    "plist_string_root": (0, _PLIST_HEAD + b"<string>hi</string></plist>", b""),
    # plistlib parses <integer>0x…</integer> through int(raw, 16), which the
    # digit cap does NOT bound — the value arrives already-int and over-cap.
    "plist_hexint": (
        0,
        _PLIST_HEAD + b"<dict><key>n</key><integer>0x" + b"F" * 5000
        + b"</integer></dict></plist>",
        b"",
    ),
    # Failing probe whose stderr carries a lone surrogate: the failure-path
    # message render class.
    "fail_surrogate": (7, b"", b"failed \xed\xa0\x80 hard"),
    # Every CLI vanished from disk mid-request: read-only dashboard tiles
    # must degrade, never 500 (mutations answer their coded 503 elsewhere).
    "vanished": (None, b"", b""),
    # A torn IPv6 authority anywhere a probe output becomes a URL:
    # urlsplit("http://[::1") is ValueError on 3.12.
    "torn_ipv6": (0, b"http://[::1\n" * 2, b""),
    # Tens of thousands of plausible rows from one probe: the iterbomb class
    # (per-row parsers must stay bounded, not accumulate unbounded output).
    "iterbomb": (0, b"a 1 2 3 4 5 6 7 8 9 10\n" * 50000, b""),
}

MODE = sys.argv[1]
RC, OUT, ERR = PAYLOADS[MODE]


class _FakeCompleted:
    def __init__(self, rc: int):
        self.returncode = rc
        self.stdout = None
        self.stderr = None


def _fake_run(argv, *args, **kwargs):
    if RC is None:
        raise FileNotFoundError(2, "No such file or directory")
    stdout = kwargs.get("stdout")
    stderr = kwargs.get("stderr")
    if hasattr(stdout, "write"):
        stdout.write(OUT)
    if hasattr(stderr, "write"):
        stderr.write(ERR)
    completed = _FakeCompleted(RC)
    if stdout == subprocess.PIPE or kwargs.get("capture_output"):
        completed.stdout = OUT
        completed.stderr = ERR
    return completed


def _fake_check_output(*args, **kwargs):
    if RC is None:
        raise FileNotFoundError(2, "No such file or directory")
    # platform.processor() passes text=True and joins the result into
    # platform.platform(); returning bytes here would be a driver bug, not
    # a panel bug (TypeError inside the stdlib platform module).
    if kwargs.get("text") or kwargs.get("universal_newlines"):
        return OUT.decode("utf-8", "replace")
    return OUT


subprocess.run = _fake_run
subprocess.check_output = _fake_check_output

from fastapi.testclient import TestClient  # noqa: E402

from hub.app_factory import create_app  # noqa: E402
from hub.auth import require_auth  # noqa: E402

app = create_app()
app.dependency_overrides[require_auth] = lambda: None
client = TestClient(app, raise_server_exceptions=False)

#: Every read the Dashboard page mounts (web/src/views/Dashboard.vue) plus
#: the adaptive scan and the Maintenance widget's list.
PATHS = [
    "/api/status?force=true",
    "/api/health",
    "/api/health/checks",
    "/api/system/sensors?force=true",
    "/api/system/sensors?light=true",
    "/api/system/host?force=true",
    "/api/system/power",
    "/api/ollama/status?force=true",
    "/api/storage?light=true",
    "/api/storage",
    "/api/ups?force=true",
    "/api/bookmarks?force=true",
    "/api/containers",
    "/api/tools/ports",
    "/api/alerts",
    "/api/metrics",
    "/api/metrics?range=48h",
    "/api/adaptive/compose-scan",
    "/api/maintenance",
]

failures = []
for path in PATHS:
    response = client.get(path)
    problems = []
    if response.status_code >= 500 and response.status_code != 503:
        problems.append(f"raw {response.status_code}")
    try:
        response.text.encode("utf-8")
    except UnicodeEncodeError:
        problems.append("unrenderable body")
    else:
        if "\ud800" in response.text or "\udfff" in response.text:
            problems.append("lone surrogate in body")
    if problems:
        failures.append(f"[{MODE}] GET {path} -> {'; '.join(problems)}: "
                        f"{response.text[:300]!r}")

for line in failures:
    print(line)
if not failures:
    print(f"[{MODE}] all {len(PATHS)} dashboard routes held")
sys.exit(1 if failures else 0)
