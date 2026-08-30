"""Audit records must name the operator in the field the Audit page reads.

``web/src/views/Audit.vue`` renders ``asRecord(e).username`` and treats every other key as an
extra detail.  The newer feature routers were written with ``actor=`` instead, so
seventeen call sites recorded who performed a privileged WireGuard, NFS, RAID,
snapshot or SMART operation and then displayed the operator as an em dash -- the
one field an audit trail exists to capture.

This pins the field name at the call sites rather than only testing ``record()``,
because ``record(**fields)`` accepts anything and cannot tell the difference.
"""
from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

ROUTERS = BASE / "hub" / "routers"
AUDIT_VIEW = BASE / "web" / "src" / "views" / "Audit.vue"

#: The key the SPA reads for "who did this".
OPERATOR_FIELD = "username"


class AuditOperatorFieldTests(unittest.TestCase):
    def test_the_spa_still_reads_username(self):
        """If the view switches fields, the assertions below are wrong, not the code."""
        text = AUDIT_VIEW.read_text()
        self.assertRegex(
            text,
            r"asRecord\(e\)\.username",
            "Audit.vue no longer renders asRecord(e).username; update OPERATOR_FIELD",
        )

    def test_no_router_records_the_operator_as_actor(self):
        offenders = []
        for path in sorted(ROUTERS.glob("*.py")):
            for i, line in enumerate(path.read_text().splitlines(), 1):
                if re.search(r"\bactor\s*=", line):
                    offenders.append(f"{path.name}:{i}: {line.strip()}")
        self.assertEqual(
            offenders,
            [],
            "these audit calls name the operator 'actor', which Audit.vue renders "
            f"as a dash; use '{OPERATOR_FIELD}=' instead:\n" + "\n".join(offenders),
        )

    def test_no_audit_call_records_the_operator_as_user(self):
        """Same defect, second spelling.

        The 'actor=' sweep fixed seventeen call sites and pinned that name, but
        the Ollama, PhotosHub, scheduler and notify routers used ``user=`` for
        the same purpose — fifteen more privileged operations whose operator
        rendered as an em dash while ``user=admin`` rode along in the detail
        column.  Scoped to audit.record() calls because ``user=`` is a fine
        parameter name elsewhere (vm_console.issue_ticket takes one).
        """
        offenders = []
        for path in sorted(ROUTERS.glob("*.py")):
            lines = path.read_text().splitlines()
            for i, line in enumerate(lines):
                if "audit.record(" not in line:
                    continue
                # An audit.record call spans a handful of lines at most.
                window = "\n".join(lines[i:i + 8])
                if re.search(r"\buser\s*=", window):
                    offenders.append(f"{path.name}:{i + 1}")
        self.assertEqual(
            offenders,
            [],
            "these audit calls name the operator 'user', which Audit.vue renders "
            f"as a dash; use '{OPERATOR_FIELD}=' instead:\n" + "\n".join(offenders),
        )

    def test_router_audit_calls_that_name_an_operator_also_name_the_client(self):
        """The Audit page has a Client column next to Account.

        Every router audit call site sits inside a request handler, so the
        caller's IP is always available via ``request_client_id(request)``.
        The same four routers that misspelled the operator also dropped the
        client, rendering that column as an em dash for privileged actions.
        Login-flow events that fire before authentication (rate limiting)
        legitimately have a client but no username, hence the one-way scope:
        username= implies client=, not the reverse.
        """
        offenders = []
        for path in sorted(ROUTERS.glob("*.py")):
            lines = path.read_text().splitlines()
            for i, line in enumerate(lines):
                if "audit.record(" not in line or line.lstrip().startswith(("#", "*")):
                    continue
                window = "\n".join(lines[i:i + 10])
                if "username=" in window and "client=" not in window:
                    offenders.append(f"{path.name}:{i + 1}")
        self.assertEqual(
            offenders,
            [],
            "these audit calls record an operator but not the caller's IP; "
            "pass client=request_client_id(request) too:\n" + "\n".join(offenders),
        )

    def test_privileged_feature_routers_do_record_an_operator(self):
        """Guards the inverse: dropping the field entirely is just as bad."""
        for name in ("nas_storage.py", "wireguard_api.py"):
            source = (ROUTERS / name).read_text()
            self.assertIn(
                f"{OPERATOR_FIELD}=username",
                source,
                f"{name} records privileged actions without naming the operator",
            )


class AuditIsolatedInTestsTests(unittest.TestCase):
    """A test run must not write into the real audit trail.

    It did: the change-password tests emitted two records per run, and because the
    trail is capped and evicts oldest-first, fixture usernames were pushing real
    security events out.  346 of 394 lines were fixture noise before this was found.
    """

    def test_password_management_tests_redirect_the_audit_path(self):
        source = (BASE / "tests" / "test_auth_password_management.py").read_text()
        self.assertRegex(
            source,
            r'patch\.object\(\s*audit\s*,\s*["\']AUDIT_PATH["\']',
            "test_auth_password_management.py drives an audited endpoint without "
            "redirecting audit.AUDIT_PATH, so it writes into data/auth-audit.jsonl",
        )


if __name__ == "__main__":
    unittest.main()
