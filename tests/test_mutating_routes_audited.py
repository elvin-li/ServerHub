"""Every mutating route must leave an audit record, or be a named exception.

The trail grew router by router — auth first, then power, NFS/RAID,
WireGuard, scheduler, notify, and finally the service/container/app/file
sweeps — and each pass found endpoints the previous one missed.  This pins
the property itself: a new POST/PUT/DELETE/PATCH handler either references
the audit module (directly, or through a helper in the same file that calls
audit.record) or is added to the exception list below with a reason a
reviewer can weigh.

PATCH is in the verb set because it was not, once: the scan knew only
POST/PUT/DELETE, so PATCH /api/photoshub/config sat outside the property
entirely — audited by luck, not by pin — and the next PATCH handler could
have shipped without a trail and without tripping anything here.
"""
from __future__ import annotations

import ast
import re
import sys
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

ROUTERS = BASE / "hub" / "routers"

#: Mutating-verb routes that deliberately do not write the audit trail here.
#: Keyed by (filename, path as written in the decorator).
ALLOWED_UNAUDITED = {
    # Read-only validation / dry-run / diagnostics: they change nothing.
    ("modules_api.py", "/api/compose/{stack_id}/validate"),
    ("modules_api.py", "/api/compose/validate"),
    ("modules_api.py", "/api/nginx/test"),
    ("system_extra.py", "/api/tools/net/ping"),
    ("system_extra.py", "/api/tools/net/dns"),
    ("storage.py", "/api/storage/pool/plan"),
    ("scheduler_api.py", "/api/backups/rsync/preview"),
    ("wireguard_api.py", "/api/wireguard/ping"),
    ("ollama_api.py", "/api/ollama/test"),
    # Starts a job that only *checks* for updates; applying them is audited.
    ("containers.py", "/api/containers/check-updates"),
    # Query surfaces, not mutations: any host change they cause goes through
    # the audited endpoints/services they invoke.
    ("assistant_api.py", "/api/assistant/ask"),
    ("ollama_api.py", "/api/ollama/chat"),
    # Terminal execution writes the dedicated 0600 terminal-audit trail in
    # hub/terminal_svc.py, with the full command text.
    ("terminal_api.py", "/api/terminal/run"),
    # Audited inside hub/catalog_remote.py (source change / sync / restore
    # events), with operator and client threaded through from the handler.
    ("catalog.py", "/api/catalog/remote"),
    ("catalog.py", "/api/catalog/remote/check"),
    ("catalog.py", "/api/catalog/remote/restore"),
    # Sends a test notification / forces an alert evaluation pass; neither
    # changes host state or configuration.
    ("settings_api.py", "/api/alerts/test"),
    ("settings_api.py", "/api/alerts/check"),
    # Opens the macOS System Settings pane on the host console; nothing on
    # the host is changed by the call itself.
    ("shares.py", "/api/shares/open-system-settings"),
    # Mints a *pending* TOTP secret; nothing is enforced until /confirm,
    # which records TWOFA_ENABLED (and repeated enrolls just re-mint).
    ("twofa_api.py", "/api/auth/totp/enroll"),
}

def _audit_helper_names(text: str) -> set[str]:
    """Module-level functions in *text* whose body calls audit.record.

    Routers wrap the repeated username/client/event plumbing in one local
    helper (_raid_call, _set_screen_sharing, _audit_mutation, ...); a route
    that calls such a helper is audited even though the literal string
    "audit" never appears in its own body.
    """
    names: set[str] = set()
    for node in ast.walk(ast.parse(text)):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            seg = ast.get_source_segment(text, node) or ""
            if "audit.record" in seg:
                names.add(node.name)
    return names


_MUTATING = {"post", "put", "delete", "patch"}


def _route_path(dec: ast.Call):
    """The literal path a route decorator registers, positional or ``path=``."""
    if dec.args and isinstance(dec.args[0], ast.Constant):
        return dec.args[0].value
    for kw in dec.keywords:
        if kw.arg == "path" and isinstance(kw.value, ast.Constant):
            return kw.value.value
    return None


def _routes(text: str):
    """(verb, path, handler source) for each mutating route in *text*.

    Any ``<name>.<verb>("/path")`` decorator counts, not just the literal
    spelling ``router.<verb>`` — renaming the APIRouter variable must not
    quietly move a file's routes out from under this scan.
    """
    for node in ast.walk(ast.parse(text)):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            if not (isinstance(dec, ast.Call)
                    and isinstance(dec.func, ast.Attribute)
                    and isinstance(dec.func.value, ast.Name)
                    and dec.func.attr in _MUTATING):
                continue
            route = _route_path(dec)
            if route is None:
                continue
            body = ast.get_source_segment(text, node) or ""
            yield dec.func.attr, route, body


def _is_audited(body: str, helpers: set[str]) -> bool:
    if "audit" in body:
        return True
    return any(re.search(rf"\b{re.escape(h)}\s*\(", body) for h in helpers)


class MutatingRoutesAuditedTests(unittest.TestCase):
    def test_every_mutating_route_audits_or_is_excepted(self):
        offenders = []
        for path in sorted(ROUTERS.glob("*.py")):
            text = path.read_text()
            helpers = _audit_helper_names(text)
            for verb, route, body in _routes(text):
                if (path.name, route) in ALLOWED_UNAUDITED:
                    continue
                if not _is_audited(body, helpers):
                    offenders.append(f"{path.name}: {verb.upper()} {route}")
        self.assertEqual(
            offenders,
            [],
            "these mutating routes leave no audit record; call audit.record "
            "with username= and client=, or add a justified exception:\n"
            + "\n".join(offenders),
        )

    def test_the_exception_list_matches_reality(self):
        """A stale exception is a hole waiting to be reopened silently."""
        real = set()
        for path in sorted(ROUTERS.glob("*.py")):
            for _verb, route, _body in _routes(path.read_text()):
                real.add((path.name, route))
        stale = sorted(k for k in ALLOWED_UNAUDITED if k not in real)
        self.assertEqual(
            stale, [],
            f"exceptions for routes that no longer exist: {stale}",
        )

    def test_no_mutating_route_hides_outside_the_routers_package(self):
        """The scans above read hub/routers/*.py and nothing else.

        That scope is only sound while it is the whole truth: a POST handler
        registered from hub/app_factory.py or a service module would carry
        the same privileges and none of these pins.  Keep every mutating
        route where the audit property is enforced.
        """
        hub_dir = BASE / "hub"
        strays = []
        for path in sorted(hub_dir.rglob("*.py")):
            if ROUTERS in path.parents:
                continue
            for verb, route, _body in _routes(path.read_text()):
                strays.append(
                    f"{path.relative_to(BASE)}: {verb.upper()} {route}"
                )
        self.assertEqual(
            strays,
            [],
            "mutating routes outside hub/routers escape the audit scan; "
            "move them into a router module:\n" + "\n".join(strays),
        )

    def test_exceptions_are_not_also_audited(self):
        """An exception for a route that *does* audit is dead weight —
        remove it so the list stays an honest inventory of the holes."""
        redundant = []
        for path in sorted(ROUTERS.glob("*.py")):
            text = path.read_text()
            helpers = _audit_helper_names(text)
            for _verb, route, body in _routes(text):
                key = (path.name, route)
                if key in ALLOWED_UNAUDITED and _is_audited(body, helpers):
                    redundant.append(key)
        self.assertEqual(redundant, [], f"already audited: {redundant}")


if __name__ == "__main__":
    unittest.main()
