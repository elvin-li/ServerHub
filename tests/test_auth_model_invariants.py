"""The authorization model itself, asserted against every route the app exposes.

96 of 130 mutating endpoints carry no route-level guard. That is not 96 holes: the
global `require_auth` dependency refuses a member account any method other than GET
on four fixed paths, and the loopback menu-bar token is scoped to six exact
endpoints. Those two facts are the entire basis of the panel's authorization, and
nothing was testing them as *properties* -- only individual routes, individually.

So this pins the properties. For every route in the real OpenAPI spec:

  * a member session may never reach a mutating endpoint
  * the loopback token may never reach anything outside its allowlist

`require_auth` is exercised directly rather than through TestClient on purpose. A
request against the live app would run the handler if the check turned out to be
missing, and "the security test pruned Docker" is not an acceptable failure mode.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import auth  # noqa: E402
from hub.app_factory import create_app  # noqa: E402

MUTATING = {"POST", "PUT", "PATCH", "DELETE"}

#: Endpoints that must stay reachable without an established session, because
#: they are how a session is established in the first place.
PUBLIC = {
    ("POST", "/api/auth/login"),
    ("POST", "/api/auth/setup"),
    ("POST", "/api/auth/logout"),
    ("GET", "/api/auth/status"),
    ("GET", "/ready"),
}

#: The loopback menu-bar client's entire surface, mirrored from
#: auth.local_client_authorized. Duplicated deliberately: if that function widens,
#: this list must be updated in a review that sees the security consequence.
LOCAL_TOKEN_ALLOWED = {
    ("GET", "/api/health"),
    ("GET", "/api/status"),
    ("GET", "/api/maintenance"),
    ("GET", "/api/launcher"),
    ("POST", "/api/action"),
    ("POST", "/api/containers/all"),
}


#: Namespaces require_auth passes to the route's own admin check, mirroring
#: auth._route_has_own_admin_guard.
DELEGATED_PREFIXES = ("/api/shares/", "/api/launcher/")

#: Guard calls that count as a route performing its own admin check.
ROUTE_GUARDS = (
    "_require_browser_session",
    "require_admin_browser",
    "_guard(",
    "browser_authenticated",
    "_require_admin",
)


def _is_delegated(path: str) -> bool:
    return any(path.startswith(prefix) for prefix in DELEGATED_PREFIXES)


def routes() -> list[tuple[str, str]]:
    """(method, concrete path) for every route, path params filled in."""
    spec = create_app().openapi()
    out = []
    for template, ops in spec["paths"].items():
        path = template
        # Any value works: authorization is decided before the handler parses it.
        while "{" in path:
            start = path.index("{")
            end = path.index("}", start)
            path = path[:start] + "x" + path[end + 1:]
        for method in ops:
            if method.upper() in MUTATING | {"GET"}:
                out.append((method.upper(), path))
    return out


class _FakeRequest:
    """Only the attributes require_auth actually reads."""

    def __init__(self, method: str, path: str, headers: dict | None = None):
        self.method = method
        self.headers = headers or {}
        self.url = type("U", (), {"path": path})()
        self.state = type("S", (), {})()
        self.client = type("C", (), {"host": "127.0.0.1"})()
        self.cookies = {}


class MemberCannotMutateTests(unittest.TestCase):
    """A family member account is read-only, on a handful of paths."""

    def setUp(self):
        self.routes = routes()
        self.assertGreater(len(self.routes), 150, "route discovery found almost nothing")

    def _member_reaches(self, method: str, path: str) -> bool:
        with (
            patch.object(auth, "setup_required", return_value=False),
            patch.object(auth, "browser_authenticated", return_value=True),
            patch.object(auth, "request_username", return_value="member"),
            patch.object(auth, "is_admin", return_value=False),
            patch.object(auth, "may_use_resource", return_value=True),
        ):
            try:
                auth.require_auth(_FakeRequest(method, path), None)
                return True
            except HTTPException:
                return False

    def test_a_member_cannot_reach_any_mutating_endpoint(self):
        """Either require_auth rejects the member, or the route rejects them itself.

        require_auth deliberately waves the shares and launcher namespaces through
        so those routes can answer with their own namespaced error codes. That
        delegation is only sound while every route in them actually performs the
        check -- see DelegatedNamespaceTests, which is the half that can regress.
        """
        reachable = [
            f"{method} {path}"
            for method, path in self.routes
            if method in MUTATING
            and (method, path) not in PUBLIC
            and not _is_delegated(path)
            and self._member_reaches(method, path)
        ]
        self.assertEqual(
            reachable,
            [],
            "a non-admin member session reached these mutations:\n"
            + "\n".join(sorted(reachable)),
        )

    def test_the_delegated_namespaces_are_the_only_exception(self):
        """A member reaching a mutation outside shares/launcher is never intended."""
        waved_through = sorted(
            f"{method} {path}"
            for method, path in self.routes
            if method in MUTATING
            and (method, path) not in PUBLIC
            and self._member_reaches(method, path)
        )
        for entry in waved_through:
            self.assertTrue(
                _is_delegated(entry.split(" ", 1)[1]),
                f"require_auth waves {entry} through but it is not a delegated route",
            )

    def test_a_member_can_still_read_its_own_dashboard(self):
        """Fail-closed must not mean fail-useless."""
        self.assertTrue(self._member_reaches("GET", "/api/status"))
        self.assertTrue(self._member_reaches("GET", "/api/health"))

    def test_a_member_cannot_read_arbitrary_endpoints(self):
        for path in ("/api/wireguard", "/api/wireguard/export", "/api/files/list",
                     "/api/settings", "/api/audit"):
            with self.subTest(path=path):
                self.assertFalse(
                    self._member_reaches("GET", path),
                    f"a member could read {path}",
                )


class LocalTokenScopeTests(unittest.TestCase):
    """Possession of the loopback token must not unlock the panel."""

    def setUp(self):
        self.routes = routes()

    def _token_reaches(self, method: str, path: str) -> bool:
        request = _FakeRequest(method, path, {auth.LOCAL_TOKEN_HEADER: "t"})
        with (
            patch.object(auth, "setup_required", return_value=False),
            patch.object(auth, "browser_authenticated", return_value=False),
            patch.object(auth, "local_client_authenticated", return_value=True),
        ):
            try:
                auth.require_auth(request, None)
                return True
            except HTTPException:
                return False

    def test_the_token_reaches_only_its_allowlist(self):
        """Delegated namespaces are excluded for the documented reason.

        require_auth lets a valid local token *reach* the shares and launcher
        routes so their own guard can answer with the stable route-specific error
        instead of a generic 401. Nothing runs before that guard, and
        DelegatedNamespaceTests proves the guard is present on every one of them.
        """
        extra = [
            f"{method} {path}"
            for method, path in self.routes
            if self._token_reaches(method, path)
            and (method, path) not in LOCAL_TOKEN_ALLOWED
            and not _is_delegated(path)
            and not (
                method == "GET"
                and path.startswith("/api/maintenance/")
                and path.endswith("/log")
            )
        ]
        self.assertEqual(
            extra,
            [],
            "the loopback token reached endpoints outside its scope:\n"
            + "\n".join(sorted(extra)),
        )

    def test_the_token_cannot_reach_key_material_or_shells(self):
        for method, path in (
            ("GET", "/api/wireguard/export"),
            ("GET", "/api/wireguard/conf"),
            ("POST", "/api/wireguard/interface"),
            ("GET", "/api/files/download"),
            ("POST", "/api/files/delete"),
            ("GET", "/api/settings"),
            ("POST", "/api/raid/delete"),
            ("POST", "/api/maintenance/daily/run"),
        ):
            with self.subTest(path=path):
                self.assertFalse(
                    self._token_reaches(method, path),
                    f"the loopback token reached {method} {path}",
                )

    def test_the_token_still_serves_the_menu_bar(self):
        for method, path in sorted(LOCAL_TOKEN_ALLOWED):
            with self.subTest(path=path):
                self.assertTrue(
                    self._token_reaches(method, path),
                    f"the menu-bar client lost access to {method} {path}",
                )


class DelegatedNamespaceTests(unittest.TestCase):
    """The dangerous half of the delegation.

    `require_auth` returns True for anything under /api/shares/ or /api/launcher/
    on the understanding that the route checks for itself. Add a route there and
    forget the check, and a member account walks straight into a mutation with no
    error anywhere -- the global dependency has already approved it.
    """

    def _mutating_handlers(self, filename: str):
        import ast

        path = BASE / "hub" / "routers" / filename
        source = path.read_text()
        lines = source.splitlines()
        for node in ast.walk(ast.parse(source)):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            methods = []
            route = ""
            for dec in node.decorator_list:
                if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute):
                    if getattr(dec.func.value, "id", "") == "router":
                        methods.append(dec.func.attr.upper())
                        if dec.args and isinstance(dec.args[0], ast.Constant):
                            route = str(dec.args[0].value)
            if not methods or not (set(methods) & MUTATING):
                continue
            body = "\n".join(lines[node.lineno - 1: node.end_lineno or node.lineno])
            yield route, sorted(set(methods)), body

    def test_every_delegated_mutation_checks_for_itself(self):
        gaps = []
        for filename in ("shares.py", "launcher_api.py"):
            for route, methods, body in self._mutating_handlers(filename):
                if not any(marker in body for marker in ROUTE_GUARDS):
                    gaps.append(f"{filename} {','.join(methods)} {route}")
        self.assertEqual(
            gaps,
            [],
            "require_auth waves these through expecting a route-level admin check "
            "that is not there, so a member session reaches them:\n" + "\n".join(gaps),
        )

    def test_the_analysis_sees_the_handlers(self):
        # Without this, a parsing change that found nothing would make the check
        # above pass vacuously.
        found = sum(
            1
            for filename in ("shares.py", "launcher_api.py")
            for _ in self._mutating_handlers(filename)
        )
        self.assertGreaterEqual(found, 6, "delegated handler discovery found too few")

    def test_the_delegation_list_matches_the_implementation(self):
        """If auth widens the delegation, this list must be reviewed with it."""
        source = (BASE / "hub" / "auth.py").read_text()
        start = source.index("def _route_has_own_admin_guard")
        body = source[start: source.index("\ndef ", start + 10)]
        for prefix in DELEGATED_PREFIXES:
            self.assertIn(prefix, body)
        quoted = {
            match
            for match in __import__("re").findall(r'"(/api/[a-z_/]+)"', body)
        }
        self.assertEqual(
            quoted,
            set(DELEGATED_PREFIXES),
            "auth._route_has_own_admin_guard covers namespaces this test does not "
            "know about; every one of them needs its own route-level check",
        )


class SetupLockdownTests(unittest.TestCase):
    def test_nothing_is_reachable_before_setup_completes(self):
        with patch.object(auth, "setup_required", return_value=True):
            for method, path in (("GET", "/api/status"), ("POST", "/api/action"),
                                 ("GET", "/api/wireguard")):
                with self.subTest(path=path):
                    with self.assertRaises(HTTPException):
                        auth.require_auth(_FakeRequest(method, path), None)


if __name__ == "__main__":
    unittest.main()
