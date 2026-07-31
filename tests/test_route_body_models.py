"""Guard against a request-body model being shadowed by a later redefinition.

``hub/routers/system_extra.py`` once declared ``NetDnsBody`` twice: first as
``{servers: list[str]}`` for setting a NIC's resolvers, then again 250 lines
later as ``{name: str}`` for a DNS lookup.  Python keeps the last definition, so
the set-resolvers endpoint silently started demanding ``{"name": ...}`` and
rejected every well-formed request from the SPA with 422.

Nothing catches that: the module imports, the routes register, and both
handlers are reachable.  Only the generated schema shows the wrong shape, so
these assertions read the OpenAPI document -- the same source the SPA and any
customer integration would consume.
"""
from __future__ import annotations

import unittest


def _openapi() -> dict:
    from hub.app_factory import create_app

    return create_app().openapi()


def _operation(spec: dict, path: str, method: str) -> dict:
    entry = spec["paths"].get(path)
    if entry is None:
        raise AssertionError(f"{path} is not registered")
    op = entry.get(method)
    if op is None:
        raise AssertionError(
            f"{path} does not accept {method.upper()} (has: "
            f"{sorted(k for k in entry if k != 'parameters')})"
        )
    return op


def _body_properties(spec: dict, path: str, method: str) -> tuple[str, list[str]]:
    """(schema name, sorted property names) of an operation's request body."""
    op = _operation(spec, path, method)
    body = op.get("requestBody")
    if not body:
        raise AssertionError(f"{method.upper()} {path} declares no request body")
    ref = body["content"]["application/json"]["schema"]["$ref"]
    name = ref.rsplit("/", 1)[-1]
    schema = spec["components"]["schemas"][name]
    return name, sorted(schema.get("properties") or {})


class TestDnsEndpointBodies(unittest.TestCase):
    """The two DNS endpoints must keep distinct, correctly-shaped bodies."""

    @classmethod
    def setUpClass(cls):
        cls.spec = _openapi()

    def test_set_resolvers_takes_a_server_list(self):
        name, props = _body_properties(
            self.spec, "/api/system/network/services/{service_name}/dns", "post"
        )
        self.assertEqual(props, ["servers"], f"resolved to {name}")

    def test_dns_lookup_takes_a_hostname(self):
        name, props = _body_properties(self.spec, "/api/tools/net/dns", "post")
        self.assertEqual(props, ["name"], f"resolved to {name}")

    def test_the_two_endpoints_do_not_share_a_model(self):
        setter, _ = _body_properties(
            self.spec, "/api/system/network/services/{service_name}/dns", "post"
        )
        lookup, _ = _body_properties(self.spec, "/api/tools/net/dns", "post")
        self.assertNotEqual(
            setter,
            lookup,
            "both endpoints resolve to the same model - one definition is "
            "shadowing the other again",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
