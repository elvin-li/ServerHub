"""WireGuard APIs — server state, peer lifecycle, multi-format export, readiness.

Endpoint shape follows the reference router panel this page is modelled on, so an
operator who knows that UI finds the same operations here: status, add/batch/delete/
import peer, next free address, PSK toggle, restart, raw config view, peer ping,
and export.

Authorization: reads need a signed-in session; every mutation needs an
administrator *browser* session, because bringing the interface up or reloading it
can require the native macOS authorization sheet.  Peer creation and deletion are
audited — a peer is a credential granting network access, so who issued or revoked
it is worth keeping.
"""
from __future__ import annotations

from fastapi import APIRouter, Request, Response
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, ConfigDict, Field, StrictBool

from hub import audit, wireguard_export, wireguard_net_svc, wireguard_svc
from hub.errors import api_error
from hub.routers.nas_common import (
    client_host,
    raise_for_admin_result,
    raise_service_error,
    require_admin_browser,
)

router = APIRouter(tags=["wireguard"])


def _guard(request: Request) -> str:
    """Administrator browser session, plus a hard stop when wg is missing."""
    username = require_admin_browser(request)
    if not wireguard_svc.installation()["installed"]:
        raise api_error("wg.not_installed")
    return username


def _call(fn, **kwargs):
    """Run a service call, translating its typed error into an API error."""
    try:
        return fn(**kwargs)
    except wireguard_svc.WireGuardError as exc:
        raise api_error(exc.code, **exc.params)


def _check_format(fmt: str) -> str:
    value = (fmt or "wg").strip().lower()
    if value not in wireguard_export.FORMATS:
        raise api_error("wg.bad_format", format=value[:20])
    return value


# ── read ─────────────────────────────────────────────────────────────────────

@router.get("/api/wireguard")
def api_wireguard(force: bool = False):
    """Server state and the peer table."""
    return wireguard_svc.status(force=force)


@router.get("/api/wireguard/readiness")
def api_wireguard_readiness():
    """Whether traffic can actually flow, not merely whether the tunnel is up."""
    return wireguard_net_svc.readiness()


@router.get("/api/wireguard/settings")
def api_wireguard_settings():
    return {
        "settings": wireguard_svc.settings(),
        "install": wireguard_svc.installation(),
        "wstunnel": wireguard_svc.wstunnel_status(),
    }


@router.get("/api/wireguard/next-ip")
def api_wireguard_next_ip():
    return _call(wireguard_svc.next_ip)


# The four endpoints below return key material -- a peer's private key, or the
# server's own.  They are guarded exactly like the mutations and marked no-store.
#
# The global auth dependency already refuses non-admin sessions here, so this is
# defence in depth rather than a patched hole.  It is still worth having: it does
# not depend on a middleware path rule staying correct, and _guard additionally
# demands a *browser* session, which a bearer-token client cannot present.
#
# no-store matters independently of authorization: without it a private key can
# come to rest in the browser's disk cache or an intermediary long after the
# session that fetched it has gone.
_SECRET_HEADERS = {
    "Cache-Control": "no-store, no-cache, must-revalidate",
    "Pragma": "no-cache",
}


@router.get("/api/wireguard/conf")
def api_wireguard_conf(request: Request, response: Response, reveal: bool = False):
    """The server config.  The private key is redacted unless explicitly revealed."""
    _guard(request)
    response.headers.update(_SECRET_HEADERS)
    return _call(wireguard_svc.view_conf, reveal=bool(reveal))


# The peer key travels as a query parameter, not a path segment: WireGuard
# public keys are raw base64, and Starlette percent-decodes the path BEFORE
# routing, so a key containing "/" (encoded as %2F by the client) splits into
# extra segments and the route 404s.  Query values are decoded after matching,
# where %2F is safe.  Keys with "/" are common enough that this is not a corner
# case -- it broke the config dialog for any such peer.
@router.get("/api/wireguard/peers/config")
def api_wireguard_peer_config(
    request: Request, response: Response, pubkey: str, format: str = "wg"
):
    """Re-issue one peer's config in the requested format."""
    _guard(request)
    response.headers.update(_SECRET_HEADERS)
    return _call(wireguard_svc.peer_conf, pubkey=pubkey, fmt=_check_format(format))


@router.get("/api/wireguard/peers/download", response_class=PlainTextResponse)
def api_wireguard_peer_download(request: Request, pubkey: str, format: str = "wg"):
    """Same payload as ``/config`` but as a file download."""
    _guard(request)
    result = _call(wireguard_svc.peer_conf, pubkey=pubkey, fmt=_check_format(format))
    return PlainTextResponse(
        result["content"],
        media_type="text/plain; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{result["filename"]}"',
            **_SECRET_HEADERS,
        },
    )


@router.get("/api/wireguard/export")
def api_wireguard_export(request: Request, response: Response, format: str = "wg"):
    """Every re-issuable peer in one response, for a bulk hand-out."""
    _guard(request)
    response.headers.update(_SECRET_HEADERS)
    return wireguard_svc.export_all(_check_format(format))


# ── settings ─────────────────────────────────────────────────────────────────

class WgSettingsBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    interface: str | None = None
    subnet: str | None = None
    listen_port: int | None = None
    dns: str | None = None
    mtu: int | None = None
    keepalive: int | None = None
    #: Public host (or host:port) clients dial. Without it, generated configs
    #: carry a placeholder Endpoint and cannot connect.
    endpoint: str | None = None
    #: Home LAN reachable through the tunnel, used for split-tunnel AllowedIPs.
    lan_cidr: str | None = None
    #: NAT egress interface; empty means follow the default route.
    wan_interface: str | None = None
    #: Wrap the UDP handshake in wstunnel (WebSocket on TCP) so a network
    #: that drops WireGuard still lets clients in.
    wstunnel_enabled: StrictBool | None = None
    wstunnel_listen: str | None = None
    wstunnel_public: str | None = None
    wstunnel_restrict_to: str | None = None


@router.put("/api/wireguard/settings")
def api_wireguard_settings_put(body: WgSettingsBody, request: Request):
    username = _guard(request)
    patch = {k: v for k, v in body.model_dump().items() if v is not None}
    saved = _call(wireguard_svc.save_settings, patch=patch)
    # Only the changed key names go into the trail: the values (endpoint,
    # LAN CIDR, wstunnel listen address) map the network for anyone who
    # later reads the log, and "who changed what knob" is the question the
    # trail answers — the current values live in the settings file itself.
    audit.record(
        audit.WIREGUARD_SETTINGS_CHANGED,
        username=username,
        client=client_host(request),
        fields=",".join(sorted(patch)),
    )
    return {"ok": True, "settings": saved}


# ── peers ────────────────────────────────────────────────────────────────────

class WgAddPeerBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    #: Omit to take the next free address in the subnet.
    ip: str = ""
    mode: str = Field("split", description="full|split")
    psk: StrictBool = False
    #: Retain the generated private key so the config can be re-issued later.
    #: Turning this off hands the key over exactly once.
    keep_key: StrictBool = True


class WgBatchAddBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    count: int
    prefix: str = "peer"
    mode: str = "split"
    psk: StrictBool = False
    keep_key: StrictBool = True


class WgDelPeerBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pubkey: str
    confirm: StrictBool = False


class WgImportPeerBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pubkey: str
    ip: str
    name: str = ""
    psk: str = ""


class WgPskBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pubkey: str
    op: str = Field(..., description="add|remove")


@router.post("/api/wireguard/peers")
def api_wireguard_add_peer(body: WgAddPeerBody, request: Request):
    username = _guard(request)
    result = _call(
        wireguard_svc.add_peer,
        name=body.name,
        ip=body.ip,
        mode=body.mode,
        psk=body.psk,
        keep_key=body.keep_key,
    )
    audit.record(
        audit.WIREGUARD_PEER_ADDED,
        username=username,
        client=client_host(request),
        name=result["name"],
        ip=result["ip"],
        mode=result["mode"],
        # The config body carries a private key; only the public half is logged.
        pubkey=result["pub"],
    )
    return result


@router.post("/api/wireguard/peers/batch")
def api_wireguard_batch_add(body: WgBatchAddBody, request: Request):
    username = _guard(request)
    result = _call(
        wireguard_svc.batch_add,
        count=body.count,
        prefix=body.prefix,
        mode=body.mode,
        psk=body.psk,
        keep_key=body.keep_key,
    )
    audit.record(
        audit.WIREGUARD_PEER_ADDED,
        username=username,
        client=client_host(request),
        batch=True,
        created=result["created"],
        prefix=body.prefix,
    )
    return result


@router.post("/api/wireguard/peers/delete")
def api_wireguard_del_peer(body: WgDelPeerBody, request: Request):
    username = _guard(request)
    if not body.confirm:
        raise api_error("wg.confirm_required")
    result = _call(wireguard_svc.del_peer, pubkey=body.pubkey)
    audit.record(
        audit.WIREGUARD_PEER_REMOVED,
        username=username,
        client=client_host(request),
        pubkey=body.pubkey,
    )
    return result


@router.post("/api/wireguard/peers/import")
def api_wireguard_import_peer(body: WgImportPeerBody, request: Request):
    username = _guard(request)
    result = _call(
        wireguard_svc.import_peer,
        pubkey=body.pubkey,
        ip=body.ip,
        name=body.name,
        psk=body.psk,
    )
    audit.record(
        audit.WIREGUARD_PEER_ADDED,
        username=username,
        client=client_host(request),
        imported=True,
        pubkey=body.pubkey,
        ip=result["ip"],
    )
    return result


@router.post("/api/wireguard/peers/psk")
def api_wireguard_toggle_psk(body: WgPskBody, request: Request):
    username = _guard(request)
    result = _call(wireguard_svc.toggle_psk, pubkey=body.pubkey, op=body.op)
    audit.record(
        audit.WIREGUARD_PEER_CHANGED,
        username=username,
        client=client_host(request),
        pubkey=body.pubkey,
        op=body.op,
    )
    return result


# ── interface control ────────────────────────────────────────────────────────

class WgInterfaceBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: str = Field(..., description="up|down|restart")


@router.post("/api/wireguard/interface")
def api_wireguard_interface(body: WgInterfaceBody, request: Request):
    username = _guard(request)
    result = _call(wireguard_svc.interface_action, action=body.action)
    audit.record(
        audit.WIREGUARD_INTERFACE,
        username=username,
        client=client_host(request),
        action=body.action,
        ok=bool(result.get("ok")),
    )
    return raise_for_admin_result(result)


@router.post("/api/wireguard/sync")
def api_wireguard_sync(request: Request):
    """Reload the running interface from disk without dropping live tunnels."""
    username = _guard(request)
    result = wireguard_svc.apply_live()
    audit.record(
        audit.WIREGUARD_INTERFACE,
        username=username,
        client=client_host(request),
        action="sync",
        ok=bool(result.get("ok")),
    )
    if not result.get("ok"):
        raise api_error("wg.sync_failed")
    return result


@router.post("/api/wireguard/ping")
def api_wireguard_ping(request: Request):
    _guard(request)
    return wireguard_svc.ping_peers()


# ── macOS readiness remediation ──────────────────────────────────────────────

class WgForwardingBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: StrictBool


class WgRemediateBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    #: Which gap to close: nat | daemon | wstunnel | wstunnel_stabilize
    target: str = Field(..., description="nat|daemon|wstunnel|wstunnel_stabilize")
    enabled: StrictBool = True


@router.post("/api/wireguard/forwarding")
def api_wireguard_forwarding(body: WgForwardingBody, request: Request):
    username = _guard(request)
    result = wireguard_net_svc.set_forwarding(body.enabled)
    audit.record(
        audit.WIREGUARD_INTERFACE,
        username=username,
        client=client_host(request),
        action="forwarding",
        enabled=body.enabled,
        ok=bool(result.get("ok")),
    )
    return raise_for_admin_result(result)


@router.post("/api/wireguard/remediate")
def api_wireguard_remediate(body: WgRemediateBody, request: Request):
    """Install or remove one of the macOS-side prerequisites."""
    username = _guard(request)
    target = (body.target or "").strip().lower()
    actions = {
        ("nat", True): wireguard_net_svc.install_nat,
        ("nat", False): wireguard_net_svc.remove_nat,
        ("daemon", True): wireguard_net_svc.install_daemon,
        ("daemon", False): wireguard_net_svc.uninstall_daemon,
        ("wstunnel", True): wireguard_net_svc.install_wstunnel,
        ("wstunnel", False): wireguard_net_svc.uninstall_wstunnel,
        ("wstunnel_stabilize", True): wireguard_net_svc.stabilize_wstunnel,
    }
    fn = actions.get((target, bool(body.enabled)))
    if fn is None:
        raise api_error("wg.bad_action", action=target[:20])
    result = fn()
    audit.record(
        audit.WIREGUARD_INTERFACE,
        username=username,
        client=client_host(request),
        action=f"{target}_{'install' if body.enabled else 'remove'}",
        ok=bool(result.get("ok")),
    )
    return raise_service_error(result, {
        "wstunnel_missing": "wg.wstunnel_missing",
        "bad_wstunnel_url": "wg.bad_wstunnel_url",
        "bad_wstunnel_target": "wg.bad_wstunnel_target",
        "wstunnel_install_unverified": "wg.wstunnel_install_unverified",
        # A leftover node occupying a staging file under data/ is a coded
        # 503 naming the path, not a raw IsADirectoryError 500.
        "stage_write_failed": "wg.write_failed",
    })
