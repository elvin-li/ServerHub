"""Sites: every web site on this Mac, discovered fresh on each refresh.

Nothing here is a static list.  Each call to :func:`list_sites` asks every
discovery source what it serves right now:

* ``nginx``       -- the ServerHub system nginx (``nginx_svc.NGINX_CONF``) and
                     any Homebrew nginx tree, following ``include`` globs
                     (``servers/``, ``sites-enabled/``, ``conf.d/``).
* ``caddy``       -- a Caddyfile under the Homebrew prefix or ``~/.config/caddy``.
* ``apache``      -- Homebrew / system httpd vhosts.
* ``cloudflared`` -- ingress hostnames from the locally-managed tunnel config.
* ``launchd``     -- LaunchAgents with an HTTP port (the shared status snapshot).
* ``docker``      -- containers with published TCP ports.
* ``listener``    -- any other local LISTEN socket that answers HTTP.

Every source is optional: a missing binary, file or engine yields an empty
list and a per-source note, never a 500.  Sources run in parallel with a hard
deadline, the merged answer is cached for ``_TTL`` seconds, and each site's
status is a TCP / HTTP probe of its local endpoint.
"""
from __future__ import annotations

import concurrent.futures as cf
import glob
import hashlib
import os
import re
import socket
import ssl
import time
from pathlib import Path

from hub import nginx_svc
from hub.errors import api_error
from hub.paths import DOCKER, user_home
from hub.util import read_text_capped, sh, ttl_memo

_CONTROL_FLOW = (KeyboardInterrupt, SystemExit)
_TTL = 10.0
_SOURCE_DEADLINE = 8.0
_PROBE_TIMEOUT = 0.8
_CONF_CAP = 512 * 1024
_MAX_INCLUDE_FILES = 200
_MAX_LISTENER_PROBES = 48
_SOURCE_ORDER = ("nginx", "caddy", "apache", "cloudflared", "launchd", "docker", "listener")
_LOCAL_HOSTS = {"", "*", "localhost", "127.0.0.1", "0.0.0.0", "::", "[::]", "::1", "[::1]"}

# Homebrew / system locations.  Module constants so tests can point them at a
# temp tree.
HOMEBREW_PREFIXES = ("/opt/homebrew", "/usr/local")


def _home() -> Path | None:
    try:
        home = user_home()
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return None
    return home if isinstance(home, Path) else None


def _extra_nginx_confs() -> list[Path]:
    return [Path(p) / "etc" / "nginx" / "nginx.conf" for p in HOMEBREW_PREFIXES]


def _caddyfiles() -> list[Path]:
    out = [Path(p) / "etc" / "Caddyfile" for p in HOMEBREW_PREFIXES]
    home = _home()
    if home is not None:
        out.append(home / ".config" / "caddy" / "Caddyfile")
    out.append(Path("/etc/caddy/Caddyfile"))
    return out


def _httpd_confs() -> list[Path]:
    out = [Path(p) / "etc" / "httpd" / "httpd.conf" for p in HOMEBREW_PREFIXES]
    out.append(Path("/etc/apache2/httpd.conf"))
    return out


def _cloudflared_configs() -> list[Path]:
    """Locally-managed tunnel configs (a token-run tunnel has none)."""
    out = []
    try:
        from hub import cloudflared_svc
        out.append(Path(cloudflared_svc.CONFIG_YML))
    except _CONTROL_FLOW:
        raise
    except BaseException:
        pass
    home = _home()
    if home is not None:
        out += [home / ".cloudflared" / "config.yml", home / ".cloudflared" / "config.yaml"]
    out += [Path(p) / "etc" / "cloudflared" / "config.yml" for p in HOMEBREW_PREFIXES]
    out.append(Path("/etc/cloudflared/config.yml"))
    return out


# ---------------------------------------------------------------- utilities

def _read(path: Path) -> str | None:
    try:
        if not path.is_file():
            return None
        text = read_text_capped(path, _CONF_CAP, errors="replace")
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return None
    if isinstance(text, (bytes, bytearray)):
        text = bytes(text).decode("utf-8", "replace")
    return text if isinstance(text, str) else None


def _clean(text) -> str:
    """JSON-safe text: lone surrogates would 500 the encoder."""
    if not isinstance(text, str):
        text = "" if text is None else str(text)
    return text.encode("utf-8", "replace").decode("utf-8")


def _port(value) -> int | None:
    try:
        n = int(str(value).strip())
    except (TypeError, ValueError, OverflowError):
        return None
    return n if 0 < n <= 65535 else None


def _is_local(host: str) -> bool:
    return (host or "").strip().lower() in _LOCAL_HOSTS


def _real_hostname(name: str) -> bool:
    """A server_name a browser can actually open (not ``_``, regex or wildcard)."""
    n = (name or "").strip().lower()
    if not n or n in ("_", "localhost") or n.startswith("~") or "*" in n or "$" in n:
        return False
    return bool(re.fullmatch(r"[a-z0-9.-]+", n)) and "." in n


def _site_id(*parts) -> str:
    raw = "\x1f".join(_clean(p) for p in parts)
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:12]


def _build_url(scheme: str, host: str, port: int | None) -> str:
    default = (scheme == "https" and port == 443) or (scheme == "http" and port == 80)
    shown = "localhost" if _is_local(host) else host
    if ":" in shown and not shown.startswith("["):
        shown = f"[{shown}]"
    return f"{scheme}://{shown}" + ("" if default or port is None else f":{port}")


def _upstream_port(upstream: str) -> int | None:
    m = re.match(r"^(?:[a-z+]+://)?(?:\[[^\]]+\]|[^/:]+)?:(\d+)", (upstream or "").strip(), re.I)
    return _port(m.group(1)) if m else None


def _make_site(source: str, *, name: str, host: str, port: int | None, scheme: str = "http",
               server_names=(), root: str | None = None, upstream: str | None = None,
               config_path: str | None = None, probe_host: str = "127.0.0.1",
               probe_tls: bool | None = None, detail: str = "", optional: bool = False,
               url: str | None = None, extra_actions=(), http_only: bool = False) -> dict:
    host = host or "localhost"
    url = url or _build_url(scheme, host, port)
    return {
        "id": _site_id(source, host, port, config_path or "", upstream or ""),
        "name": _clean(name or host),
        "source": source,
        "url": _clean(url),
        "urls": [_clean(url)],
        "host": _clean(host),
        "server_names": [_clean(s) for s in server_names],
        "port": port,
        "scheme": scheme,
        "root": _clean(root) if root else None,
        "upstream": _clean(upstream) if upstream else None,
        "config_path": _clean(config_path) if config_path else None,
        "status": "unknown",
        "detail": _clean(detail),
        "actions": ["open"] + list(extra_actions),
        "also_seen_in": [],
        # Internal probe hints; stripped before the payload leaves the module.
        "_probe": (probe_host, port, scheme == "https" if probe_tls is None else probe_tls,
                   host if not _is_local(host) else None),
        "_optional": optional,
        "_http_only": http_only,
    }


# ---------------------------------------------------------------- nginx

def _strip_hash_comments(text: str) -> str:
    out = []
    for line in text.splitlines():
        buf, quote = [], None
        for ch in line:
            if quote:
                if ch == quote:
                    quote = None
            elif ch in "'\"":
                quote = ch
            elif ch == "#":
                break
            buf.append(ch)
        out.append("".join(buf))
    return "\n".join(out)


_NGX_TOKEN = re.compile(r"""("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[{};]|[^\s{};]+)""")


def _nginx_tokens(text: str) -> list[str]:
    return _NGX_TOKEN.findall(_strip_hash_comments(text))


def _nginx_tree(tokens: list[str], src: str) -> list:
    """Nested ``[name, args, children|None, src]`` directives from a token stream."""
    stack: list[list] = [[]]
    cur: list[str] = []
    for tok in tokens:
        if tok == ";":
            if cur:
                stack[-1].append([cur[0], cur[1:], None, src])
            cur = []
        elif tok == "{":
            node = [cur[0] if cur else "", cur[1:], [], src]
            stack[-1].append(node)
            stack.append(node[2])
            cur = []
        elif tok == "}":
            cur = []
            if len(stack) > 1:
                stack.pop()
        else:
            cur.append(tok[1:-1] if len(tok) > 1 and tok[0] in "\"'" and tok[-1] == tok[0] else tok)
    return stack[0]


def _expand_includes(nodes: list, base: Path, seen: set, budget: list) -> list:
    """Inline ``include`` directives (glob, relative to the main conf's dir)."""
    out = []
    for name, args, children, src in nodes:
        if name == "include" and children is None and args:
            pattern = args[0]
            if not os.path.isabs(pattern):
                pattern = str(base / pattern)
            try:
                matches = sorted(glob.glob(pattern))
            except _CONTROL_FLOW:
                raise
            except BaseException:
                matches = []
            for m in matches:
                p = Path(m)
                if budget[0] <= 0 or str(p) in seen or p.name == "mime.types":
                    continue
                seen.add(str(p))
                budget[0] -= 1
                text = _read(p)
                if text is None:
                    continue
                out.extend(_expand_includes(_nginx_tree(_nginx_tokens(text), str(p)), base, seen, budget))
            continue
        if children is not None:
            children = _expand_includes(children, base, seen, budget)
        out.append([name, args, children, src])
    return out


def _collect_servers(nodes: list) -> list[tuple[list, str]]:
    found = []
    for name, _args, children, src in nodes:
        if children is None:
            continue
        if name == "server":
            found.append((children, src))
        elif name == "http":
            found.extend(_collect_servers(children))
    return found


def _first_arg(children: list, directive: str) -> str | None:
    for name, args, sub, _src in children:
        if name == directive and sub is None and args:
            return args[0]
    return None


def _find_all(children: list, directive: str) -> list[list[str]]:
    hits = []
    for name, args, sub, _src in children:
        if name == directive and sub is None:
            hits.append(args)
        elif sub is not None and name in ("location", "if"):
            hits.extend(_find_all(sub, directive))
    return hits


def _parse_listen(args: list[str]) -> tuple[str, int | None, bool]:
    if not args:
        return "", 80, False
    addr = args[0]
    tls = "ssl" in args[1:] or "quic" in args[1:]
    if addr.startswith("unix:"):
        return addr, None, tls
    m = re.match(r"^(\[[^\]]*\]|[^:]*):(\d+)$", addr)
    if m:
        return m.group(1), _port(m.group(2)), tls
    if addr.isdigit():
        return "", _port(addr), tls
    return addr, 80, tls


def parse_nginx_conf(conf: Path, *, reloadable: bool = False, optional: bool = False) -> list[dict]:
    """Server blocks from *conf* and everything it includes."""
    text = _read(conf)
    if text is None:
        return []
    seen = {str(conf)}
    budget = [_MAX_INCLUDE_FILES]
    tree = _expand_includes(_nginx_tree(_nginx_tokens(text), str(conf)), conf.parent, seen, budget)
    # A tree whose nginx.conf does not include its own site dirs (or a missing
    # include line) still has sites there: scan the conventional dirs too.
    for sub in ("servers", "sites-enabled", "conf.d"):
        for p in sorted(glob.glob(str(conf.parent / sub / "*.conf"))):
            if p in seen:
                continue
            seen.add(p)
            body = _read(Path(p))
            if body is None:
                continue
            # A bare conf.d file holds ``server`` blocks at top level; wrap them
            # as if included from inside ``http``.
            tree.append(["http", [], _expand_includes(
                _nginx_tree(_nginx_tokens(body), p), conf.parent, seen, budget), p])
    sites = []
    for children, src in _collect_servers(tree):
        listens = [_parse_listen(a) for a in _find_all(children, "listen")] or [("", 80, False)]
        names = [n for a in _find_all(children, "server_name") for n in a]
        root = _first_arg(children, "root") or (_find_all(children, "root") or [[None]])[0][0]
        proxies = [a[0] for a in _find_all(children, "proxy_pass") if a]
        proxies += [a[0] for a in _find_all(children, "fastcgi_pass") if a]
        returns = _find_all(children, "return")
        real = [n for n in names if _real_hostname(n)]
        host = real[0] if real else "localhost"
        actions = ("view_config", "test", "reload") if reloadable else ("view_config",)
        for addr, port, tls in listens:
            if port is None:
                continue
            scheme = "https" if tls or port == 443 else "http"
            probe_host = "127.0.0.1" if _is_local(addr) else addr.strip("[]")
            detail = ""
            if not root and not proxies and returns:
                detail = "redirect: " + " ".join(returns[0])
            sites.append(_make_site(
                "nginx", name=host if real else f"{Path(src).name}:{port}", host=host, port=port,
                scheme=scheme, server_names=names, root=root,
                upstream=" · ".join(proxies[:4]) or None, config_path=src,
                probe_host=probe_host, detail=detail, optional=optional,
                extra_actions=actions,
            ))
    return sites


def _nginx_source() -> list[dict]:
    main = Path(nginx_svc.NGINX_CONF)
    sites = parse_nginx_conf(main, reloadable=True)
    for extra in _extra_nginx_confs():
        try:
            if extra.resolve() == main.resolve():
                continue
        except OSError:
            continue
        # A stock Homebrew tree is often installed but not running; only its
        # answering sites are reported (see ``_optional``).
        sites += parse_nginx_conf(extra, optional=True)
    return sites


# ---------------------------------------------------------------- Caddy

def _caddy_blocks(text: str) -> list[tuple[list[str], list[str]]]:
    """Top-level ``(addresses, body_lines)`` pairs from a Caddyfile."""
    lines = [_strip_hash_comments(line).strip() for line in text.splitlines()]
    lines = [line for line in lines if line]
    blocks, i = [], 0
    while i < len(lines):
        line = lines[i]
        if "{" in line:
            head, rest = line.split("{", 1)
            head = head.strip()
            depth = 1 + rest.count("{") - rest.count("}")
            # ``{ admin off }`` / ``(snip) { encode gzip }`` on one line.
            inline = rest.rsplit("}", 1)[0].strip() if depth <= 0 else rest.strip()
            body = [inline] if inline else []
            i += 1
            while i < len(lines) and depth > 0:
                cur = lines[i]
                depth += cur.count("{") - cur.count("}")
                if depth > 0:
                    body.append(cur)
                i += 1
            if not head or head.startswith("("):
                continue  # global options or a snippet
            blocks.append(([a for a in re.split(r"[,\s]+", head) if a], body))
        else:
            # Single-site Caddyfile without braces: first line is the address.
            if not blocks and i == 0:
                blocks.append(([a for a in re.split(r"[,\s]+", line) if a], lines[1:]))
                break
            i += 1
    return blocks


def _caddy_address(addr: str) -> tuple[str, str, int | None]:
    scheme = ""
    m = re.match(r"^(https?)://(.*)$", addr, re.I)
    if m:
        scheme, addr = m.group(1).lower(), m.group(2)
    addr = addr.split("/", 1)[0]
    host, port = addr, None
    m = re.match(r"^(\[[^\]]*\]|[^:]*):(\d+)$", addr)
    if m:
        host, port = m.group(1), _port(m.group(2))
    if not scheme:
        if port == 80:
            scheme = "http"
        elif _is_local(host) and port is not None:
            scheme = "http" if host == "" else "https"
        else:
            scheme = "https"
    if port is None:
        port = 443 if scheme == "https" else 80
    return scheme, host or "localhost", port


def parse_caddyfile(path: Path) -> list[dict]:
    text = _read(path)
    if text is None:
        return []
    sites = []
    for addrs, body in _caddy_blocks(text):
        root = upstream = None
        for line in body:
            parts = line.split()
            if not parts:
                continue
            if parts[0] == "root" and len(parts) >= 2:
                root = parts[-1]
            elif parts[0] == "reverse_proxy" and len(parts) >= 2 and upstream is None:
                upstream = next((p for p in parts[1:] if not p.startswith("@") and p != "{"), None)
        for addr in addrs:
            scheme, host, port = _caddy_address(addr)
            sites.append(_make_site(
                "caddy", name=host if not _is_local(host) else f"caddy:{port}", host=host,
                port=port, scheme=scheme, server_names=[addr], root=root, upstream=upstream,
                config_path=str(path), extra_actions=("view_config",),
            ))
    return sites


def _caddy_source() -> list[dict]:
    out, seen = [], set()
    for p in _caddyfiles():
        if str(p) in seen:
            continue
        seen.add(str(p))
        out += parse_caddyfile(p)
    return out


# ---------------------------------------------------------------- Apache

_APACHE_INCLUDE = re.compile(r"^\s*Include(?:Optional)?\s+\"?([^\"\s]+)\"?", re.I | re.M)


def _apache_text(conf: Path, budget: list, seen: set) -> list[tuple[str, str]]:
    text = _read(conf)
    if text is None:
        return []
    out = [(str(conf), text)]
    root_m = re.search(r"^\s*ServerRoot\s+\"?([^\"\s]+)\"?", text, re.I | re.M)
    server_root = Path(root_m.group(1)) if root_m else conf.parent.parent
    for m in _APACHE_INCLUDE.finditer(_strip_hash_comments(text)):
        pattern = m.group(1)
        if not os.path.isabs(pattern):
            pattern = str(server_root / pattern)
        for p in sorted(glob.glob(pattern)):
            if budget[0] <= 0 or p in seen:
                continue
            seen.add(p)
            budget[0] -= 1
            out += _apache_text(Path(p), budget, seen)
    return out


def parse_httpd_conf(conf: Path, *, optional: bool = True) -> list[dict]:
    files = _apache_text(conf, [_MAX_INCLUDE_FILES], {str(conf)})
    sites = []
    main_listen: list[int] = []
    main_name = main_root = None
    for src, raw in files:
        text = _strip_hash_comments(raw)
        for m in re.finditer(r"^\s*Listen\s+(?:\S+:)?(\d+)", text, re.I | re.M):
            p = _port(m.group(1))
            if p:
                main_listen.append(p)
        outside = re.sub(r"<VirtualHost[^>]*>.*?</VirtualHost>", "", text, flags=re.I | re.S)
        m = re.search(r"^\s*ServerName\s+(\S+)", outside, re.I | re.M)
        if m and main_name is None:
            main_name = m.group(1)
        m = re.search(r"^\s*DocumentRoot\s+\"?([^\"\s]+)\"?", outside, re.I | re.M)
        if m and main_root is None:
            main_root = m.group(1)
        for vm in re.finditer(r"<VirtualHost\s+([^>]*)>(.*?)</VirtualHost>", text, re.I | re.S):
            body = vm.group(2)
            name_m = re.search(r"^\s*ServerName\s+(\S+)", body, re.I | re.M)
            aliases = re.findall(r"^\s*ServerAlias\s+(.+)$", body, re.I | re.M)
            root_m = re.search(r"^\s*DocumentRoot\s+\"?([^\"\s]+)\"?", body, re.I | re.M)
            proxy_m = re.search(r"^\s*ProxyPass\s+\S+\s+(\S+)", body, re.I | re.M)
            names = ([name_m.group(1)] if name_m else []) + [a for line in aliases for a in line.split()]
            tls = bool(re.search(r"^\s*SSLEngine\s+on", body, re.I | re.M))
            for addr in vm.group(1).split():
                host, _, port_s = addr.rpartition(":")
                port = _port(port_s) or (443 if tls else 80)
                hostname = names[0].split(":")[0] if names and _real_hostname(names[0].split(":")[0]) else "localhost"
                sites.append(_make_site(
                    "apache", name=hostname if hostname != "localhost" else f"httpd:{port}",
                    host=hostname, port=port, scheme="https" if tls or port == 443 else "http",
                    server_names=names, root=root_m.group(1) if root_m else None,
                    upstream=proxy_m.group(1) if proxy_m else None, config_path=src,
                    probe_host="127.0.0.1" if _is_local(host) else host.strip("[]"),
                    optional=optional, extra_actions=("view_config",),
                ))
    if not sites:
        for port in sorted(set(main_listen)) or []:
            hostname = main_name.split(":")[0] if main_name and _real_hostname(main_name.split(":")[0]) else "localhost"
            sites.append(_make_site(
                "apache", name=hostname if hostname != "localhost" else f"httpd:{port}",
                host=hostname, port=port, scheme="https" if port == 443 else "http",
                server_names=[main_name] if main_name else [], root=main_root,
                config_path=str(conf), optional=optional, extra_actions=("view_config",),
            ))
    return sites


def _apache_source() -> list[dict]:
    out = []
    for conf in _httpd_confs():
        # macOS ships /etc/apache2 configured but stopped; every Apache tree is
        # therefore "optional" and only reported while it answers.
        out += parse_httpd_conf(conf, optional=True)
    return out


# ---------------------------------------------------------------- cloudflared

def parse_cloudflared_config(path: Path) -> list[dict]:
    text = _read(path)
    if text is None:
        return []
    try:
        import yaml
        data = yaml.safe_load(text)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return []
    if not isinstance(data, dict) or not isinstance(data.get("ingress"), list):
        return []
    sites = []
    for rule in data["ingress"]:
        if not isinstance(rule, dict):
            continue
        hostname = rule.get("hostname")
        service = rule.get("service")
        if not isinstance(hostname, str) or not hostname or not isinstance(service, str):
            continue  # the catch-all http_status rule has no hostname
        up_port = _upstream_port(service)
        up_host_m = re.match(r"^[a-z]+://(\[[^\]]+\]|[^/:]+)", service, re.I)
        up_host = up_host_m.group(1).strip("[]") if up_host_m else "127.0.0.1"
        tls_up = service.lower().startswith("https://")
        site = _make_site(
            "cloudflared", name=hostname, host=hostname, port=443, scheme="https",
            server_names=[hostname], upstream=service, config_path=str(path),
            # ``path`` in an ingress rule is a regex, not a URL path: never
            # append it to the link.
            url=f"https://{hostname}",
            detail="status = local upstream probe",
        )
        # The public edge is not probed (no WAN round trip per refresh); the
        # tunnel's local upstream is what this host controls.
        site["_probe"] = ("127.0.0.1" if _is_local(up_host) else up_host, up_port, tls_up, None)
        if up_port is None:
            site["_probe"] = None
            site["status"] = "warn" if not service.startswith("http_status") else "ok"
            site["detail"] = f"service {service}"
        sites.append(site)
    return sites


def _cloudflared_source() -> list[dict]:
    out, seen = [], set()
    for p in _cloudflared_configs():
        if str(p) in seen:
            continue
        seen.add(str(p))
        out += parse_cloudflared_config(p)
    return out


# ---------------------------------------------------------------- launchd

def _launchd_rows() -> list:
    """Service rows of the shared status snapshot (``groups[].services``)."""
    from hub.status import full_status
    st = full_status()
    groups = st.get("groups") if isinstance(st, dict) else None
    rows = []
    for g in groups if isinstance(groups, list) else []:
        services = g.get("services") if isinstance(g, dict) else None
        if isinstance(services, list):
            rows.extend(services)
    return rows


def _launchd_source() -> list[dict]:
    sites = []
    for row in _launchd_rows():
        if not isinstance(row, dict) or row.get("kind") != "launchd":
            continue
        url = row.get("url") if isinstance(row.get("url"), str) else None
        port = _port(row.get("port"))
        if url and port is None:
            m = re.match(r"^https?://[^/]*:(\d+)", url)
            port = _port(m.group(1)) if m else None
        sig = row.get("signature") if isinstance(row.get("signature"), dict) else {}
        if port is None or not (url or sig.get("http")):
            continue  # no port, or nothing says it is a web UI
        scheme = "https" if (url or "").startswith("https://") else "http"
        sites.append(_make_site(
            "launchd", name=_clean(row.get("name") or row.get("id") or f":{port}"),
            host="localhost", port=port, scheme=scheme,
            upstream=_clean(row.get("id")), url=url or None,
            detail=_clean(row.get("detail") or ""),
        ))
    return sites


# ---------------------------------------------------------------- docker

_DOCKER_PORT = re.compile(r"(?:(\[[^\]]*\]|[\d.]+|::):)?(\d+)->(\d+)/tcp")


def parse_docker_ps(out: str) -> list[dict]:
    sites = []
    for line in (out or "").splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        name, ports, image = parts[0], parts[1], parts[2]
        seen: set[int] = set()
        for m in _DOCKER_PORT.finditer(ports):
            host_port, inner = _port(m.group(2)), m.group(3)
            if host_port is None or host_port in seen:
                continue
            seen.add(host_port)
            bind = (m.group(1) or "").strip("[]")
            sites.append(_make_site(
                "docker", name=f"{name}:{host_port}" if len(seen) > 1 else name,
                host="localhost", port=host_port,
                scheme="https" if inner == "443" else "http",
                upstream=f"{image} → {inner}/tcp",
                probe_host="127.0.0.1" if _is_local(bind) else bind,
                detail=f"container {name}",
                # A published redis/postgres port is not a web site.
                http_only=True,
            ))
    return sites


def _docker_source() -> list[dict]:
    if not os.path.isfile(DOCKER):
        return []
    rc, out, _err = sh(
        [DOCKER, "ps", "--format", "{{.Names}}\t{{.Ports}}\t{{.Image}}"], timeout=5,
    )
    if rc != 0 or not isinstance(out, str):
        return []
    return parse_docker_ps(out)


# ---------------------------------------------------------------- listeners

def _lsof_rows() -> list:
    from hub.adaptive import lsof_listen_snapshot
    rows = lsof_listen_snapshot()
    return rows if isinstance(rows, list) else []


def _listener_candidates() -> list[dict]:
    seen: set[int] = set()
    out = []
    for row in _lsof_rows():
        if not isinstance(row, dict):
            continue
        port = _port(row.get("port"))
        if port is None or port in seen:
            continue
        seen.add(port)
        bind = str(row.get("bind") or "")
        host = bind.rsplit(":", 1)[0] if ":" in bind else ""
        out.append({"port": port, "proc": _clean(row.get("proc") or ""),
                    "probe_host": "127.0.0.1" if _is_local(host) else host.strip("[]")})
    return out


# ---------------------------------------------------------------- probing

def _http_head(host: str, port: int, tls: bool, host_header: str | None,
               timeout: float = _PROBE_TIMEOUT) -> tuple[str, str]:
    """``(status, detail)``: ok = HTTP answered, warn = TCP only, down = refused."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError:
        return "down", "connection refused"
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return "down", "probe failed"
    try:
        sock.settimeout(timeout)
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host_header or None)
        hh = host_header or ("localhost" if _is_local(host) else host)
        sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {hh}\r\nUser-Agent: serverhub-sites\r\n\r\n".encode())
        head = sock.recv(64)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return "warn", "TCP open, no HTTP answer"
    finally:
        try:
            sock.close()
        except OSError:
            pass
    m = re.match(rb"HTTP/\d(?:\.\d)?\s+(\d{3})", head or b"")
    if not m:
        return "warn", "TCP open, no HTTP answer"
    code = int(m.group(1))
    return ("warn" if code >= 500 else "ok"), f"HTTP {code}"


def _probe_site(site: dict) -> None:
    probe = site.get("_probe")
    if not probe or probe[1] is None:
        if site.get("status") == "unknown":
            site["status"] = "warn"
        return
    host, port, tls, host_header = probe
    status, detail = _http_head(host, port, tls, host_header)
    site["status"] = status
    site["detail"] = site["detail"] + (" · " if site["detail"] else "") + detail if detail else site["detail"]


def _speaks_http(cand: dict) -> tuple[str, str] | None:
    status, detail = _http_head(cand["probe_host"], cand["port"], False, None, timeout=0.5)
    if status == "ok":
        return status, detail
    status, detail = _http_head(cand["probe_host"], cand["port"], True, None, timeout=0.5)
    return (status, detail + " (TLS)") if status == "ok" else None


# ---------------------------------------------------------------- merge

def _dedupe_key(site: dict) -> tuple[str, int | None]:
    host = (site.get("host") or "").lower()
    return ("local" if _is_local(host) else host, site.get("port"))


def merge_sites(by_source: dict[str, list[dict]]) -> list[dict]:
    """Dedupe across sources by host:port, in ``_SOURCE_ORDER`` priority."""
    merged: dict[tuple, dict] = {}
    for source in _SOURCE_ORDER:
        for site in by_source.get(source, []) or []:
            key = _dedupe_key(site)
            # Two nginx server blocks on one port with distinct names are two
            # sites; the same name/port seen twice (e.g. listen + listen [::])
            # is one.
            if key in merged:
                first = merged[key]
                if first["source"] != source and source not in first["also_seen_in"]:
                    first["also_seen_in"].append(source)
                continue
            merged[key] = site
    return list(merged.values())


def _run_sources(sources: dict) -> tuple[dict[str, list[dict]], list[dict]]:
    results: dict[str, list[dict]] = {}
    notes = []
    pool = cf.ThreadPoolExecutor(max_workers=len(sources), thread_name_prefix="sites")
    try:
        futs = {name: pool.submit(fn) for name, fn in sources.items()}
        deadline = time.monotonic() + _SOURCE_DEADLINE
        for name, fut in futs.items():
            try:
                rows = fut.result(timeout=max(0.0, deadline - time.monotonic()))
                rows = [r for r in rows if isinstance(r, dict)] if isinstance(rows, list) else []
                results[name] = rows
                notes.append({"id": name, "ok": True, "count": len(rows), "error": None})
            except cf.TimeoutError:
                results[name] = []
                notes.append({"id": name, "ok": False, "count": 0, "error": "timeout"})
            except _CONTROL_FLOW:
                raise
            except BaseException as exc:
                results[name] = []
                notes.append({"id": name, "ok": False, "count": 0,
                              "error": _clean(type(exc).__name__)})
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    return results, notes


def _sources() -> dict:
    return {
        "nginx": _nginx_source,
        "caddy": _caddy_source,
        "apache": _apache_source,
        "cloudflared": _cloudflared_source,
        "launchd": _launchd_source,
        "docker": _docker_source,
        "listener": _listener_candidates,
    }


def _probe_all(sites: list[dict]) -> None:
    if not sites:
        return
    with cf.ThreadPoolExecutor(max_workers=min(16, len(sites)), thread_name_prefix="sites-probe") as pool:
        list(pool.map(_probe_site, sites))


def _collect() -> dict:
    by_source, notes = _run_sources(_sources())
    candidates = by_source.pop("listener", [])
    sites = merge_sites(by_source)
    _probe_all(sites)
    # Stock / stopped trees (Homebrew nginx, /etc/apache2) only count while up.
    sites = [s for s in sites if not (s.get("_optional") and s["status"] == "down")]
    # Container ports that accept TCP but never answer HTTP are databases,
    # caches or brokers, not sites.
    sites = [s for s in sites
             if not (s.get("_http_only") and s["status"] == "warn"
                     and s["detail"].endswith("no HTTP answer"))]

    # Anything listening that no source explained, and that answers HTTP.
    covered = {s.get("port") for s in sites}
    for s in sites:
        p = _upstream_port(s.get("upstream") or "")
        if p:
            covered.add(p)
    fresh = [c for c in candidates if c["port"] not in covered][:_MAX_LISTENER_PROBES]
    listeners = []
    if fresh:
        with cf.ThreadPoolExecutor(max_workers=min(16, len(fresh)), thread_name_prefix="sites-lsof") as pool:
            answers = list(pool.map(_speaks_http, fresh))
        for cand, ans in zip(fresh, answers):
            if ans is None:
                continue
            tls = ans[1].endswith("(TLS)")
            site = _make_site(
                "listener", name=f"{cand['proc'] or 'listener'}:{cand['port']}",
                host="localhost", port=cand["port"], scheme="https" if tls else "http",
                upstream=cand["proc"] or None, probe_host=cand["probe_host"],
            )
            site["status"], site["detail"] = ans
            listeners.append(site)
    for n in notes:
        if n["id"] == "listener":
            n["count"] = len(listeners)
    sites += listeners

    out = []
    for s in sites:
        s.pop("_probe", None)
        s.pop("_optional", None)
        s.pop("_http_only", None)
        out.append(s)
    order = {name: i for i, name in enumerate(_SOURCE_ORDER)}
    out.sort(key=lambda s: (order.get(s["source"], 99), s["name"].lower(), s.get("port") or 0))
    return {"sites": out, "sources": notes, "count": len(out), "generated_at": time.time()}


@ttl_memo(_TTL)
def _cached() -> dict:
    return _collect()


def list_sites(force: bool = False) -> dict:
    if force:
        _cached.invalidate()
    try:
        return _cached()
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return {"sites": [], "sources": [], "count": 0, "generated_at": time.time(),
                "error": "discovery failed"}


def site_config(site_id: str) -> dict:
    """Config text of a discovered site.  Only paths discovery reported are
    readable, so this never becomes an arbitrary file read."""
    sid = str(site_id or "")
    for s in list_sites().get("sites", []):
        if s.get("id") == sid and s.get("config_path") and "view_config" in s.get("actions", []):
            text = _read(Path(s["config_path"]))
            if text is None:
                raise api_error("sites.config_unreadable")
            return {"id": sid, "path": s["config_path"], "content": _clean(text)}
    raise api_error("sites.not_found")
