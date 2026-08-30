"""Intelligent Services-page grouping without per-container override spam.

Top-level ``group_rules:`` in services.yaml.  When the key is absent, code
seeds apply (they are never auto-written to live yaml).  When the key is
present, that list is the full ruleset — ``[]`` disables the seeds.

Matchers on one rule are OR.  First matching rule wins.  Explicit
``overrides.<id>.group`` and yaml ``apps[].group`` / ``scripts[].group``
always beat rules.  Callers re-read via :func:`hub.config.cfg` so a process
does not keep a stale snapshot of the list.
"""
from __future__ import annotations

import re
from typing import Any

from hub.config import cfg, mutate
from hub.errors import api_error

_CONTROL_FLOW = (KeyboardInterrupt, SystemExit)
_ADDR_REPR_RE = re.compile(r" at 0x[0-9a-fA-F]+>")


def _isinst(value, types) -> bool:
    """``isinstance`` that a leftover ``__class__`` bomb cannot 500 through.

    CPython's ``isinstance`` reads the operand's ``__class__`` whenever the
    real-type fast check misses, so a leftover whose ``__class__`` is a
    raising property blew unguarded gates in :func:`_str_list`,
    :func:`_port_list`, :func:`parse_rule`, :func:`configured_group_rules`
    and the match walk — GET /api/group-rules and Services grouping answered
    HTTP 500 instead of dropping the junk cell.  Fail-closed.  A lying
    ``__class__`` still reports its claim; bool ids stay ``type(x) is bool``.
    """
    try:
        return isinstance(value, types)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return False

_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
_SLUG_STRIP = re.compile(r"[^a-z0-9]+")
_RE_HINT = re.compile(r"[|.*+?\[\](){}]")

# Known yaml inventory group ids → slug when the operator omits `id`.
_GROUP_SLUGS = {
    "定时任务": "scheduled-tasks",  # cjk-input: yaml inventory group id matching live services.yaml
    "智能家居": "smart-home",  # cjk-input: yaml inventory group id matching live services.yaml
    "Gravity 量化": "gravity",  # cjk-input: yaml inventory group id matching live services.yaml
    "网关": "gateway",  # cjk-input: yaml inventory group id matching live services.yaml
    "容器 · teslamate": "teslamate",  # cjk-input: yaml inventory group id matching live services.yaml
}

# Built-in seeds.  Order is match order.  Interval jobs are first so a
# calendar Gravity rotate is 定时任务, not Gravity 量化.
SEED_RULES: tuple[dict[str, Any], ...] = (
    {
        "id": "scheduled-tasks",
        "group": "定时任务",  # cjk-input: yaml inventory group id matching live services.yaml
        "launchd_interval": True,
    },
    {
        "id": "smart-home",
        "group": "智能家居",  # cjk-input: yaml inventory group id matching live services.yaml
        "compose_project": ["xiaomihub", "music-assistant"],
        "image": [
            "xiaomihub", "miot", "homeassistant", "home-assistant",
            "esphome", "music-assistant",
        ],
        "launchd_prefix": ["com.homeassistant", "local.esphome"],
        "auto_port_owner": [
            "xiaomihub", "miot", "homeassistant", "home-assistant",
            "esphome", "music-assistant",
        ],
    },
    {
        "id": "gravity",
        "group": "Gravity 量化",  # cjk-input: yaml inventory group id matching live services.yaml
        "launchd_prefix": ["com.gravity."],
        "id_prefix": ["gravity"],
    },
    {
        "id": "gateway",
        "group": "网关",  # cjk-input: yaml inventory group id matching live services.yaml
        "launchd_prefix": [
            "local.system-nginx",
            "local.cloudflared",
            "com.elvin.wstunnel",
            "com.user.remote-desktop",
        ],
    },
    {
        "id": "teslamate",
        "group": "容器 · teslamate",  # cjk-input: yaml inventory group id matching live services.yaml
        "compose_project": ["teslamate"],
    },
)


def _utf8_text(value) -> str:
    """Drop leftover ``\\ud800`` / RecursionError so matching cannot 500."""
    if value is None:
        return ""
    for base in (bytes, bytearray):
        try:
            return base.decode(value, "utf-8", "replace")
        except _CONTROL_FLOW:
            raise
        except BaseException:
            continue
    try:
        return str.encode(str.__str__(value), "utf-8", "replace").decode("utf-8")
    except _CONTROL_FLOW:
        raise
    except BaseException:
        pass
    try:
        cls = type(value)
        if cls.__str__ is object.__str__ and cls.__repr__ is object.__repr__:
            return ""
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return ""
    try:
        text = str(value)
    except RecursionError:
        try:
            return type(value).__name__
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return ""
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return ""
    try:
        text = str.encode(text, "utf-8", "replace").decode("utf-8")
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return ""
    return "" if _ADDR_REPR_RE.search(text) else text


def _as_int(value) -> int | None:
    if type(value) is bool or value is None:
        return None
    text = None
    for base in (bytes, bytearray):
        try:
            text = base.decode(value, "utf-8", "replace")
            break
        except _CONTROL_FLOW:
            raise
        except BaseException:
            continue
    try:
        n = int(text) if text is not None else int(value)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return None
    if 1 <= n <= 65535:
        return n
    return None


def _str_list(raw) -> tuple[str, ...]:
    if raw is None or type(raw) is bool:
        return ()
    if _isinst(raw, (bytes, bytearray, str)):
        text = _utf8_text(raw).strip()
        return (text,) if text else ()
    if not _isinst(raw, (list, tuple, set, frozenset)):
        return ()
    out: list[str] = []
    try:
        items = list(raw)
    except RecursionError:
        return ()
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return ()
    for item in items:
        if type(item) is bool or item is None:
            continue
        if _isinst(item, (int, float)) and type(item) is not bool:
            # YAML leftover ``.inf`` / a bare port in a string field.
            continue
        text = _utf8_text(item).strip()
        if text and text not in out:
            out.append(text)
    return tuple(out)


def _port_list(raw) -> tuple[int, ...]:
    if raw is None or type(raw) is bool:
        return ()
    if _isinst(raw, (int, float)) and type(raw) is not bool:
        n = _as_int(raw)
        return (n,) if n is not None else ()
    if _isinst(raw, str):
        n = _as_int(raw.strip())
        return (n,) if n is not None else ()
    if not _isinst(raw, (list, tuple, set, frozenset)):
        return ()
    out: list[int] = []
    try:
        items = list(raw)
    except RecursionError:
        return ()
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return ()
    for item in items:
        n = _as_int(item)
        if n is not None and n not in out:
            out.append(n)
    return tuple(out)


def _slugify(text: str, taken: set[str]) -> str:
    mapped = _GROUP_SLUGS.get(text)
    if mapped:
        return mapped
    compact = _SLUG_STRIP.sub("-", _utf8_text(text).strip().lower()).strip("-")[:63]
    slug = compact if _SLUG_RE.match(compact) else "rule"
    if slug not in taken:
        return slug
    n = 2
    while True:
        suffix = f"-{n}"
        cand = (slug[: 63 - len(suffix)] + suffix) if len(slug) + len(suffix) > 63 else slug + suffix
        if cand not in taken and _SLUG_RE.match(cand):
            return cand
        n += 1
        if n > 9999:
            return slug


def _valid_slug(value) -> str:
    text = _utf8_text(value).strip().lower()
    return text if _SLUG_RE.match(text) else ""


def parse_rule(raw, *, taken: set[str] | None = None) -> dict | None:
    """Normalise one rule for matching, or None if it cannot be used."""
    if not _isinst(raw, dict):
        return None
    group = _utf8_text(raw.get("group")).strip()
    if not group:
        return None
    used = taken if taken is not None else set()
    slug = _valid_slug(raw.get("id"))
    if not slug:
        slug = _slugify(group, used)
    compose = _str_list(raw.get("compose_project"))
    image = _str_list(raw.get("image"))
    service_id = _str_list(raw.get("service_id"))
    id_prefix = _str_list(raw.get("id_prefix"))
    launchd = _str_list(raw.get("launchd"))
    launchd_prefix = _str_list(raw.get("launchd_prefix"))
    launchd_re = _str_list(raw.get("launchd_re"))
    compiled: list[re.Pattern] = []
    for pat in launchd_re:
        try:
            compiled.append(re.compile(pat, re.I))
        except (re.error, RecursionError, TypeError, ValueError):
            continue
    interval = raw.get("launchd_interval")
    interval_match = interval is True
    owners = _str_list(raw.get("auto_port_owner"))
    ports = _port_list(raw.get("ports"))
    has_matcher = bool(
        compose or image or service_id or id_prefix or launchd
        or launchd_prefix or compiled or interval_match or owners or ports
    )
    return {
        "id": slug,
        "group": group,
        "compose_project": compose,
        "image": image,
        "service_id": service_id,
        "id_prefix": id_prefix,
        "launchd": launchd,
        "launchd_prefix": launchd_prefix,
        "launchd_re": tuple(p.pattern for p in compiled),
        "_launchd_re": tuple(compiled),
        "launchd_interval": interval_match,
        "auto_port_owner": owners,
        "ports": ports,
        "has_matcher": has_matcher,
    }


def yaml_rule(rule: dict) -> dict:
    """Operator-facing / yaml form: no compiled matchers, no empty fields."""
    row: dict[str, Any] = {
        "id": rule.get("id") or "rule",
        "group": rule.get("group") or "",
    }
    for key in (
        "compose_project", "image", "service_id", "id_prefix",
        "launchd", "launchd_prefix", "launchd_re", "auto_port_owner", "ports",
    ):
        val = rule.get(key)
        if not val:
            continue
        if _isinst(val, tuple):
            row[key] = list(val) if len(val) > 1 else val[0]
        else:
            row[key] = val
    if rule.get("launchd_interval") is True:
        row["launchd_interval"] = True
    return row


def _parse_many(raw_list) -> list[dict]:
    out: list[dict] = []
    seen: set[str] = set()
    if not _isinst(raw_list, (list, tuple)):
        return out
    try:
        items = list(raw_list)
    except RecursionError:
        return []
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return []
    for item in items:
        parsed = parse_rule(item, taken=seen)
        if not parsed:
            continue
        if parsed["id"] in seen:
            parsed = dict(parsed)
            parsed["id"] = _slugify(parsed["group"], seen)
        seen.add(parsed["id"])
        out.append(parsed)
    return out


def rules_from_config(data=None) -> tuple[list[dict], str]:
    """Return ``(parsed rules, source)``. ``source`` is ``yaml`` or ``seed``.

    Re-reads *data* (or :func:`cfg`) every call — no process-lifetime cache.
    """
    if data is None:
        try:
            data = cfg()
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return _parse_many(SEED_RULES), "seed"
    if not _isinst(data, dict):
        return _parse_many(SEED_RULES), "seed"
    if "group_rules" not in data:
        return _parse_many(SEED_RULES), "seed"
    raw = data.get("group_rules")
    if not _isinst(raw, list):
        return [], "yaml"
    return _parse_many(raw), "yaml"


def configured_group_rules() -> list[dict]:
    """Effective rules for matching. Always goes through :func:`cfg`."""
    rules, _source = rules_from_config()
    return rules


def _service_id(service: dict) -> str:
    return _utf8_text(service.get("id")).strip()


def _service_ports(service: dict) -> set[int]:
    found: set[int] = set()
    n = _as_int(service.get("port"))
    if n is not None:
        found.add(n)
    for n in _port_list(service.get("ports")):
        found.add(n)
    meta = service.get("meta")
    if _isinst(meta, dict):
        n = _as_int(meta.get("port"))
        if n is not None:
            found.add(n)
        for n in _port_list(meta.get("ports")):
            found.add(n)
    return found


def _process_name(service: dict) -> str:
    meta = service.get("meta") if _isinst(service.get("meta"), dict) else {}
    for key in ("process", "proc", "owner"):
        text = _utf8_text(service.get(key) or meta.get(key)).strip()
        if text:
            return text
    return ""


def _text_hit(haystack: str, needles: tuple[str, ...]) -> bool:
    if not haystack or not needles:
        return False
    low = haystack.lower()
    for needle in needles:
        if not needle:
            continue
        if needle.lower() in low:
            return True
        if _RE_HINT.search(needle):
            try:
                if re.search(needle, haystack, re.I):
                    return True
            except (re.error, RecursionError, TypeError, ValueError):
                continue
    return False


def _exact_ci(haystack: str, needles: tuple[str, ...]) -> bool:
    if not haystack or not needles:
        return False
    low = haystack.lower()
    return any(n.lower() == low for n in needles if n)


def _prefix_ci(haystack: str, needles: tuple[str, ...]) -> bool:
    if not haystack or not needles:
        return False
    low = haystack.lower()
    return any(low.startswith(n.lower()) for n in needles if n)


def _rule_matches(rule: dict, service: dict, *, launchd_interval: bool) -> bool:
    if not rule.get("has_matcher"):
        return False
    sid = _service_id(service)
    project = _utf8_text(service.get("compose_project")).strip()
    image = _utf8_text(service.get("image")).strip()
    label = _utf8_text(service.get("launchd") or sid).strip()
    proc = _process_name(service)
    ports = _service_ports(service)
    if rule.get("launchd_interval") and launchd_interval:
        return True
    if _exact_ci(project, rule.get("compose_project") or ()):
        return True
    if _text_hit(image, rule.get("image") or ()):
        return True
    if _exact_ci(sid, rule.get("service_id") or ()):
        return True
    if _prefix_ci(sid, rule.get("id_prefix") or ()):
        return True
    if _exact_ci(label, rule.get("launchd") or ()) or _exact_ci(sid, rule.get("launchd") or ()):
        return True
    prefixes = rule.get("launchd_prefix") or ()
    if _prefix_ci(label, prefixes) or _prefix_ci(sid, prefixes):
        return True
    for compiled in rule.get("_launchd_re") or ():
        try:
            if (label and compiled.search(label)) or (sid and compiled.search(sid)):
                return True
        except (RecursionError, TypeError, ValueError):
            continue
    if _text_hit(proc, rule.get("auto_port_owner") or ()):
        return True
    want = rule.get("ports") or ()
    if want and ports.intersection(want):
        return True
    return False


def explicit_group(value) -> str | None:
    """Non-empty group override, or None (so rules may apply)."""
    if value is None or type(value) is bool:
        return None
    if _isinst(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            return None
        text = _utf8_text(value).strip()
        return text or None
    if _isinst(value, int):
        # Leftover ``.inf`` / a port used as a group — still an explicit value
        # the caller already decided to keep; stringify only if it is usable.
        text = _utf8_text(value).strip()
        return text or None
    if _isinst(value, (bytes, bytearray, str)):
        text = _utf8_text(value).strip()
        return text or None
    text = _utf8_text(value).strip()
    return text or None


def match_group(
    service: dict | None,
    *,
    explicit: Any = None,
    launchd_interval: bool = False,
    rules=None,
) -> str | None:
    """First matching rule's group, or None.

    Returns None when *explicit* is a non-empty group (caller should keep it)
    or when no rule matches.  *rules* defaults to :func:`configured_group_rules`.
    """
    if explicit_group(explicit):
        return None
    if not _isinst(service, dict):
        return None
    try:
        interval = bool(launchd_interval) or bool(service.get("launchd_interval"))
    except RecursionError:
        interval = bool(launchd_interval)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        interval = bool(launchd_interval)
    try:
        rows = list(rules) if rules is not None else configured_group_rules()
    except _CONTROL_FLOW:
        raise
    except BaseException:
        rows = []
    for rule in rows:
        if _isinst(rule, dict) and rule.get("has_matcher") is not None and "_launchd_re" in rule:
            parsed = rule
        else:
            parsed = parse_rule(rule if _isinst(rule, dict) else {})
        if not parsed:
            continue
        try:
            if _rule_matches(parsed, service, launchd_interval=interval):
                group = _utf8_text(parsed.get("group")).strip()
                if group:
                    return group
        except RecursionError:
            continue
        except _CONTROL_FLOW:
            raise
        except BaseException:
            continue
    return None


def resolve_group(
    service: dict | None,
    *,
    explicit: Any = None,
    fallback: Any = "",
    launchd_interval: bool = False,
    rules=None,
) -> str:
    """``explicit`` → first matching rule → *fallback*."""
    exp = explicit_group(explicit)
    if exp:
        return exp
    hit = match_group(
        service if _isinst(service, dict) else {},
        launchd_interval=launchd_interval,
        rules=rules,
    )
    if hit:
        return hit
    fb = _utf8_text(fallback).strip() if fallback is not None else ""
    return fb


def resolve_yaml_entry_group(entry, *, fallback: str, rules=None) -> Any:
    """Yaml ``apps[]`` / ``scripts[]``: a non-blank ``group`` always wins."""
    if not _isinst(entry, dict):
        return fallback
    raw = entry.get("group")
    if _isinst(raw, str) and not raw.strip():
        raw = None
    if raw is not None:
        # Leftover ``group: .inf`` / a bare int must not leak into JSON.
        exp = explicit_group(raw)
        return exp if exp is not None else fallback
    ports = entry.get("ports")
    return resolve_group(
        {
            "id": entry.get("id"),
            "port": entry.get("port"),
            "ports": ports,
            "image": entry.get("image"),
            "compose_project": entry.get("compose_project"),
            "meta": {"process": entry.get("process")},
        },
        fallback=fallback,
        rules=rules,
    )


def list_rules(data=None) -> dict:
    """Effective list plus whether it came from yaml or code seeds."""
    rules, source = rules_from_config(data)
    return {
        "rules": [yaml_rule(r) for r in rules],
        "source": source,
    }


def _parse_for_save(raw, taken: set[str]) -> dict:
    if not _isinst(raw, dict):
        raise api_error("services.group_rule_invalid")
    group = _utf8_text(raw.get("group")).strip()
    if not group:
        raise api_error("services.group_rule_invalid")
    given = _utf8_text(raw.get("id")).strip().lower()
    if given and not _SLUG_RE.match(given):
        raise api_error("services.group_rule_invalid")
    parsed = parse_rule(raw, taken=taken)
    if not parsed:
        raise api_error("services.group_rule_invalid")
    if not parsed.get("has_matcher"):
        # A group with no matchers would sit in yaml forever and never fire.
        raise api_error("services.group_rule_invalid")
    if given:
        parsed = dict(parsed)
        parsed["id"] = given
    return parsed


def _write_rows(data: dict, rows: list[dict]) -> None:
    data["group_rules"] = [yaml_rule(r) for r in rows]


def save_rules(payload: dict | None) -> dict:
    """Upsert one rule, or replace the whole list when ``rules`` is present."""
    if not _isinst(payload, dict):
        raise api_error("services.group_rule_invalid")
    stored: dict = {}

    def apply(data: dict) -> None:
        if "rules" in payload:
            raw_rules = payload.get("rules")
            if not _isinst(raw_rules, list):
                raise api_error("services.group_rule_invalid")
            taken: set[str] = set()
            parsed: list[dict] = []
            for item in raw_rules:
                rule = _parse_for_save(item, taken)
                if rule["id"] in taken:
                    rule = dict(rule)
                    rule["id"] = _slugify(rule["group"], taken)
                taken.add(rule["id"])
                parsed.append(rule)
            _write_rows(data, parsed)
            stored.update(list_rules(data))
            return
        current, _source = rules_from_config(data)
        incoming = _parse_for_save(payload, {r["id"] for r in current})
        replaced = False
        next_rows: list[dict] = []
        for row in current:
            if row.get("id") == incoming["id"]:
                next_rows.append(incoming)
                replaced = True
            else:
                next_rows.append(row)
        if not replaced:
            next_rows.append(incoming)
        _write_rows(data, next_rows)
        stored.update({"ok": True, "rule": yaml_rule(incoming), **list_rules(data)})

    mutate(apply)
    if "ok" not in stored:
        stored["ok"] = True
    return stored


def delete_rule(rule_id: str) -> dict:
    slug = _valid_slug(rule_id)
    if not slug:
        raise api_error("services.group_rule_invalid")
    removed: dict = {}

    def apply(data: dict) -> None:
        current, _source = rules_from_config(data)
        keep: list[dict] = []
        for row in current:
            if row.get("id") == slug and not removed:
                removed.update(yaml_rule(row))
                continue
            keep.append(row)
        if not removed:
            return
        _write_rows(data, keep)

    mutate(apply)
    if not removed:
        raise api_error("services.group_rule_not_found", id=slug)
    return {"ok": True, "id": slug, "removed": removed}
