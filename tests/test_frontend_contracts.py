"""Static checks on the SPA that the Vite build cannot catch.

Vite resolves a missing *named* export to ``undefined`` instead of failing the
build, so ``import { getSystemSensors } from '../api/client'`` compiles happily
and then throws "is not a function" the first time that code path runs.  A page
can therefore ship broken while ``npm run build`` reports success.

These tests close that gap plus two neighbouring contracts:
  * every ``t('key')`` used in the SPA exists in the locale dictionaries, and
  * views go through ``api/client`` rather than a bare ``fetch()`` that skips
    the ``r.ok`` check and the session-lost event.
"""
from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
WEB_SRC = BASE / "web" / "src"
CLIENT = WEB_SRC / "api" / "client.js"
I18N = WEB_SRC / "i18n"

#: Views still calling fetch('/api/...') directly, bypassing the r.ok check,
#: the localized error mapping and the session-lost event in api/client.js.
#: Shares tests/i18n_baseline.json with the CJK ratchet: a data change, so
#: extraction work never has to edit this file.  May only shrink.
BASELINE_PATH = Path(__file__).resolve().parent / "i18n_baseline.json"
FALLBACK_RAW_FETCH = 103


def _raw_fetch_budget() -> int:
    try:
        return int(json.loads(BASELINE_PATH.read_text())["raw_fetch"])
    except (OSError, ValueError, KeyError, TypeError):
        return FALLBACK_RAW_FETCH


def _client_exports() -> set[str]:
    text = CLIENT.read_text(errors="replace")
    names = set(
        re.findall(r"export\s+(?:const|function|async\s+function)\s+([A-Za-z_$][\w$]*)", text)
    )
    for block in re.findall(r"export\s*\{([^}]*)\}", text):
        for part in block.split(","):
            part = part.strip()
            if part:
                names.add(part.split(" as ")[-1].strip())
    return names


def _client_imports() -> list[tuple[Path, str]]:
    """(file, imported_name) for every named import from api/client."""
    out: list[tuple[Path, str]] = []
    pattern = re.compile(
        r"import\s*\{([^}]*)\}\s*from\s*['\"][^'\"]*api/client[^'\"]*['\"]", re.S
    )
    for path in sorted(WEB_SRC.rglob("*.vue")):
        for m in pattern.finditer(path.read_text(errors="replace")):
            for name in m.group(1).split(","):
                name = name.strip().split(" as ")[0].strip()
                if name:
                    out.append((path, name))
    return out


def _locale_key_paths(name: str) -> list[str]:
    """Flatten `key: 'value'` nesting in a locale module into dotted paths.

    Returns a *list*, not a set: duplicate key paths must stay visible so the
    no-duplicates ratchet below can see them (in JS the last duplicate silently
    wins, which once hid ``err.admin.password_required`` behind an older block).
    """
    text = (I18N / f"{name}.js").read_text(errors="replace")
    body = text[text.index("{"):]
    keys: list[str] = []
    stack: list[str] = []
    # Good enough for these dictionaries: they are plain nested object literals.
    for raw in body.splitlines():
        line = re.sub(r"//.*$", "", raw).strip()
        if not line:
            continue
        m = re.match(r"^([A-Za-z_$][\w$-]*|'[^']+'|\"[^\"]+\")\s*:\s*\{", line)
        if m:
            stack.append(m.group(1).strip("'\""))
            continue
        m = re.match(r"^([A-Za-z_$][\w$-]*|'[^']+'|\"[^\"]+\")\s*:\s*(.+)$", line)
        if m:
            keys.append(".".join(stack + [m.group(1).strip("'\"")]))
            continue
        if line.startswith("}"):
            if stack:
                stack.pop()
    return keys


def _locale_keys(name: str) -> set[str]:
    """Flatten `key: 'value'` nesting in a locale module into dotted paths."""
    return set(_locale_key_paths(name))


class TestClientImportContract(unittest.TestCase):
    def test_every_imported_api_helper_exists(self):
        exported = _client_exports()
        self.assertGreater(len(exported), 20, "client.js export scan looks wrong")
        missing = sorted(
            f"{p.relative_to(BASE)}: {n}"
            for p, n in _client_imports()
            if n not in exported
        )
        self.assertEqual(
            missing,
            [],
            "\nThese views import names api/client.js does not export.  Vite "
            "silently binds them to undefined, so the page throws at runtime:\n  "
            + "\n  ".join(missing),
        )


def raw_fetch_offenders() -> list[str]:
    """"file:line" for every bare fetch('/api/...') in the SPA.

    Public because tests/test_no_hardcoded_cjk.py --update-baseline writes this
    count into the shared baseline file.
    """
    offenders: list[str] = []
    for path in sorted(WEB_SRC.rglob("*.vue")):
        for n, raw in enumerate(path.read_text(errors="replace").splitlines(), 1):
            line = re.sub(r"//.*$", "", raw)
            # EventSource/SSE and fetch() on absolute URLs are out of scope.
            if re.search(r"(?<![.\w])fetch\(\s*['\"`]/api/", line):
                offenders.append(f"{path.relative_to(BASE)}:{n}")
    return offenders


class TestNoRawFetchInViews(unittest.TestCase):
    def test_views_use_the_api_client(self):
        offenders = raw_fetch_offenders()
        budget = _raw_fetch_budget()
        self.assertLessEqual(
            len(offenders),
            budget,
            f"\n{len(offenders)} raw fetch('/api/...') calls in views (budget "
            f"{budget}).  Add a wrapper in api/client.js so the call "
            "gets the r.ok check, localized errors and 401 handling:\n  "
            + "\n  ".join(offenders[:20]),
        )


class TestVmConsoleFrontendContract(unittest.TestCase):
    def test_novnc_is_exactly_pinned(self):
        package = json.loads((BASE / "web" / "package.json").read_text())
        lock = json.loads((BASE / "web" / "package-lock.json").read_text())
        self.assertEqual(package["dependencies"].get("@novnc/novnc"), "1.7.0")
        self.assertEqual(
            lock["packages"]["node_modules/@novnc/novnc"]["version"], "1.7.0"
        )

    def test_console_is_lazy_and_single_session(self):
        component = (WEB_SRC / "components" / "VncConsole.vue").read_text()
        client = CLIENT.read_text()
        self.assertIn("await import('@novnc/novnc')", component)
        self.assertNotRegex(component, r"^import\s+.*@novnc/novnc", re.M)
        self.assertIn("createVmConsoleSession(props.vm.console_id)", component)
        self.assertIn("encodeURIComponent(consoleId)", client)
        self.assertIn("/console/session", client)

    def test_console_is_capability_gated_and_orb_keeps_shell(self):
        view = (WEB_SRC / "views" / "VMs.vue").read_text()
        self.assertIn("v.console?.available === true", view)
        self.assertIn("v.console_id", view)
        self.assertIn("v.backend !== 'orb'", view)
        self.assertIn("a !== 'shell' || v.backend === 'orb'", view)
        self.assertIn("vms.console_unavailable_orbstack", view)
        self.assertNotRegex(view, r"(?<![.\w])fetch\(")

    def test_console_uses_same_origin_and_disconnects(self):
        component = (WEB_SRC / "components" / "VncConsole.vue").read_text()
        self.assertIn("window.location.host", component)
        self.assertIn("window.location.protocol === 'https:' ? 'wss:' : 'ws:'", component)
        self.assertIn("client.disconnect()", component)
        self.assertIn("onBeforeUnmount", component)
        self.assertNotIn("navigator.clipboard", component)
        self.assertNotIn("reconnect", component.lower().replace("automatic reconnect", ""))


class TestClipboardHelperContract(unittest.TestCase):
    def test_views_do_not_call_navigator_clipboard_directly(self):
        """Copy on a plain-http LAN must go through lib/clipboard.js.

        ``navigator.clipboard`` is undefined off https, so a direct
        ``navigator.clipboard.writeText(...)`` throws on the property access
        before any catch attached to the promise can run.
        """
        offenders: list[str] = []
        allowed = {WEB_SRC / "lib" / "clipboard.js"}
        for path in sorted(WEB_SRC.rglob("*")):
            if path.suffix not in {".vue", ".js"} or path in allowed:
                continue
            if ".test.js" in path.name:
                continue
            for n, raw in enumerate(path.read_text(errors="replace").splitlines(), 1):
                line = re.sub(r"//.*$", "", raw)
                if "navigator.clipboard" in line:
                    offenders.append(f"{path.relative_to(BASE)}:{n}")
        self.assertEqual(
            offenders,
            [],
            "use copyToClipboard() from lib/clipboard.js instead of "
            "navigator.clipboard:\n  " + "\n  ".join(offenders),
        )


class TestI18nKeysResolve(unittest.TestCase):
    def test_every_referenced_key_exists_in_every_locale(self):
        referenced: set[str] = set()
        pattern = re.compile(r"\bt\(\s*['\"]([\w.$-]+)['\"]")
        for path in list(WEB_SRC.rglob("*.vue")) + list(WEB_SRC.rglob("*.js")):
            if I18N in path.parents:
                continue
            referenced |= set(pattern.findall(path.read_text(errors="replace")))
        self.assertGreater(len(referenced), 100, "t() key scan looks wrong")

        for locale in ("en", "zh-CN", "ja"):
            defined = _locale_keys(locale)
            missing = sorted(referenced - defined)
            self.assertEqual(
                missing[:20],
                [],
                f"\n{len(missing)} t() keys missing from {locale}.js — they "
                f"render as the raw key string:\n  " + "\n  ".join(missing[:20]),
            )

    def test_locales_have_identical_key_sets(self):
        en = _locale_keys("en")
        for other in ("zh-CN", "ja"):
            keys = _locale_keys(other)
            self.assertEqual(
                sorted(en - keys)[:15], [], f"keys in en.js missing from {other}.js"
            )
            self.assertEqual(
                sorted(keys - en)[:15], [], f"keys in {other}.js missing from en.js"
            )

    def test_locale_files_have_no_duplicate_key_paths(self):
        # Duplicated keys are legal JS, and `t()`-key tests keep passing because
        # the key still exists somewhere — but at runtime the *last* duplicate
        # silently wins.  That once replaced err.admin (with its password_* keys
        # that drive the in-browser admin password dialog) with an older copy
        # that lacked them, so privileged actions failed without ever prompting.
        for locale in ("en", "zh-CN", "ja"):
            paths = _locale_key_paths(locale)
            dupes = sorted({path for path in paths if paths.count(path) > 1})
            self.assertEqual(
                dupes[:15],
                [],
                f"duplicate key paths in {locale}.js — the last one silently "
                "overwrites the earlier:\n  " + "\n  ".join(dupes[:15]),
            )


class ServiceWorkerCacheTests(unittest.TestCase):
    def test_runtime_fetches_do_not_cache_failed_responses(self):
        text = (BASE / "web" / "public" / "sw.js").read_text()
        self.assertIn("function cacheIfOk(", text)
        self.assertIn("if (!response || !response.ok) return", text)
        self.assertIn("cacheIfOk(request, response)", text)
        self.assertNotRegex(
            text,
            r"fetch\(request\)\.then\(\(response\) => \{\s*const clone = response\.clone\(\)",
            "hashed /assets/ fetches must not cacheIfOk-bypass a 404 into Cache Storage",
        )
        self.assertIn("cached && cached.ok", text)
        self.assertIn("shell && shell.ok", text)
        self.assertNotIn(
            "return (await caches.match(request)) || (await caches.match('/'))",
            text,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
