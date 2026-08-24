"""Guard against re-introducing untranslated Chinese in user-facing strings.

The panel ships zh-CN / en / ja.  Two habits break that promise:

1. A ``.vue`` file writes Chinese straight into the template or a toast instead
   of calling ``t()``.  Switching the UI to English then leaves that string in
   Chinese, so a single page renders two languages at once.
2. A Python handler raises ``HTTPException(400, "中文")``.  The SPA cannot
   translate that, so it surfaces verbatim.  Handlers must raise
   ``api_error("some.code")`` instead (see ``hub/errors.py``).

Both checks are budget-based: the counts below are a ratchet.  They may only go
down.  Lower the number when you extract more strings; never raise it.
"""
from __future__ import annotations

import json
import re
import sys
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
WEB_SRC = BASE / "web" / "src"
HUB = BASE / "hub"

CJK = re.compile(r"[一-鿿]")

# ── ratchet ──────────────────────────────────────────────────────────────────
# Remaining hardcoded-CJK lines, per area.  Both must trend to 0.
#
# The budget lives in a checked-in JSON file rather than in this source so that
# extraction work and this guard do not conflict: lowering the count is a data
# change, not a code change.  Regenerate after extracting strings with
#
#     python -m tests.test_no_hardcoded_cjk --update-baseline
#
# which only ever writes numbers that are <= the current baseline.
BASELINE_PATH = Path(__file__).resolve().parent / "i18n_baseline.json"

#: Used when the baseline file is missing (fresh checkout / first run).
#: These are *measured* by the counters below, not hand-written — a hand-picked
#: number silently disagrees with the counter and makes --update-baseline
#: unable to seed itself.
FALLBACK_BASELINE = {"vue": 354, "py": 535, "raw_fetch": 103}


def _baseline() -> dict[str, int]:
    try:
        data = json.loads(BASELINE_PATH.read_text())
    except (OSError, ValueError):
        return dict(FALLBACK_BASELINE)
    return {k: int(data.get(k, v)) for k, v in FALLBACK_BASELINE.items()}


def _strip_comments_js(line: str) -> str:
    """Drop // and /* */ comment bodies so translator notes are not flagged."""
    line = re.sub(r"/\*.*?\*/", "", line)
    return re.sub(r"//.*$", "", line)


def _strip_comments_py(line: str) -> str:
    return re.sub(r"#.*$", "", line)


#: Opt-out marker for CJK that is *matched against* external input rather than
#: shown to anybody: keys in a JSON report written by the operator's own
#: scripts, filenames on their disk, and the Chinese strings that macOS itself
#: puts in ``networksetup`` / ``brew`` output when the server runs a zh locale.
#: Translating those would break the match.  A reason is mandatory so the marker
#: cannot become a silent "shut up" that hides real untranslated prose.
#:
#: Spelled the same either side of the wire — ``# cjk-input: why`` in Python,
#: ``// cjk-input: why`` in a ``.vue`` — because the two sides classify the same
#: localized ``networksetup`` output and must not drift apart.
CJK_INPUT_MARKER = re.compile(r"(?:#|//)\s*cjk-input:\s*\S")


def _vue_cjk_lines() -> list[str]:
    """CJK lines in .vue sources, excluding the i18n dictionaries themselves."""
    hits: list[str] = []
    for path in sorted(WEB_SRC.rglob("*.vue")):
        for n, raw in enumerate(path.read_text(errors="replace").splitlines(), 1):
            if CJK_INPUT_MARKER.search(raw):
                continue
            if CJK.search(_strip_comments_js(raw)):
                hits.append(f"{path.relative_to(BASE)}:{n}")
    return hits


def _py_user_facing_cjk_lines() -> list[str]:
    """CJK lines in hub/ that plausibly reach the user.

    Comments and docstrings are legitimate (the team reads Chinese); strings
    handed to the client are not.  Lines carrying a ``# cjk-input:`` marker are
    matching external input, not producing output, so they are exempt.
    """
    hits: list[str] = []
    for path in sorted(HUB.rglob("*.py")):
        in_doc = False
        for n, raw in enumerate(path.read_text(errors="replace").splitlines(), 1):
            if CJK_INPUT_MARKER.search(raw):
                continue
            stripped = raw.strip()
            # crude but adequate docstring tracking for a lint budget
            fences = stripped.count('"""') + stripped.count("'''")
            if in_doc:
                if fences:
                    in_doc = False
                continue
            if fences == 1:
                in_doc = True
                continue
            if fences >= 2:
                continue
            if CJK.search(_strip_comments_py(raw)):
                hits.append(f"{path.relative_to(BASE)}:{n}")
    return hits


class TestHardcodedCjkRatchet(unittest.TestCase):
    def test_vue_hardcoded_cjk_does_not_grow(self):
        budget = _baseline()["vue"]
        hits = _vue_cjk_lines()
        self.assertLessEqual(
            len(hits),
            budget,
            f"\nHardcoded Chinese in .vue files grew to {len(hits)} lines "
            f"(budget {budget}).\nUse t('some.key') and add the key to "
            f"web/src/i18n/{{en,zh-CN,ja}}.js.\nIf the string is matched "
            "against external input rather than rendered, mark the line "
            "'// cjk-input: <why>'.\nNew/uncounted lines include:\n  "
            + "\n  ".join(hits[:20]),
        )

    def test_python_user_facing_cjk_does_not_grow(self):
        budget = _baseline()["py"]
        hits = _py_user_facing_cjk_lines()
        self.assertLessEqual(
            len(hits),
            budget,
            f"\nChinese in hub/ code grew to {len(hits)} lines "
            f"(budget {budget}).\nRaise errors with "
            f"api_error('area.code') and register the code in hub/errors.py.\n"
            "If the string is matched against external input (a JSON key, a "
            "filename, localized macOS output) rather than shown to anybody, "
            "mark the line '# cjk-input: <why>'.\n"
            "Lines include:\n  " + "\n  ".join(hits[:20]),
        )

    def test_no_stale_cjk_input_markers(self):
        """A marker on a line with no CJK left is dead weight — delete it.

        Without this, ``# cjk-input:`` survives the edit that removed the
        Chinese it excused, and then silently excuses whatever Chinese lands on
        that line next.
        """
        stale: list[str] = []
        sources = sorted(HUB.rglob("*.py")) + sorted(WEB_SRC.rglob("*.vue"))
        for path in sources:
            for n, raw in enumerate(path.read_text(errors="replace").splitlines(), 1):
                if CJK_INPUT_MARKER.search(raw) and not CJK.search(raw):
                    stale.append(f"{path.relative_to(BASE)}:{n}")
        self.assertEqual(
            stale, [], f"'# cjk-input:' markers on lines with no CJK: {stale}"
        )


def _import_every_code_registering_module() -> list[str]:
    """Import each module that registers its own codes, so ``CODES`` is whole.

    Codes are registered as an import side effect -- ``CODES.setdefault(...)`` at
    module scope -- so that the code -> HTTP status mapping travels with the
    module that raises it.  The consequence is that ``errors.CODES`` is only as
    complete as the set of modules imported so far.

    This used to be a hand-written ``__import__("hub.catalog")``, which is a
    guard that quietly stops guarding: ``hub/backups.py`` and
    ``hub/native_catalog.py`` each grew their own ``CODES.setdefault`` block and
    nobody added the matching import, so five real codes sat outside the
    contract.  Discover the registration sites instead of listing them.
    """
    names: list[str] = []
    for path in sorted(HUB.rglob("*.py")):
        if "CODES.setdefault" not in path.read_text(errors="replace"):
            continue
        names.append(".".join(path.relative_to(BASE).with_suffix("").parts))
    for name in names:
        __import__(name)
    return names


class TestErrorCodeContract(unittest.TestCase):
    """Every api_error() code must be registered, and every code translated."""

    def test_the_registration_sites_are_still_discoverable(self):
        """Fail loudly if discovery finds nothing, rather than passing vacuously.

        Both tests below are only meaningful if the modules that register codes
        were actually imported.  Were ``CODES.setdefault`` renamed, discovery
        would return an empty list and the contract would silently hold for a
        ``CODES`` containing nothing but the defaults in ``hub/errors.py``.
        """
        found = _import_every_code_registering_module()
        self.assertNotEqual(
            found,
            [],
            "no module matched 'CODES.setdefault': the discovery heuristic in "
            "_import_every_code_registering_module() is stale, so the two "
            "contract tests below are no longer checking anything",
        )

    def test_every_raised_code_is_registered(self):
        from hub import errors

        _import_every_code_registering_module()

        raised: set[str] = set()
        pat = re.compile(r"""api_error\(\s*["']([a-z0-9_.]+)["']""")
        for path in sorted(HUB.rglob("*.py")):
            raised |= set(pat.findall(path.read_text(errors="replace")))

        missing = sorted(c for c in raised if c not in errors.CODES)
        self.assertEqual(
            missing, [], f"api_error() codes not registered in CODES: {missing}"
        )

    def test_every_registered_code_has_english_and_zh_and_ja(self):
        _import_every_code_registering_module()
        from hub import errors
        from tests.test_frontend_contracts import _locale_keys

        # The SPA resolves ``err.<area>.<leaf>`` through the *nested* dictionary
        # (see errText in web/src/i18n/index.js), so the check has to resolve the
        # whole path.  Searching for the bare leaf anywhere in the file passed on
        # any leaf name reused by another area, which is how err.vms.bad_id and
        # err.identity.bad_name shipped untranslated: ``bad_id:`` exists under
        # err.autostart and ``bad_name:`` under err.scheduler.
        locales = {name: _locale_keys(name) for name in ("en", "zh-CN", "ja")}
        for name, keys in locales.items():
            self.assertGreater(len(keys), 1000, f"{name}.js key scan looks wrong")

        missing: list[str] = []
        for code in errors.CODES:
            for name, keys in locales.items():
                if f"err.{code}" not in keys:
                    missing.append(f"{name}:err.{code}")
        self.assertEqual(
            missing[:20], [], f"error codes with no translation: {missing[:20]}"
        )


def _update_baseline() -> int:
    """Rewrite the baseline to the current counts — ratchet direction only.

    Refuses to raise a number, so running this after adding hardcoded Chinese
    cannot be used to launder the regression past the guard.
    """
    # test_frontend_contracts.py keeps its raw-fetch budget in the same file, so
    # count it here too: writing only our own keys would drop theirs and quietly
    # reset that ratchet to its fallback.
    from tests.test_frontend_contracts import raw_fetch_offenders

    cur = {
        "vue": len(_vue_cjk_lines()),
        "py": len(_py_user_facing_cjk_lines()),
        "raw_fetch": len(raw_fetch_offenders()),
    }
    old = _baseline()
    worse = {k: (old[k], cur[k]) for k in cur if cur[k] > old[k]}
    if worse:
        for area, (was, now) in sorted(worse.items()):
            print(f"refusing to raise {area} baseline: {was} -> {now}")
        print("Extract the new strings with t() / api_error() instead.")
        return 1
    BASELINE_PATH.write_text(json.dumps(cur, indent=2, sort_keys=True) + "\n")
    for area in sorted(cur):
        moved = "" if cur[area] == old[area] else f"  (was {old[area]})"
        print(f"{area}: {cur[area]}{moved}")
    return 0


if __name__ == "__main__":
    if "--update-baseline" in sys.argv:
        raise SystemExit(_update_baseline())
    unittest.main(verbosity=2)
