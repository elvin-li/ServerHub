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


def _vue_cjk_lines() -> list[str]:
    """CJK lines in .vue sources, excluding the i18n dictionaries themselves."""
    hits: list[str] = []
    for path in sorted(WEB_SRC.rglob("*.vue")):
        for n, raw in enumerate(path.read_text(errors="replace").splitlines(), 1):
            if CJK.search(_strip_comments_js(raw)):
                hits.append(f"{path.relative_to(BASE)}:{n}")
    return hits


def _py_user_facing_cjk_lines() -> list[str]:
    """CJK lines in hub/ that plausibly reach the user.

    Comments and docstrings are legitimate (the team reads Chinese); strings
    handed to the client are not.
    """
    hits: list[str] = []
    for path in sorted(HUB.rglob("*.py")):
        in_doc = False
        for n, raw in enumerate(path.read_text(errors="replace").splitlines(), 1):
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
            f"web/src/i18n/{{en,zh-CN,ja}}.js.\nNew/uncounted lines include:\n  "
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
            "Lines include:\n  " + "\n  ".join(hits[:20]),
        )


class TestErrorCodeContract(unittest.TestCase):
    """Every api_error() code must be registered, and every code translated."""

    def test_every_raised_code_is_registered(self):
        from hub import errors

        # Importing this module registers its local codes via CODES.setdefault.
        __import__("hub.catalog")

        raised: set[str] = set()
        pat = re.compile(r"""api_error\(\s*["']([a-z0-9_.]+)["']""")
        for path in sorted(HUB.rglob("*.py")):
            raised |= set(pat.findall(path.read_text(errors="replace")))

        missing = sorted(c for c in raised if c not in errors.CODES)
        self.assertEqual(
            missing, [], f"api_error() codes not registered in CODES: {missing}"
        )

    def test_every_registered_code_has_english_and_zh_and_ja(self):
        __import__("hub.catalog")
        from hub import errors

        locales = {}
        for name in ("en", "zh-CN", "ja"):
            text = (WEB_SRC / "i18n" / f"{name}.js").read_text(errors="replace")
            locales[name] = text

        missing: list[str] = []
        for code in errors.CODES:
            area, _, leaf = code.partition(".")
            for name, text in locales.items():
                # keys are nested: err: { files: { path_protected: '...' } }
                if not re.search(rf"\b{re.escape(leaf)}\s*:", text):
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
