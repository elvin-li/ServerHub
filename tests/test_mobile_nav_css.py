"""Guard the mobile navigation drawer against the containing-block trap.

The drawer (``.top-nav``) is a ``position: fixed`` element that lives *inside*
``<header class="topchrome">``.  A fixed descendant normally resolves against
the viewport, but any of these properties on an ancestor turns that ancestor
into the containing block instead:

    transform, filter, backdrop-filter, perspective, contain, will-change

When that happens the drawer is clipped to the 46px-tall header box and renders
as a small strip in the top-left corner instead of a full-height panel — the
exact symptom reported on iPhone.  ``.topchrome`` legitimately wants
``backdrop-filter: blur()`` on desktop, so the mobile media query must
neutralise it.

These are static checks: no browser needed, and they fail loudly if someone
re-adds a blur/transform to the header without thinking about the drawer.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
CSS = BASE / "web" / "src" / "styles.css"

#: Properties that make an element a containing block for fixed descendants.
CONTAINING_BLOCK_PROPS = (
    "transform",
    "filter",
    "backdrop-filter",
    "-webkit-backdrop-filter",
    "perspective",
    "contain",
    "will-change",
)

#: Ancestors of .top-nav in App.vue: header.topchrome > div.topchrome-inner.
DRAWER_ANCESTORS = (".topchrome", ".topchrome-inner", ".layout")


def _strip_comments(text: str) -> str:
    """Remove /* ... */ comments, preserving offsets so spans stay valid.

    Comments must go before selectors are parsed: a prose comment containing
    commas (like the one explaining this very trap in styles.css) would
    otherwise be glued onto the following selector and split into fragments, so
    `.topchrome` would never compare equal to any of them.
    """
    return re.sub(r"/\*.*?\*/", lambda m: " " * len(m.group(0)), text, flags=re.S)


def _blocks(text: str) -> list[tuple[str, str]]:
    """[(selector, body)] for every top-level-ish rule, media queries included."""
    out: list[tuple[str, str]] = []
    for m in re.finditer(r"([^{}]+)\{([^{}]*)\}", _strip_comments(text)):
        out.append((m.group(1).strip(), m.group(2)))
    return out


def _brace_span(text: str, start: int) -> int:
    """Index of the `}` closing the first `{` at/after *start*."""
    i = text.index("{", start)
    depth = 0
    for j in range(i, len(text)):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                return j
    raise AssertionError("unbalanced braces")


def _mobile_query_span(text: str) -> tuple[int, int]:
    """Character span of the `@media (max-width: 640px)` block."""
    start = text.index("@media (max-width: 640px)")
    i = text.index("{", start)
    depth = 0
    for j in range(i, len(text)):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                return start, j
    raise AssertionError("unbalanced braces in mobile media query")


class TestMobileDrawerContainingBlock(unittest.TestCase):
    def setUp(self):
        self.css = CSS.read_text(errors="replace")
        self.m_start, self.m_end = _mobile_query_span(self.css)
        self.mobile = self.css[self.m_start : self.m_end]

    def test_drawer_is_fixed_on_mobile(self):
        """The whole point of the drawer: a full-height fixed panel."""
        top_nav = [
            body
            for sel, body in _blocks(self.mobile)
            if sel == ".top-nav"
        ]
        self.assertTrue(top_nav, ".top-nav rule missing from the mobile query")
        joined = " ".join(top_nav)
        self.assertIn("position: fixed", joined.replace("  ", " "))

    def test_header_does_not_trap_the_fixed_drawer_on_mobile(self):
        """Every containing-block property on an ancestor must be neutralised.

        Desktop may set `backdrop-filter` on .topchrome; the mobile query has to
        turn it off again, otherwise the drawer is clipped to the header box.
        """
        # Effective value of each risky property on each ancestor, inside mobile.
        offenders: list[str] = []
        for sel, body in _blocks(self.mobile):
            selectors = {s.strip() for s in sel.split(",")}
            if not selectors & set(DRAWER_ANCESTORS):
                continue
            for prop in CONTAINING_BLOCK_PROPS:
                for pm in re.finditer(
                    rf"(?<![\w-]){re.escape(prop)}\s*:\s*([^;]+)", body
                ):
                    value = pm.group(1).strip().rstrip(";").lower()
                    if value not in ("none", "unset", "initial", "revert"):
                        offenders.append(f"{sel} {{ {prop}: {value} }}")
        self.assertEqual(
            offenders,
            [],
            "\nThese rules make a .top-nav ancestor the containing block for the\n"
            "fixed mobile drawer, so it renders clipped to the header instead of\n"
            "full-height:\n  " + "\n  ".join(offenders),
        )

    def test_desktop_blur_is_explicitly_cancelled_on_mobile(self):
        """If desktop blurs the header, mobile must cancel it.

        Catches the original bug: desktop `.topchrome { backdrop-filter: blur() }`
        with no mobile override.
        """
        desktop = self.css[: self.m_start]
        desktop_blurs = any(
            sel.strip() == ".topchrome"
            and re.search(r"(?<![\w-])backdrop-filter\s*:\s*(?!none)", body)
            for sel, body in _blocks(desktop)
        )
        if not desktop_blurs:
            self.skipTest("desktop header no longer blurs; nothing to cancel")
        cancelled = any(
            ".topchrome" in {s.strip() for s in sel.split(",")}
            and re.search(r"backdrop-filter\s*:\s*none", body)
            for sel, body in _blocks(self.mobile)
        )
        self.assertTrue(
            cancelled,
            "Desktop sets backdrop-filter on .topchrome but the mobile query "
            "does not reset it to none — the fixed drawer will be clipped to "
            "the header box.",
        )


class TestNoLaterQueryOverridesTheDrawer(unittest.TestCase):
    """A later, wider media query must not re-style the drawer.

    CSS has no specificity bonus for a narrower breakpoint: `@media (max-width:
    900px)` placed *after* the 640px block still applies on a 390px phone and
    wins on equal specificity.  A `.top-nav { width: 100% }` there stretched the
    fixed drawer across the top of the screen, which looked exactly like the
    original clipping bug even after the containing-block fix landed.
    """

    #: Properties that define the drawer's geometry; a later wider query that
    #: sets any of these on .top-nav is almost certainly a mistake.
    GEOMETRY = ("width", "height", "order", "position", "top", "left", "bottom", "flex")

    def test_wider_queries_after_the_mobile_one_do_not_restyle_top_nav(self):
        css = CSS.read_text(errors="replace")
        m_start, m_end = _mobile_query_span(css)
        after = css[m_end:]
        offenders: list[str] = []
        # Every media query that follows the phone block and still matches a phone.
        for qm in re.finditer(r"@media([^{]+)\{", after):
            cond = qm.group(1)
            lower = re.search(r"min-width:\s*(\d+)px", cond)
            # A query with min-width > 640 cannot affect a phone: it is fine.
            if lower and int(lower.group(1)) > 640:
                continue
            upper = re.search(r"max-width:\s*(\d+)px", cond)
            if not upper or int(upper.group(1)) < 641:
                continue  # not a wider query, or not width-bounded
            body = after[qm.start() : _brace_span(after, qm.start())]
            for sel, rule in _blocks(body):
                if ".top-nav" not in {s.strip() for s in sel.split(",")}:
                    continue
                for prop in self.GEOMETRY:
                    if re.search(rf"(?<![\w-]){prop}\s*:", rule):
                        offenders.append(
                            f"@media{cond.strip()} {{ {sel} {{ {prop} ... }} }}"
                        )
        self.assertEqual(
            offenders,
            [],
            "\nThese later media queries still match a phone and override the\n"
            "off-canvas drawer's geometry (add `min-width: 641px` to scope them\n"
            "above the phone breakpoint):\n  " + "\n  ".join(offenders),
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
