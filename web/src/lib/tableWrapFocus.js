/**
 * Keyboard access for the app's scrollable table containers (WCAG 2.1.1).
 *
 * `.table-wrap` (styles.css) is the shared overflow container around every
 * dense table: anything wider or taller than its card scrolls inside it. A
 * scrollable region the keyboard cannot reach cannot be scrolled by one — the
 * same reasoning already applied to the Logs viewer and the service log panes
 * — but the class appears in ~30 views, and patching each template invites
 * exactly the piecemeal drift a11y.test.js documents for the wrap itself.
 *
 * So the app shell installs this once over #main-content (App.vue) and every
 * wrap, present or future, is upgraded in place:
 *
 *   tabindex="0"  — reachable, so arrow / page keys scroll it
 *   role="region" — announced as a named container, not an anonymous div
 *   aria-label    — the nearest preceding heading ("Interfaces, region"), or
 *                   the generic dictionary label when nothing precedes it
 *
 * Author-set attributes always win: an element that already carries its own
 * tabindex / role / aria-label(ledby) keeps it. Wraps inside aria-hidden
 * subtrees (SkeletonLoader's decorative shimmer) are skipped outright — a
 * focusable element inside aria-hidden is itself an ARIA violation.
 */
import { t } from '../i18n'

const HEADINGS = 'h1, h2, h3, h4, h5, h6'

function headingText(el) {
  const text = (el.textContent || '').replace(/\s+/g, ' ').trim()
  return text || null
}

/**
 * The closest heading before the wrap in document order: at each ancestor
 * level scan previous siblings nearest-first, taking the sibling itself when
 * it is an h1–h6, otherwise the last heading rendered inside it.
 */
function nearestHeading(wrap, root) {
  for (let node = wrap; node && node !== root; node = node.parentElement) {
    for (let sib = node.previousElementSibling; sib; sib = sib.previousElementSibling) {
      if (sib.matches(HEADINGS)) {
        const text = headingText(sib)
        if (text) return text
      }
      const inner = sib.querySelectorAll(HEADINGS)
      for (let i = inner.length - 1; i >= 0; i--) {
        const text = headingText(inner[i])
        if (text) return text
      }
    }
  }
  return null
}

/**
 * Upgrade every current and future `.table-wrap` under `root`; returns the
 * teardown. One MutationObserver covers the whole region: childList catches
 * views, drawers and modals rendering their tables, and characterData catches
 * headings re-rendering in place on a locale switch — the labels this module
 * owns are recomputed then, so a Japanese page never keeps announcing English
 * region names.
 */
export function installTableWrapFocus(root) {
  // Wraps whose aria-label this module owns (no author label at first sight).
  const labelled = new Set()

  const label = (el) => {
    el.setAttribute('aria-label', nearestHeading(el, root) || t('common.table_region'))
  }

  const upgrade = (el) => {
    if (el.closest('[aria-hidden="true"]')) return
    if (!el.hasAttribute('tabindex')) el.setAttribute('tabindex', '0')
    if (!el.hasAttribute('role')) el.setAttribute('role', 'region')
    if (!labelled.has(el)) {
      if (el.hasAttribute('aria-label') || el.hasAttribute('aria-labelledby')) return
      labelled.add(el)
    }
    label(el)
  }

  const scan = () => {
    for (const el of root.querySelectorAll('.table-wrap')) upgrade(el)
    for (const el of labelled) {
      if (el.isConnected) label(el)
      else labelled.delete(el)
    }
  }

  scan()
  const observer = new MutationObserver(scan)
  observer.observe(root, { childList: true, subtree: true, characterData: true })
  return () => {
    observer.disconnect()
    labelled.clear()
  }
}
