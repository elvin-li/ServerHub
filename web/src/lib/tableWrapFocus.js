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
import { asTrimmed } from './finite.js'

const HEADINGS = 'h1, h2, h3, h4, h5, h6'

function headingText(el) {
  const text = asTrimmed((el.textContent || '').replace(/\s+/g, ' '))
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

const HEADING_TAGS = new Set(['H1', 'H2', 'H3', 'H4', 'H5', 'H6'])

/** Whether `el` is an h1–h6 or sits inside one below `root`. */
function inHeading(el, root) {
  for (; el && el !== root; el = el.parentElement) {
    if (HEADING_TAGS.has(el.tagName)) return true
  }
  return false
}

/** Whether the element `el` is, or contains, an h1–h6. */
function hasHeading(el) {
  return HEADING_TAGS.has(el.tagName) || el.querySelector(HEADINGS) != null
}

/**
 * Upgrade every current and future `.table-wrap` under `root`; returns the
 * teardown. Two observers split the work:
 *
 *   - one over the whole region for childList (views, drawers and modals
 *     rendering their tables, headings coming and going) and aria-hidden
 *     (a subtree it stops hiding may hold wraps that were skipped);
 *   - one per heading for characterData, which catches a heading
 *     re-rendering in place on a locale switch, so a Japanese page never
 *     keeps announcing English region names.
 *
 * Text edits are watched inside headings only. Polled pages rewrite table
 * cells every few seconds; observing characterData over the whole region made
 * each of those batches a full rescan that walked every wrap's preceding
 * siblings and rewrote every label. Now a cell edit creates no record at all,
 * only added subtrees are searched for wraps, and owned labels are recomputed
 * only when a heading was added, removed or edited, and rewritten only when
 * they change.
 */
export function installTableWrapFocus(root) {
  // Wraps whose aria-label this module owns (no author label at first sight).
  const labelled = new Set()

  const label = (el) => {
    const next = nearestHeading(el, root) || t('common.table_region')
    if (el.getAttribute('aria-label') !== next) el.setAttribute('aria-label', next)
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

  // The wraps at or under one element.
  const upgradeIn = (el) => {
    if (el.classList.contains('table-wrap')) upgrade(el)
    for (const wrap of el.querySelectorAll('.table-wrap')) upgrade(wrap)
  }

  // Recompute owned labels, dropping wraps that left the page.
  const relabel = () => {
    for (const el of labelled) {
      if (el.isConnected) label(el)
      else labelled.delete(el)
    }
  }

  const prune = () => {
    for (const el of labelled) if (!el.isConnected) labelled.delete(el)
  }

  // Text edits inside any current heading; re-pointed whenever headings are
  // added or removed (which also drops the ones that left the page).
  const headingEdits = new MutationObserver(relabel)
  const watchHeadings = () => {
    headingEdits.disconnect()
    for (const h of root.querySelectorAll(HEADINGS)) {
      headingEdits.observe(h, { characterData: true, subtree: true })
    }
  }

  const onMutations = (records) => {
    let headingsMoved = false
    let headingEdited = false
    let removed = false
    for (const record of records) {
      const target = record.target
      if (record.type === 'attributes') {
        if (target.isConnected) upgradeIn(target)
        continue
      }
      // childList inside a heading: a text node or inline element swapped.
      if (!headingEdited && inHeading(target, root)) headingEdited = true
      for (const node of record.addedNodes) {
        if (node.nodeType !== 1 || !node.isConnected) continue
        if (!headingsMoved && hasHeading(node)) headingsMoved = true
        upgradeIn(node)
      }
      if (record.removedNodes.length) {
        removed = true
        if (!headingsMoved) {
          for (const node of record.removedNodes) {
            if (node.nodeType === 1 && hasHeading(node)) { headingsMoved = true; break }
          }
        }
      }
    }
    if (headingsMoved) watchHeadings()
    // Wraps added by this batch were labelled against the DOM as it now
    // stands; the pass below is for the ones labelled before it.
    if (headingsMoved || headingEdited) relabel()
    else if (removed) prune()
  }

  upgradeIn(root)
  watchHeadings()
  const observer = new MutationObserver(onMutations)
  observer.observe(root, {
    childList: true,
    subtree: true,
    attributes: true,
    attributeFilter: ['aria-hidden'],
  })
  return () => {
    observer.disconnect()
    headingEdits.disconnect()
    labelled.clear()
  }
}
