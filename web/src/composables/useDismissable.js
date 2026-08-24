import { onBeforeUnmount, watch } from 'vue'

const FOCUSABLE = [
  'a[href]', 'button:not([disabled])', 'input:not([disabled])',
  'select:not([disabled])', 'textarea:not([disabled])',
  '[tabindex]:not([tabindex="-1"])',
].join(',')

function isHidden(el) {
  // Deliberately avoids offsetWidth/offsetHeight: those report 0 for every
  // element under a headless DOM with no layout engine, which would empty the
  // candidate list and silently disable the focus trap in tests.
  if (el.hidden || el.closest('[hidden]')) return true
  if (el.getAttribute('aria-hidden') === 'true') return true
  const style = el.ownerDocument?.defaultView?.getComputedStyle?.(el)
  return Boolean(style && (style.display === 'none' || style.visibility === 'hidden'))
}

function focusableWithin(root) {
  if (!root) return []
  return Array.from(root.querySelectorAll(FOCUSABLE)).filter((el) => !isHidden(el))
}

function isConsoleSurface(el) {
  // xterm and noVNC need Tab to reach the remote session. Wrapping from the
  // helper textarea / screen back to Close stole it.
  if (!el || el === document.body || el === document.documentElement) return false
  if (el.classList?.contains('vnc-screen') || el.classList?.contains('xterm-helper-textarea')) return true
  return Boolean(el.closest?.('.xterm, .vnc-screen'))
}

/**
 * Dialogs stack: the global admin-password prompt opens on top of whatever
 * modal triggered the privileged call.  Every instance used to run its own
 * document-level keydown handler, and stopPropagation() does not silence
 * other listeners on the same target, so one Escape closed the prompt AND
 * the dialog under it, while the lower dialog's Tab trap yanked Shift+Tab
 * focus behind the prompt.  The shared stack gives Escape and Tab to the
 * topmost open dialog only, and keeps the body scroll lock until the last
 * one closes instead of releasing it under a still-open modal.
 */
const openStack = []

/**
 * Wire the keyboard contract every dialog owes the user: Escape closes it,
 * focus moves in on open and returns to the trigger on close, and Tab cannot
 * wander to the page behind the overlay.
 *
 * `isOpen` is a ref/getter for visibility, `close` is called to dismiss, and
 * `panel` is a ref to the dialog element (the box, not the backdrop).
 */
export function useDismissable(isOpen, close, panel) {
  let lastFocused = null
  let pageAlive = true
  let loadGeneration = 0
  const stackToken = {}

  function stillOn(generation) {
    return pageAlive && generation === loadGeneration
  }

  function onKeydown(event) {
    // A lower dialog must not react while another is open above it.
    if (openStack[openStack.length - 1] !== stackToken) return
    if (event.key === 'Escape') {
      // While composing Japanese or Chinese, Escape cancels the composition;
      // closing the dialog out from under the half-typed word takes the whole
      // form with it.  keyCode 229 is the legacy in-composition signal some
      // engines still send instead of (or before) isComposing.
      if (event.isComposing || event.keyCode === 229) return
      event.stopPropagation()
      close()
      return
    }
    if (event.key !== 'Tab') return
    if (isConsoleSurface(event.target) || isConsoleSurface(document.activeElement)) return
    // Without this, Tab escapes into the page behind the overlay, where a
    // sighted keyboard user cannot see where the caret went.
    const items = focusableWithin(panel?.value)
    if (!items.length) return
    const first = items[0]
    const last = items[items.length - 1]
    const active = document.activeElement
    if (event.shiftKey && (active === first || !panel.value?.contains(active))) {
      event.preventDefault()
      last.focus()
    } else if (!event.shiftKey && active === last) {
      event.preventDefault()
      first.focus()
    }
  }

  function teardown() {
    document.removeEventListener('keydown', onKeydown, true)
    const at = openStack.indexOf(stackToken)
    if (at >= 0) openStack.splice(at, 1)
    // Only the last dialog out unlocks the page; releasing it under a
    // still-open modal lets the background scroll behind the overlay.
    if (!openStack.length) document.body.style.removeProperty('overflow')
    if (lastFocused && typeof lastFocused.focus === 'function') {
      lastFocused.focus()
      lastFocused = null
    }
  }

  watch(
    () => (typeof isOpen === 'function' ? isOpen() : isOpen.value),
    async (open) => {
      const generation = ++loadGeneration
      if (open) {
        lastFocused = document.activeElement
        // Truthy-to-truthy transitions re-run this branch (ServiceLogsModal
        // watches the entry object so a refresh re-focuses the pane); the
        // stack must not hold the same dialog twice.
        if (!openStack.includes(stackToken)) openStack.push(stackToken)
        document.addEventListener('keydown', onKeydown, true)
        document.body.style.overflow = 'hidden'
        await Promise.resolve()
        if (!stillOn(generation)) return
        const items = focusableWithin(panel?.value)
        ;(items[0] || panel?.value)?.focus?.()
      } else {
        teardown()
      }
    },
    { immediate: true },
  )

  onBeforeUnmount(() => {
    pageAlive = false
    loadGeneration += 1
    teardown()
  })
}
