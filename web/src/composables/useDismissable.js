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

  function onKeydown(event) {
    if (event.key === 'Escape') {
      event.stopPropagation()
      close()
      return
    }
    if (event.key !== 'Tab') return
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
    document.body.style.removeProperty('overflow')
    if (lastFocused && typeof lastFocused.focus === 'function') {
      lastFocused.focus()
      lastFocused = null
    }
  }

  watch(
    () => (typeof isOpen === 'function' ? isOpen() : isOpen.value),
    async (open) => {
      if (open) {
        lastFocused = document.activeElement
        document.addEventListener('keydown', onKeydown, true)
        document.body.style.overflow = 'hidden'
        await Promise.resolve()
        const items = focusableWithin(panel?.value)
        ;(items[0] || panel?.value)?.focus?.()
      } else {
        teardown()
      }
    },
    { immediate: true },
  )

  onBeforeUnmount(teardown)
}
