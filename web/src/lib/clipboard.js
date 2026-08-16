/**
 * One copy-to-clipboard path for the whole panel.
 *
 * `navigator.clipboard` is a secure-context API. This panel is normally reached
 * over plain http on a home LAN, where the whole object is `undefined` — so
 * `navigator.clipboard.writeText(text)` throws a TypeError on the *property
 * access*, before any promise exists. Call sites written as
 * `navigator.clipboard.writeText(x).then(ok, fail)` therefore never ran their
 * failure handler: the throw escaped to the global error handler and the user
 * got a generic page error, or nothing at all.
 *
 * The `execCommand` path is deprecated but is the only thing that works on a
 * non-secure origin, and it is what makes Copy usable for the values that most
 * need it here — recovery codes, API keys, restore commands.
 */

/**
 * Copy *text* to the clipboard.
 *
 * @returns {Promise<boolean>} whether the text actually reached the clipboard.
 *   Never rejects, so callers can toast on the result instead of guarding.
 */
export async function copyToClipboard(text) {
  const value = String(text ?? '')
  if (!value) return false
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(value)
      return true
    }
  } catch {
    // Permission denied, or a document that is not focused. Fall through.
  }
  return legacyCopy(value)
}

function legacyCopy(value) {
  if (typeof document === 'undefined' || !document.body) return false
  const area = document.createElement('textarea')
  area.value = value
  // Off-screen rather than hidden: execCommand ignores an unrendered element,
  // and `readOnly` keeps the mobile keyboard from appearing during the copy.
  area.setAttribute('readonly', '')
  area.style.position = 'fixed'
  area.style.top = '-1000px'
  area.style.opacity = '0'
  document.body.appendChild(area)
  try {
    area.select()
    return document.execCommand('copy')
  } catch {
    return false
  } finally {
    area.remove()
  }
}
