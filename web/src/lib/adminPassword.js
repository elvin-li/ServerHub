/** Web-side macOS administrator password handling.
 *
 *  Privileged server operations (WireGuard up/down, pf NAT, shares, …) need
 *  root. The server answers `admin.password_required` unless the request carries
 *  the password; this module keeps the password for the tab session and shows
 *  an in-browser dialog when one is needed — replacing the old native macOS
 *  authorization sheet, which only ever appeared on the server's own display
 *  and was impossible to answer from a phone or another computer.
 *
 *  The password lives only in a module-level variable (never localStorage) and
 *  is dropped when the server reports it as incorrect or on logout. */

let cached = ''
let promptHandler = null

/** Called by AdminPasswordDialog.vue when it mounts; the dialog provides the
 *  interactive prompt, this module only brokers the promise. */
export function registerAdminPromptHandler(handler) {
  promptHandler = handler
}

export function unregisterAdminPromptHandler(handler) {
  if (promptHandler === handler) promptHandler = null
}

export function getAdminPassword() {
  return cached
}

export function setAdminPassword(password) {
  cached = String(password || '')
}

export function clearAdminPassword() {
  cached = ''
}

/** Header value is base64(UTF-8) so non-latin passwords survive HTTP headers. */
export function encodeAdminPassword(password) {
  try {
    return btoa(String.fromCharCode(...new TextEncoder().encode(password)))
  } catch {
    return ''
  }
}

/** Headers carrying the cached password, for read endpoints that still need
 *  root (e.g. `wg show` polls). Empty object when nothing is cached — reads
 *  then degrade to whatever the passwordless sudoers rules allow. */
export function adminPasswordHeaders() {
  if (!cached) return {}
  return { 'X-Admin-Password': encodeAdminPassword(cached) }
}

/** Ask the operator for the macOS administrator password.
 *  Resolves with the password string, or null when cancelled / no dialog is
 *  mounted (e.g. on the login page). */
export function promptAdminPassword(incorrect = false) {
  if (!promptHandler) return Promise.resolve(null)
  return promptHandler(incorrect)
}
