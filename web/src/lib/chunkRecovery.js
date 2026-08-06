/**
 * Recover when a lazily-loaded route chunk no longer exists on the server.
 *
 * Every page except the dashboard is a dynamic import, and the service worker
 * serves `/assets/` cache-first. So a tab holding a previous build's `index.html`
 * asks for that build's chunk hashes. For a route the user already visited the
 * chunk is in the SW cache and still works; for a route they have *not* visited
 * the request goes to the network, where a rebuild has since removed that hash —
 * the import rejects and the page simply never opens, with no error the user can
 * act on. Observed exactly this way: every previously-visited page worked while
 * one new route was dead.
 *
 * The fix is to treat a failed chunk fetch as "my shell is stale" and reload once
 * so the browser picks up the current `index.html`. Reloading is guarded by a
 * session flag because if the chunk is genuinely missing server-side, an
 * unguarded reload becomes an infinite refresh loop — worse than the dead route.
 * The flag is cleared on the next successful navigation, so a later staleness
 * can recover again.
 */
const FLAG = 'serverhub-chunk-reload'

/** Errors that mean "the JS module could not be fetched", across browsers. */
const CHUNK_ERROR = /Failed to fetch dynamically imported module|error loading dynamically imported module|Importing a module script failed|Loading chunk \S+ failed|dynamically imported module/i

export function isChunkLoadError(error) {
  if (!error) return false
  const message = String(error.message || error)
  return CHUNK_ERROR.test(message)
}

/**
 * Reload once to pick up a fresh shell. Returns whether a reload was issued.
 */
export function recoverFromStaleChunk({
  storage = globalThis.sessionStorage,
  reload = () => globalThis.location?.reload(),
} = {}) {
  try {
    if (storage?.getItem(FLAG)) return false
    storage?.setItem(FLAG, '1')
  } catch {
    // Private mode can throw on storage access; a single reload is still better
    // than a permanently dead route, but without the flag we must not risk a
    // loop, so decline instead.
    return false
  }
  reload()
  return true
}

/** Clear the guard after a navigation succeeds, so recovery can happen again. */
export function clearStaleChunkFlag({ storage = globalThis.sessionStorage } = {}) {
  try {
    storage?.removeItem(FLAG)
  } catch {
    /* ignore */
  }
}

/**
 * Listen for Vite's preload failure, which fires before the router sees an error.
 */
export function installChunkRecovery({
  target = globalThis,
  storage = globalThis.sessionStorage,
  reload = () => globalThis.location?.reload(),
} = {}) {
  const handler = (event) => {
    // Without preventDefault Vite rethrows, which surfaces an unhandled rejection
    // in the console on top of the reload we are about to do.
    event?.preventDefault?.()
    recoverFromStaleChunk({ storage, reload })
  }
  target?.addEventListener?.('vite:preloadError', handler)
  return handler
}
