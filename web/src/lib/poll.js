/**
 * Visibility-aware polling — pause timers when the browser tab is hidden
 * so ServerHub does not burn CPU/disk while nobody is looking.
 * Includes exponential backoff on consecutive failures (mobile-friendly)
 * and network-quality awareness via navigator.connection.
 */

/** Returns a multiplier based on connection quality (1 = normal, higher = slower). */
function networkMultiplier() {
  const c = navigator.connection || navigator.mozConnection || navigator.webkitConnection
  if (!c) return 1
  if (c.saveData) return 3 // Data-saver mode: poll 3x less
  const type = c.effectiveType
  if (type === 'slow-2g' || type === '2g') return 3
  if (type === '3g') return 1.8
  return 1
}

/**
 * Runs `fn` on an interval, pausing while the tab is hidden and backing off
 * exponentially while `fn` keeps reporting failure.
 *
 * A tick counts as FAILED when either
 *   1. the promise returned by `fn` rejects, or
 *   2. `fn` resolves to exactly `false` (the opt-in sentinel).
 *
 * Backward compatibility: most callbacks in this app catch their own errors and
 * return `undefined` (or a `Promise.all` array).  Those values are not `false`,
 * so such callbacks are still treated as "succeeded" exactly as before and never
 * trigger backoff — they simply do not benefit from it.  A caller opts in by
 * either letting its errors propagate or by returning `false` from a tick where
 * something failed.
 */
export function startVisibleInterval(fn, ms) {
  let id = null
  let failures = 0
  // Bumped by every stop().  A tick that was already in flight when the poller
  // was stopped resumes *after* stop() cleared the timer, so it cannot be
  // cancelled by clearTimeout — it has to check whether it still belongs to the
  // current run before re-arming, or disposing mid-tick leaks a poller that
  // keeps hitting the host for the life of the page.
  let generation = 0
  const MAX_BACKOFF = ms * 6 // cap at 6x normal interval

  const tick = async () => {
    if (typeof document !== 'undefined' && document.hidden) return
    try {
      // `=== false` only: undefined/null/[]/0 stay "success" for legacy callbacks.
      if ((await fn()) === false) failures++
      else failures = 0
    } catch {
      failures++
    }
  }

  const effectiveMs = () =>
    Math.min(ms * Math.pow(1.5, failures) * networkMultiplier(), MAX_BACKOFF)

  const start = () => {
    if (id != null) return
    const gen = generation
    const loop = () => {
      id = setTimeout(async () => {
        // stop() may run after this timer has already fired and been queued.
        // clearTimeout cannot cancel that callback; skip fn() so a disposed
        // poller does not hit the host one extra time.
        if (gen !== generation) return
        await tick()
        if (gen !== generation) return // stopped while this tick was in flight
        loop()
      }, effectiveMs())
    }
    loop()
  }

  const stop = () => {
    generation++
    if (id != null) {
      clearTimeout(id)
      id = null
    }
  }

  const onVis = () => {
    if (document.hidden) stop()
    else {
      start()
      // One immediate refresh when the user returns.  Goes through tick() so a
      // callback that now propagates its error cannot produce an unhandled
      // rejection, and so the outcome still feeds the backoff counter.
      void tick()
    }
  }

  if (typeof document !== 'undefined') {
    document.addEventListener('visibilitychange', onVis)
  }
  if (typeof document === 'undefined' || !document.hidden) start()
  return () => {
    stop()
    if (typeof document !== 'undefined') {
      document.removeEventListener('visibilitychange', onVis)
    }
  }
}
