const UPDATE_READY_EVENT = 'sw-update-ready'

/**
 * Register the production service worker. controllerchange never triggers a
 * reload: a newly activated worker claiming open windows caused a reload
 * storm after every deploy. Tabs move onto a new build only through the
 * sw-update-ready banner the UI shows when an update is installed.
 */
export function registerServiceWorker({
  serviceWorker = globalThis.navigator?.serviceWorker,
  dispatchUpdate = () => globalThis.dispatchEvent?.(new CustomEvent(UPDATE_READY_EVENT)),
  windowTarget = globalThis,
  documentTarget = globalThis.document,
  now = () => Date.now(),
  updateCheckInterval = 60_000,
} = {}) {
  if (!serviceWorker) return Promise.resolve(null)

  const hadController = Boolean(serviceWorker.controller)

  return serviceWorker.register('/sw.js').then((registration) => {
    // A prior visit may have left an update waiting because the tab closed
    // before activation. Ask it to activate now; the tab keeps running the
    // old bundle until the user accepts the sw-update-ready banner.
    registration.waiting?.postMessage('skipWaiting')
    registration.addEventListener('updatefound', () => {
      const worker = registration.installing
      if (!worker) return
      worker.addEventListener('statechange', () => {
        if (worker.state === 'installed' && hadController) dispatchUpdate()
      })
    })

    // Browsers otherwise check a long-lived tab on their own schedule. Check when
    // the user returns to it, but throttle focus/visibility events so switching
    // windows cannot turn into repeated network requests.
    let lastUpdateCheck = now()
    const checkForUpdate = () => {
      const current = now()
      if (current - lastUpdateCheck < updateCheckInterval) return
      lastUpdateCheck = current
      Promise.resolve(registration.update?.()).catch(() => {})
    }
    windowTarget?.addEventListener?.('focus', checkForUpdate)
    documentTarget?.addEventListener?.('visibilitychange', () => {
      if (documentTarget.visibilityState === 'visible') checkForUpdate()
    })

    return registration
  })
}
