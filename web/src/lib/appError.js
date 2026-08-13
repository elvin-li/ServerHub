/**
 * Last-resort surfacing for failures nothing else caught.
 *
 * Two kinds of error used to vanish (or worse) in a long-lived tab:
 *
 *   - render-time exceptions: the old app.config.errorHandler wrote a
 *     hardcoded zh-CN string straight into the toast's DOM node, fighting the
 *     reactive binding that owns that element — the next unrelated re-render
 *     wiped it, and non-Chinese locales got Chinese;
 *   - unhandled promise rejections: nothing listened at all, so a rejected
 *     fire-and-forget call died silently in the console of a tab nobody has
 *     looked at for days.
 *
 * Both now funnel through one window event that the shell (App.vue) turns
 * into its normal localized toast, mirroring how client.js reports a lost
 * session via AUTH_LOST_EVENT. The console.error stays: the toast says
 * something broke, the console says what.
 */
import { isChunkLoadError } from './chunkRecovery'

export const APP_ERROR_EVENT = 'serverhub:app-error'

export function reportAppError(error, context) {
  console.error('[ServerHub]', context, error)
  try {
    window.dispatchEvent(new CustomEvent(APP_ERROR_EVENT, { detail: { error, context } }))
  } catch {
    // The console line above already recorded it.
  }
}

/**
 * Install the Vue error handler and the window unhandledrejection listener.
 * Returns a disposer (used by tests; the real app keeps them for the page's
 * lifetime).
 */
export function installGlobalErrorHandlers(app) {
  app.config.errorHandler = (error, _instance, info) => reportAppError(error, info)

  const onRejection = (event) => {
    // A stale-chunk rejection is already being answered with a one-shot reload
    // (lib/chunkRecovery.js); a toast on top of that reload is only noise.
    if (isChunkLoadError(event.reason)) return
    // Suppress the browser's own duplicate console entry — reportAppError logs.
    event.preventDefault()
    reportAppError(event.reason, 'unhandledrejection')
  }
  window.addEventListener('unhandledrejection', onRejection)
  return () => window.removeEventListener('unhandledrejection', onRejection)
}
