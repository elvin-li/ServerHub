import { createApp } from 'vue'
import App from './App.vue'
import router, { warmLandingChunk } from './router'
import { initializeI18n, provideI18n } from './i18n'
import { provideTheme } from './theme'
import { registerServiceWorker } from './serviceWorker'
import { installChunkRecovery, recoverFromStaleChunk } from './lib/chunkRecovery'
import { installGlobalErrorHandlers } from './lib/appError'
import './styles.css'

// Vite reports a failed chunk preload before the router sees it, so this is
// registered ahead of bootstrap to catch the earliest signal that this tab is
// running a shell whose assets the server has already replaced.
installChunkRecovery()

/**
 * Reveal the hardcoded bilingual failure notice shipped in index.html.
 *
 * Reached only when *no* dictionary loaded (initializeI18n() returned false):
 * with MESSAGES entirely empty, t() returns every key verbatim and the whole
 * UI would render as raw key paths.  The notice deliberately lives in the
 * shell rather than here so it cannot depend on any dictionary, and the
 * reload button is wired up here because the CSP forbids inline handlers.
 */
function showI18nFailure() {
  const panel = document.getElementById('i18n-failure')
  if (!panel) {
    // A shell so old it predates the notice: plain-text last resort.
    document.body.textContent = 'ServerHub could not load its language packs. Please refresh.'
    return
  }
  panel.hidden = false
  panel.querySelector('button')?.addEventListener('click', () => location.reload())
}

async function bootstrap() {
  // Kick off the landing page's chunk before awaiting anything, so it downloads
  // alongside the dictionary fetch below and the router's auth-status probe
  // rather than after them. Deliberately not awaited: the router owns rendering
  // it, this only removes the wait.
  warmLandingChunk()

  // Hold the first render until both the selected dictionary and the English
  // fallback are resident (all three locales are code-split; see i18n/index.js),
  // so the page never flashes raw key paths and t()'s synchronous English
  // fallback keeps working from the first paint on.
  //
  // When not even one dictionary made it (offline mid-deploy, storage failure),
  // do not mount at all: an app whose every label is a raw key path is worse
  // than a one-line notice with a refresh button. Locale files are hashed and
  // code-split, so a tab that still holds the previous shell asks for chunks
  // the new service-worker cache has already dropped — recoverFromStaleChunk
  // reloads once onto the current index.html. The notice is only for the case
  // where that reload did not help either (vite:preloadError does not fire for
  // these imports: initializeI18n() swallows the rejection).
  if (!await initializeI18n()) {
    if (recoverFromStaleChunk()) return
    showI18nFailure()
    return
  }

  const app = createApp(App)
  provideI18n(app)
  provideTheme(app)
  app.use(router)

  // Global error boundary: render-time exceptions and unhandled rejections
  // surface as the shell's localized toast (App.vue listens for the event)
  // instead of dying silently in a tab nobody is watching.
  installGlobalErrorHandlers(app)

  app.mount('#app')
}

bootstrap()

// Haptic feedback on button press (mobile)
if ('vibrate' in navigator && 'ontouchstart' in window) {
  document.addEventListener('click', (e) => {
    const btn = e.target.closest('button, .btn, a.btn')
    if (btn && !btn.disabled) navigator.vibrate(8)
  }, { passive: true })
}

// Register the service worker. controllerchange does not reload the tab
// (see serviceWorker.js); a stale hashed chunk recovers via
// recoverFromStaleChunk() instead.
if ('serviceWorker' in navigator && import.meta.env.PROD) {
  window.addEventListener('load', () => {
    registerServiceWorker().catch(() => {})
  })
}
