import { createApp } from 'vue'
import App from './App.vue'
import router, { warmLandingChunk } from './router'
import { initializeI18n, provideI18n } from './i18n'
import { provideTheme } from './theme'
import { registerServiceWorker } from './serviceWorker'
import { installChunkRecovery } from './lib/chunkRecovery'
import './styles.css'

// Vite reports a failed chunk preload before the router sees it, so this is
// registered ahead of bootstrap to catch the earliest signal that this tab is
// running a shell whose assets the server has already replaced.
installChunkRecovery()

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
  await initializeI18n()

  const app = createApp(App)
  provideI18n(app)
  provideTheme(app)
  app.use(router)

  // Global error boundary — catch component errors and show a toast
  app.config.errorHandler = (err, instance, info) => {
    console.error('[ServerHub]', info, err)
    // Show user-friendly toast via DOM (avoid circular dep with App)
    const el = document.querySelector('.toast')
    if (el) {
      el.textContent = '⚠ 页面出现错误，请刷新重试'
      el.classList.add('show')
      setTimeout(() => el.classList.remove('show'), 4000)
    }
  }

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

// Register service worker for PWA offline support. Existing tabs reload once
// when a newly activated worker takes control, so they cannot keep running an
// obsolete hashed bundle after a deployment.
if ('serviceWorker' in navigator && import.meta.env.PROD) {
  window.addEventListener('load', () => {
    registerServiceWorker().catch(() => {})
  })
}
