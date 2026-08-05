import { createApp } from 'vue'
import App from './App.vue'
import router from './router'
import { initializeI18n, provideI18n } from './i18n'
import { provideTheme } from './theme'
import { registerServiceWorker } from './serviceWorker'
import './styles.css'

async function bootstrap() {
  // Keep English as the synchronous fallback, but fetch the selected non-English
  // dictionary before first render so the page never flashes untranslated keys.
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
