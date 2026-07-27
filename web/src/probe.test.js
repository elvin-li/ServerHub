import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest'
import { mount } from '@vue/test-utils'
import { createRouter, createWebHistory } from 'vue-router'
import { defineComponent, h } from 'vue'
import App from './App.vue'
import { provideI18n, setLocale } from './i18n/index.js'
import { provideTheme } from './theme/index.js'
import { AUTH_LOST_EVENT } from './api/client.js'

const Blank = defineComponent({ render: () => h('div') })
function makeRouter() {
  return createRouter({ history: createWebHistory(), routes: [
    { path: '/login', name: 'login', component: Blank, meta: { authPage: true } },
    { path: '/', name: 'dashboard', component: Blank },
    { path: '/containers', name: 'containers', component: Blank },
    { path: '/:pathMatch(.*)*', name: 'ca', component: Blank },
  ]})
}
describe('probe', () => {
  let router, fetchMock
  beforeEach(async () => {
    await setLocale('en'); vi.useFakeTimers(); vi.stubGlobal('scrollTo', vi.fn())
    fetchMock = vi.fn().mockResolvedValue({ ok:true, status:200, statusText:'OK',
      json: async () => ({ counts: { ok: 7, warn: 0, down: 0, stopped: 0 } }) })
    vi.stubGlobal('fetch', fetchMock)
    router = makeRouter()
  })
  afterEach(() => { vi.unstubAllGlobals(); vi.useRealTimers() })

  it('A: mounting on /login must not poll /api/status while unauthenticated', async () => {
    await router.replace('/login'); await router.isReady()
    const app = { provide: () => {}, config: { globalProperties: {} } }
    provideI18n(app); provideTheme(app)
    const w = mount(App, { global: { plugins: [router] } })
    await vi.advanceTimersByTimeAsync(0)
    const onLogin = fetchMock.mock.calls.length
    await vi.advanceTimersByTimeAsync(15000 * 4)
    expect(fetchMock.mock.calls.length).toBe(onLogin)
    expect(onLogin).toBe(0)   // should not have fetched at all
    w.unmount()
  })

  it('B: returning after re-login must not flash stale counts', async () => {
    await router.replace('/containers'); await router.isReady()
    const app = { provide: () => {}, config: { globalProperties: {} } }
    provideI18n(app); provideTheme(app)
    const w = mount(App, { global: { plugins: [router] } })
    await vi.advanceTimersByTimeAsync(0)
    expect(w.text()).toContain('7')      // live numbers present

    window.dispatchEvent(new CustomEvent(AUTH_LOST_EVENT, { detail: {} }))
    await vi.advanceTimersByTimeAsync(0)

    // New session: make the refresh hang so only cached state could render.
    fetchMock.mockImplementation(() => new Promise(() => {}))
    await router.replace('/containers')
    await vi.advanceTimersByTimeAsync(0)
    // Stale numbers from the dead session must not be on screen.
    expect(w.text()).not.toContain('7')
    w.unmount()
  })
})
