/**
 * Behavioral cover for the shell's session-loss handling.
 *
 * client.js latches the auth-lost dispatch and router.js decides who may enter a
 * route; this file is the third piece of that chain — what the mounted shell does
 * when the session dies underneath it. It has to drop stale numbers, stop the
 * sidebar poll, and hand the current page to Login.vue via ?next=.
 *
 * The subtle half is what happens *after* the user signs back in. App.vue is the
 * root component: router-view swaps inside it, so it never unmounts across the
 * login navigation and nothing re-runs onMounted. Anything torn down here is
 * torn down for the life of the tab unless it is explicitly restarted.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { mount } from '@vue/test-utils'
import { createRouter, createWebHistory } from 'vue-router'
import { defineComponent, h } from 'vue'

import App from './App.vue'
import { provideI18n, setLocale } from './i18n/index.js'
import { provideTheme } from './theme/index.js'
import { AUTH_LOST_EVENT } from './api/client.js'
import { APP_ERROR_EVENT } from './lib/appError.js'

const Blank = defineComponent({ render: () => h('div') })

const POLL_MS = 30000

function makeRouter() {
  return createRouter({
    history: createWebHistory(),
    routes: [
      { path: '/login', name: 'login', component: Blank, meta: { authPage: true } },
      { path: '/', name: 'dashboard', component: Blank },
      { path: '/containers', name: 'containers', component: Blank },
      // The shell's nav renders a router-link per page; without a catch-all
      // every one of them warns and buries the real assertion output.
      { path: '/:pathMatch(.*)*', name: 'catch-all', component: Blank },
    ],
  })
}

/** Mount the shell through the same providers main.js installs. */
function mountShell(router) {
  // provideI18n/provideTheme take an app-like object; they only call .provide().
  const appLike = { provide: () => {}, config: { globalProperties: {} } }
  provideI18n(appLike)
  provideTheme(appLike)
  return mount(App, { global: { plugins: [router] } })
}

function loseSession() {
  window.dispatchEvent(
    new CustomEvent(AUTH_LOST_EVENT, { detail: { url: '/api/status' } }),
  )
}

/** A successful /api/status response carrying `body`. */
function statusRes(body) {
  return {
    ok: true,
    status: 200,
    statusText: 'OK',
    json: async () => body,
  }
}

/** How many times the shell has hit /api/status. */
function statusCalls(mock) {
  return mock.mock.calls.filter(([url]) => String(url).includes('/api/status')).length
}

describe('App shell session loss', () => {
  let router
  let fetchMock
  let wrapper

  beforeEach(async () => {
    await setLocale('en')
    vi.useFakeTimers()
    // jsdom implements neither; the shell calls both on scroll/route change.
    vi.stubGlobal('scrollTo', vi.fn())
    fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      statusText: 'OK',
      json: async () => ({ services: [] }),
    })
    vi.stubGlobal('fetch', fetchMock)
    router = makeRouter()
    await router.replace('/containers')
    await router.isReady()
  })

  afterEach(() => {
    wrapper?.unmount()
    wrapper = undefined
    vi.unstubAllGlobals()
    vi.useRealTimers()
  })

  it('keeps refreshing the sidebar badge after the user signs back in', async () => {
    // The regression this pins: onAuthLost() disposes the poll, but App.vue is
    // the root component and never remounts across the login navigation, so a
    // single expiry silently killed the badge for the life of the tab.
    wrapper = mountShell(router)
    await vi.advanceTimersByTimeAsync(0)

    const before = fetchMock.mock.calls.length
    await vi.advanceTimersByTimeAsync(POLL_MS)
    expect(fetchMock.mock.calls.length).toBeGreaterThan(before)

    loseSession()
    await vi.advanceTimersByTimeAsync(0)

    // Back on a real page after signing in again.
    await router.replace('/containers')
    await vi.advanceTimersByTimeAsync(0)

    const afterLogin = fetchMock.mock.calls.length
    await vi.advanceTimersByTimeAsync(POLL_MS * 3)
    expect(fetchMock.mock.calls.length).toBeGreaterThan(afterLogin)
  })

  it('stops polling while the user sits on the login page', async () => {
    // Hammering /api/status with a dead cookie just yields a 401 per tick.
    wrapper = mountShell(router)
    await vi.advanceTimersByTimeAsync(0)

    loseSession()
    await vi.advanceTimersByTimeAsync(0)
    await router.isReady()

    const parked = fetchMock.mock.calls.length
    await vi.advanceTimersByTimeAsync(POLL_MS * 4)
    expect(fetchMock.mock.calls.length).toBe(parked)
  })

  it('hands the abandoned page to the login view via ?next=', async () => {
    wrapper = mountShell(router)
    await vi.advanceTimersByTimeAsync(0)

    loseSession()
    await vi.advanceTimersByTimeAsync(0)

    expect(router.currentRoute.value.path).toBe('/login')
    // Login.vue replays this after a successful sign-in.
    expect(router.currentRoute.value.query.next).toBe('/containers')
  })

  it('omits ?next= when the lost page was already the dashboard', async () => {
    await router.replace('/')
    wrapper = mountShell(router)
    await vi.advanceTimersByTimeAsync(0)

    loseSession()
    await vi.advanceTimersByTimeAsync(0)

    expect(router.currentRoute.value.path).toBe('/login')
    // '/' is where login lands by default, so a next= round-trip adds nothing.
    expect(router.currentRoute.value.query.next).toBeUndefined()
  })

  it('does not flash counts from the dead session after signing back in', async () => {
    // Asserting on rendered text rather than `.pill.down`: the whole shell is
    // replaced by a bare router-view on /login, so any selector is absent there
    // whether or not the numbers were actually cleared. The failure that matters
    // is the badge reappearing with pre-expiry counts on the way back.
    fetchMock.mockResolvedValue(statusRes({ counts: { ok: 1, down: 7 } }))
    wrapper = mountShell(router)
    await vi.advanceTimersByTimeAsync(0)
    expect(wrapper.text()).toContain('7')

    loseSession()
    await vi.advanceTimersByTimeAsync(0)

    // Session is gone, so the refresh on return cannot answer with real data.
    fetchMock.mockRejectedValue(Object.assign(new Error('Failed to fetch'), {
      name: 'TypeError',
    }))
    await router.replace('/containers')
    await vi.advanceTimersByTimeAsync(0)

    expect(wrapper.text()).not.toContain('7')
  })

  it('does not poll the status API while the login page is showing', async () => {
    // Every one of these is an unauthenticated request the server answers with
    // 401, which in turn feeds the auth-lost latch.
    await router.replace('/login')
    wrapper = mountShell(router)
    await vi.advanceTimersByTimeAsync(0)
    await vi.advanceTimersByTimeAsync(POLL_MS * 4)

    expect(statusCalls(fetchMock)).toBe(0)
  })

  it('does not bounce a new session when a late logout returns', async () => {
    // logout() awaits /api/auth/logout. If the session dies while that POST
    // is in flight, onAuthLost already sent the user to /login; they may
    // sign back in before the original logout settles. Finishing that POST
    // must not clearAuth + replace /login on top of the new session.
    let finishLogout
    fetchMock.mockImplementation((url) => {
      if (String(url).includes('/api/auth/logout')) {
        return new Promise((resolve) => {
          finishLogout = () => resolve({
            ok: true,
            status: 200,
            statusText: 'OK',
            json: async () => ({}),
          })
        })
      }
      return Promise.resolve(statusRes({ services: [] }))
    })
    wrapper = mountShell(router)
    await vi.advanceTimersByTimeAsync(0)

    const pending = wrapper.find('.logout-btn').trigger('click')
    loseSession()
    await vi.advanceTimersByTimeAsync(0)
    expect(router.currentRoute.value.path).toBe('/login')

    await router.replace('/containers')
    await vi.advanceTimersByTimeAsync(0)

    finishLogout()
    await pending
    await vi.advanceTimersByTimeAsync(0)
    expect(router.currentRoute.value.path).toBe('/containers')
  })

  it('stops polling when the user signs out deliberately', async () => {
    // Distinct from session loss: logout() navigates to /login without firing
    // the auth-lost event, so the route watcher is the only thing that can stop
    // the poll here. Without it the shell keeps hitting /api/status as an
    // unauthenticated client for as long as the tab stays open.
    wrapper = mountShell(router)
    await vi.advanceTimersByTimeAsync(0)

    await wrapper.find('.logout-btn').trigger('click')
    await vi.advanceTimersByTimeAsync(0)
    expect(router.currentRoute.value.path).toBe('/login')

    const after = statusCalls(fetchMock)
    await vi.advanceTimersByTimeAsync(POLL_MS * 4)
    expect(statusCalls(fetchMock)).toBe(after)
  })

  it('ignores the event when the user is already on the login page', async () => {
    await router.replace('/login')
    wrapper = mountShell(router)
    await vi.advanceTimersByTimeAsync(0)

    loseSession()
    await vi.advanceTimersByTimeAsync(0)

    // A failed login attempt must not bounce the login page onto itself.
    expect(router.currentRoute.value.path).toBe('/login')
    expect(router.currentRoute.value.query.next).toBeUndefined()
  })

  it('stops polling for good once the shell unmounts', async () => {
    wrapper = mountShell(router)
    await vi.advanceTimersByTimeAsync(0)

    wrapper.unmount()
    wrapper = undefined

    const after = fetchMock.mock.calls.length
    await vi.advanceTimersByTimeAsync(POLL_MS * 4)
    expect(fetchMock.mock.calls.length).toBe(after)
  })

  it('backs the sidebar poll off while the server is unreachable', async () => {
    // refresh() reports failure to lib/poll.js by returning false, so a dead
    // panel is polled on a widening interval instead of at full rate. The
    // observable difference: after one failed tick the next fires 1.5x out.
    wrapper = mountShell(router)
    await vi.advanceTimersByTimeAsync(0)

    // Server goes away. client.js retries GETs twice (800ms, 1600ms) before
    // giving up, so the failing tick spans ~2.4s before it reports false.
    fetchMock.mockRejectedValue(Object.assign(new Error('Failed to fetch'), {
      name: 'TypeError',
    }))

    await vi.advanceTimersByTimeAsync(POLL_MS) // tick fires…
    await vi.advanceTimersByTimeAsync(5000) // …and finishes its retries
    const afterFirstFailure = statusCalls(fetchMock)

    // On the un-backed-off schedule the next tick would land 15s after the
    // failed one completed; at 1.5x it must not have fired yet.
    await vi.advanceTimersByTimeAsync(POLL_MS)
    expect(statusCalls(fetchMock)).toBe(afterFirstFailure)

    // …but it does fire once the backed-off interval elapses.
    await vi.advanceTimersByTimeAsync(POLL_MS)
    expect(statusCalls(fetchMock)).toBeGreaterThan(afterFirstFailure)
  })
})

describe('App shell global error toast', () => {
  // The other half of lib/appError.js: main.js reports uncaught errors via a
  // window event, and the mounted shell must answer with its normal localized
  // toast — the assertive kind, so a screen reader hears it.
  let router
  let wrapper

  beforeEach(async () => {
    await setLocale('en')
    vi.useFakeTimers()
    vi.stubGlobal('scrollTo', vi.fn())
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      statusText: 'OK',
      json: async () => ({ services: [] }),
    }))
    router = makeRouter()
    await router.replace('/')
    await router.isReady()
  })

  afterEach(() => {
    wrapper?.unmount()
    wrapper = undefined
    vi.unstubAllGlobals()
    vi.useRealTimers()
  })

  it('shows a localized error toast when an app-error is reported', async () => {
    wrapper = mountShell(router)
    await vi.advanceTimersByTimeAsync(0)

    window.dispatchEvent(new CustomEvent(APP_ERROR_EVENT, {
      detail: { error: new Error('boom'), context: 'render' },
    }))
    await vi.advanceTimersByTimeAsync(0)

    const toast = wrapper.find('.toast')
    expect(toast.classes()).toContain('show')
    expect(toast.text()).toContain('Something went wrong on this page')
    // Failures interrupt the screen reader; the ⚠ prefix is what flips the
    // toast to role=alert (see toastIsError in App.vue).
    expect(toast.attributes('role')).toBe('alert')
  })

  it('stops reacting to app-errors after the shell unmounts', async () => {
    wrapper = mountShell(router)
    await vi.advanceTimersByTimeAsync(0)
    wrapper.unmount()
    wrapper = undefined

    // A leaked listener would throw on the dead component's refs.
    expect(() => {
      window.dispatchEvent(new CustomEvent(APP_ERROR_EVENT, {
        detail: { error: new Error('late'), context: 'render' },
      }))
    }).not.toThrow()
  })

  it('stops reacting to connectivity and SW-update events after the shell unmounts', async () => {
    wrapper = mountShell(router)
    await vi.advanceTimersByTimeAsync(0)
    wrapper.unmount()
    wrapper = undefined

    expect(() => {
      window.dispatchEvent(new Event('offline'))
      window.dispatchEvent(new Event('online'))
      window.dispatchEvent(new Event('sw-update-ready'))
    }).not.toThrow()
  })
})
