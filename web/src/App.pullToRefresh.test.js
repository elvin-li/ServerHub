/**
 * Pull-to-refresh needs a blocking (non-passive) touchmove listener: a pull
 * past 80px calls preventDefault().  While such a listener sits on the
 * document, a phone's browser has to run the page's script before it may
 * scroll, so the shell registers it only while the page is at the top, the
 * one place a pull can start.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { reactive, ref } from 'vue'

const api = vi.hoisted(() => ({
  AUTH_LOST_EVENT: 'serverhub:auth-lost',
  getAssistantCatalog: vi.fn(() => Promise.resolve({ panels: [] })),
  getPhotosHubStatus: vi.fn(() => Promise.resolve({ photoshub_ok: false })),
  getStatus: vi.fn(() => Promise.resolve({})),
  logoutAuth: vi.fn(() => Promise.resolve({})),
  putSettings: vi.fn(() => Promise.resolve({})),
}))

vi.mock('./api/client', () => api)
vi.mock('./i18n', () => ({
  injectI18n: () => ({ t: (k) => k, locale: ref('en'), locales: [], setLocale: vi.fn() }),
}))
vi.mock('./theme', () => ({
  injectTheme: () => ({
    theme: ref('dark'),
    themes: [],
    setTheme: vi.fn(),
    setFollowSystem: vi.fn(),
    followSystem: ref(false),
  }),
}))
vi.mock('./lib/poll', () => ({ startVisibleInterval: () => () => {} }))
vi.mock('./lib/adminPassword', () => ({ clearAdminPassword: vi.fn() }))
vi.mock('./components/AdminPasswordDialog.vue', () => ({
  default: { name: 'AdminPasswordDialog', render: () => null },
}))
vi.mock('./composables/useDismissable', () => ({ useDismissable: vi.fn() }))

const route = reactive({ path: '/', query: {}, meta: {}, fullPath: '/' })
vi.mock('vue-router', () => ({
  useRoute: () => route,
  useRouter: () => ({ replace: vi.fn(), push: vi.fn() }),
}))

import App from './App.vue'

// The touchmove listeners on the document right now, with the options each
// was added with, and how many times one was added.  Tracked through an own
// property over the inherited EventTarget methods; deleting it restores them.
let moves
let moveAdds

beforeEach(() => {
  moves = new Map()
  moveAdds = 0
  const add = EventTarget.prototype.addEventListener
  const remove = EventTarget.prototype.removeEventListener
  document.addEventListener = function (type, fn, opts) {
    if (type === 'touchmove') {
      moves.set(fn, opts)
      moveAdds += 1
    }
    return add.call(this, type, fn, opts)
  }
  document.removeEventListener = function (type, fn, opts) {
    if (type === 'touchmove') moves.delete(fn)
    return remove.call(this, type, fn, opts)
  }
  window.scrollY = 0
  route.path = '/'
  route.query = {}
  route.meta = {}
})

// Shells still mounted.  A test that fails midway would otherwise leave its
// shell's document listeners behind to answer the next test's touches.
let shells = []

afterEach(() => {
  for (const shell of shells) shell.unmount()
  shells = []
  delete document.addEventListener
  delete document.removeEventListener
  window.scrollY = 0
  vi.clearAllMocks()
})

function mountShell() {
  const shell = mount(App, {
    attachTo: document.body,
    global: {
      stubs: {
        'router-link': { template: '<a href="#" class="nav-stub"><slot /></a>' },
        'router-view': { template: '<div />' },
        transition: false,
      },
    },
  })
  shells.push(shell)
  return shell
}

function unmountShell(shell) {
  shells = shells.filter((s) => s !== shell)
  shell.unmount()
}

function scrollPage(y) {
  window.scrollY = y
  window.dispatchEvent(new Event('scroll'))
}

/** A touch event the shell can read: its handlers use touches[0].clientY. */
function touch(type, y) {
  const ev = new Event(type, { bubbles: true, cancelable: true })
  Object.defineProperty(ev, 'touches', { value: y == null ? [] : [{ clientY: y }] })
  document.dispatchEvent(ev)
  return ev
}

describe('pull-to-refresh listener', () => {
  it('blocks touchmove only while the page is at the top', async () => {
    const wrapper = mountShell()
    await flushPromises()
    expect([...moves.values()]).toEqual([{ passive: false }])

    scrollPage(400)
    expect(moves.size).toBe(0)
    // Further scrolling does not churn the listener.
    scrollPage(450)
    scrollPage(800)
    expect(moves.size).toBe(0)

    scrollPage(0)
    expect([...moves.values()]).toEqual([{ passive: false }])
    expect(moveAdds).toBe(2)

    unmountShell(wrapper)
    expect(moves.size).toBe(0)
  })

  it('still turns a pull at the top into a refresh', async () => {
    const wrapper = mountShell()
    await flushPromises()
    const before = api.getStatus.mock.calls.length
    const refreshed = vi.fn()
    window.addEventListener('ptr-refresh', refreshed)

    touch('touchstart', 100)
    const move = touch('touchmove', 200)
    // Past 80px the page's own overscroll is stopped.
    expect(move.defaultPrevented).toBe(true)
    await flushPromises()
    expect(wrapper.get('.ptr-indicator').classes()).toContain('visible')

    touch('touchend')
    await flushPromises()
    expect(api.getStatus.mock.calls.length).toBe(before + 1)
    expect(refreshed).toHaveBeenCalledTimes(1)

    window.removeEventListener('ptr-refresh', refreshed)
    unmountShell(wrapper)
  })

  it('does not start a pull on a scrolled page', async () => {
    const wrapper = mountShell()
    await flushPromises()
    const before = api.getStatus.mock.calls.length
    scrollPage(300)

    touch('touchstart', 100)
    const move = touch('touchmove', 300)
    touch('touchend')
    await flushPromises()
    expect(move.defaultPrevented).toBe(false)
    expect(wrapper.get('.ptr-indicator').classes()).not.toContain('visible')
    expect(api.getStatus.mock.calls.length).toBe(before)
    unmountShell(wrapper)
  })

  it('keeps a pull that began at the top live until its touchend', async () => {
    const wrapper = mountShell()
    await flushPromises()
    const before = api.getStatus.mock.calls.length

    touch('touchstart', 100)
    touch('touchmove', 170)
    await flushPromises()
    expect(wrapper.get('.ptr-indicator').classes()).toContain('visible')

    // The finger turns back and the page scrolls off the top mid-gesture.
    scrollPage(30)
    expect([...moves.values()]).toEqual([{ passive: false }])
    touch('touchmove', 120)
    await flushPromises()
    expect(wrapper.get('.ptr-indicator').classes()).not.toContain('visible')

    touch('touchend')
    await flushPromises()
    expect(api.getStatus.mock.calls.length).toBe(before)
    // The gesture is over and the page is off the top.
    expect(moves.size).toBe(0)
    unmountShell(wrapper)
  })

  it('arms again when the page reached the top without a scroll event', async () => {
    const wrapper = mountShell()
    await flushPromises()
    scrollPage(300)
    expect(moves.size).toBe(0)

    // The content shrank under the page; no scroll event was seen.
    window.scrollY = 0
    touch('touchstart', 100)
    expect([...moves.values()]).toEqual([{ passive: false }])
    touch('touchend')
    unmountShell(wrapper)
  })
})
