/**
 * The Dashboard polls /api/status every 20s (high: 12s) and the shell's
 * top-bar badge polled the same endpoint every 30s (high: 15s) on top of it.
 * The page now shares each answer with the shell, whose own tick skips while
 * a share is fresh and goes back to its schedule once the page stops.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { h, inject, reactive, ref } from 'vue'

const api = vi.hoisted(() => ({
  AUTH_LOST_EVENT: 'serverhub:auth-lost',
  getAssistantCatalog: vi.fn(() => Promise.resolve({ panels: [] })),
  getPhotosHubStatus: vi.fn(() => Promise.resolve({ photoshub_ok: false })),
  getStatus: vi.fn(),
  logoutAuth: vi.fn(() => Promise.resolve({})),
  putSettings: vi.fn(() => Promise.resolve({})),
}))
// Every poller the shell starts, newest last, so a test can run a tick by hand.
const pollers = vi.hoisted(() => [])

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
vi.mock('./lib/poll', () => ({
  startVisibleInterval: (fn, ms) => {
    pollers.push({ fn, ms })
    return () => {}
  },
}))
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

// What the page in the router view received from the shell.
let share = null
const Page = {
  setup() {
    share = inject('shareStatus', null)
    return () => h('div')
  },
}

function mountShell() {
  return mount(App, {
    attachTo: document.body,
    global: {
      stubs: {
        'router-link': { template: '<a href="#" class="nav-stub"><slot /></a>' },
        'router-view': Page,
        transition: false,
      },
    },
  })
}

/** Runs the shell's status tick, as lib/poll.js would after one interval. */
async function tick() {
  const found = pollers.filter((p) => p.ms === 30000).pop()
  expect(found, 'status poller').toBeTruthy()
  await found.fn()
  await flushPromises()
}

function okCount(wrapper) {
  return wrapper.find('.top-status .pill.ok b').text()
}

beforeEach(() => {
  vi.useFakeTimers({ toFake: ['Date'] })
  vi.setSystemTime(new Date('2026-11-01T00:00:00Z'))
  pollers.length = 0
  share = null
  route.path = '/'
  route.query = {}
  route.meta = {}
  api.getStatus.mockResolvedValue({ counts: { ok: 3 } })
})

afterEach(() => {
  vi.useRealTimers()
  vi.clearAllMocks()
})

describe('shell status poll', () => {
  it('skips its request while the page shares fresh status', async () => {
    const wrapper = mountShell()
    await flushPromises()
    expect(api.getStatus).toHaveBeenCalledTimes(1)
    expect(typeof share).toBe('function')

    // The page's own poll answered; the badge follows it at once.
    vi.advanceTimersByTime(25000)
    share({ counts: { ok: 7 } })
    await flushPromises()
    expect(okCount(wrapper)).toBe('7')

    vi.advanceTimersByTime(5000)
    await tick()
    expect(api.getStatus).toHaveBeenCalledTimes(1)
    expect(okCount(wrapper)).toBe('7')
    wrapper.unmount()
  })

  it('asks again when the last share is a full interval old', async () => {
    const wrapper = mountShell()
    await flushPromises()
    share({ counts: { ok: 7 } })

    // The page stopped answering (its requests fail): nothing shared since.
    vi.advanceTimersByTime(30000)
    await tick()
    expect(api.getStatus).toHaveBeenCalledTimes(2)
    expect(okCount(wrapper)).toBe('3')
    wrapper.unmount()
  })

  it('goes back to its own schedule once the page stops sharing', async () => {
    const wrapper = mountShell()
    await flushPromises()
    share({ counts: { ok: 7 } })
    share(null) // the page unmounted

    vi.advanceTimersByTime(1000)
    await tick()
    expect(api.getStatus).toHaveBeenCalledTimes(2)
    expect(okCount(wrapper)).toBe('3')
    wrapper.unmount()
  })

  it('keeps polling on its own schedule when no page shares', async () => {
    const wrapper = mountShell()
    await flushPromises()
    vi.advanceTimersByTime(30000)
    await tick()
    vi.advanceTimersByTime(30000)
    await tick()
    expect(api.getStatus).toHaveBeenCalledTimes(3)
    wrapper.unmount()
  })
})
