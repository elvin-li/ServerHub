/**
 * Polling pages must *report* a dead server, not merely survive one.
 *
 * lib/poll.js backs off exponentially while ticks fail — but a tick only
 * counts as failed when the callback rejects or resolves to exactly `false`
 * (poll.test.js pins that contract). Every polling view catches its own
 * errors to drive its failure banner, and most then returned `undefined`,
 * which reads as success: with the panel's backend down or restarting, a tab
 * full of open pages kept polling at full rate for hours.
 *
 * This mounts each polling view against a client whose every call rejects and
 * asserts that every poll callback the view registered resolves to `false`,
 * i.e. the page actually engages the backoff. Logs.vue and Maintenance.vue
 * already did this before the sweep and are covered by their own structural
 * checks; Scheduler.vue's conditional loop has its own lifecycle test.
 */
import { afterEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'

const polls = vi.hoisted(() => ({ callbacks: [] }))

vi.mock('../i18n', () => ({
  injectI18n: () => ({ t: (k) => k, locale: { value: 'en' }, setLocale: vi.fn() }),
}))
vi.mock('../theme', () => ({
  injectTheme: () => ({
    theme: { value: 'unraid' },
    resolveThemeId: (id) => id,
    themes: [],
    setTheme: vi.fn(),
  }),
}))
vi.mock('vue-router', () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
  useRoute: () => ({ path: '/', query: {}, params: {}, name: 'home' }),
}))
// Capture every poll callback a view registers instead of running timers.
vi.mock('../lib/poll', () => ({
  startVisibleInterval: (fn) => {
    polls.callbacks.push(fn)
    return () => {}
  },
}))

function withDeadServer() {
  vi.doMock('../api/client', async () => {
    const actual = await vi.importActual('../api/client')
    return Object.fromEntries(
      Object.keys(actual).map((name) => [
        name,
        typeof actual[name] === 'function'
          ? vi.fn(async () => { throw new Error('backend unreachable') })
          : actual[name],
      ]),
    )
  })
  vi.resetModules()
}

async function mountAgainstDeadServer(load) {
  withDeadServer()
  polls.callbacks.length = 0
  const toast = vi.fn()
  const module = await load()
  const wrapper = mount(module.default, {
    global: {
      provide: { toast },
      stubs: { RouterLink: true, RouterView: true },
      mocks: { $route: { path: '/', query: {}, params: {} }, $router: { push: vi.fn() } },
    },
  })
  await flushPromises()
  return { wrapper, toast }
}

function release(wrapper) {
  wrapper.unmount()
  vi.doUnmock('../api/client')
  vi.resetModules()
}

describe('poll callbacks report a dead server to lib/poll.js', () => {
  // Dashboard registers two pollers (20s light, 90s heavy); the rest one each.
  const CASES = [
    { name: 'Dashboard', load: () => import('./Dashboard.vue'), pollers: 2 },
    { name: 'Services', load: () => import('./Services.vue'), pollers: 1 },
    { name: 'Containers', load: () => import('./Containers.vue'), pollers: 1 },
    { name: 'Apps', load: () => import('./Apps.vue'), pollers: 1 },
    { name: 'VMs', load: () => import('./VMs.vue'), pollers: 1 },
    { name: 'WireGuard', load: () => import('./WireGuard.vue'), pollers: 1 },
    { name: 'MainArray', load: () => import('./MainArray.vue'), pollers: 1 },
  ]

  let wrapper

  afterEach(() => {
    if (wrapper) release(wrapper)
    wrapper = undefined
  })

  for (const { name, load, pollers } of CASES) {
    it(`${name} resolves every poll tick to false while the backend is unreachable`, async () => {
      const mounted = await mountAgainstDeadServer(load)
      wrapper = mounted.wrapper

      // Guards the harness: a view that stopped registering its poll through
      // lib/poll.js would otherwise pass vacuously.
      expect(polls.callbacks.length).toBe(pollers)

      // Background ticks must also stay quiet: backoff still leaves a failing
      // tick every ~90s, and a page that toasts each one turns an outage into
      // a stream of identical toasts (announced assertively by the screen
      // reader). The on-screen LoadFailure banner already carries the state;
      // only manual Refresh/retry clicks may toast.
      mounted.toast.mockClear()
      for (const tick of polls.callbacks) {
        expect(await tick()).toBe(false)
      }
      expect(mounted.toast).not.toHaveBeenCalled()
    })
  }
})
