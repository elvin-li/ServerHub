import { describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'

/**
 * Mount every view once and require that it does not throw.
 *
 * This exists because 25 of 28 views had no mount test at all: the a11y suite only
 * reads their source, so a runtime failure — a bad default import, a helper that
 * was never defined, anything that throws in setup — shipped undetected. That is
 * how the WireGuard page reached production in a state where it simply never
 * opened.
 *
 * It is deliberately a smoke test. It does not assert what a page renders, only
 * that mounting it, resolving its initial requests, and unmounting it are all
 * survivable. Anything stronger needs per-view fixtures, which is what the
 * dedicated test files next to this one are for.
 */

// Every API call resolves to a value that is safe to read, index, iterate and
// call. Hand-written fixtures for 28 views would be unmaintainable, and a plain
// `{}` would fail on `data.items.map(...)` for reasons that say nothing about the
// view's correctness.
//
// Built inside the factory because vi.mock is hoisted above every import, so it
// cannot reference anything declared at module scope.
vi.mock('../api/client', async () => {
  const actual = await vi.importActual('../api/client')

  const permissive = () => {
    const target = function permissiveTarget() { return permissive() }
    return new Proxy(target, {
      get(_t, prop) {
        // Must not look like a promise, or awaiting it recurses forever.
        if (prop === 'then' || prop === 'catch' || prop === 'finally') return undefined
        if (prop === Symbol.toPrimitive) return () => ''
        if (prop === Symbol.iterator) return [][Symbol.iterator].bind([])
        if (prop === 'length') return 0
        if (prop === 'toJSON') return () => ({})
        if (prop === 'toString' || prop === Symbol.toStringTag) return () => ''
        // Array-ish reads used constantly in templates.
        if (['map', 'filter', 'slice', 'flatMap', 'concat', 'sort', 'reverse'].includes(prop)) {
          return () => []
        }
        if (prop === 'join') return () => ''
        if (prop === 'find' || prop === 'reduce') return () => undefined
        if (['includes', 'some', 'every'].includes(prop)) return () => false
        return permissive()
      },
      has: () => true,
    })
  }

  return Object.fromEntries(
    Object.keys(actual).map((name) => {
      const value = actual[name]
      // Non-function exports (event name constants) must keep their real value.
      if (typeof value !== 'function') return [name, value]
      return [name, vi.fn(async () => permissive())]
    }),
  )
})

vi.mock('../i18n', () => ({
  injectI18n: () => ({
    t: (key, params = {}) => Object.entries(params).reduce(
      (text, [name, value]) => text.replace(`{${name}}`, value),
      String(key),
    ),
    locale: { value: 'en' },
    setLocale: vi.fn(),
  }),
}))
// Apps, Login and Tools call useRouter/useRoute. A stubbed RouterLink is
// not a router, and Vue 3 logs an inject miss on every smoke mount.
vi.mock('vue-router', () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
  useRoute: () => ({ path: '/', query: {}, params: {}, name: 'home' }),
}))
// Real timers in a smoke test would leave 28 pollers running.
vi.mock('../lib/poll', () => ({ startVisibleInterval: () => () => {} }))

const views = import.meta.glob('./*.vue')

// Terminal and the VNC console attach to real DOM/WebSocket machinery that jsdom
// does not provide; they have no meaningful smoke coverage here.
const SKIP = new Set(['./Terminal.vue'])

describe('every view mounts', () => {
  const paths = Object.keys(views).filter((p) => !SKIP.has(p)).sort()

  it('covers the whole views directory', () => {
    // Guards the glob: a typo that matched nothing would make every case below
    // pass without mounting anything.
    expect(paths.length).toBeGreaterThan(20)
  })

  for (const path of paths) {
    it(`${path.replace('./', '').replace('.vue', '')} mounts and unmounts cleanly`, async () => {
      const module = await views[path]()
      const errors = []
      const wrapper = mount(module.default, {
        global: {
          provide: { toast: vi.fn() },
          stubs: { RouterLink: true, RouterView: true },
          config: { errorHandler: (err) => errors.push(err) },
          mocks: { $route: { path: '/', query: {}, params: {} }, $router: { push: vi.fn() } },
        },
      })
      await flushPromises()
      expect(errors, `${path} threw during render`).toEqual([])
      expect(wrapper.html()).toBeTruthy()
      wrapper.unmount()
    })
  }
})
