/**
 * A sensors tick that comes due while the full sensors request is still on
 * the wire shares that request instead of sending a second one.  The second
 * request used to take a newer generation, so the full answer (Top CPU,
 * RX/TX) was discarded when it arrived.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'

const api = vi.hoisted(() => ({
  doAction: vi.fn(),
  getAlerts: vi.fn(),
  getBookmarks: vi.fn(),
  getContainers: vi.fn(),
  getHealthChecks: vi.fn(),
  getHost: vi.fn(),
  getListeningPorts: vi.fn(),
  getMetricsRange: vi.fn(),
  getOllamaStatus: vi.fn(),
  getPower: vi.fn(),
  getSensors: vi.fn(),
  getStatus: vi.fn(),
  getStorage: vi.fn(),
  getUps: vi.fn(),
  powerAction: vi.fn(),
  setSystemSharing: vi.fn(),
}))

// Every poller the view starts, newest last, so a test can run a tick by hand.
const pollers = vi.hoisted(() => [])

vi.mock('../api/client', () => api)
vi.mock('../lib/poll', () => ({
  startVisibleInterval: (fn, ms) => {
    pollers.push({ fn, ms })
    return () => {}
  },
}))
vi.mock('../theme', () => ({
  injectTheme: () => ({
    theme: { value: 'macos' },
    resolveThemeId: () => 'macos',
    themes: [],
    setTheme: vi.fn(),
  }),
}))
vi.mock('../i18n', () => ({
  injectI18n: () => ({
    t: (key, params = {}) => Object.entries(params).reduce(
      (text, [name, value]) => text.replace(`{${name}}`, value),
      String(key),
    ),
    errText: (v) => String(v),
  }),
}))

import Dashboard from './Dashboard.vue'

const FULL = {
  cpu: {},
  memory: {},
  network: {},
  top_processes: [{ pid: 7, name: 'busyproc', cpu: 42, mem: 1, rss_mb: 12 }],
}
const LIGHT = { cpu: {}, memory: {}, network: {}, top_processes: [] }

function deferred() {
  let resolve
  const promise = new Promise((r) => { resolve = r })
  return { promise, resolve }
}

/** The newest poller running at `ms`: the sensors tick is the 20s/12s one. */
function poller(ms) {
  const found = pollers.filter((p) => p.ms === ms).pop()
  expect(found, `poller every ${ms}ms`).toBeTruthy()
  return found.fn
}

async function mountDash() {
  const wrapper = mount(Dashboard, {
    global: {
      provide: { toast: vi.fn() },
      stubs: {
        RouterLink: { template: '<a class="router-link-stub"><slot /></a>' },
        LineChart: true,
        StackBar: true,
      },
    },
  })
  await flushPromises()
  await flushPromises()
  return wrapper
}

beforeEach(() => {
  pollers.length = 0
  api.getAlerts.mockResolvedValue({ alerts: [] })
  api.getBookmarks.mockResolvedValue({ bookmarks: [] })
  api.getContainers.mockResolvedValue({ containers: [], stats: {} })
  api.getHealthChecks.mockResolvedValue({ summary: { ok: 0, warn: 0, error: 0 }, checks: [] })
  api.getHost.mockResolvedValue({ hostname: 'test-host', ncpu: 8 })
  api.getListeningPorts.mockResolvedValue({ ports: [] })
  api.getMetricsRange.mockResolvedValue({ points: [], tier: 'raw', since: 0, until: 1 })
  api.getOllamaStatus.mockResolvedValue({ installed: false, reachable: false })
  api.getPower.mockResolvedValue({ screen_sharing: { running: false } })
  api.getStatus.mockResolvedValue({ groups: [] })
  api.getStorage.mockResolvedValue({ volumes: [], disks: [] })
  api.getUps.mockResolvedValue({ present: false })
})

afterEach(() => {
  vi.clearAllMocks()
})

describe('Dashboard sensors requests in flight', () => {
  it('lets a light tick share the full request and keeps the full answer', async () => {
    const full = deferred()
    api.getSensors.mockImplementation((_force, { light } = {}) =>
      (light ? Promise.resolve(LIGHT) : full.promise))
    const wrapper = await mountDash()
    expect(api.getSensors).toHaveBeenCalledTimes(1)
    expect(api.getSensors).toHaveBeenLastCalledWith(false, { light: false })

    // The 20s tick comes due while the first-paint full collect is running.
    const tick = poller(20000)()
    await flushPromises()
    expect(api.getSensors).toHaveBeenCalledTimes(1)

    full.resolve(FULL)
    await tick
    await flushPromises()
    expect(wrapper.text()).toContain('busyproc')

    // Once it has landed, the next tick is light again.
    await poller(20000)()
    expect(api.getSensors).toHaveBeenCalledTimes(2)
    expect(api.getSensors).toHaveBeenLastCalledWith(false, { light: true })
    // The light answer merges into the full one rather than replacing it.
    await flushPromises()
    expect(wrapper.text()).toContain('busyproc')
  })

  it('shares the full request between the high-mode ticks', async () => {
    api.getStatus.mockResolvedValue({ resource_mode: 'high', groups: [] })
    const full = deferred()
    api.getSensors.mockImplementation(() => full.promise)
    await mountDash()
    expect(api.getSensors).toHaveBeenCalledTimes(1)

    const tick = poller(12000)()
    await flushPromises()
    expect(api.getSensors).toHaveBeenCalledTimes(1)

    full.resolve(FULL)
    await tick
  })

  it('still re-probes on Refresh while a scheduled request is in flight', async () => {
    const full = deferred()
    api.getSensors.mockImplementation((force) => (force ? Promise.resolve(FULL) : full.promise))
    const wrapper = await mountDash()
    expect(api.getSensors).toHaveBeenCalledTimes(1)

    const refresh = wrapper.findAll('button').find((b) => b.text() === 'common.refresh')
    expect(refresh, 'Refresh button').toBeTruthy()
    await refresh.trigger('click')
    await flushPromises()
    expect(api.getSensors).toHaveBeenCalledTimes(2)
    expect(api.getSensors).toHaveBeenLastCalledWith(true, { light: false })

    full.resolve(LIGHT)
    await flushPromises()
  })
})
