/**
 * The storage tables must say "nothing here", not render bare headers.
 *
 * Companion to emptyTables.test.js (which covers the Network tabs): the
 * MainArray SMART-disks and Volumes tables, and the Dashboard storage-array
 * tile, all looped straight over `data.disks` / `data.volumes` with no empty
 * row, so a Mac that reports no disks -- or a storage probe still in flight --
 * showed column headings above nothing at all.  Mounted, not pattern-matched,
 * for the same reason as the Network file: what matters is what renders.
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
  getSmartOverview: vi.fn(),
  getStatus: vi.fn(),
  getStorage: vi.fn(),
  getThresholds: vi.fn(),
  getUps: vi.fn(),
  manageStorageDevice: vi.fn(),
  powerAction: vi.fn(),
  setDiskPower: vi.fn(),
  setSystemSharing: vi.fn(),
  startSmartTest: vi.fn(),
}))
vi.mock('../api/client', () => api)
vi.mock('../lib/poll', () => ({ startVisibleInterval: () => () => {} }))
vi.mock('../theme', () => ({
  injectTheme: () => ({
    theme: { value: 'unraid' },
    resolveThemeId: (id) => id,
    themes: [],
    setTheme: vi.fn(),
  }),
}))
vi.mock('../i18n', () => ({
  injectI18n: () => ({
    t: (key) => key,
    errText: (v) => String(v),
  }),
}))

import MainArray from './MainArray.vue'
import Dashboard from './Dashboard.vue'

/** Column headings of every rendered table that has a head and no body rows. */
function headerOnlyTables(wrapper) {
  const bare = []
  for (const table of wrapper.element.querySelectorAll('table')) {
    if (!table.querySelector('thead tr')) continue
    if (table.querySelector('tbody tr')) continue
    bare.push([...table.querySelectorAll('thead th')].map((th) => th.textContent.trim()).join(' | '))
  }
  return bare
}

const MOUNT = {
  global: {
    provide: { toast: vi.fn() },
    stubs: {
      RouterLink: { template: '<a><slot /></a>' },
      SkeletonLoader: true,
      LoadFailure: true,
      LineChart: true,
      StackBar: true,
    },
  },
}

beforeEach(() => {
  for (const fn of Object.values(api)) fn.mockReset()
  api.getStorage.mockResolvedValue({
    array: { status: 'started', devices: [], disk_count: 0 },
    totals: {},
    volumes: [],
    disks: [],
    power_disks: [],
    managed: { volumes: [], fs_types: [] },
  })
  api.getThresholds.mockResolvedValue({})
  api.getSmartOverview.mockResolvedValue({ devices: [] })
  api.getAlerts.mockResolvedValue({ alerts: [] })
  api.getBookmarks.mockResolvedValue({ bookmarks: [] })
  api.getContainers.mockResolvedValue({ containers: [], stats: {} })
  api.getHealthChecks.mockResolvedValue({ summary: { ok: 0, warn: 0, error: 0 }, checks: [] })
  api.getHost.mockResolvedValue({ hostname: 'test-host', ncpu: 8 })
  api.getListeningPorts.mockResolvedValue({ ports: [] })
  api.getMetricsRange.mockResolvedValue({ points: [], tier: 'raw', since: 0, until: 1 })
  api.getOllamaStatus.mockResolvedValue({ installed: false, reachable: false })
  api.getPower.mockResolvedValue({})
  api.getSensors.mockResolvedValue({ cpu: {}, memory: {}, network: {} })
  api.getStatus.mockResolvedValue({ groups: [] })
  api.getUps.mockResolvedValue({ present: false })
})

afterEach(() => {
  vi.clearAllMocks()
})

describe('storage empty tables', () => {
  it('explains every empty MainArray table instead of showing a bare header', async () => {
    const wrapper = mount(MainArray, MOUNT)
    await flushPromises()
    expect(headerOnlyTables(wrapper), 'headings with no rows read as still-loading').toEqual([])
    // The two tables this file exists for, by their own copy.
    const text = wrapper.text()
    expect(text).toContain('main_extra.empty_disks')
    expect(text).toContain('main_extra.empty_volumes')
    wrapper.unmount()
  })

  it('tells an empty Dashboard array tile apart from one still loading', async () => {
    const wrapper = mount(Dashboard, MOUNT)
    await flushPromises()
    await flushPromises()
    expect(wrapper.text()).toContain('main_extra.empty_volumes')
    expect(wrapper.text()).not.toContain('common.loading')
    wrapper.unmount()
  })

  it('keeps saying loading while the storage probe is in flight', async () => {
    let resolveStorage
    api.getStorage.mockImplementation(() => new Promise((resolve) => { resolveStorage = resolve }))
    const wrapper = mount(Dashboard, MOUNT)
    await flushPromises()
    expect(wrapper.text()).toContain('common.loading')
    expect(wrapper.text()).not.toContain('main_extra.empty_volumes')
    resolveStorage({ volumes: [], disks: [] })
    await flushPromises()
    expect(wrapper.text()).toContain('main_extra.empty_volumes')
    wrapper.unmount()
  })
})
