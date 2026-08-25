/**
 * The Tools docker tab with the engine (or its vanished CLI) down.
 *
 * The backend now classifies a docker CLI that vanished mid-request the same
 * way as a stopped daemon: GET /api/docker/df answers engine_up:false and
 * POST /api/tools/docker/prune answers the coded soft-fail
 * container.engine_down.  This pins what the page does with those answers:
 *
 * - both empty tables say "engine off", not "no data" — the container-size
 *   list used to claim "no data" directly under a df row saying the engine
 *   was down, which read as two contradictory facts about the same engine;
 * - a coded prune refusal lands in the role=status line translated, not as
 *   the raw sentinel;
 * - the scheduler timer count is a live region like its syslog/ports
 *   siblings, so a Refresh announces the new number.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'

const api = vi.hoisted(() => ({
  flushDns: vi.fn(),
  generateDiagnostics: vi.fn(),
  getDockerContainerSizes: vi.fn(),
  getDockerDiskUsage: vi.fn(),
  getListeningPorts: vi.fn(),
  getScheduler: vi.fn(),
  getSystemDiagnostics: vi.fn(),
  getSystemProcesses: vi.fn(),
  getSystemScheduler: vi.fn(),
  getToolsAbout: vi.fn(),
  getToolsAgents: vi.fn(),
  getToolsCatalog: vi.fn(),
  getToolsHardware: vi.fn(),
  getToolsSyslog: vi.fn(),
  getToolsUpdates: vi.fn(),
  applyServerHubUpdate: vi.fn(),
  applyBrewUpgrade: vi.fn(),
  getMaintenanceLog: vi.fn(),
  lookupDns: vi.fn(),
  pingHost: vi.fn(),
  pruneDocker: vi.fn(),
}))
vi.mock('../api/client', () => api)
vi.mock('../i18n', () => ({
  injectI18n: () => ({
    t: (key, params = {}) => {
      const values = Object.values(params)
      return values.length ? `${key} ${values.join(' ')}` : key
    },
  }),
}))
vi.mock('vue-router', () => ({
  useRouter: () => ({ push: vi.fn() }),
  useRoute: () => ({ query: {} }),
}))

import Tools from './Tools.vue'

const MOUNT = {
  global: {
    provide: { toast: vi.fn() },
    stubs: {
      RouterLink: { template: '<a><slot /></a>' },
      SkeletonLoader: true,
    },
  },
}

async function mountOnTab(tabLabel) {
  const wrapper = mount(Tools, MOUNT)
  await flushPromises()
  await wrapper.findAll('button').find((b) => b.text() === tabLabel).trigger('click')
  await flushPromises()
  return wrapper
}

beforeEach(() => {
  for (const fn of Object.values(api)) {
    if (typeof fn?.mockResolvedValue === 'function') fn.mockResolvedValue({})
  }
  api.getToolsCatalog.mockResolvedValue({ tiles: [] })
  api.getDockerDiskUsage.mockResolvedValue({ engine_up: false, raw: '', lines: [] })
  api.getDockerContainerSizes.mockResolvedValue({ containers: [] })
  api.getScheduler.mockResolvedValue({ timers: [] })
  api.getToolsAgents.mockResolvedValue({ agents: [], count: 0, hint: '' })
})

afterEach(() => {
  vi.clearAllMocks()
  vi.unstubAllGlobals()
})

describe('Tools docker tab with the engine down', () => {
  it('says engine-off in both empty tables instead of contradicting itself', async () => {
    const wrapper = await mountOnTab('tools.tab_docker')
    const emptyRows = wrapper.findAll('.empty-row').map((r) => r.text())
    expect(emptyRows).toHaveLength(2)
    expect(emptyRows[0]).toBe('tools.engine_off')
    expect(emptyRows[1]).toBe('tools.engine_off')
    expect(wrapper.text()).not.toContain('tools.no_data')
    wrapper.unmount()
  })

  it('keeps "no data" for an empty size list while the engine is up', async () => {
    api.getDockerDiskUsage.mockResolvedValue({
      engine_up: true,
      raw: '',
      lines: [{ type: 'Images', total: '1', active: '1', size: '10MB', reclaimable: '5MB' }],
    })
    const wrapper = await mountOnTab('tools.tab_docker')
    const emptyRows = wrapper.findAll('.empty-row').map((r) => r.text())
    expect(emptyRows).toEqual(['tools.no_data'])
    wrapper.unmount()
  })

  it('announces a coded prune refusal instead of the raw sentinel', async () => {
    vi.stubGlobal('confirm', () => true)
    api.pruneDocker.mockResolvedValue({
      ok: false,
      code: 'container.engine_down',
      message: 'the Docker engine is not running',
      what: 'dangling',
      df: null,
    })
    const wrapper = await mountOnTab('tools.tab_docker')
    await wrapper.findAll('button').find((b) => b.text() === 'tools.prune_dangling').trigger('click')
    await flushPromises()
    const status = wrapper.findAll('[role="status"]').find((n) => n.text().length > 0)
    expect(status).toBeTruthy()
    // The mocked t() returns the key, so softText falls back to the coded
    // English message — never the two-word spawn sentinel.
    expect(status.text()).toBe('the Docker engine is not running')
    wrapper.unmount()
  })
})

describe('Tools scheduler timer count', () => {
  it('is a live region that announces the refreshed number', async () => {
    api.getScheduler.mockResolvedValue({
      timers: [{ label: 'a', interval_sec: 60, calendar: null, program: 'true' }],
    })
    const wrapper = await mountOnTab('tools.tab_sched')
    const count = wrapper.get('.toolbar [role="status"]')
    expect(count.text()).toBe('tools.tasks_n 1')
    wrapper.unmount()
  })
})
