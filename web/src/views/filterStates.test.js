/**
 * A filter that matches nothing must say "no match", not "none".
 *
 * The Tools process list and the Scheduler launchd table each carry a text
 * filter, and both used a single string for their empty row. Tools always said
 * "no match" — so a host that reported no processes at all looked like a typo
 * in the filter box — and Scheduler always said "none" — so a filter miss on a
 * host full of timers claimed the host had no timers. Network's listening list
 * already tells the two apart (emptyTables.test.js pins it), so the pattern is
 * established.
 *
 * The filters also announce their result count through role="status", the same
 * way the Services filter does: the count is the only feedback the box gives,
 * and it used to change silently for a screen reader.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'

const api = vi.hoisted(() => ({
  // Tools
  flushDns: vi.fn(),
  generateDiagnostics: vi.fn(),
  getDockerContainerSizes: vi.fn(),
  getDockerDiskUsage: vi.fn(),
  getListeningPorts: vi.fn(),
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
  // Scheduler
  getScheduler: vi.fn(),
  getSchedulerJobs: vi.fn(),
  getSchedulerJobRuns: vi.fn(),
  createSchedulerJob: vi.fn(),
  updateSchedulerJob: vi.fn(),
  deleteSchedulerJob: vi.fn(),
  enableSchedulerJob: vi.fn(),
  runSchedulerJobNow: vi.fn(),
}))
vi.mock('../api/client', () => api)
vi.mock('../i18n', () => ({
  injectI18n: () => ({ t: (key) => key, errText: (v) => String(v), locale: { value: 'en' } }),
}))
vi.mock('vue-router', () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
  useRoute: () => ({ path: '/tools', query: { tab: 'proc' }, params: {}, name: 'tools' }),
}))

import Tools from './Tools.vue'
import Scheduler from './Scheduler.vue'

const MOUNT = {
  global: {
    provide: { toast: vi.fn() },
    stubs: { RouterLink: { template: '<a><slot /></a>' } },
  },
}

beforeEach(() => {
  for (const fn of Object.values(api)) {
    if (typeof fn?.mockReset === 'function') fn.mockResolvedValue({})
  }
})

afterEach(() => {
  vi.clearAllMocks()
})

describe('Tools process filter', () => {
  const PROC = { pid: 1, user: 'root', cpu: 0.1, mem: 0.2, time: '0:01', command: 'launchd' }

  it('tells a filter miss apart from a host with no processes', async () => {
    api.getSystemProcesses.mockResolvedValue({ processes: [PROC] })
    const wrapper = mount(Tools, MOUNT)
    await flushPromises()

    expect(wrapper.find('tbody').text()).toContain('launchd')

    wrapper.vm.procQ = 'no-such-process'
    await flushPromises()
    const missed = wrapper.find('tbody').text()
    expect(missed).toContain('common.no_match')
    expect(missed).not.toContain('tools.no_data')
    wrapper.unmount()
  })

  it('reports an empty process list as no data, not as a filter miss', async () => {
    api.getSystemProcesses.mockResolvedValue({ processes: [] })
    const wrapper = mount(Tools, MOUNT)
    await flushPromises()

    const body = wrapper.find('tbody').text()
    expect(body).toContain('tools.no_data')
    expect(body).not.toContain('common.no_match')
    wrapper.unmount()
  })

  it('announces the result count next to the filter box', async () => {
    api.getSystemProcesses.mockResolvedValue({ processes: [PROC] })
    const wrapper = mount(Tools, MOUNT)
    await flushPromises()

    const count = wrapper.find('.meta-count[role="status"]')
    expect(count.exists(), 'live result count').toBe(true)
    expect(count.text()).toBe('1 / 1')
    wrapper.unmount()
  })
})

describe('Scheduler launchd filter', () => {
  const TIMER = { label: 'com.apple.softwareupdate', program: '/usr/libexec/su', interval_sec: 3600 }

  async function mountSystemTab() {
    const wrapper = mount(Scheduler, MOUNT)
    await flushPromises()
    wrapper.vm.tab = 'system'
    await flushPromises()
    return wrapper
  }

  it('tells a filter miss apart from a host with no timers', async () => {
    api.getScheduler.mockResolvedValue({ timers: [TIMER], count: 1 })
    api.getSchedulerJobs.mockResolvedValue({ jobs: [] })
    const wrapper = await mountSystemTab()

    expect(wrapper.text()).toContain('com.apple.softwareupdate')

    wrapper.vm.q = 'no-such-timer'
    await flushPromises()
    const missed = wrapper.text()
    expect(missed).toContain('common.no_match')
    expect(missed).not.toContain('common.none')
    wrapper.unmount()
  })

  it('reports an empty timer list as none, not as a filter miss', async () => {
    api.getScheduler.mockResolvedValue({ timers: [], count: 0 })
    api.getSchedulerJobs.mockResolvedValue({ jobs: [] })
    const wrapper = await mountSystemTab()

    const text = wrapper.text()
    expect(text).toContain('common.none')
    expect(text).not.toContain('common.no_match')
    wrapper.unmount()
  })

  it('announces the result count next to the filter box', async () => {
    api.getScheduler.mockResolvedValue({ timers: [TIMER], count: 1 })
    api.getSchedulerJobs.mockResolvedValue({ jobs: [] })
    const wrapper = await mountSystemTab()

    const count = wrapper.find('.meta-count[role="status"]')
    expect(count.exists(), 'live result count').toBe(true)
    expect(count.text()).toBe('1 / 1')
    wrapper.unmount()
  })
})
