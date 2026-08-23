/**
 * Tools leftover calendar objects must not crash the scheduler tab.
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
    t: (key, params = {}) => Object.entries(params).reduce(
      (text, [name, value]) => text.replace(`{${name}}`, value),
      key,
    ),
  }),
}))
vi.mock('vue-router', () => ({
  useRouter: () => ({ push: vi.fn() }),
  useRoute: () => ({ query: {} }),
}))

import Tools from './Tools.vue'

beforeEach(() => {
  api.getToolsCatalog.mockResolvedValue({ tiles: [] })
  api.getScheduler.mockResolvedValue({ timers: [] })
  api.getToolsAgents.mockResolvedValue({ agents: [], count: 0, hint: '' })
})

afterEach(() => {
  vi.clearAllMocks()
})

describe('Tools leftover calendar', () => {
  it('uses the shared in-page tab chrome', async () => {
    const wrapper = mount(Tools, {
      global: {
        provide: { toast: vi.fn() },
        stubs: {
          RouterLink: { template: '<a><slot /></a>' },
          SkeletonLoader: true,
          LoadFailure: true,
        },
      },
    })
    await flushPromises()
    expect(wrapper.find('.tabs').exists()).toBe(true)
    expect(wrapper.find('.tools-tabs').exists()).toBe(false)
    expect(wrapper.find('.tools-tab').exists()).toBe(false)
    wrapper.unmount()
  })

  it('does not throw when a leftover calendar is not JSON-serializable', async () => {
    const calendar = {}
    calendar.self = calendar
    api.getScheduler.mockResolvedValue({
      timers: [{ label: 'job', calendar, interval_sec: 60, program: '/bin/true' }],
    })
    const wrapper = mount(Tools, {
      global: {
        provide: { toast: vi.fn() },
        stubs: {
          RouterLink: { template: '<a><slot /></a>' },
          SkeletonLoader: true,
          LoadFailure: true,
        },
      },
    })
    await flushPromises()
    await wrapper.findAll('button').find((b) => b.text() === 'tools.tab_sched').trigger('click')
    await flushPromises()
    expect(wrapper.text()).toContain('job')
    wrapper.unmount()
  })
})
