/**
 * Tools tab announcements and failure banners.
 *
 * Behavioural half of the a11y.test.js "logs and tools surface leftovers"
 * pins: the syslog banner must survive stale lines, the syslog/ports counts
 * must be live regions with real labels, and the scrollable panes must be
 * reachable by the keyboard.
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
    // Keys carry no {placeholders}, so append the params instead: the count
    // tests below need to see the number in the rendered text.
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

async function mountOnTab(tabLabel) {
  const wrapper = mount(Tools, {
    global: {
      provide: { toast: vi.fn() },
      stubs: {
        RouterLink: { template: '<a><slot /></a>' },
        SkeletonLoader: true,
        // LoadFailure stays real: the syslog test asserts its alert renders.
      },
    },
  })
  await flushPromises()
  await wrapper.findAll('button').find((b) => b.text() === tabLabel).trigger('click')
  await flushPromises()
  return wrapper
}

beforeEach(() => {
  api.getToolsCatalog.mockResolvedValue({ tiles: [] })
  api.getToolsSyslog.mockResolvedValue({ lines: ['line one'], count: 1, hint: '' })
  api.getToolsHardware.mockResolvedValue({
    sections: { Power: { data_type: 'SPPowerDataType', text: 'AC Charger ok' } },
    disks: [],
  })
  api.getListeningPorts.mockResolvedValue({
    count: 3,
    ports: [{ command: 'uvicorn', pid: 1, user: 'root', name: '*:8086' }],
  })
})

afterEach(() => {
  vi.clearAllMocks()
})

describe('Tools syslog tab', () => {
  it('shows the failure banner above stale lines when a re-load fails', async () => {
    const wrapper = await mountOnTab('tools.tab_syslog')
    expect(wrapper.get('.log-box').text()).toContain('line one')
    expect(wrapper.find('[role="alert"]').exists()).toBe(false)

    // A level change that fails must not be swallowed by the stale lines.
    api.getToolsSyslog.mockRejectedValueOnce(new Error('log stream broke'))
    await wrapper.findAll('select')[0].setValue('fault')
    await flushPromises()
    const banner = wrapper.get('[role="alert"]')
    expect(banner.text()).toContain('log stream broke')
    expect(wrapper.get('.log-box').text()).toContain('line one')

    // The selects stay clickable above the banner, so a direct retry that
    // worked must also drop it.
    await wrapper.findAll('select')[0].setValue('error')
    await flushPromises()
    expect(wrapper.find('[role="alert"]').exists()).toBe(false)
    wrapper.unmount()
  })

  it('announces the line count and keeps the log box keyboard-reachable', async () => {
    const wrapper = await mountOnTab('tools.tab_syslog')
    const count = wrapper.get('.toolbar [role="status"]')
    expect(count.text()).toBe('tools.lines_n 1')

    const box = wrapper.get('.log-box')
    expect(box.attributes('tabindex')).toBe('0')
    expect(box.attributes('role')).toBe('region')
    expect(box.attributes('aria-label')).toBe('tools.tab_syslog')
    wrapper.unmount()
  })
})

describe('Tools hardware tab', () => {
  it('keeps each section pane keyboard-reachable and named after its heading', async () => {
    const wrapper = await mountOnTab('tools.tab_hw')
    const pane = wrapper.get('.hw-pre')
    expect(pane.text()).toContain('AC Charger ok')
    expect(pane.attributes('tabindex')).toBe('0')
    expect(pane.attributes('role')).toBe('region')
    expect(pane.attributes('aria-label')).toBe('Power')
    wrapper.unmount()
  })
})

describe('Tools network tab', () => {
  it('labels the listening-port count and announces refreshes', async () => {
    const wrapper = await mountOnTab('tools.tab_net')
    const count = wrapper.get('.card .toolbar [role="status"]')
    expect(count.text()).toBe('network.sum_ports_n 3')

    api.getListeningPorts.mockResolvedValue({ count: 5, ports: [] })
    await wrapper.findAll('.card .toolbar button').find((b) => b.text() === 'common.refresh').trigger('click')
    await flushPromises()
    expect(count.text()).toBe('network.sum_ports_n 5')
    wrapper.unmount()
  })
})
