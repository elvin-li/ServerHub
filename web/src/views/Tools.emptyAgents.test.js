/**
 * The Tools scheduler tab lists LaunchAgents; an empty list must say so.
 *
 * The timer table above it already did, so a host with no calendar/interval
 * agents got "no timers" and then a second set of column headings with
 * nothing under them.  See emptyTables.test.js for the rest of the rule.
 *
 * The section also has to keep the three-state contract from loadStates.test.js:
 * it used to render unconditionally, so while the sched load was in flight the
 * timers slot showed a skeleton but the agents table already claimed "no
 * agents", and after a failed load it kept a bare header under the timers'
 * failure banner.  The tab is switched through its real button here, because
 * that click is what triggers the load whose states are being asserted.
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
  injectI18n: () => ({ t: (key) => key, errText: (v) => String(v), locale: { value: 'en' } }),
}))
vi.mock('vue-router', () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
  useRoute: () => ({ path: '/tools', query: {}, params: {}, name: 'tools' }),
}))

import Tools from './Tools.vue'

beforeEach(() => {
  for (const fn of Object.values(api)) {
    if (typeof fn?.mockReset === 'function') fn.mockResolvedValue({})
  }
  api.getScheduler.mockResolvedValue({ timers: [] })
  api.getToolsAgents.mockResolvedValue({ agents: [], count: 0, hint: '' })
})

afterEach(() => {
  vi.clearAllMocks()
})

async function mountOnSchedTab() {
  const wrapper = mount(Tools, {
    global: {
      provide: { toast: vi.fn() },
      stubs: { RouterLink: { template: '<a><slot /></a>' } },
    },
  })
  await flushPromises()
  // The real path into the tab: switchTab() is what starts the sched load.
  await wrapper
    .findAll('.tabs button')
    .find((b) => b.text() === 'tools.tab_sched')
    .trigger('click')
  await flushPromises()
  return wrapper
}

/** Column headings of every rendered table that has a head and no body rows. */
function headerOnlyTables(wrapper) {
  return [...wrapper.element.querySelectorAll('table')]
    .filter((t) => t.querySelector('thead tr') && !t.querySelector('tbody tr'))
    .map((t) => [...t.querySelectorAll('thead th')].map((th) => th.textContent.trim()).join(' | '))
}

describe('Tools scheduler tab', () => {
  it('explains an empty LaunchAgent list instead of showing a bare header', async () => {
    const wrapper = await mountOnSchedTab()
    expect(headerOnlyTables(wrapper), 'headings with no rows under them read as still-loading').toEqual([])
    expect(wrapper.text()).toContain('tools.no_agents')
    wrapper.unmount()
  })

  it('shows a skeleton, not "no agents", while the load is in flight', async () => {
    api.getToolsAgents.mockReturnValue(new Promise(() => {}))
    const wrapper = await mountOnSchedTab()
    expect(wrapper.text()).not.toContain('tools.no_agents')
    expect(wrapper.html()).toContain('sk-wrap')
    wrapper.unmount()
  })

  it('does not call an API failure an empty LaunchAgent list', async () => {
    api.getToolsAgents.mockRejectedValue(new Error('launchctl walk failed'))
    const wrapper = await mountOnSchedTab()
    expect(wrapper.text()).toContain('launchctl walk failed')
    expect(wrapper.text()).toContain('common.retry')
    expect(wrapper.text()).not.toContain('tools.no_agents')
    expect(headerOnlyTables(wrapper), 'a failed load must not leave bare headings').toEqual([])
    wrapper.unmount()
  })
})
