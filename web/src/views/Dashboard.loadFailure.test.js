/**
 * A failed first Dashboard load must explain itself, not keep loading.
 *
 * The skeleton is gated on host/sensors still being null, and a failed first
 * admin load leaves them null forever. The comment above the skeleton always
 * promised a loadError gate, but the condition never carried it: the failure
 * banner rendered with the placeholder still pulsing beneath it, presenting
 * a dead backend as data on the way. Pending and failed are different states
 * (loadStates.test.js contract); this file mounts both to keep them apart.
 */
import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { applyAuthStatus } from '../lib/authState'

vi.mock('../api/client', () => ({
  doAction: vi.fn(),
  getAlerts: vi.fn(async () => ({ alerts: [] })),
  getBookmarks: vi.fn(async () => ({ bookmarks: [] })),
  getContainers: vi.fn(async () => ({ containers: [], stats: {} })),
  getHealthChecks: vi.fn(async () => ({ summary: { ok: 0, warn: 0, error: 0 }, checks: [] })),
  getHost: vi.fn(async () => ({ hostname: 'test-host', ncpu: 8 })),
  getListeningPorts: vi.fn(async () => ({ ports: [] })),
  getMetricsRange: vi.fn(async () => ({ points: [], tier: 'raw', since: 0, until: 1 })),
  getPower: vi.fn(async () => ({})),
  getSensors: vi.fn(async () => ({ cpu: {}, memory: {}, network: {} })),
  getStatus: vi.fn(async () => ({ groups: [] })),
  getStorage: vi.fn(async () => ({ volumes: [], disks: [] })),
  getUps: vi.fn(async () => ({ present: false })),
  getOllamaStatus: vi.fn(async () => ({ installed: false, reachable: false })),
  powerAction: vi.fn(),
  setSystemSharing: vi.fn(),
}))
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
  injectI18n: () => ({ t: (key) => key, errText: (v) => String(v) }),
}))

const { getHost, getSensors, getStatus } = await import('../api/client')
const Dashboard = (await import('./Dashboard.vue')).default

async function render() {
  const wrapper = mount(Dashboard, {
    global: {
      provide: { toast: () => {} },
      stubs: {
        RouterLink: { template: '<a class="router-link-stub" :href="to"><slot /></a>', props: ['to'] },
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
  localStorage.clear()
  applyAuthStatus({ authenticated: false })
})

afterEach(() => {
  applyAuthStatus({ authenticated: false })
  vi.clearAllMocks()
})

describe('Dashboard failed first load', () => {
  it('shows the retryable banner and drops the skeleton', async () => {
    getStatus.mockRejectedValue(new Error('backend unreachable'))
    getHost.mockRejectedValue(new Error('backend unreachable'))
    getSensors.mockRejectedValue(new Error('backend unreachable'))

    const wrapper = await render()
    const html = wrapper.html()

    expect(html, 'no failure banner').toContain('dashboard.load_failed')
    expect(html, "the server's reason is not shown").toContain('backend unreachable')
    expect(html, 'no way to retry').toContain('common.retry')
    expect(
      wrapper.find('.skeleton').exists(),
      'skeleton still pulsing under the failure banner',
    ).toBe(false)

    wrapper.unmount()
  })

  it('keeps the skeleton while the first load is genuinely pending', async () => {
    // Control case: never-settling reads are "pending", the one state the
    // placeholder exists for — the loadError gate must not eat it.
    getHost.mockReturnValue(new Promise(() => {}))
    getSensors.mockReturnValue(new Promise(() => {}))

    const wrapper = await render()

    expect(wrapper.find('.skeleton').exists(), 'skeleton gone while pending').toBe(true)
    expect(wrapper.html(), 'phantom failure banner').not.toContain('dashboard.load_failed')

    wrapper.unmount()
  })
})
