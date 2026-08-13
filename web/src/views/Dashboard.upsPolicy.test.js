/**
 * Dashboard UPS indicator: the compact chip next to the hostname.
 *
 * The old full-width tile is gone; the host-strip chip is now the at-a-glance
 * answer to "is the box protected against an outage". The policy switch lives
 * in the chip tooltip — and, mid-outage, the live phase matters more than the
 * switch: an engaged policy is promoted to visible chip text rather than a
 * green "on" hidden behind a hover.
 */
import { flushPromises, mount } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'

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
  powerAction: vi.fn(),
  setSystemSharing: vi.fn(),
}))
vi.mock('../lib/poll', () => ({ startVisibleInterval: () => () => {} }))
vi.mock('../i18n', () => ({
  injectI18n: () => ({
    t: (key, params = {}) => Object.entries(params).reduce(
      (text, [name, value]) => text.replace(`{${name}}`, value),
      String(key),
    ),
    errText: (v) => String(v),
  }),
}))

const { getUps } = await import('../api/client')
const Dashboard = (await import('./Dashboard.vue')).default

function ups({ enabled = false, phase = 'idle' } = {}) {
  return {
    present: true,
    name: 'Back-UPS ES 750',
    on_battery: phase === 'engaged',
    battery_percent: 80,
    settings: { low_battery_pct: 20, shutdown: { enabled } },
    shutdown_state: { phase },
  }
}

async function render() {
  const wrapper = mount(Dashboard, {
    global: { provide: { toast: () => {} }, stubs: { RouterLink: true } },
  })
  await flushPromises()
  return wrapper
}

beforeEach(() => {
  localStorage.clear()
  getUps.mockClear()
})

describe('UPS host-strip indicator', () => {
  it('lives in the host strip, not the tile grid', async () => {
    getUps.mockResolvedValue(ups({ enabled: true }))
    const wrapper = await render()
    expect(wrapper.find('.host-strip [data-test="ups-indicator"]').exists()).toBe(true)
    expect(wrapper.find('.dash-grid [data-test="ups-indicator"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="ups-policy"]').exists()).toBe(false)
    wrapper.unmount()
  })

  it('keeps the disabled policy switch in the tooltip', async () => {
    getUps.mockResolvedValue(ups({ enabled: false }))
    const wrapper = await render()
    expect(wrapper.find('[data-test="ups-indicator"]').attributes('title'))
      .toContain('dashboard.ups_policy_off')
    wrapper.unmount()
  })

  it('stays a quiet percent chip when enabled and idle on AC', async () => {
    getUps.mockResolvedValue(ups({ enabled: true }))
    const wrapper = await render()
    const chip = wrapper.find('[data-test="ups-indicator"]')
    expect(chip.attributes('title')).toContain('dashboard.ups_policy_on')
    expect(chip.text()).toContain('80%')
    // No state word and no alarm colour while the box sits on wall power.
    expect(chip.text()).not.toContain('dashboard.ups_policy_on')
    expect(chip.classes()).not.toContain('warn')
    expect(chip.classes()).not.toContain('danger')
    wrapper.unmount()
  })

  it('promotes the live phase to visible text while engaged', async () => {
    getUps.mockResolvedValue(ups({ enabled: true, phase: 'engaged' }))
    const wrapper = await render()
    const chip = wrapper.find('[data-test="ups-indicator"]')
    expect(chip.text()).toContain('dashboard.ups_policy_engaged')
    expect(chip.classes()).toContain('danger')
    expect(chip.attributes('title')).not.toContain('dashboard.ups_policy_on')
    wrapper.unmount()
  })

  it('is absent entirely when no UPS is attached', async () => {
    getUps.mockResolvedValue({ present: false })
    const wrapper = await render()
    expect(wrapper.find('[data-test="ups-indicator"]').exists()).toBe(false)
    wrapper.unmount()
  })
})
