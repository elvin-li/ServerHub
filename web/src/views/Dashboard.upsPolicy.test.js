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
vi.mock('../i18n', () => ({
  injectI18n: () => ({
    t: (key, params = {}) => Object.entries(params).reduce(
      (text, [name, value]) => text.replace(`{${name}}`, value),
      String(key),
    ),
    errText: (v) => String(v),
  }),
}))

const { getUps, getOllamaStatus } = await import('../api/client')
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
    global: {
      provide: { toast: () => {} },
      stubs: {
        RouterLink: { template: '<a class="router-link-stub" :href="to"><slot /></a>', props: ['to'] },
      },
    },
  })
  await flushPromises()
  return wrapper
}

beforeEach(() => {
  localStorage.clear()
  applyAuthStatus({ authenticated: false })
  getUps.mockClear()
  getOllamaStatus.mockReset()
  getOllamaStatus.mockResolvedValue({ installed: false, reachable: false })
})

afterEach(() => {
  applyAuthStatus({ authenticated: false })
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

describe('Ollama host-strip indicator', () => {
  it('is absent when Ollama is not installed', async () => {
    getOllamaStatus.mockResolvedValue({ installed: false, reachable: false })
    const wrapper = await render()
    expect(wrapper.find('[data-test="ollama-indicator"]').exists()).toBe(false)
    wrapper.unmount()
  })

  it('shows the resident model and links to /ollama', async () => {
    getOllamaStatus.mockResolvedValue({
      installed: true,
      reachable: true,
      version: '0.32.9',
      url: 'http://127.0.0.1:11434',
      resident: [{ name: 'qwen3.5:4b' }],
      service: { label: 'com.kiro.ollama' },
    })
    const wrapper = await render()
    const chip = wrapper.find('[data-test="ollama-indicator"]')
    expect(chip.exists()).toBe(true)
    expect(chip.text()).toContain('qwen3.5:4b')
    expect(chip.classes()).toContain('ok')
    expect(chip.attributes('to') || chip.attributes('href')).toContain('/ollama')
    wrapper.unmount()
  })

  it('keeps the API chip on Top CPU even when Ollama is not installed', async () => {
    getOllamaStatus.mockResolvedValue({ installed: false, reachable: false })
    const wrapper = await render()
    const api = wrapper.find('[data-test="ollama-api"]')
    expect(api.exists()).toBe(true)
    expect(api.text()).toContain('127.0.0.1:11434')
    expect(api.attributes('to') || api.attributes('href')).toContain('/ollama')
    expect(wrapper.find('table.top-cpu th.num').exists()).toBe(true)
    wrapper.unmount()
  })
})

describe('assistant host-strip chip', () => {
  it('is hidden for members', async () => {
    applyAuthStatus({
      authenticated: true, username: 'mom', role: 'member',
      resources: ['jellyfin'], can_manage: false,
    })
    const wrapper = await render()
    expect(wrapper.find('[data-test="assistant-brief-dash"]').exists()).toBe(false)
    wrapper.unmount()
  })

  it('opens a status brief for admins', async () => {
    applyAuthStatus({
      authenticated: true, username: 'admin', role: 'admin',
      resources: [], can_manage: true,
    })
    const wrapper = await render()
    const chip = wrapper.find('[data-test="assistant-brief-dash"]')
    expect(chip.exists()).toBe(true)
    const seen = []
    const onAssist = (event) => seen.push(event.detail)
    window.addEventListener('serverhub:assistant', onAssist)
    await chip.trigger('click')
    window.removeEventListener('serverhub:assistant', onAssist)
    expect(seen).toEqual([{ action: 'brief' }])
    wrapper.unmount()
  })
})
