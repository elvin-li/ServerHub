/**
 * Dashboard disk/SMART card: dense badge + temperature, full meaning in title.
 */
import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { applyAuthStatus } from '../lib/authState'
import en from '../i18n/en.js'
import ja from '../i18n/ja.js'
import zhCN from '../i18n/zh-CN.js'

const locale = vi.hoisted(() => ({
  t: (key) => key,
}))

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
  injectI18n: () => ({
    t: (key, params = {}) => locale.t(key, params),
    errText: (v) => String(v),
  }),
}))

const { getStorage } = await import('../api/client')
const Dashboard = (await import('./Dashboard.vue')).default

function disks() {
  return [
    {
      id: 'disk0',
      name: 'Macintosh HD',
      size: '1 TB',
      smart: { health: 'PASSED', temp: '39 Celsius', wear: '3%', written: '12 TB' },
    },
    {
      id: 'disk1',
      name: 'Backup',
      smart: { health: 'FAILED', temp: 41, wear: '10%', written: '4 TB' },
    },
    {
      id: 'disk2',
      name: 'USB',
      error: 'no passthrough',
    },
  ]
}

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
  locale.t = (key, params = {}) => {
    const text = key.split('.').reduce((o, k) => (o == null ? o : o[k]), en)
    return Object.entries(params).reduce(
      (out, [name, value]) => out.replace(`{${name}}`, value),
      String(text ?? key),
    )
  }
  getStorage.mockResolvedValue({ volumes: [], disks: disks() })
})

afterEach(() => {
  applyAuthStatus({ authenticated: false })
  vi.clearAllMocks()
})

describe('Dashboard SMART density', () => {
  it('uses S / ! / ? in every locale, with long titles kept', () => {
    for (const dict of [zhCN, en, ja]) {
      expect(dict.dashboard.smart_passed).toBe('S')
      expect(dict.dashboard.smart_warning).toBe('!')
      expect(dict.dashboard.smart_na).toBe('?')
      expect(dict.dashboard.smart_summary).toBe('{ok}/{total} S')
      expect(dict.dashboard.smart_passed_title).toMatch(/SMART/)
      expect(dict.dashboard.smart_warning_title).toMatch(/SMART/)
      expect(dict.dashboard.smart_na_title).toMatch(/SMART/)
    }
  })

  it('shows a one-letter ok badge, °C temps, and titles with full meaning', async () => {
    const wrapper = await render()
    const items = wrapper.findAll('.disk-item')
    expect(items).toHaveLength(3)

    const ok = items[0].get('.disk-primary-meta .badge')
    expect(ok.text()).toBe('S')
    expect(ok.classes()).toContain('ok')
    expect(ok.attributes('title')).toBe('SMART passed')
    expect(ok.attributes('aria-label')).toBe('SMART passed')
    expect(items[0].get('.disk-temp').text()).toBe('39°C')
    expect(items[0].text()).not.toMatch(/Celsius/i)

    const fail = items[1].get('.disk-primary-meta .badge')
    expect(fail.text()).toBe('!')
    expect(fail.classes()).toContain('down')
    expect(fail.attributes('title')).toBe('FAILED')
    expect(items[1].get('.disk-temp').text()).toBe('41°C')

    const na = items[2].get('.disk-primary-meta .badge')
    expect(na.text()).toBe('?')
    expect(na.classes()).not.toContain('ok')
    expect(na.classes()).not.toContain('down')
    expect(na.attributes('title')).toBe('SMART unavailable')

    const summary = wrapper.findAll('.res-card h3 .tile-tools .badge')
    const smartSummary = summary[summary.length - 1]
    expect(smartSummary.text()).toBe('2/3 S')
    expect(smartSummary.attributes('title')).toBe('2/3 SMART')
    wrapper.unmount()
  })
})
