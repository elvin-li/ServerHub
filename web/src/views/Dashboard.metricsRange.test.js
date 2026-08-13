/**
 * Dashboard chart ranges over the tiered metrics history.
 *
 * Three behaviours worth pinning:
 *  - the selected range round-trips through localStorage (and junk in
 *    localStorage falls back instead of sending a garbage ?range=),
 *  - a 30d/1y selection made before the rollup layers have filled shows the
 *    "history accumulating" hint next to whatever partial data exists,
 *    rather than an unexplained near-empty chart,
 *  - aggregated points expose `<field>_max` peaks and the charts draw them
 *    as extra series (a spike averaged into a 1h window must stay visible).
 */
import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

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
// No real pollers: they would keep firing loadMetrics after the test ends.
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

const { getMetricsRange } = await import('../api/client')
const Dashboard = (await import('./Dashboard.vue')).default

const RANGE_KEY = 'serverhub.metricsRange'
const NOW = 1_700_000_000

async function render() {
  const wrapper = mount(Dashboard, {
    global: {
      provide: { toast: () => {} },
      stubs: { RouterLink: true },
    },
  })
  await flushPromises()
  return wrapper
}

function rangeButtons(wrapper) {
  return wrapper.findAll('.range-btns button')
}

beforeEach(() => {
  localStorage.clear()
  getMetricsRange.mockClear()
  getMetricsRange.mockResolvedValue({ points: [], tier: 'raw', since: NOW - 3600, until: NOW })
})
afterEach(() => {
  localStorage.clear()
})

describe('range selection and persistence', () => {
  it('defaults to 1h when nothing is stored', async () => {
    const wrapper = await render()
    expect(getMetricsRange).toHaveBeenCalledWith('1h')
    wrapper.unmount()
  })

  it('offers the long-history ranges', async () => {
    const wrapper = await render()
    const labels = rangeButtons(wrapper).map((b) => b.text())
    expect(labels).toEqual(['1h', '6h', '24h', '48h', '30d', '1y'])
    wrapper.unmount()
  })

  it('restores a stored range on mount', async () => {
    localStorage.setItem(RANGE_KEY, '30d')
    const wrapper = await render()
    expect(getMetricsRange).toHaveBeenCalledWith('30d')
    wrapper.unmount()
  })

  it('falls back to 1h when localStorage holds junk', async () => {
    localStorage.setItem(RANGE_KEY, 'bananas')
    const wrapper = await render()
    expect(getMetricsRange).toHaveBeenCalledWith('1h')
    expect(getMetricsRange).not.toHaveBeenCalledWith('bananas')
    wrapper.unmount()
  })

  it('clicking a range fetches it and persists the choice', async () => {
    const wrapper = await render()
    const oneYear = rangeButtons(wrapper).find((b) => b.text() === '1y')
    await oneYear.trigger('click')
    await flushPromises()
    expect(getMetricsRange).toHaveBeenCalledWith('1y')
    expect(localStorage.getItem(RANGE_KEY)).toBe('1y')
    wrapper.unmount()
  })
})

describe('the accumulating-history hint', () => {
  it('shows when the data covers a fraction of the requested window', async () => {
    localStorage.setItem(RANGE_KEY, '30d')
    // 30 days requested, 3 days present: the rollup layers were enabled
    // three days ago. The chart must draw those 3 days, and the hint must
    // say why the window looks short.
    getMetricsRange.mockResolvedValue({
      tier: '5m',
      since: NOW - 30 * 86400,
      until: NOW,
      points: [
        { t: NOW - 3 * 86400, n: 3, cpu_used_pct: 10, cpu_used_pct_max: 30 },
        { t: NOW - 86400, n: 3, cpu_used_pct: 12, cpu_used_pct_max: 25 },
      ],
    })
    const wrapper = await render()
    expect(wrapper.text()).toContain('dashboard.chart_accumulating')
    expect(wrapper.text()).toContain('dashboard.chart_earliest')
    wrapper.unmount()
  })

  it('shows (without a date) when the tier is entirely empty', async () => {
    localStorage.setItem(RANGE_KEY, '1y')
    getMetricsRange.mockResolvedValue({
      tier: '1h', since: NOW - 365 * 86400, until: NOW, points: [],
    })
    const wrapper = await render()
    expect(wrapper.text()).toContain('dashboard.chart_accumulating')
    expect(wrapper.text()).not.toContain('dashboard.chart_earliest')
    wrapper.unmount()
  })

  it('stays quiet when coverage is essentially complete', async () => {
    getMetricsRange.mockResolvedValue({
      tier: 'raw',
      since: NOW - 3600,
      until: NOW,
      points: [
        { t: NOW - 3590, cpu_used_pct: 10 },
        { t: NOW - 90, cpu_used_pct: 12 },
      ],
    })
    const wrapper = await render()
    expect(wrapper.text()).not.toContain('dashboard.chart_accumulating')
    wrapper.unmount()
  })
})

describe('peak series from aggregated tiers', () => {
  it('draws the *_max companion lines when aggregates provide them', async () => {
    localStorage.setItem(RANGE_KEY, '30d')
    getMetricsRange.mockResolvedValue({
      tier: '5m',
      since: NOW - 30 * 86400,
      until: NOW,
      points: [
        { t: NOW - 30 * 86400 + 60, n: 3, cpu_used_pct: 10, cpu_used_pct_max: 90, mem_used_pct: 40, mem_used_pct_max: 70 },
        { t: NOW - 86400, n: 3, cpu_used_pct: 12, cpu_used_pct_max: 88, mem_used_pct: 42, mem_used_pct_max: 71 },
      ],
    })
    const wrapper = await render()
    expect(wrapper.text()).toContain('dashboard.chart_peak')
    wrapper.unmount()
  })

  it('hides the peak legend on plain raw points', async () => {
    getMetricsRange.mockResolvedValue({
      tier: 'raw',
      since: NOW - 3600,
      until: NOW,
      points: [
        { t: NOW - 3590, cpu_used_pct: 10 },
        { t: NOW - 90, cpu_used_pct: 12 },
      ],
    })
    const wrapper = await render()
    expect(wrapper.text()).not.toContain('dashboard.chart_peak')
    wrapper.unmount()
  })
})
