/**
 * Overview processor card: CPU | GPU side-by-side, header badges, shared loadline.
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
const themeId = vi.hoisted(() => ({ value: 'macos' }))

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
    theme: themeId,
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

const { getSensors, getMetricsRange } = await import('../api/client')
const Dashboard = (await import('./Dashboard.vue')).default

const GPU = {
  util_pct: 68,
  mem_used_bytes: 1159086080,
  mem_alloc_bytes: 8613429248,
  model: 'Apple M1 Pro',
}

async function render() {
  const wrapper = mount(Dashboard, {
    global: {
      provide: { toast: () => {} },
      stubs: {
        RouterLink: { template: '<a class="router-link-stub" :href="to"><slot /></a>', props: ['to'] },
        LineChart: {
          props: ['height', 'fill', 'title', 'series'],
          template: '<div class="lc-stub" :data-height="height" :data-title="title" :data-head="head"></div>',
          computed: {
            head() {
              const s = (this.series || [])[0]
              const v = (s?.values || []).find((x) => x != null)
              return v == null ? '' : String(v)
            },
          },
        },
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
  themeId.value = 'macos'
  getMetricsRange.mockResolvedValue({ points: [], tier: 'raw', since: 0, until: 1 })
  locale.t = (key, params = {}) => {
    const text = key.split('.').reduce((o, k) => (o == null ? o : o[k]), en)
    return Object.entries(params).reduce(
      (out, [name, value]) => out.replace(`{${name}}`, value),
      String(text ?? key),
    )
  }
  getSensors.mockResolvedValue({
    cpu: { user: 10, sys: 5, idle: 85, used_pct: 15, load1: 1, load5: 1, load15: 1 },
    memory: {},
    network: {},
    gpu: GPU,
  })
})

afterEach(() => {
  applyAuthStatus({ authenticated: false })
  vi.clearAllMocks()
})

describe('Dashboard GPU density', () => {
  it('ships GPU strings in every locale and keeps SMART shortening', () => {
    expect(zhCN.dashboard.cpu).toBe('处理器')
    expect(en.dashboard.cpu).toBe('Processor')
    expect(ja.dashboard.cpu).toBe('プロセッサ')
    expect(zhCN.dashboard.gpu).toBe('GPU')
    expect(zhCN.dashboard.gpu_util).toBe('GPU 利用率')
    expect(zhCN.dashboard.cpu_pct).toBe('CPU {p}%')
    expect(zhCN.dashboard.gpu_pct).toBe('GPU {p}%')
    expect(zhCN.dashboard.gpu_memory).toBe('GPU 内存')
    expect(en.dashboard.gpu).toBe('GPU')
    expect(en.dashboard.gpu_util).toBe('GPU utilization')
    expect(en.dashboard.cpu_pct).toBe('CPU {p}%')
    expect(en.dashboard.gpu_pct).toBe('GPU {p}%')
    expect(en.dashboard.gpu_memory).toBe('GPU memory')
    expect(ja.dashboard.gpu).toBe('GPU')
    expect(ja.dashboard.gpu_util).toBe('GPU 使用率')
    expect(ja.dashboard.cpu_pct).toBe('CPU {p}%')
    expect(ja.dashboard.gpu_pct).toBe('GPU {p}%')
    expect(ja.dashboard.gpu_memory).toBe('GPUメモリ')
    expect(zhCN.dashboard.cpu_load).toBe('CPU 负载')
    expect(en.dashboard.cpu_load).toBe('CPU Load')
    expect(ja.dashboard.cpu_load).toBe('CPU 負荷')
    for (const dict of [zhCN, en, ja]) {
      expect(dict.dashboard.smart_passed).toBe('S')
      expect(dict.dashboard.smart_summary).toBe('{ok}/{total} S')
    }
  })

  it('shows GPU util and memory on the header badge, not as AM rows', async () => {
    const wrapper = await render()
    expect(wrapper.find('.res-card h2').text()).toContain('Processor')
    expect(wrapper.find('[data-test="gpu-section"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="gpu-util"]').exists()).toBe(false)
    expect(wrapper.find('.cpu-facts').exists()).toBe(false)
    const amLabels = wrapper.findAll('.am-cpu .am-row > span').map((n) => n.text())
    expect(amLabels).not.toContain('GPU utilization')
    expect(amLabels).not.toContain('GPU memory')
    expect(amLabels).not.toContain('Thermal')
    const badge = wrapper.get('[data-test="gpu-badge"]')
    expect(badge.text()).toContain('GPU 68%')
    expect(badge.text()).toMatch(/1\.1\s*\/\s*8(\.0)? GB/)
    expect(wrapper.get('[data-test="gpu-mem"]').text()).toMatch(/1\.1\s*\/\s*8(\.0)? GB/)
    const charts = wrapper.findAll('.lc-stub')
    const heights = charts.map((n) => n.attributes('data-height'))
    expect(heights).toEqual(['128', '128', '88', '88'])
    expect(charts[0].attributes('data-title')).toBe('CPU Load')
    expect(charts[1].attributes('data-title')).toBe('GPU utilization 68%')
    expect(wrapper.find('[data-test="gpu-chart"]').exists()).toBe(true)
    const procCharts = wrapper.find('.cpu-charts.am-cpu')
    expect(procCharts.exists()).toBe(true)
    expect(procCharts.findAll('.lc-stub')).toHaveLength(2)
    expect(wrapper.get('[data-test="cpu-badge"]').text()).toBe('CPU 15%')
    const thermal = wrapper.get('[data-test="cpu-thermal"]')
    expect(thermal.text()).toContain('Thermal')
    expect(thermal.text()).toContain('Unavailable')
    wrapper.unmount()
  })

  it('hides GPU util when null and memory when both fields are null', async () => {
    getSensors.mockResolvedValue({
      cpu: { user: 1, sys: 1, idle: 98 },
      memory: {},
      network: {},
      gpu: { util_pct: null, mem_used_bytes: null, mem_alloc_bytes: null, model: 'Apple M1 Pro' },
    })
    const wrapper = await render()
    expect(wrapper.find('[data-test="gpu-util"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="gpu-mem"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="gpu-badge"]').exists()).toBe(false)
    expect(wrapper.get('[data-test="cpu-badge"]').text()).toBe('0%')
    expect(wrapper.get('[data-test="gpu-chart"]').attributes('data-title')).toBe('GPU utilization')
    wrapper.unmount()
  })

  it('shows GPU memory on the badge when only one of used/alloc is present', async () => {
    getSensors.mockResolvedValue({
      cpu: { user: 1, sys: 1, idle: 98 },
      memory: {},
      network: {},
      gpu: { util_pct: null, mem_used_bytes: 2 * 1024 ** 3, mem_alloc_bytes: null, model: 'Apple M1 Pro' },
    })
    const wrapper = await render()
    expect(wrapper.find('[data-test="gpu-util"]').exists()).toBe(false)
    expect(wrapper.get('[data-test="gpu-mem"]').text()).toMatch(/2(\.0)?\s*\/\s*— GB/)
    expect(wrapper.get('[data-test="gpu-badge"]').text()).toMatch(/2(\.0)?\s*\/\s*— GB/)
    expect(wrapper.get('[data-test="gpu-badge"]').text()).not.toMatch(/%/)
    wrapper.unmount()
  })

  it('plots gpu_util_pct from metrics history on the GPU chart', async () => {
    getMetricsRange.mockResolvedValue({
      points: [
        { t: 1, cpu_used_pct: 10, gpu_util_pct: 42 },
        { t: 2, cpu_used_pct: 12, gpu_util_pct: 50, gpu_util_pct_max: 80 },
      ],
      tier: 'raw',
      since: 0,
      until: 2,
    })
    const wrapper = await render()
    expect(wrapper.get('[data-test="gpu-chart"]').attributes('data-head')).toBe('42')
    expect(wrapper.get('[data-test="gpu-chart"]').attributes('data-title')).toBe('GPU utilization 68%')
    wrapper.unmount()
  })

  it('mirrors live GPU util onto the last history slot when that point is empty', async () => {
    getMetricsRange.mockResolvedValue({
      points: [
        { t: 1, cpu_used_pct: 10 },
        { t: 2, cpu_used_pct: 12 },
      ],
      tier: 'raw',
      since: 0,
      until: 2,
    })
    const wrapper = await render()
    expect(wrapper.get('[data-test="gpu-chart"]').attributes('data-head')).toBe('68')
    expect(wrapper.get('[data-test="gpu-chart"]').attributes('data-title')).toBe('GPU utilization 68%')
    wrapper.unmount()
  })

  it('shows a GPU chart beside the CPU chart on the compact path', async () => {
    themeId.value = 'unraid'
    const wrapper = await render()
    const charts = wrapper.findAll('.lc-stub')
    expect(charts.map((n) => n.attributes('data-height'))).toEqual(['128', '128', '72', '52'])
    expect(charts[0].attributes('data-title')).toBe('CPU Load')
    expect(charts[1].attributes('data-title')).toBe('GPU utilization 68%')
    const procCharts = wrapper.find('.cpu-charts')
    expect(procCharts.exists()).toBe(true)
    expect(procCharts.classes()).not.toContain('am-cpu')
    expect(procCharts.findAll('.lc-stub')).toHaveLength(2)
    expect(wrapper.find('.cpu-facts').exists()).toBe(false)
    expect(wrapper.find('[data-test="gpu-compact-util"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="gpu-compact-mem"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="gpu-section"]').exists()).toBe(false)
    expect(wrapper.get('[data-test="cpu-badge"]').text()).toBe('CPU 15%')
    const badge = wrapper.get('[data-test="gpu-badge"]')
    expect(badge.text()).toContain('GPU 68%')
    expect(badge.text()).toMatch(/1\.1\s*\/\s*8(\.0)? GB/)
    const thermal = wrapper.get('[data-test="cpu-thermal"]')
    expect(thermal.text()).toContain('Thermal')
    expect(thermal.text()).toContain('Unavailable')
    wrapper.unmount()
  })

  it('warns on thermal pressure in the shared loadline', async () => {
    getSensors.mockResolvedValue({
      cpu: {
        user: 10,
        sys: 5,
        idle: 85,
        used_pct: 15,
        thermal: { pressure: 'warning' },
      },
      memory: {},
      network: {},
      gpu: GPU,
    })
    const wrapper = await render()
    const thermal = wrapper.get('[data-test="cpu-thermal"]')
    expect(thermal.text()).toContain('Thermal')
    expect(thermal.text()).toContain('Pressure warning')
    expect(thermal.find('.temp-warn').exists()).toBe(true)
    wrapper.unmount()
  })
})
