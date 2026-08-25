/**
 * Services page leftover a11y/state sweep.
 *
 * Three leftovers, each pinned by a test that fails on the pre-fix template:
 *
 * - The status LEDs (problems bar, dense-table rows, card grid) carried the
 *   row's state in colour alone. The dense table at least has an sr-only
 *   column header, but the cell itself was empty, so a screen reader heard
 *   the service name with nothing saying whether it runs. Same treatment as
 *   the Containers rows and the Dashboard cards: aria-hidden the paint,
 *   spell the state in an sr-only twin (reusing the state-chip words).
 *
 * - A filter that misses and a host with nothing discovered are different
 *   answers (Tools/Scheduler/Containers pattern), but both rendered the same
 *   "services.empty" message, telling an operator whose filter missed that
 *   nothing is installed.
 *
 * - A failed *first* load in dense mode rendered a headers-only table under
 *   the LoadFailure banner — column headers above nothing, with the empty-row
 *   suppressed. The LoadFailure contract (Alerts, Users, Containers) is
 *   banner alone when nothing was fetched, banner *above* the stale rows
 *   when a re-poll fails.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'

const api = vi.hoisted(() => ({
  adoptService: vi.fn(),
  bulkServiceAction: vi.fn(),
  doAction: vi.fn(),
  forgetServiceScript: vi.fn(),
  getServiceDetail: vi.fn(),
  getServiceLogs: vi.fn(),
  getServices: vi.fn(),
  getServiceUninstallPreview: vi.fn(),
  setServiceHidden: vi.fn(),
  uninstallService: vi.fn(),
  updateServiceOverride: vi.fn(),
  updateServiceScript: vi.fn(),
}))
vi.mock('../api/client', () => api)
vi.mock('../i18n', () => ({
  injectI18n: () => ({ t: (key) => key, errText: (v) => String(v), locale: { value: 'en' } }),
}))
vi.mock('../lib/poll', () => ({ startVisibleInterval: () => () => {} }))

import Services from './Services.vue'

const MOUNT = {
  global: {
    provide: { toast: vi.fn() },
    stubs: { RouterLink: { template: '<a><slot /></a>' } },
  },
}

const STATUS = {
  ts: '12:00:00',
  engine_up: true,
  service_total: 3,
  counts: { ok: 1, warn: 1, down: 1, stopped: 0 },
  problems: [{ id: 'db', name: 'db', state: 'down' }],
  links: [],
  groups: [
    {
      group: 'web',
      services: [
        { id: 'nginx', name: 'nginx', state: 'ok', kind: 'launchd', group: 'web' },
        { id: 'api', name: 'api', state: 'warn', kind: 'script', group: 'web' },
        { id: 'db', name: 'db', state: 'down', kind: 'container', group: 'data' },
      ],
    },
  ],
}

beforeEach(() => {
  for (const fn of Object.values(api)) {
    if (typeof fn?.mockReset === 'function') fn.mockResolvedValue({})
  }
})

afterEach(() => {
  vi.clearAllMocks()
})

describe('Services status LEDs', () => {
  it('hides the paint and spells the state for the dense-table row LEDs', async () => {
    api.getServices.mockResolvedValue(STATUS)
    const wrapper = mount(Services, MOUNT)
    await flushPromises()

    const leds = wrapper.findAll('tbody .led')
    expect(leds.length).toBe(3)
    for (const led of leds) {
      expect(led.attributes('aria-hidden'), 'LED must be decoration').toBe('true')
    }
    const spelled = wrapper.findAll('tbody .led + .sr-only').map((el) => el.text())
    expect(spelled).toContain('services.state_ok')
    expect(spelled).toContain('services.state_warn')
    expect(spelled).toContain('services.state_down')
    wrapper.unmount()
  })

  it('spells the state on the problems-bar chips and the card-grid LEDs too', async () => {
    api.getServices.mockResolvedValue(STATUS)
    const wrapper = mount(Services, MOUNT)
    await flushPromises()

    const probLed = wrapper.find('.problems-bar .led')
    expect(probLed.exists()).toBe(true)
    expect(probLed.attributes('aria-hidden')).toBe('true')
    expect(wrapper.find('.problems-bar .led + .sr-only').text()).toBe('services.state_down')

    wrapper.vm.dense = false
    await flushPromises()
    const cardLeds = wrapper.findAll('.svc-card .led')
    expect(cardLeds.length).toBe(3)
    for (const led of cardLeds) {
      expect(led.attributes('aria-hidden'), 'card LED must be decoration').toBe('true')
    }
    const spelled = wrapper.findAll('.svc-card .led + .sr-only').map((el) => el.text())
    expect(spelled).toContain('services.state_ok')
    expect(spelled).toContain('services.state_down')
    wrapper.unmount()
  })
})

describe('Services empty vs filter-miss states', () => {
  it('tells a filter miss apart from a host with nothing discovered', async () => {
    api.getServices.mockResolvedValue(STATUS)
    const wrapper = mount(Services, MOUNT)
    await flushPromises()
    expect(wrapper.text()).toContain('nginx')

    wrapper.vm.q = 'no-such-service'
    await flushPromises()
    const missed = wrapper.text()
    expect(missed).toContain('common.no_match')
    expect(missed).not.toContain('services.empty')
    wrapper.unmount()
  })

  it('reports an empty service list as such, not as a filter miss', async () => {
    api.getServices.mockResolvedValue({ ...STATUS, problems: [], counts: {}, groups: [] })
    const wrapper = mount(Services, MOUNT)
    await flushPromises()

    const text = wrapper.text()
    expect(text).toContain('services.empty')
    expect(text).not.toContain('common.no_match')
    wrapper.unmount()
  })

  it('splits the same two answers in the card grid', async () => {
    api.getServices.mockResolvedValue(STATUS)
    const wrapper = mount(Services, MOUNT)
    await flushPromises()
    wrapper.vm.dense = false
    wrapper.vm.q = 'no-such-service'
    await flushPromises()
    expect(wrapper.text()).toContain('common.no_match')
    expect(wrapper.text()).not.toContain('services.empty')
    wrapper.unmount()
  })
})

describe('Services re-poll failure', () => {
  it('keeps the stale rows on screen below the failure banner', async () => {
    api.getServices.mockResolvedValue(STATUS)
    const wrapper = mount(Services, MOUNT)
    await flushPromises()
    expect(wrapper.text()).toContain('nginx')

    api.getServices.mockRejectedValue(new Error('backend unreachable'))
    await wrapper.find('.svc-toolbar button.primary').trigger('click')
    await flushPromises()

    const banner = wrapper.find('.load-failure')
    expect(banner.exists(), 'failure banner above the stale rows').toBe(true)
    expect(banner.text()).toContain('backend unreachable')
    // The rows the operator was reading stay on screen below the banner.
    expect(wrapper.text()).toContain('nginx')
    expect(wrapper.find('tbody').exists()).toBe(true)
    wrapper.unmount()
  })

  it('a failed first load renders the banner alone — no headers-only table', async () => {
    api.getServices.mockRejectedValue(new Error('backend unreachable'))
    const wrapper = mount(Services, MOUNT)
    await flushPromises()

    expect(wrapper.find('.load-failure').exists()).toBe(true)
    // Column headers above nothing claim a table that was never fetched.
    expect(wrapper.find('table').exists()).toBe(false)
    const text = wrapper.text()
    expect(text).not.toContain('services.empty')
    expect(text).not.toContain('common.no_match')
    wrapper.unmount()
  })
})
