/**
 * Containers page leftover a11y/state sweep.
 *
 * Three leftovers, each pinned by a test that fails on the pre-fix template:
 *
 * - The containers tab rendered *nothing at all* when the list was empty or
 *   when the filter / hide-system toggle hid every row — no table, no
 *   message. An empty engine and a filter miss are different answers
 *   (Tools/Scheduler pattern): "no containers" vs "no match".
 *
 * - The status LED carried the row's state in colour alone. On mobile the
 *   textual uptime column is hidden (col-hide-m), so a screen reader heard
 *   the container name with nothing saying whether it runs. Same treatment
 *   as the Network binding and Dashboard rows: aria-hidden the paint,
 *   spell the state in an sr-only twin.
 *
 * - LoadFailure was chained into the same v-if/else-if ladder as the table,
 *   so a failed 20s re-poll replaced the rows the operator was reading with
 *   just the banner. The LoadFailure contract (Alerts, Users accounts) is
 *   banner *above* the stale rows.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'

const api = vi.hoisted(() => ({
  batchContainers: vi.fn(),
  containerAction: vi.fn(),
  checkContainerUpdates: vi.fn(),
  containersAll: vi.fn(),
  createNetwork: vi.fn(),
  createVolume: vi.fn(),
  execContainer: vi.fn(),
  getContainers: vi.fn(),
  getDockerInfo: vi.fn(),
  getImages: vi.fn(),
  getNetworks: vi.fn(),
  getStackJob: vi.fn(),
  getVolumes: vi.fn(),
  inspectContainer: vi.fn(),
  openContainerLogs: vi.fn(),
  prune: vi.fn(),
  pullImageApi: vi.fn(),
  removeImage: vi.fn(),
  removeNetwork: vi.fn(),
  removeVolume: vi.fn(),
  runContainer: vi.fn(),
  setRestartPolicy: vi.fn(),
  updateContainer: vi.fn(),
}))
vi.mock('../api/client', () => api)
vi.mock('../i18n', () => ({
  injectI18n: () => ({ t: (key) => key, errText: (v) => String(v), locale: { value: 'en' } }),
}))
vi.mock('../lib/poll', () => ({ startVisibleInterval: () => () => {} }))

import Containers from './Containers.vue'

const MOUNT = {
  global: {
    provide: { toast: vi.fn() },
    stubs: { RouterLink: { template: '<a><slot /></a>' } },
  },
}

const WEB = { id: 'web', name: 'web', state: 'ok', raw_state: 'running', image: 'nginx:1' }

beforeEach(() => {
  for (const fn of Object.values(api)) {
    if (typeof fn?.mockReset === 'function') fn.mockResolvedValue({})
  }
})

afterEach(() => {
  vi.clearAllMocks()
})

describe('Containers empty vs filter-miss states', () => {
  it('tells a filter miss apart from an engine with no containers', async () => {
    api.getContainers.mockResolvedValue({ engine_up: true, containers: [WEB], stats: {} })
    const wrapper = mount(Containers, MOUNT)
    await flushPromises()

    expect(wrapper.text()).toContain('web')

    wrapper.vm.q = 'no-such-container'
    await flushPromises()
    const missed = wrapper.text()
    expect(missed).toContain('common.no_match')
    expect(missed).not.toContain('docker.no_containers')
    // No headers-only table restating the miss under the placeholder.
    expect(wrapper.find('tbody').exists()).toBe(false)
    wrapper.unmount()
  })

  it('reports an empty container list as such, not as a filter miss', async () => {
    api.getContainers.mockResolvedValue({ engine_up: true, containers: [], stats: {} })
    const wrapper = mount(Containers, MOUNT)
    await flushPromises()

    const text = wrapper.text()
    expect(text).toContain('docker.no_containers')
    expect(text).not.toContain('common.no_match')
    expect(text).not.toContain('docker.engine_off')
    wrapper.unmount()
  })

  it('a hide-system toggle that hides every row is a filter miss too', async () => {
    api.getContainers.mockResolvedValue({
      engine_up: true,
      containers: [{ ...WEB, id: 'k8s_pod', name: 'pod', system: true }],
      stats: {},
    })
    const wrapper = mount(Containers, MOUNT)
    await flushPromises()

    // hideSystem defaults on, so the only (system) row is hidden.
    const text = wrapper.text()
    expect(text).toContain('common.no_match')
    expect(text).not.toContain('docker.no_containers')
    wrapper.unmount()
  })
})

describe('Containers status LED', () => {
  it('hides the paint and spells the state for the row LED', async () => {
    api.getContainers.mockResolvedValue({
      engine_up: true,
      containers: [
        WEB,
        { id: 'db', name: 'db', state: 'stopped', raw_state: 'exited', image: 'pg:16' },
        { id: 'cache', name: 'cache', state: 'ok', raw_state: 'paused', image: 'redis:7' },
      ],
      stats: {},
    })
    const wrapper = mount(Containers, MOUNT)
    await flushPromises()

    const leds = wrapper.findAll('tbody .led')
    expect(leds.length).toBe(3)
    for (const led of leds) {
      expect(led.attributes('aria-hidden'), 'LED must be decoration').toBe('true')
    }
    const spelled = wrapper.findAll('tbody .led + .sr-only').map((el) => el.text())
    expect(spelled).toContain('common.running')
    expect(spelled).toContain('common.stopped')
    expect(spelled).toContain('docker.paused')
    wrapper.unmount()
  })
})

describe('Containers re-poll failure', () => {
  it('keeps the stale rows on screen below the failure banner', async () => {
    api.getContainers.mockResolvedValue({ engine_up: true, containers: [WEB], stats: {} })
    const wrapper = mount(Containers, MOUNT)
    await flushPromises()
    expect(wrapper.text()).toContain('web')

    api.getContainers.mockRejectedValue(new Error('backend unreachable'))
    await wrapper.find('.toolbar button.primary').trigger('click')
    await flushPromises()

    const banner = wrapper.find('.load-failure')
    expect(banner.exists(), 'failure banner above the stale rows').toBe(true)
    expect(banner.text()).toContain('backend unreachable')
    // The rows the operator was reading stay on screen below the banner.
    expect(wrapper.text()).toContain('web')
    expect(wrapper.find('tbody').exists()).toBe(true)
    wrapper.unmount()
  })

  it('a failed first load renders the banner alone — no empty-state claims', async () => {
    api.getContainers.mockRejectedValue(new Error('backend unreachable'))
    const wrapper = mount(Containers, MOUNT)
    await flushPromises()

    expect(wrapper.find('.load-failure').exists()).toBe(true)
    const text = wrapper.text()
    expect(text).not.toContain('docker.no_containers')
    expect(text).not.toContain('common.no_match')
    expect(text).not.toContain('docker.engine_off')
    wrapper.unmount()
  })
})
