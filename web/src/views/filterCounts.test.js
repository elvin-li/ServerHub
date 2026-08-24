/**
 * Every text filter announces its result count (WCAG 4.1.3).
 *
 * Typing into a filter box shrinks the table below it, and the count is the
 * only feedback the box gives — a sighted user watches rows disappear, a
 * screen-reader user heard nothing at all. Tools, Scheduler and Services
 * already announce "shown / total" through a role="status" span next to the
 * box (filterStates.test.js pins the first two); these four views carry the
 * same kind of filter and were left silent. The count also tells a filter
 * miss ("0 / 12") apart from a host with nothing to list ("0 / 0").
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'

const api = vi.hoisted(() => ({
  // Maintenance
  getMaintenance: vi.fn(),
  getMaintenanceLog: vi.fn(),
  runMaintenance: vi.fn(),
  // Brew
  brewAction: vi.fn(),
  getBrewServices: vi.fn(),
  // Audit
  getAuthAudit: vi.fn(),
  // Containers
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

import Maintenance from './Maintenance.vue'
import Brew from './Brew.vue'
import Audit from './Audit.vue'
import Containers from './Containers.vue'

const MOUNT = {
  global: {
    provide: { toast: vi.fn() },
    stubs: { RouterLink: { template: '<a><slot /></a>' } },
  },
}

beforeEach(() => {
  for (const fn of Object.values(api)) {
    if (typeof fn?.mockReset === 'function') fn.mockResolvedValue({})
  }
})

afterEach(() => {
  vi.clearAllMocks()
})

// One matching row, then a filter that misses it: the announced count must
// move from "1 / 1" to "0 / 1", never fall silent.
async function expectLiveCount(wrapper, missQuery) {
  const count = wrapper.find('.meta-count[role="status"]')
  expect(count.exists(), 'live result count').toBe(true)
  expect(count.text()).toBe('1 / 1')

  wrapper.vm.q = missQuery
  await flushPromises()
  expect(count.text()).toBe('0 / 1')
}

describe('Maintenance task filter', () => {
  it('announces the result count next to the filter box', async () => {
    api.getMaintenance.mockResolvedValue({
      tasks: [{ id: 'smart-scan', name: 'SMART scan', desc: 'Check disks', schedule: 'daily' }],
    })
    const wrapper = mount(Maintenance, MOUNT)
    await flushPromises()

    await expectLiveCount(wrapper, 'no-such-task')
    wrapper.unmount()
  })
})

describe('Brew service filter', () => {
  it('announces the result count next to the filter box', async () => {
    api.getBrewServices.mockResolvedValue({
      services: [{ id: 'nginx', name: 'nginx', state: 'ok', status: 'started', actions: [] }],
    })
    const wrapper = mount(Brew, MOUNT)
    await flushPromises()

    await expectLiveCount(wrapper, 'no-such-service')
    wrapper.unmount()
  })
})

describe('Audit event filter', () => {
  it('announces the result count next to the filter box', async () => {
    api.getAuthAudit.mockResolvedValue({
      entries: [{ ts: 1700000000, event: 'login', username: 'sam', client: '10.0.0.2', outcome: 'ok' }],
      retained_lines: 200,
    })
    const wrapper = mount(Audit, MOUNT)
    await flushPromises()

    await expectLiveCount(wrapper, 'no-such-event')
    wrapper.unmount()
  })
})

describe('Containers filter', () => {
  it('announces the result count next to the filter box', async () => {
    api.getContainers.mockResolvedValue({
      engine_up: true,
      containers: [{ id: 'c1', name: 'web', state: 'ok', raw_state: 'running', image: 'nginx:1' }],
      stats: {},
    })
    const wrapper = mount(Containers, MOUNT)
    await flushPromises()

    await expectLiveCount(wrapper, 'no-such-container')
    wrapper.unmount()
  })
})
