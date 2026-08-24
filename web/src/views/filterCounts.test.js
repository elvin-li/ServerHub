/**
 * Every text filter announces its result count (WCAG 4.1.3).
 *
 * Typing into a filter box shrinks the table below it, and the count is the
 * only feedback the box gives — a sighted user watches rows disappear, a
 * screen-reader user heard nothing at all. Tools, Scheduler and Services
 * already announce "shown / total" through a role="status" span next to the
 * box (filterStates.test.js pins the first two); the views here carry the
 * same kind of filter and were left silent: Maintenance, Brew, Audit,
 * Containers, then the sweep that followed — the Apps catalog and managed
 * searches and the two Network port filters. (Logs is not here: its filter
 * already announces through its own role="status" matched-count, pinned by
 * Logs.test.js.) The count also tells a filter miss ("0 / 12") apart from a
 * host with nothing to list ("0 / 0").
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
  // Apps
  checkCatalogRemoteUpdates: vi.fn(),
  createCloudflareTunnel: vi.fn(),
  deleteAppCredential: vi.fn(),
  getAppCredential: vi.fn(),
  getAutostartApps: vi.fn(),
  getCatalog: vi.fn(),
  getCatalogRemote: vi.fn(),
  getCloudflareStatus: vi.fn(),
  getManagedAppDetail: vi.fn(),
  getManagedAppLogs: vi.fn(),
  getManagedApps: vi.fn(),
  getStacks: vi.fn(),
  installCatalog: vi.fn(),
  manageApp: vi.fn(),
  pollCloudflareLogin: vi.fn(),
  restartCloudflare: vi.fn(),
  restoreCatalogBuiltin: vi.fn(),
  routeCloudflareDns: vi.fn(),
  runAppAutostartNow: vi.fn(),
  runStack: vi.fn(),
  saveAppCredential: vi.fn(),
  setAppAutostart: vi.fn(),
  setCatalogRemoteSource: vi.fn(),
  setDockerAutostartPolicy: vi.fn(),
  startCloudflareLogin: vi.fn(),
  startCloudflareToken: vi.fn(),
  startCloudflareTunnel: vi.fn(),
  stopCloudflare: vi.fn(),
  uninstallCatalog: vi.fn(),
  // Network
  addNetworkAlias: vi.fn(),
  connectContainerNetwork: vi.fn(),
  getSystemNetwork: vi.fn(),
  lookupNetworkDns: vi.fn(),
  removeNetworkAlias: vi.fn(),
  runAliasAutoBind: vi.fn(),
  runNetworkFailover: vi.fn(),
  setContainerPorts: vi.fn(),
  setNetworkDhcp: vi.fn(),
  setNetworkDns: vi.fn(),
  setNetworkManual: vi.fn(),
  setNetworkServiceEnabled: vi.fn(),
  setNetworkServiceOrder: vi.fn(),
  setWifiPower: vi.fn(),
  switchNetworkProfile: vi.fn(),
  updateAliasAuto: vi.fn(),
}))
vi.mock('../api/client', () => api)
vi.mock('../i18n', () => ({
  injectI18n: () => ({ t: (key) => key, errText: (v) => String(v), locale: { value: 'en' } }),
}))
vi.mock('../lib/poll', () => ({ startVisibleInterval: () => () => {} }))
// Apps calls useRouter() during setup; module-mocking the router means its
// RouterLink must come from the MOUNT stubs below, like the other views.
vi.mock('vue-router', () => ({
  useRouter: () => ({ push: vi.fn() }),
}))

import Maintenance from './Maintenance.vue'
import Brew from './Brew.vue'
import Audit from './Audit.vue'
import Containers from './Containers.vue'
import Apps from './Apps.vue'
import Network from './Network.vue'

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
// move from "1 / 1" to "0 / 1", never fall silent. `model` is the ref the
// view binds its filter box to (most call it `q`).
async function expectLiveCount(wrapper, missQuery, model = 'q') {
  const count = wrapper.find('.meta-count[role="status"]')
  expect(count.exists(), 'live result count').toBe(true)
  expect(count.text()).toBe('1 / 1')

  wrapper.vm[model] = missQuery
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

function mountApps() {
  api.getManagedApps.mockResolvedValue({
    items: [{ id: 'plex', name: 'Plex', kind: 'docker', status_text: 'running', autostart: false }],
    counts: null,
  })
  api.getAutostartApps.mockResolvedValue({ items: [], counts: null, groups: [] })
  api.getStacks.mockResolvedValue({ stacks: [], jobs: [] })
  api.getCatalog.mockResolvedValue({
    templates: [{
      id: 'jellyfin', name: 'Jellyfin', kind: 'docker', category: 'media',
      desc: 'media server', tags: [], ports: [], images: [], vars: [],
      installed: false, featured: false, source: 'builtin',
    }],
    categories: [],
    total: 1,
    installed: 0,
  })
  return mount(Apps, MOUNT)
}

describe('Apps managed filter', () => {
  it('announces the result count next to the filter box', async () => {
    const wrapper = mountApps()
    await flushPromises()

    await expectLiveCount(wrapper, 'no-such-app', 'mq')
    wrapper.unmount()
  })
})

describe('Apps catalog filter', () => {
  it('announces the result count next to the filter box', async () => {
    const wrapper = mountApps()
    await flushPromises()
    wrapper.vm.tab = 'catalog'
    await flushPromises()

    await expectLiveCount(wrapper, 'no-such-template')
    wrapper.unmount()
  })
})

async function mountNetwork(tab) {
  api.getSystemNetwork.mockResolvedValue({
    ts: '20:00:00',
    engine_up: true,
    interfaces: [],
    services: [],
    listening: [{ process: 'nginx', pid: 100, user: 'root', address: '0.0.0.0', port: 80 }],
    routes: [],
    docker_ports: [{ container: 'web', status: 'running', host_ip: '0.0.0.0', host_port: 8080, container_port: 80, protocol: 'tcp' }],
    docker_networks: [],
    interface_addresses: [],
    hardware_ports: [],
  })
  const wrapper = mount(Network, MOUNT)
  await flushPromises()
  wrapper.vm.tab = tab
  await flushPromises()
  return wrapper
}

describe('Network listening-port filter', () => {
  it('announces the result count next to the filter box', async () => {
    const wrapper = await mountNetwork('ports')

    await expectLiveCount(wrapper, 'no-such-process', 'portQ')
    wrapper.unmount()
  })
})

describe('Network docker-port filter', () => {
  it('announces the result count next to the filter box', async () => {
    const wrapper = await mountNetwork('docker')

    await expectLiveCount(wrapper, 'no-such-container', 'dockerPortQ')
    wrapper.unmount()
  })
})
