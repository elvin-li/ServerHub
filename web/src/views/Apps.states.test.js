/**
 * Apps page: a filter that matches nothing must say "no match", not "empty".
 *
 * Both Apps tables carried a single empty string. The managed inventory said
 * "no managed apps" while a kind/search filter simply matched nothing on a
 * host full of apps, and the catalog said "no apps available" while a search
 * hid a fully stocked store. Services/Tools/Brew/Containers already tell the
 * two apart (filterStates.test.js and friends pin them), so the pattern is
 * established: `common.no_match` when the underlying list has rows, the
 * table's own empty string only when it really is empty.
 *
 * The filter counts stay announced through role="status", the same live
 * region the Services filter uses.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'

const api = vi.hoisted(() => ({
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
  getStackJob: vi.fn(),
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
}))

vi.mock('../api/client', () => api)
vi.mock('../i18n', () => ({
  injectI18n: () => ({ t: (key) => key }),
}))
vi.mock('vue-router', () => ({
  useRouter: () => ({ push: vi.fn() }),
}))

import Apps from './Apps.vue'

const MANAGED_ITEM = {
  id: 'native:native-redis',
  source_id: 'native-redis',
  kind: 'native',
  name: 'Redis',
  state: 'ok',
  status_text: 'running',
  installed: true,
  ports_summary: '',
  actions: ['detail'],
}

const TEMPLATE = {
  id: 'jellyfin',
  name: 'Jellyfin',
  kind: 'docker',
  installed: false,
  featured: false,
  category: 'media',
  desc: 'demo',
  notes: '',
  tags: [],
  ports: [],
  images: [],
  vars: [],
  first_run_credentials: '',
  compose_warnings: [],
  source: 'builtin',
  builtin_available: true,
}

function mountApps() {
  return mount(Apps, {
    global: {
      provide: { toast: vi.fn() },
      stubs: { SkeletonLoader: true, LoadFailure: true, 'router-link': true },
    },
  })
}

beforeEach(() => {
  for (const fn of Object.values(api)) {
    if (typeof fn?.mockReset === 'function') fn.mockResolvedValue({})
  }
  api.getManagedApps.mockResolvedValue({ items: [], counts: null })
  api.getCatalog.mockResolvedValue({ templates: [] })
  api.getStacks.mockResolvedValue({ stacks: [], jobs: [] })
})

afterEach(() => {
  vi.clearAllMocks()
})

describe('Apps managed inventory filter', () => {
  it('tells a filter miss apart from a host with no managed apps', async () => {
    api.getManagedApps.mockResolvedValue({ items: [MANAGED_ITEM], counts: null })
    const wrapper = mountApps()
    await flushPromises()

    expect(wrapper.find('tbody').text()).toContain('Redis')

    wrapper.vm.mq = 'no-such-app'
    await flushPromises()
    const missed = wrapper.find('tbody').text()
    expect(missed).toContain('common.no_match')
    expect(missed).not.toContain('apps.managed_empty')
    wrapper.unmount()
  })

  it('a kind filter that hides everything is also a miss, not empty', async () => {
    api.getManagedApps.mockResolvedValue({ items: [MANAGED_ITEM], counts: null })
    const wrapper = mountApps()
    await flushPromises()

    wrapper.vm.mkind = 'vm'
    await flushPromises()
    const missed = wrapper.find('tbody').text()
    expect(missed).toContain('common.no_match')
    expect(missed).not.toContain('apps.managed_empty')
    wrapper.unmount()
  })

  it('reports a truly empty inventory as empty, not as a filter miss', async () => {
    const wrapper = mountApps()
    await flushPromises()

    const body = wrapper.find('tbody').text()
    expect(body).toContain('apps.managed_empty')
    expect(body).not.toContain('common.no_match')
    wrapper.unmount()
  })

  it('announces the result count next to the filter box', async () => {
    api.getManagedApps.mockResolvedValue({ items: [MANAGED_ITEM], counts: null })
    const wrapper = mountApps()
    await flushPromises()

    const count = wrapper.find('.meta-count[role="status"]')
    expect(count.exists(), 'live result count').toBe(true)
    expect(count.text()).toBe('1 / 1')
    wrapper.unmount()
  })

  it('does not throw when managed items is a leftover mapping', async () => {
    api.getManagedApps.mockResolvedValue({ items: { 0: MANAGED_ITEM }, counts: [1] })
    const wrapper = mountApps()
    await flushPromises()
    expect(wrapper.find('tbody').text()).toContain('apps.managed_empty')
    wrapper.vm.mq = 'redis'
    await flushPromises()
    expect(wrapper.find('tbody').text()).toContain('apps.managed_empty')
    wrapper.unmount()
  })

  it('does not throw when the managed payload is leftover JSON null', async () => {
    api.getManagedApps.mockResolvedValue(null)
    const wrapper = mountApps()
    await flushPromises()
    expect(wrapper.find('tbody').text()).toContain('apps.managed_empty')
    wrapper.unmount()
  })

  it('does not throw when a managed name is leftover JSON number during search', async () => {
    api.getManagedApps.mockResolvedValue({
      items: [{ ...MANAGED_ITEM, name: 6379, id: 12, ports_summary: 6379 }],
      counts: null,
    })
    const wrapper = mountApps()
    await flushPromises()
    wrapper.vm.mq = 'redis'
    await flushPromises()
    expect(wrapper.find('tbody').text()).toContain('common.no_match')
    wrapper.unmount()
  })
})

describe('Apps catalog filter', () => {
  async function openCatalog(wrapper) {
    await wrapper.findAll('.tabs button')[2].trigger('click')
    await flushPromises()
  }

  it('tells a filter miss apart from an empty store', async () => {
    api.getCatalog.mockResolvedValue({ templates: [TEMPLATE] })
    const wrapper = mountApps()
    await flushPromises()
    await openCatalog(wrapper)

    expect(wrapper.text()).toContain('Jellyfin')

    wrapper.vm.q = 'no-such-template'
    await flushPromises()
    const missed = wrapper.find('.placeholder').text()
    expect(missed).toContain('common.no_match')
    expect(missed).not.toContain('apps.empty')
    wrapper.unmount()
  })

  it('reports a truly empty store as empty, not as a filter miss', async () => {
    const wrapper = mountApps()
    await flushPromises()
    await openCatalog(wrapper)

    const placeholder = wrapper.find('.placeholder').text()
    expect(placeholder).toContain('apps.empty')
    expect(placeholder).not.toContain('common.no_match')
    wrapper.unmount()
  })

  it('announces the result count next to the filter box', async () => {
    api.getCatalog.mockResolvedValue({ templates: [TEMPLATE] })
    const wrapper = mountApps()
    await flushPromises()
    await openCatalog(wrapper)

    const count = wrapper.find('.meta-count[role="status"]')
    expect(count.exists(), 'live result count').toBe(true)
    expect(count.text()).toBe('1 / 1')
    wrapper.unmount()
  })
})
