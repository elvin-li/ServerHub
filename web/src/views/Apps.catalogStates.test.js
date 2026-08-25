/**
 * The catalog tab's three non-happy states.
 *
 * A data-backed grid has to distinguish "the request failed", "there is
 * nothing here" and "your filter matched nothing".  The catalog tab
 * conflated the last two — a search miss claimed `apps.empty` as if the
 * store had no templates — and rendered the LoadFailure banner *below* the
 * grid, so on a failed refresh the stale cards pushed the only evidence of
 * the failure off-screen and the page looked healthy while showing old
 * data.  The placeholders also changed silently for a screen reader: they
 * are the grid's only answer to a filter change, so they carry role=status
 * now (the same treatment the filter count beside them already has).
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
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

const TEMPLATE = {
  id: 'demo',
  name: 'Demo App',
  kind: 'docker',
  installed: false,
  featured: false,
  category: 'other',
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
      // vue-router is module-mocked above, so RouterLink must be stubbed too.
      // LoadFailure deliberately not stubbed: its placement is the subject.
      stubs: { SkeletonLoader: true, 'router-link': true },
    },
  })
}

async function openCatalog(wrapper) {
  await wrapper.findAll('.tabs button')[2].trigger('click')
  await flushPromises()
}

beforeEach(() => {
  vi.clearAllMocks()
  api.getManagedApps.mockResolvedValue({ items: [], counts: null })
  api.getAutostartApps.mockResolvedValue({ items: [], counts: null, groups: [] })
  api.getStacks.mockResolvedValue({ stacks: [], jobs: [] })
  api.getCatalog.mockResolvedValue({
    templates: [TEMPLATE],
    categories: [],
    counts: {},
    total: 1,
    installed: 0,
  })
})

describe('empty vs filter-miss', () => {
  it('a search miss says no_match, not the empty-catalog line', async () => {
    const wrapper = mountApps()
    await flushPromises()
    await openCatalog(wrapper)
    expect(wrapper.findAll('.app-card').length).toBe(1)

    await wrapper.find('input.search').setValue('zzz-no-such-app')
    await flushPromises()

    const placeholder = wrapper.find('.placeholder')
    expect(placeholder.exists()).toBe(true)
    expect(placeholder.text()).toContain('common.no_match')
    expect(placeholder.text()).not.toContain('apps.empty')
    expect(placeholder.attributes('role')).toBe('status')
    wrapper.unmount()
  })

  it('a genuinely empty catalog keeps the empty-catalog line', async () => {
    api.getCatalog.mockResolvedValue({
      templates: [],
      categories: [],
      counts: {},
      total: 0,
      installed: 0,
    })
    const wrapper = mountApps()
    await flushPromises()
    await openCatalog(wrapper)

    const placeholder = wrapper.find('.placeholder')
    expect(placeholder.exists()).toBe(true)
    expect(placeholder.text()).toContain('apps.empty')
    expect(placeholder.attributes('role')).toBe('status')
    wrapper.unmount()
  })
})

describe('failed refresh over stale rows', () => {
  it('renders the failure banner above the stale cards, not under them', async () => {
    const wrapper = mountApps()
    await flushPromises()
    await openCatalog(wrapper)
    expect(wrapper.findAll('.app-card').length).toBe(1)

    api.getCatalog.mockRejectedValue(new Error('backend unreachable'))
    await wrapper
      .findAll('button')
      .find((b) => b.text() === 'common.refresh')
      .trigger('click')
    await flushPromises()

    const banner = wrapper.element.querySelector('.load-failure')
    const grid = wrapper.element.querySelector('.app-grid')
    expect(banner, 'no failure banner rendered').toBeTruthy()
    expect(wrapper.find('.load-failure-detail').text()).toContain('backend unreachable')
    // The stale listing stays (best information available)…
    expect(wrapper.findAll('.app-card').length).toBe(1)
    // …but the banner precedes it in the document, so it cannot be pushed
    // off-screen by a populated catalog.
    expect(
      banner.compareDocumentPosition(grid) & Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy()
    wrapper.unmount()
  })
})
