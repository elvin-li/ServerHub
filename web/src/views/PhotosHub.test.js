/**
 * PhotosHub page: empty state must not probe Immich, and a missing tree
 * must not render the delete-review toolbar.
 */
import { afterEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'

vi.mock('../i18n', () => ({
  injectI18n: () => ({
    t: (key, params = {}) => Object.entries(params).reduce(
      (text, [name, value]) => text.replace(`{${name}}`, value),
      String(key),
    ),
    locale: { value: 'en' },
    setLocale: vi.fn(),
  }),
}))

vi.mock('../api/client', () => ({
  getPhotosHubStatus: vi.fn(),
  getPhotosHubPending: vi.fn(),
  postPhotosHubAction: vi.fn(),
  postPhotosHubPendingRemove: vi.fn(),
  getPhotosHubLogs: vi.fn(),
}))

const {
  getPhotosHubStatus, getPhotosHubPending, getPhotosHubLogs,
} = await import('../api/client')
const PhotosHub = (await import('./PhotosHub.vue')).default

const INSTALLED = {
  ts: '2026-08-15T12:00:00+08:00',
  photoshub_ok: true,
  originals: { local_original_pct: 99, originals_present: 10, assets_active: 10, gate_ready: true },
  bridge: { mode: 'export', last_success: '2026-08-15', exported_files: 3 },
  delete_review: { pending_count: 0 },
  cleanup: {},
  backup: {},
  external_backup: { last_success: null },
  inventory: {},
  gates: {
    originals_ready: true,
    allow_delete_channel: true,
    allow_cleanup: false,
    force_fallback: true,
  },
  links: { immich: 'http://127.0.0.1:2283', panel: '', handbook: '' },
  albums: { pending_delete: 'Pending Delete', yuanbao: '', erbao: '' },
}

function mountPage() {
  return mount(PhotosHub, {
    global: {
      stubs: {
        LoadFailure: { props: ['detail'], template: '<div class="load-failure">{{ detail }}</div>' },
        SkeletonLoader: { template: '<div class="skeleton" />' },
      },
    },
  })
}

afterEach(() => {
  vi.clearAllMocks()
})

describe('PhotosHub page', () => {
  it('shows an empty state and does not fetch pending or logs when absent', async () => {
    getPhotosHubStatus.mockResolvedValue({
      ...INSTALLED,
      photoshub_ok: false,
      links: { immich: '', panel: '', handbook: '' },
    })
    const wrap = mountPage()
    await flushPromises()
    expect(wrap.find('[data-test="photoshub-absent"]').exists()).toBe(true)
    expect(wrap.find('[data-test="photoshub-pending"]').exists()).toBe(false)
    expect(getPhotosHubPending).not.toHaveBeenCalled()
    expect(getPhotosHubLogs).not.toHaveBeenCalled()
    wrap.unmount()
  })

  it('loads pending and logs once the tree is present', async () => {
    getPhotosHubStatus.mockResolvedValue(INSTALLED)
    getPhotosHubPending.mockResolvedValue({ album: 'Pending Delete', assets: [], count: 0 })
    getPhotosHubLogs.mockResolvedValue({ name: 'bridge', lines: ['ok'] })
    const wrap = mountPage()
    await flushPromises()
    expect(wrap.find('[data-test="photoshub-absent"]').exists()).toBe(false)
    expect(wrap.find('[data-test="photoshub-pending"]').exists()).toBe(true)
    expect(getPhotosHubPending).toHaveBeenCalledTimes(1)
    expect(getPhotosHubLogs).toHaveBeenCalledWith('bridge')
    wrap.unmount()
  })

  it('surfaces a first-load failure', async () => {
    getPhotosHubStatus.mockRejectedValue(new Error('boom'))
    const wrap = mountPage()
    await flushPromises()
    expect(wrap.find('.load-failure').text()).toContain('boom')
    expect(getPhotosHubPending).not.toHaveBeenCalled()
    wrap.unmount()
  })
})
