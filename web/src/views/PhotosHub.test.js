/**
 * PhotosHub page: empty state must not probe Immich, and a missing tree
 * must not render the delete-review toolbar. Settings and logs stay lazy.
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
  getPhotosHubConfig: vi.fn(),
  patchPhotosHubConfig: vi.fn(),
  getPhotosHubPending: vi.fn(),
  photosHubThumbUrl: (id) => `/api/photoshub/pending-delete/thumb/${encodeURIComponent(id)}`,
  postPhotosHubAction: vi.fn(),
  postPhotosHubPendingRemove: vi.fn(),
  getPhotosHubLogs: vi.fn(),
}))

const {
  getPhotosHubStatus, getPhotosHubConfig, patchPhotosHubConfig,
  getPhotosHubPending, getPhotosHubLogs, postPhotosHubPendingRemove,
} = await import('../api/client')
const PhotosHub = (await import('./PhotosHub.vue')).default

const INSTALLED = {
  ts: '2026-08-15T12:00:00+08:00',
  photoshub_ok: true,
  originals: { local_original_pct: 99, originals_present: 10, assets_active: 10, gate_ready: true },
  bridge: { mode: 'export', last_success: '2026-08-15', exported_files: 3 },
  delete_review: { pending_count: 2 },
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
  people: {
    yuanbao: { name: 'Yuanbao', birthday: '2022-02' },
    erbao: { name: 'Erbao', birthday: '2024-12' },
  },
}

const CONFIG = {
  photoshub_ok: true,
  people: INSTALLED.people,
  albums: INSTALLED.albums,
  immich: { base_url: 'http://127.0.0.1:2283', public_url: 'http://127.0.0.1:8282', has_api_key: true },
  panel: { url: '' },
  gates: { allow_delete_channel: true, allow_cleanup: false, min_local_original_pct: 99 },
  bridge: { force_fallback: true, note: '' },
  paths: {
    photos_library: '/Volumes/PhotoVault/Photos Library.photoslibrary',
    bridge_dir: '/Volumes/PhotoVault/PhotosBridge/library',
    inbox_dir: '',
    backup_dir: '',
    media_location: '',
  },
}

function mountPage() {
  return mount(PhotosHub, {
    global: {
      provide: { toast: vi.fn() },
      stubs: {
        LoadFailure: { props: ['detail'], template: '<div class="load-failure">{{ detail }}</div>' },
        SkeletonLoader: { template: '<div class="skeleton" />' },
      },
    },
  })
}

function tabButton(wrap, key) {
  const found = wrap.findAll('button').find((button) => button.text().startsWith(key))
  expect(found, `tab ${key}`).toBeTruthy()
  return found
}

afterEach(() => {
  vi.clearAllMocks()
  const url = new URL(window.location.href)
  url.search = ''
  history.replaceState(null, '', url)
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
    expect(getPhotosHubConfig).not.toHaveBeenCalled()
    wrap.unmount()
  })

  it('keeps pending and logs off the overview until those tabs open', async () => {
    getPhotosHubStatus.mockResolvedValue(INSTALLED)
    getPhotosHubPending.mockResolvedValue({ album: 'Pending Delete', assets: [], count: 0 })
    getPhotosHubLogs.mockResolvedValue({ name: 'bridge', lines: ['ok'] })
    getPhotosHubConfig.mockResolvedValue(CONFIG)
    const wrap = mountPage()
    await flushPromises()
    expect(wrap.find('[data-test="photoshub-absent"]').exists()).toBe(false)
    expect(wrap.find('[data-test="photoshub-pending"]').exists()).toBe(false)
    expect(wrap.text()).toContain('Yuanbao')
    // The status payload already carries delete_review.pending_count: the
    // overview tile shows that number without fetching the pending list.
    expect(wrap.text()).toContain('photoshub.pending 2')
    expect(wrap.text()).not.toContain('photoshub.act_backup')
    expect(getPhotosHubPending).not.toHaveBeenCalled()
    expect(getPhotosHubLogs).not.toHaveBeenCalled()
    wrap.unmount()
  })

  it('loads the pending list only after opening that tab', async () => {
    getPhotosHubStatus.mockResolvedValue(INSTALLED)
    getPhotosHubPending.mockResolvedValue({ album: 'Pending Delete', assets: [], count: 0 })
    const wrap = mountPage()
    await flushPromises()
    await tabButton(wrap, 'photoshub.tab_pending').trigger('click')
    await flushPromises()
    expect(wrap.find('[data-test="photoshub-pending"]').exists()).toBe(true)
    expect(getPhotosHubPending).toHaveBeenCalledTimes(1)
    wrap.unmount()
  })

  it('loads settings and can save the safe fields', async () => {
    getPhotosHubStatus.mockResolvedValue(INSTALLED)
    getPhotosHubConfig.mockResolvedValue(CONFIG)
    patchPhotosHubConfig.mockResolvedValue(CONFIG)
    const wrap = mountPage()
    await flushPromises()
    await tabButton(wrap, 'photoshub.tab_settings').trigger('click')
    await flushPromises()
    expect(wrap.find('[data-test="photoshub-settings"]').exists()).toBe(true)
    expect(getPhotosHubConfig).toHaveBeenCalledTimes(1)
    expect(wrap.get('#ph-yuanbao-name').element.value).toBe('Yuanbao')
    expect(wrap.text()).toContain('photoshub.act_backup')
    await wrap.get('#ph-yuanbao-name').setValue('元宝')
    await wrap.findAll('button').find((button) => button.text() === 'common.save').trigger('click')
    await flushPromises()
    expect(patchPhotosHubConfig).toHaveBeenCalledTimes(1)
    const body = patchPhotosHubConfig.mock.calls[0][0]
    expect(body.people.yuanbao.name).toBe('元宝')
    expect(body.immich.base_url).toBe('http://127.0.0.1:2283')
    wrap.unmount()
  })

  it('keeps unsaved settings when switching tabs', async () => {
    getPhotosHubStatus.mockResolvedValue(INSTALLED)
    getPhotosHubConfig.mockResolvedValue(CONFIG)
    const wrap = mountPage()
    await flushPromises()
    await tabButton(wrap, 'photoshub.tab_settings').trigger('click')
    await flushPromises()
    await wrap.get('#ph-yuanbao-name').setValue('元宝')
    await tabButton(wrap, 'photoshub.tab_overview').trigger('click')
    await flushPromises()
    await tabButton(wrap, 'photoshub.tab_settings').trigger('click')
    await flushPromises()
    expect(wrap.get('#ph-yuanbao-name').element.value).toBe('元宝')
    expect(getPhotosHubConfig).toHaveBeenCalledTimes(2)
    wrap.unmount()
  })

  it('keeps the page up when settings fail to load', async () => {
    getPhotosHubStatus.mockResolvedValue(INSTALLED)
    getPhotosHubConfig.mockRejectedValue(new Error('no config route'))
    const wrap = mountPage()
    await flushPromises()
    await tabButton(wrap, 'photoshub.tab_settings').trigger('click')
    await flushPromises()
    expect(wrap.find('.load-failure').exists()).toBe(false)
    expect(wrap.find('[data-test="photoshub-settings-error"]').text()).toContain('no config route')
    wrap.unmount()
  })

  it('loads logs only after opening that tab', async () => {
    getPhotosHubStatus.mockResolvedValue(INSTALLED)
    getPhotosHubLogs.mockResolvedValue({ name: 'bridge', lines: ['ok'] })
    const wrap = mountPage()
    await flushPromises()
    await tabButton(wrap, 'photoshub.tab_logs').trigger('click')
    await flushPromises()
    expect(getPhotosHubLogs).toHaveBeenCalledWith('bridge')
    wrap.unmount()
  })

  it('shows a preview per pending photo instead of filenames alone', async () => {
    getPhotosHubStatus.mockResolvedValue(INSTALLED)
    getPhotosHubPending.mockResolvedValue({
      album: 'Pending Delete',
      count: 2,
      assets: [
        { id: 'aa-11', originalFileName: 'IMG_0001.HEIC', localDateTime: '2026-01-02', type: 'IMAGE' },
        { id: 'bb-22', originalFileName: 'IMG_0002.HEIC', localDateTime: '2026-01-03', type: 'IMAGE' },
      ],
    })
    const wrap = mountPage()
    await flushPromises()
    await tabButton(wrap, 'photoshub.tab_pending').trigger('click')
    await flushPromises()
    const imgs = wrap.findAll('[data-test="photoshub-pending-grid"] img')
    expect(imgs).toHaveLength(2)
    // The preview goes through the panel, so the Immich key stays server-side.
    expect(imgs[0].attributes('src')).toBe('/api/photoshub/pending-delete/thumb/aa-11')
    // A long album must not fetch every tile at once.
    expect(imgs[0].attributes('loading')).toBe('lazy')
    expect(imgs[0].attributes('alt')).toBe('IMG_0001.HEIC')
    expect(wrap.text()).toContain('IMG_0001.HEIC')
    wrap.unmount()
  })

  it('falls back to the asset type when a preview cannot be fetched', async () => {
    getPhotosHubStatus.mockResolvedValue(INSTALLED)
    getPhotosHubPending.mockResolvedValue({
      album: 'Pending Delete',
      count: 1,
      assets: [{ id: 'aa-11', originalFileName: 'IMG_0001.HEIC', type: 'IMAGE' }],
    })
    const wrap = mountPage()
    await flushPromises()
    await tabButton(wrap, 'photoshub.tab_pending').trigger('click')
    await flushPromises()
    await wrap.get('[data-test="photoshub-pending-grid"] img').trigger('error')
    expect(wrap.find('[data-test="photoshub-pending-grid"] img').exists()).toBe(false)
    expect(wrap.get('.review-noimg').text()).toBe('IMAGE')
    wrap.unmount()
  })

  it('selects tiles and removes only the picked ids', async () => {
    getPhotosHubStatus.mockResolvedValue(INSTALLED)
    getPhotosHubPending.mockResolvedValue({
      album: 'Pending Delete',
      count: 2,
      assets: [
        { id: 'aa-11', originalFileName: 'IMG_0001.HEIC', type: 'IMAGE' },
        { id: 'bb-22', originalFileName: 'IMG_0002.HEIC', type: 'IMAGE' },
      ],
    })
    postPhotosHubPendingRemove.mockResolvedValue({ removed: 1 })
    vi.spyOn(window, 'confirm').mockReturnValue(true)
    const wrap = mountPage()
    await flushPromises()
    await tabButton(wrap, 'photoshub.tab_pending').trigger('click')
    await flushPromises()
    await wrap.get('[data-test="photoshub-pending-grid"] input[type="checkbox"]').setValue(true)
    await wrap.findAll('button')
      .find((b) => b.text().startsWith('photoshub.remove_selected'))
      .trigger('click')
    await flushPromises()
    expect(postPhotosHubPendingRemove).toHaveBeenCalledWith(['aa-11'])
    wrap.unmount()
  })

  it('announces a running action through a live status note', async () => {
    // The note was paint only: the actions run for seconds and disable the
    // toolbar, and a screen-reader user heard nothing until the finish toast.
    getPhotosHubStatus.mockResolvedValue(INSTALLED)
    const { postPhotosHubAction } = await import('../api/client')
    let finish
    postPhotosHubAction.mockImplementation(() => new Promise((resolve) => { finish = resolve }))
    vi.spyOn(window, 'confirm').mockReturnValue(true)
    const wrapper = mountPage()
    await flushPromises()

    await wrapper.findAll('button').find((b) => b.text() === 'photoshub.act_sync').trigger('click')
    const note = wrapper.find('.toolbar [role="status"]')
    expect(note.exists(), 'busy note is a live region').toBe(true)
    expect(note.attributes('aria-live')).toBe('polite')
    expect(note.text()).toContain('photoshub.action_running')

    finish({ action: 'sync', ok: true, status_after: INSTALLED })
    await flushPromises()
    expect(wrapper.find('.toolbar [role="status"]').exists()).toBe(false)
    wrapper.unmount()
  })

  it('does not toast a settings save that finishes after leave', async () => {
    getPhotosHubStatus.mockResolvedValue(INSTALLED)
    getPhotosHubConfig.mockResolvedValue(CONFIG)
    let finish
    patchPhotosHubConfig.mockImplementation(() => new Promise((resolve) => { finish = resolve }))
    const toast = vi.fn()
    const wrap = mount(PhotosHub, {
      global: {
        provide: { toast },
        stubs: {
          LoadFailure: { props: ['detail'], template: '<div class="load-failure">{{ detail }}</div>' },
          SkeletonLoader: { template: '<div class="skeleton" />' },
        },
      },
    })
    await flushPromises()
    await tabButton(wrap, 'photoshub.tab_settings').trigger('click')
    await flushPromises()
    await wrap.findAll('button').find((button) => button.text() === 'common.save').trigger('click')
    wrap.unmount()
    finish(CONFIG)
    await flushPromises()
    expect(toast).not.toHaveBeenCalled()
  })

  it('can still save a half-configured install', async () => {
    // The API treats immich.base_url and albums.pending_delete as required and
    // rejects the whole patch when either arrives as "". Sending them empty
    // meant an operator who had not filled in Immich's address yet could not
    // save anything at all -- a birthday came back as "invalid Immich URL".
    const partial = {
      ...CONFIG,
      albums: { pending_delete: '', yuanbao: '', erbao: '' },
      immich: { base_url: '', public_url: '', has_api_key: false },
    }
    getPhotosHubStatus.mockResolvedValue(INSTALLED)
    getPhotosHubConfig.mockResolvedValue(partial)
    patchPhotosHubConfig.mockResolvedValue(partial)
    const wrap = mountPage()
    await flushPromises()
    await tabButton(wrap, 'photoshub.tab_settings').trigger('click')
    await flushPromises()
    await wrap.get('#ph-yuanbao-name').setValue('Yuanbao')
    await wrap.findAll('button').find((b) => b.text() === 'common.save').trigger('click')
    await flushPromises()
    const body = patchPhotosHubConfig.mock.calls[0][0]
    expect(body.people.yuanbao.name).toBe('Yuanbao')
    // Absent, not empty: the API reads a missing key as "leave this alone".
    expect('base_url' in body.immich).toBe(false)
    expect('pending_delete' in body.albums).toBe(false)
    wrap.unmount()
  })

  it('still sends the required fields once they are filled in', async () => {
    getPhotosHubStatus.mockResolvedValue(INSTALLED)
    getPhotosHubConfig.mockResolvedValue(CONFIG)
    patchPhotosHubConfig.mockResolvedValue(CONFIG)
    const wrap = mountPage()
    await flushPromises()
    await tabButton(wrap, 'photoshub.tab_settings').trigger('click')
    await flushPromises()
    await wrap.findAll('button').find((b) => b.text() === 'common.save').trigger('click')
    await flushPromises()
    const body = patchPhotosHubConfig.mock.calls[0][0]
    expect(body.immich.base_url).toBe('http://127.0.0.1:2283')
    expect(body.albums.pending_delete).toBe('Pending Delete')
    wrap.unmount()
  })

  it('reports a failed removal inside the pending tab, not as a page failure', async () => {
    getPhotosHubStatus.mockResolvedValue(INSTALLED)
    getPhotosHubPending.mockResolvedValue({
      album: 'Pending Delete',
      count: 1,
      assets: [{ id: 'aa-11', originalFileName: 'IMG_0001.HEIC', type: 'IMAGE' }],
    })
    postPhotosHubPendingRemove.mockRejectedValue(new Error('immich refused'))
    vi.spyOn(window, 'confirm').mockReturnValue(true)
    const wrap = mountPage()
    await flushPromises()
    await tabButton(wrap, 'photoshub.tab_pending').trigger('click')
    await flushPromises()
    await wrap.get('[data-test="photoshub-pending-grid"] input[type="checkbox"]').setValue(true)
    await wrap.findAll('button')
      .find((b) => b.text().startsWith('photoshub.remove_selected'))
      .trigger('click')
    await flushPromises()
    // A whole-page failure banner here offers a "reload everything" retry for a
    // page that loaded fine, and stays until the next full load.
    expect(wrap.find('.load-failure').exists()).toBe(false)
    expect(wrap.get('[data-test="photoshub-pending-error"]').text()).toContain('immich refused')
    wrap.unmount()
  })

  it('does not discard the router history state when remembering a tab', async () => {
    // vue-router keeps its scroll position and back/forward bookkeeping in
    // history.state; replacing it with null breaks navigation for the session.
    history.replaceState({ current: '/photoshub', position: 3 }, '', window.location.href)
    getPhotosHubStatus.mockResolvedValue(INSTALLED)
    getPhotosHubPending.mockResolvedValue({ album: 'Pending Delete', assets: [], count: 0 })
    const wrap = mountPage()
    await flushPromises()
    await tabButton(wrap, 'photoshub.tab_pending').trigger('click')
    await flushPromises()
    expect(new URL(window.location.href).searchParams.get('tab')).toBe('pending')
    expect(history.state).toMatchObject({ current: '/photoshub', position: 3 })
    wrap.unmount()
  })

  it('shows the delete-review count from status before the pending tab opens', async () => {
    // pendingCount used to read only the pending-tab payload, so the overview
    // tile and the tab label said "—" for a number the status response had
    // been handing the page all along.
    getPhotosHubStatus.mockResolvedValue({
      ...INSTALLED,
      delete_review: { pending_count: 7 },
    })
    const wrap = mountPage()
    await flushPromises()
    expect(wrap.text()).toContain('photoshub.pending 7')
    expect(tabButton(wrap, 'photoshub.tab_pending').text()).toContain('(7)')
    expect(getPhotosHubPending).not.toHaveBeenCalled()
    wrap.unmount()
  })

  it('announces the pending count and empty state as live status regions', async () => {
    // "Refresh pending list" and "Remove" answer only through the count and
    // the tiles (or the scanning -> "no pending" flip on an empty album);
    // both changed silently for a screen reader.
    getPhotosHubStatus.mockResolvedValue(INSTALLED)
    getPhotosHubPending.mockResolvedValue({
      album: 'Pending Delete',
      count: 2,
      assets: [
        { id: 'aa-11', originalFileName: 'IMG_0001.HEIC', type: 'IMAGE' },
        { id: 'bb-22', originalFileName: 'IMG_0002.HEIC', type: 'IMAGE' },
      ],
    })
    const wrap = mountPage()
    await flushPromises()
    await tabButton(wrap, 'photoshub.tab_pending').trigger('click')
    await flushPromises()
    const count = wrap.get('[data-test="photoshub-pending-count"]')
    expect(count.attributes('role')).toBe('status')
    expect(count.text()).toContain('2')

    getPhotosHubPending.mockResolvedValue({ album: 'Pending Delete', count: 0, assets: [] })
    await wrap.findAll('button').find((b) => b.text() === 'photoshub.refresh_pending').trigger('click')
    await flushPromises()
    const empty = wrap.get('[data-test="photoshub-pending-empty"]')
    expect(empty.attributes('role')).toBe('status')
    expect(empty.text()).toContain('photoshub.no_pending')
    wrap.unmount()
  })

  it('keeps the stale overview under the banner when a re-poll fails', async () => {
    // The LoadFailure contract (Alerts / Users / Containers): a failed
    // refresh puts the banner above the tiles the operator was reading,
    // instead of replacing them wholesale.
    getPhotosHubStatus.mockResolvedValue(INSTALLED)
    const wrap = mountPage()
    await flushPromises()
    getPhotosHubStatus.mockRejectedValue(new Error('poll died'))
    await wrap.findAll('button').find((b) => b.text() === 'common.refresh').trigger('click')
    await flushPromises()
    expect(wrap.find('.load-failure').text()).toContain('poll died')
    expect(wrap.text()).toContain('Yuanbao')
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

  it('discards a status payload that arrives after unmount', async () => {
    let resolveStatus
    getPhotosHubStatus.mockImplementation(() => new Promise((resolve) => {
      resolveStatus = resolve
    }))
    const wrap = mountPage()
    wrap.unmount()
    resolveStatus(INSTALLED)
    await flushPromises()
    expect(wrap.find('[data-test="photoshub-absent"]').exists()).toBe(false)
    expect(wrap.find('.load-failure').exists()).toBe(false)
  })
})
