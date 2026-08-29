/**
 * Files mutations that finish after leave must not toast.
 *
 * Also pins the listing's failure state: a refresh that fails keeps the last
 * listing on screen, and its empty row must not claim the folder is empty
 * when the read that would prove it just failed.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'

const api = vi.hoisted(() => ({
  deleteFile: vi.fn(),
  ensureFileBrowser: vi.fn(),
  getFilesOverview: vi.fn(),
  listFiles: vi.fn(),
  makeDirectory: vi.fn(),
  renameFile: vi.fn(),
  stopFileBrowser: vi.fn(),
  uploadFile: vi.fn(),
}))

vi.mock('../api/client', () => api)
vi.mock('../i18n', () => ({
  injectI18n: () => ({
    t: (key, params = {}) => Object.entries(params).reduce(
      (text, [name, value]) => text.replace(`{${name}}`, value),
      key,
    ),
  }),
}))

import Files from './Files.vue'

const ROOT = { id: 'home', name: 'Home', path: '/Users/a' }
const FILE = {
  name: 'notes.txt',
  path: '/Users/a/notes.txt',
  is_dir: false,
  is_file: true,
  size: 12,
  mtime: 0,
  mode: '0644',
}

function listing() {
  return {
    path: ROOT.path,
    root: ROOT.path,
    root_id: ROOT.id,
    count: 1,
    items: [FILE],
    crumbs: [],
  }
}

async function mountFiles(toast = vi.fn()) {
  const wrapper = mount(Files, {
    global: { provide: { toast } },
  })
  await wrapper.find('button.primary').trigger('click')
  await flushPromises()
  return wrapper
}

beforeEach(() => {
  api.getFilesOverview.mockResolvedValue({ roots: [ROOT], filebrowser: {} })
  api.listFiles.mockResolvedValue(listing())
})

afterEach(() => {
  vi.unstubAllGlobals()
  vi.clearAllMocks()
})

describe('Files failed reads', () => {
  it('does not call a failed refresh of an empty folder "no items"', async () => {
    api.listFiles.mockResolvedValue({ ...listing(), count: 0, items: [] })
    const wrapper = await mountFiles()
    expect(wrapper.text()).toContain('files.empty')

    api.listFiles.mockRejectedValue(new Error('mount went away'))
    await wrapper.findAll('button').find((b) => b.text() === 'common.refresh').trigger('click')
    await flushPromises()

    const text = wrapper.text()
    expect(text, 'the reason must be shown in the error bar').toContain('mount went away')
    expect(text, 'the empty row must not contradict the error bar').not.toContain('files.empty')
    expect(wrapper.find('td.empty-row').text()).toBe('common.load_failed')
    wrapper.unmount()
  })
})

describe('Files toolbar a11y', () => {
  it('announces the item count as a live region', async () => {
    // The count is the toolbar's answer to every navigation, upload and
    // delete; without role=status it changed silently for a screen reader.
    const wrapper = await mountFiles()
    const count = wrapper.find('.meta-count[role="status"]')
    expect(count.exists(), 'live item count').toBe(true)
    expect(count.text()).toBe('1 files.items')
    wrapper.unmount()
  })

  it('keeps the upload input focusable instead of hidden', async () => {
    // The hidden attribute removed the input from the tab order and the
    // accessibility tree — keyboard and screen-reader users could not upload.
    const wrapper = await mountFiles()
    const input = wrapper.get('input[type="file"]')
    expect(input.attributes('hidden')).toBeUndefined()
    expect(input.classes()).toContain('sr-only')
    wrapper.unmount()
  })
})

describe('Files leave-guards', () => {
  it('does not toast a mkdir that returns after leave', async () => {
    const toast = vi.fn()
    let resolveMkdir
    api.makeDirectory.mockImplementation(() => new Promise((resolve) => { resolveMkdir = resolve }))
    vi.stubGlobal('prompt', vi.fn(() => 'inbox'))
    const wrapper = await mountFiles(toast)
    await wrapper.findAll('button').find((b) => b.text() === 'files.mkdir').trigger('click')
    wrapper.unmount()
    resolveMkdir({ ok: true })
    await flushPromises()
    expect(toast).not.toHaveBeenCalled()
  })

  it('does not toast a rename that returns after leave', async () => {
    const toast = vi.fn()
    let resolveRename
    api.renameFile.mockImplementation(() => new Promise((resolve) => { resolveRename = resolve }))
    vi.stubGlobal('prompt', vi.fn(() => 'renamed.txt'))
    const wrapper = await mountFiles(toast)
    await wrapper.findAll('button').find((b) => b.text() === 'files.rename').trigger('click')
    wrapper.unmount()
    resolveRename({ ok: true })
    await flushPromises()
    expect(toast).not.toHaveBeenCalled()
  })

  it('does not toast an upload that returns after leave', async () => {
    const toast = vi.fn()
    let resolveUpload
    api.uploadFile.mockImplementation(() => new Promise((resolve) => { resolveUpload = resolve }))
    const wrapper = await mountFiles(toast)
    const input = wrapper.get('input[type="file"]')
    const file = new File(['hi'], 'a.txt', { type: 'text/plain' })
    Object.defineProperty(input.element, 'files', { value: [file] })
    await input.trigger('change')
    wrapper.unmount()
    resolveUpload({ ok: true })
    await flushPromises()
    expect(toast).not.toHaveBeenCalled()
  })

  it('does not toast FileBrowser start that returns after leave', async () => {
    const toast = vi.fn()
    let resolveFb
    api.ensureFileBrowser.mockImplementation(() => new Promise((resolve) => { resolveFb = resolve }))
    vi.stubGlobal('open', vi.fn())
    const wrapper = mount(Files, { global: { provide: { toast } } })
    await wrapper.findAll('button').find((b) => b.text() === 'files.open_full').trigger('click')
    wrapper.unmount()
    resolveFb({ ok: true, url: 'http://localhost:8125' })
    await flushPromises()
    expect(toast).not.toHaveBeenCalled()
  })
})

describe('Files leftover leftover lists', () => {
  it('does not throw when leftover roots and items are leftover mappings', async () => {
    api.getFilesOverview.mockResolvedValue({
      roots: { id: ROOT },
      filebrowser: ['not', 'a', 'record'],
    })
    api.listFiles.mockResolvedValue({
      path: ROOT.path,
      root: ROOT.path,
      root_id: ROOT.id,
      count: 1,
      items: { 0: FILE },
      crumbs: { 0: { name: 'Home', path: ROOT.path } },
    })
    const wrapper = await mountFiles()
    expect(wrapper.find('.err-bar').exists()).toBe(false)
    expect(wrapper.find('td.empty-row').exists()).toBe(true)
    wrapper.unmount()
  })
})

