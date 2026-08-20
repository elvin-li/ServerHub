/**
 * Files mutations that finish after leave must not toast.
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

