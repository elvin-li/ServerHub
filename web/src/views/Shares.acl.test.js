/**
 * The per-user access block of the share edit sheet.
 *
 * macOS keeps per-user SMB access on the folder's ACL, so the sheet reads the
 * shared directory's entries, offers none/read/readwrite per local user, and
 * renders the verified read-back state the server returns after each write.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'

const api = vi.hoisted(() => ({
  createShare: vi.fn(),
  getShares: vi.fn(),
  getShareAcl: vi.fn(),
  openSharingSettings: vi.fn(),
  removeShare: vi.fn(),
  setShareAcl: vi.fn(),
  setSystemSharing: vi.fn(),
  updateShare: vi.fn(),
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

import Shares from './Shares.vue'

const SHARE = {
  record_name: 'Media', name: 'Media', smb_name: 'Media',
  path: '/Users/a0000/Media', shared: true, guest: false, readonly: false,
}

const ACL = {
  path: '/Users/a0000/Media',
  mode: 'drwxr-xr-x+',
  owner: 'a0000',
  group: 'staff',
  owned_by_panel: true,
  entries: [
    { index: 0, kind: 'user', name: 'guestshare', effect: 'allow',
      perms: ['list', 'search', 'readattr'], inherited: false, level: 'read' },
  ],
  users: [
    { username: 'a0000', uid: 502, real_name: 'Elvin' },
    { username: 'guestshare', uid: 503, real_name: 'Guest Share' },
  ],
}

async function mountWithEditOpen() {
  api.getShares.mockResolvedValue({
    host: { name: 'Mac' }, system_services: [], smb: [SHARE], file_services: [],
  })
  api.getShareAcl.mockResolvedValue(ACL)
  const toast = vi.fn()
  const wrapper = mount(Shares, { global: { provide: { toast } } })
  await flushPromises()
  const edit = wrapper.findAll('button').find((b) => b.text().includes('shares.edit_action'))
  await edit.trigger('click')
  await flushPromises()
  return { wrapper, toast }
}

beforeEach(() => {
  vi.clearAllMocks()
})

describe('share ACL block', () => {
  it('loads the folder ACL when the edit sheet opens', async () => {
    const { wrapper } = await mountWithEditOpen()
    expect(api.getShareAcl).toHaveBeenCalledWith('/Users/a0000/Media')
    expect(wrapper.text()).toContain('shares.acl_title')
    // Both local users are pickable; the grantee's current level is selected.
    const selects = wrapper.findAll('.acl-user-row select')
    expect(selects).toHaveLength(2)
    expect(selects[1].element.value).toBe('read')
    // The owner's select is disabled: their access comes from POSIX ownership.
    expect(selects[0].attributes('disabled')).toBeDefined()
  })

  it('applies a change and renders the verified read-back state', async () => {
    const { wrapper, toast } = await mountWithEditOpen()
    api.setShareAcl.mockResolvedValue({
      ok: true,
      path: ACL.path, mode: ACL.mode, owner: ACL.owner, group: ACL.group,
      owned_by_panel: true,
      entries: [
        { index: 0, kind: 'user', name: 'guestshare', effect: 'allow',
          perms: ['list', 'add_file', 'delete'], inherited: false, level: 'readwrite' },
      ],
    })

    const select = wrapper.findAll('.acl-user-row select')[1]
    await select.setValue('readwrite')
    await flushPromises()

    expect(api.setShareAcl).toHaveBeenCalledWith(
      '/Users/a0000/Media', 'guestshare', 'readwrite',
    )
    expect(toast).toHaveBeenCalledWith(expect.stringContaining('acl_saved'))
    expect(wrapper.findAll('.acl-user-row select')[1].element.value).toBe('readwrite')
  })

  it('voices the ACL loading placeholder while the read is in flight', async () => {
    // The sheet already holds focus when the read starts, so the placeholder
    // must be a status region for the swap to be announced at all.
    api.getShares.mockResolvedValue({
      host: { name: 'Mac' }, system_services: [], smb: [SHARE], file_services: [],
    })
    let release
    api.getShareAcl.mockReturnValue(new Promise((resolveAcl) => { release = resolveAcl }))
    const wrapper = mount(Shares, { global: { provide: { toast: vi.fn() } } })
    await flushPromises()
    const edit = wrapper.findAll('button').find((b) => b.text().includes('shares.edit_action'))
    await edit.trigger('click')
    await flushPromises()

    const placeholder = wrapper.find('.acl-block [role="status"]')
    expect(placeholder.exists()).toBe(true)
    expect(placeholder.text()).toBe('common.loading')

    release(ACL)
    await flushPromises()
    expect(wrapper.find('.acl-block [role="status"]').exists()).toBe(false)
    expect(wrapper.findAll('.acl-user-row select')).toHaveLength(2)
  })

  it('degrades to an error line when the ACL cannot be read', async () => {
    api.getShares.mockResolvedValue({
      host: { name: 'Mac' }, system_services: [], smb: [SHARE], file_services: [],
    })
    api.getShareAcl.mockRejectedValue(new Error('acl unreadable'))
    const wrapper = mount(Shares, { global: { provide: { toast: vi.fn() } } })
    await flushPromises()
    const edit = wrapper.findAll('button').find((b) => b.text().includes('shares.edit_action'))
    await edit.trigger('click')
    await flushPromises()

    expect(wrapper.find('.acl-error').text()).toBe('acl unreadable')
    // The rest of the sheet still works — the SMB options are untouched.
    expect(wrapper.find('.sheet-body').exists()).toBe(true)
  })

  it('reloads the truth after a failed write instead of trusting the UI', async () => {
    const { wrapper, toast } = await mountWithEditOpen()
    api.setShareAcl.mockRejectedValue(new Error('verification failed'))
    api.getShareAcl.mockClear()

    const select = wrapper.findAll('.acl-user-row select')[1]
    await select.setValue('none')
    await flushPromises()

    expect(toast).toHaveBeenCalledWith(expect.stringContaining('verification failed'))
    // A fresh read replaces whatever the select briefly showed.
    expect(api.getShareAcl).toHaveBeenCalledTimes(1)
  })
})
