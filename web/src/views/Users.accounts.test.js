/**
 * The panel-accounts section of the Users page.
 *
 * This is where the administrator creates member sign-ins and decides which
 * services each member sees.  Pinned behaviours: the section renders only for
 * administrators, creation sends exactly the chosen resources, editing saves
 * through the resources endpoint, and deletion asks before revoking access.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'

const api = vi.hoisted(() => ({
  getUsers: vi.fn(),
  listPanelAccounts: vi.fn(),
  createPanelAccount: vi.fn(),
  setPanelAccountResources: vi.fn(),
  resetPanelAccountPassword: vi.fn(),
  deletePanelAccount: vi.fn(),
  adminDisableTotp: vi.fn(),
  getServices: vi.fn(),
}))

vi.mock('../api/client', () => api)
vi.mock('../i18n', () => ({
  injectI18n: () => ({ t: (key, params) => (params?.name ? `${key}:${params.name}` : key) }),
}))

import Users from './Users.vue'
import { applyAuthStatus } from '../lib/authState'

const ACCOUNTS = [
  { username: 'admin', role: 'admin', resources: [], twofa_enabled: true },
  { username: 'mom', role: 'member', resources: ['jellyfin'], twofa_enabled: false },
]

function mountUsers(toast = vi.fn()) {
  return mount(Users, {
    global: {
      provide: { toast },
      stubs: { SkeletonLoader: true, LoadFailure: true },
    },
  })
}

beforeEach(() => {
  vi.clearAllMocks()
  api.getUsers.mockResolvedValue({ users: [], count: 0, admins: 0 })
  api.listPanelAccounts.mockResolvedValue({ accounts: ACCOUNTS })
  api.getServices.mockResolvedValue({
    groups: [{
      group: 'Media',
      services: [
        { id: 'jellyfin', name: 'Jellyfin' },
        { id: 'immich', name: 'Immich' },
      ],
    }],
  })
})

describe('panel accounts section', () => {
  it('renders the account table for an administrator', async () => {
    applyAuthStatus({ authenticated: true, username: 'admin', role: 'admin', can_manage: true })
    const wrapper = mountUsers()
    await flushPromises()

    expect(api.listPanelAccounts).toHaveBeenCalled()
    expect(wrapper.text()).toContain('accounts.title')
    expect(wrapper.text()).toContain('mom')
    // The member's grants are listed; the admin row says "all".
    expect(wrapper.text()).toContain('jellyfin')
    expect(wrapper.text()).toContain('accounts.all_resources')
    wrapper.unmount()
  })

  it('does not render or fetch panel accounts for a member session', async () => {
    applyAuthStatus({ authenticated: true, username: 'mom', role: 'member', can_manage: false })
    const wrapper = mountUsers()
    await flushPromises()

    expect(api.listPanelAccounts).not.toHaveBeenCalled()
    expect(wrapper.text()).not.toContain('accounts.title')
    wrapper.unmount()
  })

  it('creates a member with the selected service grants', async () => {
    applyAuthStatus({ authenticated: true, username: 'admin', role: 'admin', can_manage: true })
    api.createPanelAccount.mockResolvedValue({ ok: true, account: {} })
    const wrapper = mountUsers()
    await flushPromises()

    await wrapper.find('.accounts-head button').trigger('click')
    const form = wrapper.find('form.accounts-create')
    await form.find('input[maxlength="64"]').setValue('kid')
    await form.find('input[type="password"]').setValue('kid-passphrase-77')
    // Tick one of the two service checkboxes.
    await form.find('input[type="checkbox"][value="immich"]').setValue(true)
    await form.trigger('submit')
    await flushPromises()

    expect(api.createPanelAccount).toHaveBeenCalledWith({
      username: 'kid',
      password: 'kid-passphrase-77',
      resources: ['immich'],
    })
    // The list is reloaded so the new row appears without a manual refresh.
    expect(api.listPanelAccounts).toHaveBeenCalledTimes(2)
    wrapper.unmount()
  })

  it('saves edited visibility through the resources endpoint', async () => {
    applyAuthStatus({ authenticated: true, username: 'admin', role: 'admin', can_manage: true })
    api.setPanelAccountResources.mockResolvedValue({ ok: true, resources: [] })
    const wrapper = mountUsers()
    await flushPromises()

    // Open the editor on the member row (the admin row has no manage button).
    await wrapper.find('td[style*="text-align"] button').trigger('click')
    const editor = wrapper.find('.account-editor')
    expect(editor.exists()).toBe(true)
    // The current grant is pre-ticked.
    expect(editor.find('input[value="jellyfin"]').element.checked).toBe(true)
    await editor.find('input[value="immich"]').setValue(true)
    await editor.find('.btns .primary').trigger('click')
    await flushPromises()

    expect(api.setPanelAccountResources).toHaveBeenCalledWith('mom', ['jellyfin', 'immich'])
    wrapper.unmount()
  })

  it('shows an empty state after a successful accounts fetch, not loading', async () => {
    applyAuthStatus({ authenticated: true, username: 'admin', role: 'admin', can_manage: true })
    api.listPanelAccounts.mockResolvedValue({ accounts: [] })
    const wrapper = mountUsers()
    await flushPromises()

    expect(wrapper.text()).toContain('common.none')
    expect(wrapper.text()).not.toContain('common.loading')
    wrapper.unmount()
  })

  it('announces a failed accounts fetch instead of a silent empty row', async () => {
    // loadAccounts() does not toast, so the empty-row cell is the only place
    // the failure surfaces; the error text must sit in a live region while the
    // loading/none states stay out of it.
    applyAuthStatus({ authenticated: true, username: 'admin', role: 'admin', can_manage: true })
    api.listPanelAccounts.mockRejectedValue(new Error('accounts backend gone'))
    const wrapper = mountUsers()
    await flushPromises()

    const alert = wrapper.find('.empty-row [role="alert"]')
    expect(alert.exists(), 'error rendered as a live region').toBe(true)
    expect(alert.text()).toBe('accounts backend gone')
    expect(wrapper.text()).not.toContain('common.loading')
    wrapper.unmount()
  })

  it('shows a failure banner above the stale rows when the accounts reload fails', async () => {
    // The empty-row alert only exists while the table is empty, so once rows
    // were on screen a failed *re*-load (after a create/save/delete) surfaced
    // nowhere at all — loadAccounts() never toasts.
    applyAuthStatus({ authenticated: true, username: 'admin', role: 'admin', can_manage: true })
    api.setPanelAccountResources.mockResolvedValue({ ok: true, resources: [] })
    const wrapper = mountUsers()
    await flushPromises()

    api.listPanelAccounts.mockRejectedValue(new Error('accounts reload failed'))
    await wrapper.find('td[style*="text-align"] button').trigger('click')
    await wrapper.find('.account-editor .btns .primary').trigger('click')
    await flushPromises()

    const banner = wrapper.find('load-failure-stub')
    expect(banner.exists(), 'failure banner above the stale rows').toBe(true)
    expect(banner.attributes('detail')).toBe('accounts reload failed')
    // The rows the operator was reading stay on screen below the banner.
    expect(wrapper.text()).toContain('mom')
    wrapper.unmount()
  })

  it('recovers from a failed first accounts fetch through the empty-row retry', async () => {
    applyAuthStatus({ authenticated: true, username: 'admin', role: 'admin', can_manage: true })
    api.listPanelAccounts.mockRejectedValueOnce(new Error('accounts backend gone'))
    const wrapper = mountUsers()
    await flushPromises()
    expect(wrapper.find('.empty-row [role="alert"]').exists()).toBe(true)

    await wrapper.find('.empty-row button').trigger('click')
    await flushPromises()

    expect(wrapper.find('.empty-row [role="alert"]').exists()).toBe(false)
    expect(wrapper.text()).toContain('mom')
    wrapper.unmount()
  })

  it('retries the service catalog from the picker failure without submitting the form', async () => {
    applyAuthStatus({ authenticated: true, username: 'admin', role: 'admin', can_manage: true })
    api.getServices.mockRejectedValueOnce(new Error('services down'))
    const wrapper = mountUsers()
    await flushPromises()

    await wrapper.find('.accounts-head button').trigger('click')
    const picker = wrapper.find('.resource-picker')
    // The 220px scroll cap makes the picker a region a keyboard must reach.
    expect(picker.attributes('tabindex')).toBe('0')
    expect(picker.attributes('role')).toBe('region')
    expect(picker.find('[role="alert"]').text()).toBe('services down')
    expect(picker.find('input[type="checkbox"]').exists()).toBe(false)

    await picker.find('button').trigger('click')
    await flushPromises()

    expect(api.getServices).toHaveBeenCalledTimes(2)
    // type=button: the retry lives inside the create <form> and must not submit it.
    expect(api.createPanelAccount).not.toHaveBeenCalled()
    expect(wrapper.find('.resource-picker input[value="jellyfin"]').exists()).toBe(true)
    wrapper.unmount()
  })

  it('does not throw when a member row omits resources', async () => {
    applyAuthStatus({ authenticated: true, username: 'admin', role: 'admin', can_manage: true })
    api.listPanelAccounts.mockResolvedValue({
      accounts: [{ username: 'kid', role: 'member', twofa_enabled: false }],
    })
    const wrapper = mountUsers()
    await flushPromises()

    expect(wrapper.text()).toContain('kid')
    expect(wrapper.text()).toContain('accounts.no_resources')
    wrapper.unmount()
  })

  it('asks before deleting and then revokes the account', async () => {
    applyAuthStatus({ authenticated: true, username: 'admin', role: 'admin', can_manage: true })
    api.deletePanelAccount.mockResolvedValue({ ok: true })
    const confirmSpy = vi.spyOn(window, 'confirm').mockReturnValue(true)
    const wrapper = mountUsers()
    await flushPromises()

    await wrapper.find('td[style*="text-align"] button').trigger('click')
    await wrapper.find('.account-editor button.danger').trigger('click')
    await flushPromises()

    expect(confirmSpy).toHaveBeenCalled()
    expect(api.deletePanelAccount).toHaveBeenCalledWith('mom')
    confirmSpy.mockRestore()
    wrapper.unmount()
  })

  it('does not toast an account create that returns after leave', async () => {
    applyAuthStatus({ authenticated: true, username: 'admin', role: 'admin', can_manage: true })
    let resolveCreate
    api.createPanelAccount.mockImplementation(() => new Promise((resolve) => { resolveCreate = resolve }))
    const toast = vi.fn()
    const wrapper = mountUsers(toast)
    await flushPromises()

    await wrapper.find('.accounts-head button').trigger('click')
    const form = wrapper.find('form.accounts-create')
    await form.find('input[maxlength="64"]').setValue('kid')
    await form.find('input[type="password"]').setValue('kid-passphrase-77')
    await form.trigger('submit')
    await wrapper.vm.$nextTick()
    wrapper.unmount()
    resolveCreate({ ok: true, account: {} })
    await flushPromises()

    expect(toast).not.toHaveBeenCalled()
  })

  it('does not throw when groups leftover is a mapping', async () => {
    applyAuthStatus({ authenticated: true, username: 'admin', role: 'admin', can_manage: true })
    api.getUsers.mockResolvedValue({
      users: { 0: { uid: 501, name: 'elvin', groups: { 0: 'staff' } } },
      count: 1,
      admins: 1,
    })
    api.getServices.mockResolvedValue({ groups: { 0: { services: { 0: { id: 'x', name: 'X' } } } } })
    const wrapper = mountUsers()
    await flushPromises()
    expect(wrapper.text()).toContain('users.empty')
    wrapper.unmount()
  })

  it('does not throw when the accounts payload is leftover JSON null', async () => {
    applyAuthStatus({ authenticated: true, username: 'admin', role: 'admin', can_manage: true })
    api.listPanelAccounts.mockResolvedValue(null)
    api.getServices.mockResolvedValue(null)
    const wrapper = mountUsers()
    await flushPromises()
    expect(wrapper.text()).toContain('accounts.title')
    expect(wrapper.text()).toContain('common.none')
    wrapper.unmount()
  })

  it('does not throw when leftover account rows are JSON lists', async () => {
    applyAuthStatus({ authenticated: true, username: 'admin', role: 'admin', can_manage: true })
    api.listPanelAccounts.mockResolvedValue({
      accounts: [['kid'], { username: 'mom', role: 'member', resources: 'jellyfin' }],
    })
    const wrapper = mountUsers()
    await flushPromises()
    expect(wrapper.text()).toContain('mom')
    expect(wrapper.text()).toContain('accounts.no_resources')
    wrapper.unmount()
  })

  it('does not throw when accounts leftover is a mapping', async () => {
    applyAuthStatus({ authenticated: true, username: 'admin', role: 'admin', can_manage: true })
    api.listPanelAccounts.mockResolvedValue({
      accounts: { 0: { username: 'kid', role: 'member', resources: { 0: 'jellyfin' }, twofa_enabled: false } },
    })
    const wrapper = mountUsers()
    await flushPromises()
    expect(wrapper.text()).toContain('common.none')
    wrapper.unmount()
  })

  it('does not throw when the users payload is leftover JSON list', async () => {
    applyAuthStatus({ authenticated: true, username: 'admin', role: 'admin', can_manage: true })
    api.getUsers.mockResolvedValue([{ uid: 501, name: 'elvin', groups: ['staff'] }])
    const wrapper = mountUsers()
    await flushPromises()
    expect(wrapper.text()).toContain('users.empty')
    wrapper.unmount()
  })
})
