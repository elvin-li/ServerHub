import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
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

function payload(overrides = {}) {
  return {
    host: {
      name: 'Test Mac',
      address: '192.0.2.10',
      smb_url: 'smb://192.0.2.10',
      vnc_url: 'vnc://192.0.2.10:5900',
    },
    system_services: [
      {
        id: 'remote_login', enabled: false, controllable: true,
        requires_admin: true, detail: 'off', confidence: 'high',
      },
      {
        id: 'remote_management', enabled: null, controllable: false,
        requires_admin: true, detail: 'System Settings', confidence: 'unknown',
      },
    ],
    smb: [],
    file_services: [],
    ...overrides,
  }
}

async function mountShares(data = payload()) {
  api.getShares.mockResolvedValue(data)
  const toast = vi.fn()
  const wrapper = mount(Shares, { global: { provide: { toast } } })
  await flushPromises()
  return { wrapper, toast }
}

function buttonByText(wrapper, text) {
  const found = wrapper.findAll('button').find((button) => button.text() === text)
  expect(found, `button ${text}`).toBeTruthy()
  return found
}

describe('integrated sharing panel', () => {
  beforeEach(() => {
    vi.stubGlobal('confirm', vi.fn(() => true))
    api.createShare.mockResolvedValue({ ok: true })
    api.removeShare.mockResolvedValue({ ok: true })
    api.setSystemSharing.mockResolvedValue({ ok: true })
    api.updateShare.mockResolvedValue({ ok: true })
    api.openSharingSettings.mockResolvedValue({ ok: true })
    // Editing a share now also loads the folder's ACL; a benign default keeps
    // every pre-ACL scenario in this file behaving exactly as before.
    api.getShareAcl.mockResolvedValue({ path: '/tmp', owner: 'x', entries: [], users: [] })
    api.setShareAcl.mockResolvedValue({ ok: true, entries: [] })
  })

  afterEach(() => {
    vi.clearAllMocks()
    vi.unstubAllGlobals()
  })

  it('groups read-only services without exposing a fake state or backend detail', async () => {
    const { wrapper } = await mountShares()
    const managed = wrapper.find('.managed-card')

    expect(managed.exists()).toBe(true)
    expect(managed.text()).toContain('shares.service_remote_management')
    expect(managed.text()).toContain('shares.managed_by_macos')
    expect(managed.text()).not.toContain('shares.unknown')
    expect(managed.text()).not.toContain('System Settings')
    expect(managed.find('[role="switch"]').exists()).toBe(false)
    wrapper.unmount()
  })

  it('keeps controllable services in the core list with verified state switches', async () => {
    const { wrapper } = await mountShares()
    const core = wrapper.find('.service-card')
    const toggle = core.find('[role="switch"]')

    expect(core.text()).toContain('shares.service_remote_login')
    expect(core.text()).not.toContain('shares.service_remote_management')
    expect(toggle.attributes('aria-checked')).toBe('false')
    expect(core.text()).toContain('common.off')
    wrapper.unmount()
  })

  it('renders host connection actions and an accessible overview', async () => {
    const { wrapper } = await mountShares()
    const overview = wrapper.find('.host-overview')
    const stats = overview.find('.host-stats')

    expect(overview.attributes('aria-labelledby')).toBe('sharing-host-title')
    expect(stats.attributes('aria-label')).toBe('shares.overview_summary')
    expect(overview.text()).toContain('Test Mac')
    expect(overview.text()).toContain('192.0.2.10')
    expect(overview.find('a[href="smb://192.0.2.10"]').exists()).toBe(true)
    expect(overview.find('a[href="vnc://192.0.2.10:5900"]').exists()).toBe(true)
    expect(overview.text()).toContain('shares.shared_folders')
    expect(overview.text()).toContain('shares.core_services')
    wrapper.unmount()
  })

  it('does not mutate a network-facing service when confirmation is cancelled', async () => {
    confirm.mockReturnValue(false)
    const { wrapper } = await mountShares()
    const toggle = wrapper.find('[role="switch"]')

    await toggle.trigger('click')

    expect(confirm).toHaveBeenCalledWith('shares.confirm_enable_service')
    expect(api.setSystemSharing).not.toHaveBeenCalled()
    wrapper.unmount()
  })

  it('shows native authorization progress and reloads the verified system state', async () => {
    let resolveMutation
    api.setSystemSharing.mockImplementation(() => new Promise((resolve) => { resolveMutation = resolve }))
    api.getShares
      .mockReset()
      .mockResolvedValueOnce(payload())
      .mockResolvedValueOnce(payload({
        system_services: [{
          id: 'remote_login', enabled: true, controllable: true,
          requires_admin: true, detail: 'on', confidence: 'high',
        }],
      }))
    const { wrapper } = await mountShares()

    await wrapper.find('[role="switch"]').trigger('click')
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('shares.waiting_for_admin')
    expect(wrapper.find('[role="switch"]').attributes('disabled')).toBeDefined()

    resolveMutation({ ok: true })
    await flushPromises()

    expect(api.setSystemSharing).toHaveBeenCalledWith('remote_login', true)
    expect(api.getShares).toHaveBeenCalledTimes(2)
    expect(wrapper.find('[role="switch"]').attributes('aria-checked')).toBe('true')
    wrapper.unmount()
  })

  it('restores the server-reported switch after a failed mutation', async () => {
    api.setSystemSharing.mockRejectedValue(new Error('authorization cancelled'))
    api.getShares.mockReset().mockResolvedValue(payload())
    const { wrapper, toast } = await mountShares()

    await wrapper.find('[role="switch"]').trigger('click')
    await flushPromises()

    expect(api.getShares).toHaveBeenCalledTimes(2)
    expect(wrapper.find('[role="switch"]').attributes('aria-checked')).toBe('false')
    expect(toast).toHaveBeenCalledWith('❌ authorization cancelled')
    wrapper.unmount()
  })

  it('creates an SMB share with a strict structured body', async () => {
    const { wrapper } = await mountShares()
    await buttonByText(wrapper, 'shares.add_folder').trigger('click')
    const inputs = wrapper.findAll('.share-sheet input[type="text"]')
    await inputs[0].setValue('/Users/test/Media')
    await inputs[1].setValue('Media Record')
    await inputs[2].setValue('Media')

    await buttonByText(wrapper, 'common.save').trigger('click')
    await flushPromises()

    expect(api.createShare).toHaveBeenCalledWith({
      path: '/Users/test/Media',
      name: 'Media Record',
      smb_name: 'Media',
      guest: false,
      readonly: false,
      encrypted: false,
      time_machine: false,
      tm_quota_gb: null,
    })
    expect(api.getShares).toHaveBeenCalledTimes(2)
    wrapper.unmount()
  })

  it('updates only editable SMB properties and preserves security flags', async () => {
    const share = {
      record_name: 'Media Record', name: 'Media Record', smb_name: 'Media',
      path: '/Users/test/Media', url: 'smb://host/Media', guest: false,
      readonly: false, encrypted: false,
    }
    const { wrapper } = await mountShares(payload({ smb: [share] }))
    await wrapper.find('button[aria-label="shares.edit_named"]').trigger('click')
    const inputs = wrapper.findAll('.share-sheet input[type="text"]')
    await inputs[0].setValue('Media Archive')
    const options = wrapper.findAll('.share-sheet input[type="checkbox"]')
    await options[1].setValue(true)
    await options[2].setValue(true)

    await buttonByText(wrapper, 'common.save').trigger('click')
    await flushPromises()

    expect(api.updateShare).toHaveBeenCalledWith('Media Record', {
      smb_name: 'Media Archive',
      guest: false,
      readonly: true,
      encrypted: true,
      time_machine: false,
      tm_quota_gb: null,
    })
    wrapper.unmount()
  })

  it('badges Time Machine shares with their quota', async () => {
    const shares = [
      {
        record_name: 'Backups', name: 'Backups', smb_name: 'Backups',
        path: '/Volumes/Backups/TM', url: 'smb://host/Backups', guest: false,
        readonly: false, encrypted: false, time_machine: true, tm_quota_gb: 500,
      },
      {
        record_name: 'Plain', name: 'Plain', smb_name: 'Plain',
        path: '/Users/test/Plain', url: 'smb://host/Plain', guest: false,
        readonly: false, encrypted: false, time_machine: false, tm_quota_gb: null,
      },
    ]
    const { wrapper } = await mountShares(payload({ smb: shares }))
    const badges = wrapper.findAll('.tm-badge')

    expect(badges).toHaveLength(1)
    expect(badges[0].text()).toContain('shares.tm_quota_badge')
    wrapper.unmount()
  })

  it('sends the Time Machine flag and an integer quota when enabled', async () => {
    const { wrapper } = await mountShares()
    await buttonByText(wrapper, 'shares.add_folder').trigger('click')
    const inputs = wrapper.findAll('.share-sheet input[type="text"]')
    await inputs[0].setValue('/Volumes/Backups/TM')
    await inputs[1].setValue('Backups')
    await inputs[2].setValue('Backups')

    expect(wrapper.find('.share-sheet input[type="number"]').exists()).toBe(false)
    const options = wrapper.findAll('.share-sheet input[type="checkbox"]')
    await options[3].setValue(true)
    const quota = wrapper.find('.share-sheet input[type="number"]')
    expect(quota.exists()).toBe(true)
    await quota.setValue('500')

    await buttonByText(wrapper, 'common.save').trigger('click')
    await flushPromises()

    expect(api.createShare).toHaveBeenCalledWith({
      path: '/Volumes/Backups/TM',
      name: 'Backups',
      smb_name: 'Backups',
      guest: false,
      readonly: false,
      encrypted: false,
      time_machine: true,
      tm_quota_gb: 500,
    })
    wrapper.unmount()
  })

  it('treats a blank quota as no cap', async () => {
    const share = {
      record_name: 'Backups', name: 'Backups', smb_name: 'Backups',
      path: '/Volumes/Backups/TM', url: 'smb://host/Backups', guest: false,
      readonly: false, encrypted: false, time_machine: true, tm_quota_gb: 500,
    }
    const { wrapper } = await mountShares(payload({
      smb: [share],
      time_machine: { share_count: 1, smb_service_running: true, adisk_advertised: true },
    }))
    await wrapper.find('button[aria-label="shares.edit_named"]').trigger('click')
    const quota = wrapper.find('.share-sheet input[type="number"]')
    expect(quota.element.value).toBe('500')
    await quota.setValue('')

    await buttonByText(wrapper, 'common.save').trigger('click')
    await flushPromises()

    expect(api.updateShare).toHaveBeenCalledWith('Backups', {
      smb_name: 'Backups',
      guest: false,
      readonly: false,
      encrypted: false,
      time_machine: true,
      tm_quota_gb: null,
    })
    wrapper.unmount()
  })

  it('explains client setup and warns when SMB sharing is off', async () => {
    const share = {
      record_name: 'Backups', name: 'Backups', smb_name: 'Backups',
      path: '/Volumes/Backups/TM', url: 'smb://host/Backups', guest: false,
      readonly: false, encrypted: false, time_machine: true, tm_quota_gb: null,
    }
    const { wrapper } = await mountShares(payload({
      smb: [share],
      time_machine: { share_count: 1, smb_service_running: false, adisk_advertised: null },
    }))
    const note = wrapper.find('.tm-note')

    expect(note.exists()).toBe(true)
    expect(note.text()).toContain('shares.tm_howto')
    expect(note.find('.tm-warn').text()).toBe('shares.tm_smb_off')
    wrapper.unmount()
  })

  it('hints when the destination is not advertised yet', async () => {
    const share = {
      record_name: 'Backups', name: 'Backups', smb_name: 'Backups',
      path: '/Volumes/Backups/TM', url: 'smb://host/Backups', guest: false,
      readonly: false, encrypted: false, time_machine: true, tm_quota_gb: null,
    }
    const { wrapper } = await mountShares(payload({
      smb: [share],
      time_machine: { share_count: 1, smb_service_running: true, adisk_advertised: false },
    }))

    expect(wrapper.find('.tm-note .tm-warn').text()).toBe('shares.tm_not_advertised')
    wrapper.unmount()
  })

  it('shows no Time Machine note when no share carries the flag', async () => {
    const { wrapper } = await mountShares(payload({
      time_machine: { share_count: 0, smb_service_running: true, adisk_advertised: null },
    }))
    expect(wrapper.find('.tm-note').exists()).toBe(false)
    wrapper.unmount()
  })

  it('states that removal keeps files and sends only the record name', async () => {
    const share = {
      record_name: 'Media Record', name: 'Media Record', smb_name: 'Media',
      path: '/Users/test/Media', url: 'smb://host/Media', guest: false,
      readonly: false, encrypted: true,
    }
    const { wrapper } = await mountShares(payload({ smb: [share] }))
    const remove = wrapper.find('button[aria-label="shares.remove_named"]')

    await remove.trigger('click')
    await flushPromises()

    expect(confirm).toHaveBeenCalledWith('shares.confirm_remove')
    expect(api.removeShare).toHaveBeenCalledWith('Media Record')
    expect(api.getShares).toHaveBeenCalledTimes(2)
    wrapper.unmount()
  })

  it('renders additional file services with the shared card and badge language', async () => {
    const { wrapper } = await mountShares(payload({
      file_services: [{ id: 'files', name: 'FileBrowser', detail: 'Port 8080', state: 'ok', url: 'http://host:8080' }],
    }))
    const row = wrapper.find('.file-service-row')

    expect(row.text()).toContain('FileBrowser')
    expect(row.text()).toContain('common.running')
    expect(row.find('.badge.ok').exists()).toBe(true)
    expect(row.find('a[href="http://host:8080"]').exists()).toBe(true)
    wrapper.unmount()
  })

  it('uses one unified system-settings action', async () => {
    const { wrapper } = await mountShares()
    const buttons = wrapper.findAll('button').filter((button) => button.text() === 'shares.open_system_settings')

    expect(buttons).toHaveLength(1)
    await buttons[0].trigger('click')
    await flushPromises()

    expect(api.openSharingSettings).toHaveBeenCalledTimes(1)
    wrapper.unmount()
  })
})
