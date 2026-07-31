import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'

const api = vi.hoisted(() => ({
  createShare: vi.fn(),
  getShares: vi.fn(),
  openSharingSettings: vi.fn(),
  removeShare: vi.fn(),
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

describe('Apple-style macOS sharing panel', () => {
  beforeEach(() => {
    vi.stubGlobal('confirm', vi.fn(() => true))
    api.createShare.mockResolvedValue({ ok: true })
    api.removeShare.mockResolvedValue({ ok: true })
    api.setSystemSharing.mockResolvedValue({ ok: true })
    api.updateShare.mockResolvedValue({ ok: true })
    api.openSharingSettings.mockResolvedValue({ ok: true })
  })

  afterEach(() => {
    vi.clearAllMocks()
    vi.unstubAllGlobals()
  })

  it('renders unknown system state without a fake off switch', async () => {
    const { wrapper } = await mountShares()
    const row = wrapper.findAll('.setting-row').find((item) => item.text().includes('shares.service_remote_management'))

    expect(row).toBeTruthy()
    expect(row.text()).toContain('shares.unknown')
    expect(row.find('[role="switch"]').exists()).toBe(false)
    expect(row.find('.row-link').exists()).toBe(true)
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
    })
    expect(api.getShares).toHaveBeenCalledTimes(2)
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

  it('opens the local Mac sharing settings from read-only rows', async () => {
    const { wrapper } = await mountShares()
    await buttonByText(wrapper, 'shares.open_system_settings').trigger('click')
    await flushPromises()

    expect(api.openSharingSettings).toHaveBeenCalledTimes(1)
    wrapper.unmount()
  })
})
