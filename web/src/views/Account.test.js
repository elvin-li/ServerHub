/**
 * The per-account self-service page.
 *
 * A member's only management surface: password rotation must target *their
 * own* username (the backend refuses anything else), and the 2FA card drives
 * the same self-service endpoints the Settings page uses.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'

const api = vi.hoisted(() => ({
  changeAuthPassword: vi.fn(),
  getTotpStatus: vi.fn(),
  enrollTotp: vi.fn(),
  confirmTotp: vi.fn(),
  disableTotp: vi.fn(),
  regenerateTotpRecovery: vi.fn(),
}))

vi.mock('../api/client', () => api)
vi.mock('../i18n', () => ({
  injectI18n: () => ({ t: (key) => key }),
}))

import Account from './Account.vue'
import { applyAuthStatus } from '../lib/authState'

function mountAccount() {
  return mount(Account, {
    global: { provide: { toast: vi.fn() } },
  })
}

beforeEach(() => {
  vi.clearAllMocks()
  api.getTotpStatus.mockResolvedValue({ enabled: false, recovery_remaining: 0 })
  applyAuthStatus({
    authenticated: true, username: 'mom', role: 'member',
    resources: ['jellyfin'], can_manage: false,
  })
})

describe('account self-service', () => {
  it('rotates the signed-in account password under its own username', async () => {
    api.changeAuthPassword.mockResolvedValue({ ok: true, username: 'mom' })
    const confirmSpy = vi.spyOn(window, 'confirm').mockReturnValue(true)
    const wrapper = mountAccount()
    await flushPromises()

    const inputs = wrapper.findAll('input[type="password"]')
    await inputs[0].setValue('old-passphrase-1')
    await inputs[1].setValue('new-passphrase-22')
    await inputs[2].setValue('new-passphrase-22')
    await wrapper.find('.password-footer button').trigger('click')
    await flushPromises()

    expect(api.changeAuthPassword).toHaveBeenCalledWith(
      'mom', 'old-passphrase-1', 'new-passphrase-22',
    )
    // The form empties so the credentials do not linger in the DOM.
    expect(inputs[0].element.value).toBe('')
    confirmSpy.mockRestore()
    wrapper.unmount()
  })

  it('blocks the save while the two new passwords differ', async () => {
    const wrapper = mountAccount()
    await flushPromises()

    const inputs = wrapper.findAll('input[type="password"]')
    await inputs[0].setValue('old-passphrase-1')
    await inputs[1].setValue('new-passphrase-22')
    await inputs[2].setValue('different-one-33')

    expect(wrapper.find('.password-footer button').attributes('disabled')).toBeDefined()
    expect(wrapper.text()).toContain('auth.password_mismatch')
    expect(api.changeAuthPassword).not.toHaveBeenCalled()
    wrapper.unmount()
  })

  it('walks the 2FA enrollment to the recovery codes', async () => {
    api.enrollTotp.mockResolvedValue({
      secret: 'S3CRET', otpauth_uri: 'otpauth://totp/x', manual_entry: 'S3CR ET',
    })
    api.confirmTotp.mockResolvedValue({ ok: true, recovery_codes: ['AAAAA-BBBBB'] })
    const wrapper = mountAccount()
    await flushPromises()

    await wrapper.find('.btns .primary').trigger('click')
    await flushPromises()
    expect(api.enrollTotp).toHaveBeenCalled()
    expect(wrapper.text()).toContain('S3CR ET')

    api.getTotpStatus.mockResolvedValue({ enabled: true, recovery_remaining: 1 })
    await wrapper.find('input[autocomplete="one-time-code"]').setValue('123456')
    await wrapper.find('.btns .primary').trigger('click')
    await flushPromises()

    expect(api.confirmTotp).toHaveBeenCalledWith('123456')
    expect(wrapper.text()).toContain('AAAAA-BBBBB')
    wrapper.unmount()
  })
})
