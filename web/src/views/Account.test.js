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

  it('explains a 2FA status failure instead of staying on loading', async () => {
    api.getTotpStatus.mockRejectedValue(new Error('backend unreachable'))
    const wrapper = mountAccount()
    await flushPromises()

    expect(wrapper.text()).toContain('backend unreachable')
    expect(wrapper.text()).toContain('common.retry')
    expect(wrapper.text()).not.toContain('twofa.enable')
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
    // The blocking reason lives in a live region: the button disables with no
    // spoken explanation otherwise.
    expect(wrapper.find('.password-footer .hint').attributes('role')).toBe('status')
    expect(api.changeAuthPassword).not.toHaveBeenCalled()
    wrapper.unmount()
  })

  it('does not throw when leftover codes payload is a mapping', async () => {
    api.enrollTotp.mockResolvedValue({
      secret: 'S3CRET', otpauth_uri: 'otpauth://totp/x', manual_entry: 'S3CR ET',
    })
    api.confirmTotp.mockResolvedValue({ ok: true, recovery_codes: { 0: 'AAAAA-BBBBB' } })
    const wrapper = mountAccount()
    await flushPromises()

    await wrapper.find('.btns .primary').trigger('click')
    await flushPromises()
    api.getTotpStatus.mockResolvedValue({ enabled: true, recovery_remaining: 1 })
    await wrapper.find('input[autocomplete="one-time-code"]').setValue('123456')
    await wrapper.find('.btns .primary').trigger('click')
    await flushPromises()

    expect(wrapper.text()).not.toContain('AAAAA-BBBBB')
    wrapper.unmount()
  })

  it('does not throw when leftover status payload is a JSON list', async () => {
    api.getTotpStatus.mockResolvedValue(['enabled'])
    const wrapper = mountAccount()
    await flushPromises()
    expect(wrapper.text()).toContain('common.off')
    wrapper.unmount()
  })
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

  it('hides the enrollment QR from the accessibility tree', async () => {
    // The QR encodes exactly the manual-entry secret shown beside it; without
    // aria-hidden it was announced as an anonymous graphic.
    api.enrollTotp.mockResolvedValue({
      secret: 'S3CRET', otpauth_uri: 'otpauth://totp/x', manual_entry: 'S3CR ET',
    })
    const wrapper = mountAccount()
    await flushPromises()

    await wrapper.find('.btns .primary').trigger('click')
    await flushPromises()

    expect(wrapper.find('.twofa-qr').attributes('aria-hidden')).toBe('true')
    wrapper.unmount()
  })

  it('toasts the recovery-code regeneration instead of a silent swap', async () => {
    // Enable and disable both toast; regeneration only swapped DOM below the
    // button, so a screen reader heard nothing happen.
    api.getTotpStatus.mockResolvedValue({ enabled: true, recovery_remaining: 2 })
    api.regenerateTotpRecovery.mockResolvedValue({ ok: true, recovery_codes: ['CCCCC-DDDDD'] })
    const confirmSpy = vi.spyOn(window, 'confirm').mockReturnValue(true)
    const toast = vi.fn()
    const wrapper = mount(Account, { global: { provide: { toast } } })
    await flushPromises()

    await wrapper.find('input[autocomplete="one-time-code"]').setValue('654321')
    await wrapper.findAll('.btns button')[0].trigger('click')
    await flushPromises()

    expect(api.regenerateTotpRecovery).toHaveBeenCalledWith('654321')
    expect(toast).toHaveBeenCalledWith('✅ twofa.regen_toast')
    expect(wrapper.text()).toContain('CCCCC-DDDDD')
    confirmSpy.mockRestore()
    wrapper.unmount()
  })
})

describe('Account leave-guards', () => {
  it('does not toast a password save that returns after leave', async () => {
    let resolveSave
    api.changeAuthPassword.mockImplementation(() => new Promise((resolve) => { resolveSave = resolve }))
    const confirmSpy = vi.spyOn(window, 'confirm').mockReturnValue(true)
    const toast = vi.fn()
    const wrapper = mount(Account, { global: { provide: { toast } } })
    await flushPromises()

    const inputs = wrapper.findAll('input[type="password"]')
    await inputs[0].setValue('old-passphrase-1')
    await inputs[1].setValue('new-passphrase-22')
    await inputs[2].setValue('new-passphrase-22')
    await wrapper.find('.password-footer button').trigger('click')
    await wrapper.vm.$nextTick()
    wrapper.unmount()
    resolveSave({ ok: true, username: 'mom' })
    await flushPromises()

    expect(toast).not.toHaveBeenCalled()
    confirmSpy.mockRestore()
  })

  it('does not toast an enroll that returns after leave', async () => {
    let resolveEnroll
    api.enrollTotp.mockImplementation(() => new Promise((resolve) => { resolveEnroll = resolve }))
    const toast = vi.fn()
    const wrapper = mount(Account, { global: { provide: { toast } } })
    await flushPromises()

    await wrapper.find('.btns .primary').trigger('click')
    await wrapper.vm.$nextTick()
    wrapper.unmount()
    resolveEnroll({ secret: 'S3CRET', otpauth_uri: 'otpauth://totp/x', manual_entry: 'S3CR ET' })
    await flushPromises()

    expect(toast).not.toHaveBeenCalled()
  })

  it('does not leave the password button stuck after a 2FA reload during save', async () => {
    // loadTwofa() bumps loadGeneration; a finally that required a generation
    // match left Update disabled after Retry during an in-flight save.
    let resolveSave
    api.changeAuthPassword.mockImplementation(() => new Promise((resolve) => { resolveSave = resolve }))
    api.getTotpStatus.mockRejectedValueOnce(new Error('backend unreachable'))
    const confirmSpy = vi.spyOn(window, 'confirm').mockReturnValue(true)
    const wrapper = mountAccount()
    await flushPromises()

    const inputs = wrapper.findAll('input[type="password"]')
    await inputs[0].setValue('old-passphrase-1')
    await inputs[1].setValue('new-passphrase-22')
    await inputs[2].setValue('new-passphrase-22')
    await wrapper.find('.password-footer button').trigger('click')
    await wrapper.vm.$nextTick()
    expect(wrapper.find('.password-footer button').attributes('disabled')).toBeDefined()

    api.getTotpStatus.mockResolvedValue({ enabled: false, recovery_remaining: 0 })
    await wrapper.find('button.tiny').trigger('click')
    resolveSave({ ok: true, username: 'mom' })
    await flushPromises()

    expect(wrapper.find('.password-footer button').attributes('disabled')).toBeUndefined()
    confirmSpy.mockRestore()
    wrapper.unmount()
  })
})
