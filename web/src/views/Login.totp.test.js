/**
 * The two-factor sign-in step.
 *
 * The login endpoint answers `{ok:false, totp_required:true, pending}` when
 * the account has TOTP enabled: no cookie exists yet, and the form has to
 * collect a code and trade the pending token for the real session. The
 * security-relevant behaviours pinned here:
 *
 *  - the pending token from the response is exactly what gets sent back —
 *    the component must never fabricate or persist it anywhere else;
 *  - `resetAuthLost()` runs only after the *second* step succeeds, because
 *    only then does a session cookie exist;
 *  - an expired pending window (auth.totp_pending_invalid) drops the form
 *    back to the password step — retrying the dead token would 401 forever.
 */
import { describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'

const api = vi.hoisted(() => ({
  getAuthStatus: vi.fn(),
  loginAuth: vi.fn(),
  setupAuth: vi.fn(),
  resetAuthLost: vi.fn(),
  verifyTotpLogin: vi.fn(),
}))

const routing = vi.hoisted(() => ({
  replace: vi.fn(),
  query: {},
}))

vi.mock('../api/client', () => api)
vi.mock('vue-router', () => ({
  useRoute: () => ({ query: routing.query }),
  useRouter: () => ({ replace: routing.replace }),
}))
vi.mock('../i18n', () => ({
  injectI18n: () => ({ t: (key) => key }),
}))

import Login from './Login.vue'

async function mountAtTotpStep() {
  routing.query = {}
  routing.replace.mockReset()
  routing.replace.mockResolvedValue(undefined)
  api.getAuthStatus.mockResolvedValue({ setup_required: false, username: 'admin' })
  api.loginAuth.mockResolvedValue({ ok: false, totp_required: true, pending: 'PENDING-TOKEN' })
  api.resetAuthLost.mockReset()
  api.verifyTotpLogin.mockReset()

  const wrapper = mount(Login)
  await flushPromises()
  await wrapper.find('input[type="password"]').setValue('correct-horse-battery')
  await wrapper.find('form').trigger('submit')
  await flushPromises()
  return wrapper
}

const codeInput = (wrapper) => wrapper.find('input[autocomplete="one-time-code"]')

describe('two-factor login step', () => {
  it('swaps to the code form without redirecting or re-arming the latch', async () => {
    const wrapper = await mountAtTotpStep()

    expect(api.loginAuth).toHaveBeenCalledWith('admin', 'correct-horse-battery')
    expect(wrapper.text()).toContain('auth.totp_title')
    expect(codeInput(wrapper).exists()).toBe(true)
    // No session exists yet: neither the redirect nor the latch reset may run.
    expect(routing.replace).not.toHaveBeenCalled()
    expect(api.resetAuthLost).not.toHaveBeenCalled()
    // The password form is gone; submitting again must not re-send credentials.
    expect(wrapper.find('input[type="password"]').exists()).toBe(false)
  })

  it('sends the pending token with the code and finishes the sign-in', async () => {
    const wrapper = await mountAtTotpStep()
    api.verifyTotpLogin.mockResolvedValue({ ok: true })

    await codeInput(wrapper).setValue('123456')
    await wrapper.find('form').trigger('submit')
    await flushPromises()

    expect(api.verifyTotpLogin).toHaveBeenCalledWith('PENDING-TOKEN', '123456')
    expect(api.resetAuthLost).toHaveBeenCalled()
    expect(routing.replace).toHaveBeenCalledWith('/')
  })

  it('surfaces a wrong code and keeps the code form usable', async () => {
    const wrapper = await mountAtTotpStep()
    const error = new Error('Invalid two-factor code')
    error.code = 'auth.bad_totp'
    api.verifyTotpLogin.mockRejectedValue(error)

    await codeInput(wrapper).setValue('000000')
    await wrapper.find('form').trigger('submit')
    await flushPromises()

    expect(wrapper.find('.login-error').text()).toBe('Invalid two-factor code')
    expect(codeInput(wrapper).exists()).toBe(true)
    expect(routing.replace).not.toHaveBeenCalled()
    expect(wrapper.find('button.login-submit').attributes('disabled')).toBeUndefined()
  })

  it('falls back to the password step when the pending window expired', async () => {
    const wrapper = await mountAtTotpStep()
    const error = new Error('window expired')
    error.code = 'auth.totp_pending_invalid'
    api.verifyTotpLogin.mockRejectedValue(error)

    await codeInput(wrapper).setValue('123456')
    await wrapper.find('form').trigger('submit')
    await flushPromises()

    expect(wrapper.find('input[type="password"]').exists()).toBe(true)
    expect(codeInput(wrapper).exists()).toBe(false)
    expect(wrapper.find('.login-error').text()).toBe('window expired')
  })

  it('does not finish a TOTP verify that returns after going back', async () => {
    const wrapper = await mountAtTotpStep()
    let resolveVerify
    api.verifyTotpLogin.mockImplementation(() => new Promise((resolve) => { resolveVerify = resolve }))

    await codeInput(wrapper).setValue('123456')
    await wrapper.find('form').trigger('submit')
    await wrapper.vm.$nextTick()
    await wrapper.find('button.totp-back').trigger('click')
    resolveVerify({ ok: true })
    await flushPromises()

    expect(routing.replace).not.toHaveBeenCalled()
    expect(api.resetAuthLost).not.toHaveBeenCalled()
    expect(wrapper.find('input[type="password"]').exists()).toBe(true)
    expect(wrapper.find('button.login-submit').attributes('disabled')).toBeUndefined()
    wrapper.unmount()
  })

  it('does not finish a TOTP verify that returns after leave', async () => {
    const wrapper = await mountAtTotpStep()
    let resolveVerify
    api.verifyTotpLogin.mockImplementation(() => new Promise((resolve) => { resolveVerify = resolve }))

    await codeInput(wrapper).setValue('123456')
    await wrapper.find('form').trigger('submit')
    await wrapper.vm.$nextTick()
    wrapper.unmount()
    resolveVerify({ ok: true })
    await flushPromises()

    expect(routing.replace).not.toHaveBeenCalled()
    expect(api.resetAuthLost).not.toHaveBeenCalled()
  })

  it('offers a way back to the password form', async () => {
    const wrapper = await mountAtTotpStep()

    await wrapper.find('button.totp-back').trigger('click')

    expect(wrapper.find('input[type="password"]').exists()).toBe(true)
    expect(codeInput(wrapper).exists()).toBe(false)
    expect(api.verifyTotpLogin).not.toHaveBeenCalled()
  })

  it('leaves the classic flow untouched for accounts without 2FA', async () => {
    routing.query = {}
    routing.replace.mockResolvedValue(undefined)
    api.getAuthStatus.mockResolvedValue({ setup_required: false, username: 'admin' })
    api.loginAuth.mockResolvedValue({ ok: true, username: 'admin' })

    const wrapper = mount(Login)
    await flushPromises()
    await wrapper.find('input[type="password"]').setValue('correct-horse-battery')
    await wrapper.find('form').trigger('submit')
    await flushPromises()

    expect(routing.replace).toHaveBeenCalledWith('/')
    expect(wrapper.find('input[autocomplete="one-time-code"]').exists()).toBe(false)
  })
})
