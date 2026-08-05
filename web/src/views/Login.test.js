/**
 * Login is the only unauthenticated page in the panel, so every branch here is
 * reachable by anyone who can open the port. Three of its behaviours are
 * security-relevant and were previously untested:
 *
 *  - `?next=` must only ever resolve to a same-origin *path*. A protocol-
 *    relative value like `//evil.example` is a valid URL to `router.replace`,
 *    so without the `//` guard a crafted link would bounce a freshly
 *    authenticated operator onto an attacker's host with a live session.
 *  - `resetAuthLost()` must run after a successful credential exchange.
 *    The client latches "session lost" to avoid redirect storms; if the latch
 *    is not cleared, the next 401 would never bounce back to /login and the
 *    panel would silently freeze instead.
 *  - A rejected login must clear `busy`. Otherwise the submit button stays
 *    disabled and a mistyped password locks the operator out of the form.
 */
import { describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'

const api = vi.hoisted(() => ({
  getAuthStatus: vi.fn(),
  loginAuth: vi.fn(),
  setupAuth: vi.fn(),
  resetAuthLost: vi.fn(),
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

/** Mount with a given /api/auth/status result and optional ?next= query. */
async function mountLogin({ status = {}, query = {} } = {}) {
  routing.query = query
  routing.replace.mockResolvedValue(undefined)
  api.getAuthStatus.mockResolvedValue(status)
  const wrapper = mount(Login)
  await flushPromises()
  return wrapper
}

/** Fill the visible password inputs by their label text. */
async function fill(wrapper, values) {
  for (const [label, value] of Object.entries(values)) {
    const field = wrapper.findAll('label').find((l) => l.find('span').text() === label)
    expect(field, `field ${label}`).toBeTruthy()
    await field.find('input').setValue(value)
  }
}

const submit = async (wrapper) => {
  await wrapper.find('form').trigger('submit')
  await flushPromises()
}

const errorText = (wrapper) => wrapper.find('.login-error').text()

describe('login page', () => {
  it('shows the returning-user form and signs in with the shared client', async () => {
    const wrapper = await mountLogin({ status: { setup_required: false, username: 'ops' } })

    expect(wrapper.find('.setup-note').exists()).toBe(false)
    expect(wrapper.find('input[autocomplete="username"]').element.value).toBe('ops')
    expect(wrapper.find('input[autocomplete="current-password"]').exists()).toBe(true)

    await fill(wrapper, { 'auth.password': 'correct-horse-battery' })
    await submit(wrapper)

    expect(api.loginAuth).toHaveBeenCalledWith('ops', 'correct-horse-battery')
    expect(api.setupAuth).not.toHaveBeenCalled()
    expect(routing.replace).toHaveBeenCalledWith('/')
  })

  it('collects the setup token on first run and never calls the login route', async () => {
    const wrapper = await mountLogin({ status: { setup_required: true, username: 'admin' } })

    expect(wrapper.find('.setup-note').exists()).toBe(true)
    await fill(wrapper, {
      'auth.setup_token': 'x'.repeat(32),
      'auth.create_password': 'first-admin-password',
      'auth.confirm_password': 'first-admin-password',
    })
    await submit(wrapper)

    expect(api.setupAuth).toHaveBeenCalledWith('admin', 'first-admin-password', 'x'.repeat(32))
    expect(api.loginAuth).not.toHaveBeenCalled()
  })

  it('rejects mismatched setup passwords before contacting the server', async () => {
    const wrapper = await mountLogin({ status: { setup_required: true } })

    await fill(wrapper, {
      'auth.setup_token': 'y'.repeat(32),
      'auth.create_password': 'first-admin-password',
      'auth.confirm_password': 'different-password-xx',
    })
    await submit(wrapper)

    expect(errorText(wrapper)).toBe('auth.password_mismatch')
    expect(api.setupAuth).not.toHaveBeenCalled()
    expect(routing.replace).not.toHaveBeenCalled()
  })

  it('rejects a short password before contacting the server', async () => {
    const wrapper = await mountLogin({ status: { setup_required: false } })

    await fill(wrapper, { 'auth.password': 'short' })
    await submit(wrapper)

    expect(errorText(wrapper)).toBe('auth.password_length')
    expect(api.loginAuth).not.toHaveBeenCalled()
  })

  it('re-arms the session-lost redirect after a successful sign-in', async () => {
    const wrapper = await mountLogin({ status: { setup_required: false } })

    await fill(wrapper, { 'auth.password': 'correct-horse-battery' })
    await submit(wrapper)

    expect(api.resetAuthLost).toHaveBeenCalled()
  })

  it('follows a same-origin ?next= path', async () => {
    const wrapper = await mountLogin({
      status: { setup_required: false },
      query: { next: '/containers?tab=running' },
    })

    await fill(wrapper, { 'auth.password': 'correct-horse-battery' })
    await submit(wrapper)

    expect(routing.replace).toHaveBeenCalledWith('/containers?tab=running')
  })

  it.each([
    ['protocol-relative host', '//evil.example/steal'],
    ['absolute external url', 'https://evil.example/steal'],
    ['non-string query value', ['/containers']],
  ])('refuses to redirect to a %s', async (_label, next) => {
    const wrapper = await mountLogin({ status: { setup_required: false }, query: { next } })

    await fill(wrapper, { 'auth.password': 'correct-horse-battery' })
    await submit(wrapper)

    expect(api.loginAuth).toHaveBeenCalled()
    expect(routing.replace).toHaveBeenCalledWith('/')
  })

  it('surfaces a rejected sign-in and leaves the form usable', async () => {
    const wrapper = await mountLogin({ status: { setup_required: false } })
    api.loginAuth.mockRejectedValue(new Error('Invalid credentials'))

    await fill(wrapper, { 'auth.password': 'wrong-but-long-enough' })
    await submit(wrapper)

    expect(errorText(wrapper)).toBe('Invalid credentials')
    expect(routing.replace).not.toHaveBeenCalled()
    expect(wrapper.find('button.login-submit').attributes('disabled')).toBeUndefined()
  })

  it('gates the form behind a loading placeholder until the probe resolves', async () => {
    routing.query = {}
    let resolveProbe
    api.getAuthStatus.mockImplementation(() => new Promise((resolve) => { resolveProbe = resolve }))
    const wrapper = mount(Login)

    // Rendering the form early would flash a "returning user" layout at an
    // operator who actually needs the first-run setup fields.
    expect(wrapper.find('.login-loading').exists()).toBe(true)
    expect(wrapper.find('form').exists()).toBe(false)

    resolveProbe({ setup_required: true })
    await flushPromises()

    expect(wrapper.find('.login-loading').exists()).toBe(false)
    expect(wrapper.find('.setup-note').exists()).toBe(true)
  })

  it('disables submit and reports progress while credentials are in flight', async () => {
    const wrapper = await mountLogin({ status: { setup_required: false } })
    let resolveLogin
    api.loginAuth.mockImplementation(() => new Promise((resolve) => { resolveLogin = resolve }))

    await fill(wrapper, { 'auth.password': 'correct-horse-battery' })
    await wrapper.find('form').trigger('submit')
    await wrapper.vm.$nextTick()

    // A double submit would send the credentials twice.
    const button = wrapper.find('button.login-submit')
    expect(button.attributes('disabled')).toBeDefined()
    expect(button.text()).toBe('auth.processing')

    resolveLogin(undefined)
    await flushPromises()

    expect(api.loginAuth).toHaveBeenCalledTimes(1)
    expect(routing.replace).toHaveBeenCalledWith('/')
  })

  it('clears a stale error when the form is resubmitted', async () => {
    const wrapper = await mountLogin({ status: { setup_required: false } })
    api.loginAuth.mockRejectedValueOnce(new Error('Invalid credentials'))

    await fill(wrapper, { 'auth.password': 'wrong-but-long-enough' })
    await submit(wrapper)
    expect(errorText(wrapper)).toBe('Invalid credentials')

    await fill(wrapper, { 'auth.password': 'correct-horse-battery' })
    await submit(wrapper)

    expect(wrapper.find('.login-error').exists()).toBe(false)
    expect(routing.replace).toHaveBeenCalledWith('/')
  })

  it.each([
    [true, 'auth.first_setup', 'auth.create_admin'],
    [false, 'auth.welcome_back', 'auth.login'],
  ])('labels the page for setup_required=%s', async (setupRequired, heading, action) => {
    const wrapper = await mountLogin({ status: { setup_required: setupRequired } })

    expect(wrapper.find('.login-brand').text()).toContain(heading)
    expect(wrapper.find('button.login-submit').text()).toBe(action)
  })

  it('falls back to the admin username when the probe omits one', async () => {
    const wrapper = await mountLogin({ status: { setup_required: false, username: '' } })

    expect(wrapper.find('input[autocomplete="username"]').element.value).toBe('admin')

    await fill(wrapper, { 'auth.password': 'correct-horse-battery' })
    await submit(wrapper)

    expect(api.loginAuth).toHaveBeenCalledWith('admin', 'correct-horse-battery')
  })

  it('trims surrounding whitespace from the submitted username', async () => {
    const wrapper = await mountLogin({ status: { setup_required: false } })

    await fill(wrapper, { 'auth.username': '  ops  ', 'auth.password': 'correct-horse-battery' })
    await submit(wrapper)

    expect(api.loginAuth).toHaveBeenCalledWith('ops', 'correct-horse-battery')
  })

  it('keeps the setup form usable when the setup token is rejected', async () => {
    const wrapper = await mountLogin({ status: { setup_required: true } })
    api.setupAuth.mockRejectedValue(new Error('Invalid setup token'))

    await fill(wrapper, {
      'auth.setup_token': 'z'.repeat(32),
      'auth.create_password': 'first-admin-password',
      'auth.confirm_password': 'first-admin-password',
    })
    await submit(wrapper)

    expect(errorText(wrapper)).toBe('Invalid setup token')
    expect(wrapper.find('.setup-note').exists()).toBe(true)
    expect(wrapper.find('button.login-submit').attributes('disabled')).toBeUndefined()
    expect(api.resetAuthLost).not.toHaveBeenCalled()
    expect(routing.replace).not.toHaveBeenCalled()
  })

  it('still renders the form when the status probe fails', async () => {
    api.getAuthStatus.mockRejectedValue(new Error('Service unavailable'))
    routing.query = {}
    const wrapper = mount(Login)
    await flushPromises()

    expect(wrapper.find('.login-loading').exists()).toBe(false)
    expect(wrapper.find('form').exists()).toBe(true)
    expect(errorText(wrapper)).toBe('Service unavailable')
    // A failed probe must not be read as "setup required": that would offer to
    // create a second admin against a panel that already has one.
    expect(wrapper.find('.setup-note').exists()).toBe(false)
  })
})
