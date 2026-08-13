/**
 * The member half of the router guard.
 *
 * A member session may open exactly the pages its API surface can feed
 * (dashboard, services, own account) — every other route renders admin data
 * the backend refuses, so the guard sends members to the dashboard instead of
 * a wall of 403 toasts.  This is a usability gate, not the security boundary:
 * the server authorizes every /api call regardless.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import router from './router.js'
import { authState } from './lib/authState.js'

function status({ authed = true, role = 'member', resources = ['jellyfin'] } = {}) {
  return {
    ok: true,
    status: 200,
    json: async () => ({
      setup_required: false,
      auth_required: true,
      authenticated: authed,
      username: authed ? (role === 'member' ? 'mom' : 'admin') : 'admin',
      role: authed ? role : null,
      resources,
      can_manage: authed && role === 'admin',
    }),
  }
}

describe('router member guard', () => {
  let fetchMock

  beforeEach(async () => {
    fetchMock = vi.fn().mockResolvedValue(status({ role: 'admin' }))
    vi.stubGlobal('fetch', fetchMock)
    vi.stubGlobal('scrollTo', vi.fn())
    await router.replace('/')
    await router.isReady()
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('lets a member open the dashboard, services and account pages', async () => {
    fetchMock.mockResolvedValue(status())
    for (const [path, name] of [['/services', 'services'], ['/account', 'account'], ['/', 'dashboard']]) {
      await router.push(path)
      expect(router.currentRoute.value.name).toBe(name)
    }
  })

  it('bounces a member off every admin page to the dashboard', async () => {
    fetchMock.mockResolvedValue(status())
    for (const path of ['/settings', '/users', '/terminal', '/shares', '/scheduler', '/files']) {
      await router.push(path)
      expect(router.currentRoute.value.path, `${path} should bounce`).toBe('/')
    }
  })

  it('publishes the session identity for the nav to consume', async () => {
    fetchMock.mockResolvedValue(status())
    await router.push('/services')
    expect(authState.authenticated).toBe(true)
    expect(authState.role).toBe('member')
    expect(authState.username).toBe('mom')
    expect(authState.resources).toEqual(['jellyfin'])
    expect(authState.canManage).toBe(false)
  })

  it('keeps every page open for an administrator', async () => {
    fetchMock.mockResolvedValue(status({ role: 'admin' }))
    for (const [path, name] of [['/settings', 'settings'], ['/users', 'users'], ['/account', 'account']]) {
      await router.push(path)
      expect(router.currentRoute.value.name).toBe(name)
    }
    expect(authState.canManage).toBe(true)
  })

  it('still sends a signed-out visitor to the login form, not the dashboard', async () => {
    fetchMock.mockResolvedValue(status({ authed: false }))
    await router.push('/services')
    expect(router.currentRoute.value.path).toBe('/login')
  })
})
