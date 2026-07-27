/**
 * Behavioral cover for the router's auth guard.
 *
 * This guard is the only thing deciding whether an unauthenticated visitor sees
 * the panel or the login form, so its failure modes are asymmetric: send an
 * authenticated user to /login and they cannot use the app, send an
 * unauthenticated one past it and every page renders empty shells around 401s.
 *
 * Note on scope: this is a *usability* gate, not the security boundary. The
 * server authorizes every /api call independently, which is why the guard
 * deliberately fails open when /api/auth/status is unreachable (see the
 * offline tests below) — a flaky network should not lock an admin out of a
 * panel whose API will answer fine.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import router from './router.js'

/** The four fields hub/routers/auth_api.py::auth_status actually returns. */
function status({ setup = false, required = true, authed = false } = {}) {
  return {
    ok: true,
    status: 200,
    json: async () => ({
      setup_required: setup,
      auth_required: required,
      authenticated: authed,
      username: 'admin',
    }),
  }
}

describe('router auth guard', () => {
  let fetchMock

  beforeEach(async () => {
    fetchMock = vi.fn().mockResolvedValue(status({ authed: true }))
    vi.stubGlobal('fetch', fetchMock)
    // jsdom has no layout, so window.scrollTo throws "Not implemented" and the
    // router's scrollBehavior turns every navigation into a stderr stack trace.
    vi.stubGlobal('scrollTo', vi.fn())
    // Land on a known route before each case so assertions read the transition
    // under test rather than leftover state from the previous one.
    await router.replace('/')
    await router.isReady()
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    vi.useRealTimers()
  })

  describe('an authenticated session', () => {
    it('is allowed through to the requested page', async () => {
      await router.push('/containers')
      expect(router.currentRoute.value.name).toBe('containers')
    })

    it('is bounced off the login page to the dashboard', async () => {
      // Visiting /login with a live session would otherwise show a sign-in form
      // to someone already signed in.
      await router.push('/login')
      expect(router.currentRoute.value.path).toBe('/')
    })

    it('checks the session on every navigation, never from cache', async () => {
      await router.push('/health')
      const [, opts] = fetchMock.mock.calls.at(-1)
      // A cached 'authenticated' answer would keep a revoked session usable.
      expect(opts.cache).toBe('no-store')
    })
  })

  describe('a session that needs login', () => {
    it('redirects to /login when auth is required and not satisfied', async () => {
      fetchMock.mockResolvedValue(status({ required: true, authed: false }))
      await router.push('/containers')
      expect(router.currentRoute.value.path).toBe('/login')
    })

    it('preserves the requested page so login can return to it', async () => {
      fetchMock.mockResolvedValue(status({ required: true, authed: false }))
      await router.push('/network')
      expect(router.currentRoute.value.query.next).toBe('/network')
    })

    it('preserves the full path including its query string', async () => {
      fetchMock.mockResolvedValue(status({ required: true, authed: false }))
      await router.push('/logs?file=install.log')
      expect(router.currentRoute.value.query.next).toBe('/logs?file=install.log')
    })

    it('redirects to /login when first-run setup has not happened', async () => {
      // setup_required alone must gate the panel even if auth is off, otherwise
      // a fresh install is wide open until someone sets a password.
      fetchMock.mockResolvedValue(status({ setup: true, required: false, authed: false }))
      await router.push('/settings')
      expect(router.currentRoute.value.path).toBe('/login')
    })

    it('lets the login page itself render instead of looping', async () => {
      fetchMock.mockResolvedValue(status({ required: true, authed: false }))
      await router.push('/login')
      // Redirecting /login to /login would be an infinite navigation loop.
      expect(router.currentRoute.value.path).toBe('/login')
    })
  })

  describe('when auth is disabled entirely', () => {
    it('allows navigation without a session', async () => {
      fetchMock.mockResolvedValue(status({ required: false, authed: false }))
      await router.push('/tools')
      expect(router.currentRoute.value.name).toBe('tools')
    })
  })

  describe('when /api/auth/status is unreachable', () => {
    it('fails open on a network error rather than locking the admin out', async () => {
      fetchMock.mockRejectedValue(new Error('Failed to fetch'))
      await router.push('/vms')
      expect(router.currentRoute.value.name).toBe('vms')
    })

    it('fails open when the response is not json', async () => {
      fetchMock.mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => {
          throw new Error('not json')
        },
      })
      await router.push('/brew')
      expect(router.currentRoute.value.name).toBe('brew')
    })

    it('gives the status check a bounded deadline', async () => {
      // Without a timeout a hung proxy would stall every navigation forever.
      fetchMock.mockResolvedValue(status({ authed: true }))
      await router.push('/alerts')
      const [, opts] = fetchMock.mock.calls.at(-1)
      expect(opts.signal).toBeInstanceOf(AbortSignal)
    })

    it('aborts the status check once the deadline passes', async () => {
      vi.useFakeTimers()
      let seen
      fetchMock.mockImplementation((_url, opts) => {
        seen = opts.signal
        return new Promise(() => {}) // never settles
      })

      const pending = router.push('/scheduler')
      await vi.advanceTimersByTimeAsync(5000)
      expect(seen.aborted).toBe(true)
      // The navigation still resolves (fail-open) rather than hanging.
      pending.catch(() => {})
    })
  })

  describe('route table', () => {
    it('sends an unknown path to the dashboard', async () => {
      await router.push('/no/such/page')
      expect(router.currentRoute.value.path).toBe('/')
    })

    it('marks the login route as an auth page so the shell hides its chrome', () => {
      // App.vue renders a bare <router-view> for authPage routes; losing this
      // flag would draw the nav sidebar around the sign-in form.
      const login = router.getRoutes().find((r) => r.name === 'login')
      expect(login.meta.authPage).toBe(true)
    })

    it('keeps the legacy /storage and /power paths redirecting', async () => {
      await router.push('/storage')
      expect(router.currentRoute.value.name).toBe('main')
      await router.push('/power')
      expect(router.currentRoute.value.path).toBe('/')
    })
  })
})
