/**
 * Behavioral cover for the API client.
 *
 * Two things here are invisible to structural tests and expensive to get wrong:
 *
 *   1. Error translation. The backend speaks machine-readable codes, and the
 *      client turns them into localized text. When that mapping breaks the user
 *      does not see a stack trace, they see a raw key path like
 *      `err.catalog.not_installed` sitting in a toast.
 *   2. Session loss. One expired cookie yields a burst of 401s from every poll
 *      in flight. The auth-lost latch must fire exactly once, must not fire for
 *      login attempts, and must re-arm after a successful sign-in. Get it wrong
 *      and the panel either bounces the user off the login form or leaves every
 *      page frozen on stale numbers.
 *
 * Assertions compare against the real en.js dictionary rather than hardcoded
 * English, so a reworded string cannot make a test lie.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import en from '../i18n/en.js'
import { setLocale } from '../i18n/index.js'
import {
  AUTH_LOST_EVENT,
  doAction,
  getStatus,
  loginAuth,
  resetAuthLost,
} from './client.js'

/** Build a fetch response double. `body` is whatever r.json() should yield. */
function res(status, body, statusText = '') {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText,
    json: async () => body,
  }
}

/** A network failure as the browser reports it. */
function netFail() {
  return Object.assign(new Error('Failed to fetch'), { name: 'TypeError' })
}

/** Total fake time needed to flush every GET retry backoff (800 + 1600). */
const ALL_RETRY_DELAYS = 800 + 1600

describe('api client', () => {
  let fetchMock

  beforeEach(async () => {
    // t() resolves against the active locale; pin it so assertions are stable.
    await setLocale('en')
    resetAuthLost()
    fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    vi.useRealTimers()
    resetAuthLost()
  })

  describe('error translation', () => {
    it('localizes a coded error and interpolates its params', async () => {
      fetchMock.mockResolvedValue(
        res(400, {
          detail: {
            code: 'catalog.not_installed',
            message: 'Not installed: widget',
            params: { id: 'widget' },
          },
        }),
      )

      // The dictionary entry is a template, so this proves interpolation ran
      // rather than that some string happened to match.
      const template = en.err.catalog.not_installed
      expect(template).toContain('{id}')
      await expect(getStatus()).rejects.toThrow(template.replace('{id}', 'widget'))
    })

    it('falls back to the server message when this build lacks the key', async () => {
      fetchMock.mockResolvedValue(
        res(400, {
          detail: { code: 'not.a.real.code.in.any.build', message: 'Server said no' },
        }),
      )
      await expect(getStatus()).rejects.toThrow('Server said no')
    })

    it('prefers the localized text over the server message when both exist', async () => {
      // The previous version of this test used a server message identical to the
      // translation, so it passed whichever branch ran. Force them apart: the key
      // must exist in this build, and the server text must differ from it.
      const translated = en.err.container.engine_down
      const serverText = 'ENGINE DOWN (raw server text)'
      expect(translated).not.toBe(serverText)

      fetchMock.mockResolvedValue(
        res(503, {
          detail: { code: 'container.engine_down', message: serverText },
        }),
      )

      let caught
      await getStatus().catch((e) => {
        caught = e
      })
      expect(caught.message).toBe(translated)
      expect(caught.message).not.toBe(serverText)
    })

    it('uses the bare code when the server sends no message either', async () => {
      fetchMock.mockResolvedValue(
        res(400, { detail: { code: 'not.a.real.code.in.any.build' } }),
      )
      await expect(getStatus()).rejects.toThrow('not.a.real.code.in.any.build')
    })

    it('passes a legacy string detail through unchanged', async () => {
      fetchMock.mockResolvedValue(res(409, { detail: 'plain legacy text' }))
      await expect(getStatus()).rejects.toThrow('plain legacy text')
    })

    it('summarizes FastAPI validation errors as field: reason', async () => {
      fetchMock.mockResolvedValue(
        res(422, {
          detail: [
            { loc: ['body', 'port'], msg: 'must be an integer', type: 'int' },
            { loc: ['query', 'name'], msg: 'required', type: 'missing' },
          ],
        }),
      )

      let caught
      await getStatus().catch((e) => {
        caught = e
      })

      // The wrapper text comes from the dictionary; the per-field detail is
      // what makes the raw array readable.
      expect(caught.message).toContain(en.err.invalid_input)
      expect(caught.message).toContain('port: must be an integer')
      expect(caught.message).toContain('name: required')
      // 'body'/'query' are transport noise and must be stripped from the label.
      expect(caught.message).not.toContain('body.port')
    })

    it('prefers a top-level message over the generic fallback', async () => {
      fetchMock.mockResolvedValue(res(500, { message: 'top level boom' }))
      await expect(getStatus()).rejects.toThrow('top level boom')
    })

    it('falls back to statusText when the payload carries nothing usable', async () => {
      fetchMock.mockResolvedValue(res(503, {}, 'Service Unavailable'))
      await expect(getStatus()).rejects.toThrow('Service Unavailable')
    })

    it('uses the localized generic message when even statusText is empty', async () => {
      fetchMock.mockResolvedValue(res(500, {}, ''))
      await expect(getStatus()).rejects.toThrow(en.err.request_failed)
    })

    it('attaches status, body and code to the thrown error', async () => {
      const body = { detail: { code: 'container.engine_down', message: 'down' } }
      fetchMock.mockResolvedValue(res(503, body))

      let caught
      await getStatus().catch((e) => {
        caught = e
      })

      // Callers branch on these, e.g. to show an engine-down banner.
      expect(caught.status).toBe(503)
      expect(caught.body).toEqual(body)
      expect(caught.code).toBe('container.engine_down')
    })

    it('leaves code null when the server sends a legacy string detail', async () => {
      fetchMock.mockResolvedValue(res(400, { detail: 'legacy' }))
      let caught
      await getStatus().catch((e) => {
        caught = e
      })
      expect(caught.code).toBeNull()
    })
  })

  describe('session loss', () => {
    it('announces a lost session once per burst of 401s', async () => {
      const onLost = vi.fn()
      window.addEventListener(AUTH_LOST_EVENT, onLost)
      fetchMock.mockResolvedValue(res(401, { detail: 'expired' }))

      await getStatus().catch(() => {})
      await getStatus().catch(() => {})
      await getStatus().catch(() => {})

      // A page has several polls in flight; three redirects would be a loop.
      expect(onLost).toHaveBeenCalledTimes(1)
      window.removeEventListener(AUTH_LOST_EVENT, onLost)
    })

    it('re-arms after a successful sign-in clears the latch', async () => {
      const onLost = vi.fn()
      window.addEventListener(AUTH_LOST_EVENT, onLost)
      fetchMock.mockResolvedValue(res(401, { detail: 'expired' }))

      await getStatus().catch(() => {})
      expect(onLost).toHaveBeenCalledTimes(1)

      resetAuthLost()
      await getStatus().catch(() => {})
      // Otherwise a second session loss in the same tab is swallowed forever.
      expect(onLost).toHaveBeenCalledTimes(2)
      window.removeEventListener(AUTH_LOST_EVENT, onLost)
    })

    it('does not treat a rejected login as a lost session', async () => {
      const onLost = vi.fn()
      window.addEventListener(AUTH_LOST_EVENT, onLost)
      fetchMock.mockResolvedValue(res(401, { detail: 'bad password' }))

      // A wrong password is a form error. Firing auth-lost here would bounce
      // the user off the very page they are trying to log in on.
      await loginAuth('me', 'wrong').catch(() => {})
      expect(onLost).not.toHaveBeenCalled()
      window.removeEventListener(AUTH_LOST_EVENT, onLost)
    })

    it('reports the failing url with the event', async () => {
      let detail
      const onLost = (e) => {
        detail = e.detail
      }
      window.addEventListener(AUTH_LOST_EVENT, onLost)
      fetchMock.mockResolvedValue(res(401, {}))

      await getStatus().catch(() => {})
      expect(detail.url).toBe('/api/status')
      window.removeEventListener(AUTH_LOST_EVENT, onLost)
    })
  })

  describe('retries and transport failures', () => {
    it('retries a failed GET and resolves when a later attempt succeeds', async () => {
      vi.useFakeTimers()
      fetchMock
        .mockRejectedValueOnce(netFail())
        .mockRejectedValueOnce(netFail())
        .mockResolvedValue(res(200, { ok: true }))

      const pending = getStatus()
      await vi.advanceTimersByTimeAsync(ALL_RETRY_DELAYS)

      await expect(pending).resolves.toEqual({ ok: true })
      expect(fetchMock).toHaveBeenCalledTimes(3)
    })

    it('gives up after the retry budget and reports being offline', async () => {
      vi.useFakeTimers()
      fetchMock.mockRejectedValue(netFail())

      const pending = getStatus()
      const assertion = expect(pending).rejects.toThrow(en.err.offline)
      await vi.advanceTimersByTimeAsync(ALL_RETRY_DELAYS)
      await assertion

      // 1 initial attempt + 2 retries, not an unbounded loop.
      expect(fetchMock).toHaveBeenCalledTimes(3)
    })

    it('never retries a non-GET request', async () => {
      fetchMock.mockRejectedValue(netFail())

      await loginAuth('me', 'pw').catch(() => {})
      // Replaying a POST could double-apply a mutation.
      expect(fetchMock).toHaveBeenCalledTimes(1)
    })

    it('aborts a request that never answers and reports it as a timeout', async () => {
      vi.useFakeTimers()
      // Do NOT inject an AbortError: honour the signal the client actually passes,
      // so this covers the real setTimeout/AbortController wiring. Injecting the
      // error directly let a mutant that removed the abort survive.
      const seenSignals = []
      fetchMock.mockImplementation(
        (_url, opts) =>
          new Promise((_resolve, reject) => {
            seenSignals.push(opts.signal)
            // A hung request: the only way out is the client's own abort.
            opts.signal.addEventListener('abort', () => {
              reject(Object.assign(new Error('aborted'), { name: 'AbortError' }))
            })
          }),
      )

      const pending = getStatus()
      let caught
      const assertion = pending.catch((e) => {
        caught = e
      })

      // Nothing has rejected yet; the request is still outstanding.
      expect(caught).toBeUndefined()

      // 30s default timeout per attempt, plus the retry backoffs between them.
      await vi.advanceTimersByTimeAsync(30000 * 3 + ALL_RETRY_DELAYS)
      await assertion

      expect(seenSignals).toHaveLength(3)
      expect(seenSignals.every((s) => s.aborted)).toBe(true)
      expect(caught.message).toBe(en.err.timeout)
      // status 0 is how callers tell transport failure from an HTTP error.
      expect(caught.status).toBe(0)
    })

    it('does not retry an HTTP error response', async () => {
      fetchMock.mockResolvedValue(res(500, {}, 'Internal Server Error'))

      await getStatus().catch(() => {})
      // The server answered; hammering it twice more helps nobody.
      expect(fetchMock).toHaveBeenCalledTimes(1)
    })

    it('survives a response body that is not json', async () => {
      fetchMock.mockResolvedValue({
        ok: true,
        status: 200,
        statusText: 'OK',
        json: async () => {
          throw new Error('not json')
        },
      })
      await expect(getStatus()).resolves.toEqual({})
    })
  })

  describe('doAction', () => {
    it('reports failure when the body says ok:false despite HTTP 200', async () => {
      fetchMock.mockResolvedValue(res(200, { ok: false, error: 'nope' }))

      const out = await doAction('svc', 'restart')
      // The endpoint signals refusal in the body, so HTTP 200 alone is not success.
      expect(out.ok).toBe(false)
      expect(out.status).toBe(200)
    })

    it('reports success and passes the payload through', async () => {
      fetchMock.mockResolvedValue(res(200, { ok: true, pid: 42 }))

      const out = await doAction('svc', 'start')
      expect(out.ok).toBe(true)
      expect(out.pid).toBe(42)
    })

    it('reports failure on an HTTP error', async () => {
      fetchMock.mockResolvedValue(res(500, {}))
      const out = await doAction('svc', 'start')
      expect(out.ok).toBe(false)
      expect(out.status).toBe(500)
    })
  })
})
