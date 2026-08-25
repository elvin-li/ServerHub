/**
 * Behavioural cover for `public/sw.js`.
 *
 * The worker is the only thing between the operator and a blank tab when the
 * panel is down, and it was until now pinned only by asserting that certain
 * source lines existed. That catches a deletion and nothing else: it cannot
 * tell whether a 502 falls back, whether a stored 404 is served, or whether an
 * /api/ call is left alone. This loads the real file, gives it a fake
 * `self`/`caches`/`fetch`, and drives the handlers it registers.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = dirname(fileURLToPath(import.meta.url))
const SOURCE = readFileSync(join(HERE, '..', 'public', 'sw.js'), 'utf8')

/** A stand-in for the parts of `Response` the worker touches. */
function reply(body, { ok = true, status = 200 } = {}) {
  const response = { ok, status, body, clone: () => reply(body, { ok, status }) }
  return response
}

function loadWorker() {
  const listeners = new Map()
  const store = new Map()
  const deleted = []

  const caches = {
    open: async () => ({
      addAll: async (urls) => urls.forEach((u) => store.set(u, reply(`precached ${u}`))),
      put: async (request, response) => store.set(urlOf(request), response),
    }),
    match: async (request) => store.get(urlOf(request)),
    keys: async () => [...new Set([...store.keys()].filter((k) => k.startsWith('serverhub-')))],
    delete: async (key) => { deleted.push(key); return true },
  }

  const self = {
    location: { origin: 'https://panel.test' },
    addEventListener: (name, fn) => listeners.set(name, fn),
    skipWaiting: vi.fn(),
    clients: { claim: vi.fn(async () => {}) },
  }

  const source = SOURCE
    .replace('__SERVERHUB_CACHE_FINGERPRINT__', 'testfingerprint')
    .replace('__SERVERHUB_PRECACHE_ASSETS__', '["/assets/app-abc.js"]')

  // eslint-disable-next-line no-new-func
  new Function('self', 'caches', 'fetch', 'setTimeout', 'clearTimeout', 'AbortController', 'URL', source)(
    self, caches, (...args) => globalThis.fetch(...args),
    globalThis.setTimeout, globalThis.clearTimeout, globalThis.AbortController, URL,
  )

  return { listeners, store, deleted, self }
}

/** Cache Storage resolves a relative key against the worker's scope. */
function urlOf(request) {
  return new URL(typeof request === 'string' ? request : request.url, 'https://panel.test').href
}

/** Run the worker's fetch handler for one request and return what it answered. */
async function navigate(worker, url, { mode = 'navigate', method = 'GET' } = {}) {
  const request = { url, mode, method }
  let answered
  worker.listeners.get('fetch')({ request, respondWith: (p) => { answered = p } })
  return answered === undefined ? undefined : await answered
}

describe('the offline shell', () => {
  let worker
  beforeEach(() => {
    worker = loadWorker()
    vi.restoreAllMocks()
  })

  it('serves the live page when the panel answers', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => reply('live page')))
    const got = await navigate(worker, 'https://panel.test/')
    expect(got.body).toBe('live page')
  })

  it('falls back to the cached shell when the gateway answers 502', async () => {
    worker.store.set('https://panel.test/', reply('cached shell'))
    vi.stubGlobal('fetch', vi.fn(async () => reply('<html>502 Bad Gateway</html>', { ok: false, status: 502 })))
    const got = await navigate(worker, 'https://panel.test/network')
    expect(got.body).toBe('cached shell')
  })

  it('never caches the gateway error page', async () => {
    worker.store.set('https://panel.test/', reply('cached shell'))
    vi.stubGlobal('fetch', vi.fn(async () => reply('502', { ok: false, status: 502 })))
    await navigate(worker, 'https://panel.test/network')
    expect(worker.store.get('https://panel.test/network')).toBeUndefined()
  })

  it('hands back the server error when there is no shell to fall back to', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => reply('502', { ok: false, status: 502 })))
    const got = await navigate(worker, 'https://panel.test/network')
    expect(got.status).toBe(502)
  })

  it('falls back to the cached shell when the network is gone', async () => {
    worker.store.set('https://panel.test/', reply('cached shell'))
    vi.stubGlobal('fetch', vi.fn(async () => { throw new Error('offline') }))
    const got = await navigate(worker, 'https://panel.test/health')
    expect(got.body).toBe('cached shell')
  })
})

describe('what the worker refuses to touch', () => {
  let worker
  beforeEach(() => { worker = loadWorker() })

  it('leaves API calls to the network', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => reply('never')))
    expect(await navigate(worker, 'https://panel.test/api/status', { mode: 'cors' })).toBeUndefined()
  })

  it('leaves non-GET requests alone', async () => {
    expect(await navigate(worker, 'https://panel.test/', { method: 'POST' })).toBeUndefined()
  })

  it('leaves cross-origin requests alone', async () => {
    expect(await navigate(worker, 'https://elsewhere.test/x.js', { mode: 'cors' })).toBeUndefined()
  })
})

describe('hashed assets', () => {
  let worker
  beforeEach(() => { worker = loadWorker() })

  it('serves a cached asset without asking the network', async () => {
    const network = vi.fn(async () => reply('from network'))
    vi.stubGlobal('fetch', network)
    worker.store.set('https://panel.test/assets/app-abc.js', reply('from cache'))
    const got = await navigate(worker, 'https://panel.test/assets/app-abc.js', { mode: 'cors' })
    expect(got.body).toBe('from cache')
    expect(network).not.toHaveBeenCalled()
  })

  it('re-fetches rather than replaying a 404 stored during a deploy', async () => {
    worker.store.set('https://panel.test/assets/app-abc.js', reply('missing', { ok: false, status: 404 }))
    vi.stubGlobal('fetch', vi.fn(async () => reply('the new build')))
    const got = await navigate(worker, 'https://panel.test/assets/app-abc.js', { mode: 'cors' })
    expect(got.body).toBe('the new build')
  })
})

describe('activation', () => {
  it('drops the caches of previous builds and keeps its own', async () => {
    const worker = loadWorker()
    worker.store.set('serverhub-oldbuild', reply('x'))
    worker.store.set('serverhub-testfingerprint', reply('x'))
    let settled
    worker.listeners.get('activate')({ waitUntil: (p) => { settled = p } })
    await settled
    expect(worker.deleted).toEqual(['serverhub-oldbuild'])
    expect(worker.self.clients.claim).toHaveBeenCalled()
  })
})
