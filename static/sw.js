// ServerHub Service Worker — offline-first app shell caching
// Vite replaces the placeholder with a stable fingerprint of the build output.
const CACHE_NAME = 'serverhub-67e34b966d6a7ac8'
// Vite replaces the placeholder with the first-paint assets (entry + vendor
// chunks and CSS) of the build output.
const PRECACHE_ASSETS = ["/assets/Account-CluPFLrS.css","/assets/Apps-BKjzjjEE.css","/assets/Backups-DRAWgFLO.css","/assets/Bookmarks-98hgDb9V.css","/assets/Compose-DZIpggS2.css","/assets/Dashboard-TpWLBNRG.css","/assets/Files-Drug7_5V.css","/assets/LineChart-BEiuHeBQ.css","/assets/LoadFailure-s5h3k7m_.css","/assets/Login-CFDh25vf.css","/assets/Logs-CSzaScg0.css","/assets/MacSwitch-C40cgBYQ.css","/assets/MainArray-tn0RQdqM.css","/assets/Network-BACYZ6AL.css","/assets/Ollama-C7yP7Gqx.css","/assets/PhotosHub-C2aCGpGj.css","/assets/Pool-B8nDm__t.css","/assets/ScheduleJobForm-D3lKEA8a.css","/assets/Services-Bu8QB6WC.css","/assets/Settings-CyFkG0U8.css","/assets/Shares-CigmDVsH.css","/assets/SkeletonLoader-CBLdJ8iz.css","/assets/Terminal-Df3z8Wvf.css","/assets/Tools-BfVhlsbW.css","/assets/Users-UnFA27JU.css","/assets/VMs-BRtVRGlK.css","/assets/WireGuard-BLqbzBO1.css","/assets/en-6FQRVebs.js","/assets/index-BhKzfDFJ.css","/assets/index-DUmemvkj.js","/assets/vendor-4S_DzOps.js"]
const SHELL_ASSETS = [
  '/',
  '/index.html',
  '/logo.svg',
  '/favicon.svg',
  '/site.webmanifest',
]
// A hung backend must not hang a navigation; fall back to the cached shell.
const NAV_TIMEOUT_MS = 2500

// Only successful responses belong in the cache. A rebuild replaces hashed
// `/assets/*` files; a tab that fetches during that window used to store the
// 404, and cache-first then served that 404 forever — the SPA cannot load a
// locale dictionary and refuses to mount.
function cacheIfOk(request, response) {
  if (!response || !response.ok) return
  const clone = response.clone()
  caches.open(CACHE_NAME).then((cache) => cache.put(request, clone))
}

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(SHELL_ASSETS.concat(PRECACHE_ASSETS)))
  )
  self.skipWaiting()
})

self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    const keys = await caches.keys()
    const oldCaches = keys.filter(
      (key) => key.startsWith('serverhub-') && key !== CACHE_NAME,
    )
    await Promise.all(oldCaches.map((key) => caches.delete(key)))
    // Claim the open windows but never force-navigate them: a bulk reload of
    // every tab after a deploy turned into a blank-screen storm. Tabs move to
    // the new build through the sw-update-ready banner instead.
    await self.clients.claim()
  })())
})

// Allow main app to trigger cache update (e.g. after deploy)
self.addEventListener('message', (event) => {
  if (event.data === 'skipWaiting') self.skipWaiting()
})

self.addEventListener('fetch', (event) => {
  const { request } = event
  const url = new URL(request.url)

  // Never intercept or cache API calls, non-GETs, or cross-origin requests.
  if (url.pathname === '/api' || url.pathname.startsWith('/api/')) return
  if (request.method !== 'GET' || url.origin !== self.location.origin) return

  // Network-first for navigation (HTML), cache-first for assets
  if (request.mode === 'navigate') {
    event.respondWith((async () => {
      // Race the network against a timeout so a stalled backend falls back to
      // the cached shell instead of leaving the browser spinner spinning.
      const controller = new AbortController()
      const timer = setTimeout(() => controller.abort(), NAV_TIMEOUT_MS)
      try {
        const response = await fetch(request, { signal: controller.signal })
        if (response && response.ok) {
          cacheIfOk(request, response)
          return response
        }
        // A gateway that is up while the panel behind it is restarting answers
        // 502 — a successful fetch of somebody else's error page, so the catch
        // below never sees it. Returning it showed the operator raw nginx
        // output during the restarts the panel performs on itself. The cached
        // shell boots instead and the SPA shows its own reconnect state.
        const stale = (await caches.match(request)) || (await caches.match('/'))
        return (stale && stale.ok) ? stale : response
      } catch {
        const cached = await caches.match(request)
        if (cached && cached.ok) return cached
        const shell = await caches.match('/')
        return (shell && shell.ok) ? shell : undefined
      } finally {
        clearTimeout(timer)
      }
    })())
  } else if (url.pathname.startsWith('/assets/')) {
    // Immutable hashed assets — cache-first, but never reuse a stored miss.
    event.respondWith(
      caches.match(request).then((cached) => {
        if (cached && cached.ok) return cached
        return fetch(request).then((response) => {
          cacheIfOk(request, response)
          return response
        })
      })
    )
  } else {
    // Stale-while-revalidate for other static files (icons, etc.)
    event.respondWith(
      caches.match(request).then((cached) => {
        const fetchPromise = fetch(request).then((response) => {
          cacheIfOk(request, response)
          return response
        }).catch(() => cached && cached.ok ? cached : undefined)
        return (cached && cached.ok ? cached : null) || fetchPromise
      })
    )
  }
})
