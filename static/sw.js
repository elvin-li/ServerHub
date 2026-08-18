// ServerHub Service Worker — offline-first app shell caching
// Vite replaces the placeholder with a stable fingerprint of the build output.
const CACHE_NAME = 'serverhub-f4c3ec0789469ff8'
// Vite replaces the placeholder with the first-paint assets (entry + vendor
// chunks and CSS) of the build output.
const PRECACHE_ASSETS = ["/assets/Account-CO1ggNv0.css","/assets/Apps-BuTVjVtz.css","/assets/Backups-B-wnW77f.css","/assets/Bookmarks-7puGVeLg.css","/assets/Compose-Bu50gwJ4.css","/assets/Dashboard-DhodEP8X.css","/assets/Files-A_jp4-Ui.css","/assets/LineChart-DH0qnAGV.css","/assets/LoadFailure-BEQ7p-Tv.css","/assets/Login-2cH-DV5c.css","/assets/Logs-CSFS16_r.css","/assets/MainArray-tn0RQdqM.css","/assets/Network-Cd4TqOqq.css","/assets/Ollama-CBDY8_YR.css","/assets/PhotosHub-DsPXjEmw.css","/assets/Pool-CsRJ6hDS.css","/assets/ScheduleJobForm-Dmls8G56.css","/assets/Services-DcipRvZV.css","/assets/Settings-Bt7pHAg2.css","/assets/Shares-CumIWhxt.css","/assets/SkeletonLoader-CBLdJ8iz.css","/assets/StackBar-dHXReq1Y.css","/assets/Terminal-BdrxAkUJ.css","/assets/Tools-BwqItP48.css","/assets/Users-CRFEYuIr.css","/assets/VMs-DyXf0bZX.css","/assets/WireGuard-B4EZP_wo.css","/assets/en-Br71c7Ge.js","/assets/index-DbGHx7fv.css","/assets/index-Dt4CcYK9.js","/assets/vendor-DVlS_6Kg.js"]
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
        cacheIfOk(request, response)
        return response
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
