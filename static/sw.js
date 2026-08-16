// ServerHub Service Worker — offline-first app shell caching
// Vite replaces the placeholder with a stable fingerprint of the build output.
const CACHE_NAME = 'serverhub-d51e4e502242a3fd'
// Vite replaces the placeholder with the first-paint assets (entry + vendor
// chunks and CSS) of the build output.
const PRECACHE_ASSETS = ["/assets/Account-KGvMr2ki.css","/assets/Apps-m-97Mgdy.css","/assets/Bookmarks-7puGVeLg.css","/assets/Compose-YTjKniP0.css","/assets/Dashboard-X3mGkswr.css","/assets/Files-A_jp4-Ui.css","/assets/LineChart-DH0qnAGV.css","/assets/LoadFailure-BEQ7p-Tv.css","/assets/Login-Ddv1ZII_.css","/assets/Logs-D4zGnGqB.css","/assets/MainArray-tn0RQdqM.css","/assets/Network-CdQFuIwV.css","/assets/Ollama-B_YivI2H.css","/assets/PhotosHub-y-J_H0-J.css","/assets/Pool-CsRJ6hDS.css","/assets/ScheduleJobForm-Dmls8G56.css","/assets/Services-Be_IP4XO.css","/assets/Settings-BnwCuhzk.css","/assets/Shares-CumIWhxt.css","/assets/SkeletonLoader-CBLdJ8iz.css","/assets/StackBar-dHXReq1Y.css","/assets/Terminal-BdrxAkUJ.css","/assets/Tools-BwqItP48.css","/assets/Users-CRFEYuIr.css","/assets/VMs-DyXf0bZX.css","/assets/WireGuard-C6-_8RoW.css","/assets/en-s7_YIatx.js","/assets/index-CPe7xBrJ.js","/assets/index-DbGHx7fv.css","/assets/vendor-DVlS_6Kg.js"]
const SHELL_ASSETS = [
  '/',
  '/index.html',
  '/logo.svg',
  '/favicon.svg',
  '/site.webmanifest',
]
// A hung backend must not hang a navigation; fall back to the cached shell.
const NAV_TIMEOUT_MS = 2500

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
        const clone = response.clone()
        caches.open(CACHE_NAME).then((cache) => cache.put(request, clone))
        return response
      } catch {
        return (await caches.match(request)) || (await caches.match('/'))
      } finally {
        clearTimeout(timer)
      }
    })())
  } else if (url.pathname.startsWith('/assets/')) {
    // Immutable hashed assets — cache-first
    event.respondWith(
      caches.match(request).then((cached) => {
        if (cached) return cached
        return fetch(request).then((response) => {
          const clone = response.clone()
          caches.open(CACHE_NAME).then((cache) => cache.put(request, clone))
          return response
        })
      })
    )
  } else {
    // Stale-while-revalidate for other static files (icons, etc.)
    event.respondWith(
      caches.match(request).then((cached) => {
        const fetchPromise = fetch(request).then((response) => {
          if (response.ok) {
            const clone = response.clone()
            caches.open(CACHE_NAME).then((cache) => cache.put(request, clone))
          }
          return response
        }).catch(() => cached)
        return cached || fetchPromise
      })
    )
  }
})
