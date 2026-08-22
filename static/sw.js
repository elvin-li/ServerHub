// ServerHub Service Worker — offline-first app shell caching
// Vite replaces the placeholder with a stable fingerprint of the build output.
const CACHE_NAME = 'serverhub-959f109a26480b3c'
// Vite replaces the placeholder with the first-paint assets (entry + vendor
// chunks and CSS) of the build output.
const PRECACHE_ASSETS = ["/assets/Account-BQ8889N_.css","/assets/Apps-C5SGjUP-.css","/assets/Backups-y7om_4XT.css","/assets/Bookmarks-CrBJ0fZy.css","/assets/Compose-BRPztoSv.css","/assets/Dashboard-EpRf2jMO.css","/assets/Files-l5mz3TWT.css","/assets/LineChart-CNkm9mVy.css","/assets/LoadFailure-s5h3k7m_.css","/assets/Login-CzCVd8Pl.css","/assets/Logs-BFK1lR4W.css","/assets/MainArray-tn0RQdqM.css","/assets/Network-Dem5pL59.css","/assets/Ollama-BDY0kcf4.css","/assets/PhotosHub-BCIayVtu.css","/assets/Pool-BZDZ_UnA.css","/assets/ScheduleJobForm-Qht-yzhv.css","/assets/Services-IvKzw6ob.css","/assets/Settings-D4L_tc9g.css","/assets/Shares-Dio_Cej2.css","/assets/SkeletonLoader-CBLdJ8iz.css","/assets/StackBar-8-c0PX14.css","/assets/Terminal-ChNLfQFA.css","/assets/Tools-sCuYZKRR.css","/assets/Users-Bs90Lvi6.css","/assets/VMs-BRtVRGlK.css","/assets/WireGuard-DH-EaeqJ.css","/assets/en-CojN8eLh.js","/assets/index-Cu7ZmNss.js","/assets/index-qLj0BWLR.css","/assets/vendor-4S_DzOps.js"]
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
