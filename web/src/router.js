import { createRouter, createWebHistory } from 'vue-router'
import {
  clearStaleChunkFlag, isChunkLoadError, recoverFromStaleChunk,
} from './lib/chunkRecovery'
import { applyAuthStatus, MEMBER_ROUTE_NAMES } from './lib/authState'

// Every page, including the two entry points, is an on-demand chunk.
//
// Dashboard used to be imported eagerly on the reasoning that the landing page
// should not wait for a second request. That held when it was small; it has since
// grown to 64 KB of source and, because LineChart and StackBar are used nowhere
// else, it dragged those in too — 27% of the first-paint bundle. Everyone paid
// for it: a deep link to /containers downloaded the whole dashboard, and an
// unauthenticated visitor was sent to /login and downloaded it anyway.
//
// Login was eager for the same reason and has the mirror-image problem: an
// authenticated visitor never renders it.
//
// The round trip that eagerness was avoiding is given back by warmLandingChunk(),
// which starts the fetch for whichever of the two this URL will actually use,
// concurrently with bootstrap's dictionary load and the auth-status probe.
const Dashboard = () => import('./views/Dashboard.vue')
const Login = () => import('./views/Login.vue')
const MainArray = () => import('./views/MainArray.vue')
const Pool = () => import('./views/Pool.vue')
const Files = () => import('./views/Files.vue')
const Shares = () => import('./views/Shares.vue')
const Users = () => import('./views/Users.vue')
const Containers = () => import('./views/Containers.vue')
const Compose = () => import('./views/Compose.vue')
const Apps = () => import('./views/Apps.vue')
const VMs = () => import('./views/VMs.vue')
const Services = () => import('./views/Services.vue')
const Brew = () => import('./views/Brew.vue')
const Ollama = () => import('./views/Ollama.vue')
const Network = () => import('./views/Network.vue')
const Gateway = () => import('./views/Gateway.vue')
const WireGuard = () => import('./views/WireGuard.vue')
const Health = () => import('./views/Health.vue')
const Scheduler = () => import('./views/Scheduler.vue')
const Tools = () => import('./views/Tools.vue')
const Terminal = () => import('./views/Terminal.vue')
const Logs = () => import('./views/Logs.vue')
const Alerts = () => import('./views/Alerts.vue')
const Audit = () => import('./views/Audit.vue')
const Backups = () => import('./views/Backups.vue')
const Bookmarks = () => import('./views/Bookmarks.vue')
const Modules = () => import('./views/Modules.vue')
const Maintenance = () => import('./views/Maintenance.vue')
const Settings = () => import('./views/Settings.vue')
const Account = () => import('./views/Account.vue')

// Unraid Tasks order: Main → Shares → Users → Docker → VMs → Apps → Tools → Settings
// + macOS extras: Dashboard, Services, Brew, Compose, Network, Gateway, Health, Scheduler
const routes = [
  { path: '/login', name: 'login', component: Login, meta: { authPage: true } },
  { path: '/', name: 'dashboard', component: Dashboard },
  { path: '/main', name: 'main', component: MainArray },
  { path: '/pool', name: 'pool', component: Pool },
  { path: '/storage', redirect: '/main' },
  { path: '/files', name: 'files', component: Files },
  { path: '/shares', name: 'shares', component: Shares },
  { path: '/users', name: 'users', component: Users },
  { path: '/containers', name: 'containers', component: Containers },
  { path: '/compose', name: 'compose', component: Compose },
  { path: '/apps', name: 'apps', component: Apps },
  { path: '/vms', name: 'vms', component: VMs },
  { path: '/services', name: 'services', component: Services },
  { path: '/brew', name: 'brew', component: Brew },
  { path: '/ollama', name: 'ollama', component: Ollama },
  { path: '/network', name: 'network', component: Network },
  { path: '/gateway', name: 'gateway', component: Gateway },
  { path: '/wireguard', name: 'wireguard', component: WireGuard },
  { path: '/health', name: 'health', component: Health },
  { path: '/scheduler', name: 'scheduler', component: Scheduler },
  { path: '/tools', name: 'tools', component: Tools },
  { path: '/terminal', name: 'terminal', component: Terminal },
  { path: '/logs', name: 'logs', component: Logs },
  { path: '/alerts', name: 'alerts', component: Alerts },
  { path: '/audit', name: 'audit', component: Audit },
  { path: '/backups', name: 'backups', component: Backups },
  { path: '/bookmarks', name: 'bookmarks', component: Bookmarks },
  { path: '/modules', name: 'modules', component: Modules },
  { path: '/maintenance', name: 'maintenance', component: Maintenance },
  { path: '/power', redirect: '/' },
  { path: '/settings', name: 'settings', component: Settings },
  // Per-account self-service (password, 2FA).  Reachable by every signed-in
  // role; it is the only management surface a member session can use.
  { path: '/account', name: 'account', component: Account },
  // Catch-all → redirect to dashboard
  { path: '/:pathMatch(.*)*', redirect: '/' },
]

/**
 * Start downloading the chunk this URL is going to need, without waiting for it.
 *
 * Called before the app mounts, so the request overlaps the locale dictionary
 * load and the `/api/auth/status` probe in the guard below — both of which the
 * first navigation already blocks on. By the time the guard resolves the chunk is
 * normally in the module cache, so making these two routes lazy costs no extra
 * serial round trip on first paint.
 *
 * Only one of the two is warmed: the point is to stop shipping both.
 * Failures are ignored on purpose — this is a prefetch, and the router will
 * request the chunk again (and surface a real error) when it actually navigates.
 */
export function warmLandingChunk(pathname = window.location.pathname) {
  const load = pathname === '/login' ? Login : Dashboard
  try {
    void load()?.catch?.(() => {})
  } catch {}
}

const router = createRouter({
  history: createWebHistory(),
  routes,
  scrollBehavior() {
    return { top: 0 }
  },
})

/* Lightweight NProgress-style top bar for route transitions */
let barEl = null
let barTimer = null
function barStart() {
  if (!barEl) {
    barEl = document.createElement('div')
    barEl.id = 'route-progress'
    document.body.appendChild(barEl)
  }
  barEl.style.transition = 'none'
  barEl.style.width = '0'
  barEl.style.opacity = '1'
  requestAnimationFrame(() => {
    barEl.style.transition = 'width 8s cubic-bezier(.1,.6,.2,1)'
    barEl.style.width = '85%'
  })
}
function barDone() {
  if (!barEl) return
  barEl.style.transition = 'width .2s ease'
  barEl.style.width = '100%'
  clearTimeout(barTimer)
  barTimer = setTimeout(() => {
    if (barEl) barEl.style.opacity = '0'
  }, 250)
}

router.beforeEach(() => {
  barStart()
  return true
})
router.afterEach(() => {
  barDone()
  // The navigation resolved, so this shell is serving working chunks. Drop the
  // guard so a future staleness can recover instead of being suppressed.
  clearStaleChunkFlag()
})

// A lazy route whose chunk hash no longer exists on the server leaves the user on
// a page that never opens. Treat it as a stale shell and reload once.
router.onError((error) => {
  if (isChunkLoadError(error)) {
    barDone()
    recoverFromStaleChunk()
  }
})

router.beforeEach(async (to) => {
  let state
  try {
    const ctrl = new AbortController()
    const timer = setTimeout(() => ctrl.abort(), 5000)
    const r = await fetch('/api/auth/status', { cache: 'no-store', signal: ctrl.signal })
    clearTimeout(timer)
    state = await r.json()
  } catch {
    return true
  }
  // Every navigation already pays for this status probe; publishing the answer
  // is what lets App.vue tailor the nav to the session's role.
  applyAuthStatus(state)
  const needsLogin = state.setup_required || (state.auth_required && !state.authenticated)
  if (to.name === 'login') {
    return needsLogin ? true : { path: '/' }
  }
  if (needsLogin) {
    return { path: '/login', query: { next: to.fullPath } }
  }
  // Members only reach the pages their API surface can actually feed; a deep
  // link to an admin page lands on the dashboard instead of a wall of 403s.
  if (
    state.authenticated &&
    state.role === 'member' &&
    !MEMBER_ROUTE_NAMES.has(to.name)
  ) {
    return { path: '/' }
  }
  return true
})

export default router
