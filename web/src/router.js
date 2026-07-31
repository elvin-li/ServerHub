import { createRouter, createWebHistory } from 'vue-router'
import Dashboard from './views/Dashboard.vue'
import Login from './views/Login.vue'
// Dashboard is the landing page. Keep it eager and split every secondary page
// into an on-demand chunk so first paint does not download the entire admin UI.
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
const Network = () => import('./views/Network.vue')
const Gateway = () => import('./views/Gateway.vue')
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
  { path: '/network', name: 'network', component: Network },
  { path: '/gateway', name: 'gateway', component: Gateway },
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
  // Catch-all → redirect to dashboard
  { path: '/:pathMatch(.*)*', redirect: '/' },
]

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
  const needsLogin = state.setup_required || (state.auth_required && !state.authenticated)
  if (to.name === 'login') {
    return needsLogin ? true : { path: '/' }
  }
  if (needsLogin) {
    return { path: '/login', query: { next: to.fullPath } }
  }
  return true
})

export default router
