<template>
  <router-view v-if="route.meta.authPage" />
  <div v-else class="layout">
    <header class="topchrome">
      <div class="topchrome-inner">
        <button
          class="hamburger"
          type="button"
          @click="menuOpen = !menuOpen"
          :class="{ open: menuOpen }"
          :aria-label="t('common.menu')"
          :aria-expanded="menuOpen"
          aria-controls="app-nav"
        >
          <span></span><span></span><span></span>
        </button>
        <div class="brand">
          <img class="logo" src="/logo.svg" width="22" height="22" alt="" />
          <span class="brand-text">{{ t('brand') }}</span>
        </div>
        <button
          v-if="canAssist"
          class="assist-launch"
          type="button"
          data-test="assistant-open"
          :aria-label="t('assistant.title')"
          :aria-expanded="assistOpen"
          @click="openAssistant()"
        >
          <Sparkles :size="14" />
          <span class="assist-launch-label">{{ t('assistant.short') }}</span>
        </button>
        <button
          v-if="canAssist"
          class="assist-launch assist-page"
          type="button"
          data-test="assistant-page-header"
          :aria-label="t('assistant.page')"
          @click="openAssistant('', 'page')"
        >
          <BookOpen :size="14" />
          <span class="assist-launch-label">{{ t('assistant.page') }}</span>
        </button>
        <div class="top-status-m" v-if="counts">
          <span class="pill" :class="engineClass">{{ engineUp ? t('common.on') : t('common.off') }}</span>
          <span class="pill down" v-if="counts.down"><b>{{ counts.down }}</b></span>
          <span class="pill warn" v-if="counts.warn"><b>{{ counts.warn }}</b></span>
        </div>
        <nav
          id="app-nav"
          ref="navPanel"
          class="top-nav"
          :class="{ open: menuOpen }"
          aria-label="Main navigation"
          :inert="navInert"
          :aria-hidden="navInert"
        >
          <div class="nav-drawer-title">{{ t('brand') }}</div>
          <router-link
            v-for="item in nav"
            :key="item.to"
            :to="item.to"
            :class="{ active: isActive(item) }"
            @click="menuOpen = false"
          >
            <component :is="item.icon" :size="15" />
            <span>{{ t(item.labelKey) }}</span>
          </router-link>
          <div class="top-controls">
            <label class="nav-tool">
              <span class="nav-tool-label">{{ t('appearance.language') }}</span>
              <select :value="locale" @change="onLocale($event)" :title="t('appearance.language')">
                <option v-for="l in locales" :key="l.id" :value="l.id">{{ l.native }}</option>
              </select>
            </label>
            <label class="nav-tool">
              <span class="nav-tool-label">{{ t('theme.title') }}</span>
              <select :value="theme" @change="onTheme($event)" :title="t('theme.title')">
                <option v-for="th in themes" :key="th.id" :value="th.id">{{ t(th.labelKey) }}</option>
              </select>
            </label>
            <button class="logout-btn" type="button" @click="logout">{{ t('auth.logout') }}</button>
          </div>
        </nav>
        <div class="top-status" v-if="counts">
          <span class="pill" :class="engineClass">{{ t('top.orbstack') }} {{ engineUp ? t('common.on') : t('common.off') }}</span>
          <span class="pill ok"><b>{{ counts.ok }}</b></span>
          <span class="pill warn" v-if="counts.warn"><b>{{ counts.warn }}</b></span>
          <span class="pill" v-if="counts.stopped" style="opacity:.75"><b>{{ counts.stopped }}</b></span>
          <span class="pill down" v-if="counts.down"><b>{{ counts.down }}</b></span>
          <span class="pill" v-if="status?.system">{{ status.system.load1 ?? '' }}</span>
          <router-link v-if="counts.down || counts.warn" class="pill down" to="/services">!</router-link>
        </div>
      </div>
      <!-- Secondary nav: related pages merged under one top tab -->
      <div class="subchrome" v-if="activeChildren.length" role="navigation" aria-label="Section navigation">
        <div class="subchrome-inner">
          <router-link
            v-for="c in activeChildren"
            :key="c.to"
            :to="c.to"
            :class="{ active: isChildActive(c) }"
            @click="menuOpen = false"
          >
            <component :is="c.icon" :size="13" />
            <span>{{ t(c.labelKey) }}</span>
          </router-link>
        </div>
      </div>
    </header>
    <!-- Mobile nav overlay -->
    <div class="nav-overlay" :class="{ show: menuOpen }" @click="menuOpen = false"></div>
    <!-- Offline banner -->
    <div v-if="offline" class="offline-banner" role="alert">⚠ {{ t('common.offline_banner') }}</div>
    <main class="main" role="main">
      <router-view v-slot="{ Component }">
        <transition name="page-fade" mode="out-in">
          <component :is="Component" />
        </transition>
      </router-view>
    </main>
    <div
      class="toast"
      :class="{ show: !!toast }"
      :role="toastIsError ? 'alert' : 'status'"
      :aria-live="toastIsError ? 'assertive' : 'polite'"
    >{{ toast }}</div>
    <!-- Pull-to-refresh indicator (mobile) -->
    <div class="ptr-indicator" :class="{ visible: ptrVisible, refreshing: ptrRefreshing }"></div>
    <!-- Back to top (mobile) -->
    <button v-show="showTop" class="fab-top" type="button" @click="scrollTop" :aria-label="t('common.back_to_top')">↑</button>
    <!-- SW update notification -->
    <div v-if="swUpdate" class="sw-update-banner" role="status">
      🚀 {{ t('common.update_ready') }}
      <button class="tiny primary" @click="applySwUpdate">{{ t('common.reload_now') }}</button>
    </div>
    <!-- Command palette (Cmd+K) -->
    <div v-if="cmdOpen" class="cmd-palette-bg" @click.self="cmdOpen=false" role="presentation">
      <div
        ref="cmdPanel"
        class="cmd-palette"
        role="dialog"
        aria-modal="true"
        :aria-label="t('common.cmd_title')"
        tabindex="-1"
      >
        <input
          ref="cmdInput"
          v-model="cmdQuery"
          type="text"
          :placeholder="t('common.cmd_ph')"
          @keydown.enter="cmdGo(cmdIdx)"
          @keydown.up.prevent="cmdIdx = Math.max(0, cmdIdx - 1)"
          @keydown.down.prevent="cmdIdx = Math.min(cmdFlat.length - 1, cmdIdx + 1)"
        />
        <ul class="cmd-list">
          <li
            v-for="(item, i) in cmdFlat"
            :key="item.to"
            :class="{ active: i === cmdIdx, 'cmd-ai': item.type === 'ai' }"
            @click="cmdGo(i)"
            @mouseenter="cmdIdx = i"
          >
            <span>{{ item.type === 'ai' ? t('assistant.ask_cmd', { q: item.query }) : (item.title || t(item.labelKey)) }}</span>
            <kbd>{{ item.type === 'ai' ? t('assistant.short') : item.to }}</kbd>
          </li>
          <li v-if="!cmdFlat.length" class="cmd-empty">{{ t('common.cmd_empty') }}</li>
        </ul>
      </div>
    </div>
    <AssistantDrawer
      :open="assistOpen"
      :seed="assistSeed"
      :seed-action="assistAction"
      @close="assistOpen = false"
      @consumed-seed="assistSeed = ''"
      @consumed-action="assistAction = ''"
      @go="onAssistGo"
    />
    <!-- Global macOS administrator password dialog for privileged operations -->
    <AdminPasswordDialog />
  </div>
</template>

<script setup>
import { computed, nextTick, onMounted, onUnmounted, provide, ref, watch } from 'vue'
import {
  LayoutDashboard, HardDrive, FolderOpen, Share2, Users, Container, Layers,
  Package, Monitor, Server, Terminal, TerminalSquare, Network, Router, Bookmark,
  Wrench, Heart, Clock, FileText, Bell, Archive, Hammer, Blocks, Bot, Camera,
  Settings, ScrollText, ShieldCheck, CircleUser, Sparkles, BookOpen,
} from '@lucide/vue'
import { authState } from './lib/authState'
import { startVisibleInterval } from './lib/poll'
import { clearAdminPassword } from './lib/adminPassword'
import { APP_ERROR_EVENT } from './lib/appError'
import AdminPasswordDialog from './components/AdminPasswordDialog.vue'
import AssistantDrawer from './components/AssistantDrawer.vue'
import { useRoute, useRouter } from 'vue-router'
import { AUTH_LOST_EVENT, getAssistantCatalog, getPhotosHubStatus, getStatus, logoutAuth, putSettings } from './api/client'
import { ASSISTANT_EVENT, matchCatalog } from './lib/assistant'
import { injectI18n } from './i18n'
import { injectTheme } from './theme'
import { useDismissable } from './composables/useDismissable'

const route = useRoute()
const router = useRouter()
const { t, locale, locales, setLocale } = injectI18n()
const { theme, themes, setTheme } = injectTheme()

const toast = ref('')
const status = ref(null)
const photoHubOk = ref(false)
const menuOpen = ref(false)
const navPanel = ref(null)
const isNarrow = ref(false)
const offline = ref(!navigator.onLine)
let narrowMq = null

// Off-canvas links stay in the tab order unless the closed drawer is inert.
// Desktop keeps the inline nav interactive even while menuOpen is false.
const navInert = computed(() => isNarrow.value && !menuOpen.value)

function closeMenu() {
  menuOpen.value = false
}

function syncNarrow() {
  isNarrow.value = Boolean(narrowMq?.matches)
}

useDismissable(menuOpen, closeMenu, navPanel)
watch(() => route.path, closeMenu)
const ptrVisible = ref(false)
const ptrRefreshing = ref(false)
const showTop = ref(false)
const swUpdate = ref(false)
const cmdOpen = ref(false)
const cmdQuery = ref('')
const cmdIdx = ref(0)
const cmdInput = ref(null)
const cmdPanel = ref(null)
const assistOpen = ref(false)
const assistSeed = ref('')
const assistAction = ref('')
const assistCatalog = ref([])
const canAssist = computed(() => authState.canManage)
let toastTimer = null
let poll = null
let ptrStartY = 0
let ptrActive = false

function showToast(msg) {
  toast.value = msg
  clearTimeout(toastTimer)
  // Long error messages (translated text + the tool's stderr tail) need longer
  // to read than a one-word confirmation.
  const dwell = Math.min(2800 + String(msg).length * 35, 9000)
  toastTimer = setTimeout(() => { toast.value = '' }, dwell)
}

//: Callers mark failures with a leading ❌ / ⚠.  A failure has to interrupt the
//: screen reader (assertive); a success confirmation must not (polite), or every
//: routine action talks over whatever the user is reading.
const toastIsError = computed(() => /^\s*(?:\u274c|\u26a0)/.test(toast.value))
provide('toast', showToast)
provide('t', t)

const counts = computed(() => status.value?.counts)
const engineUp = computed(() => status.value?.engine_up)
const engineClass = computed(() => (engineUp.value ? 'ok' : 'down'))

/**
 * Six top-level groups keep the desktop header on one line. Applications and
 * services owns every runnable workload: containers, stacks, VMs, native
 * services, Homebrew packages, and catalog applications.
 */
const NAV_ADMIN = [
  { to: '/', labelKey: 'nav.dashboard', exact: true, icon: LayoutDashboard },
  {
    // Array + the things you do *to* stored data: browse, share, own.
    to: '/main',
    labelKey: 'nav.storage',
    match: ['/main', '/storage', '/pool', '/files', '/shares', '/users'],
    icon: HardDrive,
    children: [
      { to: '/main', labelKey: 'nav.main', match: ['/main', '/storage'], icon: HardDrive },
      { to: '/pool', labelKey: 'nav.pool', icon: Layers },
      { to: '/files', labelKey: 'nav.files', icon: FolderOpen },
      { to: '/shares', labelKey: 'nav.shares', icon: Share2 },
      { to: '/users', labelKey: 'nav.users', icon: Users },
    ],
  },
  {
    // One group for everything runnable keeps the top bar compact and predictable.
    to: '/services',
    labelKey: 'nav.app_services',
    match: ['/services', '/containers', '/compose', '/vms', '/brew', '/apps', '/ollama'],
    icon: Package,
    children: [
      { to: '/services', labelKey: 'nav.sub_all_services', exact: true, icon: Server },
      { to: '/containers', labelKey: 'nav.sub_containers', exact: true, icon: Container },
      { to: '/compose', labelKey: 'nav.compose', icon: Layers },
      { to: '/vms', labelKey: 'nav.vms', icon: Monitor },
      { to: '/apps', labelKey: 'nav.apps', icon: Package },
      { to: '/brew', labelKey: 'nav.brew', icon: Terminal },
      { to: '/ollama', labelKey: 'nav.ollama', icon: Bot },
    ],
  },
  {
    to: '/network',
    labelKey: 'nav.network',
    match: ['/network', '/gateway', '/wireguard', '/bookmarks'],
    icon: Network,
    children: [
      { to: '/network', labelKey: 'nav.sub_interfaces', exact: true, icon: Network },
      { to: '/gateway', labelKey: 'nav.gateway', icon: Router },
      { to: '/wireguard', labelKey: 'nav.wireguard', icon: ShieldCheck },
      { to: '/bookmarks', labelKey: 'nav.bookmarks', icon: Bookmark },
    ],
  },
  {
    to: '/tools',
    labelKey: 'nav.tools',
    match: [
      '/tools', '/terminal', '/health', '/scheduler', '/logs',
      '/alerts', '/audit', '/backups', '/maintenance', '/photoshub', '/modules',
    ],
    icon: Wrench,
    children: [
      { to: '/tools', labelKey: 'nav.sub_diag', exact: true, icon: Wrench },
      { to: '/terminal', labelKey: 'nav.terminal', icon: TerminalSquare },
      { to: '/health', labelKey: 'nav.health', icon: Heart },
      { to: '/scheduler', labelKey: 'nav.scheduler', icon: Clock },
      { to: '/logs', labelKey: 'nav.logs', icon: FileText },
      { to: '/alerts', labelKey: 'nav.alerts', icon: Bell },
      { to: '/audit', labelKey: 'nav.audit', icon: ScrollText },
      { to: '/backups', labelKey: 'nav.backups', icon: Archive },
      { to: '/maintenance', labelKey: 'nav.maintenance', icon: Hammer },
      { to: '/photoshub', labelKey: 'nav.photoshub', icon: Camera },
      { to: '/modules', labelKey: 'nav.modules', icon: Blocks },
    ],
  },
  { to: '/settings', labelKey: 'nav.settings', icon: Settings },
]

/**
 * A member session reaches exactly the read surface the backend allows it
 * (dashboard/services, filtered per account) plus its own account page.
 * Rendering the admin groups would only produce 403 toasts on every click.
 */
const NAV_MEMBER = [
  { to: '/', labelKey: 'nav.dashboard', exact: true, icon: LayoutDashboard },
  { to: '/services', labelKey: 'nav.app_services', match: ['/services'], icon: Package },
  { to: '/account', labelKey: 'nav.account', icon: CircleUser },
]

// The router guard refreshes authState on every navigation, so this flips as
// soon as a member signs in (or an admin signs back in).
const nav = computed(() => {
  const groups = authState.authenticated && authState.role === 'member' ? NAV_MEMBER : NAV_ADMIN
  if (photoHubOk.value) return groups
  return groups.map((item) => {
    if (!item.children?.some((c) => c.to === '/photoshub')) return item
    return {
      ...item,
      children: item.children.filter((c) => c.to !== '/photoshub'),
    }
  })
})

const activeGroup = computed(() => {
  const path = route.path
  for (const item of nav.value) {
    if (item.exact && path === item.to) return item
    if (item.match && item.match.some(m => path === m || path.startsWith(m + '/'))) return item
    if (!item.exact && !item.match && (path === item.to || path.startsWith(item.to + '/'))) return item
  }
  return null
})

const activeChildren = computed(() => activeGroup.value?.children || [])

function isActive(item) {
  const path = route.path
  if (item.exact) return path === item.to
  if (item.match) return item.match.some(m => path === m || path.startsWith(m + '/'))
  return path === item.to || path.startsWith(item.to + '/')
}

function isChildActive(c) {
  const path = route.path
  if (c.exact) return path === c.to
  // A child may own several routes (e.g. Array covers /main and /storage), so
  // honour `match` here too — otherwise /storage highlights nothing.
  if (c.match) return c.match.some(m => path === m || path.startsWith(m + '/'))
  return path === c.to || path.startsWith(c.to + '/')
}

async function onLocale(ev) {
  const id = ev.target.value
  if (await setLocale(id)) {
    putSettings({ ui: { locale: id } }).catch(() => {})
  }
}

function onTheme(ev) {
  setTheme(ev.target.value)
  putSettings({ ui: { theme: ev.target.value } }).catch(() => {})
  showToast(t('theme.applied'))
}

async function logout() {
  try { await logoutAuth() } catch {}
  // A cached macOS administrator password belongs to the signed-in session.
  clearAdminPassword()
  status.value = null
  router.replace('/login')
}

// client.js already latches the dispatch, so this fires once per session loss.
// Deliberately no second latch here: a local flag would never reset after the
// user signs back in, silently swallowing every later session expiry.
function onAuthLost() {
  if (route.meta.authPage) return
  status.value = null
  stopPoll()
  showToast(t('err.session_expired'))
  // Login.vue already honours ?next=, so hand the current page over that way:
  // it survives a manual reload of /login, unlike sessionStorage.
  const next = route.fullPath && route.fullPath !== '/' ? route.fullPath : undefined
  router.replace(next ? { path: '/login', query: { next } } : '/login')
}

// Uncaught render errors and unhandled rejections, reported by the global
// handlers main.js installs (lib/appError.js). The leading ⚠ marks the toast
// as an error so the screen reader announces it assertively.
function onAppError() {
  showToast('⚠ ' + t('err.page_error'))
}

async function refresh() {
  // `false` opts the sidebar poll into lib/poll.js's failure backoff: with the
  // panel down, the badge refresh slows from every 15s toward 90s instead of
  // hammering a host that is not answering.
  try { status.value = await getStatus() } catch { return false }
}

function probePhotoHub() {
  // Members (and the login shell) are not on the photoshub whitelist;
  // probing here would 403 on every landing the way the Dashboard ollama
  // chip used to.
  if (!authState.canManage) {
    photoHubOk.value = false
    return
  }
  getPhotosHubStatus()
    .then((j) => { photoHubOk.value = Boolean(j?.photoshub_ok) })
    .catch(() => { photoHubOk.value = false })
}

// The sidebar poll is torn down on session loss and restarted once the user is
// back on a real page.  Null the disposer on stop: keeping a spent disposer in
// `poll` made `poll != null` look like "already polling", so the badge stayed
// frozen until a manual reload.
function statusPollMs() {
  return status.value?.resource_mode === 'high' ? 15000 : 30000
}

function startPoll() {
  if (poll) return
  // Low: 30s under the 35s status TTL. High: 15s for a livelier badge.
  poll = startVisibleInterval(refresh, statusPollMs())
}

function stopPoll() {
  if (typeof poll === 'function') poll()
  poll = null
}

// App.vue is the root component, so it survives the trip to /login and back —
// nothing remounts it to restart the poll.  Drive it off the route instead:
// stop while the login page is showing, resume once a real page is active.
watch(canAssist, (ok) => {
  if (ok) loadAssistCatalog()
  else assistCatalog.value = []
})
watch(
  () => status.value?.resource_mode,
  (mode, prev) => {
    if (!mode || mode === prev) return
    if (mode !== 'high' && prev !== 'high') return
    stopPoll()
    if (route.meta.authPage !== true) startPoll()
  },
)
watch(
  () => route.meta.authPage === true,
  (onAuthPage) => {
    if (onAuthPage) {
      stopPoll()
    } else {
      refresh()
      probePhotoHub()
      startPoll()
    }
  },
)

onMounted(() => {
  if (typeof window.matchMedia === 'function') {
    narrowMq = window.matchMedia('(max-width: 640px)')
    syncNarrow()
    narrowMq.addEventListener('change', syncNarrow)
  }
  // Landing straight on /login means there is no session yet, so hitting
  // /api/status here only produces 401s.  The watcher above starts the poll as
  // soon as a real page is active.
  if (!route.meta.authPage) {
    refresh()
    probePhotoHub()
    startPoll()
  }
  window.addEventListener('online', () => { offline.value = false })
  window.addEventListener('offline', () => { offline.value = true })
  // Pull-to-refresh (mobile only)
  if ('ontouchstart' in window) {
    document.addEventListener('touchstart', ptrTouchStart, { passive: true })
    document.addEventListener('touchmove', ptrTouchMove, { passive: false })
    document.addEventListener('touchend', ptrTouchEnd, { passive: true })
  }
  // Back-to-top visibility
  window.addEventListener('scroll', onScroll, { passive: true })
  // SW update notification
  window.addEventListener('sw-update-ready', () => { swUpdate.value = true })
  // Cmd+K command palette
  window.addEventListener('keydown', onCmdKey)
  // Session died server-side: redirect instead of leaving pages frozen on stale
  // data (client.js dispatches this on any non-auth 401).
  window.addEventListener(AUTH_LOST_EVENT, onAuthLost)
  // Errors nothing else caught (Vue errorHandler / unhandledrejection).
  window.addEventListener(APP_ERROR_EVENT, onAppError)
  window.addEventListener(ASSISTANT_EVENT, onAssistEvent)
  loadAssistCatalog()
})
onUnmounted(() => {
  stopPoll()
  clearTimeout(toastTimer)
  if (narrowMq) {
    narrowMq.removeEventListener('change', syncNarrow)
    narrowMq = null
  }
  document.removeEventListener('touchstart', ptrTouchStart)
  document.removeEventListener('touchmove', ptrTouchMove)
  document.removeEventListener('touchend', ptrTouchEnd)
  window.removeEventListener('scroll', onScroll)
  window.removeEventListener('keydown', onCmdKey)
  window.removeEventListener(AUTH_LOST_EVENT, onAuthLost)
  window.removeEventListener(APP_ERROR_EVENT, onAppError)
  window.removeEventListener(ASSISTANT_EVENT, onAssistEvent)
})

function onScroll() {
  showTop.value = window.scrollY > 400
}
function scrollTop() {
  window.scrollTo({ top: 0, behavior: 'smooth' })
}
function applySwUpdate() {
  if (navigator.serviceWorker?.controller) {
    navigator.serviceWorker.ready.then((reg) => {
      reg.waiting?.postMessage('skipWaiting')
    })
  }
  window.location.reload()
}

/* Pull-to-refresh handlers */
function ptrTouchStart(e) {
  if (window.scrollY <= 0 && !ptrRefreshing.value) {
    ptrStartY = e.touches[0].clientY
    ptrActive = true
  }
}
function ptrTouchMove(e) {
  if (!ptrActive) return
  const dy = e.touches[0].clientY - ptrStartY
  if (dy > 60 && window.scrollY <= 0) {
    ptrVisible.value = true
    if (dy > 80) e.preventDefault()
  } else {
    ptrVisible.value = false
  }
}
async function ptrTouchEnd() {
  if (!ptrActive) return
  ptrActive = false
  if (ptrVisible.value && !ptrRefreshing.value) {
    ptrRefreshing.value = true
    await refresh()
    // Dispatch custom event so page-level polls can also refresh
    window.dispatchEvent(new CustomEvent('ptr-refresh'))
    setTimeout(() => {
      ptrRefreshing.value = false
      ptrVisible.value = false
    }, 600)
  } else {
    ptrVisible.value = false
  }
}

/* Command palette (Cmd+K) + assistant (Cmd+J) */
function onCmdKey(e) {
  if ((e.metaKey || e.ctrlKey) && (e.key === 'j' || e.key === 'J')) {
    if (!authState.canManage) return
    e.preventDefault()
    cmdOpen.value = false
    if (assistOpen.value) {
      assistOpen.value = false
    } else {
      openAssistant()
    }
    return
  }
  if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
    e.preventDefault()
    assistOpen.value = false
    cmdOpen.value = !cmdOpen.value
    cmdQuery.value = ''
    cmdIdx.value = 0
    if (cmdOpen.value) nextTick(() => cmdInput.value?.focus())
  }
}
const cmdResults = computed(() => {
  const q = cmdQuery.value.toLowerCase().trim()
  const items = nav.value.flatMap(n => n.children ? [n, ...n.children] : [n])
  if (!q) return items.slice(0, 8)
  const fromNav = items.filter(n => {
    const label = t(n.labelKey).toLowerCase()
    return label.includes(q) || n.to.includes(q)
  })
  const seen = new Set(fromNav.map((n) => n.to))
  const fromCatalog = matchCatalog(assistCatalog.value, q, 8)
    .filter((p) => !seen.has(p.path))
    .map((p) => ({ type: 'nav', to: p.path, title: p.title, labelKey: '' }))
  return [...fromNav, ...fromCatalog].slice(0, 8)
})
const cmdFlat = computed(() => {
  const items = cmdResults.value.map((n) => ({ type: 'nav', ...n }))
  const q = cmdQuery.value.trim()
  if (authState.canManage && q) {
    items.push({ type: 'ai', query: q, to: '__ai__' })
  }
  return items
})
function openAssistant(seed = '', action = '') {
  assistSeed.value = seed
  assistAction.value = action
  assistOpen.value = true
}
function onAssistEvent(event) {
  if (!authState.canManage) return
  const action = event.detail?.action || ''
  openAssistant(event.detail?.query || '', action)
}
function loadAssistCatalog() {
  if (!authState.canManage) {
    assistCatalog.value = []
    return
  }
  getAssistantCatalog(locale.value)
    .then((body) => { assistCatalog.value = body.panels || [] })
    .catch(() => { assistCatalog.value = [] })
}
function onAssistGo(path) {
  if (path) router.push(path)
}
function cmdGo(i) {
  const item = cmdFlat.value[i]
  if (!item) return
  cmdOpen.value = false
  if (item.type === 'ai') {
    openAssistant(item.query)
    return
  }
  router.push(item.to)
}

// Escape used to be bound to the search input alone, so it stopped working the
// moment focus moved off it, and Tab wandered into the page behind the overlay.
// The composable owns Escape at the document level, traps Tab inside the panel,
// and returns focus to whatever was focused before Cmd+K.
useDismissable(cmdOpen, () => { cmdOpen.value = false }, cmdPanel)
</script>
