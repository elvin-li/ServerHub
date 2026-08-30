<template>
  <router-view v-if="route.meta.authPage" />
  <div v-else class="layout">
    <!-- WCAG 2.4.1: the nav is 18 tab stops wide and repeats on every page, so
         a keyboard user cannot reach the page body without walking all of it. -->
    <a class="skip-link" href="#main-content" @click="focusMain">{{ t('common.skip_to_content') }}</a>
    <header ref="topchromeEl" class="topchrome">
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
          <span class="pill down" v-if="finiteN(counts.down, 0)"><b>{{ finiteN(counts.down) }}</b></span>
          <span class="pill warn" v-if="finiteN(counts.warn, 0)"><b>{{ finiteN(counts.warn) }}</b></span>
        </div>
        <nav
          id="app-nav"
          ref="navPanel"
          class="top-nav"
          :class="{ open: menuOpen }"
          :aria-label="t('common.main_nav')"
          :inert="navInert"
          :aria-hidden="navInert"
        >
          <div class="nav-drawer-title">{{ t('brand') }}</div>
          <router-link
            v-for="item in asArray(nav)"
            :key="finiteText(asRecord(item).to)"
            :to="asRecord(item).to"
            :class="{ active: isActive(item) }"
            :aria-current="navCurrent(item)"
            @click="menuOpen = false"
          >
            <component :is="asRecord(item).icon" :size="15" />
            <span>{{ t(asRecord(item).labelKey) }}</span>
          </router-link>
          <div class="top-controls">
            <label class="nav-tool">
              <span class="nav-tool-label">{{ t('appearance.language') }}</span>
              <select :value="locale" @change="onLocale($event)" :title="t('appearance.language')">
                <option v-for="l in asArray(locales)" :key="finiteText(asRecord(l).id)" :value="asRecord(l).id">{{ finiteText(asRecord(l).native) }}</option>
              </select>
            </label>
            <label class="nav-tool">
              <span class="nav-tool-label">{{ t('theme.title') }}</span>
              <select
                :value="themeSelectValue"
                @change="onTheme($event)"
                :title="t('theme.title')"
                data-test="nav-theme"
              >
                <option value="system">{{ t('theme.system') }}</option>
                <option v-for="th in asArray(themes)" :key="finiteText(asRecord(th).id)" :value="asRecord(th).id">{{ t(asRecord(th).labelKey) }}</option>
              </select>
            </label>
            <button class="logout-btn" type="button" @click="logout">{{ t('auth.logout') }}</button>
          </div>
        </nav>
        <div class="top-status" v-if="counts">
          <span class="pill" :class="engineClass">{{ t('top.orbstack') }} {{ engineUp ? t('common.on') : t('common.off') }}</span>
          <span class="pill ok"><b>{{ finiteN(counts.ok) }}</b></span>
          <span class="pill warn" v-if="finiteN(counts.warn, 0)"><b>{{ finiteN(counts.warn) }}</b></span>
          <span class="pill" v-if="finiteN(counts.stopped, 0)" style="opacity:.75"><b>{{ finiteN(counts.stopped) }}</b></span>
          <span class="pill down" v-if="finiteN(counts.down, 0)"><b>{{ finiteN(counts.down) }}</b></span>
          <span class="pill" v-if="status?.system">{{ fmtLoad(status.system.load1) }}</span>
          <router-link v-if="counts.down || counts.warn" class="pill down" to="/services" :aria-label="t('common.issues')">!</router-link>
          <router-link
            v-if="authState.canManage && status?.panel_update?.update_available"
            class="pill warn"
            to="/tools?tab=updates"
          >{{ t('dashboard.open_updates') }}</router-link>
        </div>
      </div>
      <!-- Secondary nav: related pages merged under one top tab -->
      <div class="subchrome" v-if="asArray(activeChildren).length" role="navigation" :aria-label="t('common.section_nav')">
        <div class="subchrome-inner">
          <router-link
            v-for="c in asArray(activeChildren)"
            :key="c.to"
            :to="c.to"
            :class="{ active: isChildActive(c) }"
            :aria-current="isChildActive(c) ? 'page' : undefined"
            @click="menuOpen = false"
          >
            <component :is="c.icon" :size="13" />
            <span>{{ t(c.labelKey) }}</span>
          </router-link>
        </div>
      </div>
    </header>
    <!-- Mobile nav overlay: click-away scrim only, so hide it from AT the way
         every other dialog backdrop is hidden (Escape and the hamburger are
         the accessible ways out; the drawer itself is wired via useDismissable). -->
    <div class="nav-overlay" :class="{ show: menuOpen }" role="presentation" aria-hidden="true" @click="menuOpen = false"></div>
    <!-- Offline banner -->
    <div v-if="offline" class="offline-banner" role="alert">⚠ {{ t('common.offline_banner') }}</div>
    <main id="main-content" ref="mainEl" class="main" role="main" tabindex="-1">
      <router-view v-slot="{ Component }">
        <transition name="page-fade" mode="out-in">
          <component :is="Component" />
        </transition>
      </router-view>
    </main>
    <!-- Always-on live region, text gated with v-if: interpolating {{ toast }}
         when the timer clears it to '' announced a blank update. -->
    <div
      class="toast"
      :class="{ show: !!toast }"
      :role="toastIsError ? 'alert' : 'status'"
      :aria-live="toastIsError ? 'assertive' : 'polite'"
    ><span v-if="toast">{{ finiteText(toast) }}</span></div>
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
        <!--
          Combobox, not a bare text field: arrow keys move a highlight that
          lives on another element while focus stays here, so without
          aria-activedescendant a screen reader announces nothing at all as
          the reader walks the results.
        -->
        <input
          ref="cmdInput"
          v-model="cmdQuery"
          type="text"
          role="combobox"
          aria-expanded="true"
          aria-autocomplete="list"
          aria-controls="cmd-list"
          :aria-activedescendant="asArray(cmdFlat).length ? `cmd-opt-${cmdIdx}` : undefined"
          :aria-label="t('common.cmd_title')"
          :placeholder="t('common.cmd_ph')"
          @keydown.enter="cmdEnter"
          @keydown.up="cmdArrowUp"
          @keydown.down="cmdArrowDown"
        />
        <ul id="cmd-list" class="cmd-list" role="listbox" :aria-label="t('common.cmd_title')">
          <li
            v-for="(item, i) in asArray(cmdFlat)"
            :key="finiteText(asRecord(item).to)"
            :id="`cmd-opt-${i}`"
            role="option"
            :aria-selected="i === cmdIdx"
            :class="{ active: i === cmdIdx, 'cmd-ai': asRecord(item).type === 'ai' }"
            @click="cmdGo(i)"
            @mouseenter="cmdIdx = i"
          >
            <span>{{ asRecord(item).type === 'ai' ? t('assistant.ask_cmd', { q: finiteText(asRecord(item).query) }) : (finiteText(asRecord(item).title, '') || t(asRecord(item).labelKey)) }}</span>
            <kbd>{{ asRecord(item).type === 'ai' ? t('assistant.short') : finiteText(asRecord(item).to) }}</kbd>
          </li>
          <!-- role=presentation: a listbox may only own options, and "no
               matches" is a message about the list, not a choice in it. -->
          <li v-if="!asArray(cmdFlat).length" class="cmd-empty" role="presentation">{{ t('common.cmd_empty') }}</li>
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
  Settings, ScrollText, ShieldCheck, CircleUser, Sparkles, BookOpen, Palette, Zap,
} from '@lucide/vue'
import { authState, clearAuthState } from './lib/authState'
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
import { installTableWrapFocus } from './lib/tableWrapFocus'
import { asArray, asRecord, finiteN, finiteText } from './lib/finite'

const route = useRoute()
const router = useRouter()
const { t, locale, locales, setLocale } = injectI18n()
const { theme, themes, setTheme, followSystem, setFollowSystem } = injectTheme()
const themeSelectValue = computed(() => (followSystem?.value ? 'system' : (theme?.value ?? theme)))

const toast = ref('')
const status = ref(null)
const photoHubOk = ref(false)
const menuOpen = ref(false)
const navPanel = ref(null)
const topchromeEl = ref(null)
const mainEl = ref(null)
const isNarrow = ref(false)
const offline = ref(!navigator.onLine)
let narrowMq = null

// Off-canvas links stay in the tab order unless the closed drawer is inert.
// Desktop keeps the inline nav interactive even while menuOpen is false.
const navInert = computed(() => isNarrow.value && !menuOpen.value)

function closeMenu() {
  menuOpen.value = false
}

/**
 * Hand the keyboard to the page body without touching the URL.
 *
 * Letting the anchor navigate to `#main-content` would push a history entry
 * whose only difference is a hash, so Back would appear to do nothing; the
 * router also has one real hash target (`/#remote`) that a stray fragment
 * would fight with.  Focusing the region is what actually moves the tab
 * sequence, and `.main` already suppresses its focus ring, so nothing paints.
 */
function focusMain(event) {
  event?.preventDefault?.()
  const el = mainEl.value
  if (!el) return
  el.focus?.({ preventScroll: true })
  el.scrollIntoView?.({ block: 'start' })
}

function fmtLoad(v) {
  return finiteN(v, '')
}

function syncNarrow() {
  isNarrow.value = Boolean(narrowMq?.matches)
}

useDismissable(menuOpen, closeMenu, navPanel)
// WCAG 2.4.3: clicking a nav link swaps the page body but leaves focus on the
// link, so the next Tab walks the rest of the 18-stop nav instead of entering
// the new page — the skip link only helps on the first load. Moving focus to
// the main region (same target the skip link uses) puts the keyboard and the
// screen reader at the top of what just changed. Keyed to the path alone:
// query-tab switches (Settings ?tab=) swap content *inside* the page, and
// yanking focus off the tab the user just pressed would break arrowing
// through the rest. The router's scrollBehavior already scrolls to top.
watch(() => route.path, () => {
  closeMenu()
  nextTick(() => { mainEl.value?.focus?.({ preventScroll: true }) })
})

// Fixed header is out of flow; measure it (primary + optional subchrome, wrap,
// density) so .layout's padding-top matches. Skip 0-height (jsdom).
watch(topchromeEl, (el, _was, onCleanup) => {
  if (!el || typeof ResizeObserver !== 'function') return
  const apply = () => {
    const h = Math.ceil(el.getBoundingClientRect().height)
    if (h > 0) document.documentElement.style.setProperty('--topchrome-h', `${h}px`)
  }
  const ro = new ResizeObserver(apply)
  ro.observe(el)
  apply()
  onCleanup(() => {
    ro.disconnect()
    document.documentElement.style.removeProperty('--topchrome-h')
  })
}, { flush: 'post' })

// Scrollable .table-wrap containers become keyboard-reachable named regions
// the moment they render (WCAG 2.1.1 — see lib/tableWrapFocus.js). Installed
// once over the main region so every view, drawer, and modal table it hosts
// is covered without patching thirty templates.
watch(mainEl, (el, _was, onCleanup) => {
  if (!el || typeof MutationObserver !== 'function') return
  onCleanup(installTableWrapFocus(el))
}, { flush: 'post' })
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
let ptrTimer = null
let poll = null
let ptrStartY = 0
let ptrActive = false
let loadGeneration = 0

function stillOnShell(generation) {
  return generation === loadGeneration
}

function invalidateShellLoads() {
  loadGeneration += 1
  ptrRefreshing.value = false
  ptrVisible.value = false
  clearTimeout(ptrTimer)
}

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

const counts = computed(() => asRecord(asRecord(status.value).counts))
const engineUp = computed(() => asRecord(status.value).engine_up)
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
  {
    to: '/settings',
    labelKey: 'nav.settings',
    icon: Settings,
    children: [
      { to: '/settings?tab=appearance', labelKey: 'settings.tab_appearance', icon: Palette },
      { to: '/settings?tab=identity', labelKey: 'settings.tab_identity', icon: CircleUser },
      { to: '/settings?tab=datetime', labelKey: 'settings.tab_datetime', icon: Clock },
      { to: '/settings?tab=network', labelKey: 'settings.tab_network', icon: Network },
      { to: '/settings?tab=disk', labelKey: 'settings.tab_disk', icon: HardDrive },
      { to: '/settings?tab=power', labelKey: 'settings.tab_power', icon: Zap },
      { to: '/settings?tab=docker', labelKey: 'settings.tab_docker', icon: Container },
      { to: '/settings?tab=vms', labelKey: 'settings.tab_vms', icon: Monitor },
      { to: '/settings?tab=notify', labelKey: 'settings.tab_notify', icon: Bell },
      { to: '/settings?tab=shares', labelKey: 'settings.tab_shares', icon: Share2 },
      { to: '/settings?tab=scheduler', labelKey: 'settings.tab_scheduler', icon: Clock },
      { to: '/settings?tab=access', labelKey: 'settings.tab_access', icon: ShieldCheck },
      { to: '/settings?tab=advanced', labelKey: 'settings.tab_advanced', icon: Settings },
      { to: '/settings?tab=diagnostics', labelKey: 'settings.tab_diagnostics', icon: Heart },
      { to: '/settings?tab=panel', labelKey: 'settings.tab_panel', icon: Server },
    ],
  },
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
  return asArray(groups).map((item) => {
    const row = asRecord(item)
    if (!asArray(row.children).some((c) => asRecord(c).to === '/photoshub')) return item
    return {
      ...row,
      children: asArray(row.children).filter((c) => asRecord(c).to !== '/photoshub'),
    }
  })
})

const activeGroup = computed(() => {
  const path = route.path
  for (const item of asArray(nav.value)) {
    if (item.exact && path === item.to) return item
    if (item.match && asArray(item.match).some(m => path === m || path.startsWith(m + '/'))) return item
    if (!item.exact && !item.match && (path === item.to || path.startsWith(item.to + '/'))) return item
  }
  return null
})

const activeChildren = computed(() => asArray(activeGroup.value?.children))

function isActive(item) {
  const path = route.path
  if (item.exact) return path === item.to
  if (item.match) return asArray(item.match).some(m => path === m || path.startsWith(m + '/'))
  return path === item.to || path.startsWith(item.to + '/')
}

function navCurrent(item) {
  // The top-level highlight is ours (`isActive` spans a whole section), and
  // RouterLink's own aria-current only follows its exact match, so the two
  // disagreed in both directions: on /pool the highlighted Storage tab said
  // nothing at all, while on /storage and /settings?tab=network the group
  // and its child both claimed `page` -- announcing the reader as being on
  // two pages at once.  A group whose child is showing in the section nav is
  // an *ancestor* of the open page, so it takes `true` and leaves `page` to
  // the child.
  if (!isActive(item)) return undefined
  return asArray(item.children).some(isChildActive) ? 'true' : 'page'
}

function childPathAndTab(c) {
  const raw = typeof c.to === 'string' ? c.to : ''
  const qi = raw.indexOf('?')
  if (qi < 0) return { path: raw, tab: null }
  return { path: raw.slice(0, qi), tab: new URLSearchParams(raw.slice(qi + 1)).get('tab') }
}

function queryTabValue() {
  const raw = route.query?.tab
  const value = Array.isArray(raw) ? raw[0] : raw
  return typeof value === 'string' ? value : ''
}

function isChildActive(c) {
  const { path: childPath, tab: childTab } = childPathAndTab(c)
  // Query-tab children share one route (Settings). Only the matching ?tab=
  // is active; missing tab is the default category (appearance).
  if (childTab != null) {
    if (route.path !== childPath) return false
    const current = queryTabValue() || 'appearance'
    return current === childTab
  }
  const path = route.path
  if (c.exact) return path === c.to
  // A child may own several routes (e.g. Array covers /main and /storage), so
  // honour `match` here too — otherwise /storage highlights nothing.
  if (c.match) return c.match.some(m => path === m || path.startsWith(m + '/'))
  return path === c.to || path.startsWith(c.to + '/')
}

async function onLocale(ev) {
  const id = ev.target.value
  const generation = loadGeneration
  if (await setLocale(id)) {
    if (!stillOnShell(generation)) return
    putSettings({ ui: { locale: id } }).catch(() => {})
  }
}

function onTheme(ev) {
  const id = ev.target.value
  if (id === 'system') {
    setTheme('system')
    putSettings({ ui: { theme: 'system' } }).catch(() => {})
  } else {
    if (followSystem?.value && typeof setFollowSystem === 'function') setFollowSystem(false)
    setTheme(id)
    putSettings({ ui: { theme: id } }).catch(() => {})
  }
  showToast(t('theme.applied'))
}

async function logout() {
  stopPoll()
  invalidateShellLoads()
  const generation = loadGeneration
  try { await logoutAuth() } catch {}
  // Session loss or a later sign-in bumps generation; do not wipe that session.
  if (!stillOnShell(generation)) return
  // A cached macOS administrator password belongs to the signed-in session.
  clearAdminPassword()
  clearAuthState()
  status.value = null
  router.replace('/login')
}

// client.js already latches the dispatch, so this fires once per session loss.
// Deliberately no second latch here: a local flag would never reset after the
// user signs back in, silently swallowing every later session expiry.
function onAuthLost() {
  if (route.meta.authPage) return
  invalidateShellLoads()
  clearAuthState()
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
  const generation = loadGeneration
  try {
    const next = asRecord(await getStatus())
    if (!stillOnShell(generation)) return
    status.value = next
  } catch { return false }
}

function probePhotoHub() {
  // Members (and the login shell) are not on the photoshub whitelist;
  // probing here would 403 on every landing the way the Dashboard ollama
  // chip used to.
  if (!authState.canManage) {
    photoHubOk.value = false
    return
  }
  const generation = loadGeneration
  getPhotosHubStatus()
    .then((j) => {
      if (!stillOnShell(generation)) return
      photoHubOk.value = Boolean(asRecord(j).photoshub_ok)
    })
    .catch(() => { /* keep last answer: a 502 is not "not installed" */ })
}

// The sidebar poll is torn down on session loss and restarted once the user is
// back on a real page.  Null the disposer on stop: keeping a spent disposer in
// `poll` made `poll != null` look like "already polling", so the badge stayed
// frozen until a manual reload.
function statusPollMs() {
  return asRecord(status.value).resource_mode === 'high' ? 15000 : 30000
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
  () => asRecord(status.value).resource_mode,
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
      invalidateShellLoads()
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
  window.addEventListener('online', onOnline)
  window.addEventListener('offline', onOffline)
  // Pull-to-refresh (mobile only)
  if ('ontouchstart' in window) {
    document.addEventListener('touchstart', ptrTouchStart, { passive: true })
    document.addEventListener('touchmove', ptrTouchMove, { passive: false })
    document.addEventListener('touchend', ptrTouchEnd, { passive: true })
  }
  // Back-to-top visibility
  window.addEventListener('scroll', onScroll, { passive: true })
  // SW update notification
  window.addEventListener('sw-update-ready', onSwUpdateReady)
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
  invalidateShellLoads()
  stopPoll()
  clearTimeout(toastTimer)
  clearTimeout(ptrTimer)
  if (narrowMq) {
    narrowMq.removeEventListener('change', syncNarrow)
    narrowMq = null
  }
  document.removeEventListener('touchstart', ptrTouchStart)
  document.removeEventListener('touchmove', ptrTouchMove)
  document.removeEventListener('touchend', ptrTouchEnd)
  window.removeEventListener('online', onOnline)
  window.removeEventListener('offline', onOffline)
  window.removeEventListener('sw-update-ready', onSwUpdateReady)
  window.removeEventListener('scroll', onScroll)
  window.removeEventListener('keydown', onCmdKey)
  window.removeEventListener(AUTH_LOST_EVENT, onAuthLost)
  window.removeEventListener(APP_ERROR_EVENT, onAppError)
  window.removeEventListener(ASSISTANT_EVENT, onAssistEvent)
})

function onOnline() {
  offline.value = false
}
function onOffline() {
  offline.value = true
}
function onSwUpdateReady() {
  swUpdate.value = true
}
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
    const generation = loadGeneration
    ptrRefreshing.value = true
    await refresh()
    if (!stillOnShell(generation)) return
    // Dispatch custom event so page-level polls can also refresh
    window.dispatchEvent(new CustomEvent('ptr-refresh'))
    clearTimeout(ptrTimer)
    ptrTimer = setTimeout(() => {
      if (!stillOnShell(generation)) return
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
    if (cmdOpen.value) {
      const generation = loadGeneration
      nextTick(() => {
        if (!stillOnShell(generation) || !cmdOpen.value) return
        cmdInput.value?.focus()
      })
    }
  }
}
const cmdResults = computed(() => {
  const q = cmdQuery.value.toLowerCase().trim()
  const items = asArray(nav.value).flatMap(n => n.children ? [n, ...asArray(n.children)] : [n])
  const matched = q
    ? items.filter(n => t(n.labelKey).toLowerCase().includes(q) || n.to.includes(q))
    : items
  // Every group shares a destination with its first child -- Storage and
  // Array are both /main, Tools and Diagnostics are both /tools -- so the
  // flat list offered those pages twice: two rows out of only eight going to
  // the same place, keyed alike, which also let Vue reuse the wrong row when
  // the list changed underneath.  Matching runs first so both names stay
  // searchable and only the redundant second row is dropped.
  const seen = new Set()
  const fromNav = []
  for (const n of asArray(matched)) {
    if (seen.has(n.to)) continue
    seen.add(n.to)
    fromNav.push(n)
  }
  if (!q) return fromNav.slice(0, 8)
  const fromCatalog = matchCatalog(assistCatalog.value, q, 8)
    .filter((p) => !seen.has(asRecord(p).path))
    .map((p) => {
      const row = asRecord(p)
      return { type: 'nav', to: row.path, title: row.title, labelKey: '' }
    })
  return [...fromNav, ...fromCatalog].slice(0, 8)
})
const cmdFlat = computed(() => {
  const items = asArray(cmdResults.value).map((n) => ({ type: 'nav', ...n }))
  const q = cmdQuery.value.trim()
  if (authState.canManage && q) {
    items.push({ type: 'ai', query: q, to: '__ai__' })
  }
  return items
})
// Arrowing down and then narrowing the query used to strand the highlight
// past the end of the shortened list: no row looked selected, and Enter ran
// cmdGo() on an index that no longer existed, so the palette did nothing at
// all.  Only fires when the cursor is actually out of range, so a result
// list that grows underneath (the assistant catalogue arrives async) does
// not yank the reader back to the top.
watch(cmdFlat, (items) => {
  if (cmdIdx.value > asArray(items).length - 1) cmdIdx.value = 0
})

function openAssistant(seed = '', action = '') {
  assistSeed.value = seed
  assistAction.value = action
  assistOpen.value = true
}
function onAssistEvent(event) {
  if (!authState.canManage) return
  const detail = asRecord(event.detail)
  const action = finiteText(detail.action, '')
  openAssistant(finiteText(detail.query, ''), action)
}
function loadAssistCatalog() {
  if (!authState.canManage) {
    assistCatalog.value = []
    return
  }
  const generation = loadGeneration
  getAssistantCatalog(locale.value)
    .then((body) => {
      if (!stillOnShell(generation) || !authState.canManage) return
      assistCatalog.value = asArray(asRecord(body).panels)
    })
    .catch(() => {
      if (!stillOnShell(generation)) return
      assistCatalog.value = []
    })
}
function onAssistGo(path) {
  if (path) router.push(path)
}
function cmdGo(i) {
  const item = asArray(cmdFlat.value)[i]
  if (!item) return
  cmdOpen.value = false
  if (item.type === 'ai') {
    openAssistant(item.query)
    return
  }
  router.push(item.to)
}

/**
 * IME composition owns these keys first.  While composing Japanese or
 * Chinese, Enter commits the composed text and the arrows walk the
 * candidate list; acting on them here navigated away mid-word, and the
 * `.prevent` the arrows carried broke candidate selection outright.
 * keyCode 229 is the legacy signal some engines still send instead of
 * (or before) `isComposing`.
 */
function cmdComposing(e) {
  return Boolean(e.isComposing) || e.keyCode === 229
}
function cmdEnter(e) {
  if (cmdComposing(e)) return
  cmdGo(cmdIdx.value)
}
function cmdArrowUp(e) {
  if (cmdComposing(e)) return
  e.preventDefault()
  cmdIdx.value = Math.max(0, cmdIdx.value - 1)
}
function cmdArrowDown(e) {
  if (cmdComposing(e)) return
  e.preventDefault()
  cmdIdx.value = Math.min(asArray(cmdFlat.value).length - 1, cmdIdx.value + 1)
}

// Escape used to be bound to the search input alone, so it stopped working the
// moment focus moved off it, and Tab wandered into the page behind the overlay.
// The composable owns Escape at the document level, traps Tab inside the panel,
// and returns focus to whatever was focused before Cmd+K.
useDismissable(cmdOpen, () => { cmdOpen.value = false }, cmdPanel)
</script>
