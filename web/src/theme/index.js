import { inject, ref } from 'vue'

import { asArray, asRecord, recGet } from '../lib/finite.js'

const THEMES = [
  {
    id: 'macos',
    labelKey: 'theme.macos',
    swatches: ['#007AFF', '#F5F5F7', '#FFFFFF'],
  },
  {
    id: 'macos-dark',
    labelKey: 'theme.macos_dark',
    swatches: ['#0A84FF', '#1C1C1E', '#2C2C2E'],
  },
  {
    id: 'unraid',
    labelKey: 'theme.unraid',
    swatches: ['#ff8c2f', '#1c1b1b', '#ffffff'],
  },
  {
    id: 'unraid-dark',
    labelKey: 'theme.unraid_dark',
    swatches: ['#ff8c2f', '#0a0a0a', '#1a1a1a'],
  },
  {
    id: 'omv',
    labelKey: 'theme.omv',
    swatches: ['#5cb85c', '#2d3e2d', '#f4faf4'],
  },
  {
    id: 'docker',
    labelKey: 'theme.docker',
    swatches: ['#2496ed', '#0d2137', '#f0f7fc'],
  },
  {
    id: 'nord',
    labelKey: 'theme.nord',
    swatches: ['#88c0d0', '#2e3440', '#3b4252'],
  },
  {
    id: 'glass',
    labelKey: 'theme.glass',
    swatches: ['#a78bfa', '#0f172a', '#1e293b'],
  },
  {
    id: 'mono',
    labelKey: 'theme.mono',
    swatches: ['#111111', '#000000', '#fafafa'],
  },
]

const DENSITIES = [
  { id: 'compact', labelKey: 'theme.density_compact' },
  { id: 'comfortable', labelKey: 'theme.density_comfortable' },
  { id: 'cozy', labelKey: 'theme.density_cozy' },
]

const THEME_KEY = 'serverhub.theme'
const THEME_FAMILY_KEY = 'serverhub.themeFamily'
const FOLLOW_KEY = 'serverhub.followSystem'
const DENSITY_KEY = 'serverhub.density'

/** Light id → dark twin for “Follow system”. Default family is macOS. */
const THEME_PAIRS = {
  macos: 'macos-dark',
  unraid: 'unraid-dark',
}

const THEME_PAIR_LIGHT = Object.fromEntries(
  Object.entries(asRecord(THEME_PAIRS)).map(([light, dark]) => [dark, light]),
)

function read(key, fallback) {
  try {
    return localStorage.getItem(key) || fallback
  } catch {
    return fallback
  }
}

function write(key, value) {
  try {
    localStorage.setItem(key, value)
  } catch {}
}

const theme = ref('macos')
const themeFamily = ref('macos')
const followSystem = ref(true)
const appliedTheme = ref('macos')
const density = ref('compact')

const THEME_COLORS = {
  unraid: '#f5f0e8', 'unraid-dark': '#1c1b1b', omv: '#f5f5f5',
  docker: '#f0f6fc', macos: '#F5F5F7', 'macos-dark': '#1C1C1E',
  nord: '#2e3440', glass: '#1a1a2e', mono: '#ffffff',
}

// Which palettes are light. `mono` belongs here: its CSS is #fafafa on #111 with
// a #ffffff theme-color, so classifying it dark handed the page dark native
// dropdowns and scrollbars. Listing light themes explicitly (rather than
// treating dark as the fallback) keeps a new light palette from inheriting the
// wrong color-scheme by omission. Must stay in sync with the pre-paint
// bootstrap in index.html, which theme.test.js asserts.
const LIGHT_THEMES = ['unraid', 'omv', 'docker', 'macos', 'mono']

let schemeMql = null
let schemeListener = null

function prefersDark() {
  if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') {
    return false
  }
  return window.matchMedia('(prefers-color-scheme: dark)').matches
}

function isCatalogueId(id) {
  return asArray(THEMES).some(t => recGet(t, 'id') === id)
}

function pairFamily(id) {
  if (recGet(THEME_PAIRS, id)) return id
  if (recGet(THEME_PAIR_LIGHT, id)) return THEME_PAIR_LIGHT[id]
  return null
}

function rememberFamily(id) {
  const family = pairFamily(id)
  if (!family) return
  themeFamily.value = family
  write(THEME_FAMILY_KEY, family)
}

function readFollowFlag(storedTheme) {
  const raw = read(FOLLOW_KEY, '')
  if (raw === '1') return true
  if (raw === '0') {
    // Legacy `theme=system` always meant follow-OS, even if the new flag is off.
    return storedTheme === 'system'
  }
  return !storedTheme || storedTheme === 'system'
}

/**
 * Resolve a picker / persisted id → concrete data-theme.
 * Legacy `system` (and unknown ids) follow the stored family.
 * With follow-system on, paired ids paint the OS twin; unpaired ids stay put.
 */
export function resolveThemeId(
  id,
  family = themeFamily.value,
  dark = prefersDark(),
  follow = followSystem.value,
) {
  if (id === 'system' || !isCatalogueId(id)) {
    const light = THEME_PAIRS[family] ? family : 'macos'
    return dark ? THEME_PAIRS[light] : light
  }
  if (!follow) return id
  const light = pairFamily(id)
  if (!light) return id
  return dark ? THEME_PAIRS[light] : light
}

function stopSchemeListener() {
  if (schemeMql && schemeListener) {
    if (typeof schemeMql.removeEventListener === 'function') {
      schemeMql.removeEventListener('change', schemeListener)
    } else if (typeof schemeMql.removeListener === 'function') {
      schemeMql.removeListener(schemeListener)
    }
  }
  schemeMql = null
  schemeListener = null
}

function startSchemeListener() {
  stopSchemeListener()
  if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return
  schemeMql = window.matchMedia('(prefers-color-scheme: dark)')
  schemeListener = () => {
    if (!followSystem.value) return
    paintTheme(theme.value)
  }
  if (typeof schemeMql.addEventListener === 'function') {
    schemeMql.addEventListener('change', schemeListener)
  } else if (typeof schemeMql.addListener === 'function') {
    schemeMql.addListener(schemeListener)
  }
}

function paintTheme(id) {
  const applied = resolveThemeId(id)
  appliedTheme.value = applied
  if (typeof document === 'undefined') return applied
  const root = document.documentElement
  root.setAttribute('data-theme', applied)
  root.setAttribute(
    'data-color-mode',
    asArray(LIGHT_THEMES).includes(applied) ? 'light' : 'dark',
  )
  const meta = document.querySelector('meta[name="theme-color"]')
  if (meta && recGet(THEME_COLORS, applied)) meta.setAttribute('content', recGet(THEME_COLORS, applied))
  return applied
}

function persistFollow(on) {
  followSystem.value = on
  write(FOLLOW_KEY, on ? '1' : '0')
}

function persistTheme(id) {
  theme.value = id
  write(THEME_KEY, id)
}

function applyTheme(id) {
  if (id === 'system') {
    persistFollow(true)
    const applied = resolveThemeId('system')
    persistTheme(applied)
    rememberFamily(applied)
    paintTheme(applied)
    startSchemeListener()
    return applied
  }
  const valid = isCatalogueId(id) ? id : 'macos'
  persistTheme(valid)
  rememberFamily(valid)
  paintTheme(valid)
  if (followSystem.value) startSchemeListener()
  else stopSchemeListener()
  return valid
}

function applyFollowSystem(on) {
  const next = !!on
  if (next) {
    persistFollow(true)
    paintTheme(theme.value)
    startSchemeListener()
    return
  }
  const frozen = appliedTheme.value || resolveThemeId(theme.value)
  persistFollow(false)
  persistTheme(frozen)
  rememberFamily(frozen)
  paintTheme(frozen)
  stopSchemeListener()
}

function applyDensity(id) {
  const valid = asArray(DENSITIES).some(d => recGet(d, 'id') === id) ? id : 'compact'
  density.value = valid
  write(DENSITY_KEY, valid)
  if (typeof document === 'undefined') return
  document.documentElement.setAttribute('data-density', valid)
}

function initTheme() {
  const storedTheme = read(THEME_KEY, '')
  const storedFamily = read(THEME_FAMILY_KEY, '')
  if (recGet(THEME_PAIRS, storedFamily)) {
    themeFamily.value = storedFamily
  } else if (storedTheme && storedTheme !== 'system') {
    rememberFamily(storedTheme)
    if (!pairFamily(storedTheme)) themeFamily.value = 'macos'
  } else {
    themeFamily.value = 'macos'
  }

  persistFollow(readFollowFlag(storedTheme))

  if (storedTheme === 'system' || !storedTheme || !isCatalogueId(storedTheme)) {
    const applied = resolveThemeId('system')
    persistTheme(applied)
    rememberFamily(applied)
    paintTheme(applied)
  } else {
    persistTheme(storedTheme)
    paintTheme(storedTheme)
  }

  if (followSystem.value) startSchemeListener()
  else stopSchemeListener()
  applyDensity(read(DENSITY_KEY, 'compact'))
}

function useTheme() {
  return {
    theme,
    appliedTheme,
    themeFamily,
    followSystem,
    density,
    themes: asArray(THEMES),
    densities: asArray(DENSITIES),
    setTheme: applyTheme,
    setFollowSystem: applyFollowSystem,
    setDensity: applyDensity,
    resolveThemeId,
  }
}

const THEME_KEY_INJECT = Symbol('theme')

export function provideTheme(app) {
  initTheme()
  const api = useTheme()
  app.provide(THEME_KEY_INJECT, api)
  return api
}

export function injectTheme() {
  return inject(THEME_KEY_INJECT, null) || useTheme()
}
