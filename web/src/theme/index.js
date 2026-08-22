import { inject, ref } from 'vue'

const THEMES = [
  {
    id: 'system',
    labelKey: 'theme.system',
    swatches: ['#007AFF', '#F5F5F7', '#1C1C1E'],
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
const DENSITY_KEY = 'serverhub.density'

/** Light id → dark twin for “Follow system”. Default family is macOS. */
const THEME_PAIRS = {
  macos: 'macos-dark',
  unraid: 'unraid-dark',
}

const THEME_PAIR_LIGHT = Object.fromEntries(
  Object.entries(THEME_PAIRS).map(([light, dark]) => [dark, light]),
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

const theme = ref(read(THEME_KEY, 'system'))
const themeFamily = ref(read(THEME_FAMILY_KEY, 'macos'))
const density = ref(read(DENSITY_KEY, 'compact'))

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

function normalizeFamily(id) {
  if (THEME_PAIRS[id]) return id
  if (THEME_PAIR_LIGHT[id]) return THEME_PAIR_LIGHT[id]
  return 'macos'
}

function rememberFamily(id) {
  if (id === 'system') return
  const family = normalizeFamily(id)
  if (THEME_PAIRS[family]) {
    themeFamily.value = family
    write(THEME_FAMILY_KEY, family)
  }
}

/** Resolve picker id → concrete data-theme (system → macos / macos-dark). */
export function resolveThemeId(id, family = themeFamily.value, dark = prefersDark()) {
  const valid = THEMES.some(t => t.id === id) ? id : 'system'
  if (valid !== 'system') return valid
  const light = THEME_PAIRS[family] ? family : 'macos'
  const twin = THEME_PAIRS[light]
  return dark ? twin : light
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
    if (theme.value === 'system') paintTheme('system')
  }
  if (typeof schemeMql.addEventListener === 'function') {
    schemeMql.addEventListener('change', schemeListener)
  } else if (typeof schemeMql.addListener === 'function') {
    schemeMql.addListener(schemeListener)
  }
}

function paintTheme(id) {
  const valid = THEMES.some(t => t.id === id) ? id : 'system'
  const applied = resolveThemeId(valid)
  if (typeof document === 'undefined') return applied
  const root = document.documentElement
  root.setAttribute('data-theme', applied)
  if (valid === 'system') {
    // Follow OS: pin color-mode to the resolved twin so form controls match
    // the concrete macos / macos-dark (or unraid) palette we just applied.
    root.setAttribute(
      'data-color-mode',
      LIGHT_THEMES.includes(applied) ? 'light' : 'dark',
    )
  } else if (LIGHT_THEMES.includes(applied)) {
    root.setAttribute('data-color-mode', 'light')
  } else {
    root.setAttribute('data-color-mode', 'dark')
  }
  const meta = document.querySelector('meta[name="theme-color"]')
  if (meta && THEME_COLORS[applied]) meta.setAttribute('content', THEME_COLORS[applied])
  return applied
}

function applyTheme(id) {
  const valid = THEMES.some(t => t.id === id) ? id : 'system'
  theme.value = valid
  write(THEME_KEY, valid)
  rememberFamily(valid)
  paintTheme(valid)
  if (valid === 'system') startSchemeListener()
  else stopSchemeListener()
}

function applyDensity(id) {
  const valid = DENSITIES.some(d => d.id === id) ? id : 'compact'
  density.value = valid
  write(DENSITY_KEY, valid)
  if (typeof document === 'undefined') return
  document.documentElement.setAttribute('data-density', valid)
}

function initTheme() {
  const storedFamily = read(THEME_FAMILY_KEY, '')
  if (THEME_PAIRS[storedFamily]) {
    themeFamily.value = storedFamily
  } else if (theme.value !== 'system') {
    rememberFamily(theme.value)
  } else {
    themeFamily.value = 'macos'
  }
  applyTheme(theme.value)
  applyDensity(density.value)
}

function useTheme() {
  return {
    theme,
    themeFamily,
    density,
    themes: THEMES,
    densities: DENSITIES,
    setTheme: applyTheme,
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
