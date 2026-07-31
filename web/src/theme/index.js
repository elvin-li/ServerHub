import { inject, ref } from 'vue'

const THEMES = [
  {
    id: 'system',
    labelKey: 'theme.system',
    swatches: ['#ff8c2f', '#1c1b1b', '#f2f2f2'],
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
const DENSITY_KEY = 'serverhub.density'

function read(key, fallback) {
  try {
    return localStorage.getItem(key) || fallback
  } catch {
    return fallback
  }
}

const theme = ref(read(THEME_KEY, 'system'))
const density = ref(read(DENSITY_KEY, 'compact'))

const THEME_COLORS = {
  unraid: '#f5f0e8', 'unraid-dark': '#1c1b1b', omv: '#f5f5f5',
  docker: '#f0f6fc', nord: '#2e3440', glass: '#1a1a2e', mono: '#ffffff',
}

// Which palettes are light. `mono` belongs here: its CSS is #fafafa on #111 with
// a #ffffff theme-color, so classifying it dark handed the page dark native
// dropdowns and scrollbars. Listing light themes explicitly (rather than
// treating dark as the fallback) keeps a new light palette from inheriting the
// wrong color-scheme by omission. Must stay in sync with the pre-paint
// bootstrap in index.html, which theme.test.js asserts.
const LIGHT_THEMES = ['unraid', 'omv', 'docker', 'mono']

function applyTheme(id) {
  const valid = THEMES.some(t => t.id === id) ? id : 'system'
  theme.value = valid
  try {
    localStorage.setItem(THEME_KEY, valid)
  } catch {}
  if (typeof document === 'undefined') return
  const root = document.documentElement
  root.setAttribute('data-theme', valid)
  // system theme: also set color-scheme for form controls
  if (valid === 'system') {
    root.removeAttribute('data-color-mode')
  } else if (LIGHT_THEMES.includes(valid)) {
    root.setAttribute('data-color-mode', 'light')
  } else {
    root.setAttribute('data-color-mode', 'dark')
  }
  // Update browser chrome / status bar color
  const meta = document.querySelector('meta[name="theme-color"]')
  if (meta && THEME_COLORS[valid]) meta.setAttribute('content', THEME_COLORS[valid])
}

function applyDensity(id) {
  const valid = DENSITIES.some(d => d.id === id) ? id : 'compact'
  density.value = valid
  try {
    localStorage.setItem(DENSITY_KEY, valid)
  } catch {}
  if (typeof document === 'undefined') return
  document.documentElement.setAttribute('data-density', valid)
}

function initTheme() {
  applyTheme(theme.value)
  applyDensity(density.value)
}

function useTheme() {
  return {
    theme,
    density,
    themes: THEMES,
    densities: DENSITIES,
    setTheme: applyTheme,
    setDensity: applyDensity,
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
