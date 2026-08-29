import { computed, inject, ref } from 'vue'
import { asArray, asRecord } from '../lib/finite'

const MESSAGES = {}
const MESSAGE_LOADERS = {
  // English is code-split exactly like the other locales. Statically imported
  // it rendered ~110 KB into the entry chunk — nearly half of the first-paint
  // budget vite.config.js enforces — and every dictionary edit invalidated the
  // cached entry. t() still promises a *synchronous* English fallback for any
  // missing key, so initializeI18n() keeps the app from mounting until this
  // dictionary is resident: nothing renders while it is in flight, which is
  // what makes the split safe without weakening that contract.
  en: () => import('./en.js'),
  'zh-CN': () => import('./zh-CN.js'),
  ja: () => import('./ja.js'),
}
const MESSAGE_LOADS = new Map()

export const LOCALES = [
  { id: 'zh-CN', labelKey: 'lang.zhCN', native: '简体中文' },
  { id: 'en', labelKey: 'lang.en', native: 'English' },
  { id: 'ja', labelKey: 'lang.ja', native: '日本語' },
]

const STORAGE_KEY = 'serverhub.locale'

//: Used when the browser asks for a language we do not ship.  English, not
//: zh-CN: a German or French customer previously booted into a Chinese UI.
export const FALLBACK_LOCALE = 'en'

function isSupportedLocale(id) {
  return Boolean(MESSAGES[id] || MESSAGE_LOADERS[id])
}

function matchLocale(tag) {
  const low = String(tag || '').toLowerCase()
  if (!low) return null
  if (low.startsWith('zh')) return 'zh-CN'
  if (low.startsWith('ja')) return 'ja'
  if (low.startsWith('en')) return 'en'
  return null
}

function detectLocale() {
  try {
    const saved = localStorage.getItem(STORAGE_KEY)
    if (saved && isSupportedLocale(saved)) return saved
  } catch {}
  // Respect the whole preference list: a browser set to [de, en] should get
  // English rather than falling through on the first entry alone.
  const tags = typeof navigator === 'undefined'
    ? []
    : [...asArray(navigator.languages), navigator.language || '']
  for (const tag of tags) {
    const hit = matchLocale(tag)
    if (hit) return hit
  }
  return FALLBACK_LOCALE
}

async function loadMessages(id) {
  if (MESSAGES[id]) return MESSAGES[id]
  const loader = MESSAGE_LOADERS[id]
  if (!loader) return null

  let pending = MESSAGE_LOADS.get(id)
  if (!pending) {
    pending = loader()
      .then((module) => {
        const messages = module.default
        if (!messages || typeof messages !== 'object') {
          throw new TypeError(`Locale ${id} has no default message dictionary`)
        }
        MESSAGES[id] = messages
        return messages
      })
      .finally(() => MESSAGE_LOADS.delete(id))
    MESSAGE_LOADS.set(id, pending)
  }
  return pending
}

function getByPath(obj, path) {
  if (!obj || !path) return undefined
  const parts = path.split('.')
  let cur = obj
  for (const p of parts) {
    if (cur == null || typeof cur !== 'object') return undefined
    cur = cur[p]
  }
  return cur
}

function format(str, params) {
  if (!params || typeof str !== 'string') return str
  const rec = asRecord(params)
  return str.replace(/\{(\w+)\}/g, (_, k) =>
    rec[k] != null ? String(rec[k]) : `{${k}}`
  )
}

const locale = ref(detectLocale())
let localeRequest = 0

export function t(key, params) {
  const loc = locale.value
  let val = getByPath(MESSAGES[loc], key)
  // English is the only fallback.  Falling through to zh-CN (as this used to)
  // meant a single missing key rendered Chinese inside an otherwise English
  // page — the exact mixed-language symptom we are trying to eliminate.
  if (val == null && loc !== 'en') val = getByPath(MESSAGES.en, key)
  if (val == null) return key
  return format(val, params)
}

// Health checks ship stable machine codes (same registry as api_error in
// hub/errors.py) instead of prose, so the panel can translate them.
const ERR_CODE = /^[a-z0-9]+(?:\.[a-z0-9_]+)+$/

/** Translate an errors.py code ('area.code'); anything else passes through. */
function errText(v) {
  if (typeof v !== 'string' || !ERR_CODE.test(v)) return v
  const key = `err.${v}`
  const s = t(key)
  return s === key ? v : s
}

function applyDocumentLocale(id) {
  if (typeof document !== 'undefined') {
    document.documentElement.setAttribute('lang', id === 'zh-CN' ? 'zh-CN' : id)
  }
}

export async function setLocale(id) {
  if (!isSupportedLocale(id)) return false
  const request = ++localeRequest
  try {
    if (!await loadMessages(id)) return false
  } catch {
    return false
  }
  // If two dictionaries race, only the user's latest choice may win.
  if (request !== localeRequest) return false

  locale.value = id
  try {
    localStorage.setItem(STORAGE_KEY, id)
  } catch {}
  applyDocumentLocale(id)
  return true
}

export async function initializeI18n() {
  // Two dictionaries gate the first render: the selected one, so the page never
  // flashes untranslated keys, and English, so t()'s synchronous missing-key
  // fallback holds from the very first paint — the contract that let en.js be
  // split out of the entry chunk. Both fetches start immediately and run
  // concurrently with the landing-chunk warm-up and the router's auth probe
  // (see main.js), so neither adds a serial round trip before mount.
  //
  // A failed English fetch is deliberately non-fatal when the selected locale
  // did load: the page still renders fully translated, and the key-alignment
  // tests in i18n.test.js keep the fallback path unreachable in practice. If
  // neither dictionary loaded (typically a stale hashed chunk after a
  // redeploy), main.js calls recoverFromStaleChunk() and reloads the shell
  // once before showing the bilingual failure notice.
  const fallbackReady = loadMessages(FALLBACK_LOCALE).catch(() => null)
  const requested = locale.value
  const selectedOk = await setLocale(requested)
  await fallbackReady
  if (selectedOk) return true
  return setLocale(FALLBACK_LOCALE)
}

function useI18n() {
  // reactive locale for computed labels
  const loc = locale
  return {
    locale: loc,
    locales: LOCALES,
    t: (key, params) => {
      // touch locale so computed re-run
      void loc.value
      return t(key, params)
    },
    errText: (v) => {
      void loc.value
      return errText(v)
    },
    setLocale,
    /** computed helper: tRef('nav.dashboard') */
    tt: (key) => computed(() => {
      void loc.value
      return t(key)
    }),
  }
}

const I18N_KEY = Symbol('i18n')

export function provideI18n(app) {
  // initializeI18n() loads the selected and the fallback (English) dictionaries
  // before the app is created.
  applyDocumentLocale(locale.value)
  const api = {
    locale,
    locales: LOCALES,
    t: (key, params) => {
      void locale.value
      return t(key, params)
    },
    errText: (v) => {
      void locale.value
      return errText(v)
    },
    setLocale,
  }
  app.provide(I18N_KEY, api)
  app.config.globalProperties.$t = (key, params) => {
    void locale.value
    return t(key, params)
  }
  return api
}

export function injectI18n() {
  return inject(I18N_KEY, null) || useI18n()
}
