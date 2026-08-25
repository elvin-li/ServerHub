/**
 * Guards the three-locale contract.
 *
 * The panel ships zh-CN / en / ja from plain object literals, so nothing at
 * build time notices a key that exists in one dictionary and not another — the
 * UI just renders the raw key path. These tests are the only thing standing
 * between an extraction pass and a half-translated page.
 */
import { describe, expect, it } from 'vitest'
import { readFileSync, readdirSync } from 'node:fs'
import { dirname, join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'
// Rollup ships vite's own parser, so this import can never drift from the
// syntax the build actually accepts.
import { parseAst } from 'rollup/parseAst'

import en from './en.js'
import ja from './ja.js'
import zhCN from './zh-CN.js'
import { FALLBACK_LOCALE, LOCALES, t, setLocale } from './index.js'

const HERE = dirname(fileURLToPath(import.meta.url))
const SRC = join(HERE, '..')

const DICTS = { 'zh-CN': zhCN, en, ja }

/** Flatten a nested dictionary into dotted key paths. */
function flatten(obj, prefix = '', out = new Map()) {
  for (const [key, value] of Object.entries(obj)) {
    const path = prefix ? `${prefix}.${key}` : key
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      flatten(value, path, out)
    } else {
      out.set(path, value)
    }
  }
  return out
}

function walk(dir, out = []) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name)
    if (entry.isDirectory()) walk(full, out)
    else if (/\.(vue|js)$/.test(entry.name) && !entry.name.endsWith('.test.js')) {
      out.push(full)
    }
  }
  return out
}

const SOURCES = walk(SRC).filter((p) => !p.startsWith(join(SRC, 'i18n')))

describe('locale dictionaries', () => {
  // Node 26 warns on startup about its experimental global localStorage unless
  // --localstorage-file is set. jsdom owns the storage the panel actually uses,
  // so the test workers disable the Node implementation. Assert the flag rather
  // than `globalThis.localStorage === window.localStorage`: jsdom satisfies that
  // identity either way, so it cannot catch the flag being dropped.
  it('runs test workers with Node web storage disabled', () => {
    expect(process.execArgv).toContain('--no-experimental-webstorage')
  })

  it('loads every dictionary on demand, the en fallback included', () => {
    // en.js used to be a static import and alone was ~half of the entry-chunk
    // budget enforced by vite.config.js; a reverted split would not fail any
    // behavioral test, only the build gate, so pin the loading shape here too.
    const entry = readFileSync(join(HERE, 'index.js'), 'utf8')
    expect(entry).not.toMatch(/import\s+\w+\s+from\s+['"]\.\/(?:en|zh-CN|ja)\.js['"]/)
    expect(entry).toContain("import('./en.js')")
    expect(entry).toContain("import('./zh-CN.js')")
    expect(entry).toContain("import('./ja.js')")
  })

  it('ship exactly the three advertised locales', () => {
    expect(LOCALES.map((l) => l.id).sort()).toEqual(['en', 'ja', 'zh-CN'])
    expect(Object.keys(DICTS).sort()).toEqual(['en', 'ja', 'zh-CN'])
    expect(DICTS[FALLBACK_LOCALE]).toBeDefined()
  })

  it('declare every key exactly once in each dictionary source', () => {
    // Runtime imports cannot see this class of merge damage: a duplicate key
    // in an object literal silently keeps the last value, so the flatten-based
    // assertions still pass while one translation shadows another. Parse the
    // source instead and reject any object level that names a key twice.
    for (const name of Object.keys(DICTS)) {
      const file = join(HERE, `${name}.js`)
      const src = readFileSync(file, 'utf8')
      const line = (offset) => src.slice(0, offset).split('\n').length
      const ast = parseAst(src)
      const root = ast.body.find((n) => n.type === 'ExportDefaultDeclaration')
      expect(root, `${name}.js has no default export`).toBeDefined()

      const problems = []
      const walk = (node, prefix) => {
        if (!node || node.type !== 'ObjectExpression') return
        const seen = new Map()
        for (const prop of node.properties) {
          if (prop.type !== 'Property' || prop.computed) {
            // Spreads and computed keys could smuggle in duplicates the walk
            // below cannot see, so the dictionaries simply do not allow them.
            problems.push(`${prefix || '<root>'} uses ${prop.type} at line ${line(prop.start)}`)
            continue
          }
          const key = prop.key.type === 'Identifier' ? prop.key.name : String(prop.key.value)
          const path = prefix ? `${prefix}.${key}` : key
          if (seen.has(key)) {
            problems.push(`${path} declared at lines ${seen.get(key)} and ${line(prop.start)}`)
          } else {
            seen.set(key, line(prop.start))
          }
          walk(prop.value, path)
        }
      }
      walk(root.declaration, '')
      expect(problems, `duplicate keys in ${name}.js`).toEqual([])
    }
  })

  it('have identical key sets across locales', () => {
    const base = [...flatten(zhCN).keys()].sort()
    for (const [name, dict] of Object.entries(DICTS)) {
      const keys = [...flatten(dict).keys()].sort()
      expect(keys, `${name}.js key set differs from zh-CN.js`).toEqual(base)
    }
  })

  it('define a non-empty string for every key', () => {
    for (const [name, dict] of Object.entries(DICTS)) {
      const bad = [...flatten(dict).entries()]
        .filter(([, v]) => typeof v !== 'string' || v.trim() === '')
        .map(([k]) => k)
      expect(bad, `empty or non-string values in ${name}.js`).toEqual([])
    }
  })

  it('keep placeholders consistent across locales', () => {
    const placeholders = (s) => [...String(s).matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort()
    const base = flatten(zhCN)
    for (const [name, dict] of Object.entries(DICTS)) {
      if (name === 'zh-CN') continue
      const other = flatten(dict)
      const mismatched = []
      for (const [key, value] of base) {
        const a = placeholders(value)
        const b = placeholders(other.get(key))
        if (a.join(',') !== b.join(',')) mismatched.push(key)
      }
      expect(mismatched, `placeholders differ in ${name}.js`).toEqual([])
    }
  })
})

describe('t() keys referenced by the app', () => {
  it('all resolve in every locale', () => {
    const referenced = new Set()
    for (const file of SOURCES) {
      const text = readFileSync(file, 'utf8')
      for (const m of text.matchAll(/\bt\(\s*['"]([\w.$-]+)['"]/g)) referenced.add(m[1])
      // Keys stored in data and only later fed to t(): nav/theme entries carry
      // labelKey fields, and groupLabels.js maps yaml group ids to i18n keys.
      // The plain t( scan cannot see these, so a renamed dictionary entry
      // would ship as a raw key path in the sidebar without this pass.
      for (const m of text.matchAll(/\blabelKey\s*:\s*['"]([\w.$-]+)['"]/g)) referenced.add(m[1])
    }
    const groupLabels = readFileSync(join(HERE, 'groupLabels.js'), 'utf8')
    for (const m of groupLabels.matchAll(/:\s*['"]([a-z][\w$-]*(?:\.[\w$-]+)+)['"]/g)) {
      referenced.add(m[1])
    }
    // The locale picker's own labels live in index.js, outside the scan above.
    for (const l of LOCALES) referenced.add(l.labelKey)
    // Sanity-check the scanner itself: a broken regex would make this vacuous.
    expect(referenced.size).toBeGreaterThan(100)

    for (const [name, dict] of Object.entries(DICTS)) {
      const defined = flatten(dict)
      const missing = [...referenced].filter((k) => !defined.has(k)).sort()
      expect(missing, `t() keys unresolved in ${name}.js`).toEqual([])
    }
  })
})

describe('t() lookup', () => {
  it('interpolates named placeholders', async () => {
    await setLocale('en')
    expect(t('services.confirm_bulk', { n: 3, action: 'restart' })).toContain('3')
  })

  it('returns the key itself when nothing defines it', async () => {
    await setLocale('en')
    expect(t('nope.not_a_real_key')).toBe('nope.not_a_real_key')
  })

  it('loads a non-fallback locale before switching to it', async () => {
    await setLocale('ja')
    expect(t('common.failed')).toBe(ja.common.failed)
  })
})

describe('views', () => {
  /**
   * Ratchet, not a clean-zero assertion. The remaining hits are Chinese inside
   * *logic*, not UI copy: a macOS service name matched by
   * `name.includes('屏幕共享')`, and two regexes matching localized NIC names
   * (`无线` / `有线`). Extracting those into the dictionaries would break the
   * matching they exist to do.
   *
   * (Was 5 while main.js's global errorHandler carried a hardcoded zh-CN toast
   * string; that copy now lives in the dictionaries as err.page_error.)
   *
   * This number may only go down.
   */
  const CJK_BUDGET = 3
  const CJK = /[一-鿿]/

  it('keep hardcoded CJK at or below the ratchet', () => {
    const offenders = []
    for (const file of SOURCES) {
      const lines = readFileSync(file, 'utf8').split('\n')
      lines.forEach((raw, i) => {
        const line = raw.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/, '')
        if (CJK.test(line)) offenders.push(`${relative(SRC, file)}:${i + 1}`)
      })
    }
    expect(
      offenders.length,
      `hardcoded CJK went up — extract it into the dictionaries:\n  ${offenders.join('\n  ')}`,
    ).toBeLessThanOrEqual(CJK_BUDGET)
  })
})
