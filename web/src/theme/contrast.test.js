/**
 * Muted ink has to stay legible on every surface each theme defines.
 *
 * `--sub` carries the 10.5-11px secondary copy: table sub-rows, hints, the
 * second line of a card.  It is the first thing to fail WCAG AA, and it has
 * failed twice already -- Glass shipped `#94a3b8` (4.04:1 on its buttons and
 * table heads), and the fix for that, `#a1b2c6`, still measured 4.07:1 on the
 * Shares managed-services grid, where a translucent card sits inside a
 * gridline inside another translucent card.  Both were found by eye, one
 * theme at a time, after they shipped.
 *
 * So the surfaces are enumerated rather than sampled, including the stacked
 * one: a theme whose panels are see-through composites its own card colour
 * over itself, and the result is lighter than any single token in the sheet.
 *
 * Only tokens this file can resolve to a concrete colour are checked --
 * `var()` and `color-mix()` chains are left to the comments that reason about
 * them in styles.css -- and the theme count is asserted so a parser that
 * stops matching cannot quietly pass.
 */
import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'

const CSS = readFileSync(resolve(__dirname, '../styles.css'), 'utf8')

/** #rgb / #rrggbb / #rrggbbaa / rgb() / rgba() / transparent, else null. */
function parseColor(raw) {
  const value = String(raw || '').trim()
  if (!value || value === 'transparent') return value === 'transparent' ? { r: 0, g: 0, b: 0, a: 0 } : null
  let m = value.match(/^#([0-9a-f]{3,8})$/i)
  if (m) {
    let hex = m[1]
    if (hex.length === 3) hex = [...hex].map((c) => c + c).join('')
    if (hex.length !== 6 && hex.length !== 8) return null
    const n = (i) => parseInt(hex.slice(i, i + 2), 16)
    return { r: n(0), g: n(2), b: n(4), a: hex.length === 8 ? n(6) / 255 : 1 }
  }
  m = value.match(/^rgba?\(([^)]+)\)$/i)
  if (m) {
    const p = m[1].split(',').map((x) => parseFloat(x))
    if (p.length < 3 || p.some((x) => Number.isNaN(x))) return null
    return { r: p[0], g: p[1], b: p[2], a: p.length > 3 ? p[3] : 1 }
  }
  return null
}

const over = (fg, bg) => ({
  r: fg.r * fg.a + bg.r * (1 - fg.a),
  g: fg.g * fg.a + bg.g * (1 - fg.a),
  b: fg.b * fg.a + bg.b * (1 - fg.a),
  a: 1,
})

function luminance({ r, g, b }) {
  const lin = (v) => {
    const c = v / 255
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4
  }
  return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b)
}

function contrast(ink, surface) {
  const front = over(ink, surface)
  const [hi, lo] = [luminance(front), luminance(surface)].sort((a, b) => b - a)
  return (hi + 0.05) / (lo + 0.05)
}

/**
 * `{ label -> { var -> value } }`, one entry per theme *block*.
 *
 * A theme named twice -- `system` has a `prefers-color-scheme: dark` override
 * -- becomes two entries, because the override is a second palette rather
 * than an edit to the first.  Later blocks inherit the first block for their
 * own name, matching the cascade.
 */
function themeBlocks() {
  const themes = new Map()
  const seen = new Map()
  // Leaf rule bodies only: no declaration block in this sheet nests braces.
  for (const [, selector, body] of CSS.matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
    if (!/--bg\s*:/.test(body)) continue
    const names = [...selector.matchAll(/\[data-theme="([\w-]+)"\]/g)].map((m) => m[1])
    if (!names.length) continue
    const vars = {}
    for (const [, name, value] of body.matchAll(/(--[\w-]+)\s*:\s*([^;]+);/g)) {
      vars[name] = value.trim()
    }
    for (const name of names) {
      const nth = (seen.get(name) || 0) + 1
      seen.set(name, nth)
      const base = nth === 1 ? {} : themes.get(name) || {}
      themes.set(nth === 1 ? name : `${name} (override ${nth})`, { ...base, ...vars })
    }
  }
  return themes
}

/**
 * Every surface `--sub` can land on, composited down to an opaque colour.
 *
 * `nested card` is the Shares managed-services shape: a translucent card, on
 * the gridline colour used as a grid background, on another translucent card.
 */
function surfaces(vars) {
  const paper = { r: 255, g: 255, b: 255, a: 1 }
  const get = (name) => parseColor(vars[name])
  const bg = get('--bg')
  if (!bg) return {}
  const page = over(bg, paper)
  const out = { '--bg': page }
  const card = get('--card')
  if (card) {
    const onCard = over(card, page)
    out['--card'] = onCard
    for (const name of ['--table-head', '--table-alt', '--table-row']) {
      const c = get(name)
      if (c) out[`${name} on --card`] = over(c, onCard)
    }
    const line = get('--line')
    if (line) {
      // The Shares managed-services shape: card, on the gridline colour used
      // as a grid background, on another card.
      out['nested card'] = over(card, over(line, onCard))
    }
  }
  return out
}

/**
 * `--btn` is deliberately not in the list above.
 *
 * It is the lightest fill in every dark theme, and raw `--sub` on it is
 * 3.95:1 in macOS dark.  Rather than darken the muted ink everywhere for the
 * sake of two 10px chips, `styles.css` mixes it toward `--txt` at those two
 * call sites (`.badge`, `.chip-sig`).  So the pair to measure here is the
 * mixed tone, not the token -- and measuring it is the point, because
 * `.chip-sig` shipped without the mix and nobody noticed.
 */
const BADGE_MIX = 0.7

function mix(a, b, weight) {
  return {
    r: a.r * weight + b.r * (1 - weight),
    g: a.g * weight + b.g * (1 - weight),
    b: a.b * weight + b.b * (1 - weight),
    a: 1,
  }
}

//: WCAG AA for body text.  The muted copy this guards is 10.5-11px, so the
//: large-text exemption never applies to it.
const AA = 4.5

describe('theme contrast', () => {
  const themes = themeBlocks()

  it('finds every palette in the sheet', () => {
    // Guards the parser: a regex that stopped matching would make the case
    // below pass without measuring anything.
    expect([...themes.keys()].sort()).toEqual([
      'docker', 'glass', 'macos', 'macos-dark', 'mono', 'nord', 'omv',
      'system', 'system (override 2)', 'unraid', 'unraid-dark',
    ])
  })

  it('keeps muted and body ink above AA on every surface', () => {
    const offenders = []
    let checked = 0
    for (const [theme, vars] of themes) {
      for (const inkName of ['--sub', '--txt']) {
        const ink = parseColor(vars[inkName])
        if (!ink) continue
        for (const [surfaceName, surface] of Object.entries(surfaces(vars))) {
          checked += 1
          const ratio = contrast(ink, surface)
          if (ratio < AA) {
            offenders.push(
              `${theme} ${inkName} ${vars[inkName]} on ${surfaceName}: ${ratio.toFixed(2)}:1`,
            )
          }
        }
      }
    }
    expect(checked).toBeGreaterThan(100)
    expect(offenders, 'secondary copy below 4.5:1 is unreadable, not subtle').toEqual([])
  })

  it('keeps the badge/chip tone above AA on the button fill it rides on', () => {
    const offenders = []
    for (const [theme, vars] of themes) {
      const sub = parseColor(vars['--sub'])
      const txt = parseColor(vars['--txt'])
      const bg = parseColor(vars['--bg'])
      const card = parseColor(vars['--card'])
      const btn = parseColor(vars['--btn'])
      if (!sub || !txt || !bg || !card || !btn) continue
      const surface = over(btn, over(card, over(bg, { r: 255, g: 255, b: 255, a: 1 })))
      const ratio = contrast(mix(sub, txt, BADGE_MIX), surface)
      if (ratio < AA) {
        offenders.push(`${theme} badge tone on --btn ${vars['--btn']}: ${ratio.toFixed(2)}:1`)
      }
    }
    expect(offenders).toEqual([])
  })

  it('would fail if a chip used raw --sub on --btn again', () => {
    // The guard above only means something if the mix is what saves it, so
    // pin that the unmixed pair really is below the floor somewhere.
    const raw = []
    for (const [theme, vars] of themes) {
      const sub = parseColor(vars['--sub'])
      const bg = parseColor(vars['--bg'])
      const card = parseColor(vars['--card'])
      const btn = parseColor(vars['--btn'])
      if (!sub || !bg || !card || !btn) continue
      const surface = over(btn, over(card, over(bg, { r: 255, g: 255, b: 255, a: 1 })))
      if (contrast(sub, surface) < AA) raw.push(theme)
    }
    expect(raw).toContain('macos-dark')
    expect(CSS).not.toMatch(/\.chip-sig\s*\{[^}]*\bcolor:\s*var\(--sub\)/)
  })
})
