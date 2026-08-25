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
import { readFileSync, readdirSync } from 'node:fs'
import { resolve } from 'node:path'

// Comments are stripped before any declaration parsing: prose like "not
// against --card: --down-text is the label..." otherwise matches the
// declaration regex and swallows the real declaration that follows it.
const RAW_CSS = readFileSync(resolve(__dirname, '../styles.css'), 'utf8')
const CSS = RAW_CSS.replace(/\/\*[\s\S]*?\*\//g, '')

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
  // Tokens declared once on :root (the tint mixes) are inherited by every
  // theme; the *inputs* to those mixes resolve against each theme's own
  // palette, so the defaults are merged under every theme block.
  let rootVars = {}
  // Leaf rule bodies only: no declaration block in this sheet nests braces.
  for (const [, selector, body] of CSS.matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
    if (!/--bg\s*:/.test(body)) continue
    const vars = {}
    for (const [, name, value] of body.matchAll(/(--[\w-]+)\s*:\s*([^;]+);/g)) {
      vars[name] = value.trim()
    }
    if (selector.includes(':root')) rootVars = { ...rootVars, ...vars }
    const names = [...selector.matchAll(/\[data-theme="([\w-]+)"\]/g)].map((m) => m[1])
    if (!names.length) continue
    for (const name of names) {
      const nth = (seen.get(name) || 0) + 1
      seen.set(name, nth)
      const base = nth === 1 ? {} : themes.get(name) || {}
      themes.set(nth === 1 ? name : `${name} (override ${nth})`, { ...base, ...vars })
    }
  }
  for (const [name, vars] of themes) themes.set(name, { ...rootVars, ...vars })
  return themes
}

/**
 * A concrete colour for a token value that may chain through `var()` and
 * one-argument-percentage `color-mix(in srgb, A n%, B)` -- the only shapes
 * the tint tokens use.  Returns null for anything else, so a syntax this
 * cannot follow is skipped rather than mis-measured.
 */
function resolveColor(vars, value, depth = 0) {
  if (depth > 8) return null
  const v = String(value || '').trim()
  const direct = parseColor(v)
  if (direct) return direct
  let m = v.match(/^var\((--[\w-]+)\)$/)
  if (m) return resolveColor(vars, vars[m[1]], depth + 1)
  m = v.match(/^color-mix\(in srgb,\s*(.+?)\s+(\d+(?:\.\d+)?)%\s*,\s*(.+?)\)$/)
  if (m) {
    const a = resolveColor(vars, m[1], depth + 1)
    const b = resolveColor(vars, m[3], depth + 1)
    if (!a || !b) return null
    const w = parseFloat(m[2]) / 100
    // Premultiplied, as the spec interpolates: mixing toward `transparent`
    // keeps the colour and scales the alpha, it does not darken toward black.
    const alpha = a.a * w + b.a * (1 - w)
    if (alpha === 0) return { r: 0, g: 0, b: 0, a: 0 }
    return {
      r: (a.r * a.a * w + b.r * b.a * (1 - w)) / alpha,
      g: (a.g * a.a * w + b.g * b.a * (1 - w)) / alpha,
      b: (a.b * a.a * w + b.b * b.a * (1 - w)) / alpha,
      a: alpha,
    }
  }
  return null
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

/**
 * `[name, css]` for the base stylesheet and every `<style>` block in the
 * view and component trees -- the same set the token tests walk, because a
 * colour pairing that regresses does so in whichever sheet is handiest.
 */
function allSheets() {
  const sheets = [['styles.css', CSS]]
  for (const dir of ['views', 'components']) {
    const abs = resolve(__dirname, '..', dir)
    for (const file of readdirSync(abs)) {
      if (!file.endsWith('.vue')) continue
      const source = readFileSync(resolve(abs, file), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '')
      for (const [, style] of source.matchAll(/<style[^>]*>([\s\S]*?)<\/style>/g)) {
        sheets.push([`${dir}/${file}`, style])
      }
    }
  }
  return sheets
}

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

  it('keeps the status and accent text tints above AA where they land', () => {
    // --accent-text / --ok-text / --warn-text / --down-text exist because the
    // raw brand hues fail as text; this measures that the mixes actually
    // clear the floor with each theme's own inputs.  --down-text also rides
    // --btn (it is the label of every button.danger), so that surface is in
    // the list for it.
    const offenders = []
    let checked = 0
    for (const [theme, vars] of themes) {
      const paper = { r: 255, g: 255, b: 255, a: 1 }
      const bg = resolveColor(vars, vars['--bg'])
      const card = resolveColor(vars, vars['--card'])
      const btn = resolveColor(vars, vars['--btn'])
      if (!bg || !card) continue
      const page = over(bg, paper)
      const onCard = over(card, page)
      const spots = { '--bg': page, '--card': onCard }
      for (const inkName of ['--accent-text', '--ok-text', '--warn-text', '--down-text']) {
        const ink = resolveColor(vars, vars[inkName])
        if (!ink) continue
        const landings = { ...spots }
        if (inkName === '--down-text' && btn) landings['--btn'] = over(btn, onCard)
        for (const [surfaceName, surface] of Object.entries(landings)) {
          checked += 1
          const ratio = contrast(ink, surface)
          if (ratio < AA) {
            offenders.push(`${theme} ${inkName} on ${surfaceName}: ${ratio.toFixed(2)}:1`)
          }
        }
      }
      // The two composed pairs those tints feed: the filled primary button's
      // label, and the accent badge (tinted wash under tinted ink).
      const onAccent = resolveColor(vars, vars['--on-accent'])
      const fill = resolveColor(vars, vars['--accent-fill'])
      if (onAccent && fill) {
        // Over both spots: primary buttons sit on cards, but the skip-nav
        // link floats over the bare page.
        for (const [surfaceName, surface] of Object.entries(spots)) {
          checked += 1
          const ratio = contrast(onAccent, over(fill, surface))
          if (ratio < AA) {
            offenders.push(`${theme} --on-accent on --accent-fill over ${surfaceName}: ${ratio.toFixed(2)}:1`)
          }
        }
      }
      const wash = resolveColor(vars, vars['--accent-wash'])
      const onWash = resolveColor(vars, vars['--on-accent-wash'])
      if (wash && onWash) {
        for (const [surfaceName, surface] of Object.entries(spots)) {
          checked += 1
          const ratio = contrast(onWash, over(wash, surface))
          if (ratio < AA) {
            offenders.push(`${theme} --on-accent-wash on wash over ${surfaceName}: ${ratio.toFixed(2)}:1`)
          }
        }
      }
    }
    // 11 themes x (4 tints x 2+ surfaces + 3 composed pairs) -- a resolver
    // that stopped following color-mix would collapse this count.
    expect(checked).toBeGreaterThan(100)
    expect(offenders, 'a tint token that fails AA defeats its own purpose').toEqual([])
  })

  it('never uses the raw accent as text ink', () => {
    // The tints above only help where they are used.  Raw --accent as a text
    // colour is 2.3-4.0:1 on --card in most themes (Unraid orange: 2.32:1),
    // and it kept creeping back in -- the command palette's AI row, the
    // Services signature chips, the Shares sheet buttons all shipped with it.
    // Borders, fills, accent-color and icon strokes may keep the raw token;
    // `color:` declarations may not, except in selectors that only style svg
    // icons (non-text, so the 3:1 graphics floor applies, not 4.5:1).
    const offenders = []
    for (const [name, sheet] of allSheets()) {
      for (const [, selector, body] of sheet.matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
        if (!/(?:^|[^-\w])color\s*:\s*var\(--accent\)\s*(?:!important)?\s*(?:;|$)/.test(body)) continue
        // Selectors targeting svg elements colour an icon, not text.
        if (/(?:^|[\s>+~(])svg\b/.test(selector)) continue
        offenders.push(`${name}: ${selector.trim().split('\n').pop().trim()}`)
      }
    }
    expect(offenders, 'use --accent-text for ink; the raw accent is a fill colour').toEqual([])
  })

  it('never pairs a raw-accent fill with literal white ink', () => {
    // White on the raw accent is 2.32:1 on Unraid orange and 4.02:1 on macOS
    // system blue -- which is exactly why --accent-fill/--on-accent exist as
    // a pair.  The skip-nav link and the Shares icon wells both shipped with
    // `background: var(--accent); color: #fff` anyway, and looked fine in the
    // dark themes they were written against.  Pin the measurement first, so
    // the source scan below cannot outlive the problem it guards.
    const white = { r: 255, g: 255, b: 255, a: 1 }
    const paper = { r: 255, g: 255, b: 255, a: 1 }
    const failing = []
    for (const [theme, vars] of themes) {
      const accent = resolveColor(vars, vars['--accent'])
      if (!accent) continue
      if (contrast(white, over(accent, paper)) < AA) failing.push(theme)
    }
    expect(failing).toContain('unraid')
    expect(failing).toContain('macos')
    const offenders = []
    for (const [name, sheet] of allSheets()) {
      for (const [, selector, body] of sheet.matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
        const accentFill = /background(?:-color)?\s*:\s*var\(--accent\)\s*(?:!important)?\s*(?:;|$)/.test(body)
        const whiteInk = /(?:^|[^-\w])color\s*:\s*(?:#fff\b|#ffffff\b|white\b)/i.test(body)
        if (accentFill && whiteInk) {
          offenders.push(`${name}: ${selector.trim().split('\n').pop().trim()}`)
        }
      }
    }
    expect(offenders, 'a raw-accent fill takes var(--on-accent) ink via --accent-fill').toEqual([])
  })

  it('keeps the branded chip inks above AA on their own tints', () => {
    // Apps' kind chips pair a brand hue's tint with a brand-hue ink, outside
    // the --*-text token system, so the token measurements above never see
    // them. They shipped with literal inks darkened for light cards only
    // (#1a6fb0 / #b45309 / #7c4fe0): 1.7-3.0:1 on the dark themes, patched
    // for one chip by a per-theme override that also fired in *light* system
    // mode at 1.7:1 on white. The fix mixes each hue toward --txt like the
    // tokens do; this measures that the mixes clear AA on the chip's own
    // tint with every theme's own inputs.
    const apps = readFileSync(resolve(__dirname, '../views/Apps.vue'), 'utf8')
      .replace(/\/\*[\s\S]*?\*\//g, '')
    const chips = {}
    for (const name of ['chip-docker', 'chip-launchd', 'chip-remote', 'chip-feat', 'chip-native', 'chip-ok']) {
      const rule = apps.match(new RegExp(`\\.${name}\\s*\\{([^}]*)\\}`))
      const background = rule?.[1].match(/background:\s*([^;]+);/)
      const ink = rule?.[1].match(/(?:^|[^-\w])color:\s*([^;]+);/)
      if (background && ink) chips[name] = { background: background[1], ink: ink[1] }
    }
    // The Containers k8s badge is the same shape, spelled inline.
    const containers = readFileSync(resolve(__dirname, '../views/Containers.vue'), 'utf8')
    const k8s = containers.match(/style="background:([^;"]+);color:([^"]+)">k8s</)
    if (k8s) chips['k8s badge'] = { background: k8s[1], ink: k8s[2] }
    // Guards the parser: a rule that stops matching would pass vacuously.
    expect(Object.keys(chips).sort()).toEqual(
      ['chip-docker', 'chip-feat', 'chip-launchd', 'chip-native', 'chip-ok', 'chip-remote', 'k8s badge'],
    )

    const paper = { r: 255, g: 255, b: 255, a: 1 }
    const offenders = []
    let checked = 0
    for (const [theme, vars] of themes) {
      const bg = resolveColor(vars, vars['--bg'])
      const card = resolveColor(vars, vars['--card'])
      if (!bg || !card) continue
      const onCard = over(card, over(bg, paper))
      for (const [name, { background, ink }] of Object.entries(chips)) {
        const tint = resolveColor(vars, background)
        const front = resolveColor(vars, ink)
        if (!tint || !front) {
          offenders.push(`${theme} ${name}: unresolvable (${background} / ${ink})`)
          continue
        }
        checked += 1
        const ratio = contrast(front, over(tint, onCard))
        if (ratio < AA) offenders.push(`${theme} ${name}: ${ratio.toFixed(2)}:1`)
      }
    }
    expect(checked).toBeGreaterThan(70)
    expect(offenders, 'a chip ink below AA on its own tint is decoration, not a label').toEqual([])

    // The measurement only means something if the literals it replaced really
    // fail it: the old k8s ink on its own wash, on the default light card.
    const unraid = themes.get('unraid')
    const wash = resolveColor(unraid, 'color-mix(in srgb, #6366f1 20%, transparent)')
    const onCard = over(resolveColor(unraid, unraid['--card']), over(resolveColor(unraid, unraid['--bg']), paper))
    expect(contrast(parseColor('#818cf8'), over(wash, onCard))).toBeLessThan(AA)
  })

  it('never uses a raw status hue or the accent hover as text ink', () => {
    // Same reasoning as the raw-accent ban above, for the other fill hues:
    // --ok / --warn / --down are picked as fills and strokes and measure
    // 2.0-4.1:1 as text on most cards; --accent-hover is 2.7-4.2:1 in most
    // themes, which is exactly why --accent-text mixes it further. Each of
    // these crept back in as ink -- the Ollama chat error, the Backups rsync
    // note, the Apps detail link -- and each has a --*-text token that was
    // built for the job. Borders, fills and icon strokes keep the raw hues.
    const INK = /(?:^|[^-\w])color\s*:\s*var\(--(?:ok|warn|down|accent-hover)\s*[,)]/
    const offenders = []
    for (const [name, sheet] of allSheets()) {
      for (const [, selector, body] of sheet.matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
        if (!INK.test(body)) continue
        if (/(?:^|[\s>+~(])svg\b/.test(selector)) continue
        offenders.push(`${name}: ${selector.trim().split('\n').pop().trim()}`)
      }
    }
    // Inline template styles are the other place the same mistake lands
    // (the Backups and ScheduleJobForm warn notes shipped there).
    // Dynamic `:style` bindings are the third: the raw hue hides inside a JS
    // string (`{ color: cond ? 'var(--down)' : … }`), which the static scan
    // above never sees — the Dashboard volume percent and the WireGuard
    // keepalive stat both shipped through that hole.
    const BOUND_INK = /(?:^|[^-\w])color\s*:/
    const RAW_HUE_LITERAL = /'var\(--(?:ok|warn|down|accent-hover|accent)\)'/
    for (const dir of ['views', 'components']) {
      const abs = resolve(__dirname, '..', dir)
      for (const file of readdirSync(abs)) {
        if (!file.endsWith('.vue')) continue
        const source = readFileSync(resolve(abs, file), 'utf8')
        const template = source.slice(0, source.search(/<script\b/) >>> 0)
        for (const m of template.matchAll(/style="([^"]*)"/g)) {
          if (INK.test(m[1]) || /(?:^|[^-\w])color\s*:\s*var\(--accent\s*[,)]/.test(m[1])) {
            offenders.push(`${dir}/${file}: style="${m[1]}"`)
          }
        }
        for (const m of template.matchAll(/:style="([^"]*)"/g)) {
          if (BOUND_INK.test(m[1]) && RAW_HUE_LITERAL.test(m[1])) {
            offenders.push(`${dir}/${file}: :style="${m[1]}"`)
          }
        }
      }
    }
    expect(offenders, 'status hues are fills; their ink is the matching --*-text token').toEqual([])
  })

  it('keeps the PhotosHub originals ink on the -text tints', () => {
    // The binding scan above cannot follow `:style="{ color: originalsColor }"`
    // into the script, and a blanket ban on raw-hue string literals in
    // scripts would outlaw the chart stroke colours that legitimately use
    // them (Dashboard's LineChart series). So the one computed that feeds a
    // colour *ink* binding is pinned by name: it must return only the
    // AA-safe -text tints, never the raw fill hues it shipped with.
    const photoshub = readFileSync(resolve(__dirname, '../views/PhotosHub.vue'), 'utf8')
    const rule = photoshub.match(/const originalsColor = computed\(\(\) => \{([\s\S]*?)\n\}\)/)
    expect(rule, 'originalsColor computed').toBeTruthy()
    const returns = [...rule[1].matchAll(/return\s+'([^']+)'/g)].map((m) => m[1])
    expect(returns.length).toBeGreaterThan(2)
    for (const value of returns) {
      expect(value).toMatch(/^var\(--(?:ok|warn|down)-text\)$/)
    }
  })

  it('keeps the selected-row ink on --on-accent, not a literal', () => {
    // The macOS selected row paints --accent-fill under its text; the row
    // itself takes var(--on-accent), but the sub-line overrides (.sub,
    // .sub-id, .detail-cell, .name-text) shipped as literal #fff in three
    // sheets.  White happens to equal --on-accent in both macOS palettes
    // today, so nothing looked wrong -- but a literal silently detaches from
    // the fill/label pair the measurement above keeps AA-safe.
    const offenders = []
    let rules = 0
    for (const [name, sheet] of allSheets()) {
      for (const [, selector, body] of sheet.matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
        if (!selector.includes('.selected')) continue
        rules += 1
        if (/(?:^|[^-\w])color\s*:\s*(?:#[0-9a-f]{3,8}\b|white\b)/i.test(body)) {
          offenders.push(`${name}: ${selector.trim().split('\n').pop().trim()}`)
        }
      }
    }
    // Guards the scan: the selected-state rules live in styles.css,
    // Services.vue and Files.vue, so fewer than this means it stopped seeing.
    expect(rules).toBeGreaterThan(5)
    expect(offenders, 'selected-row ink rides var(--on-accent) with the --accent-fill under it').toEqual([])
  })
})
