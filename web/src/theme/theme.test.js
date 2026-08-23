/**
 * Behavioral cover for theme + density application.
 *
 * This module is the only thing that decides three user-visible attributes on
 * <html>: data-theme (which palette the CSS uses), data-density (spacing scale)
 * and data-color-mode (which drives `color-scheme`, i.e. whether native
 * dropdowns, date pickers and scrollbars render light or dark).
 *
 * The color-mode half is duplicated by the inline bootstrap in index.html, which
 * runs before the bundle so the page does not flash the wrong control style. Two
 * copies of one classification is a standing invitation to drift, so the last
 * test here pins them to each other.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { createApp } from 'vue'

import { provideTheme, resolveThemeId } from './index.js'

const HERE = dirname(fileURLToPath(import.meta.url))
const INDEX_HTML = join(HERE, '..', '..', 'index.html')

const root = () => document.documentElement

/** The panel ships this meta tag; jsdom starts without it. */
function installThemeColorMeta() {
  const meta = document.createElement('meta')
  meta.setAttribute('name', 'theme-color')
  meta.setAttribute('content', '#000000')
  document.head.appendChild(meta)
  return meta
}

function stubPrefersDark(dark) {
  vi.stubGlobal('matchMedia', (query) => ({
    matches: query.includes('prefers-color-scheme: dark') ? dark : false,
    media: query,
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    addListener: vi.fn(),
    removeListener: vi.fn(),
  }))
}

describe('theme', () => {
  let api
  let meta

  beforeEach(() => {
    localStorage.clear()
    root().removeAttribute('data-theme')
    root().removeAttribute('data-color-mode')
    root().removeAttribute('data-density')
    document.head.querySelectorAll('meta[name="theme-color"]').forEach((m) => m.remove())
    meta = installThemeColorMeta()
    stubPrefersDark(false)
    // Go through the real provider main.js uses, rather than calling
    // injectTheme() with no active component (which warns and falls back).
    api = provideTheme(createApp({}))
  })

  afterEach(() => {
    localStorage.clear()
    vi.unstubAllGlobals()
  })

  describe('setTheme', () => {
    it('applies the requested theme to the document root', () => {
      api.setFollowSystem(false)
      api.setTheme('nord')
      expect(root().getAttribute('data-theme')).toBe('nord')
      expect(api.theme.value).toBe('nord')
    })

    it('persists the choice so a reload keeps it', () => {
      api.setFollowSystem(false)
      api.setTheme('docker')
      expect(localStorage.getItem('serverhub.theme')).toBe('docker')
    })

    it('falls back to macos for an unknown id', () => {
      api.setFollowSystem(false)
      api.setTheme('not-a-theme')
      // An unrecognised id must not reach the DOM: [data-theme="not-a-theme"]
      // matches no CSS block, so the page would render unstyled.
      expect(api.theme.value).toBe('macos')
      expect(localStorage.getItem('serverhub.theme')).toBe('macos')
      expect(root().getAttribute('data-theme')).toBe('macos')
    })

    it('migrates legacy system to follow-system and a concrete twin', () => {
      api.setTheme('system')
      expect(api.followSystem.value).toBe(true)
      expect(api.theme.value).toBe('macos')
      expect(root().getAttribute('data-theme')).toBe('macos')
      expect(root().getAttribute('data-color-mode')).toBe('light')
    })

    it('updates the browser chrome color for themes that define one', () => {
      api.setFollowSystem(false)
      api.setTheme('nord')
      expect(meta.getAttribute('content')).toBe('#2e3440')
    })

    it('updates chrome color for the resolved follow-system twin', () => {
      api.setTheme('system')
      expect(meta.getAttribute('content')).toBe('#F5F5F7')
    })

    it('still applies the theme when localStorage refuses to write', () => {
      const spy = vi
        .spyOn(Storage.prototype, 'setItem')
        .mockImplementation(() => {
          throw new Error('quota')
        })

      // Private browsing / full quota must not leave the page unstyled.
      expect(() => api.setTheme('glass')).not.toThrow()
      expect(root().getAttribute('data-theme')).toBe('glass')
      spy.mockRestore()
    })
  })

  describe('follow system', () => {
    it('defaults to follow-system on with the macOS pair', () => {
      expect(api.followSystem.value).toBe(true)
      expect(api.themeFamily.value).toBe('macos')
      expect(root().getAttribute('data-theme')).toBe('macos')
      expect(localStorage.getItem('serverhub.followSystem')).toBe('1')
    })

    it('maps the macOS family to macos-dark when OS is dark', () => {
      stubPrefersDark(true)
      api = provideTheme(createApp({}))
      expect(api.followSystem.value).toBe(true)
      expect(root().getAttribute('data-theme')).toBe('macos-dark')
      expect(root().getAttribute('data-color-mode')).toBe('dark')
      expect(localStorage.getItem('serverhub.followSystem')).toBe('1')
    })

    it('remembers the unraid family when picking a twin, then follows OS', () => {
      api.setTheme('unraid-dark')
      expect(localStorage.getItem('serverhub.themeFamily')).toBe('unraid')
      expect(api.appliedTheme.value).toBe('unraid')
      stubPrefersDark(true)
      api.setFollowSystem(true)
      expect(root().getAttribute('data-theme')).toBe('unraid-dark')
    })

    it('paints the OS twin when selecting either half of a pair while following', () => {
      api.setTheme('macos-dark')
      expect(api.themeFamily.value).toBe('macos')
      expect(root().getAttribute('data-theme')).toBe('macos')
      expect(api.appliedTheme.value).toBe('macos')
    })

    it('freezes the applied twin when follow-system is turned off', () => {
      stubPrefersDark(true)
      api = provideTheme(createApp({}))
      expect(root().getAttribute('data-theme')).toBe('macos-dark')
      api.setFollowSystem(false)
      expect(api.followSystem.value).toBe(false)
      expect(api.theme.value).toBe('macos-dark')
      expect(localStorage.getItem('serverhub.followSystem')).toBe('0')
      expect(localStorage.getItem('serverhub.theme')).toBe('macos-dark')
      expect(root().getAttribute('data-theme')).toBe('macos-dark')
    })

    it('does not re-paint OS changes when follow-system is off', () => {
      let listener = null
      vi.stubGlobal('matchMedia', (query) => ({
        matches: false,
        media: query,
        addEventListener: (_ev, fn) => { listener = fn },
        removeEventListener: vi.fn(),
        addListener: (fn) => { listener = fn },
        removeListener: vi.fn(),
      }))
      api = provideTheme(createApp({}))
      api.setFollowSystem(false)
      api.setTheme('macos')
      expect(root().getAttribute('data-theme')).toBe('macos')
      vi.stubGlobal('matchMedia', (query) => ({
        matches: query.includes('dark'),
        media: query,
        addEventListener: vi.fn(),
        removeEventListener: vi.fn(),
        addListener: vi.fn(),
        removeListener: vi.fn(),
      }))
      if (typeof listener === 'function') listener()
      expect(root().getAttribute('data-theme')).toBe('macos')
    })

    it('migrates persisted theme=system to follow-system and a concrete twin', () => {
      localStorage.setItem('serverhub.theme', 'system')
      localStorage.setItem('serverhub.themeFamily', 'unraid')
      stubPrefersDark(true)
      api = provideTheme(createApp({}))
      expect(api.followSystem.value).toBe(true)
      expect(api.theme.value).not.toBe('system')
      expect(root().getAttribute('data-theme')).toBe('unraid-dark')
      expect(api.appliedTheme.value).toBe('unraid-dark')
    })

    it('does not flip an unpaired theme when following system', () => {
      let listener = null
      vi.stubGlobal('matchMedia', (query) => ({
        matches: false,
        media: query,
        addEventListener: (_ev, fn) => { listener = fn },
        removeEventListener: vi.fn(),
        addListener: (fn) => { listener = fn },
        removeListener: vi.fn(),
      }))
      api = provideTheme(createApp({}))
      api.setTheme('nord')
      expect(root().getAttribute('data-theme')).toBe('nord')
      vi.stubGlobal('matchMedia', (query) => ({
        matches: query.includes('dark'),
        media: query,
        addEventListener: vi.fn(),
        removeEventListener: vi.fn(),
        addListener: vi.fn(),
        removeListener: vi.fn(),
      }))
      expect(listener).toBeTypeOf('function')
      listener()
      expect(root().getAttribute('data-theme')).toBe('nord')
      expect(api.theme.value).toBe('nord')
    })

    it('exports resolveThemeId for the bootstrap/tests', () => {
      expect(resolveThemeId('system', 'macos', false)).toBe('macos')
      expect(resolveThemeId('system', 'macos', true)).toBe('macos-dark')
      expect(resolveThemeId('system', 'unraid', true)).toBe('unraid-dark')
      expect(resolveThemeId('nord', 'macos', true, true)).toBe('nord')
      expect(resolveThemeId('macos', 'macos', true, true)).toBe('macos-dark')
      expect(resolveThemeId('macos', 'macos', true, false)).toBe('macos')
      expect(resolveThemeId('macos-dark', 'macos', false, true)).toBe('macos')
      expect(resolveThemeId('unraid-dark', 'unraid', true, true)).toBe('unraid-dark')
    })

    it('re-paints when prefers-color-scheme changes while following system', () => {
      localStorage.setItem('serverhub.themeFamily', 'macos')
      let listener = null
      vi.stubGlobal('matchMedia', (query) => ({
        matches: false,
        media: query,
        addEventListener: (_ev, fn) => { listener = fn },
        removeEventListener: vi.fn(),
        addListener: (fn) => { listener = fn },
        removeListener: vi.fn(),
      }))
      api = provideTheme(createApp({}))
      expect(api.followSystem.value).toBe(true)
      expect(root().getAttribute('data-theme')).toBe('macos')
      expect(listener).toBeTypeOf('function')
      vi.stubGlobal('matchMedia', (query) => ({
        matches: query.includes('dark'),
        media: query,
        addEventListener: vi.fn(),
        removeEventListener: vi.fn(),
        addListener: vi.fn(),
        removeListener: vi.fn(),
      }))
      listener()
      expect(root().getAttribute('data-theme')).toBe('macos-dark')
      expect(api.appliedTheme.value).toBe('macos-dark')
    })
  })

  describe('color-scheme classification', () => {
    // Each case is checked against the palette in styles.css: a theme whose
    // --bg is near-white is light, and native controls must match it.
    const LIGHT = ['unraid', 'omv', 'docker', 'macos', 'mono']
    const DARK = ['unraid-dark', 'nord', 'glass', 'macos-dark']

    beforeEach(() => {
      api.setFollowSystem(false)
    })

    for (const id of LIGHT) {
      it(`marks ${id} as a light theme`, () => {
        api.setTheme(id)
        expect(root().getAttribute('data-color-mode')).toBe('light')
      })
    }

    for (const id of DARK) {
      it(`marks ${id} as a dark theme`, () => {
        api.setTheme(id)
        expect(root().getAttribute('data-color-mode')).toBe('dark')
      })
    }

    it('agrees with the pre-paint bootstrap in index.html', () => {
      // index.html classifies themes before the bundle loads to avoid a flash of
      // wrongly-styled form controls. If the two lists disagree, the mode flips
      // on hydration and the flash is exactly what the inline script was added
      // to prevent, so read its arrays and hold this module to them.
      const html = readFileSync(INDEX_HTML, 'utf8')
      const listOf = (name) => {
        const m = html.match(new RegExp(`var ${name} = \\[([^\\]]*)\\]`))
        if (!m) throw new Error(`index.html no longer declares a ${name} list`)
        return m[1]
          .split(',')
          .map((s) => s.trim().replace(/^'|'$/g, ''))
          .filter(Boolean)
      }

      expect(listOf('dark').sort()).toEqual([...DARK].sort())
      expect(listOf('light').sort()).toEqual([...LIGHT].sort())
      expect(html).toContain("serverhub.themeFamily")
      expect(html).toContain("serverhub.followSystem")
      expect(html).toContain("prefers-color-scheme: dark")
      expect(html).toContain("t === 'system'")
    })
  })

  describe('setDensity', () => {
    it('applies the requested density to the document root', () => {
      api.setDensity('cozy')
      expect(root().getAttribute('data-density')).toBe('cozy')
      expect(api.density.value).toBe('cozy')
    })

    it('persists the choice so a reload keeps it', () => {
      api.setDensity('comfortable')
      expect(localStorage.getItem('serverhub.density')).toBe('comfortable')
    })

    it('falls back to compact for an unknown id', () => {
      api.setDensity('enormous')
      expect(root().getAttribute('data-density')).toBe('compact')
      expect(api.density.value).toBe('compact')
    })
  })

  describe('catalogue', () => {
    it('exposes every theme with a translation key and three swatches', () => {
      expect(api.themes.length).toBeGreaterThan(1)
      for (const th of api.themes) {
        expect(th.id).toBeTruthy()
        // Settings renders these directly; a missing key shows a raw path.
        expect(th.labelKey).toMatch(/^theme\./)
        expect(th.swatches).toHaveLength(3)
      }
    })

    it('offers exactly the three documented densities', () => {
      expect(api.densities.map((d) => d.id)).toEqual([
        'compact',
        'comfortable',
        'cozy',
      ])
    })

    it('lists macos light and dark first and omits system', () => {
      const ids = api.themes.map((t) => t.id)
      expect(ids.slice(0, 2)).toEqual(['macos', 'macos-dark'])
      expect(ids).not.toContain('system')
    })

    it('classifies every catalogue theme as light or dark', () => {
      // A theme added to the catalogue but not to either list would silently
      // inherit the previous theme's control styling.
      const classified = new Set([
        'unraid',
        'omv',
        'docker',
        'macos',
        'mono',
        'unraid-dark',
        'nord',
        'glass',
        'macos-dark',
      ])
      const ids = api.themes.map((t) => t.id)
      expect(ids.filter((id) => !classified.has(id))).toEqual([])
    })
  })

  describe('macos chrome solidity', () => {
    // Sticky macos chrome used to be rgba(--header) + desktop backdrop-filter
    // blur. Content frosted through the nav, and rubber-band at scrollTop 0
    // flashed the UA's default white html. overflow-x: clip on html+body also
    // created a second scrollport so sticky never latched. These contracts
    // keep the toolbar opaque, fixed, and the canvas painted.
    const css = readFileSync(join(HERE, '..', 'styles.css'), 'utf8')

    function palette(id) {
      const m = css.match(new RegExp(`\\[data-theme="${id}"\\] \\{([^}]+)\\}`))
      if (!m) throw new Error(`styles.css is missing the ${id} palette`)
      return m[1]
    }

    function headerToken(id) {
      const m = palette(id).match(/--header:\s*([^;]+);/)
      if (!m) throw new Error(`styles.css is missing --header in ${id}`)
      return m[1].trim()
    }

    it('keeps macos --header an opaque hex so sticky chrome cannot frost content', () => {
      expect(headerToken('macos')).toMatch(/^#[0-9A-Fa-f]{6}$/)
      expect(headerToken('macos-dark')).toMatch(/^#[0-9A-Fa-f]{6}$/)
    })

    it('does not apply a desktop blur to macos topchrome', () => {
      expect(css).toMatch(/\[data-theme="macos"\] \.topchrome[\s\S]*?backdrop-filter:\s*none/)
      expect(css).toMatch(/\[data-theme="macos-dark"\] \.topchrome[\s\S]*?backdrop-filter:\s*none/)
      expect(css).not.toMatch(/saturate\(180%\)\s*blur\(20px\)/)
    })

    it('paints html and body with --bg so overscroll is not UA white', () => {
      expect(css).toMatch(/html, body \{[\s\S]*?background:\s*var\(--bg\)/)
    })

    it('puts safe-area padding on the header that owns the fill', () => {
      expect(css).toMatch(/\.topchrome \{[\s\S]*?padding-top:\s*env\(safe-area-inset-top/)
    })

    it('pins topchrome so the toolbar cannot scroll away with the page', () => {
      expect(css).toMatch(/\.topchrome \{[\s\S]*?position:\s*fixed/)
      expect(css).toMatch(/\.topchrome \{[\s\S]*?top:\s*0/)
      expect(css).toMatch(/\.layout \{[\s\S]*?padding-top:\s*var\(--topchrome-h/)
    })

    it('does not paint the header fill with accent (no full-width blue bar)', () => {
      expect(css).not.toMatch(/\.topchrome[^{]*\{[^}]*background:\s*var\(--accent\)/)
      expect(css).not.toMatch(/\.topchrome-inner[^{]*\{[^}]*background:\s*var\(--accent\)/)
    })

    it('does not leave a phone-drawer left accent on desktop tabs', () => {
      expect(css).toMatch(
        /@media \(min-width: 641px\) \{[\s\S]*?\.top-nav a \{[\s\S]*?border-left:\s*none/,
      )
      expect(css).toMatch(
        /\[data-theme="macos"\] \.top-nav a,[\s\S]*?border-left:\s*none/,
      )
    })

    it('does not paint an accent focus ring on the page chrome', () => {
      // A :focus-visible ring on #app/.layout/.main/.top-nav is a full-height
      // accent stroke; the fixed header covers the top so only the left edge
      // shows. Shell nodes also keep outline always off.
      expect(css).toMatch(
        /html, body, #app, \.layout, \.main,\s*\.topchrome, \.topchrome-inner, \.subchrome, \.top-nav,\s*\.nav-overlay \{[\s\S]*?outline:\s*none/,
      )
      expect(css).toMatch(/#app:focus-visible[\s\S]*?outline:\s*none/)
      expect(css).toMatch(/\.layout:focus-visible[\s\S]*?outline:\s*none/)
      expect(css).toMatch(/\.main:focus-visible[\s\S]*?outline:\s*none/)
      expect(css).toMatch(/\.topchrome:focus-visible[\s\S]*?outline:\s*none/)
      expect(css).toMatch(/\.top-nav:focus-visible[\s\S]*?outline:\s*none/)
      expect(css).toMatch(/\.nav-overlay:focus-visible[\s\S]*?outline:\s*none/)
      expect(css).toMatch(/\.top-nav\[inert\] \*:focus-visible[\s\S]*?outline:\s*none/)
    })

    it('hides the closed phone drawer and paints the accent mark only while open', () => {
      expect(css).toMatch(
        /@media \(max-width: 640px\) \{[\s\S]*?\.top-nav \{[\s\S]*?visibility:\s*hidden/,
      )
      expect(css).toMatch(
        /@media \(max-width: 640px\) \{[\s\S]*?\.top-nav \{[\s\S]*?opacity:\s*0/,
      )
      expect(css).toMatch(
        /@media \(max-width: 640px\) \{[\s\S]*?\.top-nav \{[\s\S]*?clip-path:\s*inset\(0 100% 0 0\)/,
      )
      expect(css).toMatch(
        /@media \(max-width: 640px\) \{[\s\S]*?\.top-nav\.open \{[\s\S]*?visibility:\s*visible/,
      )
      expect(css).toMatch(
        /@media \(max-width: 640px\) \{[\s\S]*?\.top-nav\.open \{[\s\S]*?opacity:\s*1/,
      )
      expect(css).toMatch(
        /@media \(max-width: 640px\) \{[\s\S]*?\.top-nav\.open \{[\s\S]*?clip-path:\s*none/,
      )
      expect(css).toMatch(
        /\.top-nav\.open a \{[\s\S]*?border-left:\s*3px solid transparent/,
      )
      expect(css).toMatch(
        /\.top-nav\.open a\.active \{[\s\S]*?border-left-color:\s*var\(--accent\)/,
      )
    })

    it('renders macos tabs as a segmented well, not underline-only pills', () => {
      expect(css).toMatch(/html\[data-theme="macos"\] \.tabs[\s\S]*?background:\s*#e8e8ed/)
      expect(css).toMatch(/html\[data-theme="macos"\] \.tabs button\.active[\s\S]*?background:\s*#fff/)
      expect(css).not.toMatch(/\.tools-tab/)
    })

    it('selects table rows with solid accent and white text', () => {
      expect(css).toMatch(
        /\[data-theme="macos"\] table\.dense tbody tr\.selected[\s\S]*?background:\s*var\(--accent\)/,
      )
    })

    it('uses the Sequoia radius scale including a 12px outer shell', () => {
      for (const id of ['macos', 'macos-dark']) {
        const block = palette(id)
        expect(block).toMatch(/--radius-sm:\s*6px/)
        expect(block).toMatch(/--radius:\s*8px/)
        expect(block).toMatch(/--radius-lg:\s*12px/)
        expect(block).toMatch(/--radius-modal:\s*14px/)
        expect(block).toMatch(/--radius-shell:\s*12px/)
      }
      expect(css).toMatch(
        /\[data-theme="macos"\] #app[\s\S]*?border-radius:\s*var\(--radius-shell\)/,
      )
      expect(css).toMatch(
        /\[data-theme="macos-dark"\] #app[\s\S]*?border-radius:\s*var\(--radius-shell\)/,
      )
      expect(css).toMatch(
        /\[data-theme="macos"\] \.layout[\s\S]*?border-radius:\s*var\(--radius-shell\)/,
      )
      expect(css).toMatch(
        /\[data-theme="macos-dark"\] \.layout[\s\S]*?border-radius:\s*var\(--radius-shell\)/,
      )
    })
  })
})
