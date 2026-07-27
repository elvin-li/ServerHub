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

import { provideTheme } from './index.js'

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
    // Go through the real provider main.js uses, rather than calling
    // injectTheme() with no active component (which warns and falls back).
    api = provideTheme(createApp({}))
  })

  afterEach(() => {
    localStorage.clear()
  })

  describe('setTheme', () => {
    it('applies the requested theme to the document root', () => {
      api.setTheme('nord')
      expect(root().getAttribute('data-theme')).toBe('nord')
      expect(api.theme.value).toBe('nord')
    })

    it('persists the choice so a reload keeps it', () => {
      api.setTheme('docker')
      expect(localStorage.getItem('serverhub.theme')).toBe('docker')
    })

    it('falls back to system for an unknown id', () => {
      api.setTheme('not-a-theme')
      // An unrecognised id must not reach the DOM: [data-theme="not-a-theme"]
      // matches no CSS block, so the page would render unstyled.
      expect(root().getAttribute('data-theme')).toBe('system')
      expect(api.theme.value).toBe('system')
      expect(localStorage.getItem('serverhub.theme')).toBe('system')
    })

    it('leaves color-mode unset for system so the OS preference wins', () => {
      api.setTheme('nord')
      expect(root().getAttribute('data-color-mode')).toBe('dark')

      api.setTheme('system')
      // Pinning a mode here would defeat the prefers-color-scheme media query.
      expect(root().hasAttribute('data-color-mode')).toBe(false)
    })

    it('updates the browser chrome color for themes that define one', () => {
      api.setTheme('nord')
      expect(meta.getAttribute('content')).toBe('#2e3440')
    })

    it('leaves the chrome color alone for system, which has no fixed color', () => {
      meta.setAttribute('content', '#abcdef')
      api.setTheme('system')
      expect(meta.getAttribute('content')).toBe('#abcdef')
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

  describe('color-scheme classification', () => {
    // Each case is checked against the palette in styles.css: a theme whose
    // --bg is near-white is light, and native controls must match it.
    const LIGHT = ['unraid', 'omv', 'docker', 'mono']
    const DARK = ['unraid-dark', 'nord', 'glass']

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

    it('classifies every non-system theme as light or dark', () => {
      // A theme added to the catalogue but not to either list would silently
      // inherit the previous theme's control styling.
      const classified = new Set([
        'unraid',
        'omv',
        'docker',
        'mono',
        'unraid-dark',
        'nord',
        'glass',
      ])
      const ids = api.themes.map((t) => t.id).filter((id) => id !== 'system')
      expect(ids.filter((id) => !classified.has(id))).toEqual([])
    })
  })
})
