import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { installTableWrapFocus } from './tableWrapFocus'

const SRC = resolve(dirname(fileURLToPath(import.meta.url)), '..')

// MutationObserver callbacks are microtasks; a macrotask hop guarantees the
// observer has run before the assertions look at the attributes.
const flush = () => new Promise((r) => setTimeout(r, 0))

let root
let teardown

beforeEach(() => {
  root = document.createElement('main')
  document.body.appendChild(root)
  teardown = null
})

afterEach(() => {
  teardown?.()
  root.remove()
})

describe('installTableWrapFocus', () => {
  it('makes every wrap a keyboard-reachable named region', () => {
    // The wrap scrolls (overflow: auto in styles.css); without tabindex a
    // keyboard user can see the overflow but has no way to move it
    // (WCAG 2.1.1) — same contract as the Logs viewer and service log panes.
    root.innerHTML = `
      <h2>Interfaces</h2>
      <div class="table-wrap"><table class="dense"></table></div>
    `
    teardown = installTableWrapFocus(root)
    const wrap = root.querySelector('.table-wrap')
    expect(wrap.getAttribute('tabindex')).toBe('0')
    expect(wrap.getAttribute('role')).toBe('region')
    expect(wrap.getAttribute('aria-label')).toBe('Interfaces')
  })

  it('borrows the nearest preceding heading, walking out of sibling-less nests', () => {
    // House layout puts the heading beside the card, not beside the wrap:
    // <h2>…</h2><div class=card><div class=table-wrap>. The closer heading
    // must win over the page title, and one deep inside a preceding section
    // counts (last one in document order is the nearest).
    root.innerHTML = `
      <h1>Network</h1>
      <section><h2>Older section</h2><h3>Routes</h3></section>
      <div class="card"><div class="table-wrap" id="a"></div></div>
      <h2>Peers</h2>
      <div class="card"><div class="table-wrap" id="b"></div></div>
    `
    teardown = installTableWrapFocus(root)
    expect(root.querySelector('#a').getAttribute('aria-label')).toBe('Routes')
    expect(root.querySelector('#b').getAttribute('aria-label')).toBe('Peers')
  })

  it('falls back to the shared dictionary label when no heading precedes', () => {
    // No dictionary is loaded in tests, so t() echoes the key — which is
    // exactly the pin: the fallback goes through i18n, not a hardcoded string.
    root.innerHTML = `<div class="table-wrap"></div>`
    teardown = installTableWrapFocus(root)
    expect(root.querySelector('.table-wrap').getAttribute('aria-label')).toBe('common.table_region')
  })

  it('never focuses a wrap inside aria-hidden (SkeletonLoader shimmer)', () => {
    // SkeletonLoader renders a decorative .table-wrap under aria-hidden;
    // a focusable element inside aria-hidden is itself an ARIA violation.
    root.innerHTML = `
      <div role="status" aria-busy="true">
        <div aria-hidden="true"><div class="table-wrap"></div></div>
      </div>
    `
    teardown = installTableWrapFocus(root)
    const wrap = root.querySelector('.table-wrap')
    expect(wrap.hasAttribute('tabindex')).toBe(false)
    expect(wrap.hasAttribute('role')).toBe(false)
    expect(wrap.hasAttribute('aria-label')).toBe(false)
  })

  it('leaves author-set attributes alone', () => {
    root.innerHTML = `
      <div class="table-wrap" tabindex="-1" role="group" aria-label="Mine"></div>
    `
    teardown = installTableWrapFocus(root)
    const wrap = root.querySelector('.table-wrap')
    expect(wrap.getAttribute('tabindex')).toBe('-1')
    expect(wrap.getAttribute('role')).toBe('group')
    expect(wrap.getAttribute('aria-label')).toBe('Mine')
  })

  it('upgrades wraps rendered after install (views, drawers, modals)', async () => {
    teardown = installTableWrapFocus(root)
    const drawer = document.createElement('div')
    drawer.innerHTML = `<h3>Peer config</h3><div class="table-wrap"></div>`
    root.appendChild(drawer)
    await flush()
    const wrap = root.querySelector('.table-wrap')
    expect(wrap.getAttribute('tabindex')).toBe('0')
    expect(wrap.getAttribute('role')).toBe('region')
    expect(wrap.getAttribute('aria-label')).toBe('Peer config')
  })

  it('follows the heading when it re-renders in place (locale switch)', async () => {
    root.innerHTML = `<h2>Interfaces</h2><div class="table-wrap"></div>`
    teardown = installTableWrapFocus(root)
    // Vue patches the existing text node on a locale switch — a characterData
    // mutation, not a childList one.
    root.querySelector('h2').firstChild.data = 'インターフェース'
    await flush()
    expect(root.querySelector('.table-wrap').getAttribute('aria-label')).toBe('インターフェース')
  })

  it('does no work when a poll rewrites table cells', async () => {
    // Polled pages patch cell text every few seconds. Those batches used to
    // rescan the whole region and rewrite every label.
    root.innerHTML = `
      <h2>Interfaces</h2>
      <div class="table-wrap"><table><tbody><tr><td>1 MB/s</td></tr></tbody></table></div>
    `
    teardown = installTableWrapFocus(root)
    const wrap = root.querySelector('.table-wrap')
    const writes = vi.spyOn(wrap, 'setAttribute')
    const scans = vi.spyOn(root, 'querySelectorAll')
    root.querySelector('td').firstChild.data = '2 MB/s'
    const row = document.createElement('tr')
    row.innerHTML = '<td>3 MB/s</td>'
    root.querySelector('tbody').appendChild(row)
    await flush()
    expect(writes).not.toHaveBeenCalled()
    expect(scans).not.toHaveBeenCalled()
  })

  it('does not rewrite a label that did not change', async () => {
    root.innerHTML = `<h2>Interfaces</h2><div class="table-wrap"></div>`
    teardown = installTableWrapFocus(root)
    const wrap = root.querySelector('.table-wrap')
    const writes = vi.spyOn(wrap, 'setAttribute')
    // Vue re-patches a heading's text node with the same string.
    root.querySelector('h2').firstChild.data = 'Interfaces'
    await flush()
    expect(writes).not.toHaveBeenCalled()
    expect(wrap.getAttribute('aria-label')).toBe('Interfaces')
  })

  it('relabels when a heading renders before the wrap later', async () => {
    root.innerHTML = `<div class="card"><div class="table-wrap"></div></div>`
    teardown = installTableWrapFocus(root)
    const wrap = root.querySelector('.table-wrap')
    expect(wrap.getAttribute('aria-label')).toBe('common.table_region')
    const title = document.createElement('h2')
    title.textContent = 'Peers'
    root.insertBefore(title, root.firstChild)
    await flush()
    expect(wrap.getAttribute('aria-label')).toBe('Peers')
  })

  it('follows in-place edits of a heading that rendered after install', async () => {
    root.innerHTML = `<div class="table-wrap"></div>`
    teardown = installTableWrapFocus(root)
    const title = document.createElement('h2')
    title.textContent = 'Interfaces'
    root.insertBefore(title, root.firstChild)
    await flush()
    title.firstChild.data = 'インターフェース'
    await flush()
    expect(root.querySelector('.table-wrap').getAttribute('aria-label')).toBe('インターフェース')
  })

  it('relabels when the nearest heading is removed', async () => {
    root.innerHTML = `
      <h2>Network</h2>
      <section><h3>Routes</h3></section>
      <div class="table-wrap"></div>
    `
    teardown = installTableWrapFocus(root)
    const wrap = root.querySelector('.table-wrap')
    expect(wrap.getAttribute('aria-label')).toBe('Routes')
    root.querySelector('section').remove()
    await flush()
    expect(wrap.getAttribute('aria-label')).toBe('Network')
  })

  it('follows a heading whose text node is replaced', async () => {
    root.innerHTML = `<h2>Interfaces</h2><div class="table-wrap"></div>`
    teardown = installTableWrapFocus(root)
    root.querySelector('h2').textContent = 'Peers'
    await flush()
    expect(root.querySelector('.table-wrap').getAttribute('aria-label')).toBe('Peers')
  })

  it('upgrades a wrap once its aria-hidden ancestor is shown', async () => {
    root.innerHTML = `
      <h2>Logs</h2>
      <div class="pane" aria-hidden="true"><div class="table-wrap"></div></div>
    `
    teardown = installTableWrapFocus(root)
    const wrap = root.querySelector('.table-wrap')
    expect(wrap.hasAttribute('tabindex')).toBe(false)
    root.querySelector('.pane').removeAttribute('aria-hidden')
    await flush()
    expect(wrap.getAttribute('tabindex')).toBe('0')
    expect(wrap.getAttribute('role')).toBe('region')
    expect(wrap.getAttribute('aria-label')).toBe('Logs')
  })

  it('stops observing after teardown', async () => {
    teardown = installTableWrapFocus(root)
    teardown()
    teardown = null
    const wrap = document.createElement('div')
    wrap.className = 'table-wrap'
    root.appendChild(wrap)
    await flush()
    expect(wrap.hasAttribute('tabindex')).toBe(false)
  })
})

describe('table-wrap keyboard wiring', () => {
  it('is installed by the app shell over the main region', () => {
    // The upgrade covers ~30 views at once, but only if the shell actually
    // installs it. Pin the wiring so a refactor cannot silently drop it.
    const app = readFileSync(resolve(SRC, 'App.vue'), 'utf8')
    expect(app).toMatch(/import \{ installTableWrapFocus \} from '\.\/lib\/tableWrapFocus'/)
    expect(app).toMatch(/installTableWrapFocus\(el\)/)
  })

  it('keeps a visible focus ring on the wrap', () => {
    // tabindex without a visible ring trades WCAG 2.1.1 for 2.4.7.
    const css = readFileSync(resolve(SRC, 'styles.css'), 'utf8')
    expect(css).toMatch(/\.table-wrap:focus-visible \{[^}]*outline: 2px solid var\(--accent\)/)
  })
})
