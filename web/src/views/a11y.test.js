/**
 * Structural guards for the accessibility work.
 *
 * These read the .vue sources rather than mounting every view: the modals are
 * deep inside pages that need a live API, and what regressed historically was
 * always the markup contract (a new modal copied from an old one that had no
 * dialog role), not runtime behaviour.
 */
import { describe, expect, it } from 'vitest'
import { readFileSync, readdirSync } from 'node:fs'
import { resolve } from 'node:path'

const SRC = resolve(__dirname, '..')

function vueFiles() {
  const out = []
  for (const dir of ['views', 'components']) {
    for (const f of readdirSync(resolve(SRC, dir))) {
      if (f.endsWith('.vue')) out.push([`${dir}/${f}`, readFileSync(resolve(SRC, dir, f), 'utf8')])
    }
  }
  return out
}

describe('modal dialogs', () => {
  it('pair every .modal-bg overlay with a dialog role', () => {
    const offenders = []
    for (const [name, src] of vueFiles()) {
      const overlays = (src.match(/class="modal-bg"/g) || []).length
      const dialogs = (src.match(/role="dialog"/g) || []).length
      if (overlays > dialogs) offenders.push(`${name} (${overlays} overlays, ${dialogs} dialogs)`)
    }
    expect(offenders, 'modals without role="dialog" are invisible to screen readers').toEqual([])
  })

  it('give every dialog an accessible name that resolves to a real element', () => {
    const offenders = []
    for (const [name, src] of vueFiles()) {
      const labelled = [...src.matchAll(/aria-labelledby="([^"]+)"/g)].map(m => m[1])
      for (const id of labelled) {
        // The id must exist in the same file, otherwise the name resolves to nothing.
        if (!src.includes(`id="${id}"`)) offenders.push(`${name}: ${id} has no target`)
      }
      const dialogs = (src.match(/role="dialog"/g) || []).length
      const named = labelled.length + (src.match(/role="dialog"[^>]*aria-label=/g) || []).length
      if (dialogs > named) offenders.push(`${name}: ${dialogs - named} unnamed dialog(s)`)
    }
    expect(offenders).toEqual([])
  })
})

describe('service uninstall UI', () => {
  const src = readFileSync(resolve(SRC, 'views/Services.vue'), 'utf8')

  it('is gated to launch agents only', () => {
    expect(src).toContain("s.kind === 'launchd'")
  })

  it('goes through the api client, not a bare fetch', () => {
    expect(src).toContain('getServiceUninstallPreview')
    expect(src).toContain('uninstallService')
  })

  it('states what is removed and what is kept before confirming', () => {
    for (const key of [
      'services.uninstall_removes',
      'services.uninstall_keeps',
      'services.uninstall_item_program',
      'services.uninstall_reversible',
    ]) {
      expect(src, `confirmation must show ${key}`).toContain(key)
    }
  })
})

describe('timer lifecycle', () => {
  it('clears every interval handle it declares', () => {
    const offenders = []
    for (const [name, src] of vueFiles()) {
      if (!src.includes('setInterval') && !src.includes('startVisibleInterval')) continue
      if (!src.includes('onUnmounted') && !src.includes('onBeforeUnmount')) {
        offenders.push(`${name}: starts a timer with no unmount hook`)
        continue
      }
      const tail = src.slice(src.search(/on(?:BeforeUnmount|Unmounted)\s*\(/))
      for (const handle of [...src.matchAll(/let (\w*[Tt]imer\w*)\s*=/g)].map(m => m[1])) {
        // Require an actual disposal, not merely a mention of the name.  Checking
        // `tail.includes(handle)` alone passed on a teardown that had been reduced
        // to `timer = null`: the handle is still named, the timer still runs, and
        // the page keeps polling the backend after navigation.  Both shapes are
        // legitimate here — clearInterval(t) for raw intervals, and t() for the
        // disposer startVisibleInterval returns.
        const disposed =
          new RegExp(`clear(?:Interval|Timeout)\\s*\\(\\s*${handle}\\b`).test(tail) ||
          new RegExp(`\\b${handle}\\s*\\(\\s*\\)`).test(tail)
        if (!disposed) offenders.push(`${name}: ${handle} never cleared on unmount`)
      }
    }
    expect(offenders, 'a surviving timer keeps polling the backend after navigation').toEqual([])
  })
})

describe('dialog keyboard contract', () => {
  // Every overlay must go through useDismissable.  A dialog that only closes on
  // a backdrop click or an X button is unreachable for anyone driving the panel
  // from the keyboard, and that is exactly how new modals regressed before:
  // copied from an older one that predates the composable.
  const OVERLAY = /class="(?:[^"]*\s)?(?:modal-bg|drawer-bg)(?:\s[^"]*)?"/g

  for (const [name, src] of vueFiles()) {
    const overlays = (src.match(OVERLAY) || []).length
    if (!overlays) continue

    it(`${name} wires every overlay to useDismissable`, () => {
      const wired = (src.match(/useDismissable\(/g) || []).length
      expect(wired, `${name}: ${overlays} overlay(s) but ${wired} useDismissable call(s)`)
        .toBeGreaterThanOrEqual(overlays)
      expect(src).toMatch(/from ['"][^'"]*composables\/useDismissable/)
    })

    it(`${name} passes a bound panel ref to every dialog`, () => {
      for (const m of src.matchAll(/useDismissable\([^;]*?,\s*([A-Za-z_$][\w$]*)\s*\)/g)) {
        const panel = m[1]
        expect(src, `${name}: ${panel} never declared`).toContain(`const ${panel} = ref(`)
        expect(src, `${name}: ref="${panel}" missing from template`).toContain(`ref="${panel}"`)
      }
    })
  }
})

describe('tab selection state', () => {
  it('exposes the selected tab to assistive technology', () => {
    const offenders = []
    for (const [name, src] of vueFiles()) {
      for (const [, tabs] of src.matchAll(/<div class="tabs">([\s\S]*?)<\/div>/g)) {
        const buttons = (tabs.match(/<button\b/g) || []).length
        const states = (tabs.match(/:aria-pressed=/g) || []).length
        if (buttons !== states) offenders.push(`${name}: ${buttons - states} tab button(s) hide their selected state`)
      }
    }
    expect(offenders).toEqual([])
  })
})

describe('focus visibility', () => {
  const css = readFileSync(resolve(SRC, 'styles.css'), 'utf8')

  it('keeps a global keyboard focus ring', () => {
    // A keyboard user needs to see where they are.  This rule is what makes
    // every button, link and row-as-button focusable-visible.
    expect(css).toMatch(/:focus-visible\s*\{[^}]*outline:\s*2px solid/)
  })

  it('gives every outline:none input a visible substitute', () => {
    // outline:none is fine only when something else marks focus.  Collect the
    // selectors that suppress the outline and require each to pair with a
    // box-shadow (or border-color) cue somewhere in the sheet.
    const suppressors = [...css.matchAll(/([^{}]+)\{([^}]*outline:\s*(?:none|0)[^}]*)\}/g)]
      .map(([, sel, body]) => [sel.trim(), body])
      .filter(([sel]) => /input|textarea|select/.test(sel))

    const missing = suppressors
      .filter(([sel, body]) => {
        if (/box-shadow|border-color/.test(body)) return false
        // Otherwise a sibling rule must supply the cue for the same element.
        const base = sel.split(',')[0].replace(/:focus(-visible)?/g, '').trim()
        if (!base) return false
        const sibling = new RegExp(
          `${base.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}[^{]*:focus(-visible)?[^{]*\\{[^}]*box-shadow`,
        )
        return !sibling.test(css)
      })
      .map(([sel]) => sel)

    expect(missing).toEqual([])
  })
})

describe('async status regions', () => {
  // A <pre> that fills in after the user clicks something is invisible to a
  // screen reader unless it is a live region.
  //
  // The judgement is what fills the element, not how the tag is written. An
  // earlier version keyed off `v-if="msg|log|..."`, which only matched a naming
  // habit: every <pre> rendering `{{ jobLog }}` or `{{ diagPreview }}` through
  // plain interpolation sat outside the regex, and three real omissions
  // (Containers job log, Network DNS message, Settings diagnostics preview)
  // passed the gate for exactly that reason.
  //
  // Two kinds of dynamic <pre> are deliberately NOT required to announce:
  //   - inside a dialog/drawer, where moving focus into the panel already reads
  //     the content, so a live region double-announces it;
  //   - continuously self-refreshing views (Logs.vue repolls every 6s), where
  //     announcing every update is unusable noise rather than an improvement.
  const EXEMPT_SELF_REFRESHING = new Set(['views/Logs.vue'])

  /**
   * Names assigned after an `await` inside some async function body.
   *
   * Keying off the shape of the right-hand side is what let `diagPreview`
   * escape: it is assigned `JSON.stringify({...})` built from an already-awaited
   * response, so it matched neither `= await ...` nor `= j.something`. What
   * makes content async is *when* it lands, so look at position relative to an
   * await rather than at the expression itself.
   */
  function asyncAssignedRefs(src) {
    const names = new Set()
    for (const body of src.split(/async\s+(?:function\b|\()/).slice(1)) {
      const at = body.search(/\bawait\b/)
      if (at < 0) continue
      for (const m of body.slice(at).matchAll(/([A-Za-z_$][\w$]*)\.value\s*=/g)) {
        names.add(m[1])
      }
    }
    // `.then(j => { x.value = j.log })` never goes through await.
    for (const m of src.matchAll(/([A-Za-z_$][\w$]*)\.value\s*=\s*(?:j|r|res|data|out)\b/g)) {
      names.add(m[1])
    }
    return names
  }

  it('announce output that arrives after the user acts', () => {
    const offenders = []
    for (const [name, src] of vueFiles()) {
      if (EXEMPT_SELF_REFRESHING.has(name)) continue
      const template = src.slice(0, src.search(/<script\b/) >>> 0)
      const asyncRefs = asyncAssignedRefs(src)

      for (const m of template.matchAll(/<pre\b([^>]*)>([\s\S]{0,120}?)<\/pre>/g)) {
        const [, attrs, body] = m
        if (/aria-live/.test(attrs)) continue

        // Which reactive names feed this element's content or visibility.
        const referenced = [
          ...body.matchAll(/\{\{\s*\(?\s*([A-Za-z_$][\w$]*)/g),
          ...attrs.matchAll(/v-if="!?\s*([A-Za-z_$][\w$]*)/g),
        ].map((x) => x[1])
        if (!referenced.some((n) => asyncRefs.has(n))) continue

        // Inside an overlay the panel gets focus, which reads the content.
        const before = template.slice(0, m.index)
        const opened = (before.match(/class="(?:[^"]*\s)?(?:modal-bg|drawer-bg)/g) || []).length
        const closed = (before.match(/<\/(?:aside|dialog)>/g) || []).length
        if (opened > closed) continue

        offenders.push(`${name}: <pre> shows async output with no aria-live — ${body.trim().slice(0, 40)}`)
      }
    }
    expect(offenders, 'output that arrives after a click must be announced').toEqual([])
  })
})
