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
  it('does not overlap async polling requests', () => {
    const apps = readFileSync(resolve(SRC, 'views', 'Apps.vue'), 'utf8')
    expect(apps, 'setInterval(async …) starts another request before the prior one finishes')
      .not.toMatch(/setInterval\s*\(\s*async\b/)
    expect(apps).toContain('cfPollGeneration')
    expect(apps).toMatch(/onUnmounted\s*\(\s*\(\)\s*=>\s*\{[\s\S]*stopCfLoginPolling\(\)/)
  })

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
        const clearedDirectly =
          new RegExp(`clear(?:Interval|Timeout)\\s*\\(\\s*${handle}\\b`).test(tail) ||
          new RegExp(`\\b${handle}\\s*\\(\\s*\\)`).test(tail)
        const clearedByHelper = [...src.matchAll(/function\s+(\w+)\s*\([^)]*\)\s*\{([\s\S]*?)\n\}/g)]
          .some(([, fn, body]) =>
            new RegExp(`clear(?:Interval|Timeout)\\s*\\(\\s*${handle}\\b`).test(body) &&
            new RegExp(`\\b${fn}\\s*\\(\\s*\\)`).test(tail),
          )
        if (!clearedDirectly && !clearedByHelper) {
          offenders.push(`${name}: ${handle} never cleared on unmount`)
        }
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

describe('launcher service feedback', () => {
  const settings = readFileSync(resolve(SRC, 'views/Settings.vue'), 'utf8')

  it('clears the green panel state immediately after accepting stop', () => {
    expect(settings).toContain("if (action === 'stop')")
    expect(settings).toMatch(/panel_running:\s*false/)
    expect(settings).toMatch(/panel_job_state:\s*'stopping'/)
  })
})

describe('storage state semantics', () => {
  const main = readFileSync(resolve(SRC, 'views/MainArray.vue'), 'utf8')
  const pool = readFileSync(resolve(SRC, 'views/Pool.vue'), 'utf8')

  it('does not present a missing array status as started', () => {
    expect(main).not.toContain("data?.array?.status || 'started'")
    expect(main).toContain("data?.array?.status || t('network.unknown')")
  })

  it('preserves the saved pool free-space floor when editing other fields', () => {
    expect(pool).toContain('minFreeGb.value = Number(data.min_free_gb) || 0')
    expect(pool).toContain('min_free_gb: Number(minFreeGb.value) || 0')
  })
})

describe('workload operation semantics', () => {
  const compose = readFileSync(resolve(SRC, 'views/Compose.vue'), 'utf8')
  const containers = readFileSync(resolve(SRC, 'views/Containers.vue'), 'utf8')
  const vms = readFileSync(resolve(SRC, 'views/VMs.vue'), 'utf8')

  it('serializes async job polling instead of overlapping requests', () => {
    for (const [name, src] of [['Compose.vue', compose], ['Containers.vue', containers]]) {
      expect(src, `${name} must not overlap job requests`).not.toMatch(/setInterval\s*\(\s*poll/)
      expect(src, `${name} needs an in-flight response invalidation token`).toContain('jobPollGeneration')
      expect(src, `${name} must invalidate polling on unmount`).toMatch(/onUnmounted\([^)]*stopJobPolling|onUnmounted\s*\(\s*\(\)\s*=>\s*\{[\s\S]*stopJobPolling\(\)/)
    }
  })

  it('shows partial container batch failures as failures', () => {
    expect(containers).toContain('function batchToast(j)')
    expect(containers).toContain("t('docker.done_count'")
    expect(containers).toContain('j.ok === false')
  })

  it('keeps graceful stop distinct from force kill for VMs', () => {
    expect(vms).toContain("t('vms.confirm_kill'")
    expect(vms).toContain("t('vms.confirm_restart_force'")
    expect(vms).toContain("force: action !== 'stop'")
    expect(vms).not.toContain('{ action, force: true }')
  })
})

describe('network operation semantics', () => {
  const network = readFileSync(resolve(SRC, 'views/Network.vue'), 'utf8')

  it('keeps failed network forms open and only refreshes successful changes', () => {
    for (const state of ['manualSvc', 'dnsSvc', 'portEdit', 'connectNet']) {
      expect(network, `${state} must close only inside a success branch`)
        .toMatch(new RegExp(`if \\(j\\.ok\\) \\{[\\s\\S]{0,120}${state}\\.value = null`))
    }
    expect(network).not.toMatch(/setTimeout\s*\(\s*\(\)\s*=>\s*refresh\(true\)/)
    expect(network).toContain('for (const id of refreshTimers) clearTimeout(id)')
  })

  it('warns before connection-changing operations', () => {
    for (const key of [
      'network.confirm_manual',
      'network.confirm_wifi',
      'network.confirm_recreate_ports',
      'network.confirm_disconnect',
    ]) expect(network).toContain(key)
  })
})

describe('operations polling and submission guards', () => {
  const maintenance = readFileSync(resolve(SRC, 'views/Maintenance.vue'), 'utf8')
  const logs = readFileSync(resolve(SRC, 'views/Logs.vue'), 'utf8')
  const backups = readFileSync(resolve(SRC, 'views/Backups.vue'), 'utf8')
  const alerts = readFileSync(resolve(SRC, 'views/Alerts.vue'), 'utf8')

  it('serializes maintenance and log refreshes', () => {
    expect(maintenance).not.toContain('setInterval(')
    expect(maintenance).toContain('startVisibleInterval(refresh, 15000)')
    expect(maintenance).toContain('pollGeneration')
    expect(logs).not.toContain('setInterval(')
    expect(logs).toContain('startVisibleInterval(load, 6000)')
    expect(logs).toContain('loadGeneration')
  })

  it('does not refresh a failed backup into the successful list', () => {
    expect(backups).toContain('if (r.ok) await refresh()')
  })

  it('prevents duplicate alert checks and notification tests', () => {
    expect(alerts).toContain('const busy = ref(false)')
    expect(alerts).toMatch(/async function check\(\)[\s\S]*if \(busy\.value\) return[\s\S]*finally/)
    expect(alerts).toMatch(/async function test\(\)[\s\S]*if \(busy\.value\) return[\s\S]*finally/)
  })

  it('does not report an unsaved diagnostics snapshot as saved', () => {
    const tools = readFileSync(resolve(SRC, 'views/Tools.vue'), 'utf8')
    const settings = readFileSync(resolve(SRC, 'views/Settings.vue'), 'utf8')
    expect(tools).toContain("if (j.saved_path)")
    expect(tools).toContain("t('tools.diag_save_failed'")
    expect(tools).toContain('j.save_error')
    expect(settings).toContain('const saved = Boolean(result.saved_path)')
    expect(settings).toContain("t('settings.diag_save_failed'")
    expect(settings).toContain('result.save_error')
    expect(settings).toContain("toast(saved ? '✅ '")
  })

  it('keeps dashboard actions recoverable and polling serialized', () => {
    const dashboard = readFileSync(resolve(SRC, 'views/Dashboard.vue'), 'utf8')
    expect(dashboard).toMatch(/async function act\(svc, action\)[\s\S]*if \(busy\.value\) return[\s\S]*finally/)
    expect(dashboard).toContain('if (r.ok) scheduleActionRefresh()')
    expect(dashboard).not.toContain('setTimeout(refresh, 1000)')
    expect(dashboard).toContain('await Promise.all([refresh(), loadSensors(false)])')
    expect(dashboard).toMatch(/onUnmounted\([\s\S]*clearTimeout\(actionRefreshTimer\)/)
  })

  it('keeps file navigation and terminal connection state current', () => {
    const files = readFileSync(resolve(SRC, 'views/Files.vue'), 'utf8')
    const terminal = readFileSync(resolve(SRC, 'views/Terminal.vue'), 'utf8')
    const settings = readFileSync(resolve(SRC, 'views/Settings.vue'), 'utf8')
    expect(files).toContain('const request = ++listRequest')
    expect(files).toContain('request !== listRequest || !activated.value')
    expect(files).toMatch(/function deactivate\(\)[\s\S]*listRequest \+= 1/)
    expect(files).toMatch(/onUnmounted\([\s\S]*listRequest \+= 1/)
    expect(files.match(/if \(!j\?\.ok\) throw new Error/g)).toHaveLength(2)
    expect(terminal).toContain('terminal handshake timeout')
    expect(terminal).toMatch(/message\.type === 'ready'[\s\S]{0,100}clearConnectTimer\(\)/)
    expect(terminal).toMatch(/function closeTerminal\(\)[\s\S]{0,100}clearConnectTimer\(\)/)
    expect(terminal).toMatch(/function onSocketClose\(\)[\s\S]{0,100}clearConnectTimer\(\)/)
    expect(settings).toMatch(/async function testNotify\(\)[\s\S]*if \(saving\.value\) return[\s\S]*finally/)
    expect(settings).toMatch(/async function forceCheck\(\)[\s\S]*if \(saving\.value\) return[\s\S]*finally/)
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
