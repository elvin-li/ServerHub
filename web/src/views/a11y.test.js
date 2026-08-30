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
  // App.vue sits at the src root, not under views/ or components/, so scanning
  // only those two directories skipped the application shell entirely -- and
  // the shell owns the command palette, a real dialog that was missing
  // aria-modal, had Escape bound to its input alone (so tabbing to the result
  // list lost the keybinding), and trapped focus nowhere.
  const out = [['App.vue', readFileSync(resolve(SRC, 'App.vue'), 'utf8')]]
  for (const dir of ['views', 'components']) {
    for (const f of readdirSync(resolve(SRC, dir))) {
      if (f.endsWith('.vue')) out.push([`${dir}/${f}`, readFileSync(resolve(SRC, dir, f), 'utf8')])
    }
  }
  return out
}

/**
 * Every shape the panel uses to darken the page behind a dialog.
 *
 * A literal `class="modal-bg"` was too narrow twice over: it missed the
 * `drawer-bg` overlays entirely, and it missed any overlay carrying a second
 * class. Three real drawers (Apps detail, Containers logs, Containers inspect)
 * sat unannounced behind that gap -- each one focus-trapped and Escape-closable
 * via useDismissable, so they behaved correctly for a keyboard user while
 * telling a screen reader nothing about what had opened.
 *
 * `cmd-palette-bg` is a third spelling, used once, for the Cmd+K palette.
 * `assist-bg` is the AI assistant drawer. `terminal-backdrop` is the
 * in-browser terminal, and `share-sheet-backdrop` is the Shares editor.
 * Listed explicitly rather than matched by a `-bg$` suffix rule: several
 * unrelated classes end in -bg, and a pattern loose enough to catch them
 * would demand a dialog role from things that are not dialogs.
 */
const OVERLAY = /class="(?:[^"]*\s)?(?:modal-bg|drawer-bg|cmd-palette-bg|assist-bg|terminal-backdrop|share-sheet-backdrop)(?:\s[^"]*)?"/g

describe('modal dialogs', () => {
  it('pair every overlay with a dialog role', () => {
    const offenders = []
    for (const [name, src] of vueFiles()) {
      const overlays = (src.match(OVERLAY) || []).length
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

  it('marks overlay backdrops as presentation so AT skip them', () => {
    const offenders = []
    for (const [name, src] of vueFiles()) {
      const template = src.slice(0, src.search(/<script\b/) >>> 0)
      for (const m of template.matchAll(OVERLAY)) {
        const around = template.slice(m.index, m.index + 220)
        if (!/role="presentation"/.test(around)) {
          offenders.push(`${name}: overlay backdrop without role="presentation"`)
        }
      }
    }
    expect(offenders, 'overlay wrappers without role=presentation are read as extra regions').toEqual([])
  })

  it('marks every dialog aria-modal', () => {
    const offenders = []
    for (const [name, src] of vueFiles()) {
      const template = src.slice(0, src.search(/<script\b/) >>> 0)
      for (const m of template.matchAll(/role="dialog"/g)) {
        const around = template.slice(Math.max(0, m.index - 220), m.index + 180)
        if (!/aria-modal="true"/.test(around)) offenders.push(`${name}: dialog without aria-modal`)
      }
    }
    expect(offenders, 'dialogs without aria-modal leak the page behind them to AT').toEqual([])
  })
})

describe('icon-only controls', () => {
  it('give every icon-only button or link an accessible name', () => {
    // title= is a last-resort accessible name and is invisible to some AT;
    // icon-only controls in this panel must spell the name with aria-label.
    const TAG = /<(button|a)\b([^>]*)>([\s\S]*?)<\/\1>/g
    const offenders = []
    for (const [name, src] of vueFiles()) {
      const template = src.slice(0, src.search(/<script\b/) >>> 0)
      for (const m of template.matchAll(TAG)) {
        const [, tag, attrs, body] = m
        const text = body
          .replace(/<[^>]+>/g, '')
          .replace(/\{\{[\s\S]*?\}\}/g, 'X')
          .replace(/&[^;]+;/g, 'X')
          .trim()
        const iconOnly = text === '' || /^[↑↓←→×✕!]$/.test(text)
        if (!iconOnly) continue
        if (/aria-label=/.test(attrs) || /aria-labelledby=/.test(attrs)) continue
        offenders.push(`${name}: <${tag}${attrs.slice(0, 80)}>`)
      }
    }
    expect(
      offenders,
      'icon-only controls need aria-label; title= is not a reliable name',
    ).toEqual([])
  })
})

describe('control names', () => {
  // A placeholder is an example value ("auto", "nginx:alpine", "notify.notify");
  // a name says what the control *is*.  Copying the placeholder into aria-label
  // is worse than leaving the label off: the accessible name becomes the sample
  // data, and it overrides the visible <label> that was already correct.  Every
  // one of these sites had a neighbouring label carrying the real name.
  const TAG = /<(?:input|textarea|select)\b[^>]*>/g

  it('never reuse a placeholder as the accessible name', () => {
    const offenders = []
    for (const [name, src] of vueFiles()) {
      for (const tag of src.match(TAG) || []) {
        const ph = tag.match(/\splaceholder="([^"]*)"/)
        const al = tag.match(/\saria-label="([^"]*)"/)
        if (ph && al && ph[1].trim() && ph[1] === al[1]) {
          offenders.push(`${name}: aria-label duplicates placeholder "${ph[1]}"`)
        }
      }
    }
    expect(
      offenders,
      'aria-label must name the control, not repeat its example value',
    ).toEqual([])
  })

  it('names every form control on the account, settings, sharing and workload surfaces', () => {
    // The form-grid layout puts a <label> next to its control without for/id,
    // so the label text counts for nothing: the text inputs all carried
    // aria-label while nine checkboxes/selects on Settings (notify, thresholds,
    // WoL, advanced, terminal) shipped with no accessible name at all.
    // Accepted name sources: aria-label / aria-labelledby (static or bound),
    // a wrapping <label>, or a for= that targets the control's id.
    // The sharing surfaces (Shares sheet, Files toolbar/table, PhotosHub
    // settings, WireGuard peer forms + settings dialog) are in the list so a
    // control added to any of their form grids cannot ship nameless.
    // The workload surfaces followed in the next sweep: the Apps install-modal
    // variable inputs and autostart policy select, the Containers select-all /
    // per-row / privileged checkboxes, and the Tools syslog level and range
    // selects all sat beside unassociated labels (or none at all).
    // The services/maintenance surfaces (Services toolbar + uninstall dialog,
    // Scheduler job table + job form, Maintenance/Brew/Audit filters) close the
    // sweep: their form grids use the same label-without-for layout, so a
    // control added to any of them cannot ship nameless.
    // Logs and Gateway joined last: the Logs toolbar's source/lines selects and
    // highlight filter were labeled but never pinned, and Gateway ships no form
    // control today — both are listed so one cannot be added nameless.
    const FILES = [
      'views/Login.vue', 'views/Account.vue', 'views/Users.vue', 'views/Settings.vue',
      'views/Shares.vue', 'views/Files.vue', 'views/PhotosHub.vue', 'views/WireGuard.vue',
      'views/Compose.vue', 'views/Apps.vue', 'views/Containers.vue', 'views/Network.vue',
      'views/Tools.vue', 'views/Services.vue', 'views/Scheduler.vue', 'views/Maintenance.vue',
      'views/Brew.vue', 'views/Audit.vue', 'views/Logs.vue', 'views/Gateway.vue',
      'components/ScheduleJobForm.vue',
    ]
    const TAG = /<\/?([a-zA-Z][\w-]*)((?:"[^"]*"|'[^']*'|[^>"'])*)\/?>/g
    const offenders = []
    for (const name of FILES) {
      const src = readFileSync(resolve(SRC, name), 'utf8')
      const template = src
        .slice(0, src.search(/<script\b/) >>> 0)
        // Prose comments mention tags ("the grid <label>s…"); they must not
        // confuse the nesting walker below.
        .replace(/<!--[\s\S]*?-->/g, '')
      let labelDepth = 0
      for (const m of template.matchAll(TAG)) {
        const [raw, tag, attrs] = m
        if (tag === 'label') {
          labelDepth += raw.startsWith('</') ? -1 : 1
          continue
        }
        if (raw.startsWith('</')) continue
        if (!['input', 'select', 'textarea'].includes(tag)) continue
        if (labelDepth > 0) continue
        if (/\baria-label(?:ledby)?=/.test(attrs)) continue
        const id = attrs.match(/\sid="([^"]+)"/)
        if (id && template.includes(`for="${id[1]}"`)) continue
        offenders.push(`${name}: ${raw.replace(/\s+/g, ' ').slice(0, 90)}`)
      }
    }
    expect(
      offenders,
      'a form control next to an unassociated <label> has no accessible name',
    ).toEqual([])
  })
})

describe('account surface load-failure alerts', () => {
  // These fetch failures render inline (no toast, no LoadFailure banner), so
  // without role="alert" they appear silently for assistive technology.
  it('announces the Settings 2FA and API-key load failures', () => {
    const settings = readFileSync(resolve(SRC, 'views/Settings.vue'), 'utf8')
    // Account.vue carried role="alert" on its copy of the 2FA block from the
    // start; the Settings copy shipped without it.
    expect(settings).toMatch(/v-if="twofaError"[^>]*role="alert"/)
    expect(settings).toMatch(/v-else-if="apiKeysError"[^>]*role="alert"/)
    const account = readFileSync(resolve(SRC, 'views/Account.vue'), 'utf8')
    expect(account).toMatch(/v-if="twofaError"[^>]*role="alert"/)
  })

  it('announces the Users service-picker and accounts-table load failures', () => {
    const users = readFileSync(resolve(SRC, 'views/Users.vue'), 'utf8')
    // Both copies of the resource picker (create form + row editor).
    const pickers = users.match(/v-if="serviceOptionsError"[^>]*role="alert"/g) || []
    expect(pickers.length).toBe(2)
    // The empty-row error text, but not its loading/none siblings, is live.
    expect(users).toMatch(/v-if="accountsError"[^>]*role="alert"/)
  })
})

describe('sharing surface load-failure alerts', () => {
  // Same class of gap as the account surfaces: inline fetch failures with no
  // toast and no LoadFailure banner, appearing silently for AT.
  it('announces the Shares ACL read failure inside the edit sheet', () => {
    // The ACL loads *after* the sheet already holds focus, so the panel-focus
    // read never covers it.
    const shares = readFileSync(resolve(SRC, 'views/Shares.vue'), 'utf8')
    expect(shares).toMatch(/v-else-if="aclError"[^>]*role="alert"/)
  })

  it('announces the PhotosHub settings-config load failure', () => {
    // pendingError and logError carried role="alert" from the start; the
    // settings tab's copy shipped without it.
    const photoshub = readFileSync(resolve(SRC, 'views/PhotosHub.vue'), 'utf8')
    expect(photoshub).toMatch(/v-if="settingsError"[^>]*role="alert"/)
    expect(photoshub).toMatch(/v-if="pendingError"[^>]*role="alert"/)
    expect(photoshub).toMatch(/v-if="logError"[^>]*role="alert"/)
  })

  it('announces the WireGuard settings-dialog load failure', () => {
    // The tile latches a failed read and blocks Save; without role="alert" a
    // screen-reader user hears an editable form and a disabled Save button
    // with no stated reason.
    const wireguard = readFileSync(resolve(SRC, 'views/WireGuard.vue'), 'utf8')
    expect(wireguard).toMatch(/v-if="!settingsLoaded"[^>]*role="alert"/)
  })

  it('keeps the Files listing error bar an assertive live region', () => {
    const files = readFileSync(resolve(SRC, 'views/Files.vue'), 'utf8')
    expect(files).toMatch(/class="err-live" role="alert" aria-live="assertive"/)
  })

  it('voices the Shares ACL loading placeholder inside the edit sheet', () => {
    // The ACL loads after the sheet already holds focus, so the swap from
    // this placeholder was silent for a screen reader (Login-loading /
    // Settings launcher-placeholder pattern); its failure sibling above
    // already carries role=alert.
    const shares = readFileSync(resolve(SRC, 'views/Shares.vue'), 'utf8')
    expect(shares).toMatch(/v-if="aclLoading" class="acl-hint" role="status"/)
  })

  it('announces the Shares page-title count summary', () => {
    // The shares/services breakdown is Refresh's only answer and it changed
    // silently for a screen reader, while the same page-title count on Users
    // and Bookmarks already carried role=status.
    const shares = readFileSync(resolve(SRC, 'views/Shares.vue'), 'utf8')
    expect(shares).toMatch(/class="meta" role="status">\s*\{\{ data\s*\? t\('shares\.summary'/)
  })
})

describe('sharing surface control names', () => {
  it('does not shadow the PhotosHub people labels with shorter aria-labels', () => {
    // Each input has a for/id <label> reading "child · field". The aria-labels
    // that used to sit on top overrode them with the bare field name, so both
    // birthday inputs were announced identically as "birthday" with nothing
    // saying whose.
    const photoshub = readFileSync(resolve(SRC, 'views/PhotosHub.vue'), 'utf8')
    for (const id of ['ph-yuanbao-name', 'ph-yuanbao-bday', 'ph-erbao-name', 'ph-erbao-bday']) {
      expect(photoshub, `${id} must keep its for/id label`).toContain(`for="${id}"`)
      const input = photoshub.match(new RegExp(`<input id="${id}"[^>]*>`))
      expect(input, `input #${id}`).toBeTruthy()
      expect(input[0], `${id}: aria-label overrides the richer visible label`)
        .not.toMatch(/aria-label/)
    }
  })

  it('names the Containers row checkboxes after their container', () => {
    // Same pattern the Services and Files row checkboxes already follow: a
    // page of checkboxes all announced as "checkbox" cannot be told apart in
    // a screen reader's form-controls listing.
    const containers = readFileSync(resolve(SRC, 'views/Containers.vue'), 'utf8')
    expect(containers).toMatch(
      /:aria-label="t\('common\.select_row_name',\s*\{\s*name:/,
    )
    expect(containers).toMatch(/:aria-label="t\('common\.select_all'\)"/)
  })

  it('keeps the Compose stack list keyboard-operable without nesting controls', () => {
    // Loading a stack's YAML into the editor was row-click only — no keyboard
    // path at all, unlike Apps (Detail button) and Files (name cell). The
    // button role sits on the name cell, not the <tr>: the row also holds the
    // Up/Update/Down buttons and a control may not contain other controls
    // (ARIA nested-interactive).
    const compose = readFileSync(resolve(SRC, 'views/Compose.vue'), 'utf8')
    expect(compose).toMatch(
      /<td[^>]*tabindex="0"[^>]*role="button"[^>]*@keydown\.enter\.prevent="select\(s\)"/,
    )
    expect(compose).not.toMatch(/<tr[^>]*role="button"/)
  })

  it('names every navigation landmark', () => {
    // App.vue ships two labelled navs (sidebar, section tabs). The Files
    // breadcrumb trail is a third landmark; unnamed, it is announced as an
    // anonymous "navigation" indistinguishable from the others.
    const offenders = []
    for (const [name, src] of vueFiles()) {
      const template = src.slice(0, src.search(/<script\b/) >>> 0)
      for (const m of template.matchAll(/<nav\b[^>]*>|role="navigation"[^>]*/g)) {
        const tag = m[0].startsWith('<nav')
          ? m[0]
          // role= can sit mid-tag; re-read the whole element around the match.
          : template.slice(template.lastIndexOf('<', m.index), template.indexOf('>', m.index) + 1)
        if (!/:?aria-label(?:ledby)?=/.test(tag)) offenders.push(`${name}: ${tag.replace(/\s+/g, ' ').slice(0, 80)}`)
      }
    }
    expect(offenders, 'nav landmarks need aria-label to be told apart').toEqual([])
  })
})

describe('services and scheduler surface leftovers', () => {
  it('names the Scheduler enable toggles after their job', () => {
    // A column of checkboxes all announced as "Enabled" cannot be told apart
    // in a screen reader's form-controls listing — same fix as the Services
    // and Containers row checkboxes. The single checkbox inside the job form
    // keeps the plain label; only the per-row table copy needs the job name.
    const scheduler = readFileSync(resolve(SRC, 'views/Scheduler.vue'), 'utf8')
    expect(scheduler).toMatch(/:aria-label="t\('sched\.enable_name',\s*\{\s*name:/)
    expect(scheduler).not.toMatch(/:aria-label="t\('sched\.enabled'\)"/)
  })

  it('announces the Scheduler run-history load failure inside its dialog', () => {
    // The history loads after the dialog already holds focus, so the
    // panel-focus read never covers it — same as the Shares ACL error.
    const scheduler = readFileSync(resolve(SRC, 'views/Scheduler.vue'), 'utf8')
    expect(scheduler).toMatch(/v-if="runsError"[^>]*role="alert"/)
  })

  it('announces the Scheduler job and timer counts as status regions', () => {
    // Each toolbar count is Refresh's (and, for panel jobs, the running-jobs
    // poll's) only summary, and it changed silently for a screen reader —
    // same treatment as the VMs title-meta and Users/Apps toolbar counts.
    const scheduler = readFileSync(resolve(SRC, 'views/Scheduler.vue'), 'utf8')
    expect(scheduler).toMatch(/<span class="meta" role="status"[^>]*v-if="jobsLoaded">\{\{ asArray\(jobs\)\.length \}\}/)
    expect(scheduler).toMatch(/<span class="meta" role="status"[^>]*v-if="data">\{\{ finiteN\(data\.count\) \}\}/)
  })

  it('announces the Scheduler run-history empty state inside its dialog', () => {
    // The loading -> "no runs recorded" flip is the whole outcome of an empty
    // history and lands after the dialog already holds focus, so it was
    // paint-only — same as the PhotosHub empty pending state.
    const scheduler = readFileSync(resolve(SRC, 'views/Scheduler.vue'), 'utf8')
    expect(scheduler).toMatch(/v-else-if="!asArray\(runs\)\.length" class="meta" role="status">\{\{ t\('sched\.runs_empty'\) \}\}/)
  })

  it('announces the job form stack-list load failure instead of swallowing it', () => {
    // A failed stack read was swallowed into `stacks = []`, leaving an empty
    // select and a disabled Save with no stated reason — the same silent hole
    // the WireGuard settings dialog had.
    const form = readFileSync(resolve(SRC, 'components/ScheduleJobForm.vue'), 'utf8')
    expect(form).toMatch(/v-if="stacksError"[^>]*role="alert"/)
    expect(form).toMatch(/stacksError\.value = finiteText/)
  })

  it('keeps the Services card grid keyboard-operable without nesting controls', () => {
    // Same rule that moved the Compose row role to the name cell: the card
    // holds the ServiceActions buttons, and a control may not contain other
    // controls (ARIA nested-interactive). The name span carries the role and
    // the keyboard path; @click stays on the card for mouse users.
    const services = readFileSync(resolve(SRC, 'views/Services.vue'), 'utf8')
    expect(services).not.toMatch(/<article[^>]*role="button"/)
    expect(services).toMatch(/class="name"[^>]*role="button"[^>]*@keydown\.enter\.prevent="openDetail\(s\)"/)
  })

  it('renders the Maintenance load failure as the standard retryable banner', () => {
    // The old inline placeholder only rendered once the table had rows, so a
    // failed *first* read fell into the empty-table row with no retry and no
    // role=alert. The behavioural half lives in loadStates.test.js.
    const maintenance = readFileSync(resolve(SRC, 'views/Maintenance.vue'), 'utf8')
    expect(maintenance).toMatch(/<LoadFailure v-if="loadError"[^>]*:retry="refresh"/)
    expect(maintenance).toMatch(/v-if="!asArray\(filtered\)\.length && !loadError"/)
  })

  it('announces the Maintenance job log — and its finish line — as a live region', () => {
    // pollLog appends maintenance.log_end (with the exit code) inside the
    // modal pre when the job stops running; without a live region the finish
    // was silent for a screen reader. Same role=log aria-live=polite pair the
    // Compose/Apps/Containers job logs already carry.
    const maintenance = readFileSync(resolve(SRC, 'views/Maintenance.vue'), 'utf8')
    expect(maintenance).toMatch(/<pre role="log" aria-live="polite">\{\{ finiteText\(logText\) \}\}<\/pre>/)
  })
})

describe('dashboard and storage surface leftovers', () => {
  it('exposes the Dashboard metric-range selection with aria-pressed', () => {
    // The chosen range (1h…1y) is signalled by the `primary` tint alone. The
    // "selected state" sweep above only matches `:class="{ active: … }"`, so
    // this ternary-class variant slipped through it: paint for a sighted
    // reader, nothing for anyone else.
    const dashboard = readFileSync(resolve(SRC, 'views/Dashboard.vue'), 'utf8')
    const chip = dashboard.match(/<button[^>]*v-for="r in METRIC_RANGES"[\s\S]*?>/)
    expect(chip, 'metric range chips').toBeTruthy()
    expect(chip[0]).toMatch(/:aria-pressed="metricRange === r"/)
  })

  it('spells the Dashboard standalone LED states, not just their colour', () => {
    // Four LEDs sit outside any table, so the sr-only status_led column-header
    // convention cannot cover them: the member service cards (the sub line
    // prefers free-text detail over the state word), the attention list
    // (warn vs down), the recent alerts (severity), and the failed health
    // checks (error vs warn). Same fix as the WireGuard ping rows: hide the
    // paint, put the word beside it. ledText reuses the Services state keys,
    // so no new locale strings.
    // The Docker table LED joined the sweep: it sits under the sr-only
    // status_led header, but the visible Status column is col-hide-m, so on
    // a phone the dot is the row's only state — the Containers page rule.
    const dashboard = readFileSync(resolve(SRC, 'views/Dashboard.vue'), 'utf8')
    expect(dashboard).toMatch(/function ledText\(state\)[\s\S]*t\('services\.state_ok'\)[\s\S]*t\('services\.state_down'\)/)
    const spelled = dashboard.match(/class="led" :class="led\((?:s\.state|c\.state)\)" aria-hidden="true"><\/span>\s*<span class="sr-only">\{\{ ledText\(/g) || []
    expect(spelled.length, 'member card + attention list + docker table LEDs carry sr-only state text').toBe(3)
    expect(dashboard, 'no Dashboard LED ships colour-only').not.toMatch(/class="led" :class="led\([^)]*\)"><\/span>/)
    expect(dashboard).toMatch(/a\.level === 'ok' \? 'on' : \(a\.level === 'warn' \? 'warn' : 'err'\)" aria-hidden="true"><\/span>\s*<span class="sr-only">\{\{ a\.level === 'ok' \? t\('common\.ok'\) : \(a\.level === 'warn' \? t\('common\.warn'\) : t\('common\.error'\)\) \}\}/)
    expect(dashboard).toMatch(/c\.level === 'error' \? 'err' : 'warn'" aria-hidden="true"><\/span>\s*<span class="sr-only">\{\{ c\.level === 'error' \? t\('common\.error'\) : t\('common\.warn'\) \}\}/)
    // The bookmark-card LED only repeats bmLabel's up/stopped/down text in
    // colour, so it is decoration — same treatment as the Bookmarks page.
    expect(dashboard).toMatch(/class="led" :class="bmLed\(b\)" aria-hidden="true"/)
  })

  it('keeps the Dashboard attention tile from reading unloaded as healthy-empty', () => {
    // Before status resolves, attention is [] because nothing was read, not
    // because everything is healthy: the status-gated ok branch fell through
    // to an empty .alert-list that said nothing at all — silent load
    // presented as empty, the same gap the ports/volumes rows already close.
    const dashboard = readFileSync(resolve(SRC, 'views/Dashboard.vue'), 'utf8')
    expect(dashboard).toMatch(/<div v-if="!status" class="sub">\{\{ loadError \? t\('common\.load_failed'\) : t\('common\.loading'\) \}\}<\/div>\s*<div v-else-if="!asArray\(attention\)\.length" class="sub ok-msg">\{\{ t\('dashboard\.all_ok'\) \}\}<\/div>/)
    expect(dashboard).not.toMatch(/v-if="status && !attention\.length"/)
  })

  it('announces the Dashboard live service counts as status regions', () => {
    // Both service_count summaries (member header, attention tile) update
    // silently on every status poll — the count is the poll's whole answer,
    // so it gets role=status like the Scheduler/VMs/Users toolbar counts.
    // The attention tile wraps its badge and count in one region so a poll
    // that moves both reads as one announcement.
    const dashboard = readFileSync(resolve(SRC, 'views/Dashboard.vue'), 'utf8')
    const counts = dashboard.match(/\{\{ t\('dashboard\.services_count'/g) || []
    expect(counts.length, 'both services_count copies are present').toBe(2)
    expect(dashboard).toMatch(/<span role="status">\{\{ t\('dashboard\.services_count'/)
    expect(dashboard).toMatch(/<span role="status">\s*<span class="badge" :class="asArray\(attention\)\.length \? 'down' : 'ok'">\{\{ asArray\(attention\)\.length \}\}<\/span>/)
    expect(dashboard, 'no services_count copy ships without a live region').not.toMatch(/<span>\{\{ t\('dashboard\.services_count'/)
  })

  it('drops the Dashboard skeleton once a failed first load is on record', () => {
    // The comment above the skeleton promised the loadError gate but the
    // condition never carried it: a failed first admin load rendered the
    // failure banner with the placeholder still pulsing beneath it,
    // presented as if data were on the way. The behavioural half lives in
    // Dashboard.loadFailure.test.js.
    const dashboard = readFileSync(resolve(SRC, 'views/Dashboard.vue'), 'utf8')
    expect(dashboard).toMatch(/v-else-if="!host && !sensors && !loadError"/)
  })

  it('announces the Files item count as a live region', () => {
    // The count is the answer to Refresh / navigation / delete and changed
    // silently for a screen reader — same treatment as the Modules count.
    const files = readFileSync(resolve(SRC, 'views/Files.vue'), 'utf8')
    expect(files).toMatch(/class="meta-count" role="status" v-if="listing">\{\{ finiteN\(recGet\(listing, 'count'\)\) \}\} \{\{ t\('files\.items'\) \}\}/)
  })

  it('names the MainArray SMART attribute expander and carries its open state', () => {
    // The visible face is a glyph and a count ("▼ 12"), which is also what a
    // screen reader announced — nothing said what expands, and nothing said
    // whether it already had.
    const mainArray = readFileSync(resolve(SRC, 'views/MainArray.vue'), 'utf8')
    const toggle = mainArray.match(/<button[^>]*v-if="asArray\(recGet\(recGet\(m, 'smart'\), 'attrs'\)\)\.length"[\s\S]*?>/)
    expect(toggle, 'SMART attribute expander').toBeTruthy()
    expect(toggle[0]).toMatch(/:aria-label="t\('main_extra\.smart_attrs_toggle'/)
    expect(toggle[0]).toMatch(/:aria-expanded="smartExpanded\.has\(recGet\(m, 'id'\)\)"/)
  })

  it('announces the MainArray SMART overview load failure inside its dialog', () => {
    // The overview loads after the dialog already holds focus, so the
    // panel-focus read never covers it — same as the Scheduler run-history
    // and Shares ACL errors.
    const mainArray = readFileSync(resolve(SRC, 'views/MainArray.vue'), 'utf8')
    expect(mainArray).toMatch(/v-if="smartError && !smartData" role="alert"/)
  })

  it('names the MainArray format-confirm input after its label, not the placeholder', () => {
    // The bound aria-label used to repeat the "type {name} to confirm"
    // placeholder, so the control was announced as its example value; the
    // static-attribute scan in "control names" cannot see bound duplicates.
    const mainArray = readFileSync(resolve(SRC, 'views/MainArray.vue'), 'utf8')
    const input = mainArray.match(/<input v-model="formatConfirm"[^>]*>/)
    expect(input, 'format confirm input').toBeTruthy()
    expect(input[0]).toMatch(/:aria-label="t\('main_extra\.confirm'\)"/)
    expect(input[0]).not.toMatch(/:aria-label="t\('main_extra\.format_type_ph'/)
  })

  it('announces the VMs count and hypervisor availability as a status region', () => {
    // The title-meta count (and the UTM/Orb ✓/— marks beside it) is the only
    // feedback Refresh and the 15s poll give, and it changed silently for a
    // screen reader — same treatment as the Users and Apps toolbar counts.
    const vms = readFileSync(resolve(SRC, 'views/VMs.vue'), 'utf8')
    expect(vms).toMatch(/<span class="meta" role="status">\s*\{\{ t\('vms\.meta'/)
  })

  it('announces the PhotosHub pending count and empty state as status regions', () => {
    // "Refresh pending list" and "Remove" answer only through the count and
    // the tiles (or the scanning -> "no pending" flip on an empty album);
    // both changed silently for a screen reader — the Files item-count and
    // Logs empty/loading treatment.
    const photoshub = readFileSync(resolve(SRC, 'views/PhotosHub.vue'), 'utf8')
    expect(photoshub).toMatch(/data-test="photoshub-pending-count"[^>]*>|role="status" data-test="photoshub-pending-count"/)
    expect(photoshub).toMatch(/<span v-if="pending" class="meta-count" role="status"/)
    expect(photoshub).toMatch(/data-test="photoshub-pending-empty" role="status"/)
  })

  it('announces the Backups truncation count and keeps the failed list honest', () => {
    // The truncation note is the only summary of how many backups exist and
    // appears/updates silently after every finished backup or refresh — the
    // Ollama model-count / VMs header-count treatment.  And a failed *first*
    // read must render the banner alone: a header-only table under it read
    // as an empty backup listing, on the page where "not listed" means
    // "gone" (the Containers LoadFailure contract).
    const backups = readFileSync(resolve(SRC, 'views/Backups.vue'), 'utf8')
    expect(backups).toMatch(/<p v-if="hiddenCount" class="meta"[^>]*role="status">/)
    expect(backups).toMatch(/<SkeletonLoader v-if="!loaded && !loadError"/)
    expect(backups).toMatch(/v-else-if="!loadError \|\| asArray\(backups\)\.length" class="table-wrap backups-artefacts"/)
  })

  it('does not shadow the VMs create-dialog labels with placeholder aria-labels', () => {
    // Each input has a for/id <label> ("Version", "Machine name"). The bound
    // aria-labels that used to sit on top overrode them with the placeholder,
    // so both fields were announced as their example values — same shadowing
    // the PhotosHub people labels had.
    const vms = readFileSync(resolve(SRC, 'views/VMs.vue'), 'utf8')
    for (const id of ['vm-create-version', 'vm-create-name']) {
      expect(vms, `${id} must keep its for/id label`).toContain(`for="${id}"`)
      const input = vms.match(new RegExp(`<input id="${id}"[^>]*>`))
      expect(input, `input #${id}`).toBeTruthy()
      expect(input[0], `${id}: aria-label overrides the visible label`)
        .not.toMatch(/aria-label/)
    }
  })
})

describe('backup and workload surface leftovers', () => {
  it('announces the Backups dry-run preview load failure inside its dialog', () => {
    // The preview loads after the dialog already holds focus, so the
    // panel-focus read never covers it — same as the Scheduler run-history
    // and MainArray SMART overview errors.
    const backups = readFileSync(resolve(SRC, 'views/Backups.vue'), 'utf8')
    expect(backups).toMatch(/v-else-if="previewError"[^>]*role="alert"/)
  })

  it('names each Apps autostart switch after its app', () => {
    // Three per-row copies (managed table mobile + desktop, autostart tab)
    // all announced as "Autostart" — indistinguishable in a form-controls
    // listing, same fix as the Scheduler enable toggles. The detail drawer's
    // single switch keeps the plain label: the dialog is already named after
    // the app.
    const apps = readFileSync(resolve(SRC, 'views/Apps.vue'), 'utf8')
    const named = apps.match(/:aria-label="t\('apps\.autostart_name',\s*\{\s*name:/g) || []
    expect(named.length, 'per-row autostart switches named after their app').toBe(3)
    const plain = apps.match(/:aria-label="t\('apps\.col_autostart'\)"/g) || []
    expect(plain.length, 'only the detail drawer keeps the plain label').toBe(1)
  })

  it('announces the Apps managed and autostart count breakdowns', () => {
    // Both breakdowns are the only answer Refresh (and Run now) gives, and
    // they changed silently for a screen reader while the two sibling
    // .meta-count filter spans on the same page already carried role=status.
    const apps = readFileSync(resolve(SRC, 'views/Apps.vue'), 'utf8')
    expect(apps).toMatch(/class="meta-count" role="status" v-if="recGet\(managed, 'counts'\)"/)
    expect(apps).toMatch(/class="meta-count" role="status" v-if="autostart\.counts"/)
    expect(apps).not.toMatch(/class="meta-count" v-if=/)
  })

  it('names each Apps docker restart-policy select after its container', () => {
    // Same column-of-identical-controls gap as the autostart switches: every
    // row's select was announced as "Restart policy".
    const apps = readFileSync(resolve(SRC, 'views/Apps.vue'), 'utf8')
    expect(apps).toMatch(/:aria-label="t\('apps\.policy_name',\s*\{\s*name:/)
    expect(apps).not.toMatch(/:aria-label="t\('docker\.restart_policy'\)"/)
  })

  it('never re-declares a native button as role=button', () => {
    // The Apps "Detail" button carried tabindex/role/keydown copied from the
    // non-button hotspots (Services problem chips). Redundant on a <button>,
    // and the copied @keydown.enter.prevent suppressed the element's native
    // activation to substitute its own.
    const offenders = []
    for (const [name, src] of vueFiles()) {
      if (/<button[^>]*role="button"/.test(src)) offenders.push(name)
    }
    expect(offenders, 'a <button> is already a button; role/tabindex belong on non-button hotspots').toEqual([])
  })

  it('announces the Apps remote-catalog source load failure inside its modal', () => {
    // The source config loads after the modal already holds focus, and a
    // failure used to leave it silently blank — neither "not configured" nor
    // the overrides table rendered, so a dead read looked like a fresh
    // install once the toast faded.
    const apps = readFileSync(resolve(SRC, 'views/Apps.vue'), 'utf8')
    expect(apps).toMatch(/v-if="remoteError"[^>]*role="alert"/)
    expect(apps).toMatch(/remoteError\.value = finiteText/)
  })

  it('spells the Network binding-table interface state, not just its LED colour', () => {
    // The status column of the multi-IP bindings table is the LED alone (the
    // interfaces tab pairs its LED with a textual badge); colour is invisible
    // to a screen reader. Both copies: the addressed rows and the
    // no-IPv4 row.
    const network = readFileSync(resolve(SRC, 'views/Network.vue'), 'utf8')
    const spelled = network.match(/class="sr-only">\{\{ iface\.up \? t\('network\.on'\) : t\('network\.off'\) \}\}/g) || []
    expect(spelled.length, 'both binding-table status cells carry sr-only text').toBe(2)
  })

  it('hides the Network interfaces-tab LED that the Status column already spells', () => {
    // The interfaces tab pairs its LED with a textual status badge, so the
    // dot is decoration — but it carried no aria-hidden, leaving AT a column
    // named "status LED" whose cells said nothing. Spelling it there instead
    // would have duplicated the Status column one cell over.
    const network = readFileSync(resolve(SRC, 'views/Network.vue'), 'utf8')
    expect(network).toMatch(/class="led" :class="i\.up \? 'on' : 'off'" aria-hidden="true"/)
    expect(network).not.toMatch(/class="led" :class="i\.up \? 'on' : 'off'"><\/span>/)
  })

  it('announces the Terminal container-discovery failure', () => {
    // This inline line is the only surface the failure reaches (no toast, no
    // banner), so without role=alert it appeared silently for AT.
    const terminal = readFileSync(resolve(SRC, 'views/Terminal.vue'), 'utf8')
    expect(terminal).toMatch(/v-if="containerListError"[^>]*role="alert"/)
  })

  it('renders the Terminal status load failure as the standard retryable banner', () => {
    // A failed status read leaves `status` null, which keeps the host Run
    // button disabled; the only stated reason was a toast that faded in four
    // seconds. The behavioural half lives in Terminal.test.js.
    const terminal = readFileSync(resolve(SRC, 'views/Terminal.vue'), 'utf8')
    expect(terminal).toMatch(/<LoadFailure v-if="statusError"[^>]*:retry="load"/)
  })

  it('voices the Terminal dialog connection state', () => {
    // The status dot's colour was the only connected/disconnected cue, and
    // the transition was silent for a screen reader — the VNC console beside
    // it already carries an aria-live status label for the same handshake.
    const terminal = readFileSync(resolve(SRC, 'views/Terminal.vue'), 'utf8')
    expect(terminal).toMatch(/class="status-dot" :class="\{ live: connected \}" aria-hidden="true"/)
    expect(terminal).toMatch(/class="sr-only" role="status">\{\{ connected \? t\('terminal\.a11y_connected'\) : t\('terminal\.a11y_disconnected'\) \}\}/)
  })
})

describe('settings and users surface leftovers', () => {
  it('renders every Settings bundle-backed tab failure as the standard retryable banner', () => {
    // Date & Time, Network, Shares, Scheduler and Access got the LoadFailure
    // banner in the first sweep; Power, Disk and VMs kept only a colored line
    // in their *second* card — no role=alert, no retry, and the primary card
    // rendered bare headings indistinguishable from "still loading". Eight
    // tabs read from the bundle, so eight banners. The behavioural half lives
    // in Settings.sysBundle.test.js.
    const settings = readFileSync(resolve(SRC, 'views/Settings.vue'), 'utf8')
    const banners = settings.match(/<LoadFailure v-if="sysBundleError && !sysBundle"[^>]*:retry="loadSysBundle"/g) || []
    expect(banners.length, 'every bundle-backed tab carries the retryable banner').toBe(8)
  })

  it('names the UPS shutdown stack and script checkboxes after their display name', () => {
    // Both pickers used to name each checkbox with the raw machine id while
    // the row displayed a human name — a screen reader hearing "stack:immich"
    // cannot match it to the "Immich" a sighted user is told to tick.
    const settings = readFileSync(resolve(SRC, 'views/Settings.vue'), 'utf8')
    expect(settings).toMatch(/:aria-label="finiteText\(asRecord\(row\)\.name, ''\) \|\| finiteText\(asRecord\(row\)\.id\)"/)
    expect(settings).toMatch(/:aria-label="finiteText\(asRecord\(s\)\.name, ''\) \|\| finiteText\(asRecord\(s\)\.id\)"/)
    expect(settings).not.toMatch(/:aria-label="finiteText\(row\.id\)"/)
    expect(settings).not.toMatch(/:aria-label="finiteText\(s\.id\)"/)
  })

  it('keeps the UPS load banner over stale data and announces the drill verdict', () => {
    // The banner was gated on !upsInfo, so a failed *re*-load (tab revisit
    // with the backend down) was toast-only while the stale form sat there
    // as if fresh — the Containers/Alerts LoadFailure contract. And the
    // drill verdict is the whole outcome of the drill button press, landing
    // silently after it — the Scheduler run-history treatment.
    const settings = readFileSync(resolve(SRC, 'views/Settings.vue'), 'utf8')
    expect(settings).toMatch(/<LoadFailure v-if="upsError" :detail="upsError" :retry="loadUps" \/>/)
    expect(settings).not.toMatch(/upsError && !upsInfo/)
    expect(settings).toMatch(/data-test="drill-result">[\s\S]{0,400}?<p class="hint" role="status"/)
  })

  it('spells and announces the Dashboard UPS chip state the colour carries', () => {
    // The red paint (danger class) used to be the only low-battery signal —
    // nothing at all for a screen reader (the Containers/Network LED rule) —
    // and mid-outage the poll flipped engaged/restoring silently. The
    // battery glyph repeats the percent + state word, so it is decoration.
    const dash = readFileSync(resolve(SRC, 'views/Dashboard.vue'), 'utf8')
    expect(dash).toMatch(/<span v-if="upsStateLabel" role="status">\{\{ upsStateLabel \}\}<\/span>/)
    expect(dash).toMatch(/upsLow\.value\) return t\('dashboard\.ups_low'\)/)
    expect(dash).toMatch(/<component :is="upsIcon" :size="13" aria-hidden="true" \/>/)
  })

  it('keeps the visible Username label inside the 2FA rescue input name', () => {
    // The old aria-label repeated the section heading ("Rescue another
    // account"), so the field's visible "Username" label was nowhere in its
    // accessible name — a speech-input user saying what they see could not
    // reach it (WCAG 2.5.3). The dedicated key keeps the rescue context so
    // the control stays distinguishable from the password card's username.
    const settings = readFileSync(resolve(SRC, 'views/Settings.vue'), 'utf8')
    const input = settings.match(/<input v-model\.trim="twofaResetUser"[^>]*>/)
    expect(input, '2FA rescue username input').toBeTruthy()
    expect(input[0]).toMatch(/:aria-label="t\('twofa\.admin_reset_user'\)"/)
    expect(input[0]).not.toMatch(/:aria-label="t\('twofa\.admin_reset'\)"/)
  })

  it('names the Users reset-password input after the password it takes, not the button', () => {
    // The input's accessible name used to be "Reset password" — identical to
    // the button beside it and hiding the visible "New password" placeholder,
    // so the field and its action were announced the same.
    const users = readFileSync(resolve(SRC, 'views/Users.vue'), 'utf8')
    const input = users.match(/<input\s+v-model="resetPassword"[\s\S]*?>/)
    expect(input, 'reset-password input').toBeTruthy()
    expect(input[0]).toMatch(/:aria-label="t\('settings\.new_password'\)"/)
    expect(input[0]).not.toMatch(/:aria-label="t\('accounts\.reset_password'\)"/)
  })
})

describe('llm, photos, vpn and health surface leftovers', () => {
  it('latches the Ollama settings read failure and blocks Save behind it', () => {
    // Same hole the WireGuard settings dialog had: the form falls back to
    // literal defaults on a failed read, Save sends every field, so saving on
    // top of a failure silently wiped a configured LaunchAgent label — and
    // the old catch produced no toast and no inline text at all. The
    // behavioural half lives in Ollama.test.js.
    const ollama = readFileSync(resolve(SRC, 'views/Ollama.vue'), 'utf8')
    expect(ollama).toMatch(/v-if="!ollamaSettingsLoaded && ollamaSettingsError"[\s\S]{0,120}role="alert"/)
    expect(ollama).toMatch(/@click="loadOllamaSettings"/)
    expect(ollama).toMatch(/:disabled="ollamaSaving \|\| !ollamaSettingsLoaded"/)
    expect(ollama).toMatch(/async function saveOllamaSettings\(\) \{[\s\S]{0,300}if \(!ollamaSettingsLoaded\.value\)/)
    expect(ollama).toMatch(/ollamaSettingsError\.value = finiteText/)
  })

  it('names the two Ollama copy buttons after what they copy', () => {
    // The service card holds two "Copy" buttons side by side copying
    // different URLs; announced identically, a form-controls listing cannot
    // tell them apart. The visible "Copy" stays first in the accessible name
    // (WCAG 2.5.3 label-in-name).
    const ollama = readFileSync(resolve(SRC, 'views/Ollama.vue'), 'utf8')
    expect(ollama).toMatch(/:aria-label="t\('ollama\.copy_name', \{ name: t\('ollama\.api'\) \}\)"/)
    expect(ollama).toMatch(/:aria-label="t\('ollama\.copy_name', \{ name: t\('ollama\.openai_api'\) \}\)"/)
  })

  it('announces the Ollama installed-model count as a live region', () => {
    // The count is the 10s poll's (and a finished pull/delete's) only
    // summary of the model list and changed silently for a screen reader —
    // same treatment as the VMs title-meta and Health summary counts.
    const ollama = readFileSync(resolve(SRC, 'views/Ollama.vue'), 'utf8')
    expect(ollama).toMatch(/<span v-if="asArray\(models\)\.length" class="meta" role="status">\{\{ t\('ollama\.models_count'/)
  })

  it('keeps the Ollama tables honest about a failed list read', () => {
    // reachable=true with `error` set means /api/version answered but
    // /api/tags//api/ps failed; both empty rows must route through the
    // helper that says so instead of claiming "no models". The behavioural
    // half lives in Ollama.test.js.
    const ollama = readFileSync(resolve(SRC, 'views/Ollama.vue'), 'utf8')
    expect(ollama).toMatch(/\{\{ emptyListText\('ollama\.resident_empty'\) \}\}/)
    expect(ollama).toMatch(/\{\{ emptyListText\('ollama\.models_empty'\) \}\}/)
    expect(ollama).toMatch(/function emptyListText\(emptyKey\)[\s\S]{0,220}t\('ollama\.list_error'/)
  })

  it('spells the WireGuard ping outcome, not just its LED colour', () => {
    // The ping-result rows carried reachability in the LED class alone —
    // unlike the peers table there is no textual badge, so a screen reader
    // heard name and IP with nothing saying whether the ping came back. Same
    // fix as the Network binding-table interface state.
    const wireguard = readFileSync(resolve(SRC, 'views/WireGuard.vue'), 'utf8')
    expect(wireguard).toMatch(
      /class="sr-only">\{\{ recGet\(r, 'reachable'\) \? t\('wg.reachable'\) : t\('wg.unreachable'\) \}\}/,
    )
  })

  it('announces the PhotosHub action-running note', () => {
    // The actions run for seconds and disable the toolbar; the note beside
    // them was paint only, so a screen-reader user heard nothing between the
    // click and the finish toast. Same shape as the Shares busy note.
    const photoshub = readFileSync(resolve(SRC, 'views/PhotosHub.vue'), 'utf8')
    expect(photoshub).toMatch(/v-if="busy"[^>]*role="status"[^>]*aria-live="polite"/)
  })

  it('spells the Health overall tile state instead of an emoji alone', () => {
    // The issues arm was a bare "⚠️" — announced as "warning sign" at best,
    // with no words and no locale parity with the healthy arm.
    const health = readFileSync(resolve(SRC, 'views/Health.vue'), 'utf8')
    expect(health).toMatch(/recGet\(data, 'healthy'\) \? '✅ ' \+ t\('common\.healthy'\) : '⚠️ ' \+ t\('common\.issues'\)/)
    expect(health).not.toMatch(/\{\{ data\.healthy \? '✅ OK' : '⚠️' \}\}/)
  })

  it('announces the Health toolbar summary counts', () => {
    // The passed/warnings/errors counts are the toolbar's answer to the
    // Rescan click beside them, and they updated silently for a screen
    // reader — the same role=status the Users toolbar count carries. The
    // behavioural half lives in Health.test.js.
    const health = readFileSync(resolve(SRC, 'views/Health.vue'), 'utf8')
    expect(health).toMatch(/class="meta hide-m" v-if="data\?\.summary" role="status"/)
  })

  it('marks the Health check LED as decoration', () => {
    // The LED repeats the Level badge's Pass/Warn/Error text in colour only
    // (same as the Users admin LED).
    const health = readFileSync(resolve(SRC, 'views/Health.vue'), 'utf8')
    expect(health).toMatch(/class="led" :class="led\(c\)" aria-hidden="true"/)
  })
})

describe('brew and gateway surface leftovers', () => {
  it('announces the Brew action-running note', () => {
    // brew services start/stop/restart runs for seconds (the list call alone
    // is allowed 20s) and act() greys out every button for the duration;
    // before the note that state was paint only — a screen-reader user heard
    // nothing between the click and the finish toast. Same shape as the
    // PhotosHub/Shares busy notes; the behavioural half lives in Brew.test.js.
    const brew = readFileSync(resolve(SRC, 'views/Brew.vue'), 'utf8')
    expect(brew).toMatch(/v-if="busy"[^>]*role="status"[^>]*aria-live="polite"/)
    expect(brew).toContain("t('brew.action_running'")
  })

  it('marks the Brew status LED as decoration', () => {
    // The LED repeats the Status badge's started/stopped text in colour only
    // — same treatment as the Health check LED one table over.
    const brew = readFileSync(resolve(SRC, 'views/Brew.vue'), 'utf8')
    expect(brew).toMatch(/class="led" :class="asRecord\(s\)\.state==='ok'\?'on':\(asRecord\(s\)\.state==='warn'\?'warn':'err'\)" aria-hidden="true"/)
  })

  it('tells a filtered-out Brew list apart from an empty one', () => {
    // "No Homebrew services found" beside a non-empty count misreported the
    // host whenever the filter simply matched nothing — the same split the
    // Network ports and Tools process tables already carry. The behavioural
    // half lives in Brew.test.js.
    const brew = readFileSync(resolve(SRC, 'views/Brew.vue'), 'utf8')
    expect(brew).toMatch(/q\.trim\(\) \? t\('common\.no_match'\) : t\('brew\.empty'\)/)
  })

  it('hides the Gateway status LED from the accessibility tree', () => {
    // The LED only repeats the Running/Stopped text beside it in colour, so
    // it is decoration — same treatment as the VMs and Network inline LEDs.
    // (Table-cell LEDs are covered by their sr-only column header instead.)
    const gateway = readFileSync(resolve(SRC, 'views/Gateway.vue'), 'utf8')
    expect(gateway).toMatch(/class="led" :class="recGet\(data, 'running'\) \? 'on' : 'err'" aria-hidden="true"/)
  })
})

describe('bookmarks and modules surface leftovers', () => {
  const bookmarks = readFileSync(resolve(SRC, 'views/Bookmarks.vue'), 'utf8')
  const modules = readFileSync(resolve(SRC, 'views/Modules.vue'), 'utf8')

  it('announces the Bookmarks summary and hides the card LEDs', () => {
    // The up/stopped/down summary is the answer to the Force check click and
    // changed silently for a screen reader; the LED only repeats the badge
    // text in colour, so it is decoration — same treatment as the Gateway
    // LED above. The behavioural half lives in Bookmarks.test.js.
    expect(bookmarks).toMatch(/<span class="meta" role="status" v-if="data">/)
    expect(bookmarks).toMatch(/class="led" :class="ledClass\(b\)" aria-hidden="true"/)
  })

  it('announces the Modules count and disables Refresh while loading', () => {
    // The count is the answer to the Refresh click (Tools syslog/ports
    // convention), and Refresh used to stay clickable during a load — each
    // extra click bumped the generation and threw the earlier answers away.
    // The behavioural half lives in Modules.test.js.
    expect(modules).toMatch(/class="meta-count" role="status">\{\{ t\('modules\.count_n'/)
    expect(modules).toMatch(/@click="load" :disabled="loading"/)
    expect(modules).toMatch(/<LoadFailure v-if="loadError" :detail="loadError" :retry="load" :busy="loading" \/>/)
  })
})

describe('files surface leftovers', () => {
  const files = readFileSync(resolve(SRC, 'views/Files.vue'), 'utf8')

  it('announces the Files item count', () => {
    // The count is the toolbar's answer to every navigation, upload and
    // delete, and it changed silently for a screen reader — the same
    // role=status every sibling list page already carries on .meta-count.
    // The behavioural half lives in Files.test.js.
    expect(files).toMatch(/class="meta-count" role="status" v-if="listing">\{\{ finiteN\(recGet\(listing, 'count'\)\) \}\}/)
  })

  it('keeps the upload input reachable by keyboard', () => {
    // hidden removed the file input from the tab order and the accessibility
    // tree, so a keyboard or screen-reader user had no way to upload at all —
    // drag-drop is mouse-only. sr-only keeps it focusable and the wrapping
    // label keeps naming it; the ring is drawn on the visible button.
    expect(files).toMatch(/<input type="file" multiple class="sr-only" @change="onUpload" \/>/)
    expect(files).not.toMatch(/<input type="file"[^>]*\bhidden\b/)
    expect(files).toMatch(/\.upload-btn:has\(input:focus-visible\)/)
  })
})

describe('logs and tools surface leftovers', () => {
  const tools = readFileSync(resolve(SRC, 'views/Tools.vue'), 'utf8')

  it('keeps the Tools syslog failure banner above stale lines instead of behind them', () => {
    // The old v-else-if chain put the lines branch first, so once any lines
    // were on screen a failed re-load (level/range change, Refresh) rendered
    // no banner at all — its only trace was a four-second toast. The
    // behavioural half lives in Tools.announcements.test.js.
    expect(tools).toMatch(/<LoadFailure v-if="tabError\.syslog"[\s\S]{0,600}v-if="asArray\(syslog\.lines\)\.length"/)
    expect(tools).not.toMatch(/<LoadFailure v-else-if="tabError\.syslog"/)
    // The syslog and ports loaders are wired straight to toolbar controls that
    // stay clickable above the banner, so a direct retry that worked must also
    // drop it — reload()'s up-front clear never runs on that path.
    expect(tools).toMatch(/syslog\.value = next\s*\n\s*clearTabError\('syslog'\)/)
    expect(tools).toMatch(/ports\.value = next\s*\n\s*clearTabError\('net'\)/)
  })

  it('announces the Tools syslog line count and names its scrollable log box', () => {
    // The count is the answer to the level/range selects and the Refresh
    // click; it changed silently for a screen reader. The box caps at 480px
    // and scrolls, and a scrollable region a keyboard cannot reach cannot be
    // scrolled by one (WCAG 2.1.1) — same treatment as the Logs viewer.
    expect(tools).toMatch(/<span class="meta" role="status">\{\{ t\('tools\.lines_n'/)
    expect(tools).toMatch(/class="log-box mono"\s+tabindex="0"\s+role="region"\s+:aria-label="t\('tools\.tab_syslog'\)"/)
  })

  it('keeps the Tools hardware panes keyboard-scrollable and named', () => {
    // system_profiler output overflows the 240px cap; each pane is named
    // after its own section heading.
    expect(tools).toMatch(/class="mono hw-pre" tabindex="0" role="region" :aria-label="finiteText\(key\)"/)
  })

  it('labels the Tools listening-port count instead of a bare number', () => {
    // This was a lone "12" that said nothing about what it counted, and its
    // own Refresh updated it silently. Reuses the Network summary's
    // "{n} ports" key, so no new locale strings.
    expect(tools).toMatch(/<span class="meta" role="status">\{\{ t\('network\.sum_ports_n', \{ n: finiteN\(ports\.count, 0\) \}\) \}\}<\/span>/)
    expect(tools).not.toMatch(/<span class="meta">\{\{ finiteN\(ports\.count, 0\) \}\}<\/span>/)
  })

  it('announces the Tools scheduler timer count like its syslog/ports siblings', () => {
    // The count is the answer to the Refresh click and it changed silently
    // for a screen reader — the last refresh-driven count on this page
    // without a live region.
    expect(tools).toMatch(/role="status">\{\{ t\('tools\.tasks_n', \{ n: asArray\(timers\)\.length \}\) \}\}<\/span>/)
  })

  it('tells engine-off apart from an empty container-size list', () => {
    // With the engine (or its vanished CLI, now classified by the backend)
    // down, the size list is empty because docker is unreachable — "no data"
    // under a df table saying "engine down" contradicted it. Same split the
    // df table already makes; behavioural half in Tools.dockerEngineOff.test.js.
    expect(tools).toMatch(/df\.engine_up === false \? t\('tools\.engine_off'\) : t\('tools\.no_data'\)[\s\S]{0,2500}df\.engine_up === false \? t\('tools\.engine_off'\) : t\('tools\.no_data'\)/)
  })

  it('keeps the Logs auto-refresh silent on failure but toasts a manual one', () => {
    // Same convention Audit and Alerts pinned: LoadFailure latches the state
    // on screen, and a toast per 6-second tick while the panel is unreachable
    // interrupts a screen reader over and over. The behavioural half lives in
    // Logs.test.js.
    const logs = readFileSync(resolve(SRC, 'views/Logs.vue'), 'utf8')
    expect(logs).toMatch(/async function load\(manual = false\)/)
    expect(logs).toMatch(/if \(manual\) toast/)
    expect(logs).toMatch(/startVisibleInterval\(load, 6000\)/)
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
      'services.uninstall_item_override',
      'services.uninstall_also_delete_tree',
      'services.uninstall_reversible',
    ]) {
      expect(src, `confirmation must show ${key}`).toContain(key)
    }
  })
})

describe('timer lifecycle', () => {
  it('does not overlap async polling requests', () => {
    const offenders = []
    for (const [name, src] of vueFiles()) {
      if (/setInterval\s*\(\s*async\b/.test(src)) {
        offenders.push(`${name}: setInterval(async …) starts another request before the prior one finishes`)
      }
      if (/startVisibleInterval\s*\(\s*async\b/.test(src)) {
        offenders.push(`${name}: startVisibleInterval(async …) hides the same overlap behind the helper`)
      }
    }
    expect(offenders).toEqual([])
    const apps = readFileSync(resolve(SRC, 'views', 'Apps.vue'), 'utf8')
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
            (
              new RegExp(`clear(?:Interval|Timeout)\\s*\\(\\s*${handle}\\b`).test(body) ||
              new RegExp(`\\b${handle}\\s*\\(\\s*\\)`).test(body)
            ) &&
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

  it('wires every role="dialog" through useDismissable, even without a known overlay class', () => {
    // OVERLAY is an allow-list of backdrop class names. A dialog that skips
    // those spellings (or uses a new one) would slip the per-file overlay
    // tests while still trapping the keyboard user behind a box that only
    // closes on a click.
    const offenders = []
    for (const [name, src] of vueFiles()) {
      const dialogs = (src.match(/role="dialog"/g) || []).length
      if (!dialogs) continue
      const wired = (src.match(/useDismissable\(/g) || []).length
      if (wired < dialogs) {
        offenders.push(`${name}: ${dialogs} dialog(s) but ${wired} useDismissable call(s)`)
      }
      if (!/from ['"][^'"]*composables\/useDismissable/.test(src)) {
        offenders.push(`${name}: role="dialog" without a useDismissable import`)
      }
    }
    expect(offenders).toEqual([])
  })
})

describe('mobile chrome', () => {
  const css = readFileSync(resolve(SRC, 'styles.css'), 'utf8')
  const app = readFileSync(resolve(SRC, 'App.vue'), 'utf8')

  it('moves header tools into the drawer instead of shrinking them in the top bar', () => {
    expect(app).toMatch(/<nav[\s\S]*class="top-controls"/)
    expect(css).toMatch(/\.nav-drawer-title\s*\{/)
    expect(css).toMatch(/\.top-status-m\s*\{/)
  })

  it('does not use 100vw for full-bleed sheets (that includes the scrollbar)', () => {
    expect(css).toMatch(/\.modal \{ width: 100%; max-width: 100%/)
    expect(css).toMatch(/\.drawer \{ width: 100%; \}/)
    expect(css).toMatch(/\.cmd-palette \{\s*width: min\(520px, 100%\)/)
    expect(css).toMatch(/\.assist-panel \{\s*width: min\(640px, 100%\)/)
  })

  it('keeps a one-line page footer instead of a reserved FAB well', () => {
    expect(css).toMatch(/\.main \{ padding: 10px 10px max\(28px/)
  })

  it('keeps the drawer tool strip on a single row', () => {
    expect(css).toMatch(/\.top-controls \{[\s\S]*?flex-direction: row/)
    expect(css).toMatch(/\.top-controls \{[\s\S]*?flex-wrap: nowrap/)
  })

  it('keeps the section nav on one scrolling row instead of wrapping', () => {
    expect(css).toMatch(/\.subchrome-inner \{\s*[\s\S]*?flex-wrap: nowrap/)
  })

  it('sizes page sheets with % not vw (except fullscreen VNC)', () => {
    const skip = new Set(['components/VncConsole.vue'])
    const offenders = []
    for (const [name, src] of vueFiles()) {
      if (skip.has(name)) continue
      if (/width:\s*min\([^;]*vw/.test(src) || /(?:^|[^\d])width:\s*\d+vw/.test(src)) {
        offenders.push(name)
      }
    }
    expect(offenders).toEqual([])
  })

  it('lets common flex rows wrap instead of stretching the page', () => {
    expect(css).toMatch(/\.section-title \{ flex-wrap: wrap/)
    expect(css).toMatch(/\.alert-item \{ flex-wrap: wrap/)
    expect(css).toMatch(/\.row \{ flex-wrap: wrap/)
    expect(css).toMatch(/\.kv \{ grid-template-columns: minmax\(0, 90px\)/)
  })

  it('drops low-priority table columns on the phone without keeping a 560px floor', () => {
    expect(css).toMatch(/\.col-hide-m \{ display: none/)
    expect(css).toMatch(/table\.dense\.fit-m \{ min-width: 0/)
    expect(css).toMatch(/@media \(min-width: 641px\)[\s\S]*?\.show-m \{ display: none/)
  })

  it('lets table action clusters wrap instead of stretching a thinned table', () => {
    expect(css).toMatch(/table\.dense \.ops,\s*table\.dense \.actions,\s*table\.dense \.actions-cell \{\s*white-space: normal/)
    expect(css).toMatch(/\.hide-m \{ display: none/)
    expect(css).toMatch(/\.cmd-palette input \{ font-size: 16px/)
  })

  it('collapses page form grids at the phone breakpoint, not a wider 700px cut', () => {
    const offenders = []
    for (const [name, src] of vueFiles()) {
      if (/@media \(max-width: 700px\)/.test(src)) offenders.push(name)
    }
    expect(offenders).toEqual([])
  })
})

describe('mobile table overflow', () => {
  /**
   * Every `<table class="dense">` must sit inside a `.table-wrap`, the shared
   * horizontal-overflow container (styles.css). Without it a table wider than
   * its card does not scroll on a 390px phone — it stretches the whole page,
   * and every dialog and toolbar rendered at viewport width stretches with it.
   * This regressed piecemeal: the pattern was applied to whichever table
   * someone had just seen overflow (Backups, then the Dashboard top-CPU tile)
   * while ten siblings shipped bare.
   *
   * Scope is deliberately the shared .dense class. Apps.vue's .managed-table /
   * .mini-table own a different strategy (a dedicated wrap div, and
   * word-break inside the detail drawer respectively), and a nested sub-table
   * scrolls with the wrapped parent it lives in.
   */
  const NESTED_INSIDE_WRAPPED_PARENT = { 'views/MainArray.vue': 1 }

  it('keeps every dense table inside a .table-wrap', () => {
    const offenders = []
    for (const [name, src] of vueFiles()) {
      let bare = 0
      for (const m of src.matchAll(/<table class="dense"/g)) {
        // House pattern puts the wrap opener on the line right above the
        // table, so a short lookback is enough — and stays short so one
        // table's wrapper cannot vouch for the next table down the file.
        const before = src.slice(Math.max(0, m.index - 260), m.index)
        if (!before.includes('table-wrap')) bare++
      }
      const allowed = NESTED_INSIDE_WRAPPED_PARENT[name] || 0
      if (bare > allowed) {
        offenders.push(`${name}: ${bare - allowed} dense table(s) outside .table-wrap`)
      }
    }
    expect(
      offenders,
      'tables without .table-wrap overflow the page on a 390px phone',
    ).toEqual([])
  })
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

  it('does not invent a Tools-specific tab chrome', () => {
    const offenders = []
    for (const [name, src] of vueFiles()) {
      if (src.includes('tools-tabs') || /class="tools-tab"/.test(src)) {
        offenders.push(name)
      }
    }
    expect(offenders).toEqual([])
  })
})

describe('appearance controls', () => {
  it('names the login locale select', () => {
    const login = readFileSync(resolve(__dirname, 'Login.vue'), 'utf8')
    expect(login).toMatch(/login-locale[\s\S]*aria-label="t\('appearance\.language'\)"/)
  })

  it('exposes theme and density selection with aria-pressed', () => {
    const settings = readFileSync(resolve(__dirname, 'Settings.vue'), 'utf8')
    expect(settings).toMatch(/class="theme-card"[\s\S]*:aria-pressed="\(appliedTheme \?\? theme\) === th\.id"/)
    expect(settings).toMatch(/:aria-pressed="density === d\.id"/)
  })

  it('names the admin password field instead of relying on its placeholder', () => {
    const admin = readFileSync(resolve(SRC, 'components/AdminPasswordDialog.vue'), 'utf8')
    expect(admin).toMatch(/aria-label="t\('adminPrompt.password'\)"/)
    expect(admin).not.toMatch(/placeholder="t\('adminPrompt.password'\)"/)
  })
})

/**
 * The opening tag containing *index*, quote-aware so that a `=>` inside a
 * handler cannot be mistaken for the end of the tag.
 */
function openingTagAt(source, index) {
  const start = source.lastIndexOf('<', index)
  let quote = null
  for (let i = start; i < source.length; i += 1) {
    const ch = source[i]
    if (quote) {
      if (ch === quote) quote = null
      continue
    }
    if (ch === '"' || ch === "'") {
      quote = ch
      continue
    }
    if (ch === '>') return source.slice(start, i + 1)
  }
  return source.slice(start)
}

const ACTIVE_CLASS = /:class="\{[^"]*\bactive:/g
const ARIA_STATE = /\baria-(pressed|selected|current|checked)\b/

describe('selected state', () => {
  it('exposes every "active" highlight to assistive technology', () => {
    // The panel signals the current choice -- filter chip, tab, nav link,
    // theme card -- by adding an `active` class.  That is paint: it reaches
    // a sighted reader and nobody else.  Most of these controls already
    // carried aria-pressed, which is exactly why the handful that did not
    // went unnoticed: the state chips on Services, the language buttons in
    // Settings (directly above a theme grid that did have it), the category
    // pills on Apps, and both levels of the main nav.
    const unannounced = []
    for (const [name, source] of vueFiles()) {
      for (const match of source.matchAll(ACTIVE_CLASS)) {
        const tag = openingTagAt(source, match.index)
        if (!ARIA_STATE.test(tag)) {
          unannounced.push(`${name}: ${tag.replace(/\s+/g, ' ').slice(0, 100)}`)
        }
      }
    }
    expect(unannounced).toEqual([])
  })

  it('finds the highlights it is meant to be checking', () => {
    // A scan that silently matches nothing passes for ever.  These are the
    // shapes in the tree today; the count only has to stay plausible.
    const found = vueFiles().reduce(
      (n, [, source]) => n + [...source.matchAll(ACTIVE_CLASS)].length,
      0,
    )
    expect(found).toBeGreaterThan(20)
  })

  it('announces the bulk-selection count on Services', () => {
    // Checking a row updates "{n} selected" inside a bar that only exists
    // while something is selected; without a live region a screen-reader
    // user hears nothing change as they select or deselect services.
    const services = readFileSync(resolve(SRC, 'views/Services.vue'), 'utf8')
    expect(services).toMatch(
      /<span role="status">\{\{ t\('services\.selected_n'/,
    )
  })

  it('announces the Services filter result count', () => {
    // The "34 / 50" count is the only feedback the filter box and the state
    // chips give; without a live region it changed silently.
    const services = readFileSync(resolve(SRC, 'views/Services.vue'), 'utf8')
    expect(services).toMatch(
      /<span class="meta-count" role="status">\{\{ asArray\(filtered\)\.length \}\}/,
    )
  })

  it('names each Services row checkbox after its service', () => {
    // Thirty checkboxes all called "Select this row" cannot be told apart in
    // a screen reader's form-controls listing; the Files list already names
    // its per-row checkboxes after the item, so the pattern is established.
    const services = readFileSync(resolve(SRC, 'views/Services.vue'), 'utf8')
    expect(services).toMatch(
      /:aria-label="t\('common\.select_row_name',\s*\{\s*name:/,
    )
    for (const [name, source] of vueFiles()) {
      // A regex, not the literal call text: the backend's i18n contract test
      // scans every source for translation-key references and would otherwise
      // count this guard as a use of the removed key.
      expect(source, `${name} uses the anonymous row-checkbox label`)
        .not.toMatch(/t\('common\.select_row'\)/)
    }
  })
})

describe('macos switch controls', () => {
  it('uses a capsule switch for autostart and sharing, not a green checkbox', () => {
    const apps = readFileSync(resolve(SRC, 'views/Apps.vue'), 'utf8')
    const shares = readFileSync(resolve(SRC, 'views/Shares.vue'), 'utf8')
    expect(apps).toContain('<MacSwitch')
    expect(apps).not.toMatch(/class="auto-toggle"[\s\S]{0,280}type="checkbox"/)
    expect(shares).toContain('<MacSwitch')
    expect(shares).not.toMatch(/class="mac-switch"/)
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
    expect(main).not.toContain("data?.array?.status || t('network.unknown')")
    expect(main).toContain("finiteText(data?.array?.status, '') || t('network.unknown')")
  })

  it('preserves the saved pool free-space floor when editing other fields', () => {
    expect(pool).toContain("minFreeGb.value = Number(finiteN(recGet(data, 'min_free_gb'), 0)) || 0")
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

  it('invalidates in-flight container inspect on leave', () => {
    expect(containers).toMatch(/async function openInspect\(c\)[\s\S]*const generation = listGeneration/)
    expect(containers).toMatch(/onUnmounted\(\(\) => \{[\s\S]*listGeneration \+= 1/)
  })

  it('discards container create/pull/volume/network writes after leave', () => {
    expect(containers).toContain('function stillOnList')
    for (const name of ['doRun', 'doPull', 'rmi', 'createVol', 'rmVol', 'createNet', 'rmNet']) {
      expect(containers, `${name} must snapshot listGeneration`).toMatch(
        new RegExp(`async function ${name}[\\s\\S]*const generation = listGeneration`),
      )
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
    expect(network).toMatch(/function scheduleRefresh[\s\S]*if \(generation !== loadGeneration \|\| !pageAlive\) return/)
    expect(network).toContain('function stillOnNetwork')
    expect(network).toMatch(/onUnmounted\(\(\) => \{[\s\S]*pageAlive = false/)
    expect(network).toMatch(/async function runAutoBind\([\s\S]*finally \{[\s\S]*if \(pageAlive\) busy\.value = false/)
    expect(network).toMatch(/async function runFailover\([\s\S]*finally \{[\s\S]*if \(pageAlive\) busy\.value = false/)
    for (const fn of [
      'saveAutoBind', 'applyProfile', 'saveOrder', 'toggleService', 'addAlias',
      'removeAlias', 'setDhcp', 'applyManual', 'applyDns', 'wifi', 'doLookup',
      'applyPorts', 'applyConnect',
    ]) {
      expect(network, `${fn} must drop busy with pageAlive after refresh() bumps`).toMatch(
        new RegExp(`async function ${fn}[\\s\\S]*finally \\{[\\s\\S]*if \\(pageAlive\\) busy\\.value = false`),
      )
    }
  })

  it('warns before connection-changing operations', () => {
    for (const key of [
      'network.confirm_manual',
      'network.confirm_wifi',
      'network.confirm_recreate_ports',
      'network.confirm_disconnect',
      'network.confirm_connect',
      'network.confirm_failover',
      'network.confirm_add_alias',
      'network.confirm_autobind',
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
    expect(logs).toMatch(/async function loadSources\(\)[\s\S]*if \(generation !== loadGeneration \|\| !pageAlive\)/)
  })

  it('does not refresh a failed backup into the successful list', () => {
    // refresh(true): these re-reads follow a user-initiated backup, so their
    // failure may toast (jobFinishRefresh.test.js pins the background chain).
    expect(backups).toContain('if (r.ok) await refresh(true)')
  })

  it('tears down action timers on Services and Apps job polls', () => {
    const services = readFileSync(resolve(SRC, 'views/Services.vue'), 'utf8')
    const apps = readFileSync(resolve(SRC, 'views/Apps.vue'), 'utf8')
    expect(services).toContain('for (const id of refreshTimers) clearTimeout(id)')
    expect(apps).toContain('function stopJobPolling()')
    expect(apps).toContain('jobPollGeneration')
    expect(apps).not.toContain('setInterval(poll')
  })

  it('prevents duplicate alert checks and notification tests', () => {
    expect(alerts).toContain('const busy = ref(false)')
    expect(alerts).toMatch(/async function check\(\)[\s\S]*if \(busy\.value\) return[\s\S]*finally/)
    expect(alerts).toMatch(/async function test\(\)[\s\S]*if \(busy\.value\) return[\s\S]*finally/)
    expect(alerts).toMatch(/async function refresh\([\s\S]*finally \{[\s\S]*if \(generation === loadGeneration && pageAlive\)/)
    expect(alerts).toMatch(/async function check\([\s\S]*finally \{[\s\S]*if \(generation === loadGeneration && pageAlive\) busy\.value = false/)
    expect(alerts).toMatch(/async function test\([\s\S]*finally \{[\s\S]*if \(generation === loadGeneration && pageAlive\) busy\.value = false/)
    expect(alerts).toContain('let loadGeneration = 0')
    expect(alerts).toMatch(/onUnmounted\(\(\) => \{[\s\S]*loadGeneration \+= 1/)
  })

  it('invalidates in-flight NotifyChannels and ServiceSignatures loads on leave', () => {
    const notify = readFileSync(resolve(SRC, 'components/NotifyChannels.vue'), 'utf8')
    const sigs = readFileSync(resolve(SRC, 'components/ServiceSignatures.vue'), 'utf8')
    const grules = readFileSync(resolve(SRC, 'components/GroupRules.vue'), 'utf8')
    const form = readFileSync(resolve(SRC, 'components/ScheduleJobForm.vue'), 'utf8')
    for (const [name, src] of [
      ['NotifyChannels.vue', notify],
      ['ServiceSignatures.vue', sigs],
      ['GroupRules.vue', grules],
    ]) {
      expect(src, name).toContain('let loadGeneration = 0')
      expect(src, name).toMatch(/onUnmounted\(\(\) => \{[\s\S]*loadGeneration \+= 1/)
    }
    expect(form, 'ScheduleJobForm.vue').toContain('let previewGeneration = 0')
    expect(form, 'ScheduleJobForm.vue').toContain('let stacksGeneration = 0')
    expect(form).toMatch(/onUnmounted\(\(\) => \{[\s\S]*previewGeneration \+= 1/)
    expect(form).toMatch(/onUnmounted\(\(\) => \{[\s\S]*stacksGeneration \+= 1/)
  })

  it('invalidates in-flight Bookmarks and Health loads on leave', () => {
    const bookmarks = readFileSync(resolve(SRC, 'views/Bookmarks.vue'), 'utf8')
    const health = readFileSync(resolve(SRC, 'views/Health.vue'), 'utf8')
    const modules = readFileSync(resolve(SRC, 'views/Modules.vue'), 'utf8')
    const gateway = readFileSync(resolve(SRC, 'views/Gateway.vue'), 'utf8')
    for (const [name, src] of [
      ['Bookmarks.vue', bookmarks],
      ['Health.vue', health],
      ['Modules.vue', modules],
    ]) {
      expect(src, name).toContain('let loadGeneration = 0')
      expect(src, name).toMatch(/onUnmounted\(\(\) => \{[\s\S]*loadGeneration \+= 1/)
    }
    expect(gateway).toContain('let loadSeq = 0')
    expect(gateway).toMatch(/onUnmounted\(\(\) => \{[\s\S]*loadSeq \+= 1/)
  })

  it('does not report an unsaved diagnostics snapshot as saved', () => {
    const tools = readFileSync(resolve(SRC, 'views/Tools.vue'), 'utf8')
    const settings = readFileSync(resolve(SRC, 'views/Settings.vue'), 'utf8')
    expect(tools).toContain("if (j.saved_path)")
    expect(tools).toContain("t('tools.diag_save_failed'")
    expect(tools).toContain('j.save_error')
    expect(tools).toMatch(/async function genDiag\(\)[\s\S]*if \(generation !== reloadGeneration/)
    expect(tools).toMatch(/async function doPrune\([\s\S]*if \(generation !== reloadGeneration/)
    expect(tools).toMatch(/async function doFlushDns\(\)[\s\S]*if \(generation !== reloadGeneration/)
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
    expect(dashboard).toContain('loadSensors(false, { light: !highMode.value })')
    expect(dashboard).toContain('loadSensors(forceSensors, { light: false })')
    expect(dashboard).toContain('refreshHeavy(false, highMode.value)')
    expect(dashboard).toMatch(/onUnmounted\([\s\S]*clearTimeout\(actionRefreshTimer\)/)
    expect(dashboard).toMatch(/async function loadPower\(\)[\s\S]*if \(!dashAlive\) return/)
    expect(dashboard).toMatch(/async function loadSensors\([\s\S]*const generation = \+\+sensorsGeneration/)
    expect(dashboard).toMatch(/onUnmounted\(\(\) => \{[\s\S]*sensorsGeneration \+= 1/)
  })

  it('keeps file navigation and terminal connection state current', () => {
    const files = readFileSync(resolve(SRC, 'views/Files.vue'), 'utf8')
    const terminal = readFileSync(resolve(SRC, 'views/Terminal.vue'), 'utf8')
    const settings = readFileSync(resolve(SRC, 'views/Settings.vue'), 'utf8')
    expect(files).toContain('const request = ++listRequest')
    expect(files).toMatch(/async function loadOverview\(\)[\s\S]*const request = \+\+listRequest/)
    expect(files).toContain('request !== listRequest || !activated.value')
    expect(files).toMatch(/async function openFullFB\(\)[\s\S]*if \(request !== listRequest\) return/)
    expect(files).toMatch(/async function openFullFB\([\s\S]*finally \{[\s\S]*if \(pageAlive\) busy\.value = false/)
    expect(files).toMatch(/async function stopFB\(\)[\s\S]*if \(request !== listRequest\) return/)
    expect(files).toMatch(/async function stopFB\([\s\S]*finally \{[\s\S]*if \(pageAlive\) busy\.value = false/)
    expect(files).toMatch(/async function doMkdir\(\)[\s\S]*if \(request !== listRequest\) return/)
    expect(files).toMatch(/async function doMkdir\([\s\S]*finally \{[\s\S]*if \(pageAlive\) busy\.value = false/)
    expect(files).toMatch(/async function doRename\([\s\S]*if \(request !== listRequest\) return/)
    expect(files).toMatch(/async function doRename\([\s\S]*finally \{[\s\S]*if \(pageAlive\) busy\.value = false/)
    expect(files).toMatch(/async function doDeleteOne\([\s\S]*finally \{[\s\S]*if \(pageAlive\) busy\.value = false/)
    expect(files).toMatch(/async function doDeleteSelected\([\s\S]*finally \{[\s\S]*if \(pageAlive\) busy\.value = false/)
    expect(files).toMatch(/async function uploadFiles\([\s\S]*if \(request !== listRequest\) return/)
    expect(files).toMatch(/async function uploadFiles\([\s\S]*finally \{[\s\S]*if \(pageAlive\) busy\.value = false/)
    expect(files).toMatch(/function deactivate\(\)[\s\S]*listRequest \+= 1/)
    expect(files).toMatch(/onUnmounted\([\s\S]*pageAlive = false[\s\S]*listRequest \+= 1/)
    expect(files.match(/if \(!j\.ok\) throw new Error/g)).toHaveLength(2)
    expect(files).not.toMatch(/window\.open\(`\/api\/files\/download/)
    expect(files).toContain("a.rel = 'noopener'")
    expect(files).toContain("a.download = finiteText(recGet(row, 'name'), 'download')")
    expect(terminal).toContain('terminal handshake timeout')
    expect(terminal).toMatch(/message\.type === 'ready'[\s\S]{0,100}clearConnectTimer\(\)/)
    expect(terminal).toMatch(/function closeTerminal\(\)[\s\S]{0,100}clearConnectTimer\(\)/)
    expect(terminal).toMatch(/function onSocketClose\(\)[\s\S]{0,100}clearConnectTimer\(\)/)
    expect(settings).toMatch(/async function testNotify\(\)[\s\S]*if \(saving\.value\) return[\s\S]*finally/)
    expect(settings).toMatch(/async function forceCheck\(\)[\s\S]*if \(saving\.value\) return[\s\S]*finally/)
    const photoshub = readFileSync(resolve(SRC, 'views/PhotosHub.vue'), 'utf8')
    expect(photoshub).toContain('let loadGeneration = 0')
    expect(photoshub).toMatch(/onUnmounted\(\(\) => \{[\s\S]*loadGeneration \+= 1/)
  })

  it('invalidates in-flight Settings and Account loads on leave', () => {
    const settings = readFileSync(resolve(SRC, 'views/Settings.vue'), 'utf8')
    const account = readFileSync(resolve(SRC, 'views/Account.vue'), 'utf8')
    expect(settings).toContain('let loadGeneration = 0')
    expect(settings).toMatch(/onUnmounted\(\(\) => \{[\s\S]*loadGeneration \+= 1/)
    expect(account).toContain('let loadGeneration = 0')
    expect(account).toMatch(/onUnmounted\(\(\) => \{[\s\S]*loadGeneration \+= 1/)
  })

  it('does not write Settings saves or copy timers after leave', () => {
    const settings = readFileSync(resolve(SRC, 'views/Settings.vue'), 'utf8')
    for (const fn of [
      'syncUiToServer', 'saveIdentity', 'savePassword', 'saveAdvanced',
      'saveOllama', 'saveTerminal', 'saveUps', 'saveHalt',
      'applyPower', 'runAliasAlign', 'runDiagnostics', 'pickLocale',
      'startTwofaEnroll', 'confirmTwofaEnroll', 'disableTwofa',
      'regenTwofaRecovery', 'adminResetTwofa', 'createKey', 'revokeKey',
      'runDrill', 'testNotify', 'forceCheck', 'runLauncher',
    ]) {
      expect(settings, `${fn} must ignore a late response`).toMatch(
        new RegExp(`async function ${fn}\\([\\s\\S]*if \\(!pageAlive\\) return`),
      )
    }
    // `save` is the panel/notify writer; the name is a prefix of saveIdentity etc.
    expect(settings).toMatch(/async function save\(\)[\s\S]*if \(!pageAlive\) return/)
    expect(settings).toMatch(/function persistUi\([\s\S]*if \(generation !== loadGeneration \|\| !pageAlive\) return/)
    expect(settings).toMatch(/async function copyRecoveryCodes\(\)[\s\S]*if \(!pageAlive\) return/)
    expect(settings).toMatch(/async function copyCreatedKey\(\)[\s\S]*if \(!pageAlive\) return/)
    expect(settings).toMatch(/copyRecoveryTimer = setTimeout\(\(\) => \{[\s\S]*if \(!pageAlive\) return/)
    expect(settings).toMatch(/copyKeyTimer = setTimeout\(\(\) => \{[\s\S]*if \(!pageAlive\) return/)
  })

  it('discards Users and Brew mutations that finish after leave', () => {
    const users = readFileSync(resolve(SRC, 'views/Users.vue'), 'utf8')
    const brew = readFileSync(resolve(SRC, 'views/Brew.vue'), 'utf8')
    expect(users).toMatch(/async function createAccount\(\)[\s\S]*if \(generation !== loadGeneration \|\| !pageAlive\) return/)
    expect(users).toMatch(/async function createAccount\([\s\S]*finally \{[\s\S]*if \(pageAlive\) accountsBusy\.value = false/)
    expect(users).toMatch(/async function saveResources\([\s\S]*if \(generation !== loadGeneration \|\| !pageAlive\) return/)
    expect(users).toMatch(/async function saveResources\([\s\S]*finally \{[\s\S]*if \(pageAlive\) accountsBusy\.value = false/)
    expect(users).toMatch(/async function doResetPassword\([\s\S]*if \(generation !== loadGeneration \|\| !pageAlive\) return/)
    expect(users).toMatch(/async function doResetPassword\([\s\S]*finally \{[\s\S]*if \(pageAlive\) accountsBusy\.value = false/)
    expect(users).toMatch(/async function resetTwofa\([\s\S]*if \(generation !== loadGeneration \|\| !pageAlive\) return/)
    expect(users).toMatch(/async function resetTwofa\([\s\S]*finally \{[\s\S]*if \(pageAlive\) accountsBusy\.value = false/)
    expect(users).toMatch(/async function removeAccount\([\s\S]*if \(generation !== loadGeneration \|\| !pageAlive\) return/)
    expect(users).toMatch(/async function removeAccount\([\s\S]*finally \{[\s\S]*if \(pageAlive\) accountsBusy\.value = false/)
    expect(brew).toMatch(/async function act\([\s\S]*if \(generation !== loadGeneration \|\| !pageAlive\) return/)
    // Block form since the busy note: the same pageAlive gate also clears the
    // note's action/name so a leave mid-action cannot resurrect the region.
    expect(brew).toMatch(/async function act\([\s\S]*finally \{[\s\S]*if \(pageAlive\) \{[\s\S]{0,80}busy\.value = false/)
    expect(brew).toMatch(/onUnmounted\(\(\) => \{[\s\S]*pageAlive = false/)
  })

  it('discards Containers, Services, WireGuard and Compose mutations that finish after leave', () => {
    const containers = readFileSync(resolve(SRC, 'views/Containers.vue'), 'utf8')
    const services = readFileSync(resolve(SRC, 'views/Services.vue'), 'utf8')
    const wireguard = readFileSync(resolve(SRC, 'views/WireGuard.vue'), 'utf8')
    const compose = readFileSync(resolve(SRC, 'views/Compose.vue'), 'utf8')
    expect(containers).toMatch(/function stillOnList\(generation\) \{\s*\n\s*return pageAlive && generation === listGeneration/)
    expect(containers).toMatch(/function scheduleRefresh\([\s\S]*if \(generation !== listGeneration \|\| !pageAlive\) return/)
    expect(containers).toMatch(/async function act\([\s\S]*if \(!stillOnList\(generation\)\) return/)
    expect(containers).toMatch(/async function act\([\s\S]*finally \{[\s\S]*if \(pageAlive\) busy\.value = false/)
    expect(containers).toMatch(/async function doPrune\([\s\S]*finally \{[\s\S]*if \(pageAlive\) busy\.value = false/)
    expect(containers).toMatch(/async function toggleAutostart\([\s\S]*finally \{[\s\S]*if \(pageAlive\) busy\.value = false/)
    expect(containers).toMatch(/async function openInspect\([\s\S]*finally \{[\s\S]*if \(pageAlive\) busy\.value = false/)
    expect(containers).toMatch(/async function doRun\([\s\S]*finally \{[\s\S]*if \(pageAlive\) busy\.value = false/)
    expect(containers).toMatch(/onUnmounted\(\(\) => \{[\s\S]*pageAlive = false/)
    expect(services).toMatch(/function later\([\s\S]*if \(!pageAlive\) return/)
    expect(services).toMatch(/async function onAction\([\s\S]*if \(!pageAlive\) return/)
    for (const fn of ['openUninstall', 'confirmUninstall', 'adopt', 'saveScript', 'forgetScript', 'saveOverride', 'hideService']) {
      expect(services, `${fn} must ignore a late response`).toMatch(
        new RegExp(`async function ${fn}[\\s\\S]*if \\(!pageAlive\\) return`),
      )
    }
    expect(wireguard).toMatch(/async function withBusy\([\s\S]*if \(generation !== loadGeneration \|\| !pageAlive\) return/)
    expect(wireguard).toMatch(/async function withBusy\([\s\S]*finally \{[\s\S]*if \(pageAlive\) busy\.value = false/)
    expect(wireguard).toMatch(/async function copyWstunnelCommand\(\)[\s\S]*if \(!pageAlive\) return/)
    expect(wireguard).toMatch(/async function copyPeer\(\)[\s\S]*if \(!pageAlive\) return/)
    expect(wireguard).toMatch(/async function createPeer\(\)[\s\S]*if \(!created \|\| !pageAlive\) return/)
    expect(compose).toMatch(/async function save\(\)[\s\S]*if \(generation !== composeGeneration \|\| !pageAlive\) return/)
    expect(compose).toMatch(/async function create\(\)[\s\S]*if \(generation !== stacksGeneration \|\| !pageAlive\) return/)
    expect(compose).toMatch(/async function run\([\s\S]*finally \{[\s\S]*if \(pageAlive && !holdBusy\) busy\.value = false/)
    expect(compose).toMatch(/if \(!recGet\(j, 'running'\)\) \{[\s\S]*if \(pageAlive\) busy\.value = false/)
  })

  it('discards Scheduler, VMs, Account and Shares mutations that finish after leave', () => {
    const scheduler = readFileSync(resolve(SRC, 'views/Scheduler.vue'), 'utf8')
    const vms = readFileSync(resolve(SRC, 'views/VMs.vue'), 'utf8')
    const account = readFileSync(resolve(SRC, 'views/Account.vue'), 'utf8')
    const shares = readFileSync(resolve(SRC, 'views/Shares.vue'), 'utf8')
    expect(scheduler).toMatch(/async function saveJob\([\s\S]*if \(pollStopped\) return/)
    expect(scheduler).toMatch(/async function removeJob\([\s\S]*if \(pollStopped\) return/)
    expect(vms).toMatch(/function scheduleRefresh\([\s\S]*if \(generation !== loadGeneration \|\| !pageAlive\) return/)
    expect(vms).toMatch(/async function act\([\s\S]*if \(generation !== loadGeneration \|\| !pageAlive\) return/)
    expect(vms).toMatch(/async function act\([\s\S]*finally \{[\s\S]*if \(pageAlive\) busy\.value = false/)
    expect(vms).toMatch(/async function doClone\([\s\S]*finally \{[\s\S]*if \(pageAlive\) busy\.value = false/)
    expect(vms).toMatch(/async function doCreate\([\s\S]*finally \{[\s\S]*if \(pageAlive\) busy\.value = false/)
    expect(vms).toMatch(/async function doRename\([\s\S]*finally \{[\s\S]*if \(pageAlive\) busy\.value = false/)
    expect(account).toMatch(/async function savePassword\(\)[\s\S]*if \(generation !== loadGeneration \|\| !pageAlive\) return/)
    expect(account).toMatch(/async function savePassword\([\s\S]*finally \{[\s\S]*if \(pageAlive\) savingPassword\.value = false/)
    expect(account).toMatch(/async function confirmEnroll\(\)[\s\S]*if \(generation !== loadGeneration \|\| !pageAlive\) return/)
    expect(account).toMatch(/async function startEnroll\([\s\S]*finally \{[\s\S]*if \(pageAlive\) busy\.value = false/)
    expect(account).toMatch(/async function confirmEnroll\([\s\S]*finally \{[\s\S]*if \(pageAlive\) busy\.value = false/)
    expect(account).toMatch(/async function disable\([\s\S]*finally \{[\s\S]*if \(pageAlive\) busy\.value = false/)
    expect(account).toMatch(/async function regenRecovery\([\s\S]*finally \{[\s\S]*if \(pageAlive\) busy\.value = false/)
    expect(account).toMatch(/async function copyRecoveryCodes\(\)[\s\S]*if \(!pageAlive\) return/)
    expect(shares).toMatch(/async function saveShare\(\)[\s\S]*if \(generation !== loadGeneration \|\| !pageAlive\) return/)
    expect(shares).toMatch(/async function saveShare\([\s\S]*finally \{[\s\S]*if \(pageAlive\) \{[\s\S]*busy\.value = false/)
    expect(shares).toMatch(/async function applyAcl\([\s\S]*finally \{[\s\S]*if \(pageAlive\) aclBusy\.value = false/)
    expect(shares).toMatch(/async function removeShare\([\s\S]*if \(generation !== loadGeneration \|\| !pageAlive\) return/)
    expect(shares).toMatch(/async function removeShare\([\s\S]*finally \{[\s\S]*if \(pageAlive\) \{[\s\S]*busy\.value = false/)
    expect(shares).toMatch(/async function toggleService\([\s\S]*finally \{[\s\S]*if \(pageAlive\) \{[\s\S]*busy\.value = false/)
    expect(shares).toMatch(/async function openSettings\([\s\S]*finally \{[\s\S]*if \(pageAlive\) busy\.value = false/)
  })

  it('invalidates in-flight Ollama status and settings loads on leave', () => {
    const ollama = readFileSync(resolve(SRC, 'views/Ollama.vue'), 'utf8')
    expect(ollama).toContain('let loadGeneration = 0')
    expect(ollama).toMatch(/onUnmounted\(\(\) => \{[\s\S]*loadGeneration \+= 1/)
  })

  it('discards Apps Cloudflare/remote and Containers exec that finish after leave', () => {
    const apps = readFileSync(resolve(SRC, 'views/Apps.vue'), 'utf8')
    const containers = readFileSync(resolve(SRC, 'views/Containers.vue'), 'utf8')
    const dashboard = readFileSync(resolve(SRC, 'views/Dashboard.vue'), 'utf8')
    const array = readFileSync(resolve(SRC, 'views/MainArray.vue'), 'utf8')
    expect(apps).toMatch(/function later\([\s\S]*if \(generation !== appsDataGeneration\) return/)
    expect(apps).toMatch(/async function cfLogin\(\)[\s\S]*if \(!stillOnApps\(generation\)\) return/)
    expect(apps).toMatch(/async function saveRemoteSource\(\)[\s\S]*if \(!stillOnApps\(generation\)\) return/)
    expect(containers).toMatch(/async function runExec\(\)[\s\S]*if \(!stillOnList\(generation\)\) return/)
    expect(dashboard).toMatch(/function scheduleActionRefresh\(\)[\s\S]*if \(!dashAlive\) return/)
    expect(array).toMatch(/function scheduleRefresh\([\s\S]*if \(generation !== loadSeq \|\| !pageAlive\) return/)
  })

  it('invalidates in-flight Apps catalog-remote and MainArray threshold loads', () => {
    const apps = readFileSync(resolve(SRC, 'views/Apps.vue'), 'utf8')
    const array = readFileSync(resolve(SRC, 'views/MainArray.vue'), 'utf8')
    expect(apps).toMatch(/async function loadRemote\(\)[\s\S]*const generation = appsDataGeneration/)
    expect(apps).toMatch(/onUnmounted\(\(\) => \{[\s\S]*appsDataGeneration \+= 1/)
    expect(apps).toContain('function stillOnApps')
    expect(apps).toMatch(/function stillOnApps\(generation\) \{\s*\n\s*return pageAlive && generation === appsDataGeneration/)
    expect(apps).toMatch(/async function openDetail\([\s\S]*finally \{[\s\S]*if \(pageAlive\) busy\.value = false/)
    expect(apps).toMatch(/async function saveCredential\([\s\S]*finally \{[\s\S]*if \(pageAlive\) credentialBusy\.value = false/)
    expect(apps).toMatch(/async function deleteCredential\([\s\S]*finally \{[\s\S]*if \(pageAlive\) credentialBusy\.value = false/)
    expect(apps).toMatch(/onUnmounted\(\(\) => \{[\s\S]*pageAlive = false/)
    expect(apps).toMatch(/async function setAutostartItem\([\s\S]*if \(!stillOnApps\(generation\)\) return/)
    expect(apps).toMatch(/async function doInstall\(\)[\s\S]*if \(!stillOnApps\(generation\)\) return/)
    expect(apps).toMatch(/async function launchOpenInner\([\s\S]*if \(!stillOnApps\(generation\)\) return/)
    expect(apps).toMatch(/onUnmounted\(\(\) => \{[\s\S]*closeDetail\(\)/)
    expect(apps).toMatch(/onUnmounted\(\(\) => \{[\s\S]*closeJobLog\(\)/)
    expect(array).toMatch(/async function loadSmartThresholds\(\)[\s\S]*const mySeq = loadSeq/)
    expect(array).toMatch(/onUnmounted\(\(\) => \{[\s\S]*loadSeq \+= 1/)
  })

  it('discards MainArray, Pool, Maintenance, Logs and Dashboard mutations that finish after leave', () => {
    const array = readFileSync(resolve(SRC, 'views/MainArray.vue'), 'utf8')
    const pool = readFileSync(resolve(SRC, 'views/Pool.vue'), 'utf8')
    const maintenance = readFileSync(resolve(SRC, 'views/Maintenance.vue'), 'utf8')
    const logs = readFileSync(resolve(SRC, 'views/Logs.vue'), 'utf8')
    const dashboard = readFileSync(resolve(SRC, 'views/Dashboard.vue'), 'utf8')
    const audit = readFileSync(resolve(SRC, 'views/Audit.vue'), 'utf8')
    const health = readFileSync(resolve(SRC, 'views/Health.vue'), 'utf8')
    for (const fn of ['power', 'manage', 'doRename', 'doFormat', 'runSmartTest']) {
      expect(array, `${fn} must ignore a late response`).toMatch(
        new RegExp(`async function ${fn}[\\s\\S]*if \\(generation !== loadSeq \\|\\| !pageAlive\\) return`),
      )
      expect(array, `${fn} must drop busy with pageAlive after loadSeq bumps`).toMatch(
        new RegExp(`async function ${fn}[\\s\\S]*finally \\{[\\s\\S]*if \\(pageAlive\\) (?:busy|smartTestBusy)\\.value = false`),
      )
    }
    expect(array).toMatch(/async function openSmart\([\s\S]*finally \{[\s\S]*if \(pageAlive\) smartLoading\.value = false/)
    expect(array).toMatch(/onUnmounted\(\(\) => \{[\s\S]*pageAlive = false/)
    expect(pool).toMatch(/async function doPreview\(\)[\s\S]*if \(generation !== loadGeneration \|\| !pageAlive\) return/)
    expect(pool).toMatch(/async function doPreview\([\s\S]*finally \{[\s\S]*if \(pageAlive\) busy\.value = false/)
    expect(pool).toMatch(/async function doSave\(\)[\s\S]*if \(generation !== loadGeneration \|\| !pageAlive\) return/)
    expect(pool).toMatch(/async function doSave\([\s\S]*finally \{[\s\S]*if \(pageAlive\) busy\.value = false/)
    expect(pool).toMatch(/async function doClear\(\)[\s\S]*if \(generation !== loadGeneration \|\| !pageAlive\) return/)
    expect(pool).toMatch(/async function doClear\([\s\S]*finally \{[\s\S]*if \(pageAlive\) busy\.value = false/)
    expect(maintenance).toMatch(/async function run\([\s\S]*if \(generation !== listGeneration \|\| !pageAlive\) return/)
    expect(logs).toMatch(/async function copyLog\(\)[\s\S]*if \(generation !== loadGeneration \|\| !pageAlive\) return/)
    expect(dashboard).toMatch(/async function act\([\s\S]*if \(!dashAlive\) return/)
    expect(dashboard).toMatch(/async function copyVnc\(\)[\s\S]*if \(!dashAlive\) return/)
    expect(dashboard).toMatch(/async function copyOllamaApi\(\)[\s\S]*if \(!dashAlive\) return/)
    expect(dashboard).toMatch(/function setMetricRange\([\s\S]*\.finally\(\(\) => \{[\s\S]*if \(dashAlive\) metricsSwitching\.value = false/)
    // refresh takes a `manual` flag now (poll ticks stay silent); the guard
    // itself is what this test pins, whatever the signature.
    expect(audit).toMatch(/async function refresh\([^)]*\)[\s\S]*if \(generation !== loadGeneration \|\| !pageAlive\) return/)
    expect(audit).toMatch(/async function refresh\([\s\S]*finally \{[\s\S]*if \(generation === loadGeneration && pageAlive\)/)
    expect(health).toMatch(/async function load\(\)[\s\S]*if \(generation !== loadGeneration \|\| !pageAlive\) return/)
  })

  it('discards Login credential exchange that finishes after leave', () => {
    const login = readFileSync(resolve(SRC, 'views/Login.vue'), 'utf8')
    expect(login).toMatch(/async function submit\(\)[\s\S]*if \(!pageAlive\) return/)
    expect(login).toMatch(/totpStep\.value = true[\s\S]*if \(pageAlive\) busy\.value = false/)
    expect(login).toMatch(/async function submitTotp\(\)[\s\S]*if \(!pageAlive\) return/)
    expect(login).toMatch(/async function copyToken\(\)[\s\S]*if \(!pageAlive\) return/)
    expect(login).toMatch(/onUnmounted\(\(\) => \{[\s\S]*pageAlive = false/)
    expect(login).toMatch(/function leaveTotpStep\(\)[\s\S]*loginGeneration \+= 1/)
    expect(login).toMatch(/onUnmounted\(\(\) => \{[\s\S]*loginGeneration \+= 1/)
    expect(login).toMatch(/async function submitTotp\([\s\S]*finally \{[\s\S]*if \(pageAlive && generation === loginGeneration\) busy\.value = false/)
  })

  it('discards NotifyChannels and ServiceSignatures writes that finish after leave', () => {
    const notify = readFileSync(resolve(SRC, 'components/NotifyChannels.vue'), 'utf8')
    const sigs = readFileSync(resolve(SRC, 'components/ServiceSignatures.vue'), 'utf8')
    const grules = readFileSync(resolve(SRC, 'components/GroupRules.vue'), 'utf8')
    const assist = readFileSync(resolve(SRC, 'components/AssistantDrawer.vue'), 'utf8')
    expect(notify).toMatch(/async function save\(\)[\s\S]*if \(generation !== loadGeneration \|\| !pageAlive\) return/)
    expect(notify).toMatch(/async function testChannel\([\s\S]*if \(generation !== loadGeneration \|\| !pageAlive\) return/)
    expect(notify).toMatch(/async function testChannel\([\s\S]*finally \{[\s\S]*if \(pageAlive\) busy\.value = false/)
    expect(notify).toMatch(/async function removeChannel\([\s\S]*if \(generation !== loadGeneration \|\| !pageAlive\) return/)
    expect(sigs).toMatch(/async function save\(\)[\s\S]*if \(generation !== loadGeneration \|\| !pageAlive\) return/)
    expect(sigs).toMatch(/async function removeRow\([\s\S]*if \(generation !== loadGeneration \|\| !pageAlive\) return/)
    expect(grules).toMatch(/async function save\(\)[\s\S]*if \(generation !== loadGeneration \|\| !pageAlive\) return/)
    expect(grules).toMatch(/async function removeRow\([\s\S]*if \(generation !== loadGeneration \|\| !pageAlive\) return/)
    expect(assist).toMatch(/const out = asRecord\(await askAssistant\([\s\S]*if \(generation !== sendGeneration \|\| !props\.open\) \{/)
  })

  it('discards service log copies that finish after leave', () => {
    const drawer = readFileSync(resolve(SRC, 'components/ServiceDetailDrawer.vue'), 'utf8')
    const logs = readFileSync(resolve(SRC, 'components/ServiceLogsModal.vue'), 'utf8')
    expect(drawer).toMatch(/async function copyLog\(\)[\s\S]*if \(!pageAlive\) return/)
    expect(logs).toMatch(/async function copyLog\(\)[\s\S]*if \(!pageAlive\) return/)
  })

  it('discards Gateway test/reload and VncConsole fullscreen after leave', () => {
    const gateway = readFileSync(resolve(SRC, 'views/Gateway.vue'), 'utf8')
    const vnc = readFileSync(resolve(SRC, 'components/VncConsole.vue'), 'utf8')
    expect(gateway).toMatch(/async function test\(\)[\s\S]*if \(!pageAlive\) return/)
    expect(gateway).toMatch(/async function reload\(\)[\s\S]*if \(!pageAlive\) return/)
    expect(vnc).toMatch(/async function toggleFullscreen\(\)[\s\S]*if \(disposed\) return/)
  })

  it('discards App/Terminal/Dashboard leftover loads that finish after leave', () => {
    const app = readFileSync(resolve(SRC, 'App.vue'), 'utf8')
    const terminal = readFileSync(resolve(SRC, 'views/Terminal.vue'), 'utf8')
    const dashboard = readFileSync(resolve(SRC, 'views/Dashboard.vue'), 'utf8')
    const assist = readFileSync(resolve(SRC, 'components/AssistantDrawer.vue'), 'utf8')
    expect(app).toContain('function stillOnShell')
    expect(app).toMatch(/async function refresh\(\)[\s\S]*if \(!stillOnShell\(generation\)\) return/)
    expect(app).toMatch(/function probePhotoHub\(\)[\s\S]*if \(!stillOnShell\(generation\)\) return/)
    expect(app).toMatch(/function loadAssistCatalog\(\)[\s\S]*if \(!stillOnShell\(generation\) \|\| !authState\.canManage\) return/)
    expect(app).toMatch(/async function ptrTouchEnd\(\)[\s\S]*if \(!stillOnShell\(generation\)\) return/)
    expect(app).toMatch(/async function logout\(\)[\s\S]*if \(!stillOnShell\(generation\)\) return/)
    expect(app).toMatch(/async function onLocale\([\s\S]*if \(!stillOnShell\(generation\)\) return/)
    expect(app).toMatch(/window\.addEventListener\('online', onOnline\)/)
    expect(app).toMatch(/window\.addEventListener\('offline', onOffline\)/)
    expect(app).toMatch(/window\.addEventListener\('sw-update-ready', onSwUpdateReady\)/)
    expect(app).toMatch(/onUnmounted\(\(\) => \{[\s\S]*removeEventListener\('online', onOnline/)
    expect(app).toMatch(/onUnmounted\(\(\) => \{[\s\S]*removeEventListener\('offline', onOffline/)
    expect(app).toMatch(/onUnmounted\(\(\) => \{[\s\S]*removeEventListener\('sw-update-ready', onSwUpdateReady/)
    expect(terminal).toMatch(/async function openTerminal\(\)[\s\S]*if \(!pageAlive \|\| !dialogOpen\.value\) return/)
    expect(terminal).toMatch(/\} catch \(error\) \{[\s\S]*clearConnectTimer\(\)/)
    expect(terminal).toMatch(/\} catch \(error\) \{[\s\S]*if \(!pageAlive\) return/)
    expect(dashboard).toMatch(/function startDashTimers\(\)[\s\S]*if \(!dashAlive\) return/)
    expect(assist).toMatch(/async function send\([\s\S]*if \(generation !== sendGeneration \|\| !props\.open\) \{/)
  })

  it('discards PhotosHub, Shares ACL and Settings launcher writes after leave', () => {
    const photoshub = readFileSync(resolve(SRC, 'views/PhotosHub.vue'), 'utf8')
    const shares = readFileSync(resolve(SRC, 'views/Shares.vue'), 'utf8')
    const settings = readFileSync(resolve(SRC, 'views/Settings.vue'), 'utf8')
    expect(photoshub).toMatch(/async function saveSettings\(\)[\s\S]*if \(generation !== loadGeneration \|\| !pageAlive\) return/)
    expect(photoshub).toMatch(/async function saveSettings\([\s\S]*finally \{[\s\S]*if \(pageAlive\) saving\.value = false/)
    expect(photoshub).toMatch(/async function run\([\s\S]*if \(generation !== loadGeneration \|\| !pageAlive\) return/)
    expect(photoshub).toMatch(/async function run\([\s\S]*finally \{[\s\S]*if \(pageAlive\) \{[\s\S]*busy\.value = false/)
    expect(photoshub).toMatch(/async function removeSelected\(\)[\s\S]*if \(generation !== loadGeneration \|\| !pageAlive\) return/)
    expect(photoshub).toMatch(/async function removeSelected\([\s\S]*finally \{[\s\S]*if \(pageAlive\) pendingLoading\.value = false/)
    expect(photoshub).toMatch(/async function loadPending\(\)[\s\S]*finally \{[\s\S]*if \(pageAlive\) pendingLoading\.value = false/)
    expect(shares).toMatch(/async function loadAcl\([\s\S]*if \(generation !== aclGeneration \|\| !pageAlive\) return/)
    expect(shares).toMatch(/async function applyAcl\([\s\S]*if \(generation !== aclGeneration \|\| !pageAlive\) return/)
    expect(shares).toMatch(/async function applyAcl\([\s\S]*finally \{[\s\S]*if \(pageAlive\) aclBusy\.value = false/)
    expect(settings).toMatch(/async function loadLauncher\(\)[\s\S]*if \(request === launcherLoadRequest && pageAlive\)/)
    expect(settings).toMatch(/onUnmounted\(\(\) => \{[\s\S]*launcherLoadRequest \+= 1/)
  })

  it('clears leftover Tools/Scheduler/form busy with pageAlive after a generation bump', () => {
    const tools = readFileSync(resolve(SRC, 'views/Tools.vue'), 'utf8')
    const form = readFileSync(resolve(SRC, 'components/ScheduleJobForm.vue'), 'utf8')
    const health = readFileSync(resolve(SRC, 'views/Health.vue'), 'utf8')
    const bookmarks = readFileSync(resolve(SRC, 'views/Bookmarks.vue'), 'utf8')
    const modules = readFileSync(resolve(SRC, 'views/Modules.vue'), 'utf8')
    const logs = readFileSync(resolve(SRC, 'views/Logs.vue'), 'utf8')
    const maintenance = readFileSync(resolve(SRC, 'views/Maintenance.vue'), 'utf8')
    const scheduler = readFileSync(resolve(SRC, 'views/Scheduler.vue'), 'utf8')
    const admin = readFileSync(resolve(SRC, 'components/AdminPasswordDialog.vue'), 'utf8')
    const actions = readFileSync(resolve(SRC, 'components/ServiceActions.vue'), 'utf8')
    expect(tools).toContain('let pageAlive = true')
    expect(tools).toMatch(/onUnmounted\(\(\) => \{[\s\S]*pageAlive = false[\s\S]*reloadGeneration \+= 1/)
    for (const fn of ['genDiag', 'doPrune', 'loadSyslog', 'loadHw', 'loadUpdates', 'doPing', 'doDns', 'doFlushDns']) {
      expect(tools, `${fn} must drop loading with pageAlive after reload() bumps`).toMatch(
        new RegExp(`async function ${fn}[\\s\\S]*?finally \\{[\\s\\S]*?if \\(pageAlive\\) loading\\.value = false`),
      )
    }
    expect(form).toMatch(/async function doPreview\([\s\S]*finally \{[\s\S]*if \(pageAlive\) previewing\.value = false/)
    expect(form).toContain('let previewGeneration = 0')
    expect(form).toContain('let stacksGeneration = 0')
    expect(health).toMatch(/async function load\([\s\S]*finally \{[\s\S]*if \(generation === loadGeneration && pageAlive\)/)
    expect(bookmarks).toMatch(/async function refresh\([\s\S]*finally \{[\s\S]*if \(generation === loadGeneration && pageAlive\)/)
    expect(modules).toMatch(/async function load\([\s\S]*finally \{[\s\S]*if \(generation === loadGeneration && pageAlive\) \{[\s\S]*loading\.value = false[\s\S]*loaded\.value = true/)
    expect(logs).toMatch(/async function load\([\s\S]*finally \{[\s\S]*if \(generation === loadGeneration && pageAlive\)/)
    expect(maintenance).toMatch(/async function pollLog\([\s\S]*if \(!id \|\| generation !== pollGeneration \|\| !pageAlive\) return/)
    expect(maintenance).toMatch(/async function refresh\([\s\S]*finally \{[\s\S]*if \(generation === listGeneration && pageAlive\) loaded\.value = true/)
    expect(scheduler).toMatch(/async function load\([\s\S]*finally \{[\s\S]*if \(!pollStopped\) \{[\s\S]*loading\.value = false/)
    expect(admin).toMatch(/onUnmounted\(\(\) => \{[\s\S]*settle\(null\)/)
    expect(actions).toMatch(/:aria-busy="busy \? 'true' : undefined"/)
  })

  it('discards leftover timer, watcher and copy-to-clipboard writes after leave', () => {
    const dismiss = readFileSync(resolve(SRC, 'composables/useDismissable.js'), 'utf8')
    const app = readFileSync(resolve(SRC, 'App.vue'), 'utf8')
    const containers = readFileSync(resolve(SRC, 'views/Containers.vue'), 'utf8')
    const scheduler = readFileSync(resolve(SRC, 'views/Scheduler.vue'), 'utf8')
    const vnc = readFileSync(resolve(SRC, 'components/VncConsole.vue'), 'utf8')
    const ollama = readFileSync(resolve(SRC, 'views/Ollama.vue'), 'utf8')
    const backups = readFileSync(resolve(SRC, 'views/Backups.vue'), 'utf8')
    const logs = readFileSync(resolve(SRC, 'views/Logs.vue'), 'utf8')
    const pool = readFileSync(resolve(SRC, 'views/Pool.vue'), 'utf8')
    const terminal = readFileSync(resolve(SRC, 'views/Terminal.vue'), 'utf8')
    const settings = readFileSync(resolve(SRC, 'views/Settings.vue'), 'utf8')
    const drawer = readFileSync(resolve(SRC, 'components/ServiceDetailDrawer.vue'), 'utf8')
    const poll = readFileSync(resolve(SRC, 'lib/poll.js'), 'utf8')
    const client = readFileSync(resolve(SRC, 'api/client.js'), 'utf8')
    expect(dismiss).toContain('function stillOn')
    expect(dismiss).toMatch(/await Promise\.resolve\(\)\s*\n\s*if \(!stillOn\(generation\)\) return/)
    expect(dismiss).toMatch(/onBeforeUnmount\(\(\) => \{[\s\S]*pageAlive = false[\s\S]*loadGeneration \+= 1/)
    expect(app).toMatch(/nextTick\(\(\) => \{[\s\S]*if \(!stillOnShell\(generation\) \|\| !cmdOpen\.value\) return[\s\S]*cmdInput\.value\?\.focus/)
    expect(containers).toMatch(/requestAnimationFrame\(\(\) => \{[\s\S]*if \(generation !== listGeneration\) return/)
    expect(scheduler).toMatch(/pollTimer = setTimeout\(\(\) => \{[\s\S]*if \(pollStopped\) return/)
    expect(vnc).toMatch(/await panelEl\.value\?\.requestFullscreen\(\)[\s\S]*if \(disposed\) \{/)
    expect(vnc).toMatch(/watch\(autoScale, \(enabled\) => \{[\s\S]*if \(disposed\) return/)
    expect(vnc).toMatch(/watch\(viewOnly, \(enabled\) => \{[\s\S]*if \(disposed\) return/)
    expect(ollama).toMatch(/async function copyText\([\s\S]*if \(!pageAlive\) return/)
    expect(ollama).toMatch(/function startPullPolling\(\)[\s\S]*if \(!pageAlive\) return/)
    expect(ollama).toMatch(/if \(pageAlive\) ollamaSaving\.value = false/)
    expect(ollama).toMatch(/if \(pageAlive\) unloading\.value = false/)
    expect(ollama).toMatch(/if \(pageAlive\) deleting\.value = false/)
    expect(ollama).toMatch(/async function act\([\s\S]*finally \{[\s\S]*if \(pageAlive\) svcBusy\.value = false/)
    expect(ollama).toMatch(/async function startPull\([\s\S]*finally \{[\s\S]*if \(pageAlive\) pullBusy\.value = false/)
    expect(ollama).toMatch(/async function runTest\([\s\S]*finally \{[\s\S]*if \(pageAlive\) testBusy\.value = false/)
    expect(ollama).toContain('v-if="recGet(m, \'content\') || recGet(m, \'pending\')"')
    expect(backups).toMatch(/async function copyRestore\([\s\S]*if \(!pageAlive\) return/)
    expect(logs).toMatch(/function startAutoRefresh\(\)[\s\S]*if \(!pageAlive\) return/)
    expect(logs).toMatch(/watch\(auto,[\s\S]*if \(!pageAlive\) return/)
    expect(pool).toMatch(/watch\(selected, \(\) => \{[\s\S]*if \(!pageAlive\) return/)
    expect(terminal).toMatch(/watch\(container, \(id\) => \{[\s\S]*if \(!pageAlive\) return/)
    expect(settings).toMatch(/async function loadLauncher\(\) \{\s*\n\s*if \(!pageAlive\) return/)
    expect(settings).toMatch(/await sleep\(300\)\s*\n\s*if \(!pageAlive\) return/)
    expect(drawer).toMatch(/watch\(\(\) => props\.service, \(\) => \{[\s\S]*if \(!pageAlive\) return/)
    expect(poll).toMatch(/if \(gen !== generation\) return\s*\n\s*await tick\(\)/)
    expect(client).toMatch(/const userAborted = Boolean\(signal\?\.aborted\)/)
    expect(client).toMatch(/if \(signal\?\.aborted\) \{\s*\n\s*const err = new Error\('aborted'\)/)
    expect(client).toMatch(/finiteN\(value, null\)/)
    expect(client).not.toMatch(/value: Number\(value\)/)
    expect(client).toMatch(/asUri\(id\)/)
    expect(client).not.toMatch(/encodeURIComponent\(id\)/)
  })

  it('discards a second-await mutation that used to land after leave', () => {
    const apps = readFileSync(resolve(SRC, 'views/Apps.vue'), 'utf8')
    const compose = readFileSync(resolve(SRC, 'views/Compose.vue'), 'utf8')
    const photoshub = readFileSync(resolve(SRC, 'views/PhotosHub.vue'), 'utf8')
    const wireguard = readFileSync(resolve(SRC, 'views/WireGuard.vue'), 'utf8')
    const ollama = readFileSync(resolve(SRC, 'views/Ollama.vue'), 'utf8')
    const assist = readFileSync(resolve(SRC, 'components/AssistantDrawer.vue'), 'utf8')
    expect(apps).toMatch(/async function checkRemoteUpdates\(\)[\s\S]*await loadRemote\(\)[\s\S]*if \(!stillOnApps\(generation\)\) return/)
    expect(apps).toMatch(/async function toggleManagedAutostart\([\s\S]*await loadManaged\(true\)[\s\S]*if \(!stillOnApps\(generation\)\) return/)
    expect(apps).toMatch(/async function doManagedAction\([\s\S]*await loadManaged\(true\)[\s\S]*if \(!stillOnApps\(generation\)\) return/)
    expect(compose).toMatch(/async function create\(\)[\s\S]*await loadStacks\(true\)[\s\S]*if \(!pageAlive\) return[\s\S]*selected\.value = finiteText\(recGet\(j, 'id'\), ''\)/)
    expect(photoshub).toMatch(/asRecord\(await getPhotosHubStatus\(\)\)\s*\n\s*if \(generation !== loadGeneration \|\| !pageAlive\) return\s*\n\s*data\.value =/)
    expect(photoshub).toMatch(/asRecord\(next\.status_after \|\| \(await getPhotosHubStatus\(\)\)\)\s*\n\s*if \(generation !== loadGeneration \|\| !pageAlive\) return\s*\n\s*data\.value = after/)
    expect(wireguard).not.toMatch(/pingResult\.value = await pingWireguardPeers/)
    expect(wireguard).toMatch(/await pingWireguardPeers\(\)[\s\S]*if \(generation !== loadGeneration \|\| !pageAlive\) return[\s\S]*pingResult\.value = \{/)
    expect(ollama).toMatch(/async function scrollChat\(\)[\s\S]*await nextTick\(\)[\s\S]*if \(!pageAlive\) return/)
    expect(assist).toMatch(/if \(props\.open && generation === sendGeneration\) \{[\s\S]*await nextTick\(\)\s*\n\s*if \(generation !== sendGeneration \|\| !props\.open\) return[\s\S]*logEl\.value\?\.scrollTo/)
    expect(assist).toMatch(/\} finally \{\s*\n\s*if \(generation === sendGeneration\) \{\s*\n\s*busy\.value = false/)
    expect(assist).toMatch(/if \(!isOpen\) \{[\s\S]*busy\.value = false/)
  })

  it('ignores copy-to-clipboard results that arrive after leave', () => {
    const ALIVE = /pageAlive|dashAlive|disposed|stillOn/
    const offenders = []
    for (const [name, src] of vueFiles()) {
      if (!src.includes('copyToClipboard')) continue
      for (const m of src.matchAll(/await copyToClipboard\([^)]*\)/g)) {
        const after = src.slice(m.index, m.index + 280)
        if (!ALIVE.test(after)) {
          offenders.push(`${name}: copyToClipboard result used without an alive check`)
        }
      }
    }
    expect(offenders, 'a late clipboard write must not toast on an unmounted page').toEqual([])
  })

  it('does not keep busy after a refresh that bumps generation', () => {
    // A mutation that snapshots generation, then calls a loader that does
    // `++generation` before returning, cannot gate busy=false on a generation
    // match: the increment runs before finally, so the button stays disabled.
    const offenders = []
    for (const [name, src] of vueFiles()) {
      const incrementers = new Map()
      for (const m of src.matchAll(/async function (\w+)\s*\([^)]*\)\s*\{/g)) {
        const head = src.slice(m.index + m[0].length, m.index + m[0].length + 500)
        const bump = head.match(/const \w+ = \+\+(\w+)/)
        if (bump) incrementers.set(m[1], bump[1])
      }
      for (const m of src.matchAll(/(?:async )?function (\w+)\s*\([^)]*\)\s*\{/g)) {
        const fn = m[1]
        const rest = src.slice(m.index)
        const stop = rest.slice(20).search(/\n(?:async function |function |onMounted|onUnmounted)/)
        const body = rest.slice(0, stop === -1 ? 3500 : stop + 20)
        const snap = body.match(/const (generation|request|seq|mySeq) = (?!\+\+)(\w+)/)
        if (!snap) continue
        const [, local, counter] = snap
        const fin = body.match(/finally(?:\s*\(\s*\(\)\s*=>\s*|\s*)\{([\s\S]*?)\n  \}/)
        if (!fin) continue
        if (!/\w*(?:[Bb]usy|[Ll]oading|[Ss]aving|[Ss]witching)\w*\.value = false/.test(fin[1])) continue
        const gated =
          new RegExp(`${local} === ${counter}`).test(fin[1])
          || /stillOn\w*\(\s*generation\s*\)/.test(fin[1])
        if (!gated) continue
        const before = body.slice(0, body.indexOf('finally'))
          .replace(/setTimeout\s*\(\s*(?:async\s*)?\([^)]*\)\s*=>\s*\{[\s\S]*?\n\s*\},/g, '')
        const hits = []
        for (const [inc, gen] of incrementers) {
          if (gen !== counter) continue
          if (new RegExp(`(?:await |void |\\n\\s*)${inc}\\s*\\(`).test(before)) hits.push(inc)
        }
        if (hits.length) {
          offenders.push(`${name}: ${fn}() calls ${hits[0]}() which ++${counter}, then finally gates busy on ${local}`)
        }
      }
    }
    expect(
      offenders,
      'refresh() bumps generation before finally; clear busy with pageAlive',
    ).toEqual([])
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

describe('error live regions', () => {
  /**
   * Bodies of every aria-live element, including nested children.
   *
   * The first version stopped at the first matching close tag, so Ollama's
   * chat log (`<div aria-live><div class="meta">…</div>…{{ cond ? t() : '' }}`)
   * never saw the empty interpolation sitting two siblings down.
   */
  function liveRegions(template) {
    const regions = []
    const re = /<\/?([a-z][\w-]*)\b[^>]*\/?>/gi
    const stack = []
    for (const m of template.matchAll(re)) {
      const raw = m[0]
      const tag = m[1].toLowerCase()
      if (raw.startsWith('</')) {
        for (let i = stack.length - 1; i >= 0; i--) {
          if (stack[i].tag === tag) {
            if (stack[i].live) {
              regions.push({
                raw: stack[i].raw,
                body: template.slice(stack[i].bodyStart, m.index),
                index: stack[i].index,
              })
            }
            stack.length = i
            break
          }
        }
        continue
      }
      const voidEl = /\/\s*>$/.test(raw)
        || ['area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'param', 'source', 'track', 'wbr'].includes(tag)
      if (voidEl) continue
      stack.push({
        tag,
        // role=status is an implicit polite live region; App.vue's toast
        // binds :aria-live, but several siblings only set the role.
        live: /aria-live/.test(raw) || /\brole="status"/.test(raw),
        raw,
        bodyStart: m.index + raw.length,
        index: m.index,
      })
    }
    return regions
  }

  function liveRegionBodies(template) {
    return liveRegions(template).map((r) => r.body)
  }

  function ancestorGatesIdent(template, index, ident) {
    const re = /<\/?([a-z][\w-]*)\b([^>]*)\/?>/gi
    const stack = []
    const voidEl = new Set([
      'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link',
      'meta', 'param', 'source', 'track', 'wbr',
    ])
    for (const m of template.slice(0, index).matchAll(re)) {
      const raw = m[0]
      const tag = m[1].toLowerCase()
      const attrs = m[2]
      if (raw.startsWith('</')) {
        for (let i = stack.length - 1; i >= 0; i--) {
          if (stack[i].tag === tag) {
            stack.length = i
            break
          }
        }
        continue
      }
      if (/\/\s*>$/.test(raw) || voidEl.has(tag)) continue
      stack.push({ tag, attrs })
    }
    const vif = new RegExp(`\\bv-(?:if|else-if)="[^"]*\\b${ident}\\b`)
    return stack.some((el) => vif.test(el.attrs))
  }

  it('does not interpolate an empty string into a live region', () => {
    // A failed PhotosHub log fetch used `logError ? '' : '—'` inside aria-live,
    // so the region announced nothing while the error sat in a silent sibling.
    // The `: ''` tail (Ollama chat-body) is the same hole: thinking-only and
    // error replies interpolated nothing while the text lived next door.
    const EMPTY = /\?\s*['"]{2}\s*:|:\s*['"]{2}|\|\|\s*['"]{2}|\?\?\s*['"]{2}/
    const offenders = []
    for (const [name, src] of vueFiles()) {
      const template = src.slice(0, src.search(/<script\b/) >>> 0)
      for (const body of liveRegionBodies(template)) {
        for (const interp of body.matchAll(/\{\{([\s\S]*?)\}\}/g)) {
          if (EMPTY.test(interp[1])) {
            offenders.push(`${name}: live region can render empty — ${interp[0].trim().slice(0, 60)}`)
          }
        }
      }
    }
    expect(offenders, 'an error that lands in a live region must have text').toEqual([])
  })

  it('does not interpolate an idle empty ref into an always-on live region', () => {
    // v-if="msg" on the live node (or on a parent / inner child) keeps '' out
    // of the accessibility tree. An always-mounted region that renders
    // {{ toast }} — toast starts as ref('') and is cleared back to '' — tells
    // the screen reader a blank update when the timer fires.
    const offenders = []
    for (const [name, src] of vueFiles()) {
      const emptyRefs = new Set(
        [...src.matchAll(/\b(?:const|let)\s+([A-Za-z_$][\w$]*)\s*=\s*ref\(\s*['"]{2}\s*\)/g)]
          .map((m) => m[1]),
      )
      if (!emptyRefs.size) continue
      const template = src.slice(0, src.search(/<script\b/) >>> 0)
      for (const region of liveRegions(template)) {
        for (const interp of region.body.matchAll(/\{\{\s*([A-Za-z_$][\w$]*)\s*\}\}/g)) {
          const ident = interp[1]
          if (!emptyRefs.has(ident)) continue
          // v-if on the live node only keeps '' out when it actually names
          // this ref. `v-if="tab==='logs'"` still interpolates idle {{ msg }}.
          const gatedHere = new RegExp(`\\bv-(?:if|else-if)="[^"]*\\b${ident}\\b`).test(region.raw)
          if (gatedHere) continue
          const beforeInterp = region.body.slice(0, interp.index)
          if (new RegExp(`\\bv-(?:if|else-if)="[^"]*\\b${ident}\\b`).test(beforeInterp)) continue
          if (ancestorGatesIdent(template, region.index, ident)) continue
          offenders.push(`${name}: always-on live region interpolates empty ${ident}`)
        }
      }
    }
    expect(
      offenders,
      'idle live regions must v-if the text, not interpolate ref(\'\')',
    ).toEqual([])
  })

  it('keeps persistent alert wrappers compact so :empty applies', () => {
    // Login takes idle alert wrappers out of flow with `:empty`. A newline
    // between the wrapper and its v-if child is a text node, so :empty never
    // matches and the form spends a gap on an invisible box.
    const offenders = []
    for (const [name, src] of vueFiles()) {
      const template = src.slice(0, src.search(/<script\b/) >>> 0)
      for (const m of template.matchAll(/<([a-z][\w-]*)\b([^>]*role="alert"[^>]*)>([\s\S]*?)<\/\1>/gi)) {
        const [, , attrs, body] = m
        if (!/aria-live/.test(attrs)) continue
        if (!/v-if=/.test(body)) continue
        if (/^\s/.test(body) || /\s$/.test(body)) {
          offenders.push(`${name}: whitespace inside persistent error live region`)
        }
      }
    }
    expect(offenders).toEqual([])
  })

  it('does not keep a token-error live region on the returning-user form', () => {
    const login = readFileSync(resolve(SRC, 'views/Login.vue'), 'utf8')
    const template = login.slice(0, login.search(/<script\b/) >>> 0)
    expect(template).not.toMatch(/class="token-error-live"/)
    expect(template).toMatch(/v-if="setupMode && tokenNeeded && tokenError"/)
  })

  it('does not keep leftover always-on live regions on idle Compose job logs', () => {
    const compose = readFileSync(resolve(SRC, 'views/Compose.vue'), 'utf8')
    expect(compose).toMatch(/v-if="jobLog"[\s\S]{0,80}aria-live="polite"/)
    expect(compose).not.toMatch(/<pre class="log"[^>]*aria-live="polite">\{\{ jobLog \}\}/)
  })

  it('does not keep leftover always-on live regions on idle PhotosHub logs', () => {
    const photoshub = readFileSync(resolve(SRC, 'views/PhotosHub.vue'), 'utf8')
    expect(photoshub).toMatch(/v-if="lastAction\.stdout \|\| lastAction\.stderr"[\s\S]{0,80}aria-live="polite"/)
    expect(photoshub).toMatch(/v-if="asArray\(logData\?\.lines\)\.length"[\s\S]{0,80}aria-live="polite"/)
    expect(photoshub).not.toMatch(/aria-live="polite">\{\{ lastAction\.stdout \|\| lastAction\.stderr \|\| '—' \}\}/)
    expect(photoshub).not.toMatch(/\|\| '—' \}\}<\/pre>/)
  })

  it('does not keep the Ollama chat log live while it is empty', () => {
    const ollama = readFileSync(resolve(SRC, 'views/Ollama.vue'), 'utf8')
    expect(ollama).toMatch(/:aria-live="asArray\(chatMessages\)\.length \? 'polite' : undefined"/)
    expect(ollama).not.toMatch(/class="chat-log" aria-live="polite"/)
  })

  it('does not keep the assistant log live while it is empty', () => {
    const assist = readFileSync(resolve(SRC, 'components/AssistantDrawer.vue'), 'utf8')
    expect(assist).toMatch(/:aria-live="asArray\(turns\)\.length \? 'polite' : undefined"/)
    expect(assist).not.toMatch(/class="assist-log" aria-live="polite"/)
  })
})

describe('leftover Infinity interpolations', () => {
  // Logs fmtSize and VncConsole session limits already reject Infinity. The
  // quieter leftover pages still interpolated the raw leftover number: Audit
  // returned the unparsed `ts` when Date failed, Bookmarks printed `b.ms`,
  // and Logs forwarded `meta.lines` into the i18n string.

  it('Audit timestamps do not fall back to the raw leftover value', () => {
    const audit = readFileSync(resolve(SRC, 'views/Audit.vue'), 'utf8')
    expect(audit).toMatch(/function fmt\(ts\)[\s\S]*Number\.isNaN\(d\.getTime\(\)\) \? ''/)
    expect(audit).not.toMatch(/Number\.isNaN\(d\.getTime\(\)\) \? ts/)
    expect(audit).toMatch(/Number\.isFinite\(retained\)/)
  })

  it('Bookmarks latency rejects non-finite leftovers', () => {
    const bookmarks = readFileSync(resolve(SRC, 'views/Bookmarks.vue'), 'utf8')
    expect(bookmarks).not.toMatch(/\{\{\s*b\.ms\s*\}\}/)
    expect(bookmarks).toMatch(/function finiteMs\([\s\S]*Number\.isFinite/)
  })

  it('Logs sizes and line counts reject non-finite leftovers', () => {
    const logs = readFileSync(resolve(SRC, 'views/Logs.vue'), 'utf8')
    expect(logs).toMatch(/function fmtSize\([\s\S]*Number\.isFinite/)
    expect(logs).toMatch(/function fmtCount\([\s\S]*Number\.isFinite/)
    expect(logs).toMatch(/t\('logs\.lines_n',\s*\{\s*n:\s*fmtCount\(/)
    expect(logs).not.toMatch(/\{\{\s*s\.name\s*\}\}/)
    expect(logs).toMatch(/finiteText\(recGet\(s, 'name'\)\)/)
  })

  it('Files and Ollama size formatters reject leftover Infinity', () => {
    const files = readFileSync(resolve(SRC, 'views/Files.vue'), 'utf8')
    const ollama = readFileSync(resolve(SRC, 'views/Ollama.vue'), 'utf8')
    expect(files).toMatch(/function fmtSize\([\s\S]*Number\.isFinite/)
    expect(files).toMatch(/let v = finiteN\(n, null\)/)
    expect(ollama).toMatch(/function fmtSize\([\s\S]*Number\.isFinite/)
    expect(ollama).toMatch(/function finiteN\([\s\S]*Number\.isFinite/)
    expect(ollama).toMatch(/const n = finiteNum\(v, null\)/)
    expect(ollama).toMatch(/const v = finiteNum\(n, null\)/)
    expect(ollama).toMatch(/finiteN\(testResult\.duration_s\)/)
    expect(ollama).toMatch(/finiteN\(testResult\.tokens_per_s\)/)
  })

  it('VncConsole session limits go through finiteSecs', () => {
    const vnc = readFileSync(resolve(SRC, 'components/VncConsole.vue'), 'utf8')
    expect(vnc).toMatch(/function finiteSecs\([\s\S]*Number\.isFinite/)
    expect(vnc).toMatch(/const n = finiteN\(value, null\)/)
    expect(vnc).toMatch(/expires:\s*finiteSecs\(recGet\(sessionInfo, 'expires_in'\)\)/)
    expect(vnc).toMatch(/max:\s*finiteSecs\(recGet\(sessionInfo, 'max_session_seconds'\)\)/)
    expect(vnc).toMatch(/finiteText\(recGet\(vm, 'name'\)\)/)
    expect(vnc).not.toMatch(/vm\.console\?\.protocol \|\| 'VNC'/)
    expect(vnc).toMatch(/finiteText\(recGet\(recGet\(vm, 'console'\), 'protocol'\)/)
    expect(vnc).not.toMatch(/\{\{\s*errorMessage\s*\}\}/)
    expect(vnc).toMatch(/finiteText\(errorMessage\)/)
    expect(vnc).not.toMatch(/event\.detail\?\.reason \|\| t\('vms\.console_connection_failed'\)/)
    expect(vnc).toMatch(/finiteText\(recGet\(event\.detail, 'reason'\), ''\) \|\| t\('vms\.console_connection_failed'\)/)
    expect(vnc).not.toMatch(/\{\{\s*statusLabel\s*\}\}/)
    expect(vnc).toMatch(/finiteText\(statusLabel\)/)
    expect(vnc).toMatch(/finiteText\(status\.value, 'failed'\)/)
  })

  it('Dashboard load/bps/bookmark latency reject leftover Infinity', () => {
    const dashboard = readFileSync(resolve(SRC, 'views/Dashboard.vue'), 'utf8')
    expect(dashboard).toMatch(/function fmtN\([\s\S]*Number\.isFinite/)
    expect(dashboard).toMatch(/function formatBps\([\s\S]*Number\.isFinite/)
    expect(dashboard).not.toMatch(/b\.ms != null \? b\.ms \+ ' ms'/)
    expect(dashboard).toMatch(/function bmLabel\([\s\S]*Number\.isFinite\(ms\)/)
  })

  it('LineChart drops leftover Infinity samples instead of labelling them', () => {
    const chart = readFileSync(resolve(SRC, 'components/LineChart.vue'), 'utf8')
    expect(chart).toMatch(/typeof v === 'number' && Number\.isFinite\(v\) \? v : null/)
    expect(chart).toMatch(/function formatLegend\([\s\S]*Number\.isFinite/)
    expect(chart).toMatch(/function formatTick\([\s\S]*Number\.isFinite/)
    expect(chart).not.toMatch(/\{\{\s*g\.label\s*\}\}/)
    expect(chart).toMatch(/finiteText\(recGet\(g, 'label'\)\)/)
    expect(chart).not.toMatch(/\{\{\s*s\.name\s*\}\}/)
    expect(chart).toMatch(/finiteText\(recGet\(s, 'name'\)\)/)
    expect(chart).not.toMatch(/\{\{\s*refLabel\s*\}\}/)
    expect(chart).toMatch(/finiteText\(refLabel\)/)
    expect(chart).not.toMatch(/\{\{\s*unitHint\s*\}\}/)
    expect(chart).toMatch(/finiteText\(unitHint\)/)
  })

  it('size/age formatters used in templates Number.isFinite leftover values', () => {
    // toFixed(Infinity) and Math.round(Infinity / n) stringify as the word
    // "Infinity". Any helper the template interpolates that does that math
    // has to reject non-finite leftovers the way Logs fmtSize does.
    function braceBody(src, openIdx) {
      let depth = 0
      for (let i = openIdx; i < src.length; i++) {
        if (src[i] === '{') depth++
        else if (src[i] === '}') {
          depth--
          if (depth === 0) return src.slice(openIdx + 1, i)
        }
      }
      return ''
    }

    const STRINGIFIES = /\.toFixed\s*\(|Math\.(?:round|floor)\s*\([^)]*\//
    const BYTES = /\/\s*2\s*\*\*\s*30|\/\s*1024|\/\s*1e[369]/
    const offenders = []
    for (const [name, src] of vueFiles()) {
      const template = src.slice(0, src.search(/<script\b/) >>> 0)
      const script = src.slice(src.search(/<script\b/) >>> 0)
      const decls = [
        ...script.matchAll(/function\s+(\w+)\s*\([^)]*\)\s*\{/g),
        ...script.matchAll(/(?:const|let)\s+(\w+)\s*=\s*computed\s*\(\s*(?:\(\)\s*=>\s*)?\{/g),
      ]
      for (const m of decls) {
        const fn = m[1]
        if (!new RegExp(`\\b${fn}\\b`).test(template)) continue
        const openIdx = m.index + m[0].length - 1
        const body = braceBody(script, openIdx)
        if (!STRINGIFIES.test(body) && !BYTES.test(body)) continue
        if (!/Number\.isFinite/.test(body)) {
          offenders.push(`${name}: ${fn} interpolates numbers without Number.isFinite`)
        }
      }
    }
    expect(
      offenders,
      'template formatters must clamp leftover Infinity/NaN',
    ).toEqual([])
  })

  it('does not concatenate leftover size_gb/load1 without a finite check', () => {
    const app = readFileSync(resolve(SRC, 'App.vue'), 'utf8')
    const array = readFileSync(resolve(SRC, 'views/MainArray.vue'), 'utf8')
    const tools = readFileSync(resolve(SRC, 'views/Tools.vue'), 'utf8')
    const settings = readFileSync(resolve(SRC, 'views/Settings.vue'), 'utf8')
    const backups = readFileSync(resolve(SRC, 'views/Backups.vue'), 'utf8')
    const dash = readFileSync(resolve(SRC, 'views/Dashboard.vue'), 'utf8')
    expect(app).toMatch(/from ['"][^'"]*lib\/finite/)
    expect(app).toMatch(/function fmtLoad\([\s\S]*finiteN/)
    expect(array).toMatch(/function sizeGb\([\s\S]*Number\.isFinite/)
    expect(array).toMatch(/const n = finiteN\(value, null\)/)
    expect(tools).toMatch(/function sizeGb\([\s\S]*Number\.isFinite/)
    expect(settings).toMatch(/function sizeGb\([\s\S]*Number\.isFinite/)
    expect(backups).toMatch(/function sizeMb\([\s\S]*Number\.isFinite/)
    expect(backups).toMatch(/const n = finiteN\(value, null\)/)
    expect(dash).toMatch(/const cpuUsed = computed\(\(\) => \{[\s\S]*Number\.isFinite/)
    expect(dash).toMatch(/const memUsedPct = computed\(\(\) => \{[\s\S]*Number\.isFinite/)
  })

  it('Network leftover ports/pids/mtu go through finiteN', () => {
    const network = readFileSync(resolve(SRC, 'views/Network.vue'), 'utf8')
    expect(network).toMatch(/from ['"][^'"]*lib\/finite/)
    expect(network).not.toMatch(/\{\{\s*p\.port\s*\}\}/)
    expect(network).not.toMatch(/\{\{\s*p\.pid\s*\}\}/)
    expect(network).not.toMatch(/\{\{\s*i\.mtu \|\| '—'\s*\}\}/)
    expect(network).toMatch(/finiteN\(p\.port\)/)
    expect(network).toMatch(/finiteN\(p\.pid\)/)
    expect(network).toMatch(/finiteN\(i\.mtu\)/)
    expect(network).not.toMatch(/\$\{p\.host_port\}:\$\{p\.container_port\}/)
    expect(network).toMatch(/finiteN\(p\.host_port\)/)
    expect(network).toMatch(/finiteN\(p\.container_port\)/)
    expect(network).toMatch(/finiteText\(data\.network_failover\.state\.last_check_at/)
    expect(network).not.toMatch(/at: data\.network_failover\.state\.last_check_at/)
    expect(network).toMatch(/finiteText\(data\.network_failover\.state\.last_action/)
    expect(network).not.toMatch(/data\.default_route\.gateway \|\| '—'/)
    expect(network).toMatch(/finiteText\(data\.default_route\.gateway/)
    expect(network).not.toMatch(/data\.default_route\?\.interface \|\| '—'/)
    expect(network).toMatch(/finiteText\(data\.default_route\?\.interface/)
    expect(network).not.toMatch(/\{\{\s*s\.name\s*\}\}/)
    expect(network).toMatch(/finiteText\(s\.name\)/)
    expect(network).not.toMatch(/s\.ip \|\| '—'/)
    expect(network).toMatch(/finiteText\(s\.ip\)/)
    expect(network).not.toMatch(/n\.gateway \|\| '—'/)
    expect(network).toMatch(/finiteText\(n\.gateway\)/)
    expect(network).not.toMatch(/\{\{\s*a\.ip\s*\}\}/)
    expect(network).toMatch(/finiteText\(a\.ip\)/)
    expect(network).not.toMatch(/data\?\.services_error \|\| t\('network\.empty_services'\)/)
    expect(network).toMatch(/finiteText\(data\?\.services_error, ''\) \|\| t\('network\.empty_services'\)/)
    expect(network).not.toMatch(/finiteText\(\(i\.ipv6 \|\| \[\]\)\.slice\(0,2\)\.join\(', '\)\)/)
    expect(network).toMatch(/asArray\(i\.ipv6\)\.slice\(0,2\)\.map\(n => finiteText\(n, ''\)\)/)
    expect(network).not.toMatch(/finiteText\(\(s\.dns\|\|\[\]\)\.join\(', '\)\)/)
    expect(network).toMatch(/asArray\(s\.dns\)\.map\(n => finiteText\(n, ''\)\)/)
    expect(network).not.toMatch(/\{\{\s*msg\s*\}\}/)
    expect(network).toMatch(/finiteText\(msg\)/)
    expect(network).toMatch(/toast\('❌ ' \+ finiteText\(e\.message\)\)/)
    expect(network).not.toMatch(/\{\{\s*p\.process\s*\}\}/)
    expect(network).toMatch(/finiteText\(p\.process\)/)
    expect(network).not.toMatch(/\{\{\s*p\.user\s*\}\}/)
    expect(network).toMatch(/finiteText\(p\.user\)/)
    expect(network).not.toMatch(/\{\{\s*p\.address\s*\}\}/)
    expect(network).toMatch(/finiteText\(p\.address\)/)
    expect(network).not.toMatch(/\{\{\s*r\.flags\s*\}\}/)
    expect(network).toMatch(/finiteText\(r\.flags\)/)
    expect(network).not.toMatch(/\{\{\s*n\.driver\s*\}\}/)
    expect(network).toMatch(/finiteText\(n\.driver\)/)
    expect(network).not.toMatch(/\{\{\s*portEdit\s*\}\}/)
    expect(network).toMatch(/finiteText\(portEdit\)/)
    expect(network).not.toMatch(/\{\{\s*lookupResult\.host\s*\}\}/)
    expect(network).toMatch(/finiteText\(lookupResult\.host\)/)
    expect(network).not.toMatch(/\{\{\s*lookupResult\.message\s*\}\}/)
    expect(network).toMatch(/finiteText\(lookupResult\.message\)/)
    expect(network).not.toMatch(/\{\{\s*data\.wstunnel\.client_command\s*\}\}/)
    expect(network).toMatch(/finiteText\(data\.wstunnel\.client_command\)/)
    expect(network).not.toMatch(/msg\.value = j\.message \|\| ''/)
    expect(network).toMatch(/msg\.value = finiteText\(j\.message, ''\)/)
  })

  it('Containers leftover engine figures go through finiteN', () => {
    const containers = readFileSync(resolve(SRC, 'views/Containers.vue'), 'utf8')
    expect(containers).toMatch(/from ['"][^'"]*lib\/finite/)
    expect(containers).toMatch(/finiteN\(recGet\(recGet\(engineInfo, 'info'\), 'Containers'/)
    expect(containers).toMatch(/finiteN\(recGet\(recGet\(engineInfo, 'info'\), 'NCPU'/)
    expect(containers).toMatch(/finiteN\(recGet\(recGet\(engineInfo.value, 'info'\), 'MemTotal'/)
    expect(containers).toMatch(/finiteN\(asArray\(filteredContainers\)\.length\)/)
    expect(containers).toMatch(/finiteText\(recGet\(c, 'name'\), ''\)\.toLowerCase\(\)/)
    expect(containers).toMatch(/recGet\(c, 'system'\)/)
    expect(containers).toMatch(/Object\.keys\(asRecord\(map\)\)/)
    expect(containers).toMatch(/asTrimmed\(q\.value\)\.toLowerCase\(\)/)
    expect(containers).not.toMatch(/typeof q\.value === 'string' \? q\.value\.trim\(\)\.toLowerCase\(\)/)
    expect(containers).not.toMatch(/engineInfo\.info\?\.Containers \?\? '—'/)
    expect(containers).not.toMatch(/stats\[c\.id\]\?\.mem_pct \|\| stats\[c\.id\]\?\.mem \|\| ''/)
    expect(containers).toMatch(/finiteN\(j\.done, 0\)/)
    expect(containers).toMatch(/finiteN\(j\.total, 0\)/)
    expect(containers).not.toMatch(/j\.done \|\| 0/)
    expect(containers).toMatch(/finiteText\(recGet\(data, 'update_checked_at'/)
    expect(containers).not.toMatch(/\{\{\s*data\.update_checked_at\s*\}\}/)
    expect(containers).toMatch(/finiteText\(recGet\(c, 'ports'\)/)
    expect(containers).not.toMatch(/\{\{\s*c\.ports \|\| '—'\s*\}\}/)
    expect(containers).not.toMatch(/engineInfo\.orb_version \|\| '—'/)
    expect(containers).toMatch(/finiteText\(recGet\(engineInfo, 'orb_version'/)
    expect(containers).toMatch(/finiteText\(recGet\(recGet\(engineInfo, 'info'\), 'ServerVersion'/)
    expect(containers).not.toMatch(/\{\{\s*c\.name\s*\}\}/)
    expect(containers).toMatch(/finiteText\(recGet\(c, 'name'\)/)
    expect(containers).not.toMatch(/im\.Repository \|\| '—'/)
    expect(containers).toMatch(/finiteText\(recGet\(im, 'Repository'/)
    expect(containers).not.toMatch(/inspectData\.State\?\.Health \|\| '—'/)
    expect(containers).toMatch(/finiteText\(recGet\(recGet\(inspectData, 'State'\), 'Health'/)
    expect(containers).not.toMatch(/finiteText\(stats\[c\.id\]\?\.mem_pct \|\| stats\[c\.id\]\?\.mem\)/)
    expect(containers).toMatch(/finiteText\(stats\[c\.id\]\?\.mem_pct, ''\) \|\| finiteText\(stats\[c\.id\]\?\.mem\)/)
    expect(containers).not.toMatch(/\{\{\s*execOut \|\| t\('docker\.exec_output_ph'\)\s*\}\}/)
    expect(containers).toMatch(/finiteText\(execOut, ''\) \|\| t\('docker\.exec_output_ph'\)/)
    expect(containers).not.toMatch(/\(inspectData\.Env\|\|\[\]\)\.join\('\\n'\)/)
    expect(containers).toMatch(/finiteText\(e, ''\)/)
    expect(containers).not.toMatch(/toast\('❌ ' \+ e\.message\)/)
    expect(containers).toMatch(/toast\('❌ ' \+ finiteText\(e\.message\)\)/)
    expect(containers).not.toMatch(/`❌ \$\{j\.message\}`/)
    expect(containers).toMatch(/`❌ \$\{finiteText\(j\.message\)\}`/)
    expect(containers).not.toMatch(/action: labels\[action\] \|\| action/)
    expect(containers).toMatch(/action: finiteText\(labels\[action\], ''\) \|\| finiteText\(action\)/)
    expect(containers).not.toMatch(/\{ action, n: selected\.value\.length \}/)
    expect(containers).toMatch(/action: finiteText\(action\), n: finiteN\(asArray\(selected\.value\)\.length, 0\)/)
    expect(containers).not.toMatch(/image: ref \}\)/)
    expect(containers).toMatch(/image: finiteText\(ref\)/)
    expect(containers).not.toMatch(/\{\{\s*c\.project\s*\}\}/)
    expect(containers).toMatch(/finiteText\(recGet\(c, 'project'\)/)
    expect(containers).not.toMatch(/\{\{\s*v\.Driver\s*\}\}/)
    expect(containers).toMatch(/finiteText\(recGet\(v, 'Driver'\)/)
    expect(containers).not.toMatch(/\{\{\s*v\.Mountpoint\s*\}\}/)
    expect(containers).toMatch(/finiteText\(recGet\(v, 'Mountpoint'\)/)
    expect(containers).not.toMatch(/\{\{\s*n\.Scope\s*\}\}/)
    expect(containers).toMatch(/finiteText\(recGet\(n, 'Scope'\)/)
    expect(containers).not.toMatch(/\{\{\s*n\.Driver\s*\}\}/)
    expect(containers).toMatch(/finiteText\(recGet\(n, 'Driver'\)/)
    expect(containers).not.toMatch(/\{\{\s*engineInfo\.info\?\.OperatingSystem\s*\}\}/)
    expect(containers).toMatch(/finiteText\(recGet\(recGet\(engineInfo, 'info'\), 'OperatingSystem'\)/)
    expect(containers).not.toMatch(/\{\{\s*engineInfo\.docker_cli\s*\}\}/)
    expect(containers).toMatch(/finiteText\(recGet\(engineInfo, 'docker_cli'\)/)
    expect(containers).not.toMatch(/\{\{\s*logName\s*\}\}/)
    expect(containers).toMatch(/finiteText\(logName\)/)
    expect(containers).not.toMatch(/\{\{\s*logText\s*\}\}/)
    expect(containers).toMatch(/finiteText\(logText\)/)
    expect(containers).not.toMatch(/logName\.value = c\.name/)
    expect(containers).toMatch(/logName\.value = finiteText\(recGet\(c, 'name'/)
    expect(containers).toMatch(/logText\.value \+ finiteText\(chunk, ''\)/)
  })

  it('takes the off Screen Sharing control out of the tab order', () => {
    const dash = readFileSync(resolve(SRC, 'views/Dashboard.vue'), 'utf8')
    expect(dash).toMatch(/:tabindex="ss\.running \? undefined : -1"/)
    expect(dash).toMatch(/:aria-disabled="ss\.running \? undefined : 'true'"/)
  })

  it('Apps leftover catalog counts go through finiteN', () => {
    const apps = readFileSync(resolve(SRC, 'views/Apps.vue'), 'utf8')
    expect(apps).toMatch(/from ['"][^'"]*lib\/finite/)
    expect(apps).toMatch(/finiteN\(recGet\(recGet\(managed, 'counts'\), 'total'\)/)
    expect(apps).toMatch(/finiteN\(asArray\(filtered\)\.length\)/)
    expect(apps).toMatch(/finiteN\(asArray\(catalog\)\.length\)/)
    expect(apps).toMatch(/finiteN\(asArray\(filteredManaged\)\.length\)/)
    expect(apps).toMatch(/fieldText\(recGet\(x, 'name'\)\)/)
    expect(apps).toMatch(/recGet\(x, 'featured'\)/)
    expect(apps).toMatch(/finiteN\(autostart\.counts\.autostart_on\)/)
    expect(apps).not.toMatch(/\{\{\s*managed\.counts\.total\s*\}\}/)
    expect(apps).toMatch(/finiteN\(overview\.value\.total, null\)/)
    expect(apps).not.toMatch(/r\.unchanged \?\? 0/)
    expect(apps).toMatch(/finiteText\(recGet\(remoteInfo, 'last_check'/)
    expect(apps).not.toMatch(/\{\{\s*remoteInfo\.last_check\s*\}\}/)
    expect(apps).toMatch(/finiteText\(recGet\(c, 'ports'\)/)
    expect(apps).not.toMatch(/\{\{\s*c\.ports\s*\}\}/)
    expect(apps).toMatch(/finiteText\(recGet\(it, 'ports_summary'/)
    expect(apps).not.toMatch(/\{\{\s*it\.detail \|\| it\.plist \|\| '—'\s*\}\}/)
    expect(apps).not.toMatch(/finiteText\(it\.detail \|\| it\.plist\)/)
    expect(apps).toMatch(/finiteText\(recGet\(it, 'detail'\), ''\) \|\| finiteText\(recGet\(it, 'plist'/)
    expect(apps).not.toMatch(/o\.version \|\| '—'/)
    expect(apps).toMatch(/finiteText\(recGet\(o, 'version'/)
    expect(apps).toMatch(/finiteText\(recGet\(detail, 'uuid'/)
    expect(apps).not.toMatch(/\{\{\s*tpl\.name\s*\}\}/)
    expect(apps).toMatch(/finiteText\(recGet\(tpl, 'name'\)/)
    expect(apps).not.toMatch(/\{\{\s*it\.name\s*\}\}/)
    expect(apps).toMatch(/finiteText\(recGet\(it, 'name'\)/)
    expect(apps).not.toMatch(/\{\{\s*detail\.name\s*\}\}/)
    expect(apps).toMatch(/finiteText\(recGet\(detail, 'name'\)/)
    expect(apps).not.toMatch(/n\.ip \|\| '—'/)
    expect(apps).toMatch(/finiteText\(recGet\(n, 'ip'\)/)
    expect(apps).not.toMatch(/tpl\.desc \|\| '—'/)
    expect(apps).toMatch(/finiteText\(recGet\(tpl, 'desc'\)/)
    expect(apps).not.toMatch(/it\.path \|\| it\.package \|\| it\.backend \|\| '—'/)
    expect(apps).toMatch(/finiteText\(recGet\(it, 'path'\), ''\) \|\| finiteText\(recGet\(it, 'package'\), ''\) \|\| finiteText\(recGet\(it, 'backend'\)/)
    expect(apps).not.toMatch(/toast\('❌ ' \+ e\.message\)/)
    expect(apps).toMatch(/toast\('❌ ' \+ finiteText\(e\.message\)\)/)
    expect(apps).not.toMatch(/finiteText\(\(it\.ips \|\| \[\]\)\.join\(', '\)\)/)
    expect(apps).toMatch(/asArray\(recGet\(it, 'ips'\)\)\.map\(n => finiteText\(n, ''\)\)/)
    expect(apps).not.toMatch(/\{\{\s*cfMsg\s*\}\}/)
    expect(apps).toMatch(/finiteText\(cfMsg\)/)
    expect(apps).not.toMatch(/\(detail\.env_sample \|\| \[\]\)\.join\('\\n'\)/)
    expect(apps).toMatch(/asArray\(recGet\(detail, 'env_sample'\)\)\.map\(n => finiteText\(n, ''\)\)/)
    expect(apps).not.toMatch(/managed\.value && managed\.value\.host_ip\) \|\| window\.location\.hostname/)
    expect(apps).toMatch(/function browseHost\(\)[\s\S]*finiteText\(window\.location\.hostname, ''\)/)
    expect(apps).toMatch(/finiteText\(recGet\(managed.value, 'host_ip'\), ''\)/)
    expect(apps).not.toMatch(/compose_warnings \|\| \[\]\)\.map\(\(w\) => t\(`catalog_remote\.warn_\$\{w\}`\)\)\.join/)
    expect(apps).toMatch(/asArray\(recGet\(installTpl, 'compose_warnings'\)\)\.map\(\(w\) => finiteText\(w, ''\)\)/)
    expect(apps).not.toMatch(/:href="cfStatus\.login_url"/)
    expect(apps).toMatch(/:href="finiteText\(recGet\(cfStatus, 'login_url'\), ''\)"/)
    expect(apps).not.toMatch(/\{\{\s*cfStatus\.login_url\s*\}\}/)
    expect(apps).toMatch(/finiteText\(recGet\(cfStatus, 'login_url'\)/)
    expect(apps).not.toMatch(/:href="installUrl"/)
    expect(apps).toMatch(/:href="finiteText\(installUrl, ''\)"/)
    const tools = readFileSync(resolve(SRC, 'views/Tools.vue'), 'utf8')
    expect(tools).not.toMatch(/:href="updates\.github\?\.html_url"/)
    expect(tools).toMatch(/:href="finiteText\(updates\.github\.html_url, ''\)"/)
    expect(apps).not.toMatch(/installTpl\.method \|\| 'system'/)
    expect(apps).toMatch(/finiteText\(recGet\(installTpl, 'method'\), ''\) \|\| 'system'/)
    expect(apps).not.toMatch(/installTpl\.package \? ` · \$\{installTpl\.package\}`/)
    expect(apps).toMatch(/finiteText\(recGet\(installTpl, 'package'\), ''\) \? ` · \$\{finiteText\(recGet\(installTpl, 'package'\)\)\}`/)
    expect(apps).not.toMatch(/it\.policy \? ' · ' \+ it\.policy/)
    expect(apps).toMatch(/finiteText\(recGet\(it, 'policy'\), ''\) \? ' · ' \+ finiteText\(recGet\(it, 'policy'\)/)
    expect(apps).not.toMatch(/\{\{\s*it\.kind\s*\}\}/)
    expect(apps).toMatch(/finiteText\(recGet\(it, 'kind'\)/)
    expect(apps).not.toMatch(/\{\{\s*installTpl\.notes\s*\}\}/)
    expect(apps).toMatch(/finiteText\(recGet\(installTpl, 'notes'\)/)
    expect(apps).not.toMatch(/\{\{\s*v\.help\s*\}\}/)
    expect(apps).toMatch(/finiteText\(recGet\(v, 'help'\)/)
    expect(apps).not.toMatch(/tpl\.remote_version \? ` \$\{tpl\.remote_version\}`/)
    expect(apps).toMatch(/finiteText\(recGet\(tpl, 'remote_version'\), ''\) \? ` \$\{finiteText\(recGet\(tpl, 'remote_version'\)\)\}`/)
    expect(apps).not.toMatch(/class="tag">\{\{ tg \}\}<\/span>/)
    expect(apps).toMatch(/finiteText\(tg\)/)
    expect(apps).not.toMatch(/class="section-title">\{\{ grp \}\}<\/h2>/)
    expect(apps).toMatch(/finiteText\(grp\)/)
    expect(apps).not.toMatch(/\{\{\s*logTitle\s*\}\}/)
    expect(apps).toMatch(/finiteText\(logTitle\)/)
    expect(apps).not.toMatch(/\{\{\s*installCreds\s*\}\}/)
    expect(apps).toMatch(/finiteText\(installCreds\)/)
    expect(apps).toMatch(/function kindLabel\([\s\S]*finiteText\(k\)/)
    expect(apps).not.toMatch(/c\?\.label \|\| id \|\| 'other'/)
    expect(apps).toMatch(/finiteText\(c\?\.label, ''\) \|\| finiteText\(id/)
    expect(apps).not.toMatch(/`✅ \$\{action\}`/)
    expect(apps).toMatch(/`✅ \$\{finiteText\(action\)\}`/)
    expect(apps).not.toMatch(/`✅ restart=\$\{policy\}`/)
    expect(apps).toMatch(/`✅ restart=\$\{finiteText\(policy\)\}`/)
    expect(apps).not.toMatch(/r\.first_run_credentials \|\| installTpl\.value\.first_run_credentials/)
    expect(apps).toMatch(/finiteText\(r\.first_run_credentials, ''\) \|\| finiteText\(installTpl\.value\.first_run_credentials/)
    expect(apps).not.toMatch(/logTitle\.value = title \|\| jobId/)
    expect(apps).toMatch(/logTitle\.value = finiteText\(title, ''\) \|\| finiteText\(jobId\)/)
    expect(apps).not.toMatch(/logText\.value = j\.log \+/)
    expect(apps).toMatch(/logText\.value = finiteText\(recGet\(j, 'log'\), ''\)/)
    expect(apps).not.toMatch(/if \(tpl\.url_hint\) return tpl\.url_hint/)
    expect(apps).toMatch(/finiteText\(tpl\.url_hint, ''\) \|\| finiteText\(tpl\.url, ''\)/)
    expect(apps).toMatch(/v-for="tpl in asArray\(filtered\)"/)
    expect(apps).toMatch(/v-for="it in asArray\(filteredManaged\)"/)
  })

  it('Apps cloudflared login URL is announced when it appears', () => {
    // The sign-in link arrives asynchronously (login start + poll); without a
    // live region a screen reader user is never told the panel's key
    // call-to-action showed up.
    const apps = readFileSync(resolve(SRC, 'views/Apps.vue'), 'utf8')
    expect(apps).not.toMatch(/v-if="cfStatus\.login_url" class="notes" style/)
    expect(apps).toMatch(/v-if="recGet\(cfStatus, 'login_url'\)" class="notes" role="status"/)
  })

  it('Apps cloudflared tunnel picker tells error apart from empty', () => {
    // The status API reports tunnels_error when the Cloudflare fetch failed;
    // rendering "No tunnels found" for that case silently hid the failure.
    // The message is a live region and the error detail goes through
    // finiteText so a leftover value cannot render as junk.
    const apps = readFileSync(resolve(SRC, 'views/Apps.vue'), 'utf8')
    expect(apps).toMatch(/class="field-help" v-if="!asArray\(recGet\(cfStatus, 'tunnels'\)\).length" role="status"/)
    expect(apps).toMatch(/recGet\(cfStatus, 'logged_in'\) && finiteText\(recGet\(cfStatus, 'tunnels_error'\), ''\)/)
    expect(apps).toMatch(/t\('apps\.cf_tunnels_failed'\)/)
    expect(apps).not.toMatch(/\{\{\s*cfStatus\.tunnels_error\s*\}\}/)
    for (const locale of ['en', 'ja', 'zh-CN']) {
      const dict = readFileSync(resolve(SRC, `i18n/${locale}.js`), 'utf8')
      expect(dict).toMatch(/cf_tunnels_failed/)
    }
  })

  it('Apps cloudflared login URL is announced when it appears', () => {
    // The sign-in link arrives asynchronously (login start + poll); without a
    // live region a screen reader user is never told the panel's key
    // call-to-action showed up.
    const apps = readFileSync(resolve(SRC, 'views/Apps.vue'), 'utf8')
    expect(apps).not.toMatch(/v-if="cfStatus\.login_url" class="notes" style/)
    expect(apps).toMatch(/v-if="recGet\(cfStatus, 'login_url'\)" class="notes" role="status"/)
  })

  it('Dashboard leftover volumes/ports/rss go through finite helpers', () => {
    const dash = readFileSync(resolve(SRC, 'views/Dashboard.vue'), 'utf8')
    expect(dash).toMatch(/function fmt\(ts\)[\s\S]*fmtTs/)
    expect(dash).not.toMatch(/\{\{\s*v\.used_gb\s*\}\}/)
    expect(dash).not.toMatch(/\{\{\s*v\.pct\s*\}\}%/)
    expect(dash).not.toMatch(/\{\{\s*p\.port\s*\}\}/)
    expect(dash).not.toMatch(/\{\{\s*p\.rss_mb\s*\}M/)
    expect(dash).not.toMatch(/'pid '\s*\+\s*p\.pid/)
    expect(dash).toMatch(/fmtGb\(v\.used_gb\)/)
    expect(dash).toMatch(/finiteN\(p\.port\)/)
    expect(dash).toMatch(/finiteN\(p\.pid\)/)
    expect(dash).toMatch(/withUnit\(p\.rss_mb, 'M'\)/)
    expect(dash).not.toMatch(/\{\{\s*ups\.battery_percent\s*\}\}%/)
    expect(dash).toMatch(/withUnit\(ups\.battery_percent, '%'\)/)
    expect(dash).not.toMatch(/cstats\[c\.id\]\?\.mem_pct \|\| cstats\[c\.id\]\?\.mem \|\| '—'/)
    expect(dash).not.toMatch(/finiteText\(cstats\[c\.id\]\?\.mem_pct \|\| cstats\[c\.id\]\?\.mem\)/)
    expect(dash).toMatch(/finiteText\(cstats\[c\.id\]\?\.mem_pct, ''\) \|\| finiteText\(cstats\[c\.id\]\?\.mem\)/)
    expect(dash).toMatch(/finiteText\(cstats\[c\.id\]\?\.cpu\)/)
    expect(dash).toMatch(/formatSmartTemp\(d\.smart\.temp\)/)
    expect(dash).toMatch(/finiteN\(status\.adaptive\.auto_labeled, 0\)/)
    expect(dash).toMatch(/finiteN\(status\.adaptive\.orphan_count, 0\)/)
    expect(dash).not.toMatch(/status\.adaptive\.auto_labeled \|\| 0/)
    expect(dash).toMatch(/finiteN\(cpu\.value\.user, 0\)/)
    expect(dash).toMatch(/finiteText\(errText\(c\.detail\)\)/)
    expect(dash).not.toMatch(/class="detail"[^>]*>\{\{ errText\(c\.detail\) \}\}/)
    expect(dash).not.toMatch(/if \(d\?\.size\) return d\.size/)
    expect(dash).toMatch(/function formatDiskSize\([\s\S]*finiteText\(d\?\.size/)
    expect(dash).not.toMatch(/sensors\.value\?\.uptime\?\.uptime_text \|\| sys\.value\.uptime \|\| '—'/)
    expect(dash).toMatch(/finiteText\(sensors\.value\?\.uptime\?\.uptime_text/)
    expect(dash).not.toMatch(/\{\{\s*host\?\.cpu \|\| 'CPU'\s*\}\}/)
    expect(dash).toMatch(/finiteText\(host\?\.cpu, 'CPU'\)/)
    expect(dash).not.toMatch(/finiteText\(s\.detail \|\| s\.state\)/)
    expect(dash).toMatch(/finiteText\(s\.detail, ''\) \|\| finiteText\(s\.state\)/)
    expect(dash).toMatch(/finiteText\(s\.detail\)/)
    expect(dash).not.toMatch(/host\?\.hostname \|\| '—'/)
    expect(dash).toMatch(/finiteText\(host\?\.hostname/)
    expect(dash).not.toMatch(/host\?\.lan_ip \|\| host\?\.host_ip \|\| '—'/)
    expect(dash).toMatch(/finiteText\(host\?\.lan_ip/)
    expect(dash).not.toMatch(/if \(o\.version\) lines\.push\(`v\$\{o\.version\}`\)/)
    expect(dash).toMatch(/finiteText\(o\.version/)
    expect(dash).not.toMatch(/\{\{\s*s\.name\s*\}\}/)
    expect(dash).toMatch(/finiteText\(s\.name\)/)
    expect(dash).not.toMatch(/\{\{\s*p\.name\s*\}\}/)
    expect(dash).toMatch(/finiteText\(p\.name\)/)
    expect(dash).not.toMatch(/\{\{\s*c\.name\s*\}\}/)
    expect(dash).toMatch(/finiteText\(c\.name\)/)
    expect(dash).not.toMatch(/u\.name \|\| '—'/)
    expect(dash).toMatch(/finiteText\(u\.name\)/)
    expect(dash).not.toMatch(/diskArray\.value\.used_gb \?\? sensors/)
    expect(dash).toMatch(/finiteN\(diskArray\.value\.used_gb, null\) \?\? finiteN\(sensors\.value\?\.disk\?\.root_used_gb, null\) \?\? finiteN\(sys\.value\.disk_used_gb\)/)
    expect(dash).not.toMatch(/toast\('❌ ' \+ e\.message\)/)
    expect(dash).toMatch(/toast\('❌ ' \+ finiteText\(e\.message\)\)/)
    expect(dash).not.toMatch(/\{\{\s*loadError\s*\}\}/)
    expect(dash).toMatch(/finiteText\(loadError\)/)
    expect(dash).toMatch(/loadError\.value = finiteText\(e\.message \|\| String\(e\), ''\)/)
    expect(dash).not.toMatch(/:href="s\.url"/)
    expect(dash).toMatch(/:href="finiteText\(s\.url, ''\)"/)
    expect(dash).not.toMatch(/:href="c\.url"/)
    expect(dash).toMatch(/:href="finiteText\(c\.url, ''\)"/)
    expect(dash).not.toMatch(/:href="b\.url"/)
    expect(dash).toMatch(/:href="finiteText\(asRecord\(b\)\.url, ''\)"/)
    expect(dash).not.toMatch(/\{\{\s*labels\[a\] \|\| a\s*\}\}/)
    expect(dash).toMatch(/finiteText\(labels\[a\], ''\) \|\| finiteText\(a\)/)
    expect(dash).not.toMatch(/\{\{\s*p\.process\s*\}\}/)
    expect(dash).toMatch(/finiteText\(p\.process\)/)
    expect(dash).not.toMatch(/\{\{\s*p\.address\s*\}\}/)
    expect(dash).toMatch(/finiteText\(p\.address\)/)
    expect(dash).not.toMatch(/\{\{\s*v\.kind\s*\}\}/)
    expect(dash).toMatch(/finiteText\(v\.kind\)/)
    expect(dash).toMatch(/const mount = finiteText\(v\.mount, ''\)/)
  })

  it('Settings leftover epoch stamps go through fmtTs', () => {
    const settings = readFileSync(resolve(SRC, 'views/Settings.vue'), 'utf8')
    expect(settings).toMatch(/from ['"][^'"]*lib\/finite/)
    expect(settings).toMatch(/function fmtEpoch\([\s\S]*fmtTs/)
    expect(settings).toMatch(/function fmtUpsTs\([\s\S]*fmtTs/)
    expect(settings).toMatch(/finiteN\(sysBundle\.management\.panel_port\)/)
    expect(settings).not.toMatch(/\{\{\s*upsInfo\.battery_percent\s*\}\}%/)
    expect(settings).toMatch(/withUnit\(upsInfo\.battery_percent, '%'\)/)
    expect(settings).toMatch(/withUnit\(sysBundle\.power\.ups\.battery_percent, '%'\)/)
    expect(settings).not.toMatch(/\{\{\s*dockerInfo\.info\?\.NCPU\s*\}\}/)
    expect(settings).toMatch(/finiteN\(dockerInfo\.info\?\.NCPU/)
    expect(settings).toMatch(/finiteN\(dockerInfo\.info\?\.ContainersRunning/)
    expect(settings).toMatch(/finiteN\(sysBundle\.datetime\.unix\)/)
    expect(settings).toMatch(/finiteN\(sysBundle\.disk\.disksleep_minutes\)/)
    expect(settings).toMatch(/finiteN\(sysBundle\?\.power\?\.assertion_count\)/)
    expect(settings).toMatch(/withUnit\(upsInfo\.halt_levels\.haltlevel, '%'\)/)
    expect(settings).not.toMatch(/tm\.interval \|\| tm\.calendar/)
    expect(settings).toMatch(/withUnit\(asRecord\(tm\)\.interval, 's'\)/)
    expect(settings).not.toMatch(/identity\?\.hostname \|\| '—'/)
    expect(settings).toMatch(/finiteText\(identity\?\.hostname/)
    expect(settings).not.toMatch(/host\?\.hostname \|\| '—'/)
    expect(settings).toMatch(/finiteText\(host\?\.hostname/)
    expect(settings).not.toMatch(/form\?\.version \|\| sysBundle/)
    expect(settings).not.toMatch(/class="page-title"/)
    expect(settings).toMatch(/finiteText\(sysBundle\.management\.version/)
    expect(settings).toMatch(/asRecord\(asRecord\(sysBundle\)\.vms\)\.utm_available/)
    expect(settings).toMatch(/asRecord\(asRecord\(sysBundle\)\.shares\)\.smb_running/)
    expect(settings).toMatch(/asRecord\(asRecord\(sysBundle\)\.management\)\.auth_enabled/)
    expect(settings).toMatch(/finiteText\(asRecord\(asRecord\(asRecord\(sysBundle\)\.power\)\.ups\)\.source\)/)
    expect(settings).not.toMatch(/dockerInfo\.orb_version \|\| '—'/)
    expect(settings).toMatch(/finiteText\(dockerInfo\.orb_version/)
    expect(settings).toMatch(/finiteText\(dockerInfo\.info\?\.ServerVersion/)
    expect(settings).not.toMatch(/identity\?\.model \|\| '—'/)
    expect(settings).toMatch(/finiteText\(identity\?\.model/)
    expect(settings).not.toMatch(/host\?\.platform \|\| '—'/)
    expect(settings).toMatch(/finiteText\(host\?\.platform/)
    expect(settings).not.toMatch(/upsLast\.reason \|\| '—'/)
    expect(settings).toMatch(/finiteText\(asRecord\(upsLast\)\.reason/)
    expect(settings).not.toMatch(/\{\{\s*v\.name\s*\}\}/)
    expect(settings).toMatch(/finiteText\(asRecord\(v\)\.name\)/)
    expect(settings).not.toMatch(/toast\('❌ ' \+ e\.message\)/)
    expect(settings).toMatch(/toast\('❌ ' \+ finiteText\(e\.message\)\)/)
    expect(settings).not.toMatch(/upsLast\.failed\.join\(', '\)/)
    expect(settings).toMatch(/asArray\(asRecord\(upsLast\)\.failed\)\.map\(n => finiteText\(n, ''\)\)/)
    expect(settings).not.toMatch(/\{\{\s*identityError\s*\}\}/)
    expect(settings).toMatch(/finiteText\(identityError\)/)
    expect(settings).not.toMatch(/\{\{\s*diagMsg\s*\}\}/)
    expect(settings).toMatch(/finiteText\(diagMsg\)/)
    expect(settings).not.toMatch(/\{\{\s*l\.native\s*\}\}/)
    expect(settings).toMatch(/finiteText\(asRecord\(l\)\.native\)/)
    expect(settings).not.toMatch(/n: haltLevel\.value \}\)/)
    expect(settings).toMatch(/n: finiteN\(haltLevel\.value\)/)
    expect(settings).not.toMatch(/\{\{\s*twofaEnroll\.manual_entry\s*\}\}/)
    expect(settings).toMatch(/finiteText\(twofaEnroll\.manual_entry\)/)
    expect(settings).not.toMatch(/\{\{\s*createdKey\.key\s*\}\}/)
    expect(settings).toMatch(/finiteText\(createdKey\.key\)/)
    expect(settings).not.toMatch(/\{\{\s*code\s*\}\}/)
    expect(settings).toMatch(/finiteText\(code\)/)
    expect(settings).not.toMatch(/\{\{\s*dockerInfo\.info\?\.OperatingSystem/)
    expect(settings).toMatch(/finiteText\(dockerInfo\.info\?\.OperatingSystem\)/)
    expect(settings).not.toMatch(/sysBundle\.datetime\.ntp_server \|\| ''/)
    expect(settings).toMatch(/finiteText\(sysBundle\.datetime\.ntp_server/)
    expect(settings).not.toMatch(/\{\{\s*sysBundle\?\.datetime\?\.hint\s*\}\}/)
    expect(settings).toMatch(/finiteText\(sysBundle\?\.datetime\?\.hint\)/)
    expect(settings).not.toMatch(/style="margin-bottom:6px">\{\{ a \}\}<\/div>/)
    expect(settings).toMatch(/finiteText\(a\)/)
    expect(settings).not.toMatch(/\{\{\s*diagPreview\s*\}\}/)
    expect(settings).toMatch(/finiteText\(diagPreview\)/)
    expect(settings).not.toMatch(/`✅ \$\{key\}=\$\{value\}`/)
    expect(settings).toMatch(/`✅ \$\{finiteText\(key\)\}=\$\{finiteText\(value\)\}`/)
    expect(settings).not.toMatch(/r\.emitted\?\.length \|\| 0/)
    expect(settings).toMatch(/asArray\(r\.emitted\)\.length/)
  })

  it('Ollama leftover context lengths, pids and dates reject Infinity', () => {
    const ollama = readFileSync(resolve(SRC, 'views/Ollama.vue'), 'utf8')
    expect(ollama).not.toMatch(/\{\{\s*m\.context_length \|\| '—'\s*\}\}/)
    expect(ollama).not.toMatch(/\{\{\s*data\.service\.pid\s*\}\}/)
    expect(ollama).toMatch(/finiteN\(recGet\(m, 'context_length'\)/)
    expect(ollama).toMatch(/finiteN\(recGet\(recGet\(data, 'service'\), 'pid'\)/)
    expect(ollama).toMatch(/function fmtDate\([\s\S]*Number\.isFinite/)
    expect(ollama).toMatch(/finiteText\(recGet\(m, 'parameter_size'/)
    expect(ollama).not.toMatch(/m\.parameter_size \? ' ' \+ m\.parameter_size/)
    expect(ollama).not.toMatch(/data\.version \|\| '—'/)
    expect(ollama).toMatch(/finiteText\(recGet\(data, 'version'/)
    expect(ollama).not.toMatch(/\{\{\s*m\.name\s*\}\}/)
    expect(ollama).toMatch(/finiteText\(recGet\(m, 'name'\)/)
    expect(ollama).not.toMatch(/data\.service\?\.label \|\| '—'/)
    expect(ollama).toMatch(/finiteText\(recGet\(recGet\(data, 'service'\), 'label'/)
    expect(ollama).not.toMatch(/m\.family \|\| '—'/)
    expect(ollama).toMatch(/finiteText\(recGet\(m, 'family'/)
    expect(ollama).not.toMatch(/toast\('❌ ' \+ \(e\.message \|\| e\)\)/)
    expect(ollama).toMatch(/toast\('❌ ' \+ finiteText\(e\.message \|\| e\)\)/)
    expect(ollama).not.toMatch(/\(m\.capabilities \|\| \[\]\)\.join\(', '\)/)
    expect(ollama).toMatch(/asArray\(recGet\(m, 'capabilities'\)\)\.map\(c => finiteText\(c, ''\)\)/)
    expect(ollama).not.toMatch(/class="badge cap">\{\{ c \}\}<\/span>/)
    expect(ollama).toMatch(/finiteText\(c\)/)
    expect(ollama).toMatch(/v-for="c in asArray\(recGet\(m, 'capabilities'\)\)"/)
    expect(ollama).toMatch(/const models = computed\(\(\) => asArray\(recGet\(data.value, 'models'\)\)\.map\(\(row\) => asRecord\(row\)\)\)/)
    expect(ollama).toMatch(/const resident = computed\(\(\) => asArray\(recGet\(data.value, 'resident'\)\)\.map\(\(row\) => asRecord\(row\)\)\)/)
    expect(ollama).toMatch(/loadError\.value = finiteText\(e\.message \|\| String\(e\), ''\)/)
    expect(ollama).toMatch(/recGet\(m, 'pending'\)/)
  })

  it('PhotosHub leftover originals/export figures go through finiteN', () => {
    const photoshub = readFileSync(resolve(SRC, 'views/PhotosHub.vue'), 'utf8')
    expect(photoshub).toMatch(/from ['"][^'"]*lib\/finite/)
    expect(photoshub).toMatch(/withUnit\(data\.value\?\.originals\?\.local_original_pct, '%'\)/)
    expect(photoshub).toMatch(/finiteN\(data\.bridge\?\.exported_files\)/)
    expect(photoshub).not.toMatch(/return p == null \? '—' : `\$\{p\}%`/)
    expect(photoshub).toMatch(/finiteText\(data\.external_backup\?\.last_success/)
    expect(photoshub).not.toMatch(/data\.external_backup\?\.last_success \|\| t\('photoshub\.disk_absent'\)/)
    expect(photoshub).not.toMatch(/cfg\?\.paths\?\.photos_library \|\| '—'/)
    expect(photoshub).toMatch(/finiteText\(cfg\?\.paths\?\.photos_library\)/)
    expect(photoshub).not.toMatch(/data\.bridge\?\.mode \|\| '—'/)
    expect(photoshub).toMatch(/finiteText\(data\.bridge\?\.mode\)/)
    expect(photoshub).toMatch(/\.map\(n => finiteText\(n, ''\)\)/)
    expect(photoshub).not.toMatch(/pendingCount \?\? '—'/)
    expect(photoshub).toMatch(/finiteN\(pendingCount\)/)
    expect(photoshub).not.toMatch(/aria-live="polite">\{\{ lastAction\.stdout \|\| lastAction\.stderr \}\}/)
    expect(photoshub).toMatch(/finiteText\(lastAction\.stdout, ''\) \|\| finiteText\(lastAction\.stderr\)/)
    expect(photoshub).not.toMatch(/\(logData\?\.lines \|\| \[\]\)\.join\('\\n'\)/)
    expect(photoshub).toMatch(/finiteText\(l, ''\)/)
    expect(photoshub).toMatch(/finiteText\(logError\)/)
    expect(photoshub).not.toMatch(/: \(action \|\| ''\)/)
    expect(photoshub).toMatch(/finiteText\(action, ''\)/)
    expect(photoshub).not.toMatch(/toast\('❌ ' \+ \(e\?\.message \|\| e\)\)/)
    expect(photoshub).toMatch(/toast\('❌ ' \+ finiteText\(e\?\.message \|\| e\)\)/)
  })

  it('Shares leftover Time Machine quotas go through finiteN', () => {
    const shares = readFileSync(resolve(SRC, 'views/Shares.vue'), 'utf8')
    expect(shares).toMatch(/from ['"][^'"]*lib\/finite/)
    expect(shares).toMatch(/finiteN\(asRecord\(share\)\.tm_quota_gb/)
    expect(shares).not.toMatch(/t\('shares\.tm_quota_badge', \{ gb: share\.tm_quota_gb \}\)/)
    expect(shares).not.toMatch(/\{\{\s*entry\.index\s*\}\}/)
    expect(shares).toMatch(/finiteN\(asRecord\(entry\)\.index\)/)
    expect(shares).not.toMatch(/data\.host\?\.name \|\| t\('shares\.unknown'\)/)
    expect(shares).toMatch(/finiteText\(asRecord\(asRecord\(data\)\.host\)\.name/)
    expect(shares).not.toMatch(/data\.host\?\.address \|\| '—'/)
    expect(shares).toMatch(/finiteText\(asRecord\(asRecord\(data\)\.host\)\.address/)
    expect(shares).not.toMatch(/\{\{\s*service\.name\s*\}\}/)
    expect(shares).toMatch(/finiteText\(asRecord\(service\)\.name\)/)
    expect(shares).not.toMatch(/\{\{\s*user\.username\s*\}\}/)
    expect(shares).toMatch(/finiteText\(asRecord\(user\)\.username\)/)
    expect(shares).not.toMatch(/\{\{\s*entry\.perms\.join/)
    expect(shares).toMatch(/asArray\(asRecord\(entry\)\.perms\)\.map\(p => finiteText\(p/)
    expect(shares).toMatch(/finiteText\(asRecord\(entry\)\.kind\)/)
    expect(shares).toMatch(/finiteText\(asRecord\(entry\)\.effect\)/)
    expect(shares).toMatch(/n: finiteN\(asArray\(asRecord\(acl\)\.entries\)\.length\)/)
    expect(shares).not.toMatch(/:href="data\.host\.smb_url"/)
    expect(shares).toMatch(/:href="finiteText\(asRecord\(asRecord\(data\)\.host\)\.smb_url, ''\)"/)
    expect(shares).not.toMatch(/:href="share\.url"/)
    expect(shares).toMatch(/:href="finiteText\(asRecord\(share\)\.url, ''\)"/)
    expect(shares).not.toMatch(/class="acl-error">\{\{ aclError \}\}<\/div>/)
    expect(shares).toMatch(/finiteText\(aclError\)/)
    expect(shares).not.toMatch(/aclError\.value = error\.message/)
    expect(shares).toMatch(/aclError\.value = finiteText\(error\.message, ''\)/)
    expect(shares).toMatch(/v-for="share in asArray\(asRecord\(data\)\.smb\)"/)
    expect(shares).toMatch(/v-for="service in asArray\(asRecord\(data\)\.file_services\)"/)
  })

  it('MainArray leftover capacities go through fmtGb/withUnit', () => {
    const array = readFileSync(resolve(SRC, 'views/MainArray.vue'), 'utf8')
    expect(array).toMatch(/from ['"][^'"]*lib\/finite/)
    expect(array).not.toMatch(/\{\{\s*d\.used_gb\s*\}\}/)
    expect(array).not.toMatch(/\{\{\s*d\.pct\s*\}\}%/)
    expect(array).not.toMatch(/new Date\(h\.ts \* 1000\)\.toLocaleString\(\)/)
    expect(array).toMatch(/fmtGb\(recGet\(d, 'used_gb'\)\)/)
    expect(array).toMatch(/withUnit\(recGet\(d, 'pct'\), '%'\)/)
    expect(array).toMatch(/fmtTs\(recGet\(h, 'ts'\)\)/)
    expect(array).toMatch(/recGet\(asArray\(recGet\(recGet\(m, 'smart'\), 'attrs'\)\)\[0\], 'raw'\)/)
    expect(array).not.toMatch(/data\?\.array\?\.system_count \?\? 0/)
    expect(array).toMatch(/finiteN\(data\?\.array\?\.system_count/)
    expect(array).toMatch(/finiteN\(data\?\.array\?\.disk_count/)
    expect(array).toMatch(/finiteText\(recGet\(recGet\(m, 'smart'\), 'temp'\)\)/)
    expect(array).toMatch(/finiteText\(recGet\(d, 'size'\)\)/)
    expect(array).toMatch(/finiteText\(recGet\(m, 'size'\)\)/)
    expect(array).not.toMatch(/\{\{\s*d\.size \|\| '—'\s*\}\}/)
    expect(array).not.toMatch(/\{\{\s*a\.id\s*\}\}/)
    expect(array).not.toMatch(/\{\{\s*a\.value\s*\}\}/)
    expect(array).not.toMatch(/\{\{\s*a\.worst\s*\}\}/)
    expect(array).not.toMatch(/\{\{\s*a\.thresh\s*\}\}/)
    expect(array).not.toMatch(/a\.raw !== undefined \? a\.raw : a\.value/)
    expect(array).toMatch(/finiteN\(recGet\(a, 'id'\)\)/)
    expect(array).toMatch(/finiteText\(recGet\(a, 'value'\)\)/)
    expect(array).toMatch(/finiteText\(recGet\(a, 'worst'\)\)/)
    expect(array).toMatch(/finiteText\(recGet\(a, 'thresh'\)\)/)
    expect(array).toMatch(/finiteText\(recGet\(a, 'raw'\)\)/)
    expect(array).not.toMatch(/\{\{\s*renameTarget\.id\s*\}\}/)
    expect(array).toMatch(/finiteText\(renameTarget\.id\)/)
    expect(array).not.toMatch(/\{\{\s*formatTarget\.id\s*\}\}/)
    expect(array).toMatch(/finiteText\(formatTarget\.id\)/)
    expect(array).not.toMatch(/\{\{\s*v\.id\s*\}\}/)
    expect(array).toMatch(/finiteText\(recGet\(v, 'id'\)\)/)
    expect(array).not.toMatch(/\{\{\s*m\.id\s*\}\}/)
    expect(array).toMatch(/finiteText\(recGet\(m, 'id'\)\)/)
    expect(array).not.toMatch(/v\.disk_id \|\| '—'/)
    expect(array).not.toMatch(/v\.disk_id \? ' · ' \+ v\.disk_id/)
    expect(array).toMatch(/finiteText\(recGet\(v, 'disk_id'\)/)
    expect(array).toMatch(/finiteText\(recGet\(d, 'disk_id'\)/)
    expect(array).not.toMatch(/d\.protocol \|\| '—'/)
    expect(array).toMatch(/finiteText\(recGet\(d, 'protocol'\)\)/)
    expect(array).not.toMatch(/\{\{\s*data\.array\.status\s*\}\}/)
    expect(array).toMatch(/finiteText\(data\.array\.status\)/)
    expect(array).not.toMatch(/\{\{\s*d\.label\s*\}\}/)
    expect(array).toMatch(/finiteText\(recGet\(d, 'label'\)\)/)
    expect(array).not.toMatch(/m\.smart\?\.model \|\| m\.smart\?\.serial \|\| '—'/)
    expect(array).toMatch(/finiteText\(recGet\(recGet\(m, 'smart'\), 'model'\), ''\) \|\| finiteText\(recGet\(recGet\(m, 'smart'\), 'serial'\)\)/)
    expect(array).not.toMatch(/v\.fs \|\| '—'/)
    expect(array).toMatch(/finiteText\(recGet\(v, 'fs'\)\)/)
    expect(array).not.toMatch(/toast\('❌ ' \+ e\.message\)/)
    expect(array).toMatch(/toast\('❌ ' \+ finiteText\(e\.message\)\)/)
    expect(array).not.toMatch(/\{\{\s*lastMsg\s*\}\}/)
    expect(array).toMatch(/finiteText\(lastMsg\)/)
    expect(array).not.toMatch(/m\.caps\.supported\.join\(', '\)/)
    expect(array).toMatch(/asArray\(recGet\(recGet\(m, 'caps'\), 'supported'\)\)\.map\(n => finiteText\(n, ''\)\)/)
    expect(array).toMatch(/loadError\.value = finiteText\(e\.message \|\| String\(e\), ''\)/)
    expect(array).not.toMatch(/id: d\.id \}\)/)
    expect(array).toMatch(/id: finiteText\(row\.id\)/)
    expect(array).not.toMatch(/\$\{t\('main_extra\.mount'\)\} \$\{v\.id\}/)
    expect(array).toMatch(/\$\{t\('main_extra\.mount'\)\} \$\{finiteText\(row\.id\)\}/)
    expect(array).not.toMatch(/v\.mount \|\| t\('main_extra\.not_mounted'\)/)
    expect(array).toMatch(/finiteText\(row\.mount, ''\) \|\| t\('main_extra\.not_mounted'\)/)
    expect(array).not.toMatch(/data\?\.managed\?\.hint \|\| ''/)
    expect(array).toMatch(/finiteText\(data\?\.managed\?\.hint, ''\)/)
    expect(array).not.toMatch(/\{\{\s*m\.caps\.reason\s*\}\}/)
    expect(array).toMatch(/finiteText\(recGet\(recGet\(m, 'caps'\), 'reason'\)\)/)
    expect(array).not.toMatch(/\{\{\s*m\.lastResult\s*\}\}/)
    expect(array).toMatch(/finiteText\(recGet\(m, 'lastResult'\)\)/)
    expect(array).not.toMatch(/v: health \}\)/)
    expect(array).toMatch(/v: finiteText\(health\)/)
    expect(array).not.toMatch(/:key="f" :value="f">\{\{ f \}\}<\/option>/)
    expect(array).toMatch(/finiteText\(f\)/)
    expect(array).not.toMatch(/reasons: d\.error/)
    expect(array).toMatch(/reasons: finiteText\(d\.error\)/)
    expect(array).toMatch(/const devices = asArray\(recGet\(recGet\(data\.value, 'array'\), 'devices'\)\)/)
    expect(array).toMatch(/asTrimmed\(x\) !== 'offline'/)
    expect(array).toMatch(/:key="finiteText\(k\)"/)
  })

  it('Pool leftover capacities go through fmtGb/withUnit', () => {
    const pool = readFileSync(resolve(SRC, 'views/Pool.vue'), 'utf8')
    expect(pool).toMatch(/from ['"][^'"]*lib\/finite/)
    expect(pool).not.toMatch(/\{\{\s*m\.pct\s*\}\}%/)
    expect(pool).not.toMatch(/\{\{\s*m\.used_gb\s*\}\}/)
    expect(pool).toMatch(/fmtGb\(recGet\(m, 'used_gb'\)\)/)
    expect(pool).toMatch(/withUnit\(recGet\(m, 'pct'\), '%'\)/)
    expect(pool).not.toMatch(/\{\{\s*r\.at_risk_gb\s*\}\} GB/)
    expect(pool).toMatch(/fmtGb\(recGet\(r, 'at_risk_gb'\)\)/)
    expect(pool).toMatch(/fmtGb\(recGet\(r, 'survives_gb'\)\)/)
    expect(pool).not.toMatch(/m\.disk_id \|\| '—'/)
    expect(pool).not.toMatch(/c\.disk_id \|\| '—'/)
    expect(pool).not.toMatch(/r\.disk_id \|\| '—'/)
    expect(pool).toMatch(/finiteText\(recGet\(m, 'disk_id'\)/)
    expect(pool).toMatch(/finiteText\(recGet\(c, 'disk_id'\)/)
    expect(pool).toMatch(/finiteText\(recGet\(r, 'disk_id'\)/)
    expect(pool).not.toMatch(/m\.filesystem \|\| '—'/)
    expect(pool).not.toMatch(/c\.filesystem \|\| '—'/)
    expect(pool).not.toMatch(/shownTarget \|\| '—'/)
    expect(pool).toMatch(/finiteText\(recGet\(m, 'filesystem'\)\)/)
    expect(pool).toMatch(/finiteText\(recGet\(c, 'filesystem'\)\)/)
    expect(pool).toMatch(/finiteText\(shownTarget\)/)
    expect(pool).not.toMatch(/toast\('❌ ' \+ e\.message\)/)
    expect(pool).toMatch(/toast\('❌ ' \+ finiteText\(e\.message\)\)/)
    expect(pool).not.toMatch(/\{\{\s*lastMsg\s*\}\}/)
    expect(pool).toMatch(/finiteText\(lastMsg\)/)
    expect(pool).toMatch(/lastMsg\.value = finiteText\(e\.message, ''\)/)
    expect(pool).toMatch(/loadError\.value = finiteText\(e\.message \|\| String\(e\), ''\)/)
    expect(pool).not.toMatch(/:key="m" style="margin-right:10px">\{\{ m \}\}<\/span>/)
    expect(pool).toMatch(/finiteText\(m\)/)
    expect(pool).toMatch(/fmtGb\(recGet\(shownSummary, 'avail_gb'\)\)/)
    expect(pool).toMatch(/finiteN\(recGet\(shownSummary, 'total_gb'\)\)/)
    expect(pool).toMatch(/finiteN\(recGet\(shownSummary, 'used_gb'\)\)/)
    expect(pool).toMatch(/recGet\(c, 'mount'\)/)
    expect(pool).toMatch(/recGet\(m, 'mount'\)/)
  })

  it('WireGuard leftover ports/mtu/latency go through finite helpers', () => {
    const wg = readFileSync(resolve(SRC, 'views/WireGuard.vue'), 'utf8')
    expect(wg).toMatch(/from ['"][^'"]*lib\/finite/)
    expect(wg).toMatch(/function relativeAge\([\s\S]*Number\.isFinite/)
    expect(wg).toMatch(/const s = finiteN\(seconds, null\)/)
    expect(wg).not.toMatch(/r\.latency_ms != null \? r\.latency_ms \+ ' ms'/)
    expect(wg).not.toMatch(/MTU \{\{ data\.mtu \}\}/)
    expect(wg).toMatch(/withUnit\(recGet\(r, 'latency_ms'\), ' ms'\)/)
    expect(wg).toMatch(/finiteN\(data\.mtu\)/)
    expect(wg).toMatch(/finiteN\(data\.listen_port\)/)
    expect(wg).toMatch(/finiteN\(data\.active_count\)/)
    expect(wg).toMatch(/finiteN\(data\.peer_count\)/)
    expect(wg).toMatch(/finiteN\(data\.keepalive_missing\)/)
    expect(wg).not.toMatch(/\{\{\s*data\.active_count \}\}/)
    expect(wg).toMatch(/finiteText\(recGet\(p, 'keepalive'\), 'off'\)/)
    expect(wg).not.toMatch(/\{\{\s*p\.keepalive \|\| 'off'\s*\}\}/)
    expect(wg).toMatch(/finiteN\(readiness\.peer_origin\.foreign/)
    expect(wg).toMatch(/finiteN\(recGet\(pingResult, 'reachable'/)
    expect(wg).toMatch(/finiteN\(result\.created/)
    expect(wg).toMatch(/finiteText\(recGet\(p, 'tx_human'\)/)
    expect(wg).not.toMatch(/n: readiness\.peer_origin\.foreign/)
    expect(wg).not.toMatch(/↑\{\{ p\.tx_human \}\}/)
    expect(wg).not.toMatch(/\{\{\s*c\.detail\s*\}\}/)
    expect(wg).toMatch(/finiteText\(recGet\(c, 'detail'\)/)
    expect(wg).not.toMatch(/p\.name \|\| t\('wg\.unnamed'\)/)
    expect(wg).toMatch(/finiteText\(recGet\(p, 'name'/)
    expect(wg).not.toMatch(/data\.public_key \|\| '—'/)
    expect(wg).toMatch(/finiteText\(data\.public_key/)
    expect(wg).not.toMatch(/p\.endpoint \|\| '—'/)
    expect(wg).toMatch(/finiteText\(recGet\(p, 'endpoint'/)
    expect(wg).not.toMatch(/data\.address \|\| data\.subnet/)
    expect(wg).toMatch(/finiteText\(data\.address, ''\) \|\| finiteText\(data\.subnet\)/)
    expect(wg).not.toMatch(/data\.wstunnel\.port \|\| data\.wstunnel\.listen/)
    expect(wg).toMatch(/finiteText\(recGet\(recGet\(data, 'wstunnel'\), 'port'\), ''\) \|\| finiteText\(recGet\(recGet\(data, 'wstunnel'\), 'listen'\)/)
    expect(wg).toMatch(/finiteText\(recGet\(recGet\(data, 'wstunnel'\), 'listen'\)/)
    expect(wg).toMatch(/finiteText\(recGet\(recGet\(data, 'wstunnel'\), 'client_command'\)/)
    expect(wg).toMatch(/recGet\(recGet\(data, 'wstunnel'\), 'running'\) \? t\('common.running'\)/)
    expect(wg).not.toMatch(/toast\('❌ ' \+ e\.message\)/)
    expect(wg).toMatch(/toast\('❌ ' \+ finiteText\(e\.message\)\)/)
    expect(wg).not.toMatch(/readiness\?\.wan_interface \|\| 'en0'/)
    expect(wg).toMatch(/finiteText\(readiness\?\.wan_interface, ''\) \|\| 'en0'/)
    expect(wg).toMatch(/v-for="r in asArray\(recGet\(pingResult, 'results'\)\)"/)
    expect(wg).toMatch(/recGet\(c, 'ok'\)/)
    expect(wg).toMatch(/recGet\(c, 'id'\)/)
  })

  it('VMs leftover ids go through finiteText', () => {
    const vms = readFileSync(resolve(SRC, 'views/VMs.vue'), 'utf8')
    expect(vms).toMatch(/from ['"][^'"]*lib\/finite/)
    expect(vms).not.toMatch(/\{\{\s*renameTarget\.id\s*\}\}/)
    expect(vms).toMatch(/finiteText\(recGet\(renameTarget, 'id'\)/)
    expect(vms).not.toMatch(/\{\{\s*v\.name\s*\}\}/)
    expect(vms).toMatch(/finiteText\(recGet\(v, 'name'\)/)
    expect(vms).not.toMatch(/\{\{\s*cloneTarget\.name\s*\}\}/)
    expect(vms).toMatch(/finiteText\(recGet\(cloneTarget, 'name'\)/)
    expect(vms).not.toMatch(/v\.ips\.join\(', '\)/)
    expect(vms).toMatch(/finiteText\(ip, ''\)/)
    expect(vms).not.toMatch(/\{\{\s*labels\[a\] \|\| a\s*\}\}/)
    expect(vms).toMatch(/finiteText\(asRecord\(labels\)\[a\], ''\) \|\| finiteText\(a\)/)
    expect(vms).not.toMatch(/\{\{\s*d\s*\}\}/)
    expect(vms).toMatch(/finiteText\(d\)/)
    expect(vms).not.toMatch(/toast\('❌ ' \+ e\.message\)/)
    expect(vms).toMatch(/toast\('❌ ' \+ finiteText\(e\.message\)\)/)
    expect(vms).toMatch(/finiteText\(recGet\(data.value, 'host_ip'/)
    expect(vms).toMatch(/finiteText\(recGet\(row, 'name'/)
    expect(vms).toMatch(/finiteText\(recGet\(out, 'message'/)
    expect(vms).toMatch(/finiteText\(window\.location\.hostname, ''\) \|\| finiteText\(recGet\(data.value, 'host_ip'\), ''\)/)
    expect(vms).not.toMatch(/data\?\.orb_distros \|\| distros/)
    expect(vms).toMatch(/asArray\(recGet\(data, 'orb_distros'\)\)/)
    expect(vms).toMatch(/v-for="v in asArray\(vms\)"/)
    expect(vms).toMatch(/loadError\.value = finiteText\(e\.message \|\| String\(e\), ''\)/)
    expect(vms).toMatch(/msg\.value = finiteText\(e\.message\)/)
    expect(vms).toMatch(/recGet\(row, 'actions'\)/)
    expect(vms).toMatch(/recGet\(row, 'backend'\)/)
  })

  it('Tools leftover disk/pid interpolations go through finite helpers', () => {
    const tools = readFileSync(resolve(SRC, 'views/Tools.vue'), 'utf8')
    expect(tools).toMatch(/from ['"][^'"]*lib\/finite/)
    expect(tools).not.toMatch(/diag\.root_disk_pct \?\? '—'/)
    expect(tools).not.toMatch(/\{\{\s*p\.pid\s*\}\}/)
    expect(tools).toMatch(/withUnit\(diag\.root_disk_pct, '%'\)/)
    expect(tools).toMatch(/finiteN\(p\.pid\)/)
    expect(tools).toMatch(/fmtGb\(diag\.root_disk_free_gb\)/)
    expect(tools).not.toMatch(/row\.interval_sec \? row\.interval_sec \+ 's'/)
    expect(tools).toMatch(/withUnit\(row\.interval_sec, 's'\)/)
    expect(tools).toMatch(/\.map\(n => finiteN\(n\)\)\.join\(' \/ '\)/)
    expect(tools).toMatch(/finiteText\(diag\.ts\)/)
    expect(tools).toMatch(/finiteText\(l\.reclaimable\)/)
    expect(tools).not.toMatch(/\{\{\s*diag\.cpu \|\| '—'\s*\}\}/)
    expect(tools).not.toMatch(/\{\{\s*diag\.uptime_human \|\| '—'\s*\}\}/)
    expect(tools).toMatch(/finiteText\(diag\.cpu\)/)
    expect(tools).toMatch(/finiteText\(diag\.uptime_human\)/)
    expect(tools).not.toMatch(/\{\{\s*diag\.hostname\s*\}\}/)
    expect(tools).toMatch(/finiteText\(diag\.hostname\)/)
    expect(tools).not.toMatch(/diag\.version \|\| '—'/)
    expect(tools).toMatch(/finiteText\(diag\.version/)
    expect(tools).toMatch(/finiteText\(about\.version/)
    expect(tools).not.toMatch(/\{\{\s*c\.name\s*\}\}/)
    expect(tools).toMatch(/finiteText\(c\.name\)/)
    expect(tools).not.toMatch(/\{\{\s*p\.name\s*\}\}/)
    expect(tools).toMatch(/finiteText\(p\.name\)/)
    expect(tools).not.toMatch(/\{\{\s*a\.label\s*\}\}/)
    expect(tools).toMatch(/finiteText\(a\.label\)/)
    expect(tools).not.toMatch(/d\.power_state \|\| '—'/)
    expect(tools).toMatch(/finiteText\(d\.power_state/)
    expect(tools).not.toMatch(/sec\.text \|\| '—'/)
    expect(tools).toMatch(/finiteText\(sec\.text\)/)
    expect(tools).not.toMatch(/toast\('❌ ' \+ e\.message\)/)
    expect(tools).toMatch(/toast\('❌ ' \+ finiteText\(e\.message\)\)/)
    expect(tools).not.toMatch(/\{\{\s*diagMsg\s*\}\}/)
    expect(tools).toMatch(/finiteText\(diagMsg\)/)
    expect(tools).not.toMatch(/finiteText\(\(updates\.macos\?\.lines\|\|\[\]\)\.join\('\\n'\)/)
    expect(tools).toMatch(/asArray\(updates\.macos\?\.lines\)\.map\(n => finiteText\(n, ''\)\)/)
    expect(tools).not.toMatch(/\{\{\s*dnsOut\s*\}\}/)
    expect(tools).toMatch(/finiteText\(dnsOut\)/)
    expect(tools).not.toMatch(/what: labels\[what\] \|\| what/)
    expect(tools).toMatch(/what: finiteText\(labels\[what\], ''\) \|\| finiteText\(what\)/)
    expect(tools).toMatch(/function formatCal\([\s\S]*jsonText/)
    expect(tools).not.toMatch(/JSON\.stringify\(c\)/)
    expect(tools).toMatch(/processes\.value = asArray\(j\.processes\)/)
    expect(tools).toMatch(/v-for="p in asArray\(filteredProc\)"/)
  })

  it('Files leftover listing counts and mtimes reject Infinity', () => {
    const files = readFileSync(resolve(SRC, 'views/Files.vue'), 'utf8')
    expect(files).toMatch(/from ['"][^'"]*lib\/finite/)
    expect(files).not.toMatch(/\{\{\s*listing\.count\s*\}\}/)
    expect(files).toMatch(/finiteN\(recGet\(listing, 'count'\)\)/)
    expect(files).toMatch(/function fmtTime\([\s\S]*fmtTs/)
    expect(files).not.toMatch(/listing\.root_id \|\| 'root'/)
    expect(files).toMatch(/finiteText\(recGet\(listing, 'root_id'/)
    expect(files).not.toMatch(/\{\{\s*it\.name\s*\}\}/)
    expect(files).toMatch(/finiteText\(recGet\(it, 'name'\)\)/)
    expect(files).not.toMatch(/class="err-bar">\{\{ error \}\}<\/div>/)
    expect(files).toMatch(/finiteText\(error\)/)
    expect(files).not.toMatch(/it\.mode \? ' · ' \+ it\.mode/)
    expect(files).toMatch(/finiteText\(recGet\(it, 'mode'\), ''\) \? ' · ' \+ finiteText\(recGet\(it, 'mode'\)\)/)
    expect(files).toMatch(/v-for="it in asArray\(recGet\(listing, 'items'\)\)"/)
    expect(files).toMatch(/v-for="r in asArray\(roots\)"/)
    expect(files).toMatch(/items: asArray\(recGet\(j, 'items'\)\)\.map\(\(row\) => asRecord\(row\)\)/)
    expect(files).toMatch(/crumbs: asArray\(recGet\(j, 'crumbs'\)\)\.map\(\(row\) => asRecord\(row\)\)/)
    expect(files).toMatch(/recGet\(i, 'path'\)/)
    expect(files).toMatch(/recGet\(row, 'is_dir'\)/)
    expect(files).toMatch(/recGet\(first, 'id'\)/)
  })

  it('Modules leftover names go through finiteText', () => {
    const modules = readFileSync(resolve(SRC, 'views/Modules.vue'), 'utf8')
    expect(modules).toMatch(/from ['"][^'"]*lib\/finite/)
    expect(modules).not.toMatch(/\{\{\s*m\.name\s*\}\}/)
    expect(modules).toMatch(/finiteText\(recGet\(m, 'name'\)\)/)
    expect(modules).toMatch(/finiteText\(recGet\(m, 'description'\)\)/)
    expect(modules).not.toMatch(/class="btn tiny">\{\{ r \}\}<\/router-link>/)
    expect(modules).toMatch(/finiteText\(r\)/)
    expect(modules).toMatch(/label === key \? finiteText\(cat\)/)
    expect(modules).toMatch(/v-for="\(list, cat\) in asRecord\(byCat\)"/)
    expect(modules).toMatch(/:key="finiteText\(cat\)"/)
    expect(modules).toMatch(/v-for="m in asArray\(list\)"/)
    expect(modules).toMatch(/asArray\(recGet\(m, 'ui_routes'\)\)/)
    expect(modules).toMatch(/asArray\(list\)\.length/)
    expect(modules).toMatch(/asCategoryMap\(j\.by_category\)/)
    expect(modules).toMatch(/asRecord\(await getModules\(\)\)/)
    expect(modules).toMatch(/loadError\.value = finiteText\(e\.message \|\| String\(e\), ''\)/)
  })

  it('Health leftover summary counts go through finiteN', () => {
    const health = readFileSync(resolve(SRC, 'views/Health.vue'), 'utf8')
    expect(health).toMatch(/from ['"][^'"]*lib\/finite/)
    expect(health).not.toMatch(/\{\{\s*data\.summary\.ok\s*\}\}/)
    expect(health).not.toMatch(/data\?\.ts \|\| '…'/)
    expect(health).toMatch(/finiteN\(recGet\(recGet\(data, 'summary'\), 'ok'\)\)/)
    expect(health).toMatch(/finiteN\(recGet\(recGet\(data, 'summary'\), 'warn'\)\)/)
    expect(health).toMatch(/finiteN\(recGet\(recGet\(data, 'summary'\), 'error'\)\)/)
    expect(health).toMatch(/finiteN\(recGet\(recGet\(data, 'summary'\), 'total'\)\)/)
    expect(health).toMatch(/finiteText\(data\?\.ts/)
    expect(health).toMatch(/finiteText\(errText\(recGet\(c, 'detail'\)\)\)/)
    expect(health).not.toMatch(/\{\{\s*errText\(c\.detail\)\s*\}\}/)
    expect(health).not.toMatch(/\{\{\s*c\.name\s*\}\}/)
    expect(health).toMatch(/finiteText\(recGet\(c, 'name'\)\)/)
    expect(health).not.toMatch(/toast\('❌ ' \+ e\.message\)/)
    expect(health).toMatch(/toast\('❌ ' \+ finiteText\(e\.message\)\)/)
    expect(health).toMatch(/v-for="c in asArray\(filtered\)"/)
    expect(health).toMatch(/recGet\(data, 'healthy'\) \? t\('common\.healthy'\)/)
    expect(health).toMatch(/asArray\(recGet\(data, 'checks'\)\)/)
    expect(health).toMatch(/finiteN\(asArray\(filtered\)\.length\)/)
    expect(health).toMatch(/finiteN\(asArray\(recGet\(data, 'checks'\)\)\.length\)/)
    expect(health).toMatch(/recGet\(c, 'ok'\)/)
    expect(health).toMatch(/recGet\(c, 'level'\)/)
  })

  it('Users leftover counts and uids go through finiteN', () => {
    const users = readFileSync(resolve(SRC, 'views/Users.vue'), 'utf8')
    expect(users).toMatch(/from ['"][^'"]*lib\/finite/)
    expect(users).not.toMatch(/\{\{\s*data\.count\s*\}\}/)
    expect(users).not.toMatch(/\{\{\s*u\.uid\s*\}\}/)
    expect(users).not.toMatch(/\(data\.count \|\| 0\) - \(data\.admins \|\| 0\)/)
    expect(users).toMatch(/finiteN\(recGet\(data, 'count'\)\)/)
    expect(users).toMatch(/finiteN\(recGet\(data, 'admins'\)\)/)
    expect(users).toMatch(/finiteN\(recGet\(u, 'uid'\)\)/)
    expect(users).toMatch(/function finiteDiff\([\s\S]*finiteN/)
    expect(users).toMatch(/finiteDiff\(recGet\(data, 'count'\), recGet\(data, 'admins'\)\)/)
    expect(users).not.toMatch(/\{\{\s*u\.name\s*\}\}/)
    expect(users).toMatch(/finiteText\(recGet\(u, 'name'\)\)/)
    expect(users).toMatch(/finiteText\(recGet\(opt, 'id'\)\)/)
    expect(users).toMatch(/finiteText\(recGet\(opt, 'name'\)\)/)
    expect(users).not.toMatch(/\{\{\s*opt\.name\s*\}\}/)
    expect(users).not.toMatch(/u\.gecos \|\| '—'/)
    expect(users).not.toMatch(/acct\.resources\.join\(', '\)/)
    expect(users).toMatch(/function resourceList\([\s\S]*finiteText/)
    expect(users).toMatch(/finiteText\(serviceOptionsError\)/)
    // The error now renders inside its own v-if="accountsError" alert span,
    // so the '' fallback that used to pick the loading/none branch is gone.
    expect(users).toMatch(/finiteText\(accountsError\)/)
    expect(users).not.toMatch(/toast\('❌ ' \+ e\.message\)/)
    expect(users).toMatch(/toast\('❌ ' \+ finiteText\(e\.message\)\)/)
    expect(users).toMatch(/v-for="opt in asArray\(serviceOptions\)"/)
    expect(users).toMatch(/asArray\(recGet\(asRecord\(await listPanelAccounts\(\)\), 'accounts'\)\)\.map\(\(row\) => asRecord\(row\)\)/)
    expect(users).toMatch(/v-for="acct in asArray\(accounts\)"/)
    expect(users).toMatch(/asArray\(recGet\(acct, 'resources'\)\)/)
    expect(users).toMatch(/function accountName\([\s\S]*recGet\(acct, 'username'\)/)
    expect(users).toMatch(/const status = asRecord\(await getServices\(\)\)/)
    expect(users).toMatch(/const next = asRecord\(await getUsers\(\)\)/)
    expect(users).toMatch(/asArray\(createForm\.value\.resources\)/)
    expect(users).toMatch(/function secretLen\([\s\S]*typeof value === 'string'/)
    expect(users).toMatch(/loadError\.value = finiteText\(e\.message \|\| String\(e\), ''\)/)
    expect(users).toMatch(/accountsError\.value = finiteText\(e\.message \|\| String\(e\), ''\)/)
    expect(users).toMatch(/serviceOptionsError\.value = finiteText\(e\.message \|\| String\(e\), ''\)/)
  })

  it('Gateway leftover pids go through finiteN', () => {
    const gateway = readFileSync(resolve(SRC, 'views/Gateway.vue'), 'utf8')
    expect(gateway).toMatch(/from ['"][^'"]*lib\/finite/)
    expect(gateway).not.toMatch(/pid \{\{ data\.pid \}\}/)
    expect(gateway).toMatch(/finiteN\(recGet\(data, 'pid'\)/)
    expect(gateway).not.toMatch(/\{\{\s*data\.label\s*\}\}/)
    expect(gateway).toMatch(/finiteText\(recGet\(data, 'label'\)\)/)
    expect(gateway).not.toMatch(/\(s\.server_names \|\| \[\]\)\.join\(', '\) \|\| '—'/)
    expect(gateway).not.toMatch(/\{\{\s*data\.conf\s*\}\}/)
    expect(gateway).toMatch(/finiteText\(recGet\(data, 'conf'\)\)/)
    expect(gateway).not.toMatch(/\{\{\s*\(s\.listens \|\| \[\]\)\.join/)
    expect(gateway).toMatch(/asArray\(recGet\(s, 'listens'\)\)\.map\(n => finiteText\(n/)
    expect(gateway).toMatch(/asArray\(recGet\(s, 'server_names'\)\)\.map\(n => finiteText\(n/)
    expect(gateway).not.toMatch(/\{\{\s*msg\s*\}\}/)
    expect(gateway).toMatch(/finiteText\(msg\)/)
    expect(gateway).not.toMatch(/msg\.value = j\.message \|\| ''/)
    expect(gateway).toMatch(/msg\.value = finiteText\(recGet\(j, 'message'\), ''\)/)
    expect(gateway).toMatch(/loadError\.value = finiteText\(e\.message \|\| String\(e\), ''\)/)
    expect(gateway).toMatch(/recGet\(data, 'running'\)/)
    expect(gateway).toMatch(/asArray\(recGet\(next, 'sites'\)\)/)
  })

  it('Maintenance leftover rc and finished reject Infinity', () => {
    const maintenance = readFileSync(resolve(SRC, 'views/Maintenance.vue'), 'utf8')
    expect(maintenance).toMatch(/from ['"][^'"]*lib\/finite/)
    expect(maintenance).not.toMatch(/❌ \{\{ task\.rc \}\}/)
    expect(maintenance).toMatch(/finiteN\(recGet\(task, 'rc'\)\)/)
    expect(maintenance).toMatch(/finiteText\(recGet\(task, 'finished'\)\)/)
    expect(maintenance).toMatch(/finiteN\(recGet\(j, 'rc'\)\)/)
    expect(maintenance).not.toMatch(/\{\{\s*task\.id\s*\}\}/)
    expect(maintenance).toMatch(/finiteText\(recGet\(task, 'id'\)\)/)
    expect(maintenance).not.toMatch(/\{\{\s*task\.name\s*\}\}/)
    expect(maintenance).toMatch(/finiteText\(recGet\(task, 'name'\)\)/)
    expect(maintenance).not.toMatch(/\{\{\s*loadError\s*\}\}/)
    // loadError is no longer interpolated inline: it feeds the LoadFailure
    // banner, whose detail line applies finiteText internally.
    expect(maintenance).toMatch(/:detail="loadError"/)
    expect(maintenance).not.toMatch(/loadError \|\| \(loaded/)
    expect(maintenance).not.toMatch(/\{\{\s*logTitle\s*\}\}/)
    expect(maintenance).toMatch(/finiteText\(logTitle\)/)
    expect(maintenance).not.toMatch(/\{\{\s*logText\s*\}\}/)
    expect(maintenance).toMatch(/finiteText\(logText\)/)
    expect(maintenance).toMatch(/logText\.value = finiteText\(recGet\(j, 'log'\), ''\)/)
    expect(maintenance).toMatch(/logTitle\.value = finiteText\(rec\.name\)/)
    expect(maintenance).toMatch(/v-for="task in asArray\(filtered\)"/)
    expect(maintenance).toMatch(/v-else-if="!asArray\(tasks\)\.length"/)
    expect(maintenance).toMatch(/asRecord\(await getMaintenanceLog/)
    expect(maintenance).toMatch(/asArray\(recGet\(list, 'tasks'\)\)/)
    expect(maintenance).toMatch(/asRecord\(row\)/)
    expect(maintenance).toMatch(/finiteN\(asArray\(filtered\)\.length\)/)
    expect(maintenance).toMatch(/finiteN\(asArray\(tasks\)\.length\)/)
    expect(maintenance).toMatch(/asTrimmed\(q\.value\)\.toLowerCase\(\)/)
    expect(maintenance).not.toMatch(/typeof q\.value === 'string' \? q\.value\.trim\(\)\.toLowerCase\(\)/)
    expect(maintenance).toMatch(/recGet\(row, 'running'\)/)
    expect(maintenance).toMatch(/recGet\(row, 'name'\)/)
  })

  it('Account leftover recovery counts go through finiteN', () => {
    const account = readFileSync(resolve(SRC, 'views/Account.vue'), 'utf8')
    const settings = readFileSync(resolve(SRC, 'views/Settings.vue'), 'utf8')
    expect(account).toMatch(/from ['"][^'"]*lib\/finite/)
    expect(account).toMatch(/finiteN\(twofa\.recovery_remaining/)
    expect(account).not.toMatch(/n: twofa\.recovery_remaining/)
    expect(settings).toMatch(/finiteN\(twofa\.recovery_remaining/)
    expect(settings).not.toMatch(/n: twofa\.recovery_remaining/)
    expect(account).not.toMatch(/name: authState\.username/)
    expect(account).toMatch(/name: finiteText\(recGet\(authState, 'username'\)/)
    expect(account).not.toMatch(/\{\{\s*authState\.username\s*\}\}/)
    expect(account).toMatch(/finiteText\(recGet\(authState, 'username'\)/)
    expect(account).not.toMatch(/\{\{\s*enrollment\.manual_entry\s*\}\}/)
    expect(account).toMatch(/finiteText\(enrollment\.manual_entry\)/)
    expect(account).not.toMatch(/\{\{\s*code\s*\}\}/)
    expect(account).toMatch(/finiteText\(code\)/)
    expect(account).not.toMatch(/\{\{\s*twofaError\s*\}\}/)
    expect(account).toMatch(/finiteText\(twofaError\)/)
    expect(account).not.toMatch(/passwordMessage \|\| t\('settings\.password_rule'\)/)
    expect(account).toMatch(/finiteText\(passwordMessage, ''\) \|\| t\('settings\.password_rule'\)/)
    expect(account).not.toMatch(/toast\('❌ ' \+ e\.message\)/)
    expect(account).toMatch(/toast\('❌ ' \+ finiteText\(e\.message\)\)/)
    expect(account).toMatch(/v-for="code in asArray\(recoveryCodes\)"/)
    expect(account).toMatch(/v-if="asArray\(recoveryCodes\)\.length"/)
    expect(account).toMatch(/asArray\(r\.recovery_codes\)/)
    expect(account).toMatch(/asRecord\(await getTotpStatus\(\)\)/)
    expect(account).toMatch(/function secretLen\([\s\S]*typeof value === 'string'/)
    expect(account).not.toMatch(/newPassword\.value\.length/)
  })

  it('Bookmarks leftover summary counts go through finite helpers', () => {
    const bookmarks = readFileSync(resolve(SRC, 'views/Bookmarks.vue'), 'utf8')
    expect(bookmarks).toMatch(/from ['"][^'"]*lib\/finite/)
    expect(bookmarks).toMatch(/finiteN\(recGet\(data, 'up'\)/)
    expect(bookmarks).toMatch(/finiteN\(recGet\(data, 'down'\)/)
    expect(bookmarks).toMatch(/finiteText\(recGet\(data, 'checked_at'\)/)
    expect(bookmarks).not.toMatch(/at: data\.checked_at \|\| '—'/)
    expect(bookmarks).not.toMatch(/\{\{\s*b\.name\s*\}\}/)
    expect(bookmarks).toMatch(/finiteText\(recGet\(b, 'name'\)\)/)
    expect(bookmarks).toMatch(/finiteText\(recGet\(b, 'url'\)\)/)
    expect(bookmarks).not.toMatch(/return b\.status \|\| t\('dashboard\.bm_up'\)/)
    expect(bookmarks).toMatch(/finiteText\(recGet\(b, 'status'\), ''\) \|\| t\('dashboard\.bm_up'\)/)
    expect(bookmarks).toMatch(/finiteText\(bk\.name, ''\) \|\| finiteText\(bk\.id, ''\)/)
    expect(bookmarks).not.toMatch(/:href="b\.url"/)
    expect(bookmarks).toMatch(/:href="finiteText\(recGet\(b, 'url'\), ''\)"/)
    expect(bookmarks).toMatch(/v-for="\(b, i\) in asArray\(recGet\(data, 'bookmarks'\)\)"/)
    expect(bookmarks).toMatch(/asRecord\(await getBookmarks/)
    expect(bookmarks).toMatch(/const n = finiteN\(ms, null\)/)
    expect(bookmarks).toMatch(/recGet\(b, 'health'\)/)
    expect(bookmarks).toMatch(/recGet\(b, 'backend'\)/)
  })

  it('Alerts leftover timestamps go through fmtTs', () => {
    const alerts = readFileSync(resolve(SRC, 'views/Alerts.vue'), 'utf8')
    expect(alerts).toMatch(/from ['"][^'"]*lib\/finite/)
    expect(alerts).toMatch(/function fmt\([\s\S]*fmtTs/)
    expect(alerts).not.toMatch(/\{\{\s*a\.name\s*\}\}/)
    expect(alerts).toMatch(/finiteText\(recGet\(a, 'name'\)\)/)
    expect(alerts).not.toMatch(/n: r\.emitted\?\.length \|\| 0/)
    expect(alerts).not.toMatch(/n: finiteN\(r\.emitted\?\.length, 0\)/)
    expect(alerts).toMatch(/n: asArray\(recGet\(r, 'emitted'\)\)\.length/)
    expect(alerts).not.toMatch(/'❌ ' \+ \(r\.message \|\| ''\)/)
    expect(alerts).toMatch(/'❌ ' \+ finiteText\(recGet\(r, 'message'\), ''\)/)
    expect(alerts).toMatch(/finiteN\(asArray\(filtered\)\.length\)/)
    expect(alerts).toMatch(/finiteN\(asArray\(alerts\)\.length\)/)
    expect(alerts).toMatch(/loadError\.value = finiteText\(e\.message \|\| String\(e\), ''\)/)
    expect(alerts).toMatch(/recGet\(a, 'level'\)/)
  })

  it('Scheduler leftover counts/duration/rc go through finite helpers', () => {
    const scheduler = readFileSync(resolve(SRC, 'views/Scheduler.vue'), 'utf8')
    expect(scheduler).toMatch(/from ['"][^'"]*lib\/finite/)
    expect(scheduler).not.toMatch(/\{\{\s*data\.count\s*\}\}/)
    expect(scheduler).not.toMatch(/\{\{\s*run\.duration \}\}s/)
    expect(scheduler).not.toMatch(/rc=\{\{ run\.rc \?\? '—' \}\}/)
    expect(scheduler).toMatch(/function fmt\([\s\S]*fmtTs/)
    expect(scheduler).toMatch(/finiteN\(data\.count/)
    expect(scheduler).toMatch(/withUnit\(asRecord\(run\)\.duration, 's'\)/)
    expect(scheduler).toMatch(/finiteN\(asRecord\(run\)\.rc/)
    expect(scheduler).not.toMatch(/s\.enabled \? s\.interval :/)
    expect(scheduler).toMatch(/finiteText\(asRecord\(s\)\.interval/)
    expect(scheduler).toMatch(/function formatCal\([\s\S]*finiteText/)
    expect(scheduler).not.toMatch(/typeof c === 'object' \? JSON\.stringify\(c\) : String\(c\)/)
    expect(scheduler).not.toMatch(/\{\{\s*job\.name\s*\}\}/)
    expect(scheduler).toMatch(/finiteText\(asRecord\(job\)\.name\)/)
    expect(scheduler).not.toMatch(/row\.program \|\| '—'/)
    expect(scheduler).toMatch(/finiteText\(asRecord\(row\)\.program\)/)
    expect(scheduler).not.toMatch(/toast\('❌ ' \+ e\.message\)/)
    expect(scheduler).toMatch(/toast\('❌ ' \+ finiteText\(e\.message\)\)/)
    expect(scheduler).not.toMatch(/\{\{\s*runsError\s*\}\}/)
    expect(scheduler).toMatch(/finiteText\(runsError\)/)
    expect(scheduler).toMatch(/loadError\.value = finiteText\(e\.message \|\| String\(e\), ''\)/)
    expect(scheduler).not.toMatch(/\{\{\s*job\.cron\s*\}\}/)
    expect(scheduler).toMatch(/finiteText\(asRecord\(job\)\.cron\)/)
    expect(scheduler).not.toMatch(/\{\{\s*run\.tail\s*\}\}/)
    expect(scheduler).toMatch(/finiteText\(asRecord\(run\)\.tail\)/)
    expect(scheduler).toMatch(/v-for="job in asArray\(jobs\)"/)
    expect(scheduler).toMatch(/v-for="s in asArray\(systemJobs\)"/)
    expect(scheduler).toMatch(/v-for="\(run, i\) in asArray\(runs\)"/)
    expect(scheduler).toMatch(/jobs\.value = ingestJobRows\(d, 'jobs'\)/)
    expect(scheduler).toMatch(/systemJobs\.value = ingestJobRows\(d, 'system'\)/)
    expect(scheduler).toMatch(/runs\.value = ingestJobRows\(d, 'runs'\)/)
    expect(scheduler).toMatch(/function ingestJobRows\(/)
    expect(scheduler).toMatch(/asRecord\(job\)/)
    expect(scheduler).toMatch(/Do not wrap a Set as asArray/)
  })

  it('Backups leftover ports/files/mtime go through finite helpers', () => {
    const backups = readFileSync(resolve(SRC, 'views/Backups.vue'), 'utf8')
    expect(backups).toMatch(/from ['"][^'"]*lib\/finite/)
    expect(backups).toMatch(/function sizeMb\([\s\S]*Number\.isFinite/)
    expect(backups).toMatch(/function fmt\([\s\S]*fmtTs/)
    expect(backups).not.toMatch(/:\{\{ layers\.db\.port \}\}/)
    expect(backups).toMatch(/finiteN\(recGet\(recGet\(layers, 'db'\), 'port'/)
    expect(backups).toMatch(/finiteN\(recGet\(recGet\(layers, 'bridge'\), 'exported_files'/)
    expect(backups).toMatch(/finiteN\(recGet\(recGet\(job, 'params'\), 'retain'/)
    expect(backups).toMatch(/finiteText\(rsyncBinary\.version/)
    expect(backups).toMatch(/finiteText\(recGet\(recGet\(preview, 'binary'\), 'version'/)
    expect(backups).toMatch(/finiteText\(recGet\(recGet\(job, 'params'\), 'stack_id'/)
    expect(backups).not.toMatch(/\{\{\s*job\.name\s*\}\}/)
    expect(backups).toMatch(/finiteText\(recGet\(job, 'name'\)\)/)
    expect(backups).not.toMatch(/\{\{\s*b\.name\s*\}\}/)
    expect(backups).toMatch(/finiteText\(recGet\(b, 'name'\)\)/)
    expect(backups).not.toMatch(/layers\.db\?\.last\?\.name \|\| t\('photoshub\.never'\)/)
    expect(backups).toMatch(/finiteText\(recGet\(recGet\(recGet\(layers, 'db'\), 'last'\), 'name'/)
    expect(backups).not.toMatch(/layers\.bridge\?\.path \|\| '—'/)
    expect(backups).toMatch(/finiteText\(recGet\(recGet\(layers, 'bridge'\), 'last_success'\), ''\) \|\| finiteText\(recGet\(recGet\(layers, 'bridge'\), 'path'\)/)
    expect(backups).not.toMatch(/toast\('❌ ' \+ e\.message\)/)
    expect(backups).toMatch(/toast\('❌ ' \+ finiteText\(e\.message\)\)/)
    expect(backups).not.toMatch(/\{\{\s*msg\s*\}\}/)
    expect(backups).toMatch(/finiteText\(msg\)/)
    expect(backups).toMatch(/msg\.value = finiteText\(e\.message, ''\)/)
    expect(backups).toMatch(/loadError\.value = finiteText\(e\.message \|\| String\(e\), ''\)/)
    expect(backups).toMatch(/asArray\(postgresTargets\.value\)\.map\(\(t\) => finiteText\(recGet\(t, 'id'\), ''\)\)/)
    expect(backups).not.toMatch(/\{\{\s*job\.cron\s*\}\}/)
    expect(backups).toMatch(/finiteText\(recGet\(job, 'cron'\)\)/)
    expect(backups).not.toMatch(/preview\.samples" :key="i">\{\{ line \}\}<\/div>/)
    expect(backups).toMatch(/finiteText\(line\)/)
    expect(backups).toMatch(/v-for="\(line, i\) in asArray\(recGet\(preview, 'samples'\)\)"/)
    expect(backups).toMatch(/v-for="b in asArray\(backups\)"/)
    expect(backups).toMatch(/jobs\.value = asArray\(recGet\(d, 'jobs'\)\)\.map\(\(row\) => asRecord\(row\)\)/)
    expect(backups).toMatch(/recGet\(d, 'name'\)/)
    expect(backups).toMatch(/recGet\(j, 'running'\)/)
  })

  it('App leftover service counts go through finiteN', () => {
    const app = readFileSync(resolve(SRC, 'App.vue'), 'utf8')
    expect(app).toMatch(/from ['"][^'"]*lib\/finite/)
    expect(app).not.toMatch(/\{\{\s*counts\.ok\s*\}\}/)
    expect(app).not.toMatch(/\{\{\s*counts\.warn\s*\}\}/)
    expect(app).toMatch(/finiteN\(counts\.ok/)
    expect(app).toMatch(/finiteN\(counts\.warn/)
    expect(app).toMatch(/finiteN\(counts\.down/)
    expect(app).not.toMatch(/item\.title \|\| t\(item\.labelKey\)/)
    expect(app).toMatch(/finiteText\(recGet\(item, 'title'/)
    expect(app).toMatch(/finiteText\(recGet\(item, 'to'\)/)
    expect(app).toMatch(/finiteText\(toast\)/)
    expect(app).not.toMatch(/\{\{\s*l\.native\s*\}\}/)
    expect(app).toMatch(/finiteText\(recGet\(l, 'native'\)\)/)
    expect(app).toMatch(/v-for="item in asArray\(nav\)"/)
    expect(app).toMatch(/v-for="th in asArray\(themes\)"/)
    expect(app).not.toMatch(/v-for="item in nav"/)
    expect(app).not.toMatch(/v-for="th in themes"/)
    expect(app).toMatch(/asArray\(recGet\(c, 'match'\)\)\.some/)
    expect(app).not.toMatch(/return c\.match\.some/)
    expect(app).toMatch(/asTrimmed\(cmdQuery\.value\)/)
    expect(app).not.toMatch(/cmdQuery\.value\.trim\(\)/)
    expect(app).not.toMatch(/cmdQuery\.value\.toLowerCase\(\)\.trim\(\)/)
    const vms = readFileSync(resolve(SRC, 'views/VMs.vue'), 'utf8')
    expect(vms).toMatch(/!asTrimmed\(cloneName\)/)
    expect(vms).toMatch(/!asTrimmed\(renameName\)/)
    expect(vms).not.toMatch(/cloneName\.trim\(\)/)
    expect(vms).not.toMatch(/createForm\.value\.version\.trim\(\)/)
    const ollama = readFileSync(resolve(SRC, 'views/Ollama.vue'), 'utf8')
    expect(ollama).toMatch(/!asTrimmed\(pullName\)/)
    expect(ollama).toMatch(/!asTrimmed\(testPrompt\)/)
    expect(ollama).not.toMatch(/pullName\.trim\(\)/)
    const containers = readFileSync(resolve(SRC, 'views/Containers.vue'), 'utf8')
    expect(containers).toMatch(/!asTrimmed\(pullImage\)/)
    expect(containers).toMatch(/!asTrimmed\(newVol\)/)
    expect(containers).toMatch(/!asTrimmed\(newNet\)/)
    expect(containers).not.toMatch(/pullImage\.trim\(\)/)
    const mainArray = readFileSync(resolve(SRC, 'views/MainArray.vue'), 'utf8')
    expect(mainArray).toMatch(/!asTrimmed\(renameName\)/)
    expect(mainArray).not.toMatch(/!renameName\.trim\(\)/)
    const assistant = readFileSync(resolve(SRC, 'components/AssistantDrawer.vue'), 'utf8')
    expect(assistant).toMatch(/!asTrimmed\(draft\)/)
    expect(assistant).not.toMatch(/!draft\.trim\(\)/)
  })

  it('theme leftover catalogues go through asArray', () => {
    const src = readFileSync(resolve(SRC, 'theme/index.js'), 'utf8')
    expect(src).toMatch(/from ['"][^'"]*lib\/finite/)
    expect(src).toMatch(/asArray\(THEMES\)\.some/)
    expect(src).toMatch(/asArray\(DENSITIES\)\.some/)
    expect(src).toMatch(/themes: asArray\(THEMES\)/)
    expect(src).toMatch(/densities: asArray\(DENSITIES\)/)
    expect(src).toMatch(/asArray\(LIGHT_THEMES\)\.includes/)
    expect(src).not.toMatch(/return THEMES\.some/)
  })

  it('Audit leftover extra fields go through finiteText', () => {
    const audit = readFileSync(resolve(SRC, 'views/Audit.vue'), 'utf8')
    expect(audit).toMatch(/from ['"][^'"]*lib\/finite/)
    expect(audit).toMatch(/finiteText\(v\)/)
    expect(audit).not.toMatch(/`\$\{k\}=\$\{v\}`/)
    expect(audit).not.toMatch(/e\.username \|\| '—'/)
    expect(audit).toMatch(/finiteText\(recGet\(e, 'username'\)\)/)
    expect(audit).not.toMatch(/e\.client \|\| '—'/)
    expect(audit).toMatch(/finiteText\(recGet\(e, 'client'\)\)/)
    expect(audit).not.toMatch(/e\.outcome \|\| '—'/)
    expect(audit).toMatch(/finiteText\(recGet\(e, 'outcome'\)\)/)
    expect(audit).not.toMatch(/\{\{\s*e\.client\s*\}\}/)
    expect(audit).toMatch(/`\$\{finiteText\(k\)\}=\$\{finiteText\(v\)\}`/)
    expect(audit).toMatch(/n: finiteN\(asArray\(entries\)\.length\)/)
    expect(audit).toMatch(/max: finiteN\(maxRetained\)/)
    expect(audit).toMatch(/asArray\(entries\.value\)\.slice\(\)\.reverse\(\)/)
    expect(audit).toMatch(/v-for="\(e, i\) in asArray\(filteredRows\)"/)
    expect(audit).toMatch(/:key="finiteText\(recGet\(e, 'ts'\)\)/)
    expect(audit).toMatch(/finiteN\(asArray\(filteredRows\)\.length\)/)
    expect(audit).toMatch(/finiteN\(recGet\(d, 'retained_lines'\)/)
    expect(audit).toMatch(/asTrimmed\(q\.value\)\.toLowerCase\(\)/)
  })

  it('Dashboard leftover service totals go through finiteN', () => {
    const dash = readFileSync(resolve(SRC, 'views/Dashboard.vue'), 'utf8')
    expect(dash).toMatch(/finiteN\(status\?\.service_total/)
    expect(dash).toMatch(/finiteN\(status\?\.counts\?\.ok/)
    expect(dash).not.toMatch(/status\?\.service_total \?\? '—'/)
  })

  it('Services leftover totals go through finiteN', () => {
    const services = readFileSync(resolve(SRC, 'views/Services.vue'), 'utf8')
    expect(services).toMatch(/from ['"][^'"]*lib\/finite/)
    expect(services).toMatch(/finiteN\(status\.service_total/)
    expect(services).not.toMatch(/status\.service_total \?\? flat\.length/)
    expect(services).not.toMatch(/status\?\.counts\?\.ok \?\? 0/)
    expect(services).toMatch(/finiteN\(status\?\.counts\?\.ok, 0\)/)
    expect(services).toMatch(/finiteN\(result\.ok_count, 0\)/)
    expect(services).not.toMatch(/`✅ \$\{result\.ok_count\}`/)
    expect(services).not.toMatch(/ts: status\.ts,/)
    expect(services).toMatch(/finiteText\(status\.ts/)
    expect(services).not.toMatch(/\{\{\s*s\.detail\s*\}\}/)
    expect(services).toMatch(/finiteText\(s\.detail\)/)
    expect(services).not.toMatch(/\{\{\s*s\.id\s*\}\}/)
    expect(services).toMatch(/finiteText\(s\.id\)/)
    expect(services).not.toMatch(/\{\{\s*s\.name\s*\}\}/)
    expect(services).toMatch(/finiteText\(s\.name\)/)
    expect(services).toMatch(/finiteText\(p\.name\)/)
    expect(services).not.toMatch(/toast\(`❌ \$\{e\.message \|\| e\}`\)/)
    expect(services).toMatch(/toast\('❌ ' \+ finiteText\(e\.message \|\| e\)\)/)
    expect(services).toMatch(/loadError\.value = finiteText\(e\.message \|\| String\(e\), ''\)/)
    expect(services).toMatch(/v-for="l in asArray\(status\.links\)"/)
    expect(services).toMatch(/v-for="s in asArray\(filtered\)"/)
    expect(services).toMatch(/v-for="g in asArray\(filteredGroups\)"/)
    expect(services).toMatch(/v-for="s in asArray\(g\.services\)"/)
  })

  it('Containers job log live region is gated on jobLog', () => {
    const containers = readFileSync(resolve(SRC, 'views/Containers.vue'), 'utf8')
    expect(containers).toMatch(/<pre v-if="jobLog"[\s\S]*aria-live="polite"/)
    expect(containers).toMatch(/finiteText\(stats\[c\.id\]\?\.cpu\)/)
    expect(containers).not.toMatch(/stats\[c\.id\]\?\.cpu \|\| '—'/)
    expect(containers).toMatch(/finiteText\(recGet\(c, 'network'\)/)
    expect(containers).toMatch(/v-for="\(im,i\) in asArray\(images\)"/)
    expect(containers).toMatch(/v-for="v in asArray\(volumes\)"/)
    expect(containers).toMatch(/v-for="n in asArray\(networks\)"/)
    expect(containers).toMatch(/recGet\(data, 'engine_up'\) \? t\('common.running'\)/)
  })

  it('ScheduleJobForm leftover preview counts go through finiteN', () => {
    const form = readFileSync(resolve(SRC, 'components/ScheduleJobForm.vue'), 'utf8')
    expect(form).toMatch(/from ['"][^'"]*lib\/finite/)
    expect(form).toMatch(/finiteN\(recGet\(preview, 'creates'\)/)
    expect(form).toMatch(/finiteN\(recGet\(preview, 'updates'\)/)
    expect(form).toMatch(/finiteN\(recGet\(preview, 'deletes'\)/)
    expect(form).not.toMatch(/n: preview\.creates \}\)/)
    expect(form).toMatch(/finiteText\(line\)/)
    expect(form).not.toMatch(/\{\{\s*line\s*\}\}/)
    expect(form).not.toMatch(/\{\{\s*previewError\s*\}\}/)
    expect(form).toMatch(/finiteText\(previewError\)/)
    expect(form).not.toMatch(/\{\{\s*cronText\s*\}\}/)
    expect(form).toMatch(/finiteText\(cronText\)/)
    expect(form).not.toMatch(/\(p\.exclude \|\| \[\]\)\.join\('\\n'\)/)
    expect(form).toMatch(/asArray\(recGet\(p, 'exclude'\)\)\.map\(\(n\) => finiteText\(n, ''\)\)/)
    expect(form).toMatch(/previewError\.value = finiteText\(e\.message \|\| String\(e\), ''\)/)
    expect(form).toMatch(/n: finiteN\(step\[1\]\)/)
    expect(form).toMatch(/v-for="s in asArray\(stacks\)"/)
    expect(form).toMatch(/v-for="\(line, i\) in asArray\(recGet\(preview, 'samples'\)\)"/)
  })

  it('ServiceDetailDrawer leftover detail goes through finiteText', () => {
    const drawer = readFileSync(resolve(SRC, 'components/ServiceDetailDrawer.vue'), 'utf8')
    expect(drawer).toMatch(/from ['"][^'"]*lib\/finite/)
    expect(drawer).not.toMatch(/\{\{\s*service\.detail \|\| '—'\s*\}\}/)
    expect(drawer).toMatch(/finiteText\(recGet\(service, 'detail'\)\)/)
    expect(drawer).not.toMatch(/\{\{\s*service\.id\s*\}\}/)
    expect(drawer).toMatch(/finiteText\(recGet\(service, 'id'\)\)/)
    expect(drawer).not.toMatch(/service\.group \|\| '—'/)
    expect(drawer).toMatch(/finiteText\(recGet\(service, 'group'\)\)/)
    expect(drawer).not.toMatch(/service\.url \|\| '—'/)
    expect(drawer).toMatch(/finiteText\(recGet\(service, 'url'\)\)/)
    expect(drawer).not.toMatch(/\{\{\s*service\.name\s*\}\}/)
    expect(drawer).toMatch(/finiteText\(recGet\(service, 'name'\)\)/)
    expect(drawer).not.toMatch(/\(service\.env_sample \|\| \[\]\)\.join\('\\n'\)/)
    expect(drawer).toMatch(/asArray\(recGet\(service, 'env_sample'\)\)\.map\(n => finiteText\(n, ''\)\)/)
    expect(drawer).not.toMatch(/\{\{\s*service\.launchctl\s*\}\}/)
    expect(drawer).toMatch(/finiteText\(recGet\(service, 'launchctl'\)\)/)
    expect(drawer).not.toMatch(/\{\{\s*log \|\| t\('services\.log_empty'\)\s*\}\}/)
    expect(drawer).toMatch(/finiteText\(log, ''\) \|\| t\('services\.log_empty'\)/)
    expect(drawer).not.toMatch(/\(ad\.ports \|\| \[\]\)\.join\(', '\)/)
    expect(drawer).toMatch(/asArray\(recGet\(ad, 'ports'\)\)\.map\(\(n\) => finiteText\(n, ''\)\)/)
    expect(drawer).toMatch(/asArray\(recGet\(sc, 'ports'\)\)\.map\(\(n\) => finiteText\(n, ''\)\)/)
  })

  it('NotifyChannels leftover channel ids go through finiteText', () => {
    const ch = readFileSync(resolve(SRC, 'components/NotifyChannels.vue'), 'utf8')
    expect(ch).toMatch(/from ['"][^'"]*lib\/finite/)
    expect(ch).not.toMatch(/\{\{\s*c\.id\s*\}\}/)
    expect(ch).toMatch(/finiteText\(recGet\(c, 'id'\)\)/)
    expect(ch).not.toMatch(/editing\.name \|\| editing\.id/)
    expect(ch).toMatch(/finiteText\(recGet\(editing, 'id'\)/)
    expect(ch).not.toMatch(/\{\{\s*c\.name\s*\}\}/)
    expect(ch).toMatch(/finiteText\(recGet\(c, 'name'\)\)/)
    expect(ch).not.toMatch(/role="alert">\{\{ loadError \}\}<\/div>/)
    expect(ch).toMatch(/finiteText\(loadError\)/)
    expect(ch).not.toMatch(/toast\('❌ ' \+ e\.message\)/)
    expect(ch).toMatch(/toast\('❌ ' \+ finiteText\(e\.message\)\)/)
    expect(ch).not.toMatch(/toast\('❌ ' \+ err\.message\)/)
    expect(ch).toMatch(/toast\('❌ ' \+ finiteText\(err\.message\)\)/)
    expect(ch).toMatch(/v-for="c in asArray\(channels\)"/)
    expect(ch).toMatch(/loadError\.value = finiteText\(e\.message \|\| String\(e\), ''\)/)
    expect(ch).toMatch(/Object\.keys\(asRecord\(types\.value\)\)/)
    expect(ch).toMatch(/:key="finiteText\(ty\)"/)
    expect(ch).not.toMatch(/:key="ty"/)
    expect(ch).toMatch(/recGet\(row, 'id'\)/)
    expect(ch).toMatch(/recGet\(editing\.value, 'id'\)/)
  })

  it('AssistantDrawer leftover path/title interpolations go through finiteText', () => {
    const ad = readFileSync(resolve(SRC, 'components/AssistantDrawer.vue'), 'utf8')
    expect(ad).toMatch(/from ['"][^'"]*lib\/finite/)
    expect(ad).not.toMatch(/\{\{\s*p\.path\s*\}\}/)
    expect(ad).toMatch(/finiteText\(recGet\(p, 'path'\)\)/)
    expect(ad).not.toMatch(/\{\{\s*p\.title\s*\}\}/)
    expect(ad).toMatch(/finiteText\(recGet\(p, 'title'\)\)/)
    expect(ad).not.toMatch(/\$\{p\.name\} · \$\{p\.state\}/)
    expect(ad).toMatch(/finiteText\(p\.name\)/)
    expect(ad).not.toMatch(/q: query \|\| ''/)
    expect(ad).toMatch(/q: finiteText\(query, ''\)/)
    expect(ad).toMatch(/finiteText\(reply\.text, ''\)/)
    expect(ad).not.toMatch(/: \(err\.message \|\| String\(err\)\)/)
    expect(ad).toMatch(/finiteText\(err\.message \|\| String\(err\)\)/)
    expect(ad).toMatch(/emit\('go', finiteText\(path, ''\) \|\| '\/'\)/)
    expect(ad).toMatch(/finiteText\(displayText\(out, query\), ''\)/)
  })

  it('ServiceLogsModal leftover source goes through finiteText', () => {
    const modal = readFileSync(resolve(SRC, 'components/ServiceLogsModal.vue'), 'utf8')
    expect(modal).toMatch(/from ['"][^'"]*lib\/finite/)
    expect(modal).not.toMatch(/\{\{\s*entry\.source\s*\}\}/)
    expect(modal).toMatch(/finiteText\(recGet\(entry, 'source'\)\)/)
    expect(modal).not.toMatch(/entry\.log \|\| t\('services\.log_empty'\)/)
    expect(modal).toMatch(/finiteText\(recGet\(entry, 'log'\), ''\) \|\| t\('services\.log_empty'\)/)
  })

  it('ServiceActions leftover leftover url and state go through recGet', () => {
    const actions = readFileSync(resolve(SRC, 'components/ServiceActions.vue'), 'utf8')
    expect(actions).toMatch(/from ['"][^'"]*lib\/finite/)
    expect(actions).toMatch(/finiteText\(recGet\(service, 'url'\), ''\)/)
    expect(actions).toMatch(/recGet\(props\.service, 'state'\)/)
    expect(actions).toMatch(/v-for="a in asArray\(buttonActs\)"/)
  })

  it('ServiceSignatures leftover ports and counts go through finite helpers', () => {
    const sigs = readFileSync(resolve(SRC, 'components/ServiceSignatures.vue'), 'utf8')
    expect(sigs).toMatch(/from ['"][^'"]*lib\/finite/)
    expect(sigs).toMatch(/function fmtPorts\([\s\S]*finiteText/)
    expect(sigs).toMatch(/finiteN\(recGet\(data, 'builtin_count'\), 0\)/)
    expect(sigs).not.toMatch(/data\.builtin_count \|\| 0/)
    expect(sigs).not.toMatch(/\{\{\s*row\.name\s*\}\}/)
    expect(sigs).toMatch(/finiteText\(recGet\(row, 'name'\)\)/)
    expect(sigs).not.toMatch(/\{\{\s*row\.slug\s*\}\}/)
    expect(sigs).toMatch(/finiteText\(recGet\(row, 'slug'\)\)/)
    expect(sigs).not.toMatch(/\{\{\s*row\.category\s*\}\}/)
    expect(sigs).toMatch(/finiteText\(recGet\(row, 'category'\)\)/)
    expect(sigs).not.toMatch(/toast\(`❌ \$\{e\.message \|\| e\}`\)/)
    expect(sigs).not.toMatch(/toast\(`❌ \$\{err\.message \|\| err\}`\)/)
    expect(sigs).toMatch(/toast\('❌ ' \+ finiteText\(e\.message \|\| e\)\)/)
    expect(sigs).toMatch(/toast\('❌ ' \+ finiteText\(err\.message \|\| err\)\)/)
    expect(sigs).not.toMatch(/\(row\.procs \|\| \[\]\)\.join\(', '\)/)
    expect(sigs).toMatch(/asArray\(recGet\(rec, 'procs'\)\)\.map\(\(n\) => finiteText\(n, ''\)\)/)
    expect(sigs).toMatch(/asArray\(recGet\(rec, 'ports'\)\)\.map\(\(n\) => finiteText\(n, ''\)\)/)
    expect(sigs).toMatch(/rows\.value = asArray\(recGet\(data, 'signatures'\)\)\.map\(\(r\) => asRecord\(r\)\)/)
  })

  it('GroupRules leftover ids and matcher lists go through finite helpers', () => {
    const grules = readFileSync(resolve(SRC, 'components/GroupRules.vue'), 'utf8')
    expect(grules).toMatch(/from ['"][^'"]*lib\/finite/)
    expect(grules).not.toMatch(/\{\{\s*row\.group\s*\}\}/)
    expect(grules).toMatch(/finiteText\(recGet\(row, 'group'\)\)/)
    expect(grules).not.toMatch(/\{\{\s*row\.id\s*\}\}/)
    expect(grules).toMatch(/finiteText\(recGet\(row, 'id'\)\)/)
    expect(grules).not.toMatch(/toast\(`❌ \$\{e\.message \|\| e\}`\)/)
    expect(grules).not.toMatch(/toast\(`❌ \$\{err\.message \|\| err\}`\)/)
    expect(grules).toMatch(/toast\('❌ ' \+ finiteText\(e\.message \|\| e\)\)/)
    expect(grules).toMatch(/toast\('❌ ' \+ finiteText\(err\.message \|\| err\)\)/)
    expect(grules).toMatch(/function fmtList\([\s\S]*asArray/)
    expect(grules).toMatch(/rows\.value = asArray\(recGet\(data, 'rules'\)\)\.map\(\(r\) => asRecord\(r\)\)/)
  })

  it('string identifier interpolations go through finiteText', () => {
    // Leftover Infinity is a truthy number, so `hostname || '—'` still prints
    // the word "Infinity". Identifier fields skip finiteN (they are strings)
    // and have to go through finiteText instead.
    const BARE_ID = /^\{\{\s*[A-Za-z_$][\w$]*(?:\?\.|\.)(?:id|hostname|local_hostname|host_ip|lan_ip|disk_id|stack_id|root_id|uuid|version|orb_version|ServerVersion)\s*\}\}$/
    const ID_SLICE = /\{\{(?:(?!finiteText)[^}])*\.id\.slice\b/
    const HOST_OR = /\{\{(?:(?!finiteText)[^}])*\b(?:hostname|local_hostname|host_ip|lan_ip|disk_id|stack_id|root_id|uuid|version|orb_version|ServerVersion)\b[^}]*\|\|/
    const ID_FALLBACK = /\{\{(?:(?!finiteText)[^}])*\|\|\s*[A-Za-z_$][\w$?]*\.id\b/
    const DISK_Q = /\{\{(?:(?!finiteText)[^}])*\.disk_id\s*\?/
    const ATTR_ID = /(?::title|:aria-label)="(?!finiteText)[^"]*\.id"/g
    const offenders = []
    for (const [name, src] of vueFiles()) {
      const template = src.slice(0, src.search(/<script\b/) >>> 0)
      for (const m of template.matchAll(/\{\{[\s\S]*?\}\}/g)) {
        const interp = m[0].replace(/\s+/g, ' ').trim()
        if (BARE_ID.test(interp) || ID_SLICE.test(interp) || HOST_OR.test(interp) || ID_FALLBACK.test(interp) || DISK_Q.test(interp)) {
          offenders.push(`${name}: ${interp}`)
        }
      }
      for (const m of template.matchAll(ATTR_ID)) {
        offenders.push(`${name}: ${m[0]}`)
      }
    }
    expect(
      offenders,
      'identifier leftover Infinity must go through finiteText',
    ).toEqual([])
  })

  it('Compose leftover stack names go through finiteText', () => {
    const compose = readFileSync(resolve(SRC, 'views/Compose.vue'), 'utf8')
    expect(compose).toMatch(/from ['"][^'"]*lib\/finite/)
    expect(compose).not.toMatch(/\{\{\s*s\.name\s*\}\}/)
    expect(compose).toMatch(/finiteText\(recGet\(s, 'name'\)\)/)
    expect(compose).not.toMatch(/\{\{\s*s\.status\s*\}\}/)
    expect(compose).toMatch(/finiteText\(recGet\(s, 'status'\)\)/)
    expect(compose).not.toMatch(/s\.path \|\| '—'/)
    expect(compose).toMatch(/finiteText\(recGet\(s, 'path'\)\)/)
    expect(compose).not.toMatch(/\{\{\s*msg\s*\}\}/)
    expect(compose).toMatch(/finiteText\(msg\)/)
    expect(compose).not.toMatch(/\{\{\s*jobLog\s*\}\}/)
    expect(compose).toMatch(/finiteText\(jobLog\)/)
    expect(compose).not.toMatch(/id: j\.id \}\)/)
    expect(compose).toMatch(/id: finiteText\(recGet\(j, 'id'\)\)/)
    expect(compose).toMatch(/recGet\(s, 'id'\)/)
    expect(compose).not.toMatch(/r\.message \|\| t\('compose\.started'\)/)
    expect(compose).toMatch(/finiteText\(recGet\(r, 'message'\), ''\) \|\| t\('compose\.started'\)/)
    expect(compose).not.toMatch(/jobLog\.value = j\.log \|\| ''/)
    expect(compose).toMatch(/jobLog\.value = finiteText\(recGet\(j, 'log'\), ''\)/)
    expect(compose).toMatch(/v-for="s in asArray\(stacks\)"/)
    expect(compose).toMatch(/stacks\.value = asArray\(recGet\(d, 'stacks'\)\)\.map\(\(s\) => asRecord\(s\)\)/)
    expect(compose).toMatch(/loadError\.value = finiteText\(e\.message \|\| String\(e\), ''\)/)
  })

  it('Brew leftover names go through finiteText', () => {
    const brew = readFileSync(resolve(SRC, 'views/Brew.vue'), 'utf8')
    expect(brew).toMatch(/from ['"][^'"]*lib\/finite/)
    expect(brew).not.toMatch(/\{\{\s*s\.name\s*\}\}/)
    expect(brew).toMatch(/finiteText\(asRecord\(s\)\.name\)/)
    expect(brew).not.toMatch(/s\.user \|\| '—'/)
    expect(brew).toMatch(/finiteText\(asRecord\(s\)\.user\)/)
    expect(brew).not.toMatch(/\{\{\s*s\.status\s*\}\}/)
    expect(brew).toMatch(/finiteText\(asRecord\(s\)\.status\)/)
    expect(brew).not.toMatch(/\{\{\s*labels\[a\] \|\| a\s*\}\}/)
    expect(brew).toMatch(/finiteText\(labels\[a\], ''\) \|\| finiteText\(a\)/)
    expect(brew).toMatch(/v-for="s in asArray\(filtered\)"/)
    expect(brew).toMatch(/v-for="a in asArray\(asRecord\(s\)\.actions\)"/)
  })

  it('Logs leftover names go through finiteText', () => {
    const logs = readFileSync(resolve(SRC, 'views/Logs.vue'), 'utf8')
    expect(logs).toMatch(/from ['"][^'"]*lib\/finite/)
    expect(logs).not.toMatch(/\{\{\s*s\.name\s*\}\}/)
    expect(logs).toMatch(/finiteText\(recGet\(s, 'name'\)\)/)
    expect(logs).not.toMatch(/\{\{\s*meta\.path\s*\}\}/)
    expect(logs).toMatch(/finiteText\(recGet\(meta, 'path'\)\)/)
    expect(logs).toMatch(/n: finiteN\(asArray\(displayLines\)\.length\)/)
    expect(logs).not.toMatch(/displayLines\.value\.join\('\\n'\)/)
    expect(logs).toMatch(/asArray\(displayLines\.value\)\.map\(\(l\) => finiteText\(l, ''\)\)/)
    expect(logs).not.toMatch(/\{\{\s*displayText\s*\}\}/)
    expect(logs).toMatch(/finiteText\(displayText\)/)
    expect(logs).toMatch(/v-for="s in asArray\(sources\)"/)
    expect(logs).toMatch(/asArray\(recGet\(d, 'sources'\)\)\.map\(\(s\) => asRecord\(s\)\)/)
    expect(logs).toMatch(/function asLogLines\(/)
    expect(logs).toMatch(/jsonLoad\(text\)/)
    expect(logs).toMatch(/let v = finiteN\(n, null\)/)
    expect(logs).toMatch(/const v = finiteN\(n, null\)/)
    expect(logs).toMatch(/asTrimmed\(rawFilter\)\.toLowerCase\(\)/)
    expect(logs).toMatch(/asTrimmed\(finiteText\(filter, ''\)\)/)
  })

  it('Terminal leftover container labels and session ids go through finiteText', () => {
    const terminal = readFileSync(resolve(SRC, 'views/Terminal.vue'), 'utf8')
    expect(terminal).toMatch(/from ['"][^'"]*lib\/finite/)
    expect(terminal).not.toMatch(/\{\{\s*containerListError\s*\}\}/)
    expect(terminal).toMatch(/finiteText\(containerListError\)/)
    expect(terminal).not.toMatch(/\{\{\s*sessionId\s*\}\}/)
    expect(terminal).toMatch(/finiteText\(sessionId\)/)
    expect(terminal).not.toMatch(/item\?\.label \|\| container\.value \|\| t\('terminal\.target_container'\)/)
    expect(terminal).toMatch(/finiteText\(recGet\(item, 'label'\), ''\) \|\| finiteText\(container\.value, ''\)/)
    expect(terminal).toMatch(/sessionId\.value = finiteText\(recGet\(message, 'session'\), ''\)/)
    expect(terminal).toMatch(/socket\.send\(jsonDump\(/)
    expect(terminal).not.toMatch(/socket\.send\(JSON\.stringify\(/)
    expect(terminal).toMatch(/v-for="c in asArray\(containers\)"/)
    expect(terminal).toMatch(/finiteText\(recGet\(c, 'label'\)/)
  })

  it('leftover name interpolations in listed views go through finiteText', () => {
    const FILES = [
      'views/Network.vue', 'views/Containers.vue', 'views/Scheduler.vue',
      'views/Dashboard.vue', 'views/Apps.vue', 'views/Brew.vue', 'views/Compose.vue',
      'views/Ollama.vue', 'views/VMs.vue', 'views/Alerts.vue', 'views/Health.vue',
      'views/Tools.vue', 'views/Backups.vue', 'views/Settings.vue', 'views/Logs.vue',
      'views/Shares.vue', 'views/WireGuard.vue', 'views/MainArray.vue',
      'views/PhotosHub.vue', 'views/Pool.vue', 'views/Services.vue',
      'components/ServiceDetailDrawer.vue', 'components/NotifyChannels.vue',
      'components/ServiceSignatures.vue', 'components/ServiceLogsModal.vue',
      'components/GroupRules.vue',
      'components/AssistantDrawer.vue', 'components/LineChart.vue',
      'components/VncConsole.vue',
    ]
    const BARE_NAME = /^\{\{\s*[A-Za-z_$][\w$]*(?:\?\.|\.)name\s*\}\}$/
    const NAME_OR = /\{\{(?:(?!finiteText)[^}])*\.name\s*\|\|/
    const ATTR_NAME = /(?::title|:aria-label|:placeholder)="(?![^"]*finiteText)[^"]*\.name"/g
    const offenders = []
    for (const rel of FILES) {
      const src = readFileSync(resolve(SRC, rel), 'utf8')
      const template = src.slice(0, src.search(/<script\b/) >>> 0)
      for (const m of template.matchAll(/\{\{[\s\S]*?\}\}/g)) {
        const interp = m[0].replace(/\s+/g, ' ').trim()
        if (BARE_NAME.test(interp) || NAME_OR.test(interp)) offenders.push(`${rel}: ${interp}`)
      }
      for (const m of template.matchAll(ATTR_NAME)) offenders.push(`${rel}: ${m[0]}`)
    }
    expect(offenders, 'leftover name Infinity must go through finiteText').toEqual([])
  })

  it('leftover string || em-dash interpolations go through finiteText', () => {
    const FILES = [
      'views/Network.vue', 'views/Containers.vue', 'views/Scheduler.vue',
      'views/Dashboard.vue', 'views/Apps.vue', 'views/Brew.vue', 'views/Compose.vue',
      'views/Ollama.vue', 'views/VMs.vue', 'views/Alerts.vue', 'views/Health.vue',
      'views/Tools.vue', 'views/Backups.vue', 'views/Settings.vue', 'views/Logs.vue',
      'views/Shares.vue', 'views/WireGuard.vue', 'views/MainArray.vue',
      'views/PhotosHub.vue', 'views/Pool.vue', 'views/Services.vue',
      'components/ServiceDetailDrawer.vue', 'components/NotifyChannels.vue',
      'components/ServiceSignatures.vue', 'components/ServiceLogsModal.vue',
      'components/GroupRules.vue',
      'components/AssistantDrawer.vue', 'components/ScheduleJobForm.vue',
      'components/LineChart.vue',
      'components/VncConsole.vue', 'App.vue',
    ]
    const OR_DASH = /\{\{(?:(?!finiteText)[^}])*\|\|\s*'—'\}/
    const offenders = []
    for (const rel of FILES) {
      const src = readFileSync(resolve(SRC, rel), 'utf8')
      const template = src.slice(0, src.search(/<script\b/) >>> 0)
      for (const m of template.matchAll(/\{\{[\s\S]*?\}\}/g)) {
        const interp = m[0].replace(/\s+/g, ' ').trim()
        if (OR_DASH.test(interp)) offenders.push(`${rel}: ${interp}`)
      }
    }
    expect(offenders, 'leftover || em-dash Infinity must go through finiteText').toEqual([])
  })

  it('leftover status/path/label/detail/protocol/ip/mac interpolations go through finiteText', () => {
    const BARE = /^\{\{\s*[A-Za-z_$][\w$]*(?:\?\.|\.)(?:[A-Za-z_$][\w$]*(?:\?\.|\.))*(?:status|path|label|detail|protocol|ip|mac)\s*\}\}$/
    const OR_FIELD = /\{\{(?:(?!finiteText)[^}])*\.(?:status|path|label|detail|protocol|ip|mac)\s*\|\|/
    const ATTR_FIELD = /(?::title|:aria-label)="(?![^"]*finiteText)[^"]*\.(?:status|path|label|detail|protocol|ip|mac)"/g
    const offenders = []
    for (const [name, src] of vueFiles()) {
      const template = src.slice(0, src.search(/<script\b/) >>> 0)
      for (const m of template.matchAll(/\{\{[\s\S]*?\}\}/g)) {
        const interp = m[0].replace(/\s+/g, ' ').trim()
        if (BARE.test(interp) || OR_FIELD.test(interp)) offenders.push(`${name}: ${interp}`)
      }
      for (const m of template.matchAll(ATTR_FIELD)) offenders.push(`${name}: ${m[0]}`)
    }
    expect(
      offenders,
      'leftover status/path/label/detail/protocol/ip/mac Infinity must go through finiteText',
    ).toEqual([])
  })

  it('Login leftover username/token/error go through finiteText', () => {
    const login = readFileSync(resolve(SRC, 'views/Login.vue'), 'utf8')
    expect(login).toMatch(/from ['"][^'"]*lib\/finite/)
    expect(login).not.toMatch(/state\.username \|\| 'admin'/)
    expect(login).toMatch(/finiteText\(state\.username, ''\) \|\| 'admin'/)
    expect(login).not.toMatch(/autoToken\.value = tokenResp\.setup_token \|\| ''/)
    expect(login).toMatch(/finiteText\(tokenResp\.setup_token, ''\)/)
    expect(login).not.toMatch(/username: result\.username \|\| username\.value/)
    expect(login).toMatch(/finiteText\(row\.username, ''\) \|\| finiteText\(username\.value\)/)
    expect(login).not.toMatch(/\{\{\s*autoToken\s*\}\}/)
    expect(login).toMatch(/finiteText\(autoToken\)/)
    expect(login).not.toMatch(/\{\{\s*error\s*\}\}/)
    expect(login).toMatch(/finiteText\(error\)/)
    expect(login).not.toMatch(/error\.value = e\.message/)
    expect(login).toMatch(/error\.value = finiteText\(e\.message, ''\)/)
    expect(login).not.toMatch(/totpPending\.value = result\.pending \|\| ''/)
    expect(login).toMatch(/finiteText\(result\.pending, ''\)/)
    expect(login).not.toMatch(/\{\{\s*l\.native\s*\}\}/)
    expect(login).toMatch(/finiteText\(asRecord\(l\)\.native\)/)
  })

  it('AdminPasswordDialog has no leftover API interpolations', () => {
    const dlg = readFileSync(resolve(SRC, 'components/AdminPasswordDialog.vue'), 'utf8')
    const template = dlg.slice(0, dlg.search(/<script\b/) >>> 0)
    const leftover = []
    for (const m of template.matchAll(/\{\{[\s\S]*?\}\}/g)) {
      const interp = m[0].replace(/\s+/g, ' ').trim()
      if (!/\bt\(/.test(interp)) leftover.push(interp)
    }
    expect(leftover, 'AdminPasswordDialog interpolates only i18n strings').toEqual([])
    expect(dlg).toMatch(/aria-label="t\('adminPrompt.password'\)"/)
    expect(dlg).toMatch(/aria-label="t\('adminPrompt.title'\)"/)
  })

  it('leftover i18n identifier params go through finiteText', () => {
    // i18n calls that pass leftover.username interpolate leftover Infinity
    // into translated strings. finiteText must run on leftover identifier
    // params the way Compose wraps created-stack ids.
    const BARE = /\b(?:name|id|username|path|label)\s*:\s*(?:authState|acct|svc|task|it|c|uninstallModal|target|detail\.value|j|item|dev|twofaResetUser|portEdit|cfSelectedTunnel|createForm\.value)\.(?:username|name|id|path|label|remove_data_path|value)\b/
    const offenders = []
    for (const [name, src] of vueFiles()) {
      for (const m of src.matchAll(/t\(\s*(?:key|[`'"][^`'"]+[`'"]|[A-Za-z_$][\w$]*)\s*,\s*\{[\s\S]*?\}/g)) {
        const call = m[0].replace(/\s+/g, ' ')
        if (BARE.test(call)) offenders.push(`${name}: ${call.slice(0, 160)}`)
      }
    }
    expect(offenders, 'leftover i18n identifier params must go through finiteText').toEqual([])
  })

  it('leftover toast/confirm identifier interpolations go through finiteText', () => {
    const TOAST_IDENT = /toast\((?:(?!finiteText)[^;\n])*\$\{(?:c|s|svc|it|v|job|task|acct|file)\.(?:name|username|id)/
    const CONFIRM_IDENT = /confirm\(t\((?:(?!finiteText)[^)]*)\b(?:name|id|username|path|label)\s*:\s*(?:svc|task|it|c|acct|detail\.value|uninstallModal|target|dev|peer)\.(?:name|username|id)/
    const offenders = []
    for (const [name, src] of vueFiles()) {
      for (const m of src.matchAll(new RegExp(TOAST_IDENT, 'g'))) {
        offenders.push(`${name}: ${m[0].slice(0, 120)}`)
      }
      for (const m of src.matchAll(new RegExp(CONFIRM_IDENT, 'g'))) {
        offenders.push(`${name}: ${m[0].slice(0, 120)}`)
      }
    }
    expect(offenders, 'leftover toast/confirm identifier interpolations must go through finiteText').toEqual([])
  })

  it('leftover :title/:aria-label interpolations go through finiteText', () => {
    const ATTR = /(?::title|:aria-label)="(?![^"]*(?:finiteText|t\())[^"]*\.(?:name|id|username|path|status|label|detail|protocol|ip|mac|url|conf|file|image|ports|pubkey|command|program|restore|source|error)"/g
    const offenders = []
    for (const [name, src] of vueFiles()) {
      const template = src.slice(0, src.search(/<script\b/) >>> 0)
      for (const m of template.matchAll(ATTR)) {
        offenders.push(`${name}: ${m[0]}`)
      }
    }
    expect(offenders, 'leftover :title/:aria-label Infinity must go through finiteText').toEqual([])
    const dash = readFileSync(resolve(SRC, 'views/Dashboard.vue'), 'utf8')
    expect(dash).toMatch(/finiteText\(first\?\.name, ''\)/)
    expect(dash).toMatch(/const url = finiteText\(o\.url, ''\)/)
    expect(dash).toMatch(/finiteText\(ollamaTooltip\.value, ''\) \|\| 'http:\/\/127\.0\.0\.1:11434'/)
    expect(dash).toMatch(/finiteText\(ollama\.value\?\.url, ''\) \|\| 'http:\/\/127\.0\.0\.1:11434'/)
  })

  it('LoadFailure leftover message/detail go through finiteText', () => {
    const fail = readFileSync(resolve(SRC, 'components/LoadFailure.vue'), 'utf8')
    expect(fail).toMatch(/from ['"][^'"]*lib\/finite/)
    expect(fail).not.toMatch(/\{\{\s*message\s*\}\}/)
    expect(fail).toMatch(/finiteText\(message, ''\) \|\| t\('common\.load_failed'\)/)
    expect(fail).not.toMatch(/\{\{\s*detail\s*\}\}/)
    expect(fail).toMatch(/finiteText\(detail\)/)
  })

  it('leftover template array joins map finiteText per element', () => {
    // `finiteText(list.join(', '))` still prints leftover Infinity inside an
    // element. Each joined leftover has to go through finiteText first.
    const BARE_JOIN = /\{\{(?:(?!finiteText|finiteN)[^}])*\.join\s*\(/
    const offenders = []
    for (const [name, src] of vueFiles()) {
      const template = src.slice(0, src.search(/<script\b/) >>> 0)
      for (const m of template.matchAll(/\{\{[\s\S]*?\}\}/g)) {
        const interp = m[0].replace(/\s+/g, ' ').trim()
        if (BARE_JOIN.test(interp)) offenders.push(`${name}: ${interp}`)
      }
    }
    expect(offenders, 'leftover .join interpolations must map finiteText per element').toEqual([])
  })

  it('leftover document.title and hostname interpolations reject Infinity', () => {
    const indexHtml = readFileSync(resolve(SRC, '../../index.html'), 'utf8')
    expect(indexHtml).not.toMatch(/document\.title=\(c\.down\?`🔴\$\{c\.down\}/)
    expect(indexHtml).toMatch(/document\.title=\(num\(c\.down,0\)>0\?`🔴\$\{num\(c\.down/)
    expect(indexHtml).not.toMatch(/\$\{c\.ok\} 正常/)
    expect(indexHtml).toMatch(/num\(c\.ok,"\?"\)/)
    const vms = readFileSync(resolve(SRC, 'views/VMs.vue'), 'utf8')
    const apps = readFileSync(resolve(SRC, 'views/Apps.vue'), 'utf8')
    const dash = readFileSync(resolve(SRC, 'views/Dashboard.vue'), 'utf8')
    const settings = readFileSync(resolve(SRC, 'views/Settings.vue'), 'utf8')
    expect(vms).toMatch(/finiteText\(recGet\(data.value, 'host_ip'\), ''\)/)
    expect(apps).toMatch(/finiteText\(recGet\(managed.value, 'host_ip'\), ''\)/)
    expect(dash).toMatch(/finiteText\(host\?\.hostname/)
    expect(settings).toMatch(/finiteText\(identity\?\.hostname/)
    expect(settings).toMatch(/finiteText\(host\?\.hostname/)
  })

  it('keeps MainArray unknown-status leftover composition', () => {
    const main = readFileSync(resolve(SRC, 'views/MainArray.vue'), 'utf8')
    expect(main).toContain("finiteText(data?.array?.status, '') || t('network.unknown')")
  })
})

describe('Users and Account leftover a11y', () => {
  it('keeps both Users resource pickers keyboard-reachable and named', () => {
    // Both copies (create form + row editor) cap at 220px and scroll; a
    // scrollable region a keyboard cannot reach cannot be scrolled by one
    // (WCAG 2.1.1) — the Tools log-box treatment.
    const users = readFileSync(resolve(SRC, 'views/Users.vue'), 'utf8')
    const pickers = users.match(
      /class="resource-picker" tabindex="0" role="region" :aria-label="t\('accounts\.resources'\)"/g,
    ) || []
    expect(pickers.length).toBe(2)
  })

  it('renders the Users accounts reload failure above the stale rows with retries', () => {
    // The empty-row alert only exists while the table is empty; once rows were
    // on screen a failed re-load surfaced nowhere (loadAccounts never toasts).
    const users = readFileSync(resolve(SRC, 'views/Users.vue'), 'utf8')
    expect(users).toMatch(/<LoadFailure\s+v-if="accountsError && asArray\(accounts\)\.length"/)
    // Both inline failure spots offer a non-submitting retry.
    expect(users).toMatch(/v-if="accountsError"[^>]*type="button" @click="loadAccounts"/)
    const retries = users.match(
      /v-if="serviceOptionsError"[^>]*type="button" @click="loadServiceOptions"/g,
    ) || []
    expect(retries.length).toBe(2)
  })

  it('labels and announces the Users toolbar counts', () => {
    // "12 · 3 Admins" left the total unlabeled, and Refresh updated both
    // numbers silently for a screen reader (Tools ports pattern).
    const users = readFileSync(resolve(SRC, 'views/Users.vue'), 'utf8')
    expect(users).toMatch(
      /<span class="meta"[^>]*v-if="data" role="status">\s*\{\{ finiteN\(recGet\(data, 'count'\)\) \}\} \{\{ t\('users\.total'\) \}\}/,
    )
  })

  it('marks the Users admin LED as decoration', () => {
    // The LED repeats the Role badge's Admin/Standard text in colour only
    // (same as the Gateway and VMs LEDs).
    const users = readFileSync(resolve(SRC, 'views/Users.vue'), 'utf8')
    expect(users).toMatch(/class="led" :class="recGet\(u, 'admin'\) \? 'on' : 'off'" aria-hidden="true"/)
  })

  it('hides the Account enrollment QR and voices the password rule', () => {
    const account = readFileSync(resolve(SRC, 'views/Account.vue'), 'utf8')
    // A duplicate of the manual-entry secret; an anonymous graphic otherwise
    // (same as the WireGuard peer QR).
    expect(account).toMatch(/class="twofa-qr" aria-hidden="true"/)
    // The identical enrollment QR on the Settings panel tab gets the same
    // treatment; its manual-entry secret also sits right below.
    const settings = readFileSync(resolve(SRC, 'views/Settings.vue'), 'utf8')
    expect(settings).toMatch(/class="twofa-qr" aria-hidden="true"/)
    // The Update button disables with no spoken reason; the hint carries it.
    expect(account).toMatch(/:class="\{ bad: !!passwordMessage \}" role="status"/)
    // The 2FA card's pending state is a status region, like the Settings
    // launcher placeholder.
    expect(account).toMatch(/v-else-if="!twofa" class="hint" role="status"/)
  })

  it('voices the Login loading placeholder', () => {
    const login = readFileSync(resolve(SRC, 'views/Login.vue'), 'utf8')
    // The auth-status probe decides which form renders; the placeholder
    // swap was silent for a screen reader (Account 2FA-card pattern).
    expect(login).toMatch(/v-if="loading" class="login-loading" role="status"/)
  })
})
