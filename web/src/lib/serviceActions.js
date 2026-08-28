/**
 * Single source of truth for what a service entry offers in the UI.
 *
 * Services.vue renders the same service three ways — dense table row, card,
 * detail drawer — and each used to carry its own copy of these predicates.
 * They live here so the offers cannot drift apart again;
 * components/ServiceActions.vue consumes them for all three renderings.
 *
 * Everything in this module is pure: no Vue, no i18n instance, no API calls.
 * Label helpers take `t` from the caller so the maps stay single-sourced
 * without binding this module to a component lifecycle.
 */

import { asArray, finiteText } from './finite'

/** Verbs that mutate service state (as opposed to open/logs/detail). */
const CONTROL_ACTS = new Set(['start', 'stop', 'restart', 'run', 'pause', 'unpause', 'remove', 'kill'])

/** Render order for control buttons in the full-width renderings. */
const ACT_ORDER = ['start', 'stop', 'restart', 'run', 'pause', 'unpause']

/**
 * Whether the backend can perform `act` on this service.
 *
 * When the server sent an action list it is authoritative: guessing here
 * rendered Start/Stop buttons for entries the backend has no way to control
 * (adopted scripts without commands, auto-discovered ports), and every such
 * click failed.  The state-based fallback survives only for payloads that
 * carry no action list at all (older servers).
 */
export function canAct(s, act) {
  if (!s) return false
  if (s.actions != null && !Array.isArray(s.actions)) return false
  if (asArray(s.actions).includes(act)) return true
  if (Array.isArray(s.actions)) return false
  if (act === 'start' && (s.state === 'down' || s.state === 'stopped')) return true
  if (act === 'stop' && s.state === 'ok') return true
  if (act === 'restart' && s.state === 'ok') return true
  return false
}

/** Ordered control actions for the table row and the drawer. */
export function controlActs(s) {
  return ACT_ORDER.filter((a) => canAct(s, a))
}

/** The card's compact subset: the server's own order, capped at three. */
export function primaryActs(s) {
  return asArray(s.actions).filter((a) => CONTROL_ACTS.has(a)).slice(0, 3)
}

export function canLogs(s) {
  if (!s) return false
  if (s.can_logs === false) return false
  if (s.can_logs === true) return true
  if (asArray(s.actions).includes('logs')) return true
  // A served action list without `logs` is authoritative. Member rows are
  // stripped to open/detail and omit can_logs; guessing from kind painted
  // Logs (and 403'd) for those accounts.
  if (Array.isArray(s.actions) || (s.actions != null && typeof s.actions === 'object')) return false
  return ['container', 'launchd', 'script'].includes(s.kind)
}

export function ledOf(state) {
  if (state === 'ok') return 'on'
  if (state === 'warn') return 'warn'
  if (state === 'stopped') return 'off'
  return 'err'
}

export function stateChipClass(state) {
  if (state === 'ok') return 'chip-ok'
  if (state === 'warn') return 'chip-warn'
  if (state === 'down') return 'chip-down'
  return 'chip-muted'
}

/** Compact port readout: explicit port, numeric ports[], first ports[] entry, or one scraped from the detail line. */
export function portOf(s) {
  const nums = []
  const push = (p) => {
    const n = typeof p === 'number' ? p : (typeof p === 'string' && /^\d+$/.test(p) ? Number(p) : null)
    if (n != null && Number.isFinite(n) && !nums.includes(n)) nums.push(n)
  }
  if (s?.port != null) push(s.port)
  if (Array.isArray(s?.ports)) {
    for (const p of s.ports) push(p)
    if (!nums.length && s.ports.length) {
      const first = s.ports[0]
      if (typeof first === 'number' && !Number.isFinite(first)) return '—'
      if (typeof first === 'object') return JSON.stringify(first)
      return String(finiteText(first))
    }
  }
  if (nums.length) return nums.map((p) => `:${p}`).join(' ')
  const m = String(finiteText(s?.detail, '')).match(/:(\d{2,5})\b/)
  return m ? `:${m[1]}` : '—'
}

/** Recognition payload lives on the row or under meta, depending on the endpoint. */
export function signatureOf(s) {
  return s?.signature || s?.meta?.signature || null
}

const ACT_LABEL_KEYS = {
  start: 'services.act_start',
  stop: 'services.act_stop',
  restart: 'services.act_restart',
  run: 'services.act_run',
  pause: 'services.act_pause',
  unpause: 'services.act_unpause',
}

const KIND_LABEL_KEYS = {
  launchd: 'services.kind_launchd',
  container: 'services.kind_container',
  app: 'services.kind_app',
  'app-engine': 'services.kind_engine',
  script: 'services.kind_script',
  vm: 'services.kind_vm',
  auto: 'services.kind_auto',
}

const STATE_LABEL_KEYS = {
  ok: 'services.state_ok',
  warn: 'services.state_warn',
  down: 'services.state_down',
  stopped: 'services.state_stopped',
}

/** Localised display names, unknown values passed through verbatim. */
export function serviceLabels(t) {
  return {
    actLabel: (a) => (ACT_LABEL_KEYS[a] ? t(ACT_LABEL_KEYS[a]) : finiteText(a)),
    kindLabel: (k) => (KIND_LABEL_KEYS[k] ? t(KIND_LABEL_KEYS[k]) : finiteText(k)),
    stateLabel: (st) => (STATE_LABEL_KEYS[st] ? t(STATE_LABEL_KEYS[st]) : finiteText(st)),
  }
}
