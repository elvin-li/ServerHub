/**
 * Contract for the single source of truth behind service action rendering.
 *
 * Services.vue's table rows, cards and drawer all derive their buttons from
 * this module; what regressed historically was each surface carrying its own
 * copy of these predicates and drifting (cards offering actions the table did
 * not, fallback guesses rendering Start for entries the backend cannot
 * control). These tests pin the shared behaviour.
 */
import { describe, expect, it } from 'vitest'
import {
  canAct,
  canLogs,
  controlActs,
  ledOf,
  portOf,
  primaryActs,
  serviceLabels,
  stateChipClass,
} from './serviceActions'

// Realistic /api/services rows: the backend always sends an `actions` list
// (enrich_service_list_item appends at least "detail").
const runningContainer = {
  id: 'jellyfin', kind: 'container', state: 'ok',
  actions: ['restart', 'stop', 'pause', 'logs', 'open', 'detail'],
  url: 'http://nas:8096',
}
const downLaunchd = {
  id: 'com.example.sync', kind: 'launchd', state: 'down',
  actions: ['start', 'logs', 'detail'],
}
const adoptedPort = {
  id: 'auto:8080', kind: 'auto', state: 'ok',
  actions: ['detail'],
}

describe('canAct', () => {
  it('treats a served action list as authoritative', () => {
    expect(canAct(runningContainer, 'stop')).toBe(true)
    expect(canAct(runningContainer, 'restart')).toBe(true)
    expect(canAct(runningContainer, 'start')).toBe(false)
    // An ok-state entry whose list offers nothing gets no guesses: this is the
    // adopted-script case where every guessed click failed.
    expect(canAct(adoptedPort, 'stop')).toBe(false)
    expect(canAct(adoptedPort, 'restart')).toBe(false)
  })

  it('falls back to state-based guesses only when no list was sent at all', () => {
    const legacyOk = { id: 'x', kind: 'app', state: 'ok' }
    const legacyDown = { id: 'y', kind: 'app', state: 'down' }
    expect(canAct(legacyOk, 'stop')).toBe(true)
    expect(canAct(legacyOk, 'restart')).toBe(true)
    expect(canAct(legacyOk, 'start')).toBe(false)
    expect(canAct(legacyDown, 'start')).toBe(true)
    expect(canAct(legacyDown, 'stop')).toBe(false)
    expect(canAct(null, 'start')).toBe(false)
  })
})

describe('table and card offers agree', () => {
  // The card renders primaryActs, the table renders controlActs. For any row
  // the backend actually serves (an action list is always present), the two
  // surfaces must offer the same set; only order and the card's three-button
  // cap may differ.
  const fixtures = [runningContainer, downLaunchd, adoptedPort]

  it('offer the identical action set for the same service', () => {
    for (const s of fixtures) {
      expect(new Set(primaryActs(s)), s.id).toEqual(new Set(controlActs(s)))
    }
  })

  it('keeps the table in canonical order and the card in server order, capped at three', () => {
    expect(controlActs(runningContainer)).toEqual(['stop', 'restart', 'pause'])
    expect(primaryActs(runningContainer)).toEqual(['restart', 'stop', 'pause'])
    const busyRow = { ...runningContainer, actions: ['unpause', 'run', 'restart', 'stop', 'logs'] }
    expect(primaryActs(busyRow)).toEqual(['unpause', 'run', 'restart'])
    expect(controlActs(busyRow)).toEqual(['stop', 'restart', 'run', 'unpause'])
  })
})

describe('canLogs', () => {
  it('respects an explicit can_logs refusal above everything else', () => {
    expect(canLogs({ kind: 'container', actions: ['logs'], can_logs: false })).toBe(false)
  })

  it('accepts a served logs action, then falls back to the kind whitelist', () => {
    expect(canLogs({ kind: 'vm', actions: ['logs'] })).toBe(true)
    expect(canLogs({ kind: 'launchd', actions: [] })).toBe(true)
    expect(canLogs({ kind: 'vm', actions: [] })).toBe(false)
    expect(canLogs(null)).toBe(false)
  })
})

describe('formatters', () => {
  it('reads the port from the field, the ports list, or the detail line', () => {
    expect(portOf({ port: 8096 })).toBe(':8096')
    expect(portOf({ port: 6379, ports: [6379, 6380] })).toBe(':6379 :6380')
    expect(portOf({ ports: ['0.0.0.0:80->80/tcp'] })).toBe('0.0.0.0:80->80/tcp')
    expect(portOf({ ports: [{ port: 53 }] })).toBe('{"port":53}')
    expect(portOf({ detail: 'listening on :8443 ok' })).toBe(':8443')
    expect(portOf({ detail: 'no port here' })).toBe('—')
  })

  it('maps states onto LED and chip classes', () => {
    expect(ledOf('ok')).toBe('on')
    expect(ledOf('warn')).toBe('warn')
    expect(ledOf('stopped')).toBe('off')
    expect(ledOf('down')).toBe('err')
    expect(stateChipClass('ok')).toBe('chip-ok')
    expect(stateChipClass('down')).toBe('chip-down')
    expect(stateChipClass('anything-else')).toBe('chip-muted')
  })

  it('resolves labels through t and passes unknown values through', () => {
    const t = (k) => `L:${k}`
    const { actLabel, kindLabel, stateLabel } = serviceLabels(t)
    expect(actLabel('start')).toBe('L:services.act_start')
    expect(actLabel('frobnicate')).toBe('frobnicate')
    expect(kindLabel('launchd')).toBe('L:services.kind_launchd')
    expect(kindLabel('weird-kind')).toBe('weird-kind')
    expect(kindLabel('')).toBe('—')
    expect(stateLabel('warn')).toBe('L:services.state_warn')
    expect(stateLabel(undefined)).toBe('—')
  })
})
