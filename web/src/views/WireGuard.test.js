import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'

// The whole point of this file: nothing mounted WireGuard.vue, so a runtime error
// in it (a bad default import, a missing helper, a throw during setup) shipped
// silently — the a11y suite only reads the source statically.
const api = vi.hoisted(() => ({
  getWireguard: vi.fn(),
  getWireguardReadiness: vi.fn(),
  getWireguardSettings: vi.fn(),
  getWireguardNextIp: vi.fn(),
  getWireguardConf: vi.fn(),
  getWireguardPeerConfig: vi.fn(),
  addWireguardPeer: vi.fn(),
  batchAddWireguardPeers: vi.fn(),
  deleteWireguardPeer: vi.fn(),
  importWireguardPeer: vi.fn(),
  setWireguardPsk: vi.fn(),
  controlWireguardInterface: vi.fn(),
  syncWireguard: vi.fn(),
  pingWireguardPeers: vi.fn(),
  putWireguardSettings: vi.fn(),
  setWireguardForwarding: vi.fn(),
  remediateWireguard: vi.fn(),
  wireguardPeerDownloadUrl: vi.fn(() => '/download'),
}))
vi.mock('../api/client', () => api)
vi.mock('../i18n', () => ({
  injectI18n: () => ({
    t: (key, params = {}) => Object.entries(params).reduce(
      (text, [name, value]) => text.replace(`{${name}}`, value),
      key,
    ),
  }),
}))
vi.mock('../lib/poll', () => ({ startVisibleInterval: () => () => {} }))

import WireGuard from './WireGuard.vue'

function status(overrides = {}) {
  return {
    ts: '2026-08-05 12:00:00',
    installed: true,
    install: { installed: true, tools_version: 'wireguard-tools v1.0' },
    interface: 'wg0',
    running: false,
    state_error: '',
    listen_port: 51821,
    public_key: 'Orpt/ZFGi6y2QTZ/fGd+iW0ZAHvZzIGbN5yLkcOnth0=',
    address: '10.10.0.1/24',
    subnet: '10.10.0.0/24',
    mtu: 1280,
    dns: '1.1.1.1',
    endpoint: '',
    peers: [],
    peer_count: 0,
    active_count: 0,
    stale_count: 0,
    keepalive_missing: 0,
    unknown_count: 0,
    reissuable_count: 0,
    ...overrides,
  }
}

function readiness(overrides = {}) {
  return {
    checks: [
      { id: 'installed', ok: true, level: 'error', detail: 'v1.0' },
      { id: 'endpoint', ok: false, level: 'error', detail: '' },
      { id: 'forwarding', ok: false, level: 'error', detail: 'net.inet.ip.forwarding' },
      { id: 'nat', ok: false, level: 'error', detail: '/etc/pf.anchors/x -> en0' },
    ],
    ready: false,
    blocking: ['endpoint', 'forwarding', 'nat'],
    warnings: [],
    forwarding: false,
    pf_enabled: false,
    nat: { complete: false },
    daemon: { installed: false },
    peer_origin: { conflict: false, foreign: 0, total: 0 },
    wan_interface: 'en0',
    endpoint: '',
    ...overrides,
  }
}

async function mountView(overrides = {}, readyOverrides = {}) {
  api.getWireguard.mockResolvedValue(status(overrides))
  api.getWireguardReadiness.mockResolvedValue(readiness(readyOverrides))
  api.getWireguardSettings.mockResolvedValue({ settings: { subnet: '10.10.0.0/24' } })
  api.getWireguardNextIp.mockResolvedValue({ next_ip: '10.10.0.2/32' })
  const toast = vi.fn()
  const wrapper = mount(WireGuard, { global: { provide: { toast } } })
  await flushPromises()
  return { wrapper, toast }
}

describe('WireGuard page', () => {
  beforeEach(() => {
    for (const fn of Object.values(api)) {
      if (typeof fn?.mockReset === 'function') fn.mockReset()
    }
    api.wireguardPeerDownloadUrl.mockReturnValue('/download')
  })

  it('mounts without throwing and renders the server card', async () => {
    const { wrapper, toast } = await mountView()
    expect(wrapper.text()).toContain('51821')
    expect(wrapper.text()).toContain('10.10.0.1/24')
    // A thrown setup error surfaces as an error toast rather than a mount failure.
    expect(toast).not.toHaveBeenCalled()
  })

  it('surfaces blocking readiness gaps instead of claiming the tunnel works', async () => {
    const { wrapper } = await mountView()
    expect(wrapper.text()).toContain('wg.not_ready')
    expect(wrapper.text()).toContain('wg.check_forwarding')
    expect(wrapper.text()).toContain('wg.check_nat')
  })

  it('tells the operator when wireguard-tools is absent', async () => {
    const { wrapper } = await mountView({ installed: false, install: { installed: false } })
    expect(wrapper.text()).toContain('wg.not_installed_title')
  })

  it('renders a peer row with traffic and handshake state', async () => {
    const { wrapper } = await mountView({
      running: true,
      peer_count: 1,
      active_count: 1,
      peers: [{
        pubkey: 'cwhX5s68aveCxaGMuNhXhxCyyMV4qhWPiYZwjrZ1nis=',
        name: 'phone', mode: 'split', allowed_ips: '10.10.0.2/32',
        endpoint: '203.0.113.9:2854', last_handshake: 1785834615,
        handshake_age: 42, active: true, stale: false, keepalive: '25',
        psk: false, rx: 1024, tx: 2048, rx_human: '1.0K', tx_human: '2.0K',
        reissuable: true, known: true,
      }],
    })
    expect(wrapper.text()).toContain('phone')
    expect(wrapper.text()).toContain('10.10.0.2/32')
    expect(wrapper.text()).toContain('2.0K')
  })

  it('flags peers copied from another server', async () => {
    const { wrapper } = await mountView({}, {
      peer_origin: { conflict: true, foreign: 5, total: 5, foreign_keys: [] },
    })
    expect(wrapper.text()).toContain('wg.foreign_peers_title')
  })

  it('creates a peer and shows its config', async () => {
    const { wrapper } = await mountView()
    api.addWireguardPeer.mockResolvedValue({
      ok: true, name: 'laptop', ip: '10.10.0.3/32', pub: 'PUB=',
      mode: 'split', psk: '', client_conf: '[Interface]\nPrivateKey = x\n',
      reissuable: true, applied: false, endpoint_configured: true,
    })
    vi.spyOn(window, 'confirm').mockReturnValue(true)

    const inputs = wrapper.findAll('input[type="text"]')
    await inputs[0].setValue('laptop')
    const createBtn = wrapper.findAll('button').find((b) => b.text() === 'wg.create')
    await createBtn.trigger('click')
    await flushPromises()

    expect(api.addWireguardPeer).toHaveBeenCalled()
    expect(wrapper.text()).toContain('[Interface]')
  })
})

describe('WireGuard readiness table', () => {
  beforeEach(() => {
    for (const fn of Object.values(api)) {
      if (typeof fn?.mockReset === 'function') fn.mockReset()
    }
    api.wireguardPeerDownloadUrl.mockReturnValue('/download')
  })

  /** Rows in the blocking-gaps table, by the check label each one renders. */
  function blockingRows(wrapper) {
    const table = wrapper.findAll('table.dense')[0]
    if (!table) return []
    return table.findAll('tbody tr').map((row) => row.findAll('td')[1]?.text() ?? '')
  }

  it('renders one row per problem, not one per check that mentions it', async () => {
    // Several gates sit downstream of one another: NAT cannot load out of a
    // pf.conf pf refuses, and an endpoint cannot resolve correctly if none is
    // set. The server suppresses the downstream check; the page must therefore
    // never receive -- or render -- two rows saying the same thing.
    const { wrapper } = await mountView({}, {
      checks: [
        { id: 'installed', ok: true, level: 'error', detail: 'v1.0' },
        { id: 'endpoint', ok: false, level: 'error', detail: '' },
        { id: 'pf_conf', ok: false, level: 'error', detail: '/etc/pf.conf:12: Rules must be in order' },
      ],
      blocking: ['endpoint', 'pf_conf'],
    })
    const rows = blockingRows(wrapper)
    expect(rows).toHaveLength(2)
    expect(new Set(rows).size).toBe(rows.length)
  })

  it('gives every row a label and a remedy rather than a bare id', async () => {
    const { wrapper } = await mountView({}, {
      checks: [
        { id: 'endpoint_resolves', ok: false, level: 'error', detail: 'vpn.example -> 2001:db8::1 (not this host)' },
        { id: 'pf_conf', ok: false, level: 'error', detail: '/etc/pf.conf:12' },
      ],
      blocking: ['endpoint_resolves', 'pf_conf'],
    })
    const text = wrapper.text()
    // Resolved through the explicit label/fix maps, so a new check id added on the
    // server without a translation shows up here rather than on the page.
    for (const key of [
      'wg.check_endpoint_resolves', 'wg.fix_endpoint_resolves',
      'wg.check_pf_conf', 'wg.fix_pf_conf',
    ]) {
      expect(text).toContain(key)
    }
    expect(text).not.toContain('endpoint_resolves ')
  })

  it('offers the same repair action for a broken pf.conf as for a missing NAT rule', async () => {
    // Installing the NAT rule rewrites /etc/pf.conf in the order pf requires,
    // which is exactly what repairs a file pf is currently refusing.
    const { wrapper } = await mountView({}, {
      checks: [{ id: 'pf_conf', ok: false, level: 'error', detail: '/etc/pf.conf:12' }],
      blocking: ['pf_conf'],
    })
    api.remediateWireguard.mockResolvedValue({ ok: true })
    const install = wrapper.findAll('button').find((b) => b.text() === 'wg.install')
    expect(install).toBeTruthy()
    await install.trigger('click')
    await flushPromises()
    expect(api.remediateWireguard).toHaveBeenCalledWith('nat', true)
  })

  it('does not repeat the foreign-peer finding in the table and its own callout', async () => {
    // The callout below explains the situation and names the keys; the table row
    // could only restate it with less room.
    const { wrapper } = await mountView({}, {
      checks: [
        { id: 'peer_origin', ok: false, level: 'error', detail: '5/5 peers from another server' },
        { id: 'pf_conf', ok: false, level: 'error', detail: '/etc/pf.conf:12' },
      ],
      blocking: ['peer_origin', 'pf_conf'],
      peer_origin: { conflict: true, foreign: 5, total: 5, foreign_keys: [] },
    })
    expect(wrapper.text()).toContain('wg.foreign_peers_title')
    expect(blockingRows(wrapper)).toEqual(['wg.check_pf_conf'])
  })

  it('says nothing when every gate is satisfied', async () => {
    const { wrapper } = await mountView({ running: true }, {
      checks: [{ id: 'installed', ok: true, level: 'error', detail: 'v1.0' }],
      ready: true,
      blocking: [],
    })
    expect(wrapper.text()).not.toContain('wg.not_ready')
  })

  it('keeps warnings out of the blocking table', async () => {
    const { wrapper } = await mountView({}, {
      checks: [
        { id: 'pf_conf', ok: false, level: 'error', detail: '/etc/pf.conf:12' },
        { id: 'boot', ok: false, level: 'warn', detail: '/Library/LaunchDaemons/x.plist' },
      ],
      blocking: ['pf_conf'],
      warnings: ['boot'],
    })
    expect(blockingRows(wrapper)).toEqual(['wg.check_pf_conf'])
  })
})

describe('WireGuard non-blocking warnings', () => {
  beforeEach(() => {
    for (const fn of Object.values(api)) {
      if (typeof fn?.mockReset === 'function') fn.mockReset()
    }
    api.wireguardPeerDownloadUrl.mockReturnValue('/download')
  })

  /** Rows in the warnings tile, by the check label each one renders. */
  function warningRows(wrapper) {
    const tile = wrapper.findAll('.tile').find((t) => t.text().includes('wg.warnings'))
    if (!tile) return []
    return tile.findAll('tbody tr').map((row) => row.findAll('td')[1]?.text() ?? '')
  }

  it('shows warn-level checks, which previously rendered nowhere at all', async () => {
    // The server computed these and the page dropped them, so whether the tunnel
    // survives a reboot was information the operator could not see.
    const { wrapper } = await mountView({ running: true }, {
      checks: [
        { id: 'boot', ok: false, level: 'warn', detail: '/Library/LaunchDaemons/x.plist' },
      ],
      ready: true,
      blocking: [],
      warnings: ['boot'],
    })
    expect(warningRows(wrapper)).toEqual(['wg.check_boot'])
    expect(wrapper.text()).toContain('wg.fix_boot')
  })

  it('offers boot persistence, an action the API had and the page could not reach', async () => {
    const { wrapper } = await mountView({ running: true }, {
      checks: [{ id: 'boot', ok: false, level: 'warn', detail: '/x.plist' }],
      ready: true,
      blocking: [],
      warnings: ['boot'],
    })
    api.remediateWireguard.mockResolvedValue({ ok: true })
    const button = wrapper.find('button.wg-fix-boot')
    expect(button.exists()).toBe(true)
    await button.trigger('click')
    await flushPromises()
    expect(api.remediateWireguard).toHaveBeenCalledWith('daemon', true)
  })

  it('does not restate the interface state, which the status bar already carries', async () => {
    const { wrapper } = await mountView({ running: false }, {
      checks: [
        { id: 'running', ok: false, level: 'warn', detail: 'wg0' },
        { id: 'boot', ok: false, level: 'warn', detail: '/x.plist' },
      ],
      ready: true,
      blocking: [],
      warnings: ['running', 'boot'],
    })
    expect(warningRows(wrapper)).toEqual(['wg.check_boot'])
    // Still stated once, by the status bar and its Start button.
    expect(wrapper.text()).toContain('wg.tunnel_stopped')
  })

  it('keeps blocking gaps out of the warnings tile and vice versa', async () => {
    const { wrapper } = await mountView({}, {
      checks: [
        { id: 'endpoint', ok: false, level: 'error', detail: '' },
        { id: 'boot', ok: false, level: 'warn', detail: '/x.plist' },
      ],
      blocking: ['endpoint'],
      warnings: ['boot'],
    })
    expect(warningRows(wrapper)).toEqual(['wg.check_boot'])
    const blocking = wrapper.findAll('table.dense')[0]
    expect(blocking.text()).toContain('wg.check_endpoint')
    expect(blocking.text()).not.toContain('wg.check_boot')
  })

  it('says nothing when there are no warnings', async () => {
    const { wrapper } = await mountView({ running: true }, {
      checks: [{ id: 'installed', ok: true, level: 'error', detail: 'v1.0' }],
      ready: true,
      blocking: [],
      warnings: [],
    })
    expect(wrapper.text()).not.toContain('wg.warnings')
  })

  it('offers to enable pf, since installing the NAT rule is what turns it on', async () => {
    const { wrapper } = await mountView({ running: true }, {
      checks: [{ id: 'pf', ok: false, level: 'warn', detail: 'pfctl status' }],
      ready: true,
      blocking: [],
      warnings: ['pf'],
    })
    api.remediateWireguard.mockResolvedValue({ ok: true })
    const tile = wrapper.findAll('.tile').find((t) => t.text().includes('wg.warnings'))
    const button = tile.findAll('button').find((b) => b.text() === 'wg.enable')
    expect(button).toBeTruthy()
    await button.trigger('click')
    await flushPromises()
    expect(api.remediateWireguard).toHaveBeenCalledWith('nat', true)
  })
})
