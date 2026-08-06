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
