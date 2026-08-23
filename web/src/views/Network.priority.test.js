import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'

const api = vi.hoisted(() => ({
  getSystemNetwork: vi.fn(),
  addNetworkAlias: vi.fn(),
  connectContainerNetwork: vi.fn(),
  lookupNetworkDns: vi.fn(),
  removeNetworkAlias: vi.fn(),
  runAliasAutoBind: vi.fn(),
  runNetworkFailover: vi.fn(),
  setContainerPorts: vi.fn(),
  setNetworkDhcp: vi.fn(),
  setNetworkDns: vi.fn(),
  setNetworkManual: vi.fn(),
  setNetworkServiceEnabled: vi.fn(),
  setNetworkServiceOrder: vi.fn(),
  setWifiPower: vi.fn(),
  switchNetworkProfile: vi.fn(),
  updateAliasAuto: vi.fn(),
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

import Network from './Network.vue'

function overview({ services = [], wifi_power = null } = {}) {
  return {
    ts: '20:00:00',
    interfaces: [],
    services,
    listening: [],
    routes: [],
    default_route: { gateway: '192.168.1.1', interface: 'en7' },
    docker_ports: [],
    docker_networks: [],
    interface_addresses: [],
    hardware_ports: [],
    wifi_power,
  }
}

async function mountNetwork(payload) {
  api.getSystemNetwork.mockResolvedValue(overview(payload))
  const wrapper = mount(Network, {
    global: {
      provide: { toast: vi.fn() },
      stubs: { RouterLink: { template: '<a class="router-link-stub"><slot /></a>' } },
    },
  })
  await flushPromises()
  return wrapper
}

function wifiService(extra = {}) {
  return {
    name: 'Wi-Fi',
    hardware_port: 'Wi-Fi',
    device: 'en0',
    disabled: false,
    mode: 'dhcp',
    ip: '',
    ...extra,
  }
}

function ethernetService(extra = {}) {
  return {
    name: 'USB 10/100/1000 LAN',
    hardware_port: 'USB 10/100/1000 LAN',
    device: 'en7',
    disabled: false,
    mode: 'dhcp',
    ip: '192.168.1.10',
    ...extra,
  }
}

describe('Network service priority status', () => {
  beforeEach(() => {
    for (const fn of Object.values(api)) {
      if (typeof fn?.mockReset === 'function') fn.mockReset()
    }
    vi.stubGlobal('confirm', vi.fn(() => true))
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('shows Wi-Fi as off when the radio is off even if the service is enabled', async () => {
    const wrapper = await mountNetwork({
      services: [wifiService()],
      wifi_power: { ok: true, on: false, device: 'en0', message: 'Off' },
    })
    const row = wrapper.find('tbody tr')
    expect(row.text()).toContain('network.off')
    expect(row.text()).not.toContain('network.on')
    expect(row.text()).not.toContain('network.no_ipv4')
    wrapper.unmount()
  })

  it('shows no IPv4 when the radio is on but the service has no address', async () => {
    const wrapper = await mountNetwork({
      services: [wifiService({ ip: '' })],
      wifi_power: { ok: true, on: true, device: 'en0', message: 'On' },
    })
    const row = wrapper.find('tbody tr')
    expect(row.text()).toContain('network.no_ipv4')
    expect(row.text()).not.toContain('network.on')
    wrapper.unmount()
  })

  it('shows no IPv4 when radio state is unknown and there is no address', async () => {
    const wrapper = await mountNetwork({
      services: [wifiService({ ip: 'none' })],
      wifi_power: { ok: false, on: null, device: 'en0', message: '' },
    })
    const row = wrapper.find('tbody tr')
    expect(row.text()).toContain('network.no_ipv4')
    expect(row.text()).not.toContain('network.on')
    wrapper.unmount()
  })

  it('shows Wi-Fi as on when the radio is on and an address is present', async () => {
    const wrapper = await mountNetwork({
      services: [wifiService({ ip: '10.0.0.8' })],
      wifi_power: { ok: true, on: true, device: 'en0', message: 'On' },
    })
    const row = wrapper.find('tbody tr')
    expect(row.text()).toContain('network.on')
    expect(row.text()).not.toContain('network.no_ipv4')
    wrapper.unmount()
  })

  it('keeps a disabled Wi-Fi service as off even if the radio reports on', async () => {
    const wrapper = await mountNetwork({
      services: [wifiService({ disabled: true, ip: '10.0.0.8' })],
      wifi_power: { ok: true, on: true, device: 'en0', message: 'On' },
    })
    const row = wrapper.find('tbody tr')
    expect(row.text()).toContain('network.off')
    expect(row.text()).not.toContain('network.on')
    wrapper.unmount()
  })

  it('does not apply radio or IPv4 rules to wired rows', async () => {
    const wrapper = await mountNetwork({
      services: [ethernetService({ ip: '' })],
      wifi_power: { ok: true, on: false, device: 'en0', message: 'Off' },
    })
    const row = wrapper.find('tbody tr')
    expect(row.text()).toContain('network.on')
    expect(row.text()).not.toContain('network.no_ipv4')
    expect(row.text()).not.toContain('network.off')
    wrapper.unmount()
  })

  it('exposes radio power buttons on the Wi-Fi priority row', async () => {
    const wrapper = await mountNetwork({
      services: [wifiService(), ethernetService()],
      wifi_power: { ok: true, on: false, device: 'en0', message: 'Off' },
    })
    const rows = wrapper.findAll('tbody tr')
    const wifiRow = rows.find((row) => row.text().includes('Wi-Fi'))
    const wiredRow = rows.find((row) => row.text().includes('USB 10/100/1000 LAN'))
    expect(wifiRow.findAll('button').map((b) => b.text())).toEqual(
      expect.arrayContaining(['network.wifi_on', 'network.wifi_off']),
    )
    expect(wiredRow.findAll('button').map((b) => b.text())).not.toEqual(
      expect.arrayContaining(['network.wifi_on', 'network.wifi_off']),
    )
    wrapper.unmount()
  })
})
