import { beforeEach, describe, expect, it, vi } from 'vitest'
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

function overview(wstunnel) {
  return {
    ts: '20:00:00',
    interfaces: [],
    services: [],
    listening: [],
    routes: [],
    default_route: { gateway: '192.168.1.1', interface: 'en7' },
    docker_ports: [],
    docker_networks: [],
    interface_addresses: [],
    hardware_ports: [],
    wstunnel,
  }
}

async function mountNetwork(wstunnel) {
  api.getSystemNetwork.mockResolvedValue(overview(wstunnel))
  const toast = vi.fn()
  const wrapper = mount(Network, {
    global: {
      provide: { toast },
      stubs: { RouterLink: { template: '<a class="router-link-stub"><slot /></a>' } },
    },
  })
  await flushPromises()
  return wrapper
}

describe('Network wstunnel tile', () => {
  beforeEach(() => {
    for (const fn of Object.values(api)) {
      if (typeof fn?.mockReset === 'function') fn.mockReset()
    }
  })

  it('stays off the page when obfuscation was never turned on', async () => {
    const wrapper = await mountNetwork({
      enabled: false, configured: false, running: false,
    })
    expect(wrapper.text()).not.toContain('network.wstunnel_title')
  })

  it('shows the live layout and the LAN-address warning', async () => {
    const wrapper = await mountNetwork({
      enabled: true,
      configured: true,
      running: true,
      listen: 'ws://0.0.0.0:8444',
      public: 'ws://elvin.top:8444',
      restrict_to: '192.168.1.206:51821',
      stable_restrict: false,
      stale_restrict: false,
      aligned: true,
      client_command: 'wstunnel client -L udp://127.0.0.1:51821:192.168.1.206:51821 ws://elvin.top:8444',
    })
    expect(wrapper.text()).toContain('network.wstunnel_title')
    expect(wrapper.text()).toContain('ws://0.0.0.0:8444')
    expect(wrapper.text()).toContain('192.168.1.206:51821')
    expect(wrapper.text()).toContain('wg.wstunnel_unstable')
    expect(wrapper.text()).toContain('network.wstunnel_open')
  })
})
