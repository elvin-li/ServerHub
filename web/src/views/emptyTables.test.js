/**
 * A table that comes back empty must say so, not render a bare header.
 *
 * Every other list in the panel does: a `<tr v-if="!rows.length">` with a
 * one-line explanation, or a `.placeholder` in place of the table.  Four did
 * not -- the Network page's service order, DNS-per-service and route tables,
 * and the Tools page's LaunchAgent list -- so a host where `networksetup`
 * reports nothing showed column headings above nothing at all.  That reads as
 * "still loading" rather than "there is nothing here", and the *failure* case
 * read as nothing whatsoever: the services error the backend already returns
 * had no row to be printed in, on the very tab the page opens on.
 *
 * Mounted rather than pattern-matched on the source, because what matters is
 * what renders: plenty of tables here are bare in the markup and covered by a
 * `v-if` on an ancestor, and a source rule cannot tell those apart from a real
 * gap without an allow-list that would rot.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { readFileSync, readdirSync } from 'node:fs'
import { resolve } from 'node:path'

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
    t: (key) => key,
    errText: (v) => String(v),
    locale: { value: 'en' },
  }),
}))

import Network from './Network.vue'

const MOUNT = {
  global: {
    provide: { toast: vi.fn() },
    stubs: { RouterLink: { template: '<a><slot /></a>' } },
  },
}

/** Column headings of every rendered table that has a head and no body rows. */
function headerOnlyTables(wrapper) {
  const bare = []
  for (const table of wrapper.element.querySelectorAll('table')) {
    if (!table.querySelector('thead tr')) continue
    if (table.querySelector('tbody tr')) continue
    bare.push([...table.querySelectorAll('thead th')].map((th) => th.textContent.trim()).join(' | '))
  }
  return bare
}

/** A well-formed overview that simply has nothing in it. */
function emptyOverview(extra = {}) {
  return {
    ts: '20:00:00',
    interfaces: [],
    services: [],
    listening: [],
    routes: [],
    default_route: {},
    docker_ports: [],
    docker_networks: [],
    interface_addresses: [],
    hardware_ports: [],
    wifi_power: null,
    ...extra,
  }
}

const TABS = ['switch', 'ifaces', 'ip', 'dns', 'ports', 'routes', 'docker']

beforeEach(() => {
  for (const fn of Object.values(api)) {
    if (typeof fn?.mockReset === 'function') fn.mockReset()
  }
  api.getSystemNetwork.mockResolvedValue(emptyOverview())
})

afterEach(() => {
  vi.clearAllMocks()
})

describe('empty tables', () => {
  it('explains every empty Network tab instead of showing a bare header', async () => {
    const wrapper = mount(Network, MOUNT)
    await flushPromises()
    const bare = {}
    for (const tab of TABS) {
      wrapper.vm.tab = tab
      await flushPromises()
      const found = headerOnlyTables(wrapper)
      if (found.length) bare[tab] = found
    }
    wrapper.unmount()
    expect(bare, 'headings with no rows under them read as still-loading').toEqual({})
  })

  it('prints the services error in the table it emptied', async () => {
    api.getSystemNetwork.mockResolvedValue(
      emptyOverview({ services_error: 'could not read network services' }),
    )
    const wrapper = mount(Network, MOUNT)
    await flushPromises()
    // The service-order table is the first thing the page shows, and why it is
    // empty is the only useful thing to put in it.
    expect(wrapper.find('tbody').text()).toContain('could not read network services')
    wrapper.unmount()
  })

  it('tells a filtered listening list apart from an empty one', async () => {
    api.getSystemNetwork.mockResolvedValue(emptyOverview({
      listening: [{ process: 'nginx', pid: 12, user: 'root', address: '*', port: 80 }],
    }))
    const wrapper = mount(Network, MOUNT)
    await flushPromises()
    wrapper.vm.tab = 'ports'
    await flushPromises()
    expect(wrapper.find('tbody').text()).toContain('nginx')

    wrapper.vm.portQ = 'no-such-process'
    await flushPromises()
    const body = wrapper.find('tbody').text()
    expect(body).toContain('common.no_match')
    expect(body).not.toContain('network.no_listening')
    wrapper.unmount()
  })

  it('does not call an API failure an empty Docker network list', async () => {
    api.getSystemNetwork.mockRejectedValue(new Error('engine listing timed out'))
    const wrapper = mount(Network, MOUNT)
    await flushPromises()
    wrapper.vm.tab = 'docker'
    await flushPromises()
    expect(wrapper.text()).toContain('engine listing timed out')
    expect(wrapper.text()).not.toContain('network.empty_docker_nets')
    wrapper.unmount()
  })
})

describe('empty-row class', () => {
  it('styles empty table cells through the shared empty-row class', () => {
    // Inline color:var(--sub) on colspan cells skipped the hover-exempt
    // empty-row rule in styles.css and drifted from Network/Services.
    const dir = resolve(__dirname)
    const offenders = []
    for (const f of readdirSync(dir)) {
      if (!f.endsWith('.vue')) continue
      const src = readFileSync(resolve(dir, f), 'utf8')
      const template = src.slice(0, src.search(/<script\b/) >>> 0)
      for (const m of template.matchAll(/<td\b[^>]*colspan="\d+"[^>]*>/g)) {
        const tag = m[0]
        if (!/style="[^"]*color:var\(--sub\)/.test(tag)) continue
        offenders.push(`${f}: ${tag}`)
      }
    }
    expect(offenders, 'empty cells should use class="empty-row"').toEqual([])
  })

  it('styles Dashboard member empty/loading tiles through .sub, not inline --sub', () => {
    const src = readFileSync(resolve(__dirname, 'Dashboard.vue'), 'utf8')
    const template = src.slice(0, src.search(/<script\b/) >>> 0)
    expect(template).not.toMatch(/class="tile"[^>]*style="color:var\(--sub\)"/)
    expect(template).toMatch(/class="tile sub"/)
  })
})

