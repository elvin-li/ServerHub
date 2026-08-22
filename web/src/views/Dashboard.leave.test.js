/**
 * Dashboard service actions and copies that finish after leave must not toast.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'

const api = vi.hoisted(() => ({
  doAction: vi.fn(),
  getAlerts: vi.fn(),
  getBookmarks: vi.fn(),
  getContainers: vi.fn(),
  getHealthChecks: vi.fn(),
  getHost: vi.fn(),
  getListeningPorts: vi.fn(),
  getMetricsRange: vi.fn(),
  getOllamaStatus: vi.fn(),
  getPower: vi.fn(),
  getSensors: vi.fn(),
  getStatus: vi.fn(),
  getStorage: vi.fn(),
  getUps: vi.fn(),
  powerAction: vi.fn(),
  setSystemSharing: vi.fn(),
}))

const clipboard = vi.hoisted(() => ({
  copyToClipboard: vi.fn(),
}))

vi.mock('../api/client', () => api)
vi.mock('../lib/clipboard', () => clipboard)
vi.mock('../lib/poll', () => ({ startVisibleInterval: () => () => {} }))
vi.mock('../i18n', () => ({
  injectI18n: () => ({
    t: (key, params = {}) => Object.entries(params).reduce(
      (text, [name, value]) => text.replace(`{${name}}`, value),
      String(key),
    ),
    errText: (v) => String(v),
  }),
}))

import Dashboard from './Dashboard.vue'

function button(wrapper, text) {
  const found = wrapper.findAll('button').find((candidate) => candidate.text() === text)
  expect(found, `button ${text}`).toBeTruthy()
  return found
}

async function mountDash(toast = vi.fn()) {
  const wrapper = mount(Dashboard, {
    global: {
      provide: { toast },
      stubs: {
        RouterLink: { template: '<a class="router-link-stub"><slot /></a>' },
        LineChart: true,
        StackBar: true,
      },
    },
  })
  await flushPromises()
  await flushPromises()
  return { wrapper, toast }
}

beforeEach(() => {
  api.getAlerts.mockResolvedValue({ alerts: [] })
  api.getBookmarks.mockResolvedValue({ bookmarks: [] })
  api.getContainers.mockResolvedValue({ containers: [], stats: {} })
  api.getHealthChecks.mockResolvedValue({ summary: { ok: 0, warn: 0, error: 0 }, checks: [] })
  api.getHost.mockResolvedValue({ hostname: 'test-host', ncpu: 8 })
  api.getListeningPorts.mockResolvedValue({ ports: [] })
  api.getMetricsRange.mockResolvedValue({ points: [], tier: 'raw', since: 0, until: 1 })
  api.getOllamaStatus.mockResolvedValue({ installed: false, reachable: false, url: 'http://127.0.0.1:11434' })
  api.getPower.mockResolvedValue({
    screen_sharing: { running: true, vnc_url: 'vnc://192.0.2.10:5900' },
  })
  api.getSensors.mockResolvedValue({ cpu: {}, memory: {}, network: {} })
  api.getStatus.mockResolvedValue({
    groups: [
      {
        group: 'Apps',
        services: [
          {
            id: 'nginx',
            name: 'Nginx',
            state: 'down',
            detail: 'exited',
            actions: ['start', 'restart'],
          },
        ],
      },
    ],
  })
  api.getStorage.mockResolvedValue({ volumes: [], disks: [] })
  api.getUps.mockResolvedValue({ present: false })
  clipboard.copyToClipboard.mockResolvedValue(true)
})

afterEach(() => {
  vi.clearAllMocks()
  vi.unstubAllGlobals()
})

describe('Dashboard leave-guards', () => {
  it('loads light sensors on the low-mode heavy tick', async () => {
    await mountDash()
    expect(api.getSensors).toHaveBeenCalledWith(false, { light: true })
  })

  it('loads full sensors on the high-mode heavy tick', async () => {
    api.getStatus.mockResolvedValue({ resource_mode: 'high', groups: [] })
    await mountDash()
    expect(api.getSensors).toHaveBeenCalledWith(false, { light: false })
  })

  it('does not toast a service start that returns after leave', async () => {
    let resolveAct
    api.doAction.mockImplementation(() => new Promise((resolve) => { resolveAct = resolve }))
    const { wrapper, toast } = await mountDash()
    await button(wrapper, 'dashboard.act_start').trigger('click')
    wrapper.unmount()
    resolveAct({ ok: true, message: 'started' })
    await flushPromises()
    expect(toast).not.toHaveBeenCalled()
  })

  it('does not toast a VNC copy that returns after leave', async () => {
    let resolveCopy
    clipboard.copyToClipboard.mockImplementation(() => new Promise((resolve) => { resolveCopy = resolve }))
    const { wrapper, toast } = await mountDash()
    await wrapper.get('[aria-label="power.copy"]').trigger('click')
    wrapper.unmount()
    resolveCopy(true)
    await flushPromises()
    expect(toast).not.toHaveBeenCalled()
  })

  it('does not toast an Ollama API copy that returns after leave', async () => {
    let resolveCopy
    clipboard.copyToClipboard.mockImplementation(() => new Promise((resolve) => { resolveCopy = resolve }))
    const { wrapper, toast } = await mountDash()
    await wrapper.get('[data-test="ollama-api-copy"]').trigger('click')
    wrapper.unmount()
    resolveCopy(true)
    await flushPromises()
    expect(toast).not.toHaveBeenCalled()
  })

  it('does not toast a power action that returns after leave', async () => {
    vi.stubGlobal('confirm', () => true)
    let resolvePower
    api.powerAction.mockImplementation(() => new Promise((resolve) => { resolvePower = resolve }))
    const { wrapper, toast } = await mountDash()
    await wrapper.get('[aria-label="power.sleep"]').trigger('click')
    wrapper.unmount()
    resolvePower({ ok: true, message: 'sleeping' })
    await flushPromises()
    expect(toast).not.toHaveBeenCalled()
  })

  it('does not toast a screen-sharing toggle that returns after leave', async () => {
    vi.stubGlobal('confirm', () => true)
    let resolveShare
    api.setSystemSharing.mockImplementation(() => new Promise((resolve) => { resolveShare = resolve }))
    const { wrapper, toast } = await mountDash()
    await wrapper.get('[aria-label="power.disable_ss"]').trigger('click')
    wrapper.unmount()
    resolveShare({ ok: true, message: 'stopped' })
    await flushPromises()
    expect(toast).not.toHaveBeenCalled()
  })
})
