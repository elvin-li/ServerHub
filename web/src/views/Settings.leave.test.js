/**
 * Settings writes that finish after leave must not toast or flip copy flags.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { ref } from 'vue'

const api = vi.hoisted(() => ({
  changeAuthPassword: vi.fn(),
  controlPanelService: vi.fn(),
  createApiKey: vi.fn(),
  forceAlertCheck: vi.fn(),
  getDockerInfo: vi.fn(),
  getHost: vi.fn(),
  getIdentity: vi.fn(),
  getLauncherStatus: vi.fn(),
  getSettings: vi.fn(),
  getSystemSettings: vi.fn(),
  getTotpStatus: vi.fn(),
  getUps: vi.fn(),
  getUpsShutdownPlan: vi.fn(),
  listApiKeys: vi.fn(),
  openLauncherApp: vi.fn(),
  putIdentity: vi.fn(),
  putSettings: vi.fn(),
  setLauncherLogin: vi.fn(),
  testNotify: vi.fn(),
}))

const clipboard = vi.hoisted(() => ({
  copyToClipboard: vi.fn(),
}))

vi.mock('../api/client', () => api)
vi.mock('../lib/clipboard', () => clipboard)
vi.mock('../i18n', () => ({
  injectI18n: () => ({
    t: (key) => key,
    locale: ref('en'),
    locales: [],
    setLocale: vi.fn(),
  }),
}))
vi.mock('../theme', () => ({
  injectTheme: () => ({
    theme: ref('macos'),
    appliedTheme: ref('macos'),
    density: ref('compact'),
    themes: [],
    densities: [],
    followSystem: ref(true),
    setTheme: vi.fn(),
    setFollowSystem: vi.fn(),
    setDensity: vi.fn(),
  }),
}))

import Settings from './Settings.vue'

function settingsPayload() {
  return {
    version: 'test',
    host_ip_config: 'auto',
    paths: {},
    auth: { enabled: true, username: 'admin', has_password: true },
    notify: {},
    thresholds: {},
    ip_aliases: {},
    terminal: {},
  }
}

function button(wrapper, key) {
  const found = wrapper.findAll('button').find((candidate) => candidate.text() === key)
  expect(found, `button ${key}`).toBeTruthy()
  return found
}

async function mountSettings() {
  const toast = vi.fn()
  const wrapper = mount(Settings, {
    global: {
      provide: { toast },
      stubs: {
        RouterLink: { template: '<a><slot /></a>' },
        NotifyChannels: true,
        ServiceSignatures: true,
        GroupRules: true,
        LoadFailure: true,
      },
    },
  })
  await flushPromises()
  return { wrapper, toast }
}

beforeEach(() => {
  api.getSettings.mockResolvedValue(settingsPayload())
  api.getHost.mockResolvedValue({ hostname: 'test-host' })
  api.getIdentity.mockResolvedValue({ computer_name: 'box', comment: '', host_ip_config: 'auto' })
  api.getLauncherStatus.mockResolvedValue({})
  api.getTotpStatus.mockResolvedValue({ enabled: false, recovery_remaining: 0 })
  api.listApiKeys.mockResolvedValue({ keys: [] })
})

afterEach(() => {
  vi.clearAllMocks()
})

describe('Settings leave-guards', () => {
  it('does not toast a display sync that returns after leave', async () => {
    let resolveSave
    api.putSettings.mockImplementation(() => new Promise((resolve) => { resolveSave = resolve }))
    const { wrapper, toast } = await mountSettings()
    await button(wrapper, 'appearance.save_server').trigger('click')
    wrapper.unmount()
    resolveSave({})
    await flushPromises()
    expect(toast).not.toHaveBeenCalled()
  })

  it('does not toast an identity save that returns after leave', async () => {
    let resolveSave
    api.putIdentity.mockImplementation(() => new Promise((resolve) => { resolveSave = resolve }))
    const { wrapper, toast } = await mountSettings()
    await button(wrapper, 'settings.tab_identity').trigger('click')
    await flushPromises()
    await button(wrapper, 'settings.save_identity').trigger('click')
    wrapper.unmount()
    resolveSave({ message: 'saved' })
    await flushPromises()
    expect(toast).not.toHaveBeenCalled()
  })

  it('does not toast a panel save that returns after leave', async () => {
    let resolveSave
    api.putSettings.mockImplementation(() => new Promise((resolve) => { resolveSave = resolve }))
    const { wrapper, toast } = await mountSettings()
    await button(wrapper, 'settings.tab_panel').trigger('click')
    await flushPromises()
    await button(wrapper, 'settings.save_settings').trigger('click')
    wrapper.unmount()
    resolveSave({})
    await flushPromises()
    expect(toast).not.toHaveBeenCalled()
  })

  it('does not clear saving when an older write finishes after a newer one', async () => {
    const resolvers = []
    api.putSettings.mockImplementation(() => new Promise((resolve) => { resolvers.push(resolve) }))
    const { wrapper } = await mountSettings()
    const saveServer = button(wrapper, 'appearance.save_server')
    saveServer.trigger('click')
    saveServer.trigger('click')
    await flushPromises()
    expect(resolvers.length).toBeGreaterThanOrEqual(1)
    if (resolvers.length < 2) {
      resolvers[0]({})
      await flushPromises()
      return
    }
    expect(saveServer.attributes('disabled')).toBeDefined()
    resolvers[0]({})
    await flushPromises()
    expect(saveServer.attributes('disabled')).toBeDefined()
    resolvers[1]({})
    await flushPromises()
    expect(saveServer.attributes('disabled')).toBeUndefined()
  })

  it('does not toast a late copy failure after leave', async () => {
    let resolveCopy
    clipboard.copyToClipboard.mockImplementation(() => new Promise((resolve) => { resolveCopy = resolve }))
    api.createApiKey.mockResolvedValue({ key: 'shk_test', record: { id: '1', name: 'cli' } })
    const { wrapper, toast } = await mountSettings()
    await button(wrapper, 'settings.tab_panel').trigger('click')
    await flushPromises()
    await wrapper.get('input[aria-label="common.name"]').setValue('cli')
    await button(wrapper, 'apikeys.create').trigger('click')
    await flushPromises()
    await button(wrapper, 'common.copy').trigger('click')
    wrapper.unmount()
    resolveCopy(false)
    await flushPromises()
    expect(toast).not.toHaveBeenCalled()
  })
})
