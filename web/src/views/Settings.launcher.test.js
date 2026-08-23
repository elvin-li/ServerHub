import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { reactive, ref } from 'vue'

const api = vi.hoisted(() => ({
  changeAuthPassword: vi.fn(),
  controlPanelService: vi.fn(),
  forceAlertCheck: vi.fn(),
  getDockerInfo: vi.fn(),
  getHost: vi.fn(),
  getIdentity: vi.fn(),
  getLauncherStatus: vi.fn(),
  getSettings: vi.fn(),
  openLauncherApp: vi.fn(),
  putIdentity: vi.fn(),
  putSettings: vi.fn(),
  setLauncherLogin: vi.fn(),
  testNotify: vi.fn(),
}))

vi.mock('../api/client', () => api)
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

const route = reactive({ path: '/settings', query: {} })
vi.mock('vue-router', () => ({
  useRoute: () => route,
  useRouter: () => ({
    replace: vi.fn((loc) => {
      if (loc && typeof loc === 'object' && loc.query) route.query = { ...loc.query }
    }),
    push: vi.fn(),
  }),
}))

import Settings from './Settings.vue'

async function selectTab(id) {
  route.query = { ...route.query, tab: id }
  await flushPromises()
}

const launcherStatus = (overrides = {}) => ({
  app_installed: true,
  app_running: true,
  panel_running: true,
  panel_registered: true,
  panel_job_state: 'running',
  login_enabled: true,
  app_path: '/Applications/ServerHub.app',
  ...overrides,
})

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

async function mountPanel(status = launcherStatus(), configureStatus = true) {
  if (configureStatus) api.getLauncherStatus.mockResolvedValue(status)
  const toast = vi.fn()
  const wrapper = mount(Settings, {
    global: {
      provide: { toast },
      stubs: { RouterLink: { template: '<a><slot /></a>' } },
    },
  })
  await flushPromises()
  await selectTab('panel')
  return { wrapper, toast }
}

function button(wrapper, key) {
  const found = wrapper.findAll('button').find((candidate) => candidate.text() === key)
  expect(found, `button ${key}`).toBeTruthy()
  return found
}

describe('Settings native launcher controls', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    vi.stubGlobal('confirm', vi.fn(() => true))
    route.query = {}
    api.getSettings.mockResolvedValue(settingsPayload())
    api.getHost.mockResolvedValue({ hostname: 'test-host' })
    api.getIdentity.mockResolvedValue({})
  })

  afterEach(() => {
    vi.clearAllMocks()
    vi.unstubAllGlobals()
    vi.useRealTimers()
  })

  it('shows the panel as stopped immediately after the stop request is accepted', async () => {
    api.controlPanelService.mockResolvedValue({ ok: true, message: 'scheduled' })
    const { wrapper } = await mountPanel()

    await button(wrapper, 'settings.launcher_stop').trigger('click')
    await flushPromises()

    expect(wrapper.find('.tabs').exists()).toBe(false)
    expect(api.controlPanelService).toHaveBeenCalledWith('stop')
    expect(wrapper.text()).toContain('common.stopped')
    expect(button(wrapper, 'settings.launcher_stop').attributes('disabled')).toBeDefined()
    expect(api.getLauncherStatus).toHaveBeenCalledTimes(1)
    wrapper.unmount()
  })

  it('reloads launcher state after changing login startup', async () => {
    api.setLauncherLogin.mockResolvedValue({ ok: true, message: 'disabled' })
    api.getLauncherStatus
      .mockReset()
      .mockResolvedValueOnce(launcherStatus({ login_enabled: true }))
      .mockResolvedValueOnce(launcherStatus({ login_enabled: false }))
    const { wrapper } = await mountPanel()

    await button(wrapper, 'settings.launcher_disable_login').trigger('click')
    await flushPromises()
    expect(api.setLauncherLogin).toHaveBeenCalledWith(false)

    await vi.advanceTimersByTimeAsync(300)
    await flushPromises()
    expect(api.getLauncherStatus).toHaveBeenCalledTimes(2)
    expect(button(wrapper, 'settings.launcher_enable_login')).toBeTruthy()
    wrapper.unmount()
  })

  it('keeps the last known status and unlocks actions when post-action refresh fails', async () => {
    api.setLauncherLogin.mockResolvedValue({ ok: true, message: 'enabled' })
    api.getLauncherStatus
      .mockReset()
      .mockResolvedValueOnce(launcherStatus({ login_enabled: false }))
      .mockRejectedValueOnce(new Error('refresh offline'))
    const { wrapper, toast } = await mountPanel()

    await button(wrapper, 'settings.launcher_enable_login').trigger('click')
    await flushPromises()
    await vi.advanceTimersByTimeAsync(300)
    await flushPromises()

    expect(api.setLauncherLogin).toHaveBeenCalledWith(true)
    expect(api.getLauncherStatus).toHaveBeenCalledTimes(2)
    expect(wrapper.find('.launcher-unavailable').exists()).toBe(false)
    expect(wrapper.find('.launcher-card').attributes('aria-busy')).toBe('false')
    expect(button(wrapper, 'settings.launcher_enable_login').attributes('disabled')).toBeUndefined()
    expect(toast).toHaveBeenCalledWith('✅ enabled')
    expect(toast).toHaveBeenCalledWith('❌ refresh offline')
    wrapper.unmount()
  })

  it('keeps the last known running state when a stop request fails', async () => {
    api.controlPanelService.mockResolvedValue({ ok: false, message: 'denied' })
    const { wrapper, toast } = await mountPanel()

    await button(wrapper, 'settings.launcher_stop').trigger('click')
    await flushPromises()

    expect(wrapper.text()).toContain('common.running')
    expect(button(wrapper, 'settings.launcher_stop').attributes('disabled')).toBeUndefined()
    expect(toast).toHaveBeenCalledWith('❌ denied')
    wrapper.unmount()
  })

  it('does not call the service API when restart confirmation is cancelled', async () => {
    confirm.mockReturnValue(false)
    const { wrapper } = await mountPanel()

    await button(wrapper, 'settings.launcher_restart').trigger('click')

    expect(confirm).toHaveBeenCalledWith('settings.launcher_restart_confirm')
    expect(api.controlPanelService).not.toHaveBeenCalled()
    wrapper.unmount()
  })

  it('locks every launcher action while a request is in flight', async () => {
    let resolveOpen
    api.openLauncherApp.mockImplementation(() => new Promise((resolve) => { resolveOpen = resolve }))
    const { wrapper } = await mountPanel()

    await button(wrapper, 'settings.launcher_open').trigger('click')
    await wrapper.vm.$nextTick()

    for (const action of wrapper.find('.launcher-card').findAll('button')) {
      expect(action.attributes('disabled')).toBeDefined()
    }
    await button(wrapper, 'settings.launcher_open').trigger('click')
    expect(api.openLauncherApp).toHaveBeenCalledTimes(1)

    resolveOpen({ ok: true, message: 'opened' })
    await vi.advanceTimersByTimeAsync(300)
    await flushPromises()
    wrapper.unmount()
  })

  it('does not reload launcher status when the selected panel tab is clicked again', async () => {
    const { wrapper } = await mountPanel()

    await selectTab('panel')

    expect(api.getLauncherStatus).toHaveBeenCalledTimes(1)
    wrapper.unmount()
  })

  it('keeps busy state until the newest overlapping status request finishes', async () => {
    let resolveOld
    let resolveNew
    api.getLauncherStatus
      .mockReset()
      .mockResolvedValueOnce(launcherStatus())
      .mockImplementationOnce(() => new Promise((resolve) => { resolveOld = resolve }))
      .mockImplementationOnce(() => new Promise((resolve) => { resolveNew = resolve }))
    const { wrapper } = await mountPanel()

    await selectTab('appearance')
    await selectTab('panel')
    await selectTab('appearance')
    await selectTab('panel')
    expect(wrapper.find('.launcher-card').attributes('aria-busy')).toBe('true')

    resolveOld(launcherStatus({ login_enabled: true }))
    await flushPromises()
    expect(wrapper.find('.launcher-card').attributes('aria-busy')).toBe('true')

    resolveNew(launcherStatus({ login_enabled: false }))
    await flushPromises()
    expect(wrapper.find('.launcher-card').attributes('aria-busy')).toBe('false')
    expect(button(wrapper, 'settings.launcher_enable_login')).toBeTruthy()
    wrapper.unmount()
  })

  it('ignores an older request failure after a newer refresh succeeds', async () => {
    let rejectOld
    let resolveNew
    api.getLauncherStatus
      .mockReset()
      .mockResolvedValueOnce(launcherStatus())
      .mockImplementationOnce(() => new Promise((resolve, reject) => { rejectOld = reject }))
      .mockImplementationOnce(() => new Promise((resolve) => { resolveNew = resolve }))
    const { wrapper, toast } = await mountPanel()

    await selectTab('appearance')
    await selectTab('panel')
    await selectTab('appearance')
    await selectTab('panel')

    resolveNew(launcherStatus({ login_enabled: false }))
    await flushPromises()
    expect(wrapper.find('.launcher-card').attributes('aria-busy')).toBe('false')
    expect(button(wrapper, 'settings.launcher_enable_login')).toBeTruthy()

    rejectOld(new Error('stale offline'))
    await flushPromises()

    expect(wrapper.find('.launcher-unavailable').exists()).toBe(false)
    expect(button(wrapper, 'settings.launcher_enable_login')).toBeTruthy()
    expect(toast).not.toHaveBeenCalledWith('❌ stale offline')
    wrapper.unmount()
  })

  it('prevents duplicate manual refresh requests while loading', async () => {
    let resolveRefresh
    api.getLauncherStatus
      .mockReset()
      .mockResolvedValueOnce(launcherStatus())
      .mockImplementationOnce(() => new Promise((resolve) => { resolveRefresh = resolve }))
    const { wrapper } = await mountPanel()

    const refresh = button(wrapper, 'common.refresh')
    await refresh.trigger('click')
    expect(refresh.attributes('disabled')).toBeDefined()
    await refresh.trigger('click')
    expect(api.getLauncherStatus).toHaveBeenCalledTimes(2)

    resolveRefresh(launcherStatus())
    await flushPromises()
    expect(refresh.attributes('disabled')).toBeUndefined()
    wrapper.unmount()
  })

  it('announces the initial launcher load and removes it after completion', async () => {
    let resolveStatus
    api.getLauncherStatus.mockImplementation(() => new Promise((resolve) => { resolveStatus = resolve }))
    const wrapper = mount(Settings, {
      global: {
        provide: { toast: vi.fn() },
        stubs: { RouterLink: { template: '<a><slot /></a>' } },
      },
    })
    await flushPromises()

    await selectTab('panel')
    await wrapper.vm.$nextTick()
    const card = wrapper.find('.launcher-card')
    const loading = card.find('.launcher-placeholder')

    expect(card.attributes('aria-busy')).toBe('true')
    expect(loading.attributes('role')).toBe('status')
    expect(loading.attributes('aria-live')).toBe('polite')
    expect(loading.text()).toBe('common.loading')

    resolveStatus(launcherStatus())
    await flushPromises()

    expect(card.attributes('aria-busy')).toBe('false')
    expect(card.find('.launcher-placeholder').exists()).toBe(false)
    expect(card.findAll('.launcher-status-item')).toHaveLength(4)
    wrapper.unmount()
  })

  it('shows an unavailable state after the first load fails and recovers on retry', async () => {
    api.getLauncherStatus
      .mockReset()
      .mockRejectedValueOnce(new Error('offline'))
      .mockResolvedValueOnce(launcherStatus())
    const { wrapper, toast } = await mountPanel(undefined)
    const card = wrapper.find('.launcher-card')

    expect(card.attributes('aria-busy')).toBe('false')
    expect(card.find('.load-failure').exists()).toBe(true)
    expect(card.find('.load-failure').text()).toContain('offline')
    expect(card.find('.launcher-unavailable').exists()).toBe(false)
    expect(card.text()).not.toContain('common.loading')
    expect(toast).toHaveBeenCalledWith('❌ offline')

    await button(wrapper, 'common.refresh').trigger('click')
    await flushPromises()

    expect(card.find('.load-failure').exists()).toBe(false)
    expect(card.findAll('.launcher-status-item')).toHaveLength(4)
    expect(api.getLauncherStatus).toHaveBeenCalledTimes(2)
    wrapper.unmount()
  })

  it('keeps the last known state and unlocks retry after a refresh fails', async () => {
    api.getLauncherStatus
      .mockReset()
      .mockResolvedValueOnce(launcherStatus())
      .mockRejectedValueOnce(new Error('refresh offline'))
    const { wrapper, toast } = await mountPanel()
    const card = wrapper.find('.launcher-card')

    await button(wrapper, 'common.refresh').trigger('click')
    await flushPromises()

    expect(toast).toHaveBeenCalledWith('❌ refresh offline')
    expect(card.attributes('aria-busy')).toBe('false')
    expect(card.find('.launcher-unavailable').exists()).toBe(false)
    expect(card.findAll('.launcher-status-item')).toHaveLength(4)
    expect(card.find('.launcher-overall').classes()).toContain('is-ready')
    expect(card.find('.launcher-path code').text()).toBe('/Applications/ServerHub.app')
    expect(button(wrapper, 'common.refresh').attributes('disabled')).toBeUndefined()
    expect(button(wrapper, 'settings.launcher_stop').attributes('disabled')).toBeUndefined()
    expect(api.getLauncherStatus).toHaveBeenCalledTimes(2)
    wrapper.unmount()
  })

  it('announces a concise launcher summary and exposes busy state', async () => {
    const { wrapper } = await mountPanel()
    const card = wrapper.find('.launcher-card')
    const live = card.find('[role="status"]')

    expect(card.attributes('role')).toBe('region')
    expect(card.attributes('aria-labelledby')).toBe('launcher-title')
    expect(card.find('#launcher-title').text()).toBe('settings.launcher_title')
    expect(card.attributes('aria-busy')).toBe('false')
    expect(live.attributes('aria-live')).toBe('polite')
    expect(live.attributes('aria-atomic')).toBe('true')
    expect(live.text()).toContain('settings.launcher_app: settings.launcher_installed')
    expect(live.text()).toContain('settings.launcher_menu_bar: common.running')
    expect(live.text()).toContain('settings.launcher_panel_service: common.running')
    expect(live.text()).toContain('settings.launcher_login: common.on')
    expect(live.text()).not.toContain('settings.launcher_path')
    expect(live.text()).not.toContain('/Applications/ServerHub.app')

    const statusGrid = card.find('.launcher-status-grid')
    const statusItems = statusGrid.findAll('.launcher-status-item')
    expect(statusGrid.element.tagName).toBe('DL')
    expect(statusItems).toHaveLength(4)
    for (const item of statusItems) {
      expect(item.find('dt').exists()).toBe(true)
      expect(item.find('dd .badge').exists()).toBe(true)
    }
    expect(card.find('.launcher-path code').text()).toBe('/Applications/ServerHub.app')
    const actions = card.find('.launcher-actions')
    expect(actions.attributes('role')).toBe('group')
    expect(actions.attributes('aria-label')).toBe('settings.launcher_actions')
    expect(actions.findAll('button')).toHaveLength(5)
    expect(card.find('.launcher-overall').classes()).toContain('is-ready')
    expect(card.find('.form-grid').exists()).toBe(false)
    wrapper.unmount()
  })

  it('keeps each status accurate when launcher components are only partially healthy', async () => {
    const { wrapper } = await mountPanel(launcherStatus({
      panel_running: false,
      login_enabled: false,
    }))
    const card = wrapper.find('.launcher-card')
    const overall = card.find('.launcher-overall')
    const badges = card.findAll('.launcher-status-item').map((item) => item.find('.badge'))
    const live = card.find('[role="status"]')

    expect(overall.classes()).toContain('is-idle')
    expect(overall.text()).toContain('common.off')
    expect(badges.map((badge) => badge.classes())).toEqual([
      ['badge', 'ok'],
      ['badge', 'ok'],
      ['badge', 'down'],
      ['badge', 'warn'],
    ])
    expect(badges.map((badge) => badge.text())).toEqual([
      'settings.launcher_installed',
      'common.running',
      'common.stopped',
      'common.off',
    ])
    expect(live.text()).toContain('settings.launcher_menu_bar: common.running')
    expect(live.text()).toContain('settings.launcher_panel_service: common.stopped')
    expect(live.text()).toContain('settings.launcher_login: common.off')
    expect(button(wrapper, 'settings.launcher_stop').attributes('disabled')).toBeDefined()
    expect(button(wrapper, 'settings.launcher_enable_login').attributes('disabled')).toBeUndefined()
    wrapper.unmount()
  })

  it('keeps panel controls available when the menu-bar app is not installed', async () => {
    const { wrapper } = await mountPanel(launcherStatus({
      app_installed: false,
      app_running: false,
      app_path: null,
      login_enabled: false,
      panel_running: true,
      panel_registered: true,
    }))
    const card = wrapper.find('.launcher-card')
    const badges = card.findAll('.launcher-status-item').map((item) => item.find('.badge'))
    const live = card.find('[role="status"]')

    expect(card.find('.launcher-overall').classes()).toContain('is-idle')
    expect(badges.map((badge) => badge.text())).toEqual([
      'settings.launcher_not_installed',
      'common.off',
      'common.running',
      'common.off',
    ])
    expect(badges.map((badge) => badge.classes())).toEqual([
      ['badge', 'down'],
      ['badge', 'warn'],
      ['badge', 'ok'],
      ['badge', 'warn'],
    ])
    expect(card.find('.launcher-path code').text()).toBe('—')
    expect(live.text()).toContain('settings.launcher_menu_bar: common.off')
    expect(live.text()).toContain('settings.launcher_panel_service: common.running')
    expect(button(wrapper, 'settings.launcher_open').attributes('disabled')).toBeDefined()
    expect(button(wrapper, 'settings.launcher_enable_login').attributes('disabled')).toBeDefined()
    expect(button(wrapper, 'settings.launcher_restart').attributes('disabled')).toBeUndefined()
    expect(button(wrapper, 'settings.launcher_stop').attributes('disabled')).toBeUndefined()
    expect(button(wrapper, 'common.refresh').attributes('disabled')).toBeUndefined()
    wrapper.unmount()
  })
})
