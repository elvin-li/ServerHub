/**
 * The read-only system tabs must explain a failed bundle read.
 *
 * Date & Time, Network, Shares, Scheduler and Management Access all render out
 * of one getSystemSettings() bundle, and every card in them was written as
 * `v-if="sysBundle?.section"`. When that read failed the error went to a toast
 * — gone in four seconds — and the tab settled as headings with nothing under
 * them: indistinguishable from "still loading", with no way to retry. (The VMs,
 * Power and Disk tabs already print sysBundleError; these five did not.)
 *
 * Mounted rather than pattern-matched, because what matters is what renders:
 * the failure banner, the pending placeholder, and the loaded grid must be
 * mutually exclusive, which only v-if ordering decides.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { reactive, ref } from 'vue'

const api = vi.hoisted(() => ({
  changeAuthPassword: vi.fn(),
  controlPanelService: vi.fn(),
  forceAlertCheck: vi.fn(),
  generateDiagnostics: vi.fn(),
  getDockerInfo: vi.fn(),
  getHost: vi.fn(),
  getIdentity: vi.fn(),
  getLauncherStatus: vi.fn(),
  getSettings: vi.fn(),
  getSystemSettings: vi.fn(),
  getUps: vi.fn(),
  getUpsShutdownPlan: vi.fn(),
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

async function mountSettings() {
  const wrapper = mount(Settings, {
    global: {
      provide: { toast: vi.fn() },
      stubs: { RouterLink: { template: '<a><slot /></a>' } },
    },
  })
  await flushPromises()
  return wrapper
}

async function selectTab(id) {
  route.query = { ...route.query, tab: id }
  await flushPromises()
}

beforeEach(() => {
  route.query = {}
  api.getSettings.mockResolvedValue(settingsPayload())
  api.getHost.mockResolvedValue({ hostname: 'test-host' })
  api.getIdentity.mockResolvedValue({})
})

afterEach(() => {
  vi.clearAllMocks()
})

describe('Settings system-bundle tabs', () => {
  it('shows a retryable failure banner instead of a bare heading', async () => {
    api.getSystemSettings.mockRejectedValue(new Error('bundle probe failed'))
    const wrapper = await mountSettings()
    await selectTab('datetime')

    const html = wrapper.html()
    expect(html, 'no failure banner').toContain('load-failure')
    expect(html, "the server's reason is not shown").toContain('bundle probe failed')
    expect(html, 'no way to retry').toContain('common.retry')
    expect(html, 'a dead read must not read as a slow one').not.toContain('common.loading')
    wrapper.unmount()
  })

  it('recovers through the banner retry button', async () => {
    api.getSystemSettings.mockRejectedValue(new Error('bundle probe failed'))
    const wrapper = await mountSettings()
    await selectTab('datetime')

    api.getSystemSettings.mockResolvedValue({
      datetime: { now: '2026-01-01 00:00:00', timezone: 'UTC', ntp_enabled: true, unix: 1 },
    })
    const retry = wrapper.findAll('button').find((b) => b.text() === 'common.retry')
    expect(retry, 'retry button').toBeTruthy()
    await retry.trigger('click')
    await flushPromises()

    const html = wrapper.html()
    expect(html).not.toContain('load-failure')
    expect(html).toContain('settings.now')
    wrapper.unmount()
  })

  it('says loading while the bundle is still in flight', async () => {
    api.getSystemSettings.mockReturnValue(new Promise(() => {}))
    const wrapper = await mountSettings()
    await selectTab('access')

    const html = wrapper.html()
    expect(html).toContain('common.loading')
    expect(html).not.toContain('load-failure')
    wrapper.unmount()
  })

  it('surfaces the failure on every bundle-backed tab, not just one', async () => {
    api.getSystemSettings.mockRejectedValue(new Error('bundle probe failed'))
    const wrapper = await mountSettings()
    for (const tab of ['datetime', 'network', 'shares', 'scheduler', 'access']) {
      await selectTab(tab)
      expect(wrapper.html(), `${tab}: failed read renders no explanation`).toContain('load-failure')
    }
    wrapper.unmount()
  })
})
