/**
 * UPS safe-shutdown policy card (Settings → notify tab).
 *
 * Pins the client-side halves of the policy contract:
 *  - the form renders from the saved config: configured stacks first in their
 *    saved stop order (ticked), the rest of the catalog below (unticked);
 *  - saving converts the form back correctly — cleared trigger inputs become
 *    explicit nulls ("condition off"), custom mode sends the ordered id list;
 *  - enabling with both conditions cleared is refused client-side before any
 *    request (mirror of the server's ups.policy_no_condition);
 *  - the drill button POSTs the dry-run and renders the returned sequence
 *    without any other write;
 *  - the pmset halt card shows the system's own thresholds.
 */
import { flushPromises, mount } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { reactive } from 'vue'

vi.mock('../api/client', () => ({
  adminDisableTotp: vi.fn(),
  changeAuthPassword: vi.fn(),
  confirmTotp: vi.fn(),
  controlPanelService: vi.fn(),
  createApiKey: vi.fn(),
  disableTotp: vi.fn(),
  enrollTotp: vi.fn(),
  forceAlertCheck: vi.fn(),
  generateDiagnostics: vi.fn(),
  getDockerInfo: vi.fn(async () => ({})),
  getHost: vi.fn(async () => null),
  getIdentity: vi.fn(async () => ({ computer_name: 'x', comment: '', host_ip: 'auto' })),
  getLauncherStatus: vi.fn(async () => ({})),
  getSettings: vi.fn(async () => ({})),
  getSystemSettings: vi.fn(async () => ({})),
  getTotpStatus: vi.fn(async () => ({})),
  getUps: vi.fn(),
  getUpsShutdownPlan: vi.fn(),
  listApiKeys: vi.fn(async () => ({ keys: [] })),
  openLauncherApp: vi.fn(),
  putIdentity: vi.fn(),
  putSettings: vi.fn(),
  putUpsHalt: vi.fn(),
  putUpsSettings: vi.fn(async () => ({})),
  regenerateTotpRecovery: vi.fn(),
  revokeApiKey: vi.fn(),
  runAliasAutoBind: vi.fn(),
  runUpsShutdownDrill: vi.fn(),
  setLauncherLogin: vi.fn(),
  setPowerSetting: vi.fn(),
  testNotify: vi.fn(),
}))
vi.mock('../i18n', () => ({
  injectI18n: () => ({
    t: (key, params = {}) => Object.entries(params).reduce(
      (text, [name, value]) => text.replace(`{${name}}`, value),
      String(key),
    ),
    errText: (v) => String(v),
    locale: 'en',
    locales: [],
    setLocale: () => {},
  }),
}))
vi.mock('../theme', () => ({
  injectTheme: () => ({
    theme: 'macos', appliedTheme: 'macos', density: 'compact', themes: [], densities: [],
    followSystem: true, setTheme: () => {}, setFollowSystem: () => {}, setDensity: () => {},
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

const {
  getUps, getUpsShutdownPlan, putUpsSettings, runUpsShutdownDrill,
} = await import('../api/client')
const Settings = (await import('./Settings.vue')).default

const UPS = {
  present: true,
  on_battery: false,
  battery_percent: 100,
  halt_levels: { haltlevel: 15 },
  settings: {
    alerts_enabled: true,
    low_battery_pct: 20,
    shutdown: {
      enabled: true,
      trigger_pct: 30,
      trigger_remaining_min: null,
      require_both: false,
      stacks: ['teslamate'],
      stop_scripts: ['gravity'],
    },
  },
  shutdown_state: {
    phase: 'idle',
    last: {
      engaged_at: 1_700_000_000, reason: 'battery 18% ≤ 25%',
      restored_at: 1_700_000_600, restarted: ['teslamate'], failed: [],
    },
  },
}

const PLAN = {
  catalog: {
    stacks: [
      { id: 'immich', name: 'Immich', running: true },
      { id: 'teslamate', name: 'TeslaMate', running: true },
    ],
    scripts: [{ id: 'gravity', name: 'Gravity', has_stop: true }],
  },
  steps: [],
}

async function renderNotifyTab() {
  route.query = { tab: 'notify' }
  const wrapper = mount(Settings, {
    global: {
      provide: { toast: () => {} },
      stubs: { RouterLink: true, NotifyChannels: true, LoadFailure: true },
    },
  })
  await flushPromises()
  return wrapper
}

function buttonByText(wrapper, text) {
  return wrapper.findAll('button').find((b) => b.text() === text)
}

beforeEach(() => {
  vi.clearAllMocks()
  route.query = {}
  getUps.mockResolvedValue(JSON.parse(JSON.stringify(UPS)))
  getUpsShutdownPlan.mockResolvedValue(JSON.parse(JSON.stringify(PLAN)))
})

describe('policy form rendering', () => {
  it('lists configured stacks first in saved order, catalog rest unticked', async () => {
    const wrapper = await renderNotifyTab()
    // The checkboxes are named by the display name the row shows, not the raw
    // stack id a screen reader could not match to the visible text.
    const rows = wrapper.findAll('input[aria-label="TeslaMate"], input[aria-label="Immich"]')
    expect(rows.map((r) => r.attributes('aria-label'))).toEqual(['TeslaMate', 'Immich'])
    expect(rows[0].element.checked).toBe(true)
    expect(rows[1].element.checked).toBe(false)
  })

  it('shows the configured script ticked and the last-trigger record', async () => {
    const wrapper = await renderNotifyTab()
    const script = wrapper.find('input[aria-label="Gravity"]')
    expect(script.element.checked).toBe(true)
    expect(wrapper.find('[data-test="last-run"]').text()).toContain('settings.ups_last_trigger')
  })

  it('shows the system pmset halt config read-only next to the write field', async () => {
    const wrapper = await renderNotifyTab()
    expect(wrapper.text()).toContain('haltlevel 15%')
  })
})

describe('saving', () => {
  it('sends the ordered custom stack list and null for a cleared condition', async () => {
    const wrapper = await renderNotifyTab()
    const remaining = wrapper.find('input[aria-label="settings.ups_shutdown_remaining"]')
    await remaining.setValue('')
    await buttonByText(wrapper, 'common.save').trigger('click')
    await flushPromises()
    expect(putUpsSettings).toHaveBeenCalledTimes(1)
    const body = putUpsSettings.mock.calls[0][0]
    expect(body.shutdown).toEqual({
      enabled: true,
      trigger_pct: 30,
      trigger_remaining_min: null,
      require_both: false,
      stacks: ['teslamate'],
      stop_scripts: ['gravity'],
    })
  })

  it('refuses enabled-with-no-condition before any request is made', async () => {
    const wrapper = await renderNotifyTab()
    await wrapper.find('input[aria-label="settings.ups_shutdown_pct"]').setValue('')
    await wrapper.find('input[aria-label="settings.ups_shutdown_remaining"]').setValue('')
    await buttonByText(wrapper, 'common.save').trigger('click')
    await flushPromises()
    expect(putUpsSettings).not.toHaveBeenCalled()
  })
})

describe('drill', () => {
  it('renders the dry-run sequence and performs no write', async () => {
    runUpsShutdownDrill.mockResolvedValue({
      would_trigger_now: false,
      reason: '',
      steps: [
        { kind: 'stack', id: 'immich', name: 'Immich', running: true },
        { kind: 'stack', id: 'teslamate', name: 'TeslaMate', running: false },
      ],
    })
    const wrapper = await renderNotifyTab()
    await buttonByText(wrapper, 'settings.ups_shutdown_drill').trigger('click')
    await flushPromises()
    expect(runUpsShutdownDrill).toHaveBeenCalledTimes(1)
    const result = wrapper.find('[data-test="drill-result"]')
    expect(result.exists()).toBe(true)
    expect(result.text()).toContain('settings.ups_would_not_trigger')
    expect(result.text()).toContain('Immich')
    expect(result.text()).toContain('settings.ups_step_skip')
    expect(putUpsSettings).not.toHaveBeenCalled()
  })

  it('announces the drill verdict as a status region', async () => {
    // The verdict is the whole outcome of the button press and lands after
    // it silently — the Scheduler run-history / PhotosHub empty-state rule.
    runUpsShutdownDrill.mockResolvedValue({
      would_trigger_now: true, reason: 'battery 18% ≤ 25%', steps: [],
    })
    const wrapper = await renderNotifyTab()
    await buttonByText(wrapper, 'settings.ups_shutdown_drill').trigger('click')
    await flushPromises()
    const verdict = wrapper.find('[data-test="drill-result"] [role="status"]')
    expect(verdict.exists()).toBe(true)
    expect(verdict.text()).toContain('settings.ups_would_trigger')
  })
})

describe('load failure', () => {
  it('renders the retryable banner alone when the first load fails', async () => {
    getUps.mockRejectedValue(new Error('ups read failed'))
    const wrapper = await renderNotifyTab()
    expect(wrapper.find('load-failure-stub').exists()).toBe(true)
    expect(wrapper.find('input[aria-label="settings.ups_low_pct"]').exists()).toBe(false)
    expect(wrapper.text()).not.toContain('common.loading')
  })

  it('keeps the banner above the stale form on a re-load failure', async () => {
    // The banner was gated on !upsInfo: a tab revisit with the backend down
    // was toast-only, leaving the stale form on screen as if fresh — the
    // Containers/Alerts LoadFailure contract says banner *above* the data.
    const wrapper = await renderNotifyTab()
    expect(wrapper.find('load-failure-stub').exists()).toBe(false)
    getUps.mockRejectedValue(new Error('boom'))
    route.query = { tab: 'appearance' }
    await flushPromises()
    route.query = { tab: 'notify' }
    await flushPromises()
    expect(wrapper.find('load-failure-stub').exists()).toBe(true)
    // The previously fetched form is still the best information available.
    expect(wrapper.find('input[aria-label="settings.ups_low_pct"]').exists()).toBe(true)
  })
})
