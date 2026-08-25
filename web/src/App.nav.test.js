/**
 * Role-dependent navigation in the application shell.
 *
 * The nav is the first thing a family member sees after signing in; if the
 * admin groups render, every click answers 403.  The shell reads the shared
 * authState (filled by the router guard), so these tests drive that state
 * directly and assert on which entries exist.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { reactive, ref } from 'vue'

vi.mock('./api/client', () => ({
  AUTH_LOST_EVENT: 'serverhub:auth-lost',
  getAssistantCatalog: vi.fn(() => Promise.resolve({ panels: [] })),
  getPhotosHubStatus: vi.fn(() => Promise.resolve({ photoshub_ok: false })),
  getStatus: vi.fn(() => Promise.resolve({})),
  logoutAuth: vi.fn(() => Promise.resolve({})),
  putSettings: vi.fn(() => Promise.resolve({})),
}))
vi.mock('./i18n', () => ({
  injectI18n: () => ({ t: (k) => k, locale: ref('en'), locales: [], setLocale: vi.fn() }),
}))
vi.mock('./theme', () => ({
  injectTheme: () => ({
    theme: ref('dark'),
    themes: [],
    setTheme: vi.fn(),
    setFollowSystem: vi.fn(),
    followSystem: ref(false),
  }),
}))
vi.mock('./lib/poll', () => ({ startVisibleInterval: () => () => {} }))
vi.mock('./lib/adminPassword', () => ({ clearAdminPassword: vi.fn() }))
vi.mock('./components/AdminPasswordDialog.vue', () => ({
  default: { name: 'AdminPasswordDialog', render: () => null },
}))
vi.mock('./composables/useDismissable', () => ({ useDismissable: vi.fn() }))

const route = reactive({ path: '/', query: {}, meta: {}, fullPath: '/' })
vi.mock('vue-router', () => ({
  useRoute: () => route,
  useRouter: () => ({ replace: vi.fn(), push: vi.fn() }),
}))

import App from './App.vue'
import { applyAuthStatus } from './lib/authState'
import { getPhotosHubStatus } from './api/client'

beforeEach(() => {
  route.path = '/'
  route.query = {}
  getPhotosHubStatus.mockReset()
  getPhotosHubStatus.mockImplementation(() => Promise.resolve({ photoshub_ok: false }))
})

function mountShell() {
  return mount(App, {
    global: {
      stubs: {
        'router-link': { template: '<a class="nav-stub"><slot /></a>' },
        'router-view': { template: '<div />' },
        transition: false,
      },
    },
  })
}

function navLabels(wrapper) {
  return wrapper
    .findAll('nav.top-nav a')
    .map((a) => a.text())
}

function childLabels(wrapper) {
  return wrapper.findAll('.subchrome a').map((a) => a.text())
}

describe('shell navigation by role', () => {
  it('shows the full admin nav to an administrator', async () => {
    route.path = '/'
    applyAuthStatus({
      authenticated: true, username: 'admin', role: 'admin',
      resources: [], can_manage: true,
    })
    const wrapper = mountShell()
    const labels = navLabels(wrapper).join(' ')
    expect(labels).toContain('nav.settings')
    expect(labels).toContain('nav.tools')
    expect(labels).toContain('nav.storage')
    expect(labels).not.toContain('nav.account')
    expect(wrapper.find('[data-test="assistant-open"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="assistant-page-header"]').exists()).toBe(true)
    wrapper.unmount()
  })

  it('shows a member only their dashboard, services and account', async () => {
    route.path = '/'
    applyAuthStatus({
      authenticated: true, username: 'mom', role: 'member',
      resources: ['jellyfin'], can_manage: false,
    })
    const wrapper = mountShell()
    await flushPromises()
    const labels = navLabels(wrapper)
    expect(labels).toEqual(['nav.dashboard', 'nav.app_services', 'nav.account'])
    expect(getPhotosHubStatus).not.toHaveBeenCalled()
    expect(wrapper.find('[data-test="assistant-open"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="assistant-page-header"]').exists()).toBe(false)
    wrapper.unmount()
  })

  it('keeps the admin nav when nobody is signed in yet (login page shell)', async () => {
    route.path = '/'
    applyAuthStatus({ authenticated: false })
    const wrapper = mountShell()
    expect(navLabels(wrapper).join(' ')).toContain('nav.settings')
    wrapper.unmount()
  })

  it('hides Family Photos until PhotosHub is actually installed', async () => {
    route.path = '/tools'
    applyAuthStatus({
      authenticated: true, username: 'admin', role: 'admin',
      resources: [], can_manage: true,
    })
    getPhotosHubStatus.mockImplementation(() => Promise.resolve({ photoshub_ok: false }))
    const wrapper = mountShell()
    await flushPromises()
    expect(childLabels(wrapper).join(' ')).not.toContain('nav.photoshub')
    wrapper.unmount()
  })

  it('shows Family Photos once PhotosHub reports it is present', async () => {
    route.path = '/tools'
    applyAuthStatus({
      authenticated: true, username: 'admin', role: 'admin',
      resources: [], can_manage: true,
    })
    getPhotosHubStatus.mockImplementation(() => Promise.resolve({ photoshub_ok: true }))
    const wrapper = mountShell()
    await flushPromises()
    expect(childLabels(wrapper).join(' ')).toContain('nav.photoshub')
    wrapper.unmount()
  })

  it('lists every Settings category in the subchrome on /settings', async () => {
    route.path = '/settings'
    applyAuthStatus({
      authenticated: true, username: 'admin', role: 'admin',
      resources: [], can_manage: true,
    })
    const wrapper = mountShell()
    expect(childLabels(wrapper)).toEqual([
      'settings.tab_appearance',
      'settings.tab_identity',
      'settings.tab_datetime',
      'settings.tab_network',
      'settings.tab_disk',
      'settings.tab_power',
      'settings.tab_docker',
      'settings.tab_vms',
      'settings.tab_notify',
      'settings.tab_shares',
      'settings.tab_scheduler',
      'settings.tab_access',
      'settings.tab_advanced',
      'settings.tab_diagnostics',
      'settings.tab_panel',
    ])
    const active = wrapper.findAll('.subchrome a').filter((a) => a.classes().includes('active'))
    expect(active).toHaveLength(1)
    expect(active[0].text()).toBe('settings.tab_appearance')
    wrapper.unmount()
  })

  it('highlights only the Settings child that matches ?tab=', async () => {
    route.path = '/settings'
    route.query = { tab: 'advanced' }
    applyAuthStatus({
      authenticated: true, username: 'admin', role: 'admin',
      resources: [], can_manage: true,
    })
    const wrapper = mountShell()
    let active = wrapper.findAll('.subchrome a').filter((a) => a.classes().includes('active'))
    expect(active).toHaveLength(1)
    expect(active[0].text()).toBe('settings.tab_advanced')

    route.query = { tab: 'panel' }
    await wrapper.vm.$nextTick()
    active = wrapper.findAll('.subchrome a').filter((a) => a.classes().includes('active'))
    expect(active).toHaveLength(1)
    expect(active[0].text()).toBe('settings.tab_panel')
    wrapper.unmount()
  })
})

describe('mobile shell chrome', () => {
  it('keeps language, theme and sign-out inside the nav drawer', () => {
    applyAuthStatus({
      authenticated: true, username: 'admin', role: 'admin',
      resources: [], can_manage: true,
    })
    const wrapper = mountShell()
    const nav = wrapper.find('nav.top-nav')
    expect(nav.find('.top-controls').exists()).toBe(true)
    expect(nav.find('.logout-btn').exists()).toBe(true)
    expect(nav.find('.nav-drawer-title').text()).toBe('brand')
    expect(wrapper.find('.hamburger').attributes('aria-controls')).toBe('app-nav')
    expect(wrapper.find('.hamburger').attributes('aria-expanded')).toBe('false')
    wrapper.unmount()
  })

  it('offers follow-system in the nav theme select', () => {
    applyAuthStatus({
      authenticated: true, username: 'admin', role: 'admin',
      resources: [], can_manage: true,
    })
    const wrapper = mountShell()
    const themeSelect = wrapper.get('[data-test="nav-theme"]')
    const values = themeSelect.findAll('option').map((o) => o.element.value)
    expect(values[0]).toBe('system')
    expect(themeSelect.text()).toContain('theme.system')
    wrapper.unmount()
  })

  it('marks the hamburger open state for assistive technology', async () => {
    applyAuthStatus({
      authenticated: true, username: 'admin', role: 'admin',
      resources: [], can_manage: true,
    })
    const wrapper = mountShell()
    await wrapper.find('.hamburger').trigger('click')
    expect(wrapper.find('.hamburger').attributes('aria-expanded')).toBe('true')
    expect(wrapper.find('nav.top-nav').classes()).toContain('open')
    wrapper.unmount()
  })

  it('hides the click-away nav scrim from assistive technology', () => {
    // The scrim is mouse-only (no tabindex, no name); Escape and the hamburger
    // are the accessible ways out, so AT must not land on an anonymous div.
    applyAuthStatus({
      authenticated: true, username: 'admin', role: 'admin',
      resources: [], can_manage: true,
    })
    const wrapper = mountShell()
    const scrim = wrapper.find('.nav-overlay')
    expect(scrim.attributes('role')).toBe('presentation')
    expect(scrim.attributes('aria-hidden')).toBe('true')
    wrapper.unmount()
  })
})

describe('which page the nav says you are on', () => {
  /**
   * The highlight was CSS only.  A screen reader user tabbing the nav heard
   * the same list of destinations on every page, with nothing to say which
   * one was already open -- so "where am I" had no answer without sight.
   */
  function admin() {
    applyAuthStatus({
      authenticated: true, username: 'admin', role: 'admin',
      resources: [], can_manage: true,
    })
  }

  function currentOf(links) {
    return links
      .filter((a) => a.attributes('aria-current'))
      .map((a) => [a.text(), a.attributes('aria-current')])
  }

  it('names the open page in the top nav', () => {
    route.path = '/'
    admin()
    const wrapper = mountShell()
    expect(currentOf(wrapper.findAll('nav.top-nav a'))).toEqual([
      ['nav.dashboard', 'page'],
    ])
    wrapper.unmount()
  })

  it('leaves every other destination unmarked', () => {
    route.path = '/'
    admin()
    const wrapper = mountShell()
    const marked = wrapper
      .findAll('nav.top-nav a')
      .filter((a) => a.attributes('aria-current') !== undefined)
    expect(marked).toHaveLength(1)
    wrapper.unmount()
  })

  it('marks a section owner as an ancestor, not as the page itself', () => {
    // Both links are highlighted at once here.  Saying "page" twice would
    // claim the reader is on two pages; the group is one level up.
    route.path = '/pool'
    admin()
    const wrapper = mountShell()
    expect(currentOf(wrapper.findAll('nav.top-nav a'))).toEqual([
      ['nav.storage', 'true'],
    ])
    expect(currentOf(wrapper.findAll('.subchrome a'))).toEqual([
      ['nav.pool', 'page'],
    ])
    wrapper.unmount()
  })

  it('does not let a query-tab child and its group both claim the page', async () => {
    // RouterLink's own aria-current ignores the query string, so at
    // /settings?tab=network it marked the Settings group as the current
    // page while the section nav marked the tab as the current page too.
    route.path = '/settings'
    route.query = { tab: 'network' }
    admin()
    const wrapper = mountShell()
    const groups = currentOf(wrapper.findAll('nav.top-nav a'))
    expect(groups).toEqual([['nav.settings', 'true']])
    expect(currentOf(wrapper.findAll('.subchrome a'))).toEqual([
      ['settings.tab_network', 'page'],
    ])
    wrapper.unmount()
  })

  it('follows the reader to another page', async () => {
    route.path = '/'
    admin()
    const wrapper = mountShell()
    route.path = '/files'
    await flushPromises()
    expect(currentOf(wrapper.findAll('.subchrome a'))).toEqual([
      ['nav.files', 'page'],
    ])
    wrapper.unmount()
  })
})
