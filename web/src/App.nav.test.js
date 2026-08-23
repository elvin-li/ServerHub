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
    followSystem: ref(false),
  }),
}))
vi.mock('./lib/poll', () => ({ startVisibleInterval: () => () => {} }))
vi.mock('./lib/adminPassword', () => ({ clearAdminPassword: vi.fn() }))
vi.mock('./components/AdminPasswordDialog.vue', () => ({
  default: { name: 'AdminPasswordDialog', render: () => null },
}))
vi.mock('./composables/useDismissable', () => ({ useDismissable: vi.fn() }))

const route = reactive({ path: '/', meta: {}, fullPath: '/' })
vi.mock('vue-router', () => ({
  useRoute: () => route,
  useRouter: () => ({ replace: vi.fn(), push: vi.fn() }),
}))

import App from './App.vue'
import { applyAuthStatus } from './lib/authState'
import { getPhotosHubStatus } from './api/client'

beforeEach(() => {
  route.path = '/'
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
})
