/**
 * Role-dependent navigation in the application shell.
 *
 * The nav is the first thing a family member sees after signing in; if the
 * admin groups render, every click answers 403.  The shell reads the shared
 * authState (filled by the router guard), so these tests drive that state
 * directly and assert on which entries exist.
 */
import { describe, expect, it, vi } from 'vitest'
import { mount } from '@vue/test-utils'
import { ref } from 'vue'

vi.mock('./api/client', () => ({
  AUTH_LOST_EVENT: 'serverhub:auth-lost',
  getStatus: vi.fn().mockResolvedValue({}),
  logoutAuth: vi.fn().mockResolvedValue({}),
  putSettings: vi.fn().mockResolvedValue({}),
}))
vi.mock('./i18n', () => ({
  injectI18n: () => ({ t: (k) => k, locale: ref('en'), locales: [], setLocale: vi.fn() }),
}))
vi.mock('./theme', () => ({
  injectTheme: () => ({ theme: ref('dark'), themes: [], setTheme: vi.fn() }),
}))
vi.mock('./lib/poll', () => ({ startVisibleInterval: () => () => {} }))
vi.mock('./lib/adminPassword', () => ({ clearAdminPassword: vi.fn() }))
vi.mock('./components/AdminPasswordDialog.vue', () => ({
  default: { name: 'AdminPasswordDialog', render: () => null },
}))
vi.mock('./composables/useDismissable', () => ({ useDismissable: vi.fn() }))
vi.mock('vue-router', () => ({
  useRoute: () => ({ path: '/', meta: {}, fullPath: '/' }),
  useRouter: () => ({ replace: vi.fn(), push: vi.fn() }),
}))

import App from './App.vue'
import { applyAuthStatus } from './lib/authState'

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

describe('shell navigation by role', () => {
  it('shows the full admin nav to an administrator', async () => {
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
    wrapper.unmount()
  })

  it('shows a member only their dashboard, services and account', async () => {
    applyAuthStatus({
      authenticated: true, username: 'mom', role: 'member',
      resources: ['jellyfin'], can_manage: false,
    })
    const wrapper = mountShell()
    const labels = navLabels(wrapper)
    expect(labels).toEqual(['nav.dashboard', 'nav.app_services', 'nav.account'])
    wrapper.unmount()
  })

  it('keeps the admin nav when nobody is signed in yet (login page shell)', async () => {
    applyAuthStatus({ authenticated: false })
    const wrapper = mountShell()
    expect(navLabels(wrapper).join(' ')).toContain('nav.settings')
    wrapper.unmount()
  })
})
