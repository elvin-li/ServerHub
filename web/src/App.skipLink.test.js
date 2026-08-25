/**
 * The bypass-block link (WCAG 2.4.1).
 *
 * The shell puts the whole primary nav — 18 tab stops — ahead of the page
 * body, and repeats it on every route, so without a skip link a keyboard user
 * walks the entire nav before reaching any page content.  These tests pin the
 * three things that make the link actually work: it is the first focusable
 * element, it targets the main region, and activating it moves focus there
 * without pushing a hash onto the URL.
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

beforeEach(() => {
  route.path = '/'
  route.query = {}
  route.meta = {}
})

function mountShell() {
  return mount(App, {
    attachTo: document.body,
    global: {
      stubs: {
        'router-link': { template: '<a href="#" class="nav-stub"><slot /></a>' },
        'router-view': { template: '<div><button class="page-btn">page</button></div>' },
        transition: false,
      },
    },
  })
}

const FOCUSABLE =
  'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex="0"]'

describe('skip link', () => {
  it('is the first thing the keyboard reaches', async () => {
    const wrapper = mountShell()
    await flushPromises()
    const first = wrapper.element.querySelector(FOCUSABLE)
    expect(first?.classList.contains('skip-link')).toBe(true)
    wrapper.unmount()
  })

  it('points at the main region, which can hold focus', async () => {
    const wrapper = mountShell()
    await flushPromises()
    const link = wrapper.get('.skip-link')
    expect(link.attributes('href')).toBe('#main-content')
    const main = wrapper.get('main')
    expect(main.attributes('id')).toBe('main-content')
    expect(main.attributes('tabindex')).toBe('-1')
    wrapper.unmount()
  })

  it('moves focus into the page body instead of navigating to a hash', async () => {
    const wrapper = mountShell()
    await flushPromises()
    const main = wrapper.get('main').element
    let defaultPrevented = false
    await wrapper.get('.skip-link').trigger('click', {
      preventDefault: () => { defaultPrevented = true },
    })
    expect(document.activeElement).toBe(main)
    expect(defaultPrevented).toBe(true)
    wrapper.unmount()
  })

  it('leaves the login page alone — it has no nav to bypass', async () => {
    route.meta = { authPage: true }
    const wrapper = mountShell()
    await flushPromises()
    expect(wrapper.find('.skip-link').exists()).toBe(false)
    wrapper.unmount()
  })
})
