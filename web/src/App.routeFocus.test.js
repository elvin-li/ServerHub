/**
 * Focus follows navigation (WCAG 2.4.3).
 *
 * Clicking a nav link swaps the page body but leaves focus on the link, so
 * the next Tab walks the rest of the 18-stop nav instead of entering the new
 * page, and a screen reader announces nothing about what just changed. The
 * shell moves focus to the main region — the same target the skip link uses —
 * whenever the route *path* changes. Query-only changes (Settings ?tab=) swap
 * content inside the page and must not yank focus off the tab the user just
 * pressed.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { nextTick, reactive, ref } from 'vue'

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
  route.fullPath = '/'
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

describe('route change focus', () => {
  it('moves focus to the main region when the path changes', async () => {
    const wrapper = mountShell()
    await flushPromises()
    // The user is mid-nav: focus sits on the link they just activated.
    wrapper.element.querySelector('.nav-stub').focus()
    expect(document.activeElement).not.toBe(wrapper.get('main').element)

    route.path = '/services'
    route.fullPath = '/services'
    await nextTick()
    await nextTick()
    expect(document.activeElement).toBe(wrapper.get('main').element)
    wrapper.unmount()
  })

  it('does not move on mount — the first Tab must still reach the skip link', async () => {
    const wrapper = mountShell()
    await flushPromises()
    expect(document.activeElement).not.toBe(wrapper.get('main').element)
    wrapper.unmount()
  })

  it('leaves focus alone on a query-only change (in-page tabs)', async () => {
    route.path = '/settings'
    route.fullPath = '/settings'
    const wrapper = mountShell()
    await flushPromises()
    const pageBtn = wrapper.element.querySelector('.page-btn')
    pageBtn.focus()

    route.query = { tab: 'network' }
    route.fullPath = '/settings?tab=network'
    await nextTick()
    await nextTick()
    expect(document.activeElement).toBe(pageBtn)
    wrapper.unmount()
  })
})
