/**
 * The Cmd+K palette, driven the way a keyboard user drives it.
 *
 * The palette is the shell's fastest route to any page, and it is reached
 * entirely by keyboard, so the highlight is the whole interface: it says what
 * Enter will do.  These tests type, arrow and press Enter against the real
 * component rather than asserting on source text, because the bug they pin --
 * a highlight stranded past the end of a narrowed result list -- is only
 * visible in the interaction.
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
const push = vi.fn()
vi.mock('vue-router', () => ({
  useRoute: () => route,
  useRouter: () => ({ replace: vi.fn(), push }),
}))

import App from './App.vue'
import { applyAuthStatus } from './lib/authState'

beforeEach(() => {
  route.path = '/'
  route.query = {}
  push.mockReset()
  applyAuthStatus({
    authenticated: true, username: 'admin', role: 'admin',
    resources: [], can_manage: true,
  })
})

function mountShell() {
  return mount(App, {
    attachTo: document.body,
    global: {
      stubs: {
        'router-link': { template: '<a><slot /></a>' },
        'router-view': { template: '<div />' },
        transition: false,
      },
    },
  })
}

/** Open the palette the only way a user can: the global Cmd+K binding. */
async function openPalette() {
  const wrapper = mountShell()
  window.dispatchEvent(new KeyboardEvent('keydown', { key: 'k', metaKey: true }))
  await flushPromises()
  return wrapper
}

function rows(wrapper) {
  return wrapper.findAll('.cmd-list li').filter((li) => !li.classes('cmd-empty'))
}

function highlighted(wrapper) {
  return rows(wrapper).findIndex((li) => li.classes('active'))
}

describe('the command palette highlight', () => {
  it('starts on the first result', async () => {
    const wrapper = await openPalette()
    expect(rows(wrapper).length).toBeGreaterThan(1)
    expect(highlighted(wrapper)).toBe(0)
    wrapper.unmount()
  })

  it('moves with the arrow keys', async () => {
    const wrapper = await openPalette()
    const input = wrapper.get('.cmd-palette input')
    await input.trigger('keydown', { key: 'ArrowDown' })
    await input.trigger('keydown', { key: 'ArrowDown' })
    expect(highlighted(wrapper)).toBe(2)
    await input.trigger('keydown', { key: 'ArrowUp' })
    expect(highlighted(wrapper)).toBe(1)
    wrapper.unmount()
  })

  it('opens whatever is highlighted when Enter is pressed', async () => {
    const wrapper = await openPalette()
    const input = wrapper.get('.cmd-palette input')
    await input.trigger('keydown', { key: 'ArrowDown' })
    await input.trigger('keydown', { key: 'Enter' })
    expect(push).toHaveBeenCalledTimes(1)
    wrapper.unmount()
  })

  it('comes back to a real row when the query narrows the list', async () => {
    // Arrow down first, then type: the list shrinks under a cursor that was
    // pointing into the longer one.  Nothing looked selected afterwards.
    const wrapper = await openPalette()
    const input = wrapper.get('.cmd-palette input')
    for (let i = 0; i < 5; i += 1) {
      await input.trigger('keydown', { key: 'ArrowDown' })
    }
    await input.setValue('dashboard')
    await flushPromises()

    expect(rows(wrapper).length).toBeGreaterThan(0)
    expect(highlighted(wrapper)).toBe(0)
    wrapper.unmount()
  })

  it('still opens something after the query narrows the list', async () => {
    // The visible symptom: Enter ran against an index the shortened list no
    // longer had, so the palette sat there and did nothing.
    const wrapper = await openPalette()
    const input = wrapper.get('.cmd-palette input')
    for (let i = 0; i < 5; i += 1) {
      await input.trigger('keydown', { key: 'ArrowDown' })
    }
    await input.setValue('dashboard')
    await flushPromises()
    await input.trigger('keydown', { key: 'Enter' })

    expect(push).toHaveBeenCalledTimes(1)
    wrapper.unmount()
  })

  it('leaves the cursor alone when the list only grows', async () => {
    // A result set that lengthens (the assistant catalogue arriving) must not
    // yank the reader back to the top of a list they had already walked.
    const wrapper = await openPalette()
    const input = wrapper.get('.cmd-palette input')
    await input.setValue('dashboard')
    await flushPromises()
    const before = rows(wrapper).length
    await input.trigger('keydown', { key: 'ArrowDown' })
    expect(highlighted(wrapper)).toBe(1)

    await input.setValue('')
    await flushPromises()

    expect(rows(wrapper).length).toBeGreaterThan(before)
    expect(highlighted(wrapper)).toBe(1)
    wrapper.unmount()
  })
})
