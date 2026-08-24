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

  it('never offers the same destination twice', async () => {
    // Every group shares a path with its first child, so the flat list had
    // Storage and Array both pointing at /main -- a wasted row out of eight,
    // and a duplicate :key that lets Vue reuse the wrong one on an update.
    const wrapper = await openPalette()
    const paths = rows(wrapper).map((li) => li.get('kbd').text())
    expect(paths).toEqual([...new Set(paths)])
    wrapper.unmount()
  })

  it('never leaves a row from an earlier query on screen', async () => {
    // This is what the duplicate key actually cost.  Vue reuses nodes by
    // key, and two rows keyed alike made it reuse the wrong ones as the
    // list changed under each keystroke: rows matching nothing the reader
    // had typed stayed behind -- still visible, still clickable, still
    // pointing somewhere else.  Typing "net" left "Array -> /main" sitting
    // at the top of the results.
    const wrapper = await openPalette()
    const input = wrapper.get('.cmd-palette input')
    for (const query of ['n', 'ne', 'net']) {
      await input.setValue(query)
      await flushPromises()
      const paths = rows(wrapper).map((li) => li.get('kbd').text())
      expect(paths, `stale rows while typing "${query}"`).toEqual([...new Set(paths)])
      expect(paths.length, `too many rows for "${query}"`).toBeLessThanOrEqual(9)
    }
    wrapper.unmount()
  })

  it('keeps both the group name and the page name searchable', async () => {
    // De-duplicating before matching would have thrown away whichever name
    // the reader did not type: /tools answers both to the group's name and
    // to the diagnostics page's own.  (Labels are their keys under the i18n
    // stub, so the queries here are substrings of those keys.)
    const wrapper = await openPalette()
    const input = wrapper.get('.cmd-palette input')
    for (const [query, label] of [['nav.tools', 'nav.tools'], ['sub_diag', 'nav.sub_diag']]) {
      await input.setValue(query)
      await flushPromises()
      expect(rows(wrapper).map((li) => li.get('span').text())).toContain(label)
    }
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

describe('what the command palette tells a screen reader', () => {
  /**
   * The arrow keys move a highlight that lives on a list item while focus
   * stays in the text field.  Nothing about that reaches assistive
   * technology on its own: without aria-activedescendant the reader hears
   * their own keystrokes and silence, however far down the list they walk.
   */
  function activeRowText(wrapper) {
    const pointer = wrapper.get('.cmd-palette input').attributes('aria-activedescendant')
    if (!pointer) return null
    return wrapper.get(`#${pointer}`).get('span').text()
  }

  it('points the text field at the row it has highlighted', async () => {
    const wrapper = await openPalette()
    const input = wrapper.get('.cmd-palette input')
    await input.trigger('keydown', { key: 'ArrowDown' })

    const highlightedRow = rows(wrapper).find((li) => li.classes('active'))
    expect(activeRowText(wrapper)).toBe(highlightedRow.get('span').text())
    wrapper.unmount()
  })

  it('follows the highlight as the arrow keys move it', async () => {
    const wrapper = await openPalette()
    const input = wrapper.get('.cmd-palette input')
    const walked = []
    for (let i = 0; i < 3; i += 1) {
      walked.push(activeRowText(wrapper))
      await input.trigger('keydown', { key: 'ArrowDown' })
    }
    expect(new Set(walked).size).toBe(3)
    wrapper.unmount()
  })

  it('offers the results as a listbox of options', async () => {
    const wrapper = await openPalette()
    const input = wrapper.get('.cmd-palette input')
    const list = wrapper.get('.cmd-list')

    expect(input.attributes('role')).toBe('combobox')
    expect(input.attributes('aria-controls')).toBe(list.attributes('id'))
    expect(list.attributes('role')).toBe('listbox')
    expect(rows(wrapper).every((li) => li.attributes('role') === 'option')).toBe(true)
    wrapper.unmount()
  })

  it('marks exactly one option selected', async () => {
    const wrapper = await openPalette()
    await wrapper.get('.cmd-palette input').trigger('keydown', { key: 'ArrowDown' })

    const selected = rows(wrapper).filter((li) => li.attributes('aria-selected') === 'true')
    expect(selected).toHaveLength(1)
    expect(selected[0].classes()).toContain('active')
    wrapper.unmount()
  })

  it('points at nothing rather than at a row that is not there', async () => {
    // "No matches" is a message about the list, not a choice inside it, so
    // it is not an option and there is nothing for the pointer to name.
    // Signed in as a member: an admin's palette always keeps the "ask the
    // assistant" row, so it is the only account that can empty the list.
    applyAuthStatus({
      authenticated: true, username: 'mom', role: 'member',
      resources: [], can_manage: false,
    })
    const wrapper = await openPalette()
    const input = wrapper.get('.cmd-palette input')
    await input.setValue('zzz-no-such-page')
    await flushPromises()

    expect(rows(wrapper)).toHaveLength(0)
    expect(input.attributes('aria-activedescendant')).toBeUndefined()
    expect(wrapper.get('.cmd-empty').attributes('role')).toBe('presentation')
    wrapper.unmount()
  })
})
