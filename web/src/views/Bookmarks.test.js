/**
 * Bookmark page announcements and leave-guards.
 *
 * Behavioural half of the a11y.test.js "bookmarks and modules surface
 * leftovers" pins: the up/stopped/down summary is the answer to the Force
 * check click and must be a live region, the health LED is decoration, and
 * a load that fails after leave must not toast.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'

const api = vi.hoisted(() => ({
  getBookmarks: vi.fn(),
}))

vi.mock('../api/client', () => api)
vi.mock('../i18n', () => ({
  injectI18n: () => ({
    // Keys carry no {placeholders}, so append the params instead: the summary
    // test below needs to see the counts in the rendered text.
    t: (key, params = {}) => {
      const values = Object.values(params)
      return values.length ? `${key} ${values.join(' ')}` : key
    },
  }),
}))

import Bookmarks from './Bookmarks.vue'

function mountPage(toast = vi.fn()) {
  return mount(Bookmarks, {
    global: {
      provide: { toast },
      stubs: { SkeletonLoader: true, LoadFailure: true },
    },
  })
}

beforeEach(() => {
  api.getBookmarks.mockResolvedValue({
    bookmarks: [
      {
        id: 'nas', service: 'nas', name: 'NAS', url: 'http://nas.local',
        ok: true, health: 'ok', status: 200, ms: 12, error: null, backend: null,
      },
      {
        id: 'vm', service: 'vm', name: 'Old VM', url: 'http://vm.local',
        ok: false, health: 'stopped', status: null, ms: null, error: null,
        backend: { id: 'vm', name: 'old-vm', kind: 'vm', state: 'stopped', status: 'stopped' },
      },
      {
        id: 'down', service: 'down', name: 'Broken', url: 'http://down.local',
        ok: false, health: 'error', status: null, ms: 3, error: 'refused', backend: null,
      },
    ],
    up: 1,
    stopped: 1,
    down: 1,
    checked_at: '12:00:00',
  })
})

afterEach(() => {
  vi.clearAllMocks()
})

describe('Bookmarks summary announcement', () => {
  it('announces the up/stopped/down counts through a live region', async () => {
    const wrapper = mountPage()
    await flushPromises()

    const summary = wrapper.get('.toolbar [role="status"]')
    expect(summary.text()).toBe('bookmarks.summary 1 1 1 12:00:00')
    wrapper.unmount()
  })

  it('hides the card LEDs from the accessibility tree', async () => {
    const wrapper = mountPage()
    await flushPromises()

    const leds = wrapper.findAll('.led')
    expect(leds.length).toBe(3)
    for (const led of leds) {
      expect(led.attributes('aria-hidden')).toBe('true')
    }
    // The badge next to each LED carries the state in words, so nothing is
    // lost by hiding the dot.
    const badges = wrapper.findAll('.badge').map((b) => b.text())
    expect(badges).toEqual(['200', 'dashboard.bm_stopped', 'dashboard.bm_down'])
    wrapper.unmount()
  })
})

describe('Bookmarks leftover payloads', () => {
  it('renders the empty placeholder for a zero-bookmark answer', async () => {
    api.getBookmarks.mockResolvedValue({ bookmarks: [], up: 0, stopped: 0, down: 0, checked_at: '12:00:00' })
    const wrapper = mountPage()
    await flushPromises()

    expect(wrapper.find('.bm-page-card').exists()).toBe(false)
    expect(wrapper.get('.placeholder').text()).toBe('common.none')
    wrapper.unmount()
  })

  it('never prints Infinity for huge JSON numbers in the payload', async () => {
    // A >4300-digit YAML hex id/count that slips through as a JSON number
    // arrives as Infinity out of JSON.parse; the summary and the ms footer
    // must fall back instead of announcing "Infinity" to the live region.
    api.getBookmarks.mockResolvedValue({
      bookmarks: [
        {
          id: Infinity, service: 'big', name: 'Big', url: 'http://big.lan',
          ok: false, health: 'error', status: Infinity, ms: Infinity,
          error: null, backend: null,
        },
      ],
      up: Infinity,
      stopped: NaN,
      down: 1,
      checked_at: '12:00:00',
    })
    const wrapper = mountPage()
    await flushPromises()

    expect(wrapper.text()).not.toContain('Infinity')
    expect(wrapper.text()).not.toContain('NaN')
    const summary = wrapper.get('.toolbar [role="status"]')
    expect(summary.text()).toBe('bookmarks.summary — 0 1 12:00:00')
    wrapper.unmount()
  })
})

describe('Bookmarks leftover leftover lists', () => {
  it('fail-closes a mapping leftover bookmarks field without throwing', async () => {
    api.getBookmarks.mockResolvedValue({
      bookmarks: { 0: { id: 'ghost', name: 'Ghost', url: 'http://ghost.lan' } },
      up: 1, stopped: 0, down: 0, checked_at: '12:00:00',
    })
    const wrapper = mountPage()
    await flushPromises()
    expect(wrapper.find('.bm-page-card').exists()).toBe(false)
    expect(wrapper.get('.placeholder').text()).toBe('common.none')
    wrapper.unmount()
  })

  it('null and primitive rows do not throw out of the card v-for', async () => {
    api.getBookmarks.mockResolvedValue({
      bookmarks: [
        null,
        'x',
        {
          id: 'nas', service: 'nas', name: 'NAS', url: 'http://nas.local',
          ok: true, health: 'ok', status: 200, ms: 12, error: null,
          backend: ['not-a-map'],
        },
      ],
      up: 1, stopped: 0, down: 0, checked_at: '12:00:00',
    })
    const wrapper = mountPage()
    await flushPromises()
    expect(wrapper.findAll('.bm-page-card').length).toBe(3)
    expect(wrapper.text()).toContain('NAS')
    expect(wrapper.text()).toContain('http://nas.local')
    wrapper.unmount()
  })

  it('a whole-payload list leftover renders empty instead of throwing', async () => {
    api.getBookmarks.mockResolvedValue(['nas'])
    const wrapper = mountPage()
    await flushPromises()
    expect(wrapper.find('.bm-page-card').exists()).toBe(false)
    expect(wrapper.get('.placeholder').text()).toBe('common.none')
    wrapper.unmount()
  })
})

describe('Bookmarks failure states', () => {
  it('latches the failure banner and toasts once', async () => {
    api.getBookmarks.mockRejectedValue(new Error('probe sweep failed'))
    const toast = vi.fn()
    const wrapper = mountPage(toast)
    await flushPromises()

    const banner = wrapper.findComponent({ name: 'LoadFailure' })
    expect(banner.exists(), 'failure banner').toBe(true)
    expect(banner.attributes('detail')).toBe('probe sweep failed')
    expect(toast).toHaveBeenCalledTimes(1)
    expect(toast).toHaveBeenCalledWith('❌ probe sweep failed')
    wrapper.unmount()
  })

  it('keeps stale cards visible below the banner when a re-check fails', async () => {
    // Force check fails after a good first load: the operator must see the
    // failure *and* keep the last known rows — banner above, stale grid below,
    // never a blank page that reads as "no bookmarks".
    const wrapper = mountPage()
    await flushPromises()
    expect(wrapper.findAll('.bm-page-card').length).toBe(3)

    api.getBookmarks.mockRejectedValue(new Error('sweep died'))
    await wrapper.get('.toolbar button.primary').trigger('click')
    await flushPromises()

    const banner = wrapper.findComponent({ name: 'LoadFailure' })
    expect(banner.exists(), 'failure banner').toBe(true)
    expect(wrapper.findAll('.bm-page-card').length, 'stale rows survive').toBe(3)
    expect(wrapper.find('.placeholder').exists(), 'not the empty state').toBe(false)
    const html = wrapper.html()
    expect(html.indexOf('load-failure-stub')).toBeGreaterThan(-1)
    expect(html.indexOf('load-failure-stub'), 'banner above the grid')
      .toBeLessThan(html.indexOf('bm-page-grid'))
    wrapper.unmount()
  })

  it('does not toast a load that fails after leave', async () => {
    let rejectLoad
    api.getBookmarks.mockImplementation(() => new Promise((_, reject) => { rejectLoad = reject }))
    const toast = vi.fn()
    const wrapper = mountPage(toast)
    wrapper.unmount()
    rejectLoad(new Error('gone'))
    await flushPromises()
    expect(toast).not.toHaveBeenCalled()
  })
})
