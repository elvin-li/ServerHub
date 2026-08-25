/**
 * Module registry page announcements and refresh guards.
 *
 * Behavioural half of the a11y.test.js "bookmarks and modules surface
 * leftovers" pins: the module count is the answer to the Refresh click and
 * must be a live region, Refresh must not stay clickable while a load is in
 * flight, and a load that fails after leave must not toast.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'

const api = vi.hoisted(() => ({
  getModules: vi.fn(),
}))

vi.mock('../api/client', () => api)
vi.mock('../i18n', () => ({
  injectI18n: () => ({
    // Keys carry no {placeholders}, so append the params instead: the count
    // test below needs to see the number in the rendered text.
    t: (key, params = {}) => {
      const values = Object.values(params)
      return values.length ? `${key} ${values.join(' ')}` : key
    },
  }),
}))

import Modules from './Modules.vue'

function mountPage(toast = vi.fn()) {
  return mount(Modules, {
    global: {
      provide: { toast },
      stubs: {
        RouterLink: { template: '<a><slot /></a>' },
        SkeletonLoader: true,
        LoadFailure: true,
      },
    },
  })
}

beforeEach(() => {
  api.getModules.mockResolvedValue({
    modules: [],
    by_category: {
      system: [
        { id: 'dashboard', name: 'Dashboard', description: 'Tiles', category: 'system', enabled: true, ui_routes: ['/'] },
        { id: 'services', name: 'Services', description: 'Discovery', category: 'system', enabled: true, ui_routes: ['/services'] },
      ],
      ops: [
        { id: 'logs', name: 'Log Center', description: 'Tails', category: 'ops', enabled: true, ui_routes: ['/logs'] },
      ],
    },
  })
})

afterEach(() => {
  vi.clearAllMocks()
})

describe('Modules count announcement', () => {
  it('announces the total module count through a live region', async () => {
    const wrapper = mountPage()
    await flushPromises()

    const count = wrapper.get('.toolbar [role="status"]')
    expect(count.text()).toBe('modules.count_n 3')
    expect(wrapper.findAll('.tile').length).toBe(3)
    wrapper.unmount()
  })
})

describe('Modules refresh guard', () => {
  it('disables Refresh while a load is in flight', async () => {
    let resolveLoad
    api.getModules.mockImplementation(() => new Promise((resolve) => { resolveLoad = resolve }))
    const wrapper = mountPage()
    await flushPromises()

    const refresh = wrapper.get('.toolbar button')
    expect(refresh.attributes('disabled'), 'disabled during load').toBeDefined()

    resolveLoad({ modules: [], by_category: {} })
    await flushPromises()
    expect(refresh.attributes('disabled'), 'enabled after load').toBeUndefined()
    wrapper.unmount()
  })
})

describe('Modules failure states', () => {
  it('latches the failure banner and toasts once', async () => {
    api.getModules.mockRejectedValue(new Error('registry failed'))
    const toast = vi.fn()
    const wrapper = mountPage(toast)
    await flushPromises()

    const banner = wrapper.findComponent({ name: 'LoadFailure' })
    expect(banner.exists(), 'failure banner').toBe(true)
    expect(banner.attributes('detail')).toBe('registry failed')
    expect(toast).toHaveBeenCalledTimes(1)
    expect(toast).toHaveBeenCalledWith('❌ registry failed')
    wrapper.unmount()
  })

  it('does not toast a load that fails after leave', async () => {
    let rejectLoad
    api.getModules.mockImplementation(() => new Promise((_, reject) => { rejectLoad = reject }))
    const toast = vi.fn()
    const wrapper = mountPage(toast)
    wrapper.unmount()
    rejectLoad(new Error('gone'))
    await flushPromises()
    expect(toast).not.toHaveBeenCalled()
  })
})
