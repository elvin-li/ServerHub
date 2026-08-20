/**
 * An audit load that fails after leave must not toast.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'

const api = vi.hoisted(() => ({
  getAuthAudit: vi.fn(),
}))

vi.mock('../api/client', () => api)
vi.mock('../i18n', () => ({
  injectI18n: () => ({
    t: (key, params = {}) => Object.entries(params).reduce(
      (text, [name, value]) => text.replace(`{${name}}`, value),
      key,
    ),
  }),
}))

import Audit from './Audit.vue'

beforeEach(() => {
  api.getAuthAudit.mockResolvedValue({ entries: [], retained_lines: 0 })
})

afterEach(() => {
  vi.clearAllMocks()
})

describe('Audit leave-guards', () => {
  it('does not toast a load that fails after leave', async () => {
    let rejectLoad
    api.getAuthAudit.mockImplementation(() => new Promise((_, reject) => { rejectLoad = reject }))
    const toast = vi.fn()
    const wrapper = mount(Audit, {
      global: {
        provide: { toast },
        stubs: { SkeletonLoader: true, LoadFailure: true },
      },
    })
    wrapper.unmount()
    rejectLoad(new Error('gone'))
    await flushPromises()
    expect(toast).not.toHaveBeenCalled()
  })

  it('does not toast a successful load that returns after leave', async () => {
    let resolveLoad
    api.getAuthAudit.mockImplementation(() => new Promise((resolve) => { resolveLoad = resolve }))
    const toast = vi.fn()
    const wrapper = mount(Audit, {
      global: {
        provide: { toast },
        stubs: { SkeletonLoader: true, LoadFailure: true },
      },
    })
    wrapper.unmount()
    resolveLoad({ entries: [{ ts: 1, event: 'login', username: 'a', outcome: 'success' }], retained_lines: 1 })
    await flushPromises()
    expect(toast).not.toHaveBeenCalled()
  })

  it('does not render leftover infinite timestamps as Infinity', async () => {
    api.getAuthAudit.mockResolvedValue({
      entries: [
        { ts: Number.POSITIVE_INFINITY, event: 'login', username: 'alice', outcome: 'success' },
        { ts: '2026-08-19T12:00:00+0000', event: 'logout', username: 'bob', outcome: 'success' },
      ],
      retained_lines: Number.POSITIVE_INFINITY,
    })
    const wrapper = mount(Audit, {
      global: {
        provide: { toast: vi.fn() },
        stubs: { SkeletonLoader: true, LoadFailure: true },
      },
    })
    await flushPromises()
    expect(wrapper.text()).not.toContain('Infinity')
    expect(wrapper.text()).toContain('alice')
    expect(wrapper.text()).toContain('bob')
    wrapper.unmount()
  })
})

