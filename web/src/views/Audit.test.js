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

  it('filters rows across every rendered column', async () => {
    api.getAuthAudit.mockResolvedValue({
      entries: [
        { ts: 1, event: 'auth.login.ok', username: 'alice', client: '10.0.0.5', outcome: 'success' },
        { ts: 2, event: 'auth.login.failed', username: 'bob', client: '10.0.0.9', outcome: 'failure', reason: 'bad password' },
      ],
      retained_lines: 2,
    })
    const wrapper = mount(Audit, {
      global: {
        provide: { toast: vi.fn() },
        stubs: { SkeletonLoader: true, LoadFailure: true },
      },
    })
    await flushPromises()
    const input = wrapper.find('input[type="text"]')

    await input.setValue('alice')
    expect(wrapper.text()).toContain('alice')
    expect(wrapper.text()).not.toContain('bob')

    // Extra detail fields count too — that is where failure reasons live.
    await input.setValue('bad password')
    expect(wrapper.text()).toContain('bob')
    expect(wrapper.text()).not.toContain('alice')

    // A filter miss must say "no match", not claim the log is empty: the
    // empty-row only renders when entries exist and the needle missed.
    await input.setValue('no-such-thing')
    expect(wrapper.text()).toContain('common.no_match')
    expect(wrapper.text()).not.toContain('common.none')
    expect(wrapper.text()).not.toContain('audit.empty')
    wrapper.unmount()
  })

  it('polls while mounted and stops the poller on leave', async () => {
    const wrapper = mount(Audit, {
      global: {
        provide: { toast: vi.fn() },
        stubs: { SkeletonLoader: true, LoadFailure: true },
      },
    })
    await flushPromises()
    expect(api.getAuthAudit).toHaveBeenCalledTimes(1)
    vi.useFakeTimers()
    wrapper.unmount()
    await vi.advanceTimersByTimeAsync(120000)
    vi.useRealTimers()
    expect(api.getAuthAudit).toHaveBeenCalledTimes(1)
  })

  it('keeps background poll failures silent but toasts a manual refresh failure', async () => {
    const toast = vi.fn()
    api.getAuthAudit.mockRejectedValue(new Error('panel down'))
    vi.useFakeTimers()
    const wrapper = mount(Audit, {
      global: {
        provide: { toast },
        stubs: { SkeletonLoader: true, LoadFailure: true },
      },
    })
    await vi.advanceTimersByTimeAsync(0)
    expect(toast).toHaveBeenCalledTimes(1)
    await vi.advanceTimersByTimeAsync(31000)
    expect(toast).toHaveBeenCalledTimes(1)
    vi.useRealTimers()
    wrapper.unmount()
  })
})

