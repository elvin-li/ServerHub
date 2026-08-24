/**
 * Alerts page: a notification test that returns after leave must not toast.
 */
import { describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'

const api = vi.hoisted(() => ({
  getAlerts: vi.fn(),
  forceAlertCheck: vi.fn(),
  testNotify: vi.fn(),
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

import Alerts from './Alerts.vue'

describe('Alerts page', () => {
  it('does not toast a notification test after leave', async () => {
    const toast = vi.fn()
    api.getAlerts.mockResolvedValue({ alerts: [] })
    let resolveTest
    api.testNotify.mockImplementation(() => new Promise((resolve) => {
      resolveTest = resolve
    }))
    const w = mount(Alerts, {
      global: {
        provide: { toast },
        stubs: {
          LoadFailure: true,
          SkeletonLoader: true,
          RouterLink: true,
        },
      },
    })
    await flushPromises()
    await w.findAll('button').find((b) => b.text() === 'alerts.test_notify').trigger('click')
    w.unmount()
    resolveTest({ ok: true })
    await flushPromises()
    expect(toast).not.toHaveBeenCalled()
  })

  it('does not toast an inspect that finishes after leave', async () => {
    const toast = vi.fn()
    api.getAlerts.mockResolvedValue({ alerts: [] })
    let resolveCheck
    api.forceAlertCheck.mockImplementation(() => new Promise((resolve) => {
      resolveCheck = resolve
    }))
    const w = mount(Alerts, {
      global: {
        provide: { toast },
        stubs: { LoadFailure: true, SkeletonLoader: true, RouterLink: true },
      },
    })
    await flushPromises()
    await w.findAll('button').find((b) => b.text() === 'alerts.check_now').trigger('click')
    w.unmount()
    resolveCheck({ emitted: [] })
    await flushPromises()
    expect(toast).not.toHaveBeenCalled()
  })

  it('does not render leftover alert timestamps as Invalid Date', async () => {
    api.getAlerts.mockResolvedValue({
      alerts: [
        { t: '2026-08-19', id: 'a', name: 'x', level: 'down', event: 'problem' },
        { t: null, id: 'b', name: 'y', level: 'down', event: 'problem' },
        { t: 1_800_000_000, id: 'c', name: 'z', level: 'ok', event: 'resolved' },
      ],
    })
    const w = mount(Alerts, {
      global: {
        provide: { toast: vi.fn() },
        stubs: { LoadFailure: true, SkeletonLoader: true, RouterLink: true },
      },
    })
    await flushPromises()
    expect(w.text()).not.toMatch(/Invalid Date/)
    expect(w.text()).toContain('z')
    w.unmount()
  })

  it('treats a non-array alerts payload as empty', async () => {
    api.getAlerts.mockResolvedValue({ alerts: { t: 1 } })
    const w = mount(Alerts, {
      global: {
        provide: { toast: vi.fn() },
        stubs: { LoadFailure: true, SkeletonLoader: true, RouterLink: true },
      },
    })
    await flushPromises()
    expect(w.text()).toContain('alerts.empty')
    w.unmount()
  })

  it('filters rows by level through the tabs', async () => {
    api.getAlerts.mockResolvedValue({
      alerts: [
        { t: 1, name: 'svc-a', level: 'down', event: 'problem', kind: 'service' },
        { t: 2, name: 'svc-b', level: 'warn', event: 'problem', kind: 'service' },
        { t: 3, name: 'svc-c', level: 'ok', event: 'resolved', kind: 'service' },
      ],
    })
    const w = mount(Alerts, {
      global: {
        provide: { toast: vi.fn() },
        stubs: { LoadFailure: true, SkeletonLoader: true, RouterLink: true },
      },
    })
    await flushPromises()
    const tab = (label) => w.findAll('button').find((b) => b.text() === label)

    expect(w.text()).toContain('svc-c')
    await tab('alerts.only_issues').trigger('click')
    expect(w.text()).toContain('svc-a')
    expect(w.text()).toContain('svc-b')
    expect(w.text()).not.toContain('svc-c')

    await tab('alerts.only_down').trigger('click')
    expect(w.text()).toContain('svc-a')
    expect(w.text()).not.toContain('svc-b')

    await tab('alerts.only_warn').trigger('click')
    expect(w.text()).toContain('svc-b')
    expect(w.text()).not.toContain('svc-a')

    await tab('common.all').trigger('click')
    expect(w.text()).toContain('svc-c')
    w.unmount()
  })

  it('says a filter came up empty instead of rendering a bare table', async () => {
    api.getAlerts.mockResolvedValue({
      alerts: [{ t: 3, name: 'svc-c', level: 'ok', event: 'resolved', kind: 'service' }],
    })
    const w = mount(Alerts, {
      global: {
        provide: { toast: vi.fn() },
        stubs: { LoadFailure: true, SkeletonLoader: true, RouterLink: true },
      },
    })
    await flushPromises()
    await w.findAll('button').find((b) => b.text() === 'alerts.only_down').trigger('click')
    expect(w.text()).toContain('alerts.filter_empty')
    w.unmount()
  })

  it('polls while mounted and stops the poller on leave', async () => {
    api.getAlerts.mockResolvedValue({ alerts: [] })
    const w = mount(Alerts, {
      global: {
        provide: { toast: vi.fn() },
        stubs: { LoadFailure: true, SkeletonLoader: true, RouterLink: true },
      },
    })
    await flushPromises()
    expect(api.getAlerts).toHaveBeenCalledTimes(1)
    // The poller re-arms with setTimeout; a queued tick that fires after
    // unmount must not hit the API again.
    vi.useFakeTimers()
    w.unmount()
    await vi.advanceTimersByTimeAsync(120000)
    vi.useRealTimers()
    expect(api.getAlerts).toHaveBeenCalledTimes(1)
  })

  it('keeps background poll failures silent but toasts a manual refresh failure', async () => {
    const toast = vi.fn()
    api.getAlerts.mockRejectedValue(new Error('panel down'))
    vi.useFakeTimers()
    const w = mount(Alerts, {
      global: {
        provide: { toast },
        stubs: { LoadFailure: true, SkeletonLoader: true, RouterLink: true },
      },
    })
    // Mount refresh counts as manual: the operator just navigated here.
    await vi.advanceTimersByTimeAsync(0)
    expect(toast).toHaveBeenCalledTimes(1)
    // One background tick later: no second toast for the same outage.
    await vi.advanceTimersByTimeAsync(31000)
    expect(toast).toHaveBeenCalledTimes(1)
    vi.useRealTimers()
    w.unmount()
  })
})
