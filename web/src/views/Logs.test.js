/**
 * A log copy that finishes after leave must not toast.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'

const api = vi.hoisted(() => ({
  getLogSources: vi.fn(),
  getLogTail: vi.fn(),
}))

const clipboard = vi.hoisted(() => ({
  copyToClipboard: vi.fn(),
}))

vi.mock('../api/client', () => api)
vi.mock('../lib/clipboard', () => clipboard)
vi.mock('../i18n', () => ({
  injectI18n: () => ({
    // Keys carry no {placeholders}, so append the params instead: the live
    // region test below needs to see the match count in the rendered text.
    t: (key, params = {}) => {
      const values = Object.values(params)
      return values.length ? `${key} ${values.join(' ')}` : key
    },
  }),
}))
// Captures the registered tick so tests can fire a background refresh by hand.
const poll = vi.hoisted(() => ({ startVisibleInterval: vi.fn(() => () => {}) }))
vi.mock('../lib/poll', () => poll)

import Logs from './Logs.vue'

function button(wrapper, text) {
  const found = wrapper.findAll('button').find((candidate) => candidate.text() === text)
  expect(found, `button ${text}`).toBeTruthy()
  return found
}

async function mountPage() {
  const toast = vi.fn()
  const wrapper = mount(Logs, {
    global: {
      provide: { toast },
      stubs: { LoadFailure: true },
    },
  })
  await flushPromises()
  return { wrapper, toast }
}

beforeEach(() => {
  api.getLogSources.mockResolvedValue({
    sources: [{ id: 'panel', name: 'Panel', exists: true, size: 12 }],
  })
  api.getLogTail.mockResolvedValue({
    path: '/tmp/panel.log',
    size: 12,
    lines: 2,
    log: 'hello\nworld',
  })
  clipboard.copyToClipboard.mockResolvedValue(true)
})

afterEach(() => {
  vi.clearAllMocks()
})

describe('Logs leave-guards', () => {
  it('does not toast a copy that returns after leave', async () => {
    let resolveCopy
    clipboard.copyToClipboard.mockImplementation(() => new Promise((resolve) => { resolveCopy = resolve }))
    const { wrapper, toast } = await mountPage()
    await button(wrapper, 'logs.copy').trigger('click')
    wrapper.unmount()
    resolveCopy(true)
    await flushPromises()
    expect(toast).not.toHaveBeenCalled()
  })

  it('does not render leftover infinite sizes as Infinity', async () => {
    api.getLogSources.mockResolvedValue({
      sources: [{ id: 'panel', name: 'Panel', exists: true, size: Number.POSITIVE_INFINITY }],
    })
    api.getLogTail.mockResolvedValue({
      path: '/tmp/panel.log',
      size: Number.POSITIVE_INFINITY,
      lines: Number.POSITIVE_INFINITY,
      log: 'hello\nworld',
    })
    const { wrapper } = await mountPage()
    expect(wrapper.text()).not.toContain('Infinity')
  })

  it('does not toast a tail that fails after leave', async () => {
    let rejectTail
    api.getLogTail.mockImplementation(() => new Promise((_, reject) => { rejectTail = reject }))
    const toast = vi.fn()
    const wrapper = mount(Logs, {
      global: { provide: { toast }, stubs: { LoadFailure: true } },
    })
    await flushPromises()
    wrapper.unmount()
    rejectTail(new Error('gone'))
    await flushPromises()
    expect(toast).not.toHaveBeenCalled()
  })
})

describe('Logs keyboard and announcements', () => {
  it('keeps the scrollable viewer reachable and named for the keyboard', async () => {
    // The viewer caps at 72vh and scrolls; without tabindex a keyboard user
    // can see the overflow but has no way to move it (WCAG 2.1.1).
    const { wrapper } = await mountPage()
    const viewer = wrapper.get('.log-viewer')
    expect(viewer.text()).toContain('hello')
    expect(viewer.attributes('tabindex')).toBe('0')
    expect(viewer.attributes('role')).toBe('region')
    expect(viewer.attributes('aria-label')).toBe('logs.title')
    wrapper.unmount()
  })

  it('announces the filter match count through a live region', async () => {
    const { wrapper } = await mountPage()
    // Rendered before any filter is typed: a live region that appears
    // together with its first message is not reliably announced.
    const status = wrapper.get('[role="status"]')
    expect(status.text()).toBe('')

    await wrapper.get('input[type="text"]').setValue('hello')
    expect(status.text()).toContain('logs.matched 1')

    await wrapper.get('input[type="text"]').setValue('no-such-line')
    expect(status.text()).toContain('logs.matched 0')
    wrapper.unmount()
  })

  it('announces an empty tail through a live region, not a silent blank pane', async () => {
    api.getLogTail.mockResolvedValue({
      path: '/tmp/panel.log',
      size: 0,
      lines: 0,
      log: '',
    })
    const { wrapper } = await mountPage()
    const pane = wrapper.get('.log-viewer')
    expect(pane.text()).toBe('logs.empty')
    expect(pane.attributes('role')).toBe('status')
    wrapper.unmount()
  })

  it('announces loading through a polite live region before the first tail', async () => {
    api.getLogTail.mockImplementation(() => new Promise(() => {}))
    const { wrapper } = await mountPage()
    const pane = wrapper.get('.log-viewer')
    expect(pane.text()).toBe('common.loading')
    expect(pane.attributes('role')).toBe('status')
    expect(pane.attributes('aria-live')).toBe('polite')
    wrapper.unmount()
  })

  it('keeps auto-refresh failures silent but toasts a manual refresh failure', async () => {
    // Same convention Audit and Alerts pinned: LoadFailure latches the state
    // on screen, so a toast per 6-second tick while the panel is unreachable
    // is pure noise — it re-interrupts a screen reader on every backoff.
    api.getLogTail.mockRejectedValue(new Error('panel down'))
    const { wrapper, toast } = await mountPage()
    // The mount load is user-initiated navigation: one toast.
    expect(toast).toHaveBeenCalledTimes(1)

    // A background tick from the auto-refresh poller stays silent.
    const tick = poll.startVisibleInterval.mock.calls.at(-1)[0]
    await expect(tick()).resolves.toBe(false) // lib/poll's backoff sentinel
    await flushPromises()
    expect(toast).toHaveBeenCalledTimes(1)

    // A manual Refresh click toasts again.
    await button(wrapper, 'common.refresh').trigger('click')
    await flushPromises()
    expect(toast).toHaveBeenCalledTimes(2)
    wrapper.unmount()
  })
})
