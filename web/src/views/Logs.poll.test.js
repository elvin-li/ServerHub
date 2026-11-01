/**
 * The 6-second auto-refresh re-rendered the page twice per tick even when the
 * log had not changed: once when it disabled Refresh for the request, and
 * again when it enabled it and replaced `meta` with an equal new object.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'

const api = vi.hoisted(() => ({
  getLogSources: vi.fn(),
  getLogTail: vi.fn(),
}))
// Captures the registered tick so tests can run a background refresh by hand.
const poll = vi.hoisted(() => ({ startVisibleInterval: vi.fn(() => () => {}) }))

vi.mock('../api/client', () => api)
vi.mock('../lib/clipboard', () => ({ copyToClipboard: vi.fn() }))
vi.mock('../lib/poll', () => poll)
vi.mock('../i18n', () => ({
  injectI18n: () => ({
    t: (key, params = {}) => {
      const values = Object.values(params)
      return values.length ? `${key} ${values.join(' ')}` : key
    },
  }),
}))

import Logs from './Logs.vue'

const TAIL = { path: '/tmp/panel.log', size: 12, lines: 2, log: 'hello\nworld' }

// Re-renders of the Logs page itself (stubs and children are not counted).
// By name: mount() hands Vue a copy of the definition, not the import.
let renders = 0
const countRenders = {
  updated() {
    if (this.$.type.__name === 'Logs') renders += 1
  },
}

function deferred() {
  let resolve
  let reject
  const promise = new Promise((res, rej) => { resolve = res; reject = rej })
  return { promise, resolve, reject }
}

async function mountPage() {
  const wrapper = mount(Logs, {
    global: {
      provide: { toast: vi.fn() },
      stubs: { LoadFailure: true },
      mixins: [countRenders],
    },
  })
  await flushPromises()
  return wrapper
}

function refreshButton(wrapper) {
  const found = wrapper.findAll('button').find((b) => b.text() === 'common.refresh')
  expect(found, 'Refresh button').toBeTruthy()
  return found
}

/** One auto-refresh tick, as lib/poll.js runs it (no arguments). */
async function tick() {
  const result = await poll.startVisibleInterval.mock.calls.at(-1)[0]()
  await flushPromises()
  return result
}

beforeEach(() => {
  renders = 0
  api.getLogSources.mockResolvedValue({
    sources: [{ id: 'panel', name: 'Panel', exists: true, size: 12 }],
  })
  // A new object per call, like a parsed JSON response.
  api.getLogTail.mockImplementation(() => Promise.resolve({ ...TAIL }))
})

afterEach(() => {
  vi.clearAllMocks()
})

describe('Logs auto-refresh', () => {
  it('re-renders nothing when the tail has not changed', async () => {
    const wrapper = await mountPage()
    renders = 0
    await tick()
    await tick()
    await tick()
    expect(api.getLogTail).toHaveBeenCalledTimes(4)
    expect(renders).toBe(0)
    expect(wrapper.get('.log-viewer').text()).toBe('hello\nworld')
    wrapper.unmount()
  })

  it('shows a grown log with one render', async () => {
    const wrapper = await mountPage()
    renders = 0
    api.getLogTail.mockResolvedValueOnce({
      path: '/tmp/panel.log', size: 20, lines: 3, log: 'hello\nworld\nagain',
    })
    await tick()
    expect(wrapper.get('.log-viewer').text()).toContain('again')
    expect(wrapper.text()).toContain('20 B')
    expect(wrapper.text()).toContain('logs.lines_n 3')
    expect(renders).toBe(1)
    wrapper.unmount()
  })

  it('follows a new path even when size and line count match', async () => {
    const wrapper = await mountPage()
    api.getLogTail.mockResolvedValueOnce({ ...TAIL, path: '/tmp/panel.log.1' })
    await tick()
    expect(wrapper.text()).toContain('/tmp/panel.log.1')
    wrapper.unmount()
  })

  it('keeps Refresh enabled while a background tick is in flight', async () => {
    const wrapper = await mountPage()
    const pending = deferred()
    api.getLogTail.mockImplementationOnce(() => pending.promise)
    const run = tick()
    await flushPromises()
    expect(refreshButton(wrapper).attributes('disabled')).toBeUndefined()
    pending.resolve({ ...TAIL })
    await run
    wrapper.unmount()
  })

  it('still disables Refresh while a manual refresh runs', async () => {
    const wrapper = await mountPage()
    const pending = deferred()
    api.getLogTail.mockImplementationOnce(() => pending.promise)
    await refreshButton(wrapper).trigger('click')
    expect(refreshButton(wrapper).attributes('disabled')).toBeDefined()
    pending.resolve({ ...TAIL })
    await flushPromises()
    expect(refreshButton(wrapper).attributes('disabled')).toBeUndefined()
    wrapper.unmount()
  })

  it('keeps a failing source steady across background ticks', async () => {
    api.getLogTail.mockRejectedValue(new Error('panel down'))
    const wrapper = await mountPage()
    const failure = wrapper.get('load-failure-stub')
    renders = 0
    const pending = deferred()
    api.getLogTail.mockImplementationOnce(() => pending.promise)
    const run = tick()
    await flushPromises()
    // The retry button does not flash busy for a tick nobody asked for.
    expect(failure.attributes('busy')).toBe('false')
    pending.reject(new Error('panel down'))
    await expect(run).resolves.toBe(false)
    expect(await tick()).toBe(false)
    expect(renders).toBe(0)
    wrapper.unmount()
  })
})
