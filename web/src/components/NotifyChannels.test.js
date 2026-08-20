/**
 * Notification channel card: a late Settings-tab leave must not toast
 * a failure from the request that was in flight when the card unmounted.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'

const api = vi.hoisted(() => ({
  getNotifyChannels: vi.fn(),
  createNotifyChannel: vi.fn(),
  updateNotifyChannel: vi.fn(),
  deleteNotifyChannel: vi.fn(),
  testNotifyChannel: vi.fn(),
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

import NotifyChannels from './NotifyChannels.vue'

function mountCard(toast = vi.fn()) {
  return mount(NotifyChannels, {
    global: { provide: { toast } },
  })
}

beforeEach(() => {
  for (const fn of Object.values(api)) fn.mockReset()
  api.getNotifyChannels.mockResolvedValue({
    channels: [{ id: 'email-1', name: 'Home', type: 'email', min_level: 'warn', enabled: true }],
    types: { email: { fields: ['host'], secrets: ['password'] } },
  })
})

describe('NotifyChannels', () => {
  it('lists channels after the first load', async () => {
    const w = mountCard()
    await flushPromises()
    expect(w.text()).toContain('Home')
    expect(w.text()).toContain('email-1')
    w.unmount()
  })

  it('treats a non-array channels payload as empty, not a crash', async () => {
    api.getNotifyChannels.mockResolvedValue({ channels: { id: 'x' }, types: {} })
    const w = mountCard()
    await flushPromises()
    expect(w.text()).toContain('notifych.empty')
    expect(w.text()).not.toContain('email-1')
    w.unmount()
  })

  it('does not toast a late failure after unmount', async () => {
    const toast = vi.fn()
    let rejectLoad
    api.getNotifyChannels.mockImplementation(() => new Promise((_, reject) => {
      rejectLoad = reject
    }))
    const w = mountCard(toast)
    w.unmount()
    rejectLoad(new Error('gone'))
    await flushPromises()
    expect(toast).not.toHaveBeenCalled()
  })

  it('does not toast a channel test that finishes after leave', async () => {
    const toast = vi.fn()
    let resolveTest
    api.testNotifyChannel.mockImplementation(() => new Promise((resolve) => {
      resolveTest = resolve
    }))
    const w = mountCard(toast)
    await flushPromises()
    await w.findAll('button').find((b) => b.text() === 'common.test').trigger('click')
    w.unmount()
    resolveTest({ ok: true })
    await flushPromises()
    expect(toast).not.toHaveBeenCalled()
  })
})
