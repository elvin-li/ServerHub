/**
 * A health rescan that fails after leave must not toast, and the level tabs
 * must announce their result count (WCAG 4.1.3): they shrink the table the
 * same way a text filter does, and the text filters already announce
 * "shown / total" through a role="status" span (filterCounts.test.js).
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'

const api = vi.hoisted(() => ({
  getHealthChecks: vi.fn(),
}))

vi.mock('../api/client', () => api)
vi.mock('../i18n', () => ({
  injectI18n: () => ({
    t: (key, params = {}) => Object.entries(params).reduce(
      (text, [name, value]) => text.replace(`{${name}}`, value),
      key,
    ),
    errText: (v) => String(v),
  }),
}))

import Health from './Health.vue'

beforeEach(() => {
  api.getHealthChecks.mockResolvedValue({
    healthy: true,
    summary: { ok: 1, warn: 0, error: 0, total: 1 },
    checks: [],
  })
})

afterEach(() => {
  vi.clearAllMocks()
})

describe('Health level tabs', () => {
  it('announce the filtered result count next to the tabs', async () => {
    api.getHealthChecks.mockResolvedValue({
      healthy: false,
      summary: { ok: 1, warn: 1, error: 1, total: 3 },
      checks: [
        { id: 'a', name: 'Disk', ok: true, level: 'ok', detail: '' },
        { id: 'b', name: 'Firewall', ok: false, level: 'warn', detail: 'off' },
        { id: 'c', name: 'SMART', ok: false, level: 'error', detail: 'failing' },
      ],
    })
    const wrapper = mount(Health, {
      global: {
        provide: { toast: vi.fn() },
        stubs: { SkeletonLoader: true, LoadFailure: true },
      },
    })
    await flushPromises()

    const count = wrapper.find('.tabs .meta-count[role="status"]')
    expect(count.exists(), 'live result count').toBe(true)
    expect(count.text()).toBe('3 / 3')

    const tab = (label) => wrapper.findAll('.tabs button').find((b) => b.text() === label)
    await tab('health.only_issues').trigger('click')
    expect(count.text()).toBe('2 / 3')
    await tab('health.errors').trigger('click')
    expect(count.text()).toBe('1 / 3')
    wrapper.unmount()
  })
})

describe('Health leave-guards', () => {
  it('does not toast a load that fails after leave', async () => {
    let rejectLoad
    api.getHealthChecks.mockImplementation(() => new Promise((_, reject) => { rejectLoad = reject }))
    const toast = vi.fn()
    const wrapper = mount(Health, {
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
})
