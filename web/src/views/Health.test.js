/**
 * A health rescan that fails after leave must not toast.
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
