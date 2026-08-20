/**
 * Gateway page: nginx test/reload results that arrive after leave must not toast.
 */
import { describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'

const api = vi.hoisted(() => ({
  getNginx: vi.fn(),
  testNginx: vi.fn(),
  reloadNginx: vi.fn(),
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

import Gateway from './Gateway.vue'

describe('Gateway page', () => {
  it('does not toast a config test after leave', async () => {
    const toast = vi.fn()
    api.getNginx.mockResolvedValue({ running: true, sites: [] })
    let resolveTest
    api.testNginx.mockImplementation(() => new Promise((resolve) => {
      resolveTest = resolve
    }))
    const w = mount(Gateway, {
      global: {
        provide: { toast },
        stubs: { LoadFailure: true, SkeletonLoader: true },
      },
    })
    await flushPromises()
    await w.findAll('button').find((b) => b.text() === 'gateway.test').trigger('click')
    w.unmount()
    resolveTest({ ok: true, message: 'syntax ok' })
    await flushPromises()
    expect(toast).not.toHaveBeenCalled()
  })
})
