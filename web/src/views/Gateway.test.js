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

function mountPage(toast = vi.fn()) {
  return mount(Gateway, {
    global: {
      provide: { toast },
      stubs: { LoadFailure: true, SkeletonLoader: true },
    },
  })
}

describe('Gateway leftover payloads', () => {
  it('renders the empty row for a zero-site answer, not for a failed load', async () => {
    api.getNginx.mockResolvedValue({ running: false, pid: null, sites: [] })
    const wrapper = mountPage()
    await flushPromises()
    expect(wrapper.get('.empty-row').text()).toBe('gateway.empty')
    wrapper.unmount()

    // Filter-miss/empty vs failure must stay split: a failed load shows the
    // failure banner and never claims "no sites in conf.d".
    api.getNginx.mockRejectedValue(new Error('nginx scan failed'))
    const failed = mountPage()
    await flushPromises()
    expect(failed.find('load-failure-stub').exists()).toBe(true)
    expect(failed.find('.empty-row').exists()).toBe(false)
    failed.unmount()
  })

  it('never prints Infinity for huge JSON numbers in the payload', async () => {
    // A >4300-digit pid/conf leftover that slips through as a JSON number
    // arrives as Infinity out of JSON.parse; the pid chip must hide and the
    // conf line must fall back instead of rendering "Infinity".
    api.getNginx.mockResolvedValue({
      running: true,
      pid: Infinity,
      label: 'local.system-nginx',
      conf: Infinity,
      sites: [{ file: 'a.conf', listens: [], server_names: [], upstreams: [] }],
    })
    const wrapper = mountPage()
    await flushPromises()
    expect(wrapper.text()).not.toContain('Infinity')
    expect(wrapper.text()).not.toContain('NaN')
    expect(wrapper.text()).not.toContain('pid ')
    wrapper.unmount()
  })

  it('announces the config test result through the status live region', async () => {
    api.getNginx.mockResolvedValue({ running: true, pid: '743', sites: [] })
    api.testNginx.mockResolvedValue({ ok: true, message: 'syntax ok' })
    const wrapper = mountPage()
    await flushPromises()
    await wrapper.findAll('button').find((b) => b.text() === 'gateway.test').trigger('click')
    await flushPromises()
    const region = wrapper.get('pre[role="status"]')
    expect(region.attributes('aria-live')).toBe('polite')
    expect(region.text()).toBe('syntax ok')
    wrapper.unmount()
  })
})

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
