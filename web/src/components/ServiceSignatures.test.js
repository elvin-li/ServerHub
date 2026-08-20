/**
 * Recognition-rule card: lists operator signatures, emits upsert/delete
 * through the API, and never shows the editor until the user asks.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'

const api = vi.hoisted(() => ({
  getServiceSignatures: vi.fn(),
  upsertServiceSignature: vi.fn(),
  forgetServiceSignature: vi.fn(),
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

import ServiceSignatures from './ServiceSignatures.vue'

function mountCard() {
  return mount(ServiceSignatures, {
    global: { provide: { toast: vi.fn() } },
  })
}

beforeEach(() => {
  api.getServiceSignatures.mockReset()
  api.upsertServiceSignature.mockReset()
  api.forgetServiceSignature.mockReset()
  api.getServiceSignatures.mockResolvedValue({
    signatures: [{ slug: 'my-api', name: 'My API', category: 'Apps', ports: [8100] }],
    builtin_count: 42,
  })
})

describe('ServiceSignatures', () => {
  it('lists operator rules and the builtin count', async () => {
    const w = mountCard()
    await flushPromises()
    expect(w.text()).toContain('My API')
    expect(w.text()).toContain('my-api')
    expect(w.text()).toContain('svcsig.builtin')
    expect(w.text()).not.toContain('svcsig.slug')
    w.unmount()
  })

  it('saves a parsed add-form payload', async () => {
    api.upsertServiceSignature.mockResolvedValue({ ok: true })
    const w = mountCard()
    await flushPromises()
    await w.findAll('button').find((b) => b.text() === 'svcsig.add').trigger('click')
    const inputs = w.findAll('.form-grid input')
    await inputs[0].setValue('cache')
    await inputs[1].setValue('Cache')
    await inputs[2].setValue('Infra')
    await inputs[3].setValue('redis-server')
    await inputs[4].setValue('6379, junk, 6380')
    await w.find('select').setValue('false')
    await w.findAll('button').find((b) => b.text() === 'common.save').trigger('click')
    await flushPromises()
    expect(api.upsertServiceSignature).toHaveBeenCalledWith({
      slug: 'cache',
      name: 'Cache',
      category: 'Infra',
      procs: ['redis-server'],
      ports: [6379, 6380],
      brew: undefined,
      http: false,
    })
    w.unmount()
  })

  it('does not toast a late failure after unmount', async () => {
    const toast = vi.fn()
    let rejectLoad
    api.getServiceSignatures.mockImplementation(() => new Promise((_, reject) => {
      rejectLoad = reject
    }))
    const w = mount(ServiceSignatures, {
      global: { provide: { toast } },
    })
    w.unmount()
    rejectLoad(new Error('gone'))
    await flushPromises()
    expect(toast).not.toHaveBeenCalled()
  })

  it('does not toast a save that finishes after leave', async () => {
    const toast = vi.fn()
    let resolveSave
    api.upsertServiceSignature.mockImplementation(() => new Promise((resolve) => {
      resolveSave = resolve
    }))
    const w = mount(ServiceSignatures, {
      global: { provide: { toast } },
    })
    await flushPromises()
    await w.findAll('button').find((b) => b.text() === 'svcsig.add').trigger('click')
    const inputs = w.findAll('.form-grid input')
    await inputs[0].setValue('cache')
    await w.findAll('button').find((b) => b.text() === 'common.save').trigger('click')
    w.unmount()
    resolveSave({ ok: true })
    await flushPromises()
    expect(toast).not.toHaveBeenCalled()
  })
})
