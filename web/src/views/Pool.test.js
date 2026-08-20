/**
 * Pool writes that finish after leave must not toast or adopt a stale plan.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'

const api = vi.hoisted(() => ({
  clearStoragePool: vi.fn(),
  getStoragePool: vi.fn(),
  planStoragePool: vi.fn(),
  saveStoragePool: vi.fn(),
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

import Pool from './Pool.vue'

function payload(overrides = {}) {
  return {
    configured: true,
    name: 'pool',
    policy: 'most-free',
    min_free_gb: 0,
    members: [
      {
        mount: '/Volumes/A',
        disk_id: 'disk4',
        filesystem: 'APFS',
        total_gb: 100,
        used_gb: 40,
        avail_gb: 60,
        pct: 40,
      },
    ],
    unassigned: [],
    missing_members: [],
    summary: { total_gb: 100, used_gb: 40, avail_gb: 60, pct: 40, member_count: 1 },
    next_write_target: '/Volumes/A',
    fault_model: [],
    policies: ['most-free', 'least-used-pct', 'round-robin'],
    union: { single_mount_supported: false },
    ...overrides,
  }
}

function button(wrapper, text) {
  const found = wrapper.findAll('button').find((candidate) => candidate.text() === text)
  expect(found, `button ${text}`).toBeTruthy()
  return found
}

async function mountPage() {
  const toast = vi.fn()
  const wrapper = mount(Pool, {
    global: {
      provide: { toast },
      stubs: { SkeletonLoader: true, LoadFailure: true },
    },
  })
  await flushPromises()
  return { wrapper, toast }
}

beforeEach(() => {
  api.getStoragePool.mockResolvedValue(payload())
})

afterEach(() => {
  vi.clearAllMocks()
})

describe('Pool leave-guards', () => {
  it('does not toast a save that returns after leave', async () => {
    let resolveSave
    api.saveStoragePool.mockImplementation(() => new Promise((resolve) => { resolveSave = resolve }))
    const { wrapper, toast } = await mountPage()
    await button(wrapper, 'pool.save').trigger('click')
    wrapper.unmount()
    resolveSave(payload())
    await flushPromises()
    expect(toast).not.toHaveBeenCalled()
  })

  it('does not toast a preview that fails after leave', async () => {
    let rejectPreview
    api.planStoragePool.mockImplementation(() => new Promise((_, reject) => { rejectPreview = reject }))
    const { wrapper, toast } = await mountPage()
    await button(wrapper, 'pool.preview').trigger('click')
    wrapper.unmount()
    rejectPreview(new Error('plan failed'))
    await flushPromises()
    expect(toast).not.toHaveBeenCalled()
  })

  it('does not toast a clear that returns after leave', async () => {
    let resolveClear
    api.clearStoragePool.mockImplementation(() => new Promise((resolve) => { resolveClear = resolve }))
    const { wrapper, toast } = await mountPage()
    await button(wrapper, 'pool.clear').trigger('click')
    await button(wrapper, 'pool.clear_ok').trigger('click')
    wrapper.unmount()
    resolveClear(payload({ configured: false, members: [] }))
    await flushPromises()
    expect(toast).not.toHaveBeenCalled()
  })
})
