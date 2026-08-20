/**
 * Storage mutations that finish after leave must not toast or queue a refresh.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'

const api = vi.hoisted(() => ({
  getSmartOverview: vi.fn(),
  getStorage: vi.fn(),
  getThresholds: vi.fn(),
  manageStorageDevice: vi.fn(),
  setDiskPower: vi.fn(),
  startSmartTest: vi.fn(),
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
vi.mock('../lib/poll', () => ({ startVisibleInterval: () => () => {} }))

import MainArray from './MainArray.vue'

function payload() {
  return {
    array: { status: 'started', devices: [], disk_count: 1 },
    totals: {},
    volumes: [],
    disks: [],
    power_disks: [
      {
        id: 'disk1',
        device: '/dev/disk4',
        name: 'Backup SSD',
        hint: '',
        protocol: 'USB',
        size_gb: 500,
        power_state: 'active',
        system: false,
        actions: ['sleep', 'eject'],
        volumes: [{ mount: '/Volumes/Backup' }],
      },
    ],
    managed: {
      volumes: [
        {
          id: 'disk4s1',
          volume_name: 'Backup',
          name: 'Backup',
          system: false,
          fs: 'ExFAT',
          size_gb: 500,
          mount: '/Volumes/Backup',
          actions: ['unmount', 'rename', 'eraseVolume'],
        },
      ],
      fs_types: ['APFS', 'ExFAT'],
    },
  }
}

function button(wrapper, text) {
  const found = wrapper.findAll('button').find((candidate) => candidate.text() === text)
  expect(found, `button ${text}`).toBeTruthy()
  return found
}

async function mountPage() {
  const toast = vi.fn()
  const wrapper = mount(MainArray, {
    global: {
      provide: { toast },
      stubs: { SkeletonLoader: true, LoadFailure: true },
    },
  })
  await flushPromises()
  return { wrapper, toast }
}

beforeEach(() => {
  vi.stubGlobal('confirm', vi.fn(() => true))
  api.getStorage.mockResolvedValue(payload())
  api.getThresholds.mockResolvedValue({})
  api.getSmartOverview.mockResolvedValue({
    ts: 'now',
    passwordless_sudo: true,
    smartctl_installed: true,
    devices: [
      {
        id: 'disk1',
        device: '/dev/disk4',
        capabilities: { supported: ['short'] },
      },
    ],
  })
})

afterEach(() => {
  vi.unstubAllGlobals()
  vi.clearAllMocks()
})

describe('MainArray leave-guards', () => {
  it('does not toast a disk sleep that returns after leave', async () => {
    let resolvePower
    api.setDiskPower.mockImplementation(() => new Promise((resolve) => { resolvePower = resolve }))
    const { wrapper, toast } = await mountPage()
    await button(wrapper, 'main.sleep').trigger('click')
    wrapper.unmount()
    resolvePower({ ok: true, message: 'asleep' })
    await flushPromises()
    expect(toast).not.toHaveBeenCalled()
  })

  it('does not toast a volume unmount that returns after leave', async () => {
    let resolveManage
    api.manageStorageDevice.mockImplementation(() => new Promise((resolve) => { resolveManage = resolve }))
    const { wrapper, toast } = await mountPage()
    await button(wrapper, 'main_extra.unmount').trigger('click')
    wrapper.unmount()
    resolveManage({ ok: true, message: 'unmounted' })
    await flushPromises()
    expect(toast).not.toHaveBeenCalled()
  })

  it('does not toast a rename that returns after leave', async () => {
    let resolveManage
    api.manageStorageDevice.mockImplementation(() => new Promise((resolve) => { resolveManage = resolve }))
    const { wrapper, toast } = await mountPage()
    await button(wrapper, 'main_extra.rename').trigger('click')
    await button(wrapper, 'common.confirm').trigger('click')
    wrapper.unmount()
    resolveManage({ ok: true, message: 'renamed' })
    await flushPromises()
    expect(toast).not.toHaveBeenCalled()
  })

  it('does not toast a format that returns after leave', async () => {
    let resolveManage
    api.manageStorageDevice.mockImplementation(() => new Promise((resolve) => { resolveManage = resolve }))
    const { wrapper, toast } = await mountPage()
    await button(wrapper, 'main_extra.format').trigger('click')
    await wrapper.get('input[placeholder="main_extra.format_type_ph"]').setValue('Backup')
    await button(wrapper, 'main_extra.format_ok').trigger('click')
    wrapper.unmount()
    resolveManage({ ok: true, message: 'erased' })
    await flushPromises()
    expect(toast).not.toHaveBeenCalled()
  })

  it('does not toast a SMART test that returns after leave', async () => {
    let resolveTest
    api.startSmartTest.mockImplementation(() => new Promise((resolve) => { resolveTest = resolve }))
    const { wrapper, toast } = await mountPage()
    await button(wrapper, 'main.smart_btn').trigger('click')
    await flushPromises()
    await button(wrapper, 'main_extra.smart_start main_extra.smart_short').trigger('click')
    wrapper.unmount()
    resolveTest({ ok: true })
    await flushPromises()
    expect(toast).not.toHaveBeenCalled()
  })
})
