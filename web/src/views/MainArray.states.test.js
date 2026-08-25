/**
 * MainArray managed-volumes filter miss vs empty, and the SMART scan live region.
 *
 * With "show system volumes" off and only system volumes present, the managed
 * table claimed "No volumes" — a diagnosis ("this disk holds nothing") when the
 * truth was a filter miss ("your toggle hid them").  Brew/Tools pinned the
 * common.no_match split for search boxes; the system-volumes checkbox is the
 * same kind of filter and gets the same split.
 *
 * The SMART dialog's "Scanning…" indicator renders after the modal already
 * holds focus, so without a live region a screen-reader user hears nothing
 * between opening the dialog and the table appearing.
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

function payload(managedVolumes) {
  return {
    array: { status: 'started', devices: [], disk_count: 0 },
    totals: {},
    volumes: [],
    disks: [],
    power_disks: [],
    managed: { volumes: managedVolumes, fs_types: ['APFS'] },
  }
}

const SYSTEM_VOL = {
  id: 'disk3s1',
  volume_name: 'Macintosh HD',
  name: 'Macintosh HD',
  system: true,
  fs: 'APFS',
  size_gb: 500,
  mount: '/',
  actions: [],
}

async function mountPage() {
  const wrapper = mount(MainArray, {
    global: {
      provide: { toast: vi.fn() },
      stubs: { SkeletonLoader: true, LoadFailure: true },
    },
  })
  await flushPromises()
  return wrapper
}

/** Text of the managed-volumes empty row (the colspan-6 one). */
function managedEmptyRow(wrapper) {
  return wrapper.element.querySelector('td.empty-row[colspan="6"]')?.textContent.trim()
}

beforeEach(() => {
  api.getThresholds.mockResolvedValue({})
  api.getSmartOverview.mockResolvedValue({ devices: [] })
})

afterEach(() => {
  vi.clearAllMocks()
})

describe('MainArray managed-volumes states', () => {
  it('calls hidden system volumes a filter miss, not an empty disk', async () => {
    api.getStorage.mockResolvedValue(payload([SYSTEM_VOL]))
    const wrapper = await mountPage()
    expect(managedEmptyRow(wrapper)).toBe('common.no_match')
    expect(wrapper.text()).not.toContain('main_extra.no_vols')
    wrapper.unmount()
  })

  it('shows the hidden rows once the system-volumes toggle is on', async () => {
    api.getStorage.mockResolvedValue(payload([SYSTEM_VOL]))
    const wrapper = await mountPage()
    await wrapper.get('input[type="checkbox"]').setValue(true)
    expect(wrapper.text()).toContain('Macintosh HD')
    expect(managedEmptyRow(wrapper)).toBeUndefined()
    wrapper.unmount()
  })

  it('still says no volumes when the backend reports none', async () => {
    api.getStorage.mockResolvedValue(payload([]))
    const wrapper = await mountPage()
    expect(managedEmptyRow(wrapper)).toBe('main_extra.no_vols')
    expect(wrapper.text()).not.toContain('common.no_match')
    wrapper.unmount()
  })
})

describe('MainArray SMART dialog scan announcement', () => {
  it('announces the in-flight SMART scan through a status live region', async () => {
    api.getStorage.mockResolvedValue(payload([]))
    api.getSmartOverview.mockImplementation(() => new Promise(() => {}))
    const wrapper = await mountPage()
    const open = wrapper.findAll('button').find((b) => b.text() === 'main.smart_btn')
    expect(open, 'SMART button').toBeTruthy()
    await open.trigger('click')
    await flushPromises()
    const statuses = wrapper.findAll('[role="status"]').map((n) => n.text())
    expect(statuses).toContain('main_extra.scanning')
    wrapper.unmount()
  })
})
