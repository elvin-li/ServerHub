/**
 * A maintenance run that finishes after leave must not toast or reopen the log.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'

const api = vi.hoisted(() => ({
  getMaintenance: vi.fn(),
  getMaintenanceLog: vi.fn(),
  runMaintenance: vi.fn(),
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

import Maintenance from './Maintenance.vue'

const TASK = { id: 'brew-up', name: 'Brew upgrade', desc: 'upgrade', running: false }

function button(wrapper, text) {
  const found = wrapper.findAll('button').find((candidate) => candidate.text() === text)
  expect(found, `button ${text}`).toBeTruthy()
  return found
}

async function mountPage() {
  const toast = vi.fn()
  const wrapper = mount(Maintenance, { global: { provide: { toast } } })
  await flushPromises()
  return { wrapper, toast }
}

beforeEach(() => {
  vi.stubGlobal('confirm', vi.fn(() => true))
  api.getMaintenance.mockResolvedValue([{ ...TASK }])
  api.getMaintenanceLog.mockResolvedValue({ log: '', running: false, rc: 0 })
})

afterEach(() => {
  vi.unstubAllGlobals()
  vi.clearAllMocks()
})

describe('Maintenance leave-guards', () => {
  it('does not toast a run that succeeds after leave', async () => {
    let resolveRun
    api.runMaintenance.mockImplementation(() => new Promise((resolve) => { resolveRun = resolve }))
    const { wrapper, toast } = await mountPage()
    await button(wrapper, 'maintenance.run').trigger('click')
    wrapper.unmount()
    resolveRun({})
    await flushPromises()
    expect(toast).not.toHaveBeenCalled()
  })

  it('does not toast a run that fails after leave', async () => {
    let rejectRun
    api.runMaintenance.mockImplementation(() => new Promise((_, reject) => { rejectRun = reject }))
    const { wrapper, toast } = await mountPage()
    await button(wrapper, 'maintenance.run').trigger('click')
    wrapper.unmount()
    rejectRun(new Error('brew failed'))
    await flushPromises()
    expect(toast).not.toHaveBeenCalled()
  })

  it('does not bind an undefined starting flag on run buttons', async () => {
    const { wrapper } = await mountPage()
    const run = button(wrapper, 'maintenance.run')
    expect(run.attributes('disabled')).toBeUndefined()
    expect(wrapper.vm.starting).toBeUndefined()
  })
})

describe('Maintenance empty state', () => {
  it('points a configured-empty list at the services.yaml section', async () => {
    api.getMaintenance.mockResolvedValue([])
    const { wrapper } = await mountPage()
    expect(wrapper.text()).toContain('maintenance.empty_hint')
    expect(wrapper.text()).toContain('services.yaml → maintenance:')
  })

  it('says no_match on a filter miss, not none or the setup hint', async () => {
    // Brew/Health/Services split: tasks exist, the filter hid them — the row
    // must say the filter missed, not claim the page is empty.
    const { wrapper } = await mountPage()
    await wrapper.find('input[type="text"]').setValue('nothing-matches-this')
    expect(wrapper.text()).toContain('common.no_match')
    expect(wrapper.text()).not.toContain('common.none')
    expect(wrapper.text()).not.toContain('maintenance.empty_hint')
  })

  it('shows the load error instead of the setup hint when the read failed', async () => {
    api.getMaintenance.mockRejectedValue(new Error('backend gone'))
    const { wrapper } = await mountPage()
    expect(wrapper.text()).toContain('backend gone')
    expect(wrapper.text()).not.toContain('maintenance.empty_hint')
  })
})
