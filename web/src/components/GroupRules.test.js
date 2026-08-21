/**
 * Group-rules card: lists effective rules, emits add/delete through the API,
 * and never toasts after unmount.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'

const api = vi.hoisted(() => ({
  getGroupRules: vi.fn(),
  saveGroupRules: vi.fn(),
  deleteGroupRule: vi.fn(),
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

import GroupRules from './GroupRules.vue'

function mountCard() {
  return mount(GroupRules, {
    global: { provide: { toast: vi.fn() } },
  })
}

beforeEach(() => {
  api.getGroupRules.mockReset()
  api.saveGroupRules.mockReset()
  api.deleteGroupRule.mockReset()
  api.getGroupRules.mockResolvedValue({
    source: 'seed',
    rules: [{
      id: 'smart-home',
      group: 'Smart Home',
      compose_project: ['xiaomihub'],
      image: 'miot',
    }],
  })
})

describe('GroupRules', () => {
  it('lists rules and the seed-source hint', async () => {
    const w = mountCard()
    await flushPromises()
    expect(w.text()).toContain('Smart Home')
    expect(w.text()).toContain('smart-home')
    expect(w.text()).toContain('xiaomihub')
    expect(w.text()).toContain('grules.source_seed')
    expect(w.text()).not.toContain('grules.compose_project')
    w.unmount()
  })

  it('saves a parsed add-form payload', async () => {
    api.saveGroupRules.mockResolvedValue({ ok: true })
    const w = mountCard()
    await flushPromises()
    await w.findAll('button').find((b) => b.text() === 'grules.add').trigger('click')
    const inputs = w.findAll('.form-grid input')
    await inputs[0].setValue('Smart Home')
    await inputs[1].setValue('xiaomihub, music-assistant')
    await inputs[2].setValue('miot')
    await inputs[3].setValue('com.homeassistant')
    await inputs[4].setValue('8123, junk, 6052')
    await w.findAll('button').find((b) => b.text() === 'common.save').trigger('click')
    await flushPromises()
    expect(api.saveGroupRules).toHaveBeenCalledWith({
      group: 'Smart Home',
      compose_project: ['xiaomihub', 'music-assistant'],
      image: ['miot'],
      launchd_prefix: ['com.homeassistant'],
      ports: [8123, 6052],
    })
    w.unmount()
  })

  it('does not toast a late failure after unmount', async () => {
    const toast = vi.fn()
    let rejectLoad
    api.getGroupRules.mockImplementation(() => new Promise((_, reject) => {
      rejectLoad = reject
    }))
    const w = mount(GroupRules, {
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
    api.saveGroupRules.mockImplementation(() => new Promise((resolve) => {
      resolveSave = resolve
    }))
    const w = mount(GroupRules, {
      global: { provide: { toast } },
    })
    await flushPromises()
    await w.findAll('button').find((b) => b.text() === 'grules.add').trigger('click')
    const inputs = w.findAll('.form-grid input')
    await inputs[0].setValue('Smart Home')
    await w.findAll('button').find((b) => b.text() === 'common.save').trigger('click')
    w.unmount()
    resolveSave({ ok: true })
    await flushPromises()
    expect(toast).not.toHaveBeenCalled()
  })
})
