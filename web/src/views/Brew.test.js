/**
 * Brew page: a running brew action must be announced, not just greyed out.
 *
 * `brew services start/stop/restart` runs for seconds (the list call alone is
 * allowed 20s) and act() disables every button for the duration. Before the
 * busy note that state was paint only: a screen-reader user heard nothing
 * between the click and the finish toast.
 */
import { describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'

const api = vi.hoisted(() => ({
  getBrewServices: vi.fn(),
  brewAction: vi.fn(),
}))

vi.mock('../api/client', () => api)
// Echoes interpolation params so the assertions below can see *which* service
// and action the note announces, not just that some note rendered.
vi.mock('../i18n', () => ({
  injectI18n: () => ({
    t: (key, params) => (params
      ? `${key}[${Object.entries(params).map(([name, value]) => `${name}=${value}`).join(' ')}]`
      : String(key)),
  }),
}))

import Brew from './Brew.vue'

const REDIS = {
  id: 'redis', name: 'redis', state: 'off', status: 'none', user: '', actions: ['start'],
}

function mountPage(toast = vi.fn()) {
  return mount(Brew, {
    global: {
      provide: { toast },
      stubs: { LoadFailure: true, SkeletonLoader: true },
    },
  })
}

describe('Brew page', () => {
  it('announces a running action through a live status note', async () => {
    api.getBrewServices.mockResolvedValue({ services: [REDIS] })
    let finish
    api.brewAction.mockImplementation(() => new Promise((resolve) => { finish = resolve }))
    const wrapper = mountPage()
    await flushPromises()
    expect(wrapper.find('[data-test="brew-busy"]').exists()).toBe(false)

    await wrapper.findAll('button').find((b) => b.text() === 'services.act_start').trigger('click')
    const note = wrapper.find('[data-test="brew-busy"]')
    expect(note.exists(), 'busy note is rendered while the action runs').toBe(true)
    expect(note.attributes('role')).toBe('status')
    expect(note.attributes('aria-live')).toBe('polite')
    // The note says what is running and on which service — the row buttons
    // already repeat the bare verb down the table.
    expect(note.text()).toContain('brew.action_running')
    expect(note.text()).toContain('action=services.act_start')
    expect(note.text()).toContain('name=redis')
    // The disabled toolbar is the visual half of the same state.
    const refresh = wrapper.findAll('button').find((b) => b.text() === 'common.refresh')
    expect(refresh.attributes('disabled')).toBeDefined()

    finish({ ok: true })
    await flushPromises()
    expect(wrapper.find('[data-test="brew-busy"]').exists()).toBe(false)
    wrapper.unmount()
  })

  it('drops the note when the action fails, alongside the error toast', async () => {
    api.getBrewServices.mockResolvedValue({ services: [REDIS] })
    let fail
    api.brewAction.mockImplementation(() => new Promise((_resolve, reject) => { fail = reject }))
    const toast = vi.fn()
    const wrapper = mountPage(toast)
    await flushPromises()

    await wrapper.findAll('button').find((b) => b.text() === 'services.act_start').trigger('click')
    expect(wrapper.find('[data-test="brew-busy"]').exists()).toBe(true)

    fail(new Error('brew exploded'))
    await flushPromises()
    expect(wrapper.find('[data-test="brew-busy"]').exists()).toBe(false)
    expect(toast).toHaveBeenCalledWith('❌ brew exploded')
    wrapper.unmount()
  })

  it('tells a filtered-out list apart from an empty one', async () => {
    // "brew.empty" claims no Homebrew services are installed; beside a
    // non-empty count that misreports the host whenever the filter simply
    // matched nothing.
    api.getBrewServices.mockResolvedValue({ services: [REDIS] })
    const wrapper = mountPage()
    await flushPromises()
    expect(wrapper.find('tbody').text()).toContain('redis')

    wrapper.vm.q = 'no-such-service'
    await flushPromises()
    const body = wrapper.find('tbody').text()
    expect(body).toContain('common.no_match')
    expect(body).not.toContain('brew.empty')
    wrapper.unmount()
  })

  it('still calls a truly empty list empty', async () => {
    api.getBrewServices.mockResolvedValue({ services: [] })
    const wrapper = mountPage()
    await flushPromises()
    expect(wrapper.find('tbody').text()).toContain('brew.empty')
    wrapper.unmount()
  })
})
