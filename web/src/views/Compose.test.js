/**
 * Compose run() must drop busy after Refresh bumps stacksGeneration, and a
 * run that finishes after leave must not toast.
 *
 * Also pins the editor tile's failure state: a failed getCompose read used to
 * reset the tile to the "pick a stack" placeholder — a false claim, with the
 * only explanation in a four-second toast and no way to retry.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'

const api = vi.hoisted(() => ({
  createCompose: vi.fn(),
  getCompose: vi.fn(),
  getStackJob: vi.fn(),
  getStacks: vi.fn(),
  putCompose: vi.fn(),
  runStack: vi.fn(),
  validateCompose: vi.fn(),
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

import Compose from './Compose.vue'

const STACK = { id: 'app', name: 'App', status: 'ok', compose_path: '/tmp/app', path: '/tmp/app' }

async function mountCompose(toast = vi.fn()) {
  const wrapper = mount(Compose, {
    global: {
      provide: { toast },
      stubs: { SkeletonLoader: true, LoadFailure: true },
    },
  })
  await flushPromises()
  return wrapper
}

beforeEach(() => {
  api.getStacks.mockResolvedValue({ stacks: [STACK] })
  api.runStack.mockResolvedValue({ ok: true, message: 'started' })
})

afterEach(() => {
  vi.unstubAllGlobals()
  vi.clearAllMocks()
})

describe('Compose editor load failure', () => {
  it('latches a retryable banner instead of the pick-a-stack placeholder', async () => {
    api.getCompose.mockRejectedValue(new Error('compose read failed'))
    // Real LoadFailure (not stubbed): the assertions read its detail and
    // retry button.
    const wrapper = mount(Compose, {
      global: { provide: { toast: vi.fn() }, stubs: { SkeletonLoader: true } },
    })
    await flushPromises()

    // Enter on the stack-name cell is the keyboard path to select(s); the
    // row click is only a mouse shortcut.
    await wrapper.find('td[role="button"]').trigger('keydown.enter')
    await flushPromises()
    expect(api.getCompose).toHaveBeenCalledWith('app')

    expect(wrapper.text()).toContain('compose read failed')
    expect(wrapper.text()).toContain('common.retry')
    expect(wrapper.text()).not.toContain('compose.pick_stack')

    // Retry after the backend recovers swaps the banner for the editor.
    api.getCompose.mockResolvedValue({ content: 'services: {}', compose_path: '/tmp/app/docker-compose.yml' })
    await wrapper.findAll('button').find((b) => b.text() === 'common.retry').trigger('click')
    await flushPromises()
    expect(wrapper.find('textarea.compose-editor').exists()).toBe(true)
    expect(wrapper.text()).not.toContain('compose read failed')
    wrapper.unmount()
  })
})

describe('Compose leave-guards', () => {
  it('does not toast a stack run that returns after leave', async () => {
    const toast = vi.fn()
    let resolveRun
    api.runStack.mockImplementation(() => new Promise((resolve) => { resolveRun = resolve }))
    const wrapper = await mountCompose(toast)
    await wrapper.findAll('button').find((b) => b.text() === 'compose.up').trigger('click')
    wrapper.unmount()
    resolveRun({ ok: true, message: 'started' })
    await flushPromises()
    expect(toast).not.toHaveBeenCalled()
  })

  it('drops busy when Refresh bumps stacksGeneration during a run', async () => {
    const toast = vi.fn()
    let resolveRun
    api.runStack.mockImplementation(() => new Promise((resolve) => { resolveRun = resolve }))
    const wrapper = await mountCompose(toast)
    const up = wrapper.findAll('button').find((b) => b.text() === 'compose.up')
    await up.trigger('click')
    expect(up.attributes('disabled')).toBeDefined()
    await wrapper.findAll('button').find((b) => b.text() === 'common.refresh').trigger('click')
    await flushPromises()
    resolveRun({ ok: true, message: 'started' })
    await flushPromises()
    expect(toast).not.toHaveBeenCalled()
    expect(wrapper.findAll('button').find((b) => b.text() === 'compose.up').attributes('disabled')).toBeUndefined()
    wrapper.unmount()
  })
})
