/**
 * Compose run() must drop busy after Refresh bumps stacksGeneration, and a
 * run that finishes after leave must not toast.
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
