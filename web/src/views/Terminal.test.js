/**
 * Terminal loads that finish after leave must not toast.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'

const api = vi.hoisted(() => ({
  getTerminal: vi.fn(),
  getContainers: vi.fn(),
}))

vi.mock('../api/client', () => api)
vi.mock('../i18n', () => ({
  injectI18n: () => ({ t: (key) => key }),
}))
vi.mock('@xterm/xterm', () => ({ Terminal: class {} }))
vi.mock('@xterm/addon-fit', () => ({ FitAddon: class {} }))
vi.mock('@xterm/xterm/css/xterm.css', () => ({}))
vi.mock('../composables/useDismissable', () => ({ useDismissable: () => {} }))

import Terminal from './Terminal.vue'

beforeEach(() => {
  api.getTerminal.mockResolvedValue({ host_enabled: true })
  api.getContainers.mockResolvedValue({ containers: [] })
})

afterEach(() => {
  vi.clearAllMocks()
})

describe('Terminal leave-guards', () => {
  it('does not toast a status load that fails after leave', async () => {
    let rejectStatus
    api.getTerminal.mockImplementation(() => new Promise((_, reject) => { rejectStatus = reject }))
    const toast = vi.fn()
    const wrapper = mount(Terminal, {
      global: {
        provide: { toast },
        stubs: { RouterLink: { template: '<a><slot /></a>' } },
      },
    })
    wrapper.unmount()
    rejectStatus(new Error('gone'))
    await flushPromises()
    expect(toast).not.toHaveBeenCalled()
  })

  it('does not throw when container discovery fails after leave', async () => {
    let rejectContainers
    api.getContainers.mockImplementation(() => new Promise((_, reject) => { rejectContainers = reject }))
    const toast = vi.fn()
    const wrapper = mount(Terminal, {
      global: {
        provide: { toast },
        stubs: { RouterLink: { template: '<a><slot /></a>' } },
      },
    })
    await flushPromises()
    wrapper.unmount()
    rejectContainers(new Error('docker down'))
    await flushPromises()
    expect(toast).not.toHaveBeenCalled()
  })
})
