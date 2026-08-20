/**
 * A leftover / invalid console URL must fail the modal, not throw uncaught.
 */
import { afterEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'

const api = vi.hoisted(() => ({
  createVmConsoleSession: vi.fn(),
}))

vi.mock('../api/client', () => api)
vi.mock('../i18n', () => ({
  injectI18n: () => ({
    t: (key) => key,
  }),
}))
vi.mock('../composables/useDismissable', () => ({ useDismissable: () => {} }))
vi.mock('@novnc/novnc', () => ({
  default: class RFB {
    constructor() {
      this.scaleViewport = false
      this.viewOnly = false
    }
    addEventListener() {}
    disconnect() {}
  },
}))

import VncConsole from './VncConsole.vue'

afterEach(() => {
  vi.clearAllMocks()
})

describe('VncConsole leftover URL', () => {
  it('shows a failed status when the session URL is leftover junk', async () => {
    api.createVmConsoleSession.mockResolvedValue({
      ws_url: 'javascript:alert(1)',
      view_only: false,
      expires_in: Number.POSITIVE_INFINITY,
    })
    const wrapper = mount(VncConsole, {
      props: { vm: { name: 'desk', console_id: 'utm:desk', console: {} } },
    })
    await flushPromises()
    expect(wrapper.text()).toContain('vms.console_status_failed')
    wrapper.unmount()
  })

  it('does not interpolate leftover Infinity into the session toolbar', async () => {
    api.createVmConsoleSession.mockResolvedValue({
      ws_url: 'ws://127.0.0.1/vnc',
      view_only: false,
      expires_in: Number.POSITIVE_INFINITY,
      max_session_seconds: Number.NaN,
    })
    const wrapper = mount(VncConsole, {
      props: { vm: { name: 'desk', console_id: 'utm:desk', console: {} } },
    })
    await flushPromises()
    expect(wrapper.text()).not.toContain('Infinity')
    expect(wrapper.text()).not.toContain('NaN')
    wrapper.unmount()
  })
})
