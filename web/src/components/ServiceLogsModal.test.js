/**
 * Logs modal contract: it displays what the parent fetched, emits close and
 * refresh rather than fetching itself, and honours the dialog teardown rules
 * (Escape closes, the scroll lock never outlives the modal).
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { nextTick } from 'vue'
import { mount } from '@vue/test-utils'

const clipboard = vi.hoisted(() => ({
  copyToClipboard: vi.fn(),
}))

vi.mock('../lib/clipboard', () => clipboard)
vi.mock('../i18n', () => ({
  injectI18n: () => ({
    t: (key, params = {}) => Object.entries(params).reduce(
      (text, [name, value]) => text.replace(`{${name}}`, value),
      key,
    ),
  }),
}))

import ServiceLogsModal from './ServiceLogsModal.vue'

const entry = {
  id: 'jellyfin', name: 'Jellyfin', source: 'docker logs', log: 'line one\nline two',
}

function mountModal(props = {}) {
  return mount(ServiceLogsModal, {
    props: { entry, ...props },
    global: { provide: { toast: vi.fn() } },
  })
}

beforeEach(() => {
  document.body.style.removeProperty('overflow')
})

describe('ServiceLogsModal', () => {
  it('renders the service name, source and log text', () => {
    const w = mountModal()
    expect(w.find('.drawer-title').text()).toContain('Jellyfin')
    expect(w.text()).toContain('docker logs')
    expect(w.find('pre.log').text()).toBe('line one\nline two')
    w.unmount()
  })

  it('says (empty) when the log has no content', () => {
    const w = mountModal({ entry: { ...entry, log: '' } })
    expect(w.find('pre.log').text()).toBe('services.log_empty')
    w.unmount()
  })

  it('keeps the scrolling log pane keyboard-reachable and named', () => {
    // The pane scrolls inside a fixed-height modal; without tabindex a
    // keyboard user can see the overflow but has no way to move it.
    const w = mountModal()
    const pane = w.get('pre.log')
    expect(pane.attributes('tabindex')).toBe('0')
    expect(pane.attributes('role')).toBe('region')
    expect(pane.attributes('aria-label')).toBe('services.logs')
    w.unmount()
  })

  it('emits refresh and close from the header buttons', async () => {
    const w = mountModal()
    await w.findAll('button').find((b) => b.text() === 'common.refresh').trigger('click')
    await w.findAll('button').find((b) => b.text() === 'common.close').trigger('click')
    expect(w.emitted('refresh')).toHaveLength(1)
    expect(w.emitted('close')).toHaveLength(1)
    w.unmount()
  })

  it('closes on Escape and tears the scroll lock down on unmount', async () => {
    const onClose = vi.fn()
    const w = mount(ServiceLogsModal, {
      props: { entry },
      attrs: { onClose },
      global: { provide: { toast: vi.fn() } },
    })
    await nextTick()
    expect(document.body.style.overflow).toBe('hidden')
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true, cancelable: true }))
    expect(onClose).toHaveBeenCalledTimes(1)
    w.unmount()
    expect(document.body.style.overflow).toBe('')

    // The document-level key listener must not survive the modal: another
    // Escape after unmount may not re-fire close.
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true, cancelable: true }))
    expect(onClose).toHaveBeenCalledTimes(1)
  })

  it('does not toast a clipboard copy that finishes after leave', async () => {
    const toast = vi.fn()
    let resolveCopy
    clipboard.copyToClipboard.mockImplementation(() => new Promise((resolve) => {
      resolveCopy = resolve
    }))
    const w = mount(ServiceLogsModal, {
      props: { entry },
      global: { provide: { toast } },
    })
    await w.findAll('button').find((b) => b.text() === 'services.copy_log').trigger('click')
    w.unmount()
    resolveCopy(true)
    await flushPromises()
    expect(toast).not.toHaveBeenCalled()
  })
})
