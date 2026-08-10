// The dialog keyboard contract, exercised against a real DOM rather than by
// grepping source: Escape dismisses, focus moves in and comes back out, and Tab
// cannot leave the panel.
import { beforeEach, describe, expect, it } from 'vitest'
import { defineComponent, h, nextTick, ref } from 'vue'
import { mount } from '@vue/test-utils'
import { useDismissable } from './useDismissable.js'

function makeHost() {
  return defineComponent({
    setup() {
      const open = ref(false)
      const panel = ref(null)
      const closed = ref(0)
      useDismissable(open, () => { open.value = false; closed.value += 1 }, panel)
      return { open, panel, closed }
    },
    render() {
      return h('div', [
        h('button', { id: 'trigger', onClick: () => { this.open = true } }, 'open'),
        this.open
          ? h('div', { ref: 'panel', role: 'dialog' }, [
              h('button', { id: 'first' }, 'first'),
              h('button', { id: 'last' }, 'last'),
            ])
          : null,
      ])
    },
  })
}

function press(key, opts = {}) {
  document.dispatchEvent(
    new KeyboardEvent('keydown', { key, bubbles: true, cancelable: true, ...opts }),
  )
}

describe('useDismissable', () => {
  beforeEach(() => {
    document.body.innerHTML = ''
    document.body.style.removeProperty('overflow')
  })

  it('closes the dialog when Escape is pressed', async () => {
    const wrapper = mount(makeHost(), { attachTo: document.body })
    wrapper.vm.open = true
    await nextTick()
    press('Escape')
    await nextTick()
    expect(wrapper.vm.open).toBe(false)
    expect(wrapper.vm.closed).toBe(1)
    wrapper.unmount()
  })

  it('moves focus into the dialog and returns it to the trigger', async () => {
    const wrapper = mount(makeHost(), { attachTo: document.body })
    const trigger = document.getElementById('trigger')
    trigger.focus()
    expect(document.activeElement).toBe(trigger)

    wrapper.vm.open = true
    await nextTick()
    await Promise.resolve()
    await nextTick()
    expect(document.getElementById('first')).toBe(document.activeElement)

    press('Escape')
    await nextTick()
    expect(document.activeElement).toBe(trigger)
    wrapper.unmount()
  })

  it('locks background scrolling while open and restores it on close', async () => {
    const wrapper = mount(makeHost(), { attachTo: document.body })
    wrapper.vm.open = true
    await nextTick()
    expect(document.body.style.overflow).toBe('hidden')
    press('Escape')
    await nextTick()
    expect(document.body.style.overflow).toBe('')
    wrapper.unmount()
  })

  it('wraps Tab from the last focusable back to the first', async () => {
    const wrapper = mount(makeHost(), { attachTo: document.body })
    wrapper.vm.open = true
    await nextTick()
    await Promise.resolve()
    await nextTick()
    document.getElementById('last').focus()
    press('Tab')
    await nextTick()
    expect(document.activeElement).toBe(document.getElementById('first'))
    wrapper.unmount()
  })

  it('wraps Shift+Tab from the first focusable back to the last', async () => {
    const wrapper = mount(makeHost(), { attachTo: document.body })
    wrapper.vm.open = true
    await nextTick()
    await Promise.resolve()
    await nextTick()
    document.getElementById('first').focus()
    press('Tab', { shiftKey: true })
    await nextTick()
    expect(document.activeElement).toBe(document.getElementById('last'))
    wrapper.unmount()
  })

  it('releases the scroll lock when the component unmounts while open', async () => {
    const wrapper = mount(makeHost(), { attachTo: document.body })
    wrapper.vm.open = true
    await nextTick()
    expect(document.body.style.overflow).toBe('hidden')
    wrapper.unmount()
    expect(document.body.style.overflow).toBe('')
  })
})
