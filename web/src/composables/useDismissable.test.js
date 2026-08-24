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

  it('does not trap Tab when focus is on a console surface', async () => {
    const host = defineComponent({
      setup() {
        const open = ref(true)
        const panel = ref(null)
        useDismissable(open, () => { open.value = false }, panel)
        return { open, panel }
      },
      render() {
        return h('div', { ref: 'panel', role: 'dialog' }, [
          h('button', { id: 'chrome' }, 'close'),
          h('textarea', { id: 'term', class: 'xterm-helper-textarea' }),
        ])
      },
    })
    const wrapper = mount(host, { attachTo: document.body })
    await nextTick()
    await Promise.resolve()
    await nextTick()
    const term = document.getElementById('term')
    term.focus()
    const event = new KeyboardEvent('keydown', { key: 'Tab', bubbles: true, cancelable: true })
    term.dispatchEvent(event)
    expect(event.defaultPrevented).toBe(false)
    wrapper.unmount()
  })

  it('ignores Escape while an IME composition is in progress', async () => {
    const wrapper = mount(makeHost(), { attachTo: document.body })
    wrapper.vm.open = true
    await nextTick()

    const composing = new KeyboardEvent('keydown', { key: 'Escape', bubbles: true, cancelable: true })
    Object.defineProperty(composing, 'isComposing', { value: true })
    document.dispatchEvent(composing)
    await nextTick()
    expect(wrapper.vm.open).toBe(true)

    // keyCode 229 is the legacy in-composition signal some engines send
    // instead of (or before) isComposing.
    const legacy = new KeyboardEvent('keydown', { key: 'Escape', bubbles: true, cancelable: true })
    Object.defineProperty(legacy, 'keyCode', { value: 229 })
    document.dispatchEvent(legacy)
    await nextTick()
    expect(wrapper.vm.open).toBe(true)

    press('Escape')
    await nextTick()
    expect(wrapper.vm.open).toBe(false)
    wrapper.unmount()
  })

  it('does not steal focus after unmount before the open microtask lands', async () => {
    const wrapper = mount(makeHost(), { attachTo: document.body })
    const trigger = document.getElementById('trigger')
    const other = document.createElement('button')
    other.id = 'elsewhere'
    document.body.appendChild(other)
    trigger.focus()

    wrapper.vm.open = true
    wrapper.unmount()
    other.focus()
    await Promise.resolve()
    await nextTick()
    expect(document.activeElement).toBe(other)
    other.remove()
  })
})

// The admin-password prompt opens on top of whatever modal triggered the
// privileged call, so two dismissables can be live at once. Escape must close
// only the top one, the lower Tab trap must stand down, and the scroll lock
// must survive until the last dialog closes.
describe('useDismissable stacking', () => {
  beforeEach(() => {
    document.body.innerHTML = ''
    document.body.style.removeProperty('overflow')
  })

  function makeStackedHost() {
    return defineComponent({
      setup() {
        const lowerOpen = ref(false)
        const upperOpen = ref(false)
        const lowerPanel = ref(null)
        const upperPanel = ref(null)
        useDismissable(lowerOpen, () => { lowerOpen.value = false }, lowerPanel)
        useDismissable(upperOpen, () => { upperOpen.value = false }, upperPanel)
        return { lowerOpen, upperOpen, lowerPanel, upperPanel }
      },
      render() {
        return h('div', [
          this.lowerOpen
            ? h('div', { ref: 'lowerPanel', role: 'dialog' }, [
                h('button', { id: 'lower-first' }, 'first'),
                h('button', { id: 'lower-last' }, 'last'),
              ])
            : null,
          this.upperOpen
            ? h('div', { ref: 'upperPanel', role: 'dialog' }, [
                h('button', { id: 'upper-first' }, 'first'),
                h('button', { id: 'upper-last' }, 'last'),
              ])
            : null,
        ])
      },
    })
  }

  async function openBoth(wrapper) {
    wrapper.vm.lowerOpen = true
    await nextTick()
    await Promise.resolve()
    wrapper.vm.upperOpen = true
    await nextTick()
    await Promise.resolve()
    await nextTick()
  }

  it('closes only the topmost dialog on Escape', async () => {
    const wrapper = mount(makeStackedHost(), { attachTo: document.body })
    await openBoth(wrapper)

    press('Escape')
    await nextTick()
    expect(wrapper.vm.upperOpen).toBe(false)
    expect(wrapper.vm.lowerOpen).toBe(true)

    press('Escape')
    await nextTick()
    expect(wrapper.vm.lowerOpen).toBe(false)
    wrapper.unmount()
  })

  it('keeps the lower Tab trap from stealing focus behind the top dialog', async () => {
    const wrapper = mount(makeStackedHost(), { attachTo: document.body })
    await openBoth(wrapper)

    // The final activeElement can land back in the top dialog even when the
    // lower trap misfires (both handlers run), so record any illegal stop.
    let lowerStoleFocus = false
    document.getElementById('lower-last').addEventListener('focus', () => { lowerStoleFocus = true })

    document.getElementById('upper-first').focus()
    press('Tab', { shiftKey: true })
    await nextTick()
    expect(lowerStoleFocus).toBe(false)
    expect(document.activeElement).toBe(document.getElementById('upper-last'))
    wrapper.unmount()
  })

  it('holds the scroll lock until the last dialog closes', async () => {
    const wrapper = mount(makeStackedHost(), { attachTo: document.body })
    await openBoth(wrapper)
    expect(document.body.style.overflow).toBe('hidden')

    press('Escape')
    await nextTick()
    expect(wrapper.vm.upperOpen).toBe(false)
    expect(document.body.style.overflow).toBe('hidden')

    press('Escape')
    await nextTick()
    expect(wrapper.vm.lowerOpen).toBe(false)
    expect(document.body.style.overflow).toBe('')
    wrapper.unmount()
  })

  it('does not let a mounting closed dialog drop an open dialog\'s scroll lock', async () => {
    const opened = mount(makeHost(), { attachTo: document.body })
    opened.vm.open = true
    await nextTick()
    expect(document.body.style.overflow).toBe('hidden')

    // Every dismissable runs its watcher immediately; a closed one used to
    // tear the shared body style down on mount.
    const closed = mount(makeHost(), { attachTo: document.body })
    await nextTick()
    expect(document.body.style.overflow).toBe('hidden')

    closed.unmount()
    expect(document.body.style.overflow).toBe('hidden')
    opened.unmount()
    expect(document.body.style.overflow).toBe('')
  })
})
