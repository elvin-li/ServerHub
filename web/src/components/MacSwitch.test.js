import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { mount } from '@vue/test-utils'
import MacSwitch from './MacSwitch.vue'

const sfc = readFileSync(join(dirname(fileURLToPath(import.meta.url)), 'MacSwitch.vue'), 'utf8')
const style = sfc.match(/<style[^>]*>([\s\S]*?)<\/style>/)[1]

describe('MacSwitch', () => {
  it('exposes a switch with the current checked state', () => {
    const wrapper = mount(MacSwitch, {
      props: { checked: true, 'aria-label': 'Autostart' },
    })
    const btn = wrapper.get('[role="switch"]')
    expect(btn.attributes('aria-checked')).toBe('true')
    expect(btn.attributes('aria-label')).toBe('Autostart')
    expect(btn.classes()).toContain('mac-switch')
    wrapper.unmount()
  })

  it('emits the next boolean without a checkmark control', async () => {
    const wrapper = mount(MacSwitch, { props: { modelValue: false } })
    expect(wrapper.find('input[type="checkbox"]').exists()).toBe(false)
    await wrapper.get('[role="switch"]').trigger('click')
    expect(wrapper.emitted('update:modelValue')).toEqual([[true]])
    expect(wrapper.emitted('change')).toEqual([[true]])
    wrapper.unmount()
  })

  it('does not toggle when disabled', async () => {
    const wrapper = mount(MacSwitch, { props: { checked: false, disabled: true } })
    await wrapper.get('[role="switch"]').trigger('click')
    expect(wrapper.emitted('change')).toBeUndefined()
    wrapper.unmount()
  })

  it('falls aria-label through to the native button', () => {
    const wrapper = mount(MacSwitch, {
      attrs: { 'aria-label': 'shares.toggle_service' },
    })
    expect(wrapper.get('[role="switch"]').attributes('aria-label')).toBe('shares.toggle_service')
    wrapper.unmount()
  })

  it('paints the checked track with accent, not ok', () => {
    expect(style).toMatch(
      /\.mac-switch\[aria-checked="true"\]\s*\{[^}]*background:\s*var\(--accent\)/,
    )
    expect(style).not.toMatch(
      /\.mac-switch\[aria-checked="true"\]\s*\{[^}]*background:\s*var\(--ok\)/,
    )
    expect(style).not.toMatch(/background:\s*var\(--ok\)/)
    expect(style).toMatch(/\.mac-switch \{[\s\S]*?background:\s*#999/)
    expect(style).toMatch(/\.mac-switch span \{[\s\S]*?background:\s*#fff/)
  })
})
