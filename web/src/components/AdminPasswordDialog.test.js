/**
 * The admin password field is a bare input — it needs a name, not a placeholder.
 */
import { describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'

vi.mock('../i18n', () => ({
  injectI18n: () => ({ t: (key) => key }),
}))

import AdminPasswordDialog from './AdminPasswordDialog.vue'
import { promptAdminPassword } from '../lib/adminPassword'

describe('AdminPasswordDialog', () => {
  it('names the password field for assistive technology', async () => {
    const wrapper = mount(AdminPasswordDialog)
    const pending = promptAdminPassword()
    await flushPromises()
    const input = wrapper.get('input[type="password"]')
    expect(input.attributes('aria-label')).toBe('adminPrompt.password')
    expect(input.attributes('placeholder')).toBeUndefined()
    await wrapper.find('button').trigger('click')
    await pending
    wrapper.unmount()
  })

  it('resolves a pending prompt when the dialog unmounts', async () => {
    const wrapper = mount(AdminPasswordDialog)
    const pending = promptAdminPassword()
    await flushPromises()
    wrapper.unmount()
    await expect(pending).resolves.toBeNull()
  })
})
