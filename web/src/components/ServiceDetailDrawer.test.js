/**
 * Drawer contract: the adopt form appears only for adoptable auto-discovered
 * entries, admin-only controls disappear for member sessions, forms follow the
 * service prop, and every mutation leaves as an emit (the parent owns busy,
 * confirms and refresh).
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { nextTick } from 'vue'
import { mount } from '@vue/test-utils'

vi.mock('../i18n', () => ({
  injectI18n: () => ({
    t: (key, params = {}) => Object.entries(params).reduce(
      (text, [name, value]) => text.replace(`{${name}}`, value),
      key,
    ),
  }),
}))

import ServiceDetailDrawer from './ServiceDetailDrawer.vue'

const autoService = {
  id: 'auto:8080', name: 'listener 8080', kind: 'auto', state: 'ok',
  actions: ['detail'],
  can_adopt: true,
  adopt_defaults: { id: 'web-app', name: 'Web app', group: 'Apps', url: '', ports: [8080] },
  signature: { name: 'Grafana', category: 'monitoring', confidence: 'high' },
}

const launchdService = {
  id: 'com.example.sync', name: 'Sync agent', kind: 'launchd', state: 'ok',
  actions: ['stop', 'restart', 'logs', 'detail'],
  plist: '/Users/x/Library/LaunchAgents/com.example.sync.plist',
}

function mountDrawer(props = {}) {
  return mount(ServiceDetailDrawer, {
    props: { service: launchdService, ...props },
    global: { provide: { toast: vi.fn() } },
  })
}

beforeEach(() => {
  document.body.style.removeProperty('overflow')
})

describe('adopt form', () => {
  it('renders only for adoptable auto-discovered entries', () => {
    const auto = mountDrawer({ service: autoService })
    expect(auto.text()).toContain('services.sec_adopt')
    expect(auto.text()).toContain('services.identified_as')
    auto.unmount()

    const managed = mountDrawer({ service: launchdService })
    expect(managed.text()).not.toContain('services.sec_adopt')
    managed.unmount()
  })

  it('prefills from adopt_defaults and emits the parsed payload', async () => {
    const w = mountDrawer({ service: autoService })
    const inputs = w.findAll('.form-grid input')
    expect(inputs[0].element.value).toBe('Web app')
    expect(inputs[3].element.value).toBe('8080')

    await inputs[3].setValue('8080, 9090, junk, 99999')
    await w.findAll('button').find((b) => b.text() === 'services.adopt').trigger('click')
    expect(w.emitted('adopt')).toEqual([[{
      id: 'web-app', name: 'Web app', group: 'Apps', url: null, ports: [8080, 9090],
    }]])
    w.unmount()
  })
})

describe('member sessions', () => {
  it('hides the override editor and the hide button for non-admins', () => {
    const member = mountDrawer({ canManage: false })
    expect(member.text()).not.toContain('services.sec_override')
    expect(member.text()).not.toContain('services.hide')
    member.unmount()

    const admin = mountDrawer({ canManage: true })
    expect(admin.text()).toContain('services.sec_override')
    expect(admin.text()).toContain('services.hide')
    admin.unmount()
  })

  it('offers uninstall only when the parent says so', () => {
    const no = mountDrawer({ canUninstall: false })
    expect(no.text()).not.toContain('services.uninstall')
    no.unmount()

    const yes = mountDrawer({ canUninstall: true })
    expect(yes.findAll('button').some((b) => b.text() === 'services.uninstall')).toBe(true)
    yes.unmount()
  })
})

describe('override editor', () => {
  it('emits the normalised body and resets when the service is re-read', async () => {
    const w = mountDrawer({ canManage: true })
    const inputs = w.findAll('.form-grid input')
    await inputs[0].setValue('Nicer name')
    await inputs[1].setValue('')
    await inputs[3].setValue('8443')
    await w.findAll('button').find((b) => b.text() === 'common.save').trigger('click')
    expect(w.emitted('save-override')).toEqual([[{
      name: 'Nicer name', group: null, url: null, port: 8443,
    }]])

    // A detail re-read hands down a fresh object; the form follows it.
    await w.setProps({ service: { ...launchdService, name: 'Renamed by server' } })
    await nextTick()
    expect(w.findAll('.form-grid input')[0].element.value).toBe('Renamed by server')
    w.unmount()
  })
})

describe('actions and dismissal', () => {
  it('emits act/load-logs/hide instead of executing them', async () => {
    const w = mountDrawer({ canManage: true })
    await w.findAll('button').find((b) => b.text() === 'services.act_stop').trigger('click')
    await w.findAll('button').find((b) => b.text() === 'services.logs').trigger('click')
    await w.findAll('button').find((b) => b.text() === 'services.hide').trigger('click')
    expect(w.emitted('act')).toEqual([['stop']])
    expect(w.emitted('load-logs')).toHaveLength(1)
    expect(w.emitted('hide')).toHaveLength(1)
    w.unmount()
  })

  it('shows the inline log section only once the parent supplies text', async () => {
    const w = mountDrawer({ log: null })
    expect(w.find('pre.log:not(.mini-log)').exists()).toBe(false)
    await w.setProps({ log: '', logSource: 'launchd stdout' })
    expect(w.text()).toContain('services.log_empty')
    await w.setProps({ log: 'line one' })
    expect(w.find('pre.log:not(.mini-log)').text()).toBe('line one')
    w.unmount()
  })

  it('closes on Escape and restores the scroll lock on unmount', async () => {
    const w = mountDrawer()
    await nextTick()
    expect(document.body.style.overflow).toBe('hidden')
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true, cancelable: true }))
    expect(w.emitted('close')).toHaveLength(1)
    w.unmount()
    expect(document.body.style.overflow).toBe('')
  })
})
