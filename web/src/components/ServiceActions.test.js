/**
 * The rendered half of the action source-of-truth contract: the table row and
 * the card must offer the identical set of operations for the same service,
 * because both render through this one component. Before the extraction each
 * mode had its own button block in Services.vue and they drifted.
 */
import { describe, expect, it, vi } from 'vitest'
import { mount } from '@vue/test-utils'

vi.mock('../i18n', () => ({
  injectI18n: () => ({
    t: (key, params = {}) => Object.entries(params).reduce(
      (text, [name, value]) => text.replace(`{${name}}`, value),
      key,
    ),
  }),
}))

import ServiceActions from './ServiceActions.vue'

const service = {
  id: 'jellyfin', name: 'Jellyfin', kind: 'container', state: 'ok',
  url: 'http://nas:8096',
  actions: ['restart', 'stop', 'pause', 'logs', 'open', 'detail'],
}

function mountVariant(variant, extra = {}) {
  return mount(ServiceActions, { props: { service, variant, ...extra } })
}

function offered(wrapper) {
  // Control-action buttons carry the services.act_* label keys (t is mocked
  // to return the key).
  return wrapper.findAll('button')
    .map((b) => b.text())
    .filter((label) => label.startsWith('services.act_'))
}

describe('table and card render identical offers', () => {
  it('offer the same action set, open link and logs for one service', () => {
    const table = mountVariant('table')
    const card = mountVariant('card')
    expect(new Set(offered(card))).toEqual(new Set(offered(table)))
    expect(offered(table).length).toBeGreaterThan(0)
    for (const w of [table, card]) {
      expect(w.find('a').attributes('href')).toBe(service.url)
      expect(w.text()).toContain('services.logs')
      expect(w.text()).toContain('services.more')
    }
  })

  it('omits the open link when the service has no url', () => {
    const w = mount(ServiceActions, { props: { service: { ...service, url: '' }, variant: 'table' } })
    expect(w.find('a').exists()).toBe(false)
  })

  it('hides the logs button when the service cannot provide logs', () => {
    const w = mount(ServiceActions, {
      props: { service: { ...service, can_logs: false }, variant: 'card' },
    })
    expect(w.text()).not.toContain('services.logs')
  })
})

describe('busy state', () => {
  it('disables control buttons but never logs or details', () => {
    const w = mountVariant('table', { busy: true })
    for (const b of w.findAll('button')) {
      const isControl = b.text().startsWith('services.act_')
      expect(b.attributes('disabled') !== undefined, b.text()).toBe(isControl)
    }
  })
})

describe('emits', () => {
  it('emits act/logs/more without executing anything itself', async () => {
    const w = mountVariant('table')
    await w.findAll('button').find((b) => b.text() === 'services.act_stop').trigger('click')
    await w.findAll('button').find((b) => b.text() === 'services.logs').trigger('click')
    await w.findAll('button').find((b) => b.text() === 'services.more').trigger('click')
    expect(w.emitted('act')).toEqual([['stop']])
    expect(w.emitted('logs')).toHaveLength(1)
    expect(w.emitted('more')).toHaveLength(1)
  })
})

describe('drawer variant', () => {
  it('drops the details button (it is the details) and renders slot extras', () => {
    const w = mount(ServiceActions, {
      props: { service, variant: 'drawer' },
      slots: { default: '<button class="danger">extra-admin</button>' },
    })
    expect(w.text()).not.toContain('services.more')
    expect(w.text()).toContain('extra-admin')
  })
})
