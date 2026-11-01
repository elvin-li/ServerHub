/**
 * Sites page: discovery rows, filtering, rescans, config viewer and nginx actions.
 */
import { afterEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'

const api = vi.hoisted(() => ({
  getSites: vi.fn(),
  getSiteConfig: vi.fn(),
  testNginx: vi.fn(),
  reloadNginx: vi.fn(),
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

import Sites from './Sites.vue'

const PAYLOAD = {
  sites: [
    {
      id: 'a1', name: 'app.example.com', source: 'nginx', url: 'https://app.example.com',
      host: 'app.example.com', port: 443, status: 'ok', detail: 'HTTP 200',
      upstream: 'http://127.0.0.1:3000', config_path: '/etc/nginx/servers/app.conf',
      server_names: ['app.example.com'], actions: ['open', 'view_config', 'test', 'reload'],
      also_seen_in: ['docker'],
    },
    {
      id: 'b2', name: 'immich', source: 'docker', url: 'http://localhost:2283', host: 'localhost',
      port: 2283, status: 'down', detail: 'connection refused', actions: ['open'],
    },
    {
      id: 'c3', name: 'node:5000', source: 'listener', url: 'javascript:alert(1)', port: 5000,
      status: 'weird', actions: ['open'],
    },
  ],
  sources: [
    { id: 'nginx', ok: true, count: 1, error: null },
    { id: 'caddy', ok: false, count: 0, error: 'timeout' },
  ],
  count: 3,
}

function mountPage(toast = vi.fn()) {
  return mount(Sites, {
    attachTo: document.body,
    global: {
      provide: { toast },
      stubs: { LoadFailure: true, SkeletonLoader: true },
    },
  })
}

function button(wrapper, label) {
  return wrapper.findAll('button').find((b) => b.text() === label)
}

afterEach(() => {
  vi.clearAllMocks()
  vi.unstubAllGlobals()
})

describe('Sites page', () => {
  it('rescans on mount and on refresh, and renders every discovered site', async () => {
    api.getSites.mockResolvedValue(PAYLOAD)
    const wrapper = mountPage()
    await flushPromises()
    expect(api.getSites).toHaveBeenCalledWith(true)
    const rows = wrapper.findAll('[data-test="site-row"]')
    expect(rows).toHaveLength(3)
    expect(rows[0].text()).toContain('app.example.com')
    expect(rows[0].text()).toContain('sites.st_ok')
    expect(rows[0].text()).toContain('sites.also')
    expect(rows[1].text()).toContain('sites.st_down')
    // Unknown status degrades, and a non-http URL is never rendered as a link.
    expect(rows[2].text()).toContain('sites.st_unknown')
    expect(rows[2].find('a').exists()).toBe(false)
    expect(rows[0].find('a').attributes('href')).toBe('https://app.example.com')
    expect(rows[0].find('a').attributes('rel')).toContain('noopener')
    expect(wrapper.get('[data-test="sites-count"]').text()).toBe('sites.count')
    expect(wrapper.findAll('[data-test="source-note"]')).toHaveLength(1)

    api.getSites.mockResolvedValue({ sites: [PAYLOAD.sites[1]], sources: [] })
    await button(wrapper, 'common.refresh').trigger('click')
    await flushPromises()
    expect(api.getSites).toHaveBeenLastCalledWith(true)
    expect(wrapper.findAll('[data-test="site-row"]')).toHaveLength(1)
    wrapper.unmount()
  })

  it('filters by text and by source', async () => {
    api.getSites.mockResolvedValue(PAYLOAD)
    const wrapper = mountPage()
    await flushPromises()
    await wrapper.get('input[type="search"]').setValue('2283')
    expect(wrapper.findAll('[data-test="site-row"]')).toHaveLength(1)
    await wrapper.get('input[type="search"]').setValue('3000')
    expect(wrapper.findAll('[data-test="site-row"]').map((r) => r.text())[0]).toContain('app.example.com')
    await wrapper.get('input[type="search"]').setValue('nothing-matches')
    expect(wrapper.get('.empty-row').text()).toBe('sites.no_match')
    await wrapper.get('input[type="search"]').setValue('')
    await wrapper.get('select').setValue('docker')
    expect(wrapper.findAll('[data-test="site-row"]')).toHaveLength(1)
    expect(wrapper.findAll('select option').map((o) => o.element.value)).toEqual(['', 'nginx', 'docker', 'listener'])
    wrapper.unmount()
  })

  it('shows the empty row only for a successful empty scan', async () => {
    api.getSites.mockResolvedValue({ sites: [], sources: [] })
    const wrapper = mountPage()
    await flushPromises()
    expect(wrapper.get('.empty-row').text()).toBe('sites.empty')
    wrapper.unmount()

    const toast = vi.fn()
    api.getSites.mockRejectedValue(new Error('scan failed'))
    const failed = mountPage(toast)
    await flushPromises()
    expect(failed.find('load-failure-stub').exists()).toBe(true)
    expect(failed.find('.empty-row').exists()).toBe(false)
    expect(toast).toHaveBeenCalled()
    failed.unmount()
  })

  it('opens and closes the config viewer only for sites that offer it', async () => {
    api.getSites.mockResolvedValue(PAYLOAD)
    api.getSiteConfig.mockResolvedValue({ id: 'a1', path: '/etc/nginx/servers/app.conf', content: 'server { }' })
    const wrapper = mountPage()
    await flushPromises()
    const configButtons = wrapper.findAll('button').filter((b) => b.text() === 'sites.view_config')
    expect(configButtons).toHaveLength(1)
    await configButtons[0].trigger('click')
    await flushPromises()
    expect(api.getSiteConfig).toHaveBeenCalledWith('a1')
    expect(wrapper.get('[data-test="site-config"]').text()).toBe('server { }')
    await wrapper.get('[role="dialog"]').find('button').trigger('click')
    expect(wrapper.find('[data-test="site-config"]').exists()).toBe(false)
    wrapper.unmount()
  })

  it('offers nginx test/reload only when an nginx site is reloadable', async () => {
    api.getSites.mockResolvedValue({ sites: [PAYLOAD.sites[1]], sources: [] })
    const plain = mountPage()
    await flushPromises()
    expect(button(plain, 'sites.nginx_test')).toBeUndefined()
    plain.unmount()

    const toast = vi.fn()
    api.getSites.mockResolvedValue(PAYLOAD)
    api.testNginx.mockResolvedValue({ ok: true, message: 'syntax ok' })
    api.reloadNginx.mockResolvedValue({ ok: true, message: 'reloaded' })
    vi.stubGlobal('confirm', vi.fn(() => true))
    const wrapper = mountPage(toast)
    await flushPromises()
    await button(wrapper, 'sites.nginx_test').trigger('click')
    await flushPromises()
    expect(wrapper.get('pre[role="status"]').text()).toBe('syntax ok')
    await button(wrapper, 'sites.nginx_reload').trigger('click')
    await flushPromises()
    expect(api.reloadNginx).toHaveBeenCalled()
    expect(api.getSites).toHaveBeenLastCalledWith(true)
    expect(toast).toHaveBeenCalledWith('✅ common.reloaded')
    wrapper.unmount()
  })

  it('drops a scan that lands after leave', async () => {
    let resolve
    api.getSites.mockImplementation(() => new Promise((r) => { resolve = r }))
    const toast = vi.fn()
    const wrapper = mountPage(toast)
    wrapper.unmount()
    resolve(PAYLOAD)
    await flushPromises()
    expect(toast).not.toHaveBeenCalled()
  })

  it('tolerates leftover payload shapes without printing Infinity', async () => {
    api.getSites.mockResolvedValue({
      sites: [{ id: 'x', name: null, host: 'h', port: Infinity, actions: 'nope', also_seen_in: { 0: 'a' } }, 'junk', null],
      sources: 'bad',
    })
    const wrapper = mountPage()
    await flushPromises()
    expect(wrapper.findAll('[data-test="site-row"]')).toHaveLength(1)
    expect(wrapper.text()).not.toContain('Infinity')
    wrapper.unmount()
  })
})
