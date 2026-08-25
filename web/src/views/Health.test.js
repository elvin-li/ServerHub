/**
 * A health rescan that fails after leave must not toast, and the level tabs
 * must announce their result count (WCAG 4.1.3): they shrink the table the
 * same way a text filter does, and the text filters already announce
 * "shown / total" through a role="status" span (filterCounts.test.js).
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'

const api = vi.hoisted(() => ({
  getHealthChecks: vi.fn(),
}))

vi.mock('../api/client', () => api)
vi.mock('../i18n', () => ({
  injectI18n: () => ({
    t: (key, params = {}) => Object.entries(params).reduce(
      (text, [name, value]) => text.replace(`{${name}}`, value),
      key,
    ),
    errText: (v) => String(v),
  }),
}))

import Health from './Health.vue'

beforeEach(() => {
  api.getHealthChecks.mockResolvedValue({
    healthy: true,
    summary: { ok: 1, warn: 0, error: 0, total: 1 },
    checks: [],
  })
})

afterEach(() => {
  vi.clearAllMocks()
})

describe('Health level tabs', () => {
  it('announce the filtered result count next to the tabs', async () => {
    api.getHealthChecks.mockResolvedValue({
      healthy: false,
      summary: { ok: 1, warn: 1, error: 1, total: 3 },
      checks: [
        { id: 'a', name: 'Disk', ok: true, level: 'ok', detail: '' },
        { id: 'b', name: 'Firewall', ok: false, level: 'warn', detail: 'off' },
        { id: 'c', name: 'SMART', ok: false, level: 'error', detail: 'failing' },
      ],
    })
    const wrapper = mount(Health, {
      global: {
        provide: { toast: vi.fn() },
        stubs: { SkeletonLoader: true, LoadFailure: true },
      },
    })
    await flushPromises()

    const count = wrapper.find('.tabs .meta-count[role="status"]')
    expect(count.exists(), 'live result count').toBe(true)
    expect(count.text()).toBe('3 / 3')

    const tab = (label) => wrapper.findAll('.tabs button').find((b) => b.text() === label)
    await tab('health.only_issues').trigger('click')
    expect(count.text()).toBe('2 / 3')
    await tab('health.errors').trigger('click')
    expect(count.text()).toBe('1 / 3')
    wrapper.unmount()
  })
})

describe('Health toolbar summary', () => {
  // Rescan updates the passed/warnings/errors counts, and without
  // role=status they changed silently for a screen reader.
  it('announces the summary counts as a live region', async () => {
    api.getHealthChecks.mockResolvedValue({
      healthy: false,
      summary: { ok: 2, warn: 1, error: 1, total: 4 },
      checks: [],
    })
    const wrapper = mount(Health, {
      global: {
        provide: { toast: vi.fn() },
        stubs: { SkeletonLoader: true, LoadFailure: true },
      },
    })
    await flushPromises()

    const summary = wrapper.find('.toolbar .meta[role="status"]')
    expect(summary.exists(), 'live summary counts').toBe(true)
    expect(summary.text()).toContain('health.passed 2')
    expect(summary.text()).toContain('health.warnings 1')
    expect(summary.text()).toContain('health.errors 1')
    wrapper.unmount()
  })
})

describe('Health check LEDs', () => {
  // The LED repeats the Level badge's Pass/Warn/Error text in colour only,
  // so it is decoration — same treatment as the Users admin LED.
  it('hides the row LEDs from the accessibility tree', async () => {
    api.getHealthChecks.mockResolvedValue({
      healthy: false,
      summary: { ok: 1, warn: 1, error: 0, total: 2 },
      checks: [
        { id: 'a', name: 'Disk', ok: true, level: 'ok', detail: '' },
        { id: 'b', name: 'Firewall', ok: false, level: 'warn', detail: 'off' },
      ],
    })
    const wrapper = mount(Health, {
      global: {
        provide: { toast: vi.fn() },
        stubs: { SkeletonLoader: true, LoadFailure: true },
      },
    })
    await flushPromises()

    const leds = wrapper.findAll('tbody .led')
    expect(leds.length).toBe(2)
    for (const led of leds) expect(led.attributes('aria-hidden')).toBe('true')
    wrapper.unmount()
  })
})

describe('Health overall tile', () => {
  // The issues state used to be a bare "⚠️" — an emoji with no words, no
  // locale, and at best a "warning sign" announcement.
  it('spells the state instead of an emoji alone', async () => {
    api.getHealthChecks.mockResolvedValue({
      healthy: false,
      summary: { ok: 1, warn: 0, error: 1, total: 2 },
      checks: [
        { id: 'a', name: 'Disk', ok: true, level: 'ok', detail: '' },
        { id: 'b', name: 'SMART', ok: false, level: 'error', detail: 'failing' },
      ],
    })
    const wrapper = mount(Health, {
      global: {
        provide: { toast: vi.fn() },
        stubs: { SkeletonLoader: true, LoadFailure: true },
      },
    })
    await flushPromises()

    const tiles = wrapper.findAll('.dash-grid .tile .v')
    expect(tiles.at(-1).text()).toBe('⚠️ common.issues')
    wrapper.unmount()
  })
})

describe('Health empty vs filter-miss', () => {
  // A level tab that misses and a scan that produced no checks are
  // different answers (Logs/Services split): "no matching items" on an
  // empty scan hid that there is nothing to filter at all.
  it('says no_match only when a filter hides existing checks', async () => {
    api.getHealthChecks.mockResolvedValue({
      healthy: true,
      summary: { ok: 1, warn: 0, error: 0, total: 1 },
      checks: [{ id: 'a', name: 'Disk', ok: true, level: 'ok', detail: '' }],
    })
    const wrapper = mount(Health, {
      global: {
        provide: { toast: vi.fn() },
        stubs: { SkeletonLoader: true, LoadFailure: true },
      },
    })
    await flushPromises()

    const tab = (label) => wrapper.findAll('.tabs button').find((b) => b.text() === label)
    await tab('health.errors').trigger('click')
    expect(wrapper.find('.empty-row').text()).toBe('common.no_match')
    wrapper.unmount()
  })

  it('says the scan is empty when there are no checks at all', async () => {
    api.getHealthChecks.mockResolvedValue({
      healthy: true,
      summary: { ok: 0, warn: 0, error: 0, total: 0 },
      checks: [],
    })
    const wrapper = mount(Health, {
      global: {
        provide: { toast: vi.fn() },
        stubs: { SkeletonLoader: true, LoadFailure: true },
      },
    })
    await flushPromises()

    expect(wrapper.find('.empty-row').text()).toBe('health.empty')
    wrapper.unmount()
  })
})

describe('Health failed first load', () => {
  // Nothing was fetched, so the LoadFailure banner stands alone: the table
  // used to render its column headers above nothing (the empty-row is
  // loadError-suppressed), claiming a scan that never arrived.
  it('renders the banner without a headers-only table', async () => {
    api.getHealthChecks.mockRejectedValue(new Error('boom'))
    const wrapper = mount(Health, {
      global: {
        provide: { toast: vi.fn() },
        stubs: { SkeletonLoader: true, LoadFailure: true },
      },
    })
    await flushPromises()

    expect(wrapper.findComponent({ name: 'LoadFailure' }).exists()).toBe(true)
    expect(wrapper.find('.table-wrap').exists(), 'no headers-only table').toBe(false)
    wrapper.unmount()
  })

  it('keeps stale rows on screen when a later rescan fails', async () => {
    api.getHealthChecks.mockResolvedValueOnce({
      healthy: true,
      summary: { ok: 1, warn: 0, error: 0, total: 1 },
      checks: [{ id: 'a', name: 'Disk', ok: true, level: 'ok', detail: '' }],
    })
    const wrapper = mount(Health, {
      global: {
        provide: { toast: vi.fn() },
        stubs: { SkeletonLoader: true, LoadFailure: true },
      },
    })
    await flushPromises()
    expect(wrapper.findAll('tbody tr').length).toBe(1)

    api.getHealthChecks.mockRejectedValueOnce(new Error('poll failed'))
    await wrapper.find('.toolbar button.primary').trigger('click')
    await flushPromises()

    expect(wrapper.findComponent({ name: 'LoadFailure' }).exists()).toBe(true)
    expect(wrapper.find('.table-wrap').exists(), 'stale rows stay').toBe(true)
    expect(wrapper.text()).toContain('Disk')
    wrapper.unmount()
  })
})

describe('Health leave-guards', () => {
  it('does not toast a load that fails after leave', async () => {
    let rejectLoad
    api.getHealthChecks.mockImplementation(() => new Promise((_, reject) => { rejectLoad = reject }))
    const toast = vi.fn()
    const wrapper = mount(Health, {
      global: {
        provide: { toast },
        stubs: { SkeletonLoader: true, LoadFailure: true },
      },
    })
    wrapper.unmount()
    rejectLoad(new Error('gone'))
    await flushPromises()
    expect(toast).not.toHaveBeenCalled()
  })
})
