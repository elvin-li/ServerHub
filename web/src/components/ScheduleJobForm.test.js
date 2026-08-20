/**
 * Scheduler/backup job form: closing the modal mid-request must not write
 * stacks or a preview into an unmounted instance.
 */
import { describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'

const api = vi.hoisted(() => ({
  getStacks: vi.fn(),
  rsyncPreview: vi.fn(),
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

import ScheduleJobForm from './ScheduleJobForm.vue'

function mountForm(props = {}) {
  return mount(ScheduleJobForm, {
    props: { allowedTypes: ['stack_backup'], ...props },
    global: { provide: { toast: vi.fn() } },
  })
}

describe('ScheduleJobForm', () => {
  it('does not write stacks that arrive after unmount', async () => {
    let resolveStacks
    api.getStacks.mockImplementation(() => new Promise((resolve) => {
      resolveStacks = resolve
    }))
    const w = mountForm()
    w.unmount()
    resolveStacks({ stacks: [{ id: 'ghost', name: 'Ghost stack' }] })
    await flushPromises()
    expect(w.text()).not.toContain('Ghost stack')
  })

  it('does not drop stacks when a preview starts while stacks are loading', async () => {
    let resolveStacks
    api.getStacks.mockImplementation(() => new Promise((resolve) => {
      resolveStacks = resolve
    }))
    api.rsyncPreview.mockResolvedValue({
      creates: 0, updates: 0, deletes: 0, total: 0, samples: [],
    })
    const w = mount(ScheduleJobForm, {
      props: { allowedTypes: ['rsync', 'stack_backup'] },
      global: { provide: { toast: vi.fn() } },
    })
    await w.findAll('button').find((b) => b.text() === 'sched.rsync_preview').trigger('click')
    resolveStacks({ stacks: [{ id: 'photos', name: 'Photos' }] })
    await flushPromises()
    await w.findAll('select')[0].setValue('stack_backup')
    await flushPromises()
    expect(w.findAll('option').map((o) => o.text()).join(' ')).toContain('Photos')
    w.unmount()
  })

  it('does not surface a preview that arrives after unmount', async () => {
    api.getStacks.mockResolvedValue({ stacks: [] })
    let resolvePreview
    api.rsyncPreview.mockImplementation(() => new Promise((resolve) => {
      resolvePreview = resolve
    }))
    const w = mount(ScheduleJobForm, {
      props: { allowedTypes: ['rsync'] },
      global: { provide: { toast: vi.fn() } },
    })
    await flushPromises()
    await w.findAll('button').find((b) => b.text() === 'sched.rsync_preview').trigger('click')
    w.unmount()
    resolvePreview({ creates: 3, updates: 0, deletes: 0, total: 3, samples: ['+ a.txt'] })
    await flushPromises()
    expect(w.text()).not.toContain('sched.preview_creates')
  })
})
