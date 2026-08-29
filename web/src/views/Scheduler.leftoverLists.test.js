/**
 * Jobs listing leftover leftover lists: hostile JSON cells must not throw
 * out of v-for / .filter / .some / .length on the Scheduler jobs table.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'

const api = vi.hoisted(() => ({
  createSchedulerJob: vi.fn(),
  deleteSchedulerJob: vi.fn(),
  enableSchedulerJob: vi.fn(),
  getScheduler: vi.fn(async () => ({ timers: [] })),
  getSchedulerJobRuns: vi.fn(async () => ({ runs: [] })),
  getSchedulerJobs: vi.fn(),
  runSchedulerJobNow: vi.fn(),
  updateSchedulerJob: vi.fn(),
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

import Scheduler from './Scheduler.vue'

function mountPage() {
  return mount(Scheduler, {
    global: {
      provide: { toast: vi.fn() },
      stubs: {
        SkeletonLoader: true,
        LoadFailure: true,
        ScheduleJobForm: true,
        RouterLink: true,
      },
    },
  })
}

const JOB = {
  id: 'job-1',
  name: 'nightly',
  type: 'command',
  cron: '0 3 * * *',
  enabled: true,
  running: false,
  last: { status: 'ok', ts: 1 },
}

beforeEach(() => {
  api.getSchedulerJobs.mockResolvedValue({ jobs: [JOB], system: [], types: [] })
  api.getScheduler.mockResolvedValue({ timers: [], count: 0 })
})

afterEach(() => {
  vi.clearAllMocks()
})

describe('Scheduler leftover leftover lists', () => {
  it('does not blank the page when a leftover list cell is null', async () => {
    api.getSchedulerJobs.mockResolvedValue({
      jobs: [null, JOB],
      system: [],
    })
    const wrapper = mountPage()
    await flushPromises()
    expect(wrapper.text()).toContain('nightly')
  })

  it('fail-closes a leftover mapping jobs field without throwing', async () => {
    api.getSchedulerJobs.mockResolvedValue({
      jobs: { id: 'not-a-list' },
      system: [],
    })
    const wrapper = mountPage()
    await flushPromises()
    expect(wrapper.text()).toContain('sched.no_jobs')
  })

  it('a whole-payload list leftover still lists jobs', async () => {
    api.getSchedulerJobs.mockResolvedValue([JOB])
    const wrapper = mountPage()
    await flushPromises()
    expect(wrapper.text()).toContain('nightly')
  })

  it('fail-closes leftover list last without throwing on .status', async () => {
    api.getSchedulerJobs.mockResolvedValue({
      jobs: [{ ...JOB, last: ['not', 'a', 'mapping'] }],
      system: [],
    })
    const wrapper = mountPage()
    await flushPromises()
    expect(wrapper.text()).toContain('nightly')
  })

  it('does not throw when timers leftover is a mapping', async () => {
    api.getScheduler.mockResolvedValue({ timers: { label: 'not-a-list' }, count: 1 })
    const wrapper = mountPage()
    await flushPromises()
    const systemTab = wrapper.findAll('button').find((b) => b.text() === 'sched.tab_system')
    await systemTab.trigger('click')
    expect(wrapper.text()).toContain('common.none')
  })
})
