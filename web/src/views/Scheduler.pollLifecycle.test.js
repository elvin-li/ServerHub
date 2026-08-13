/**
 * Lifecycle of the Scheduler page's conditional running-jobs refresh.
 *
 * The 7s loop is hand-rolled (it only runs while some job reports `running`,
 * so it cannot use lib/poll.js's fixed interval), which means it has to solve
 * the same teardown problem the helper solves with its generation counter: a
 * loadJobs() that is already in flight when the page unmounts lands *after*
 * onBeforeUnmount cleared the armed timer, and used to re-arm the loop — an
 * unmounted page then polled /api/scheduler/jobs every 7 seconds for as long
 * as a job kept running. These tests drive that exact sequence.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { mount } from '@vue/test-utils'

vi.mock('../api/client', () => ({
  createSchedulerJob: vi.fn(),
  deleteSchedulerJob: vi.fn(),
  enableSchedulerJob: vi.fn(),
  getScheduler: vi.fn(async () => ({ timers: [] })),
  getSchedulerJobRuns: vi.fn(async () => ({ runs: [] })),
  getSchedulerJobs: vi.fn(),
  runSchedulerJobNow: vi.fn(),
  updateSchedulerJob: vi.fn(),
}))

const { getSchedulerJobs } = await import('../api/client')
const Scheduler = (await import('./Scheduler.vue')).default

const POLL_MS = 7000

/** Control document.hidden, which jsdom exposes as a prototype getter. */
function setHidden(hidden) {
  Object.defineProperty(document, 'hidden', {
    configurable: true,
    get: () => hidden,
  })
}

function payload(running) {
  return {
    jobs: [{
      id: 'job-1',
      name: 'nightly backup',
      enabled: true,
      running,
      schedule: '0 3 * * *',
      last_status: running ? 'running' : 'ok',
    }],
    system: [],
  }
}

function mountScheduler() {
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

/** Flush pending microtasks under fake timers (flushPromises needs real ones). */
const flush = () => vi.advanceTimersByTimeAsync(0)

describe('the running-jobs refresh loop', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    setHidden(false)
    getSchedulerJobs.mockReset()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('keeps refreshing every 7s while a job is running', async () => {
    getSchedulerJobs.mockResolvedValue(payload(true))
    const wrapper = mountScheduler()
    await flush()
    expect(getSchedulerJobs).toHaveBeenCalledTimes(1)

    await vi.advanceTimersByTimeAsync(POLL_MS)
    expect(getSchedulerJobs).toHaveBeenCalledTimes(2)

    await vi.advanceTimersByTimeAsync(POLL_MS)
    expect(getSchedulerJobs).toHaveBeenCalledTimes(3)
    wrapper.unmount()
  })

  it('goes quiet once nothing is running', async () => {
    getSchedulerJobs
      .mockResolvedValueOnce(payload(true))
      .mockResolvedValue(payload(false))
    const wrapper = mountScheduler()
    await flush()

    // The running job arms one refresh; that refresh reports it finished.
    await vi.advanceTimersByTimeAsync(POLL_MS)
    expect(getSchedulerJobs).toHaveBeenCalledTimes(2)

    // Nothing running any more, so the loop must not re-arm.
    await vi.advanceTimersByTimeAsync(POLL_MS * 10)
    expect(getSchedulerJobs).toHaveBeenCalledTimes(2)
    wrapper.unmount()
  })

  it('stops for good on unmount even when a refresh is still in flight', async () => {
    let release
    getSchedulerJobs
      .mockResolvedValueOnce(payload(true))
      .mockImplementationOnce(() => new Promise((resolve) => { release = resolve }))
    const wrapper = mountScheduler()
    await flush()
    expect(getSchedulerJobs).toHaveBeenCalledTimes(1)

    // The 7s tick fires and its request is outstanding when the user navigates
    // away — the everyday sequence, not an edge case.
    await vi.advanceTimersByTimeAsync(POLL_MS)
    expect(getSchedulerJobs).toHaveBeenCalledTimes(2)

    wrapper.unmount()
    release(payload(true))
    await flush()

    // The late response reports a job still running; the dead page must not
    // schedule another poll on its behalf.
    await vi.advanceTimersByTimeAsync(POLL_MS * 20)
    expect(getSchedulerJobs).toHaveBeenCalledTimes(2)
  })

  it('skips the fetch while the tab is hidden and resumes on return', async () => {
    getSchedulerJobs.mockResolvedValue(payload(true))
    const wrapper = mountScheduler()
    await flush()
    expect(getSchedulerJobs).toHaveBeenCalledTimes(1)

    setHidden(true)
    await vi.advanceTimersByTimeAsync(POLL_MS * 3)
    // The loop stays armed but a hidden tab spends no requests on the host.
    expect(getSchedulerJobs).toHaveBeenCalledTimes(1)

    setHidden(false)
    await vi.advanceTimersByTimeAsync(POLL_MS)
    expect(getSchedulerJobs).toHaveBeenCalledTimes(2)
    wrapper.unmount()
  })
})
