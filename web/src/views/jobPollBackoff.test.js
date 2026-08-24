/**
 * The conditional running-job loops must back off while the panel is dead.
 *
 * Backups.vue and Scheduler.vue re-read the job list every 7s while any job
 * reports `running`. That loop cannot use lib/poll.js (it only runs while a
 * job is live), so it also missed the helper's failure backoff: with the
 * panel down mid-run, the stale `running` flag kept both pages asking a host
 * that was not answering every 7 seconds for as long as the tab stayed open —
 * and Backups additionally re-toasted the same failure on every tick.
 *
 * These tests pin the fix: consecutive failures stretch the delay 1.5^n
 * (capped at 6x, mirroring lib/poll.js), one success snaps it back to 7s,
 * and a background tick failure never toasts.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { mount } from '@vue/test-utils'

vi.mock('../api/client', () => ({
  backupConfigs: vi.fn(),
  backupImmich: vi.fn(),
  backupPostgres: vi.fn(),
  createSchedulerJob: vi.fn(),
  deleteSchedulerJob: vi.fn(),
  enableSchedulerJob: vi.fn(),
  getBackups: vi.fn(async () => ({ backups: [], root: '/b', total: 0 })),
  getRsyncBinary: vi.fn(async () => ({ available: true, variant: 'rsync3', version: '3.4.1' })),
  getScheduler: vi.fn(async () => ({ timers: [] })),
  getSchedulerJobRuns: vi.fn(async () => ({ runs: [] })),
  getSchedulerJobs: vi.fn(),
  rsyncPreview: vi.fn(),
  runSchedulerJobNow: vi.fn(),
  updateSchedulerJob: vi.fn(),
}))

const { getSchedulerJobs } = await import('../api/client')
const Backups = (await import('./Backups.vue')).default
const Scheduler = (await import('./Scheduler.vue')).default

const POLL_MS = 7000

function payload(running) {
  return {
    jobs: [{
      id: 'job-1',
      name: 'nightly backup',
      type: 'rsync',
      enabled: true,
      running,
      cron: '0 3 * * *',
      last_status: running ? 'running' : 'ok',
      params: { src: '/a', dest: '/b', direction: 'push' },
    }],
    system: [],
  }
}

function mountView(component, toast) {
  return mount(component, {
    global: {
      provide: { toast },
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

describe.each([
  ['Backups', Backups],
  ['Scheduler', Scheduler],
])('%s running-job loop with the backend unreachable', (name, component) => {
  let toast
  let wrapper

  beforeEach(() => {
    vi.useFakeTimers()
    getSchedulerJobs.mockReset()
    toast = vi.fn()
  })

  afterEach(() => {
    if (wrapper) wrapper.unmount()
    wrapper = undefined
    vi.useRealTimers()
  })

  it('stretches the delay on consecutive failures instead of busy-looping at 7s', async () => {
    getSchedulerJobs
      .mockResolvedValueOnce(payload(true))
      .mockRejectedValue(new Error('backend unreachable'))
    wrapper = mountView(component, toast)
    await flush()
    expect(getSchedulerJobs).toHaveBeenCalledTimes(1)
    toast.mockClear()

    // First tick fails → the next one is due after 7000 * 1.5 = 10500ms.
    await vi.advanceTimersByTimeAsync(POLL_MS)
    expect(getSchedulerJobs).toHaveBeenCalledTimes(2)

    await vi.advanceTimersByTimeAsync(POLL_MS)
    expect(getSchedulerJobs).toHaveBeenCalledTimes(2)
    await vi.advanceTimersByTimeAsync(POLL_MS / 2)
    expect(getSchedulerJobs).toHaveBeenCalledTimes(3)

    // Second failure → 7000 * 1.5² = 15750ms until the next attempt.
    await vi.advanceTimersByTimeAsync(15749)
    expect(getSchedulerJobs).toHaveBeenCalledTimes(3)
    await vi.advanceTimersByTimeAsync(1)
    expect(getSchedulerJobs).toHaveBeenCalledTimes(4)

    // The failing background ticks marked the on-screen error banner; they
    // must not additionally toast the same message once per tick.
    expect(toast).not.toHaveBeenCalled()
  })

  it('caps the failure delay at 6x and snaps back to 7s after one success', async () => {
    getSchedulerJobs
      .mockResolvedValueOnce(payload(true))
      .mockRejectedValueOnce(new Error('backend unreachable'))
      .mockRejectedValueOnce(new Error('backend unreachable'))
      .mockRejectedValueOnce(new Error('backend unreachable'))
      .mockRejectedValueOnce(new Error('backend unreachable'))
      .mockRejectedValueOnce(new Error('backend unreachable'))
      .mockResolvedValue(payload(true))
    wrapper = mountView(component, toast)
    await flush()
    expect(getSchedulerJobs).toHaveBeenCalledTimes(1)

    // Walk through five failures: 7s, 10.5s, 15.75s, 23.625s, ~35.44s.
    // 35437.5 is fractional, so the last step advances 35438 — the ≤1ms
    // surplus is why the cap boundary below is probed with a margin.
    for (const delay of [7000, 10500, 15750, 23625, 35438]) {
      await vi.advanceTimersByTimeAsync(delay)
    }
    expect(getSchedulerJobs).toHaveBeenCalledTimes(6)

    // Five consecutive failures: 7000 * 1.5⁵ ≈ 53s, capped at 6x = 42s.
    await vi.advanceTimersByTimeAsync(41000)
    expect(getSchedulerJobs).toHaveBeenCalledTimes(6)
    await vi.advanceTimersByTimeAsync(1000)
    expect(getSchedulerJobs).toHaveBeenCalledTimes(7)

    // That call succeeded (job still running) → back to the normal 7s cadence.
    await vi.advanceTimersByTimeAsync(POLL_MS)
    expect(getSchedulerJobs).toHaveBeenCalledTimes(8)
  })
})
