/**
 * Both scheduled-task types stay creatable, whatever already exists.
 *
 * rsync tasks and compose-stack backups each get a table once they have jobs,
 * and the collapsed "Advanced" block carries the "New task" button for a type
 * that has none. Gating that block on *both* types being empty left a hole: a
 * single rsync job hid the stack card and the Advanced block at the same time,
 * so there was no way to create a stack backup anywhere on the page.
 */
import { mount } from '@vue/test-utils'
import { describe, expect, it, vi } from 'vitest'

vi.mock('../api/client', () => ({
  getBackups: vi.fn(async () => ({ backups: [], root: '/b', total: 0 })),
  backupPostgres: vi.fn(),
  backupImmich: vi.fn(),
  backupConfigs: vi.fn(),
  getSchedulerJobs: vi.fn(async () => ({ jobs: [] })),
  getRsyncBinary: vi.fn(async () => ({ available: true, variant: 'rsync3', version: '3.4.1' })),
  rsyncPreview: vi.fn(),
  createSchedulerJob: vi.fn(),
  updateSchedulerJob: vi.fn(),
  deleteSchedulerJob: vi.fn(),
  runSchedulerJobNow: vi.fn(),
  getStacks: vi.fn(async () => ({ stacks: [] })),
}))

const { getSchedulerJobs, backupPostgres } = await import('../api/client')
const { setLocale } = await import('../i18n/index.js')
const Backups = (await import('./Backups.vue')).default

const RSYNC_JOB = {
  id: 'r1',
  name: 'Nightly offsite',
  type: 'rsync',
  cron: '30 3 * * *',
  enabled: true,
  params: { src: '/a', dest: '/b', direction: 'push' },
}

const STACK_JOB = {
  id: 's1',
  name: 'Immich appdata',
  type: 'stack_backup',
  cron: '0 4 * * *',
  enabled: true,
  params: { stack_id: 'immich' },
}

async function render(jobs) {
  await setLocale('en')
  getSchedulerJobs.mockResolvedValue({ jobs })
  const wrapper = mount(Backups, {
    global: {
      provide: { toast: () => {} },
      stubs: { SkeletonLoader: true, LoadFailure: true, RouterLink: true },
    },
  })
  await new Promise((resolve) => setTimeout(resolve, 0))
  await wrapper.vm.$nextTick()
  return wrapper
}

/** Open the editor the button belongs to and report the type it was given. */
function newTaskTypes(wrapper) {
  return wrapper.findAll('button')
    .filter((b) => b.text() === 'New task')
    .map((b) => {
      const card = b.element.closest('.tile')
      return card?.querySelector('h3')?.textContent?.trim() || ''
    })
}

describe('creating a scheduled backup task', () => {
  it('offers both types when nothing is scheduled yet', async () => {
    const wrapper = await render([])
    expect(wrapper.find('[data-test="backup-advanced"]').exists()).toBe(true)
    const titles = newTaskTypes(wrapper)
    expect(titles.some((s) => /rsync/i.test(s))).toBe(true)
    expect(titles.some((s) => /stack/i.test(s))).toBe(true)
  })

  it('still offers a stack backup when only an rsync task exists', async () => {
    const wrapper = await render([RSYNC_JOB])
    const titles = newTaskTypes(wrapper)
    expect(titles.some((s) => /stack/i.test(s))).toBe(true)
    expect(titles.some((s) => /rsync/i.test(s))).toBe(true)
  })

  it('still offers an rsync task when only a stack backup exists', async () => {
    const wrapper = await render([STACK_JOB])
    const titles = newTaskTypes(wrapper)
    expect(titles.some((s) => /rsync/i.test(s))).toBe(true)
    expect(titles.some((s) => /stack/i.test(s))).toBe(true)
  })

  it('drops the advanced block once both types have tasks of their own', async () => {
    const wrapper = await render([RSYNC_JOB, STACK_JOB])
    expect(wrapper.find('[data-test="backup-advanced"]').exists()).toBe(false)
    const titles = newTaskTypes(wrapper)
    expect(titles.some((s) => /rsync/i.test(s))).toBe(true)
    expect(titles.some((s) => /stack/i.test(s))).toBe(true)
  })

  it('does not toast a postgres backup that finishes after leave', async () => {
    let finish
    backupPostgres.mockImplementation(() => new Promise((resolve) => { finish = resolve }))
    vi.stubGlobal('confirm', () => true)
    await setLocale('en')
    getSchedulerJobs.mockResolvedValue({ jobs: [] })
    const toast = vi.fn()
    const wrapper = mount(Backups, {
      global: {
        provide: { toast },
        stubs: { SkeletonLoader: true, LoadFailure: true, RouterLink: true },
      },
    })
    await new Promise((resolve) => setTimeout(resolve, 0))
    await wrapper.vm.$nextTick()
    const pg = wrapper.findAll('button').find((b) => b.text() === 'Backup PostgreSQL')
    expect(pg, 'postgres backup button').toBeTruthy()
    await pg.trigger('click')
    wrapper.unmount()
    finish({ ok: true, message: 'dumped', path: '/b/x.sql.bak', size_mb: 1 })
    await new Promise((resolve) => setTimeout(resolve, 0))
    expect(toast).not.toHaveBeenCalled()
    vi.unstubAllGlobals()
  })
})

const { getBackups } = await import('../api/client')

/** Mount under fake timers so the 7s running-poll can be driven by the test. */
async function renderWithFakeTimers(jobs) {
  await setLocale('en')
  getSchedulerJobs.mockResolvedValue({ jobs })
  vi.useFakeTimers()
  const wrapper = mount(Backups, {
    global: {
      provide: { toast: () => {} },
      stubs: { SkeletonLoader: true, LoadFailure: true, RouterLink: true },
    },
  })
  await vi.advanceTimersByTimeAsync(0)
  return wrapper
}

describe('running-task polling', () => {
  it('re-reads jobs while one runs, refreshes artefacts when it finishes, and stops on leave', async () => {
    const wrapper = await renderWithFakeTimers([{ ...RSYNC_JOB, running: true }])
    try {
      expect(getSchedulerJobs).toHaveBeenCalledTimes(1)
      getBackups.mockClear()

      // First armed tick: still running -> another jobs read, no artefact refresh.
      await vi.advanceTimersByTimeAsync(7100)
      expect(getSchedulerJobs).toHaveBeenCalledTimes(2)
      expect(getBackups).not.toHaveBeenCalled()

      // Second tick: the run has finished -> the artefact table refreshes itself.
      getSchedulerJobs.mockResolvedValue({ jobs: [{ ...RSYNC_JOB, running: false, last: { status: 'ok' } }] })
      await vi.advanceTimersByTimeAsync(7100)
      expect(getSchedulerJobs).toHaveBeenCalledTimes(3)
      expect(getBackups).toHaveBeenCalledTimes(1)

      // Idle now: no timer is armed any more.
      await vi.advanceTimersByTimeAsync(30000)
      expect(getSchedulerJobs).toHaveBeenCalledTimes(3)
      wrapper.unmount()
    } finally {
      vi.useRealTimers()
    }
  })

  it('does not keep polling after the page is left mid-run', async () => {
    const wrapper = await renderWithFakeTimers([{ ...RSYNC_JOB, running: true }])
    try {
      expect(getSchedulerJobs).toHaveBeenCalledTimes(1)
      wrapper.unmount()
      await vi.advanceTimersByTimeAsync(60000)
      expect(getSchedulerJobs).toHaveBeenCalledTimes(1)
    } finally {
      vi.useRealTimers()
    }
  })
})
