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

const { getSchedulerJobs } = await import('../api/client')
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
})
