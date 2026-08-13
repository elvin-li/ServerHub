/**
 * The backups table is capped, and saying so is the point.
 *
 * `/api/backups` returns the newest 40 rows. It used to return only those rows,
 * so once a nightly dump pushed the count past the cap the older files simply
 * stopped appearing -- on a *backups* page, which is the one place where "not
 * listed" reads as "gone". The endpoint now also reports how many exist and the
 * page says which of those it is showing.
 */
import { mount } from '@vue/test-utils'
import { describe, expect, it, vi } from 'vitest'

vi.mock('../api/client', () => ({
  getBackups: vi.fn(),
  backupPostgres: vi.fn(),
  backupConfigs: vi.fn(),
  // The scheduled-task cards (rsync / stack backups) load alongside the
  // artefact table; empty answers keep them rendered but inert.
  getSchedulerJobs: vi.fn(async () => ({ jobs: [] })),
  getRsyncBinary: vi.fn(async () => ({ available: true, variant: 'rsync3', version: '3.4.1' })),
  rsyncPreview: vi.fn(),
  createSchedulerJob: vi.fn(),
  updateSchedulerJob: vi.fn(),
  deleteSchedulerJob: vi.fn(),
  runSchedulerJobNow: vi.fn(),
  getStacks: vi.fn(async () => ({ stacks: [] })),
}))

const { getBackups } = await import('../api/client')
const { setLocale } = await import('../i18n/index.js')
const Backups = (await import('./Backups.vue')).default

function rows(n) {
  return Array.from({ length: n }, (_, i) => ({
    path: `/b/${i}.tgz`,
    name: `${i}.tgz`,
    dir: '/b',
    size_mb: 1,
    mtime: 1700000000 - i,
  }))
}

async function render(payload) {
  // Every dictionary is code-split, the en fallback included, so English is no
  // longer resident just because the module graph loaded. These assertions read
  // real interpolated copy ("Showing the 40 newest of 137 backup files…"), so
  // pin the locale before mounting — the same convention client.test.js uses.
  await setLocale('en')
  getBackups.mockResolvedValue(payload)
  const wrapper = mount(Backups, {
    global: {
      provide: { toast: () => {} },
      stubs: { SkeletonLoader: true, LoadFailure: true },
    },
  })
  // let onMounted's refresh() settle
  await new Promise((resolve) => setTimeout(resolve, 0))
  await wrapper.vm.$nextTick()
  return wrapper
}

describe('the backups table is honest about its cap', () => {
  it('says nothing when every backup is on screen', async () => {
    const wrapper = await render({ backups: rows(12), root: '/b', total: 12 })
    expect(wrapper.text()).not.toMatch(/newest|Showing/i)
  })

  it('reports how many exist when the list is capped', async () => {
    const wrapper = await render({ backups: rows(40), root: '/b', total: 137 })
    const text = wrapper.text()
    expect(text).toContain('40')
    expect(text).toContain('137')
  })

  it('treats a missing total as "not truncated" rather than as zero', async () => {
    // An older backend does not send `total`. Claiming everything is hidden
    // would be worse than saying nothing.
    const wrapper = await render({ backups: rows(9), root: '/b' })
    expect(wrapper.text()).not.toMatch(/newest|Showing/i)
  })

  it('still shows the empty state when there are genuinely none', async () => {
    const wrapper = await render({ backups: [], root: '/b', total: 0 })
    expect(wrapper.text()).not.toMatch(/newest|Showing/i)
  })

  it('renders one row per backup', async () => {
    const wrapper = await render({ backups: rows(5), root: '/b', total: 5 })
    // Scoped to the artefact table: the scheduled-task cards above it own
    // their own <tbody> rows (including empty-state rows) and, since the
    // mobile-overflow fix, their own .table-wrap as well.
    expect(wrapper.findAll('.backups-artefacts tbody tr')).toHaveLength(5)
  })
})
