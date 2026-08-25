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
  backupImmich: vi.fn(),
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
      stubs: { SkeletonLoader: true, LoadFailure: true, RouterLink: true },
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

  it('announces the truncation count as a status region', async () => {
    // The note is the only summary of how many backups exist and it
    // appears/updates silently after every finished backup or refresh for a
    // screen reader — the Ollama model-count treatment.
    const wrapper = await render({ backups: rows(40), root: '/b', total: 137 })
    const note = wrapper.find('.backups-artefacts [role="status"]')
    expect(note.exists()).toBe(true)
    expect(note.text()).toContain('137')
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
    // Scoped to the artefact table: configured rsync/stack cards own their
    // own <tbody> rows. Empty generic tools collapse into <details>.
    expect(wrapper.findAll('.backups-artefacts tbody tr')).toHaveLength(5)
  })

  it('renders the failure banner alone on a failed first load', async () => {
    // A header-only artefact table under the banner used to read as an empty
    // backup listing — on the page where "not listed" means "gone".
    await setLocale('en')
    getBackups.mockRejectedValueOnce(new Error('backend unreachable'))
    const wrapper = mount(Backups, {
      global: {
        provide: { toast: () => {} },
        stubs: { SkeletonLoader: true, LoadFailure: true, RouterLink: true },
      },
    })
    await new Promise((resolve) => setTimeout(resolve, 0))
    await wrapper.vm.$nextTick()
    expect(wrapper.findComponent({ name: 'LoadFailure' }).exists()).toBe(true)
    expect(wrapper.find('.backups-artefacts').exists()).toBe(false)
  })

  it('keeps the stale rows on screen under the banner when a re-read fails', async () => {
    // The LoadFailure contract (Containers, Users accounts): a failed
    // refresh raises the banner *above* what the operator was reading, it
    // does not blank the rows.
    const wrapper = await render({ backups: rows(5), root: '/b', total: 5 })
    getBackups.mockRejectedValueOnce(new Error('backend unreachable'))
    const refreshBtn = wrapper
      .findAll('.toolbar button')
      .find((b) => b.text() === 'Refresh list')
    await refreshBtn.trigger('click')
    await new Promise((resolve) => setTimeout(resolve, 0))
    await wrapper.vm.$nextTick()
    expect(wrapper.findComponent({ name: 'LoadFailure' }).exists()).toBe(true)
    expect(wrapper.findAll('.backups-artefacts tbody tr')).toHaveLength(5)
  })

  it('shows Immich layers and hides empty generic tools', async () => {
    const wrapper = await render({
      backups: rows(1),
      root: '/b',
      total: 1,
      immich: {
        available: true,
        last: { name: 'immich_20260816_033704.sql.gz', size_mb: 33 },
        layers: {
          db: { port: 5433, last: { name: 'immich_20260816_033704.sql.gz', size_mb: 33 } },
          originals: { path: '/Volumes/PhotoVault/Photos Library.photoslibrary', present: true, backup: { last_success: '2026-08-16T03:20:00', size_human: '12G' } },
          bridge: { path: '/Volumes/PhotoVault/PhotosBridge/library', present: true },
          generated: { path: '/Volumes/PhotoVault/immich', present: true, dirs: [{ name: 'thumbs', present: true }] },
          external: { last_success: '2026-08-16T03:40:00' },
        },
      },
    })
    await new Promise((resolve) => setTimeout(resolve, 0))
    await wrapper.vm.$nextTick()
    expect(wrapper.find('[data-test="immich-layers"]').exists()).toBe(true)
    expect(wrapper.text()).toContain('thumbs')
    expect(wrapper.find('[data-test="backup-advanced"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="backup-advanced"]').element.tagName).toBe('DETAILS')
  })
})
