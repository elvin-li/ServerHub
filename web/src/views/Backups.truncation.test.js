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
}))

const { getBackups } = await import('../api/client')
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
    expect(wrapper.findAll('tbody tr')).toHaveLength(5)
  })
})
