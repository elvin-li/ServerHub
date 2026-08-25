/**
 * The refresh a finishing job triggers is a background tick, not a click.
 *
 * Apps, Compose and Backups all poll a running stack/backup job and, when it
 * reports not-running, re-read the list it changed so the operator sees the
 * result without pressing Refresh. That re-read fires on the *server's*
 * timing — the operator may be on another tab of the page, mid-form, or
 * reading a log — and all three views routed it through the same load
 * function their Refresh buttons call, whose catch toasted unconditionally.
 * So a panel that answered the job poll and then failed the follow-up read
 * toasted an error the user never asked about (announced assertively by the
 * screen reader), while the on-screen failure state already told the story.
 *
 * jobPollBackoff.test.js pins that the failing *ticks* stay silent; this
 * pins the chain those ticks end with. Manual reloads must keep their toast
 * — deleting the feedback wholesale would break the Refresh buttons — so
 * each case asserts both halves.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'

const api = vi.hoisted(() => ({
  // Backups
  backupConfigs: vi.fn(),
  backupImmich: vi.fn(),
  backupPostgres: vi.fn(),
  createSchedulerJob: vi.fn(),
  deleteSchedulerJob: vi.fn(),
  getBackups: vi.fn(),
  getRsyncBinary: vi.fn(),
  getSchedulerJobs: vi.fn(),
  rsyncPreview: vi.fn(),
  runSchedulerJobNow: vi.fn(),
  updateSchedulerJob: vi.fn(),
  // Compose
  createCompose: vi.fn(),
  getCompose: vi.fn(),
  getStackJob: vi.fn(),
  getStacks: vi.fn(),
  putCompose: vi.fn(),
  runStack: vi.fn(),
  validateCompose: vi.fn(),
  // Apps (the view imports far more; every fn defaults to resolving {})
  checkCatalogRemoteUpdates: vi.fn(),
  createCloudflareTunnel: vi.fn(),
  deleteAppCredential: vi.fn(),
  getAppCredential: vi.fn(),
  getAutostartApps: vi.fn(),
  getCatalog: vi.fn(),
  getCatalogRemote: vi.fn(),
  getCloudflareStatus: vi.fn(),
  getManagedAppDetail: vi.fn(),
  getManagedAppLogs: vi.fn(),
  getManagedApps: vi.fn(),
  installCatalog: vi.fn(),
  manageApp: vi.fn(),
  pollCloudflareLogin: vi.fn(),
  restartCloudflare: vi.fn(),
  restoreCatalogBuiltin: vi.fn(),
  routeCloudflareDns: vi.fn(),
  runAppAutostartNow: vi.fn(),
  saveAppCredential: vi.fn(),
  setAppAutostart: vi.fn(),
  setCatalogRemoteSource: vi.fn(),
  setDockerAutostartPolicy: vi.fn(),
  startCloudflareLogin: vi.fn(),
  startCloudflareToken: vi.fn(),
  startCloudflareTunnel: vi.fn(),
  stopCloudflare: vi.fn(),
  uninstallCatalog: vi.fn(),
}))
vi.mock('../api/client', () => api)
vi.mock('../i18n', () => ({
  injectI18n: () => ({ t: (key) => key, errText: (v) => String(v), locale: { value: 'en' } }),
}))
vi.mock('../lib/poll', () => ({ startVisibleInterval: () => () => {} }))
vi.mock('vue-router', () => ({
  useRouter: () => ({ push: vi.fn() }),
}))

import Apps from './Apps.vue'
import Backups from './Backups.vue'
import Compose from './Compose.vue'

function mountView(component, toast) {
  return mount(component, {
    global: {
      provide: { toast },
      stubs: {
        RouterLink: { template: '<a><slot /></a>' },
        SkeletonLoader: true,
        LoadFailure: true,
        ScheduleJobForm: true,
      },
    },
  })
}

beforeEach(() => {
  for (const fn of Object.values(api)) {
    if (typeof fn?.mockReset === 'function') {
      fn.mockReset()
      fn.mockResolvedValue({})
    }
  }
})

afterEach(() => {
  vi.clearAllMocks()
})

describe('Apps stack-job completion refresh', () => {
  it('stays silent when the follow-up stacks read fails, but manual reloads still toast', async () => {
    api.getStacks.mockResolvedValueOnce({ stacks: [], jobs: [] })
    const toast = vi.fn()
    const wrapper = mountView(Apps, toast)
    await flushPromises()
    toast.mockClear()

    api.getStacks.mockRejectedValue(new Error('backend unreachable'))
    api.getStackJob.mockResolvedValue({ running: false, log: 'done' })
    wrapper.vm.openJob('job-1', 'demo stack')
    await flushPromises()
    expect(toast, 'a background refresh failure must not toast').not.toHaveBeenCalled()

    await wrapper.vm.refresh(true)
    expect(toast).toHaveBeenCalledWith(expect.stringContaining('backend unreachable'))
    wrapper.unmount()
  })
})

describe('Compose stack-job completion refresh', () => {
  it('stays silent when the follow-up stacks read fails, but manual reloads still toast', async () => {
    api.getStacks.mockResolvedValueOnce({ stacks: [{ id: 's1', name: 'S1' }] })
    const toast = vi.fn()
    const wrapper = mountView(Compose, toast)
    await flushPromises()
    toast.mockClear()

    api.getStacks.mockRejectedValue(new Error('backend unreachable'))
    api.getStackJob.mockResolvedValue({ running: false, log: 'done' })
    wrapper.vm.watchJob('job-1')
    await flushPromises()
    expect(toast, 'a background refresh failure must not toast').not.toHaveBeenCalled()
    // The failure is still on screen: loadStacks records it for LoadFailure.
    expect(wrapper.vm.loadError).toContain('backend unreachable')

    await wrapper.vm.loadStacks(true)
    expect(toast).toHaveBeenCalledWith(expect.stringContaining('backend unreachable'))
    wrapper.unmount()
  })
})

describe('Backups task-completion refresh', () => {
  it('stays silent when the follow-up artefact read fails, but manual reloads still toast', async () => {
    vi.useFakeTimers()
    try {
      const running = {
        jobs: [{
          id: 'job-1', name: 'nightly', type: 'rsync', enabled: true, running: true,
          cron: '0 3 * * *', last_status: 'running',
          params: { src: '/a', dest: '/b', direction: 'push' },
        }],
        system: [],
      }
      const finished = { ...running, jobs: [{ ...running.jobs[0], running: false, last_status: 'ok' }] }
      api.getBackups.mockResolvedValueOnce({ backups: [], root: '/b', total: 0 })
      api.getSchedulerJobs.mockResolvedValueOnce(running).mockResolvedValue(finished)
      api.getRsyncBinary.mockResolvedValue({ available: true, variant: 'rsync3', version: '3.4.1' })
      const toast = vi.fn()
      const wrapper = mountView(Backups, toast)
      await vi.advanceTimersByTimeAsync(0)
      toast.mockClear()

      // The 7s running-job poll sees the task end and re-reads the artefacts;
      // that read now fails.
      api.getBackups.mockRejectedValue(new Error('backend unreachable'))
      await vi.advanceTimersByTimeAsync(7000)
      expect(toast, 'a background refresh failure must not toast').not.toHaveBeenCalled()

      await wrapper.vm.refresh(true)
      expect(toast).toHaveBeenCalledWith(expect.stringContaining('backend unreachable'))
      wrapper.unmount()
    } finally {
      vi.useRealTimers()
    }
  })
})
