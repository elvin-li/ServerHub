/**
 * The install dialog's safety surfaces.
 *
 * Two audit follow-ups live here:
 *  - a remote template that uses elevated-access compose directives
 *    (privileged, docker.sock, ...) must show a red warning in the install
 *    dialog, plus a note when it overrides a built-in id — a remote override
 *    otherwise looks exactly like the shipped template;
 *  - a template whose upstream image ships a fixed first-run login
 *    (Calibre-Web's admin/admin123, Mealie, NPM) must surface that pair on
 *    the install success panel with a change-it-now reminder, not leave it
 *    buried in prose notes.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'

const api = vi.hoisted(() => ({
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
  getStackJob: vi.fn(),
  getStacks: vi.fn(),
  installCatalog: vi.fn(),
  manageApp: vi.fn(),
  pollCloudflareLogin: vi.fn(),
  restartCloudflare: vi.fn(),
  restoreCatalogBuiltin: vi.fn(),
  routeCloudflareDns: vi.fn(),
  runAppAutostartNow: vi.fn(),
  runStack: vi.fn(),
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
  injectI18n: () => ({ t: (key) => key }),
}))
vi.mock('vue-router', () => ({
  useRouter: () => ({ push: vi.fn() }),
}))

import Apps from './Apps.vue'

const TEMPLATE = {
  kind: 'docker',
  installed: false,
  featured: false,
  category: 'other',
  desc: 'demo',
  notes: '',
  tags: [],
  ports: [],
  images: [],
  vars: [],
  first_run_credentials: '',
  compose_warnings: [],
  source: 'builtin',
  builtin_available: true,
}

const REMOTE_DANGEROUS = {
  ...TEMPLATE,
  id: 'evil-demo',
  name: 'Evil Demo',
  source: 'remote',
  builtin_available: true,
  compose_warnings: ['docker_socket', 'privileged'],
}

const CALIBRE = {
  ...TEMPLATE,
  id: 'calibre-web',
  name: 'Calibre-Web',
  first_run_credentials: 'admin / admin123',
}

function mountApps() {
  return mount(Apps, {
    global: {
      provide: { toast: vi.fn() },
      // vue-router is module-mocked above, so RouterLink must be stubbed too.
      stubs: { SkeletonLoader: true, LoadFailure: true, 'router-link': true },
    },
  })
}

async function openCatalogAndInstall(wrapper, name) {
  await wrapper.findAll('.tabs button')[2].trigger('click')
  await flushPromises()
  const card = wrapper
    .findAll('.app-card')
    .find((c) => c.find('.app-title').text() === name)
  expect(card, `no card for ${name}`).toBeTruthy()
  await card.find('button.primary').trigger('click')
  await flushPromises()
}

beforeEach(() => {
  vi.clearAllMocks()
  api.getManagedApps.mockResolvedValue({ items: [], counts: null })
  api.getAutostartApps.mockResolvedValue({ items: [], counts: null, groups: [] })
  api.getStacks.mockResolvedValue({ stacks: [], jobs: [] })
  api.getCatalog.mockResolvedValue({
    templates: [REMOTE_DANGEROUS, CALIBRE],
    categories: [],
    counts: {},
    total: 2,
    installed: 0,
  })
  vi.spyOn(window, 'confirm').mockReturnValue(true)
})

describe('elevated-access warnings for remote templates', () => {
  it('lists the flagged directives and the built-in override note in red', async () => {
    const wrapper = mountApps()
    await flushPromises()
    await openCatalogAndInstall(wrapper, 'Evil Demo')

    const boxes = wrapper.findAll('.modal .tpl-danger')
    expect(boxes.length).toBe(2)
    expect(boxes[0].text()).toContain('catalog_remote.warn_title')
    expect(boxes[0].text()).toContain('catalog_remote.warn_docker_socket')
    expect(boxes[0].text()).toContain('catalog_remote.warn_privileged')
    expect(boxes[1].text()).toContain('catalog_remote.overrides_builtin_note')
    wrapper.unmount()
  })

  it('shows nothing extra for a clean built-in template', async () => {
    const wrapper = mountApps()
    await flushPromises()
    await openCatalogAndInstall(wrapper, 'Calibre-Web')

    expect(wrapper.findAll('.modal .tpl-danger').length).toBe(0)
    wrapper.unmount()
  })
})

describe('first-run credentials on the success panel', () => {
  it('surfaces the upstream default login with a change-now reminder', async () => {
    api.installCatalog.mockResolvedValue({
      ok: true,
      message: 'started',
      path: '/tmp/calibre-web',
      first_run_credentials: 'admin / admin123',
    })
    const wrapper = mountApps()
    await flushPromises()
    await openCatalogAndInstall(wrapper, 'Calibre-Web')

    await wrapper.find('.modal .app-actions button.primary').trigger('click')
    await flushPromises()

    const creds = wrapper.find('.modal .first-run-creds')
    expect(creds.exists()).toBe(true)
    expect(creds.text()).toContain('apps.first_run_creds_title')
    expect(creds.text()).toContain('admin / admin123')
    expect(creds.text()).toContain('apps.first_run_creds_hint')
    wrapper.unmount()
  })

  it('stays hidden when the template ships no fixed default login', async () => {
    api.installCatalog.mockResolvedValue({ ok: true, message: 'started', path: '/tmp/x' })
    const wrapper = mountApps()
    await flushPromises()
    await openCatalogAndInstall(wrapper, 'Evil Demo')

    await wrapper.find('.modal .app-actions button.primary').trigger('click')
    await flushPromises()

    expect(wrapper.find('.modal .first-run-creds').exists()).toBe(false)
    wrapper.unmount()
  })

  it('stays hidden when the install fails', async () => {
    api.installCatalog.mockResolvedValue({ ok: false, message: 'boom' })
    const wrapper = mountApps()
    await flushPromises()
    await openCatalogAndInstall(wrapper, 'Calibre-Web')

    await wrapper.find('.modal .app-actions button.primary').trigger('click')
    await flushPromises()

    expect(wrapper.find('.modal .first-run-creds').exists()).toBe(false)
    wrapper.unmount()
  })
})
