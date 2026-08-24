/**
 * Guards for the three states a data-backed page actually has.
 *
 * A page that reads from the API is in one of three states, and they are mutually
 * exclusive:
 *
 *   pending  — the request has not come back. Show a placeholder.
 *   failed   — the request came back an error. Say so, and offer a retry.
 *   loaded   — the request succeeded. Now, and only now, an empty list means the
 *              list is empty.
 *
 * Every regression here has been silent: nothing throws, the page just makes a
 * false statement. Two shapes recurred often enough to be worth pinning:
 *
 *   1. `v-if="!rows.length"` as the only guard. That condition is true both before
 *      the request resolves and after it returns nothing, so pages asserted "no
 *      backups", "no alerts", "no disks", "no brew services" while the first read
 *      was still in flight — and `brew services list` is allowed 20s, so that
 *      claim was readable for twenty seconds.
 *
 *   2. A failure that is only toasted. The toast is gone in four seconds while the
 *      wrong state stays on screen indefinitely with no way to retry. In the worst
 *      cases the fallback branch said "Loading…" (Settings' Docker tab, Tools'
 *      hardware tab), so a dead backend looked like a slow one forever.
 *
 * Division of labour between the two halves below is deliberate. Whether an empty
 * state is reachable during a failure depends on v-if/v-else-if ordering, which
 * source matching cannot read without reimplementing the template compiler — an
 * earlier draft of this file tried and produced thirteen false positives. So that
 * invariant is asserted by mounting with a failing client, where it is exact by
 * construction. Source matching is kept only for properties it can decide
 * reliably, in the same spirit as a11y.test.js.
 */
import { describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { readFileSync, readdirSync } from 'node:fs'
import { resolve } from 'node:path'

function views() {
  return readdirSync(__dirname)
    .filter((f) => f.endsWith('.vue'))
    .map((f) => [f, readFileSync(resolve(__dirname, f), 'utf8')])
}

/** Names of refs a view uses to remember that a read failed. */
function errorRefs(script) {
  return [...script.matchAll(/^const (\w*(?:[Ee]rror)\w*) = ref\(/gm)].map((m) => m[1])
}

/** Something that tells the user a request is in flight or has failed. */
const PENDING_SIGNAL = /SkeletonLoader|common\.loading|common\.scanning|[Ll]oadError|[Tt]abError|\berror\b/

describe('pending is distinguishable from empty (source)', () => {
  it('never leaves a "collection is empty" test as a page\'s only state', () => {
    const offenders = []
    for (const [name, src] of views()) {
      const template = src.split('<script setup>')[0]
      const hasEmptyState = /v-(?:if|else-if)="[^"]*!\s*[\w.?()[\]|]+\.length/.test(template)
      if (hasEmptyState && !PENDING_SIGNAL.test(src)) {
        offenders.push(
          `${name}: renders an empty state with no pending or failure signal, so it `
          + 'cannot tell "not fetched yet" from "fetched, and empty"',
        )
      }
    }
    expect(offenders, offenders.join('\n')).toEqual([])
  })

  it('latches the pending flag instead of deriving it from `loading`', () => {
    // `loading` flips on every poll and every Refresh press. Gating a skeleton on
    // it blanks a populated table each time the operator refreshes; the gate has
    // to mean "has never arrived", which only a latched flag can express.
    const offenders = []
    for (const [name, src] of views()) {
      for (const m of src.matchAll(/<SkeletonLoader[^>]*v-if="!(\w+)"/g)) {
        if (/^(loading|busy)$/.test(m[1])) {
          offenders.push(`${name}: skeleton gated on \`${m[1]}\`, which toggles on every refresh`)
        }
      }
    }
    expect(offenders, offenders.join('\n')).toEqual([])
  })

  it('feeds every failure banner from a ref something actually assigns', () => {
    const offenders = []
    for (const [name, src] of views()) {
      if (!src.includes('LoadFailure')) continue
      const script = src.split('<script setup>')[1] || ''
      const errs = errorRefs(script)
      if (!errs.length) {
        offenders.push(`${name}: renders LoadFailure but declares no error ref`)
        continue
      }
      // Assigned from something other than the empty string, i.e. a real failure.
      const assigned = errs.some((e) =>
        new RegExp(`${e}\\.value(?:\\.\\w+)?\\s*=\\s*(?!''|"")`).test(script)
        || new RegExp(`${e}\\.value\\s*=\\s*\\{`).test(script),
      )
      if (!assigned) {
        offenders.push(`${name}: declares ${errs.join('/')} but never records a failure in it`)
      }
    }
    expect(offenders, offenders.join('\n')).toEqual([])
  })

  it('clears the failure on the next success, so no banner is sticky', () => {
    const offenders = []
    for (const [name, src] of views()) {
      if (!src.includes('LoadFailure')) continue
      const script = src.split('<script setup>')[1] || ''
      for (const err of errorRefs(script)) {
        // Three spellings in use: a plain ref, a keyed field on an object ref, and
        // a replaced object literal carrying a cleared key.
        const cleared =
          new RegExp(`${err}\\.value(?:\\.\\w+)?\\s*=\\s*(?:''|"")`).test(script)
          || new RegExp(`${err}\\.value\\s*=\\s*\\{[^}]*:\\s*(?:''|"")`).test(script)
        if (!cleared) {
          offenders.push(`${name}: ${err} is set on failure but never cleared on success`)
        }
      }
    }
    expect(offenders, offenders.join('\n')).toEqual([])
  })
})

// ── behavioural half ────────────────────────────────────────────────────────
vi.mock('../i18n', () => ({
  injectI18n: () => ({ t: (k) => k, locale: { value: 'en' }, setLocale: vi.fn() }),
}))
vi.mock('vue-router', () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
  useRoute: () => ({ path: '/', query: {}, params: {}, name: 'home' }),
}))
vi.mock('../lib/poll', () => ({ startVisibleInterval: () => () => {} }))

function withFailingApi(failing) {
  vi.doMock('../api/client', async () => {
    const actual = await vi.importActual('../api/client')
    return Object.fromEntries(
      Object.keys(actual).map((name) => [
        name,
        typeof actual[name] === 'function'
          ? vi.fn(async () => {
              if (failing.includes(name)) throw new Error('backend unreachable')
              return {}
            })
          : actual[name],
      ]),
    )
  })
  vi.resetModules()
}

async function mountFailing(load, failing) {
  withFailingApi(failing)
  const module = await load()
  const wrapper = mount(module.default, {
    global: {
      provide: { toast: vi.fn() },
      stubs: { RouterLink: true, RouterView: true },
      mocks: { $route: { path: '/', query: {}, params: {} }, $router: { push: vi.fn() } },
    },
  })
  await flushPromises()
  return wrapper
}

function release(wrapper) {
  wrapper.unmount()
  vi.doUnmock('../api/client')
  vi.resetModules()
}

describe('a failed first load explains itself', () => {
  // `empty` is the i18n key the view would wrongly render if the failure were
  // swallowed; `t` is stubbed to the key, so its absence is the assertion.
  const CASES = [
    { name: 'Brew', load: () => import('./Brew.vue'), api: ['getBrewServices'], empty: 'brew.empty' },
    { name: 'Audit', load: () => import('./Audit.vue'), api: ['getAuthAudit'], empty: 'audit.empty' },
    { name: 'Alerts', load: () => import('./Alerts.vue'), api: ['getAlerts'], empty: 'alerts.empty' },
    { name: 'Backups', load: () => import('./Backups.vue'), api: ['getBackups'], empty: 'backups.empty' },
    { name: 'Users', load: () => import('./Users.vue'), api: ['getUsers'], empty: 'users.empty' },
    { name: 'Gateway', load: () => import('./Gateway.vue'), api: ['getNginx'], empty: 'gateway.empty' },
    { name: 'Modules', load: () => import('./Modules.vue'), api: ['getModules'], empty: 'common.none' },
    { name: 'VMs', load: () => import('./VMs.vue'), api: ['getVms'], empty: 'vms.empty' },
    { name: 'MainArray', load: () => import('./MainArray.vue'), api: ['getStorage'], empty: 'main_extra.empty_disks' },
    { name: 'Pool', load: () => import('./Pool.vue'), api: ['getStoragePool'], empty: 'pool.empty_members' },
    { name: 'Services', load: () => import('./Services.vue'), api: ['getServices'], empty: 'services.empty' },
    { name: 'Apps', load: () => import('./Apps.vue'), api: ['getManagedApps'], empty: 'apps.managed_empty' },
    { name: 'Logs', load: () => import('./Logs.vue'), api: ['getLogSources'], empty: 'logs.empty' },
    { name: 'WireGuard', load: () => import('./WireGuard.vue'), api: ['getWireguard'], empty: 'wg.no_peers' },
  ]

  for (const { name, load, api, empty } of CASES) {
    it(`${name} shows a retryable banner and drops its empty state`, async () => {
      const wrapper = await mountFailing(load, api)
      const html = wrapper.html()

      expect(html, `${name}: no failure banner`).toContain('load-failure')
      expect(html, `${name}: the server's reason is not shown`).toContain('backend unreachable')
      expect(html, `${name}: no way to retry`).toContain('common.retry')
      expect(html, `${name}: still claims ${empty} after a failed read`).not.toContain(empty)
      expect(html, `${name}: skeleton still up after the load settled`).not.toContain('sk-wrap')

      release(wrapper)
    })
  }

  it('Containers blames the API rather than the Docker engine', async () => {
    // `data` stays null when the list read fails, and the page's fallback branch
    // is "engine is not running" — so a panel-side failure used to be reported as
    // Docker being down, sending the operator to debug the wrong thing.
    const wrapper = await mountFailing(() => import('./Containers.vue'), ['getContainers'])
    const html = wrapper.html()
    expect(html, 'no failure banner').toContain('load-failure')
    expect(html, 'blamed the engine for an API failure').not.toContain('docker.engine_off')
    release(wrapper)
  })

  it('Alerts does not call an API failure a filter mismatch', async () => {
    // The `alerts.empty` placeholder was already guarded, but the failed branch
    // fell through to the level tabs and a table whose only row said "no alerts
    // match this filter" — a filter excuse for a request that never came back.
    const wrapper = await mountFailing(() => import('./Alerts.vue'), ['getAlerts'])
    const html = wrapper.html()
    expect(html, 'no failure banner').toContain('load-failure')
    expect(html, 'called an API failure a filter mismatch').not.toContain('alerts.filter_empty')
    release(wrapper)
  })

  it('Audit does not call an API failure an empty audit trail', async () => {
    // Same shape as Alerts: the guarded placeholder was skipped, but the table
    // rendered anyway with a "None" row — on the page whose whole job is to
    // prove whether events were recorded.
    const wrapper = await mountFailing(() => import('./Audit.vue'), ['getAuthAudit'])
    const html = wrapper.html()
    expect(html, 'no failure banner').toContain('load-failure')
    expect(html, 'called an API failure an empty audit trail').not.toContain('common.none')
    release(wrapper)
  })
})
