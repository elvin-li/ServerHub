/**
 * Ratchet on raw `fetch()` in views.
 *
 * The shared client in src/api/client.js is the only caller that checks
 * `res.ok`. A view that calls `fetch()` directly and reads `r.json()`
 * unconditionally writes the *error* body into its data model on a 401 or 500:
 * the page renders `undefined` in every field, and — worse — the AUTH_LOST_EVENT
 * that bounces an expired session to /login never fires, so the operator sits on
 * a silently frozen page.
 *
 * All views now use the shared client. Keep the budget at zero: any new raw
 * fetch would reintroduce silent HTTP failures and bypass session-loss handling.
 */
import { describe, expect, it } from 'vitest'
import { readFileSync, readdirSync } from 'node:fs'
import { resolve } from 'node:path'

const VIEWS = resolve(__dirname)

/** Raw JSON requests in views are forbidden. */
const BUDGET = 0

function viewSources() {
  return readdirSync(VIEWS)
    .filter((f) => f.endsWith('.vue'))
    .map((f) => [f, readFileSync(resolve(VIEWS, f), 'utf8')])
}

/** Count `fetch(` call sites, ignoring the identifier in comments. */
function rawFetchSites(src) {
  return (src.match(/(?<![.\w])fetch\s*\(/g) || []).length
}

describe('raw fetch ratchet', () => {
  it('raw fetch() in views does not grow', () => {
    const perFile = viewSources()
      .map(([name, src]) => [name, rawFetchSites(src)])
      .filter(([, n]) => n > 0)
    const total = perFile.reduce((a, [, n]) => a + n, 0)
    const detail = perFile.map(([n, c]) => `${n}:${c}`).join(' ')
    expect(
      total,
      `Raw fetch() call sites in views grew to ${total} (budget ${BUDGET}). ` +
        `A raw fetch skips the r.ok check, so a 401 body lands in the view ` +
        `and AUTH_LOST_EVENT never fires. Use src/api/client.js. Sites: ${detail}`,
    ).toBeLessThanOrEqual(BUDGET)
  })

  it('migrated views stay on the shared client', () => {
    // These were fixed deliberately; a regression here is a real bug, not drift.
    for (const name of [
      'Apps.vue', 'Bookmarks.vue', 'Files.vue', 'Gateway.vue', 'MainArray.vue',
      'Modules.vue', 'Network.vue', 'Services.vue', 'Settings.vue', 'Tools.vue',
    ]) {
      const src = readFileSync(resolve(VIEWS, name), 'utf8')
      expect(rawFetchSites(src), `${name} must not reintroduce raw fetch()`).toBe(0)
      expect(src, `${name} must import the shared client`).toMatch(
        /from '\.\.\/api\/client'/,
      )
    }
  })
})
