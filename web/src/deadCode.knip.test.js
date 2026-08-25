/**
 * Pins the dead-code check (`npm run check:dead-code`, i.e. knip) to the real
 * SPA entrypoints.
 *
 * Knip only reports what its roots cannot reach, so its value depends entirely
 * on the roots being right. Two silent failure modes are worth guarding:
 *
 *  - The roots drift. The app graph is discovered through the Vite plugin from
 *    `index.html`'s module script (`/src/main.js`); the service worker is
 *    served standalone and is invisible to the import graph, so it is pinned
 *    by hand in `package.json`'s knip `entry`. If either anchor moves without
 *    the config following, knip starts flagging the whole live app — or stops
 *    seeing the worker at all.
 *
 *  - The roots grow too wide. A well-meant `src/**` entry glob would make every
 *    file its own root and the check would pass forever while dead modules
 *    accumulate. The canary test proves an unreferenced file in `src/` is
 *    still reported, so a clean run keeps meaning something.
 */
import { afterEach, describe, expect, it } from 'vitest'
import { execFileSync } from 'node:child_process'
import { existsSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const WEB_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const PACKAGE = JSON.parse(readFileSync(join(WEB_ROOT, 'package.json'), 'utf8'))

describe('the knip roots match the SPA entrypoints', () => {
  it('keeps `check:dead-code` wired to knip', () => {
    expect(PACKAGE.scripts['check:dead-code']).toBe('knip')
  })

  it('reaches the app graph through index.html’s module script', () => {
    const html = readFileSync(join(WEB_ROOT, 'index.html'), 'utf8')
    expect(html).toMatch(/<script type="module" src="\/src\/main\.js">/)
    expect(existsSync(join(WEB_ROOT, 'src', 'main.js'))).toBe(true)
  })

  it('pins the standalone service worker as an explicit entry', () => {
    expect(PACKAGE.knip.entry).toContain('public/sw.js')
    expect(existsSync(join(WEB_ROOT, 'public', 'sw.js'))).toBe(true)
  })

  it('lists no entry wide enough to swallow application modules', () => {
    for (const entry of PACKAGE.knip.entry) {
      expect(entry, `knip entry "${entry}" would hide dead code under src/`)
        .not.toMatch(/^src\//)
    }
  })
})

describe('the check still detects dead code', () => {
  // Unique enough that a crashed run leaves an obviously disposable file.
  const CANARY = join(WEB_ROOT, 'src', '__knip-canary__.js')

  afterEach(() => rmSync(CANARY, { force: true }))

  it('flags an unreferenced module under src/', () => {
    writeFileSync(CANARY, 'export const deadCanary = true\n')
    // --no-exit-code so a positive finding parses as a report, not a throw.
    const stdout = execFileSync(
      process.execPath,
      [join(WEB_ROOT, 'node_modules', 'knip', 'bin', 'knip.js'), '--no-exit-code', '--reporter', 'json'],
      { cwd: WEB_ROOT, encoding: 'utf8' },
    )
    const report = JSON.parse(stdout)
    expect(report.files).toContain('src/__knip-canary__.js')
  }, 60_000)
})
