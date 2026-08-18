/**
 * The boot path when no locale dictionary loaded at all.
 *
 * initializeI18n() returning false used to be ignored: the app mounted with
 * empty dictionaries and every surface rendered raw key paths.  main.js now
 * refuses to mount and instead reveals the hardcoded bilingual notice that
 * ships hidden inside index.html (it must not depend on the dictionaries
 * that just failed, and the CSP forbids inline handlers, so the shell only
 * carries the markup and main.js wires the reload button).
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const i18n = vi.hoisted(() => ({
  initializeI18n: vi.fn(),
  provideI18n: vi.fn(),
}))

vi.mock('./i18n', () => i18n)
vi.mock('./router', () => ({
  default: { install: vi.fn() },
  warmLandingChunk: vi.fn(),
}))
vi.mock('./App.vue', () => ({ default: { name: 'AppStub', render: () => null } }))
vi.mock('./theme', () => ({ provideTheme: vi.fn() }))
vi.mock('./serviceWorker', () => ({ registerServiceWorker: vi.fn() }))
const chunkRecovery = vi.hoisted(() => ({
  installChunkRecovery: vi.fn(),
  recoverFromStaleChunk: vi.fn(() => false),
}))

vi.mock('./lib/chunkRecovery', () => chunkRecovery)

const HERE = dirname(fileURLToPath(import.meta.url))

function shell() {
  document.body.innerHTML = `
    <div id="app"></div>
    <div id="i18n-failure" hidden role="alert">
      <p lang="zh-CN">加载失败</p>
      <p lang="en">failed to load</p>
      <button type="button">刷新 / Reload</button>
    </div>
  `
}

async function boot() {
  vi.resetModules()
  await import('./main.js')
  // bootstrap() is fired on import but not awaited; one macrotask flushes it.
  await new Promise((resolve) => setTimeout(resolve, 0))
}

beforeEach(() => {
  vi.clearAllMocks()
  chunkRecovery.recoverFromStaleChunk.mockReturnValue(false)
  shell()
})

describe('bootstrap with every dictionary failed', () => {
  it('does not mount and reveals the hardcoded failure notice', async () => {
    i18n.initializeI18n.mockResolvedValue(false)
    await boot()

    const panel = document.getElementById('i18n-failure')
    expect(panel.hidden).toBe(false)
    expect(panel.querySelector('button')).toBeTruthy()
    // The main app never mounted: nothing rendered into #app, no i18n
    // provider was installed.
    expect(i18n.provideI18n).not.toHaveBeenCalled()
    expect(document.getElementById('app').innerHTML).toBe('')
  })

  it('reloads once instead of showing the notice when the shell is stale', async () => {
    i18n.initializeI18n.mockResolvedValue(false)
    chunkRecovery.recoverFromStaleChunk.mockReturnValue(true)
    await boot()

    expect(chunkRecovery.recoverFromStaleChunk).toHaveBeenCalled()
    expect(document.getElementById('i18n-failure').hidden).toBe(true)
    expect(i18n.provideI18n).not.toHaveBeenCalled()
  })

  it('mounts normally and keeps the notice hidden when a dictionary loaded', async () => {
    i18n.initializeI18n.mockResolvedValue(true)
    await boot()

    expect(i18n.provideI18n).toHaveBeenCalled()
    expect(document.getElementById('i18n-failure').hidden).toBe(true)
  })
})

describe('the shipped shell', () => {
  it('carries the hidden bilingual notice main.js reveals', () => {
    const html = readFileSync(join(HERE, '..', 'index.html'), 'utf8')
    expect(html).toContain('id="i18n-failure"')
    expect(html).toMatch(/<div id="i18n-failure" hidden/)
    // Bilingual, with a reload button — and no inline handler (CSP).
    expect(html).toContain('lang="zh-CN"')
    expect(html).toContain('lang="en"')
    expect(html).not.toMatch(/i18n-failure[\s\S]{0,600}onclick=/)
  })
})
