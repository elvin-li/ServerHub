/**
 * Dictionary loading failure modes of initializeI18n().
 *
 * All three locales are code-split, so a broken deploy, an offline first
 * visit or a storage failure can reject every loader.  With MESSAGES empty,
 * t() returns each key verbatim and the whole UI would render as raw key
 * paths — main.js therefore refuses to mount when initializeI18n() reports
 * that nothing loaded (see main.bootFailure.test.js for that half).
 *
 * The loaders are mocked at the module boundary exactly like the audit's
 * repro: the dynamic import()s themselves reject.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'

const gate = vi.hoisted(() => ({ en: false, zh: false, ja: false }))

vi.mock('./en.js', async (importOriginal) => {
  if (gate.en) throw new Error('simulated chunk failure: en')
  return await importOriginal()
})
vi.mock('./zh-CN.js', async (importOriginal) => {
  if (gate.zh) throw new Error('simulated chunk failure: zh-CN')
  return await importOriginal()
})
vi.mock('./ja.js', async (importOriginal) => {
  if (gate.ja) throw new Error('simulated chunk failure: ja')
  return await importOriginal()
})

/** Fresh i18n module instance so MESSAGES/locale state never leaks between tests. */
async function freshI18n() {
  vi.resetModules()
  return await import('./index.js')
}

beforeEach(() => {
  localStorage.clear()
  gate.en = gate.zh = gate.ja = false
})

describe('initializeI18n() when every dictionary fails', () => {
  it('returns false and t() degrades to raw keys', async () => {
    gate.en = gate.zh = gate.ja = true
    localStorage.setItem('serverhub.locale', 'zh-CN')
    const { initializeI18n, t } = await freshI18n()

    expect(await initializeI18n()).toBe(false)
    expect(t('nav.dashboard')).toBe('nav.dashboard')
    expect(t('common.refresh')).toBe('common.refresh')
  })
})

describe('initializeI18n() partial failures stay non-fatal', () => {
  it('falls back to English when only the selected locale fails', async () => {
    gate.zh = true
    localStorage.setItem('serverhub.locale', 'zh-CN')
    const { initializeI18n, t } = await freshI18n()

    expect(await initializeI18n()).toBe(true)
    // The English dictionary answered, so keys resolve rather than echo.
    expect(t('common.refresh')).not.toBe('common.refresh')
  })

  it('keeps the selected locale when only the English fallback fails', async () => {
    gate.en = true
    localStorage.setItem('serverhub.locale', 'zh-CN')
    const { initializeI18n, t } = await freshI18n()

    // Documented behaviour: a failed fallback fetch is non-fatal as long as
    // the page can render fully translated in the selected locale.
    expect(await initializeI18n()).toBe(true)
    expect(t('common.refresh')).not.toBe('common.refresh')
  })
})
