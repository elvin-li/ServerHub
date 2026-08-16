/**
 * Copying must work, or say it did not, on a plain-http home server.
 *
 * `navigator.clipboard` is a secure-context API. Over `http://192.168.x.x` the
 * whole object is undefined, so the old `navigator.clipboard.writeText(x)
 * .then(ok, fail)` call sites threw a TypeError on the property access, before
 * any promise existed -- the failure handler never ran and the user got a
 * generic page error (or, where the promise was not awaited inside a try, a
 * success toast for a copy that never happened).
 */
import { afterEach, describe, expect, it, vi } from 'vitest'

import { copyToClipboard } from './clipboard'

const original = Object.getOwnPropertyDescriptor(navigator, 'clipboard')

function setClipboard(value) {
  Object.defineProperty(navigator, 'clipboard', {
    value, configurable: true, writable: true,
  })
}

afterEach(() => {
  if (original) Object.defineProperty(navigator, 'clipboard', original)
  else delete navigator.clipboard
  vi.restoreAllMocks()
})

describe('copyToClipboard', () => {
  it('uses the Clipboard API when it is available', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined)
    setClipboard({ writeText })
    expect(await copyToClipboard('restore me')).toBe(true)
    expect(writeText).toHaveBeenCalledWith('restore me')
  })

  it('falls back instead of throwing on a non-secure origin', async () => {
    setClipboard(undefined)
    const exec = vi.fn().mockReturnValue(true)
    document.execCommand = exec
    expect(await copyToClipboard('restore me')).toBe(true)
    expect(exec).toHaveBeenCalledWith('copy')
    // The scratch textarea must not survive the copy.
    expect(document.querySelectorAll('textarea')).toHaveLength(0)
  })

  it('reports failure rather than rejecting when both paths fail', async () => {
    setClipboard({ writeText: vi.fn().mockRejectedValue(new Error('denied')) })
    document.execCommand = vi.fn().mockReturnValue(false)
    expect(await copyToClipboard('restore me')).toBe(false)
  })

  it('falls back to execCommand when permission is denied', async () => {
    setClipboard({ writeText: vi.fn().mockRejectedValue(new Error('denied')) })
    const exec = vi.fn().mockReturnValue(true)
    document.execCommand = exec
    expect(await copyToClipboard('restore me')).toBe(true)
    expect(exec).toHaveBeenCalledWith('copy')
  })

  it('treats an empty value as nothing to copy', async () => {
    const writeText = vi.fn()
    setClipboard({ writeText })
    expect(await copyToClipboard('')).toBe(false)
    expect(await copyToClipboard(null)).toBe(false)
    expect(writeText).not.toHaveBeenCalled()
  })
})
