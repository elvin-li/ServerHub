import { beforeEach, describe, expect, it, vi } from 'vitest'
import {
  clearStaleChunkFlag, installChunkRecovery, isChunkLoadError, recoverFromStaleChunk,
} from './chunkRecovery'

function fakeStorage(initial = {}) {
  const data = { ...initial }
  return {
    getItem: (k) => (k in data ? data[k] : null),
    setItem: (k, v) => { data[k] = String(v) },
    removeItem: (k) => { delete data[k] },
    _data: data,
  }
}

describe('isChunkLoadError', () => {
  it('recognises the message browsers actually produce', () => {
    for (const message of [
      'Failed to fetch dynamically imported module: https://host/assets/WireGuard-abc.js',
      'error loading dynamically imported module',
      'Importing a module script failed.',
      'Loading chunk 42 failed.',
    ]) {
      expect(isChunkLoadError(new Error(message)), message).toBe(true)
    }
  })

  it('does not swallow unrelated navigation errors', () => {
    for (const message of [
      'Navigation aborted',
      'TypeError: x is not a function',
      'NetworkError when attempting to fetch resource',
    ]) {
      expect(isChunkLoadError(new Error(message)), message).toBe(false)
    }
  })

  it('tolerates a non-error argument', () => {
    expect(isChunkLoadError(null)).toBe(false)
    expect(isChunkLoadError('Failed to fetch dynamically imported module')).toBe(true)
  })
})

describe('recoverFromStaleChunk', () => {
  it('reloads once so the browser picks up the current shell', () => {
    const storage = fakeStorage()
    const reload = vi.fn()
    expect(recoverFromStaleChunk({ storage, reload })).toBe(true)
    expect(reload).toHaveBeenCalledTimes(1)
  })

  it('refuses a second reload, so a genuinely missing chunk cannot loop', () => {
    const storage = fakeStorage()
    const reload = vi.fn()
    recoverFromStaleChunk({ storage, reload })
    expect(recoverFromStaleChunk({ storage, reload })).toBe(false)
    expect(reload).toHaveBeenCalledTimes(1)
  })

  it('recovers again after a successful navigation clears the guard', () => {
    const storage = fakeStorage()
    const reload = vi.fn()
    recoverFromStaleChunk({ storage, reload })
    clearStaleChunkFlag({ storage })
    expect(recoverFromStaleChunk({ storage, reload })).toBe(true)
    expect(reload).toHaveBeenCalledTimes(2)
  })

  it('declines rather than risking a loop when storage is unavailable', () => {
    const storage = {
      getItem: () => { throw new Error('denied') },
      setItem: () => { throw new Error('denied') },
      removeItem: () => {},
    }
    const reload = vi.fn()
    expect(recoverFromStaleChunk({ storage, reload })).toBe(false)
    expect(reload).not.toHaveBeenCalled()
  })
})

describe('installChunkRecovery', () => {
  let listeners

  beforeEach(() => {
    listeners = {}
  })

  const target = {
    addEventListener: (name, fn) => { listeners[name] = fn },
  }

  it('reloads on vite:preloadError and suppresses the rethrow', () => {
    const storage = fakeStorage()
    const reload = vi.fn()
    installChunkRecovery({ target, storage, reload })

    const preventDefault = vi.fn()
    listeners['vite:preloadError']({ preventDefault })

    expect(preventDefault).toHaveBeenCalled()
    expect(reload).toHaveBeenCalledTimes(1)
  })

  it('does nothing when the environment has no event target', () => {
    expect(() => installChunkRecovery({ target: undefined })).not.toThrow()
  })
})
