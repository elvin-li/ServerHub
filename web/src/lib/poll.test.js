/**
 * Behavioral cover for the visibility-aware poller.
 *
 * Every page in the panel schedules its refreshes through this helper, so a
 * regression here is either a hidden tab that keeps hammering the host or a
 * visible tab that silently stops updating. The structural tests elsewhere
 * cannot see either failure, so drive the real timers instead.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { startVisibleInterval } from './poll.js'

const MS = 1000

/** Control document.hidden, which jsdom exposes as a prototype getter. */
function setHidden(hidden) {
  Object.defineProperty(document, 'hidden', {
    configurable: true,
    get: () => hidden,
  })
}

describe('startVisibleInterval', () => {
  let stop

  beforeEach(() => {
    vi.useFakeTimers()
    setHidden(false)
  })

  afterEach(() => {
    stop?.()
    stop = undefined
    vi.useRealTimers()
  })

  it('does not fire before the first interval elapses', async () => {
    const fn = vi.fn()
    stop = startVisibleInterval(fn, MS)

    await vi.advanceTimersByTimeAsync(MS - 1)
    expect(fn).not.toHaveBeenCalled()

    await vi.advanceTimersByTimeAsync(1)
    expect(fn).toHaveBeenCalledTimes(1)
  })

  it('keeps polling on the base interval while ticks succeed', async () => {
    const fn = vi.fn().mockResolvedValue(undefined)
    stop = startVisibleInterval(fn, MS)

    await vi.advanceTimersByTimeAsync(MS * 3)
    expect(fn).toHaveBeenCalledTimes(3)
  })

  it('stops firing once the returned disposer runs', async () => {
    const fn = vi.fn()
    const dispose = startVisibleInterval(fn, MS)

    await vi.advanceTimersByTimeAsync(MS)
    expect(fn).toHaveBeenCalledTimes(1)

    dispose()
    await vi.advanceTimersByTimeAsync(MS * 5)
    expect(fn).toHaveBeenCalledTimes(1)
  })

  it('never schedules a tick while the tab starts hidden', async () => {
    setHidden(true)
    const fn = vi.fn()
    stop = startVisibleInterval(fn, MS)

    await vi.advanceTimersByTimeAsync(MS * 5)
    expect(fn).not.toHaveBeenCalled()
  })

  it('pauses when the tab hides and refreshes immediately when it returns', async () => {
    const fn = vi.fn().mockResolvedValue(undefined)
    stop = startVisibleInterval(fn, MS)

    await vi.advanceTimersByTimeAsync(MS)
    expect(fn).toHaveBeenCalledTimes(1)

    setHidden(true)
    document.dispatchEvent(new Event('visibilitychange'))
    await vi.advanceTimersByTimeAsync(MS * 4)
    expect(fn).toHaveBeenCalledTimes(1)

    setHidden(false)
    document.dispatchEvent(new Event('visibilitychange'))
    await vi.advanceTimersByTimeAsync(0)
    // The immediate catch-up refresh, not a scheduled tick.
    expect(fn).toHaveBeenCalledTimes(2)
  })

  it('backs off exponentially while a tick reports false', async () => {
    const fn = vi.fn().mockResolvedValue(false)
    stop = startVisibleInterval(fn, MS)

    await vi.advanceTimersByTimeAsync(MS)
    expect(fn).toHaveBeenCalledTimes(1)

    // One failure recorded, so the next tick is 1.5x out and must not land early.
    await vi.advanceTimersByTimeAsync(MS * 1.5 - 1)
    expect(fn).toHaveBeenCalledTimes(1)
    await vi.advanceTimersByTimeAsync(1)
    expect(fn).toHaveBeenCalledTimes(2)
  })

  it('backs off when the tick rejects', async () => {
    const fn = vi.fn().mockRejectedValue(new Error('boom'))
    stop = startVisibleInterval(fn, MS)

    await vi.advanceTimersByTimeAsync(MS)
    expect(fn).toHaveBeenCalledTimes(1)

    await vi.advanceTimersByTimeAsync(MS)
    expect(fn).toHaveBeenCalledTimes(1)
    await vi.advanceTimersByTimeAsync(MS * 0.5)
    expect(fn).toHaveBeenCalledTimes(2)
  })

  it('treats undefined as success so legacy callbacks never back off', async () => {
    // Most callers catch their own errors and return undefined; that contract is
    // load-bearing, because backing those off would silently halve refresh rates.
    const fn = vi.fn().mockResolvedValue(undefined)
    stop = startVisibleInterval(fn, MS)

    await vi.advanceTimersByTimeAsync(MS * 2)
    expect(fn).toHaveBeenCalledTimes(2)
  })

  it('recovers the base interval after a failing tick succeeds again', async () => {
    const fn = vi.fn().mockResolvedValueOnce(false).mockResolvedValue(undefined)
    stop = startVisibleInterval(fn, MS)

    await vi.advanceTimersByTimeAsync(MS)
    expect(fn).toHaveBeenCalledTimes(1)

    // Backed-off tick succeeds, clearing the failure counter...
    await vi.advanceTimersByTimeAsync(MS * 1.5)
    expect(fn).toHaveBeenCalledTimes(2)

    // ...so the following tick is back on the base interval.
    await vi.advanceTimersByTimeAsync(MS)
    expect(fn).toHaveBeenCalledTimes(3)
  })

  it('caps the backoff at six times the base interval', async () => {
    const fn = vi.fn().mockResolvedValue(false)
    stop = startVisibleInterval(fn, MS)

    // Drive enough failures that 1.5^failures would exceed the 6x cap.
    await vi.advanceTimersByTimeAsync(MS * 200)
    const saturated = fn.mock.calls.length
    expect(saturated).toBeGreaterThan(5)

    // At the cap the poller must still fire every 6x, not drift further apart.
    await vi.advanceTimersByTimeAsync(MS * 6)
    expect(fn).toHaveBeenCalledTimes(saturated + 1)
  })

  it('stops for good when disposed while a tick is still in flight', async () => {
    // Unmounting a view during an in-flight refresh is the common case, not an
    // edge case: every page disposes its poller while a fetch is outstanding.
    // The timer has already fired by then, so clearTimeout cannot cancel it and
    // the loop must decline to re-arm itself.
    let release
    const fn = vi.fn(() => new Promise((r) => { release = r }))
    const dispose = startVisibleInterval(fn, MS)

    await vi.advanceTimersByTimeAsync(MS)
    expect(fn).toHaveBeenCalledTimes(1)

    dispose()
    release()
    await vi.advanceTimersByTimeAsync(MS * 50)
    expect(fn).toHaveBeenCalledTimes(1)
  })

  it('skips a tick whose timer fired before the hide event arrived', async () => {
    // A browser sets document.hidden *before* dispatching visibilitychange, so a
    // timer that expires in that window runs with no stop() yet recorded. The
    // guard inside the tick body is the only thing that keeps a backgrounded tab
    // from spending one more request on the host.
    const fn = vi.fn().mockResolvedValue(undefined)
    stop = startVisibleInterval(fn, MS)

    await vi.advanceTimersByTimeAsync(MS)
    expect(fn).toHaveBeenCalledTimes(1)

    setHidden(true)
    await vi.advanceTimersByTimeAsync(MS * 3)
    expect(fn).toHaveBeenCalledTimes(1)
  })

  it('removes its visibilitychange listener on dispose', async () => {
    const fn = vi.fn().mockResolvedValue(undefined)
    const dispose = startVisibleInterval(fn, MS)
    dispose()

    setHidden(false)
    document.dispatchEvent(new Event('visibilitychange'))
    await vi.advanceTimersByTimeAsync(MS * 3)
    // A leaked listener would restart the loop and refresh a dead page.
    expect(fn).not.toHaveBeenCalled()
  })
})
