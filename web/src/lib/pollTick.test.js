import { describe, expect, it } from 'vitest'

import { inPollTick, runPollTick } from './pollTick.js'

describe('runPollTick', () => {
  it('marks only the stretch of the callback before its first await', async () => {
    const seen = []
    const done = runPollTick(async () => {
      seen.push(inPollTick())
      await Promise.resolve()
      seen.push(inPollTick())
      return 'ok'
    })
    // Back in the caller, before the callback resumes: not a tick any more.
    expect(inPollTick()).toBe(false)
    await expect(done).resolves.toBe('ok')
    expect(seen).toEqual([true, false])
  })

  it('clears the mark when the callback throws', () => {
    expect(() => runPollTick(() => { throw new Error('boom') })).toThrow('boom')
    expect(inPollTick()).toBe(false)
  })

  it('nests', () => {
    const seen = []
    runPollTick(() => {
      runPollTick(() => seen.push(inPollTick()))
      seen.push(inPollTick())
    })
    seen.push(inPollTick())
    expect(seen).toEqual([true, true, false])
  })
})
