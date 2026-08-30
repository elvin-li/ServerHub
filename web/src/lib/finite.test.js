import { describe, expect, it } from 'vitest'
import { asArray, asRecord, asJsonBody, barPct, finiteN, finiteText, fmtGb, fmtMb, fmtTs, jsonDump, jsonLoad, jsonText, withUnit } from './finite'

describe('asJsonBody leftover answers', () => {
  it('keeps lists and mappings, fail-closes primitives', () => {
    expect(asJsonBody({ a: 1 })).toEqual({ a: 1 })
    expect(asJsonBody(['a'])).toEqual(['a'])
    expect(asJsonBody([])).toEqual([])
    expect(asJsonBody(null)).toEqual({})
    expect(asJsonBody('x')).toEqual({})
    expect(asJsonBody(12)).toEqual({})
  })
})

describe('asRecord leftover mappings', () => {
  it('keeps real objects and fail-closes lists', () => {
    expect(asRecord({ a: 1 })).toEqual({ a: 1 })
    expect(asRecord([])).toEqual({})
    expect(asRecord(['a'])).toEqual({})
    expect(asRecord(null)).toEqual({})
    expect(asRecord('x')).toEqual({})
  })
})

describe('asArray leftover lists', () => {
  it('keeps real arrays and fail-closes mappings', () => {
    expect(asArray(['a'])).toEqual(['a'])
    expect(asArray([])).toEqual([])
    expect(asArray({ 0: 'a', length: 1 })).toEqual([])
    expect(asArray(null)).toEqual([])
    expect(asArray('x')).toEqual([])
  })
})

describe('leftover number clamps', () => {
  it('finiteN rejects Infinity and NaN', () => {
    expect(finiteN(Number.POSITIVE_INFINITY)).toBe('—')
    expect(finiteN(Number.NEGATIVE_INFINITY)).toBe('—')
    expect(finiteN(Number.NaN)).toBe('—')
    expect(finiteN(12)).toBe(12)
    expect(finiteN(0)).toBe(0)
    expect(finiteN(null)).toBe('—')
    expect(finiteN(undefined, 0)).toBe(0)
    expect(finiteN('8080')).toBe(8080)
    expect(finiteN('nope')).toBe('—')
  })

  it('finiteText keeps strings and drops leftover numbers', () => {
    expect(finiteText('1.2GB')).toBe('1.2GB')
    expect(finiteText(Number.POSITIVE_INFINITY)).toBe('—')
    expect(finiteText(Number.NaN)).toBe('—')
    expect(finiteText(3)).toBe(3)
    expect(finiteText('')).toBe('—')
    expect(finiteText('Infinity')).toBe('—')
  })

  it('leftover identifier/version composition drops Infinity then keeps a finite fallback', () => {
    // `form.version || bundle.version || '—'` keeps leftover Infinity because
    // Infinity is truthy. finiteText must run on each branch first.
    expect(finiteText(Number.POSITIVE_INFINITY, '') || finiteText('1.2.3')).toBe('1.2.3')
    expect(finiteText(Number.POSITIVE_INFINITY, '') || finiteText(Number.NaN)).toBe('—')
    expect(finiteText(Number.POSITIVE_INFINITY, '') || finiteText('disk0')).toBe('disk0')
    expect(finiteText('Infinity', '') || finiteText('disk0')).toBe('disk0')
  })

  it('unit formatters omit the unit when the leftover is non-finite', () => {
    expect(fmtGb(500)).toBe('500 GB')
    expect(fmtGb(Number.POSITIVE_INFINITY)).toBe('—')
    expect(fmtMb(33)).toBe('33 MB')
    expect(fmtMb(Number.NaN)).toBe('—')
    expect(withUnit(12, ' ms')).toBe('12 ms')
    expect(withUnit(Number.POSITIVE_INFINITY, ' ms')).toBe('—')
  })

  it('barPct clamps leftover widths to 0', () => {
    expect(barPct(Number.POSITIVE_INFINITY)).toBe(0)
    expect(barPct(Number.NaN)).toBe(0)
    expect(barPct(140)).toBe(100)
    expect(barPct(37)).toBe(37)
  })

  it('fmtTs rejects leftover Infinity timestamps', () => {
    expect(fmtTs(Number.POSITIVE_INFINITY)).toBe('—')
    expect(fmtTs(Number.NaN)).toBe('—')
    expect(fmtTs(0)).toBe('—')
    expect(fmtTs(1_700_000_000)).not.toBe('—')
    expect(fmtTs(1_700_000_000)).not.toContain('Infinity')
  })

  it('leftover action/policy labels drop Infinity then keep a finite fallback', () => {
    // `labels[a] || a` and `it.policy || 'no'` keep leftover Infinity because
    // Infinity is truthy. finiteText must run on the leftover branch first.
    expect(finiteText(Number.POSITIVE_INFINITY, '') || finiteText('start')).toBe('start')
    expect(finiteText(Number.POSITIVE_INFINITY, '') || 'no').toBe('no')
    expect(finiteText('unless-stopped', '') || 'no').toBe('unless-stopped')
  })

  it('leftover join maps drop Infinity per element then keep finite siblings', () => {
    expect(
      ['ok', Number.POSITIVE_INFINITY, 'b', 'Infinity']
        .map((n) => finiteText(n, ''))
        .filter(Boolean)
        .join(', '),
    ).toBe('ok, b')
    expect(
      finiteText(Number.POSITIVE_INFINITY, '') || 'localhost',
    ).toBe('localhost')
  })
})

describe('jsonText leftover circular mappings', () => {
  it('fail-closes circular leftover objects', () => {
    const cycle = {}
    cycle.self = cycle
    expect(jsonDump(cycle)).toBe('')
    expect(jsonText(cycle)).toBe('—')
    expect(jsonText({ a: 1 })).toBe('{"a":1}')
    expect(jsonText({ a: 1 }, '', 2)).toBe('{\n  "a": 1\n}')
  })

  it('fail-closes leftover invalid JSON text', () => {
    expect(jsonLoad('{')).toBe(null)
    expect(jsonLoad('{', {})).toEqual({})
    expect(jsonLoad('{"a":1}')).toEqual({ a: 1 })
    expect(jsonLoad(undefined)).toBe(null)
  })
})
