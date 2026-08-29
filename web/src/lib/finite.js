/**
 * Reject leftover Infinity/NaN so templates cannot print those words.
 *
 * JSON leftover numbers survive as JS Infinity/NaN; interpolating them
 * verbatim is how the session toolbar, log sizes and bookmark latency
 * used to render "Infinity".
 */

/** Hostile leftover lists used to be mappings; `.filter`/`.map` then threw. */
export function asArray(value) {
  return Array.isArray(value) ? value : []
}

/** Hostile leftover mappings used to be lists; Object.values/v-for then threw. */
export function asRecord(value) {
  return value != null && typeof value === 'object' && !Array.isArray(value) ? value : {}
}

export function finiteN(value, fallback = '—') {
  if (value == null || value === '') return fallback
  const n = typeof value === 'number' ? value : Number(value)
  return Number.isFinite(n) ? n : fallback
}

export function finiteText(value, fallback = '—') {
  if (value == null || value === '') return fallback
  if (typeof value === 'number' && !Number.isFinite(value)) return fallback
  if (value === 'Infinity' || value === '-Infinity' || value === 'NaN') return fallback
  return value
}

export function fmtGb(value, fallback = '—') {
  const n = finiteN(value, null)
  return n == null ? fallback : `${n} GB`
}

export function fmtMb(value, fallback = '—') {
  const n = finiteN(value, null)
  return n == null ? fallback : `${n} MB`
}

export function withUnit(value, unit, fallback = '—') {
  const n = finiteN(value, null)
  return n == null ? fallback : `${n}${unit}`
}

export function barPct(value) {
  const n = Number(value)
  return Number.isFinite(n) ? Math.max(0, Math.min(100, n)) : 0
}

/** Leftover circular/bigint mappings used to throw out of JSON.stringify. */
export function jsonText(value, fallback = '—') {
  try {
    const text = JSON.stringify(value)
    return text == null ? fallback : text
  } catch {
    return fallback
  }
}
export function fmtTs(value, fallback = '—') {
  const n = finiteN(value, null)
  if (n == null || n <= 0) return fallback
  const d = new Date(n * 1000)
  return Number.isNaN(d.getTime()) ? fallback : d.toLocaleString()
}
