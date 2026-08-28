import { asArray } from './finite'

/** Shell event: open the AI drawer from any page (Dashboard, etc.). */
export const ASSISTANT_EVENT = 'serverhub:assistant'

/** Open the drawer and optionally seed a brief / page / find turn. */
export function openAssistant(detail = {}) {
  window.dispatchEvent(new CustomEvent(ASSISTANT_EVENT, { detail }))
}

/**
 * Rank catalog rows the same way the backend scores a find query.
 * Used by Cmd+K so "logs" / "docker" jump without opening the drawer.
 */
export function matchCatalog(panels, query, limit = 6) {
  const needle = String(query || '').trim().toLowerCase()
  if (!needle || !Array.isArray(panels)) return []
  const scored = []
  for (const panel of panels) {
    const title = String(panel.title || '').toLowerCase()
    const path = String(panel.path || '').toLowerCase()
    const aliases = asArray(panel.aliases).map((alias) => String(alias).toLowerCase())
    let score = 0
    if (title === needle || panel.id === needle || path === needle || path === `/${needle}`) {
      score = 100
    } else if (aliases.includes(needle)) {
      score = 90
    } else if (title.startsWith(needle) || aliases.some((alias) => alias.startsWith(needle))) {
      score = 80
    } else if (title.includes(needle) || path.includes(needle)) {
      score = 70
    } else if (aliases.some((alias) => alias.length >= 2 && (needle.includes(alias) || alias.includes(needle)))) {
      score = 60
    }
    if (score) scored.push({ ...panel, score })
  }
  scored.sort((a, b) => b.score - a.score || String(a.id).localeCompare(String(b.id)))
  const seen = new Set()
  const out = []
  for (const row of scored) {
    if (seen.has(row.path)) continue
    seen.add(row.path)
    out.push(row)
    if (out.length >= limit) break
  }
  return out
}
