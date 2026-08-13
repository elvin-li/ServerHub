import { reactive } from 'vue'

/**
 * Session identity shared across the SPA.
 *
 * The router guard already fetches /api/auth/status on every navigation; this
 * module is where that answer lands, so App.vue (nav filtering) and any view
 * can read the current role without re-fetching.  Nothing here is a security
 * boundary — the backend refuses member requests regardless — it only decides
 * what is worth rendering.
 */
export const authState = reactive({
  known: false,        // at least one status answer has arrived
  authenticated: false,
  username: '',
  role: null,          // 'admin' | 'member' | null
  resources: [],
  canManage: false,
})

/** Fold one /api/auth/status (or login) response into the shared state. */
export function applyAuthStatus(status) {
  if (!status || typeof status !== 'object') return
  authState.known = true
  authState.authenticated = !!status.authenticated
  authState.username = status.authenticated ? String(status.username || '') : ''
  authState.role = status.authenticated ? (status.role || null) : null
  authState.resources = Array.isArray(status.resources) ? status.resources : []
  authState.canManage = !!status.can_manage
}

export function isMember() {
  return authState.authenticated && authState.role === 'member'
}

/**
 * Routes a member session may open, by route name.  Mirrors the backend
 * whitelist (status/services reads + per-account self-service): everything
 * else would only render permission errors, so the guard sends members back
 * to the dashboard and App.vue never shows the entry.
 */
export const MEMBER_ROUTE_NAMES = new Set(['dashboard', 'services', 'account', 'login'])
