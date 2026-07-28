import { t } from '../i18n/index.js'

const DEFAULT_TIMEOUT = 30000 // 30s — generous for docker ops on LAN
const MAX_RETRIES = 2 // retry failed GET requests up to 2 times
const RETRY_DELAY = 800 // ms between retries

/** Fired when the server reports the session is gone, so the SPA can redirect
 *  instead of leaving every page frozen on stale numbers. */
export const AUTH_LOST_EVENT = 'serverhub:auth-lost'

// A page typically has several polls in flight, so one expired session yields a
// burst of 401s.  Latch here (rather than in a component) so the event fires
// once per session loss and Login.vue can clear it after a successful sign-in.
let authLost = false

/** Called by the login view after authenticating, so a later session loss
 *  redirects again instead of being swallowed by the latch. */
export function resetAuthLost() {
  authLost = false
}

/** Turn an error payload into localized text.
 *
 *  The backend raises machine-readable codes (see hub/errors.py):
 *      {"detail": {"code": "files.path_protected", "message": "...",
 *                  "params": {...}}}
 *  We translate `err.<code>` and interpolate params, falling back to the
 *  server's English `message` when this build has no key for the code yet.
 *  Legacy string details are passed through unchanged. */
function errorText(payload, statusText) {
  const d = payload?.detail
  if (d && typeof d === 'object' && !Array.isArray(d) && d.code) {
    const key = `err.${d.code}`
    const translated = t(key, d.params || {})
    // t() returns the key itself when it is missing — prefer the server text.
    if (translated !== key) return translated
    return d.message || d.code
  }
  if (typeof d === 'string' && d) return d
  // FastAPI request-validation errors: detail is a list of
  // {loc: [...], msg, type}.  Rendering the raw array as JSON is unreadable,
  // so summarise it as "field: reason" for each offending field.
  if (Array.isArray(d) && d.length) {
    const parts = d.map((it) => {
      const field = Array.isArray(it?.loc)
        ? it.loc.filter((s) => s !== 'body' && s !== 'query').join('.')
        : ''
      const msg = it?.msg || t('err.request_failed')
      return field ? `${field}: ${msg}` : msg
    })
    return `${t('err.invalid_input')} — ${parts.join('; ')}`
  }
  if (typeof payload?.message === 'string' && payload.message) return payload.message
  return statusText || t('err.request_failed')
}

async function json(url, opts, timeout = DEFAULT_TIMEOUT) {
  const isGet = !opts?.method || opts.method === 'GET'
  const attempts = isGet ? MAX_RETRIES + 1 : 1

  for (let i = 0; i < attempts; i++) {
    const ctrl = new AbortController()
    const timer = setTimeout(() => ctrl.abort(), timeout)
    try {
      const r = await fetch(url, { ...opts, signal: ctrl.signal })
      const j = await r.json().catch(() => ({}))
      if (!r.ok) {
        const err = new Error(errorText(j, r.statusText))
        err.status = r.status
        err.body = j
        err.code = (j?.detail && typeof j.detail === 'object' && j.detail.code) || null
        // A dead session must not look like empty data on every page.  Auth
        // endpoints are exempt: a failed login is a form error, not a lost
        // session, and must not bounce the user off the login page.
        if (r.status === 401 && !url.includes('/api/auth/') && !authLost) {
          authLost = true
          try {
            window.dispatchEvent(new CustomEvent(AUTH_LOST_EVENT, { detail: { url } }))
          } catch {}
        }
        throw err
      }
      return j
    } catch (e) {
      const isLast = i === attempts - 1
      // Retry on network errors / timeouts for GET requests
      if (!isLast && isGet && (e.name === 'AbortError' || e.message === 'Failed to fetch' || e.status === 0)) {
        await new Promise(r => setTimeout(r, RETRY_DELAY * (i + 1)))
        continue
      }
      if (e.name === 'AbortError') {
        const err = new Error(t('err.timeout'))
        err.status = 0
        throw err
      }
      if (!e.status && e.message === 'Failed to fetch') {
        const err = new Error(t('err.offline'))
        err.status = 0
        throw err
      }
      throw e
    } finally {
      clearTimeout(timer)
    }
  }
}

export const getAuthStatus = () => json('/api/auth/status')
export const setupAuth = (username, password, setupToken) => json('/api/auth/setup', {
  method: 'POST', headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ username, password, setup_token: setupToken }),
})
export const loginAuth = (username, password) => json('/api/auth/login', {
  method: 'POST', headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ username, password }),
})
export const logoutAuth = () => json('/api/auth/logout', { method: 'POST' })
export const changeAuthPassword = (username, currentPassword, newPassword) =>
  json('/api/auth/change-password', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username,
      current_password: currentPassword,
      new_password: newPassword,
    }),
  })

export const getStatus = () => json('/api/status')
export const doAction = (target, action) =>
  fetch('/api/action', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ target, action }),
  }).then(async r => {
    const j = await r.json().catch(() => ({}))
    return { ok: r.ok && j.ok !== false, ...j, status: r.status }
  })

export const getMaintenance = () => json('/api/maintenance')
export const runMaintenance = (id) =>
  json(`/api/maintenance/${id}/run`, { method: 'POST' })
export const getMaintenanceLog = (id) => json(`/api/maintenance/${id}/log`)

// Homebrew services. Service actions can run for up to 120 seconds server-side.
const BREW_ACTION_TIMEOUT = 130000
export const getBrewServices = () => json('/api/brew/services')
export const brewAction = (name, action) =>
  json(`/api/brew/services/${encodeURIComponent(name)}/action`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action }),
  }, BREW_ACTION_TIMEOUT)

// Launch-agent uninstall. Preview is read-only; the POST unregisters the agent
// and archives its plist, so it goes through the shared client for consistent
// session-lost handling.
export const getServiceUninstallPreview = (sid) =>
  json(`/api/services/${encodeURIComponent(sid)}/uninstall/preview`)
export const uninstallService = (sid) =>
  json(`/api/services/${encodeURIComponent(sid)}/uninstall`, { method: 'POST' })

// Container operations. Synchronous Docker commands need the backend ceiling plus
// a little transport slack; batch/all execute actions serially across containers.
const CONTAINER_BATCH_TIMEOUT = 900000
const CONTAINER_EXEC_TIMEOUT = 70000
const IMAGE_PULL_TIMEOUT = 610000
const IMAGE_REMOVE_TIMEOUT = 130000
const VOLUME_REMOVE_TIMEOUT = 70000
const CONTAINER_RUN_TIMEOUT = 190000

export const getContainers = (stats = true) =>
  json(`/api/containers?stats=${stats ? 'true' : 'false'}`)
export const containerAction = (name, action) =>
  json(`/api/containers/${encodeURIComponent(name)}/action`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action }),
  })
export const batchContainers = (action, names) =>
  json('/api/containers/batch', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action, names }),
  }, CONTAINER_BATCH_TIMEOUT)
export const containersAll = (action) =>
  json('/api/containers/all', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action }),
  }, CONTAINER_BATCH_TIMEOUT)
export const checkContainerUpdates = () =>
  json('/api/containers/check-updates', { method: 'POST' })
export const updateContainer = (name) =>
  json(`/api/containers/${encodeURIComponent(name)}/update`, { method: 'POST' })
export const execContainer = (name, command) =>
  json(`/api/containers/${encodeURIComponent(name)}/exec`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ command }),
  }, CONTAINER_EXEC_TIMEOUT)
export const setRestartPolicy = (name, policy) =>
  json(`/api/containers/${encodeURIComponent(name)}/restart-policy`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ policy }),
  })
export const inspectContainer = (name) =>
  json(`/api/containers/${encodeURIComponent(name)}/inspect`)
export const runContainer = (body) =>
  json('/api/containers/run', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  }, CONTAINER_RUN_TIMEOUT)
export const getImages = () => json('/api/images')
export const pullImageApi = (image) =>
  json('/api/images/pull', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ image }),
  }, IMAGE_PULL_TIMEOUT)
export const removeImage = (image, force = false) =>
  json('/api/images/remove', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ image, force }),
  }, IMAGE_REMOVE_TIMEOUT)
export const getVolumes = () => json('/api/volumes')
export const createVolume = (name) =>
  json('/api/volumes/create', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name }),
  })
export const removeVolume = (name, force = false) =>
  json('/api/volumes/remove', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, force }),
  }, VOLUME_REMOVE_TIMEOUT)
export const getNetworks = () => json('/api/networks')
export const createNetwork = (name) =>
  json('/api/networks/create', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name }),
  })
export const removeNetwork = (name) =>
  json('/api/networks/remove', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name }),
  })
export const prune = (kind = 'system') =>
  json('/api/prune', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ kind }),
  })

// Compose editor
const COMPOSE_OPERATION_TIMEOUT = 40000
export const getStacks = () => json('/api/stacks')
export const runStack = (id, action = 'update') =>
  json(`/api/stacks/${encodeURIComponent(id)}/run`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action }),
  })
export const getStackJob = (jobId) =>
  json(`/api/stacks/jobs/${encodeURIComponent(jobId)}`)
export const getCompose = (stackId) =>
  json(`/api/compose/${encodeURIComponent(stackId)}`)
export const putCompose = (stackId, content, check = true) =>
  json(`/api/compose/${encodeURIComponent(stackId)}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ content, check }),
  }, COMPOSE_OPERATION_TIMEOUT)
export const validateCompose = (content, cwd) =>
  json('/api/compose/validate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ content, cwd }),
  }, COMPOSE_OPERATION_TIMEOUT)
export const createCompose = (id, name, content) =>
  json('/api/compose', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ id, name, content }),
  }, COMPOSE_OPERATION_TIMEOUT)

export const getStorage = (light = false) => json(`/api/storage${light ? '?light=true' : ''}`)

/* Storage pool (JBOD union, deliberately not RAID).
 *
 * `plan` previews a membership set without persisting it; `save` writes the
 * membership and placement policy into services.yaml.  Neither one touches disk
 * state: no partition table, filesystem, mount or file is modified, and `clear`
 * only forgets the definition — every member keeps its files and stays mounted.
 */
export const getStoragePool = (force = false) =>
  json(`/api/storage/pool${force ? '?force=true' : ''}`)
export const planStoragePool = (mounts, policy) =>
  json('/api/storage/pool/plan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ mounts, policy }),
  })
export const saveStoragePool = (body) =>
  json('/api/storage/pool/save', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
export const clearStoragePool = () => json('/api/storage/pool/clear', { method: 'POST' })

export const getShares = () => json('/api/shares')
export const getLogSources = () => json('/api/logs')
export const getLogTail = (id, lines = 200) =>
  json(`/api/logs/${encodeURIComponent(id)}?lines=${lines}`)
export const getSettings = () => json('/api/settings')
export const putSettings = (body) =>
  json('/api/settings', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
export const getMetrics = (minutes = 60) => json(`/api/metrics?minutes=${minutes}`)
export const getAlerts = (limit = 50) => json(`/api/alerts?limit=${limit}`)
// Read-only: there is deliberately no writer or clear endpoint for the audit
// trail, so this module exposes only the reader.
export const getAuthAudit = (limit = 100) => json(`/api/audit/auth?limit=${limit}`)
export const testNotify = () => json('/api/alerts/test', { method: 'POST' })
export const forceAlertCheck = () => json('/api/alerts/check', { method: 'POST' })
export const getBackups = () => json('/api/backups')
export const backupPostgres = () => json('/api/backups/postgres', { method: 'POST' })
export const backupConfigs = () => json('/api/backups/configs', { method: 'POST' })
export const getCatalog = () => json('/api/catalog')
const CATALOG_INSTALL_TIMEOUT = 900000 // brew cask / pull can exceed 30s

export const installCatalog = (id, variables = {}) =>
  json(
    `/api/catalog/${encodeURIComponent(id)}/install`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ confirm: true, variables }),
    },
    CATALOG_INSTALL_TIMEOUT,
  )
export const uninstallCatalog = (id, { remove_data = true } = {}) =>
  json(
    `/api/catalog/${encodeURIComponent(id)}/uninstall`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ confirm: true, remove_data }),
    },
    CATALOG_INSTALL_TIMEOUT,
  )

// Nginx gateway. Reload can test, reload and fall back to kickstart server-side.
const NGINX_RELOAD_TIMEOUT = 70000
export const getNginx = () => json('/api/nginx')
export const testNginx = () => json('/api/nginx/test', { method: 'POST' })
export const reloadNginx = () =>
  json('/api/nginx/reload', { method: 'POST' }, NGINX_RELOAD_TIMEOUT)

// OrbStack VM creation and clone operations can run for up to ten minutes.
const VM_OPERATION_TIMEOUT = 610000
export const getVms = () => json('/api/vms')
export const createVm = (body) =>
  json('/api/vms/create', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  }, VM_OPERATION_TIMEOUT)
export const vmAction = (vmId, body) =>
  json(`/api/vms/${encodeURIComponent(vmId)}/action`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  }, VM_OPERATION_TIMEOUT)
export const createVmConsoleSession = (consoleId) =>
  json(`/api/vms/${encodeURIComponent(consoleId)}/console/session`, {
    method: 'POST',
  })
export const getHost = () => json('/api/system/host')
// Dashboard used to call these three with a bare fetch().then(r => r.json()),
// which skips the r.ok check: a 401/500 JSON body was written straight into the
// view as if it were live data, and the session-lost event never fired.
export const getSensors = (force = false) =>
  json(`/api/system/sensors?force=${force ? 'true' : 'false'}`)
// Cheap listening-port summary (one lsof call).  This is deliberately the only
// network helper here: the full /api/system/network overview fans out
// networksetup per service, netstat and a docker network inspect per network,
// which is far too much work for a tile that renders a dozen rows.  Network.vue
// calls that endpoint directly.
export const getListeningPorts = (limit = 40) => json(`/api/tools/ports?limit=${limit}`)
// `force` re-probes every link instead of serving the 45s server-side cache.
export const getBookmarks = (force = false) =>
  json(`/api/bookmarks?force=${force ? 'true' : 'false'}`)
export const getModules = () => json('/api/modules')

export const getTerminal = () => json('/api/terminal')

// Unraid parity APIs
export const getUsers = () => json('/api/users')
export const getHealthChecks = () => json('/api/health/checks')
export const getIdentity = () => json('/api/identity')
export const putIdentity = (body) =>
  json('/api/identity', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
export const getDockerInfo = () => json('/api/docker/info')
export const getScheduler = () => json('/api/scheduler')

// Power & remote desktop
export const getPower = () => json('/api/system/power')
export const powerAction = (action, confirm = true) =>
  json('/api/system/power/action', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action, confirm }),
  })
export const enableScreenSharing = () =>
  json('/api/system/screensharing/enable', { method: 'POST' })
export const disableScreenSharing = () =>
  json('/api/system/screensharing/disable', { method: 'POST' })

export function openContainerLogs(name, { tail = 200, follow = true } = {}) {
  const q = new URLSearchParams({
    tail: String(tail),
    follow: follow ? 'true' : 'false',
  })
  return new EventSource(`/api/containers/${encodeURIComponent(name)}/logs?${q}`)
}
