import { t } from '../i18n/index.js'
import {
  adminPasswordHeaders,
  clearAdminPassword,
  encodeAdminPassword,
  getAdminPassword,
  promptAdminPassword,
  setAdminPassword,
} from '../lib/adminPassword.js'

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
    // Privileged-operation failures carry the tool's own stderr tail in
    // params.detail; appending it keeps the generic "operation failed" text
    // from hiding the actual cause (e.g. wg-quick's error line).
    const detail = typeof d.params?.detail === 'string' ? d.params.detail.trim() : ''
    // t() returns the key itself when it is missing — prefer the server text.
    if (translated !== key) return detail ? `${translated}\n${detail}` : translated
    return detail ? `${d.message || d.code}\n${detail}` : d.message || d.code
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

async function json(url, opts, timeout = DEFAULT_TIMEOUT, adminRetry = 0) {
  const isGet = !opts?.method || opts.method === 'GET'
  const attempts = isGet ? MAX_RETRIES + 1 : 1
  const userSignal = opts?.signal
  const fetchOpts = { ...opts }
  delete fetchOpts.signal

  for (let i = 0; i < attempts; i++) {
    const ctrl = new AbortController()
    const timer = setTimeout(() => ctrl.abort(), timeout)
    const onUserAbort = () => ctrl.abort()
    if (userSignal) {
      if (userSignal.aborted) ctrl.abort()
      else userSignal.addEventListener('abort', onUserAbort, { once: true })
    }
    try {
      const r = await fetch(url, { ...fetchOpts, signal: ctrl.signal })
      const j = await r.json().catch(() => ({}))
      if (!r.ok) {
        const err = new Error(errorText(j, r.statusText))
        err.status = r.status
        err.body = j
        err.code = (j?.detail && typeof j.detail === 'object' && j.detail.code) || null
        // Privileged macOS operations need the operator's administrator
        // password. The server says so with these two codes; ask for it in an
        // in-browser dialog and retry once with it attached. A wrong password
        // clears the cache so the dialog reappears for a second attempt.
        if (
          (err.code === 'admin.password_required' || err.code === 'admin.password_incorrect') &&
          adminRetry < 3
        ) {
          const incorrect = err.code === 'admin.password_incorrect'
          if (incorrect) clearAdminPassword()
          let password = incorrect ? '' : getAdminPassword()
          if (!password) password = await promptAdminPassword(incorrect)
          if (password) {
            setAdminPassword(password)
            const headers = {
              ...(opts?.headers || {}),
              'X-Admin-Password': encodeAdminPassword(password),
            }
            return json(url, { ...opts, headers }, timeout, adminRetry + 1)
          }
        }
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
      const userAborted = Boolean(userSignal?.aborted)
      // Retry on network errors / timeouts for GET requests
      if (!isLast && isGet && !userAborted && (e.name === 'AbortError' || e.message === 'Failed to fetch' || e.status === 0)) {
        await new Promise(r => setTimeout(r, RETRY_DELAY * (i + 1)))
        continue
      }
      if (e.name === 'AbortError') {
        const err = new Error(t(userAborted ? 'err.cancelled' : 'err.timeout'))
        err.status = 0
        err.code = userAborted ? 'cancelled' : 'timeout'
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
      if (userSignal) userSignal.removeEventListener('abort', onUserAbort)
    }
  }
}

export const getAuthStatus = () => json('/api/auth/status')
export const getSetupToken = () => json('/api/auth/setup-token')
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

// ── two-factor (TOTP) ────────────────────────────────────────────────────────
export const verifyTotpLogin = (pending, code) => json('/api/auth/totp/verify', {
  method: 'POST', headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ pending, code }),
})
export const getTotpStatus = () => json('/api/auth/totp')
export const enrollTotp = () => json('/api/auth/totp/enroll', { method: 'POST' })
export const confirmTotp = (code) => json('/api/auth/totp/confirm', {
  method: 'POST', headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ code }),
})
export const disableTotp = (code) => json('/api/auth/totp/disable', {
  method: 'POST', headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ code }),
})
export const regenerateTotpRecovery = (code) => json('/api/auth/totp/recovery', {
  method: 'POST', headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ code }),
})
export const adminDisableTotp = (username) => json('/api/auth/totp/admin-disable', {
  method: 'POST', headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ username }),
})

// ── API keys (admin browser session only; see hub/routers/api_keys_api.py) ──
export const listApiKeys = () => json('/api/api-keys')
export const createApiKey = ({ name, role, expiresDays }) => json('/api/api-keys', {
  method: 'POST', headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    name,
    role,
    ...(expiresDays ? { expires_days: expiresDays } : {}),
  }),
})
export const revokeApiKey = (id) => json(`/api/api-keys/${encodeURIComponent(id)}`, {
  method: 'DELETE',
})

// ── panel accounts (admin browser session only; hub/routers/accounts_api.py) ─
export const listPanelAccounts = () => json('/api/auth/accounts')
export const createPanelAccount = ({ username, password, resources }) =>
  json('/api/auth/accounts', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password, resources: resources || [] }),
  })
export const setPanelAccountResources = (username, resources) =>
  json(`/api/auth/accounts/${encodeURIComponent(username)}/resources`, {
    method: 'PUT', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ resources }),
  })
export const resetPanelAccountPassword = (username, newPassword) =>
  json(`/api/auth/accounts/${encodeURIComponent(username)}/password`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ new_password: newPassword }),
  })
export const deletePanelAccount = (username) =>
  json(`/api/auth/accounts/${encodeURIComponent(username)}`, { method: 'DELETE' })

export const getStatus = () => json('/api/status')
export const doAction = async (target, action) => {
  try {
    const result = await json('/api/action', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target, action }),
    })
    return { ...result, ok: result.ok !== false, status: 200 }
  } catch (error) {
    // Service actions historically return a result object instead of throwing on
    // an HTTP refusal. Keep that component contract while still routing the
    // request through json(), which handles auth loss, timeout and localization.
    if (error.status) {
      return {
        ...(error.body || {}),
        ok: false,
        message: error.message,
        status: error.status,
      }
    }
    throw error
  }
}

// Page-domain APIs. Views deliberately contain no raw fetch() calls: every JSON
// request must pass through json() so a 401 expires the SPA session consistently
// and HTTP failures never get written into page state as if they were data.
const jsonBody = (method, body) => ({
  method,
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body),
})

// Managed applications / autostart / credentials
export const getManagedApps = (force = false) =>
  json(`/api/apps/managed${force ? '?force=true' : ''}`)
export const getManagedAppDetail = (id) =>
  json(`/api/apps/managed/detail?id=${encodeURIComponent(id)}`)
export const manageApp = (id, action, removeData = false) =>
  json('/api/apps/managed/action', jsonBody('POST', { id, action, remove_data: removeData }))
export const getManagedAppLogs = (id, lines = 150) =>
  json(`/api/apps/managed/logs?id=${encodeURIComponent(id)}&lines=${lines}`)
export const getAutostartApps = (force = false) =>
  json(`/api/apps/autostart${force ? '?force=true' : ''}`)
export const setAppAutostart = (id, enabled, policy = undefined) =>
  json('/api/apps/autostart', jsonBody('POST', {
    id,
    enabled: Boolean(enabled),
    ...(policy == null ? {} : { policy }),
  }))
export const setDockerAutostartPolicy = (name, policy) =>
  json('/api/apps/autostart/docker-policy', jsonBody('POST', { name, policy }))
export const runAppAutostartNow = () =>
  json('/api/apps/autostart/run-now', { method: 'POST' })
export const getAppCredential = (id) =>
  json(`/api/apps/credentials?id=${encodeURIComponent(id)}`)
export const saveAppCredential = (body) =>
  json('/api/apps/credentials', jsonBody('POST', body))
export const deleteAppCredential = (id) =>
  json(`/api/apps/credentials?id=${encodeURIComponent(id)}`, { method: 'DELETE' })

// Cloudflare Tunnel operations
export const getCloudflareStatus = () => json('/api/cloudflared/status')
export const startCloudflareLogin = () => json('/api/cloudflared/login', { method: 'POST' })
export const pollCloudflareLogin = () => json('/api/cloudflared/login/poll')
export const createCloudflareTunnel = (name) =>
  json('/api/cloudflared/create', jsonBody('POST', { name }))
export const startCloudflareTunnel = (tunnel) =>
  json('/api/cloudflared/start', jsonBody('POST', { tunnel }))
export const startCloudflareToken = (token, label) =>
  json('/api/cloudflared/start-token', jsonBody('POST', { token, label }))
export const stopCloudflare = () => json('/api/cloudflared/stop', { method: 'POST' })
export const restartCloudflare = () => json('/api/cloudflared/restart', { method: 'POST' })
export const routeCloudflareDns = (tunnel, hostname) =>
  json('/api/cloudflared/route-dns', jsonBody('POST', { tunnel, hostname }))

// Built-in file manager. Downloads remain navigation URLs; uploads still use the
// same shared response/error path but intentionally omit Content-Type so the
// browser can add the multipart boundary.
export const getFilesOverview = () => json('/api/files')
export const listFiles = (path = '', rootId = '') => {
  const query = new URLSearchParams()
  if (path) query.set('path', path)
  if (rootId) query.set('root_id', rootId)
  return json(`/api/files/list?${query}`)
}
export const makeDirectory = (path, name, rootId = '') =>
  json('/api/files/mkdir', jsonBody('POST', { path, name, root_id: rootId || null }))
export const renameFile = (path, newName, rootId = '') =>
  json('/api/files/rename', jsonBody('POST', { path, new_name: newName, root_id: rootId || null }))
export const deleteFile = (path, rootId = '') =>
  json('/api/files/delete', jsonBody('POST', { path, root_id: rootId || null }))
export const uploadFile = (formData) =>
  json('/api/files/upload', { method: 'POST', body: formData })
export const ensureFileBrowser = () =>
  json('/api/files/filebrowser/ensure', { method: 'POST' })
export const stopFileBrowser = () =>
  json('/api/files/filebrowser/stop', { method: 'POST' })

// Storage management
export const setDiskPower = (diskId, action) =>
  json(`/api/storage/disks/${encodeURIComponent(diskId)}/power`, jsonBody('POST', { action }))
export const manageStorageDevice = (deviceId, body) =>
  json(`/api/storage/manage/${encodeURIComponent(deviceId)}`, jsonBody('POST', body))

// Enriched service management
export const getServices = (force = false) =>
  json(`/api/services${force ? '?force=true' : ''}`)
export const getServiceDetail = (id) =>
  json(`/api/services/${encodeURIComponent(id)}/detail`)
export const getServiceLogs = (id, lines = 200) =>
  json(`/api/services/${encodeURIComponent(id)}/logs?lines=${lines}`)
export const bulkServiceAction = (ids, action) =>
  json('/api/services/bulk-action', jsonBody('POST', { ids, action }))
export const updateServiceOverride = (id, body) =>
  json(`/api/services/${encodeURIComponent(id)}/override`, jsonBody('PUT', body))
export const setServiceHidden = (id, hide = true) =>
  json(`/api/services/${encodeURIComponent(id)}/hide`, jsonBody('POST', { hide }))
// Promote an auto-discovered listener into a managed services.yaml entry.
export const adoptService = (id, body = {}) =>
  json(`/api/services/${encodeURIComponent(id)}/adopt`, jsonBody('POST', body))
export const updateServiceScript = (id, body) =>
  json(`/api/services/${encodeURIComponent(id)}/script`, jsonBody('PUT', body))
export const forgetServiceScript = (id) =>
  json(`/api/services/${encodeURIComponent(id)}/script`, { method: 'DELETE' })
export const getServiceSignatures = () => json('/api/services/signatures')
export const upsertServiceSignature = (body) =>
  json('/api/services/signatures', jsonBody('PUT', body))
export const forgetServiceSignature = (slug) =>
  json(`/api/services/signatures/${encodeURIComponent(slug)}`, { method: 'DELETE' })

// Network configuration and diagnostics
export const getSystemNetwork = (force = false) =>
  json(`/api/system/network?force=${force ? 'true' : 'false'}`)
export const runAliasAutoBind = () =>
  json('/api/system/network/alias/auto/run', { method: 'POST' })
export const runNetworkFailover = () =>
  json('/api/system/network/failover/run', { method: 'POST' })
export const updateAliasAuto = (body) =>
  json('/api/system/network/alias/auto', jsonBody('PUT', body))
export const switchNetworkProfile = (profile) =>
  json('/api/system/network/profile', jsonBody('POST', { profile }))
export const setNetworkServiceOrder = (services) =>
  json('/api/system/network/order', jsonBody('POST', { services }))
export const setNetworkServiceEnabled = (name, enabled) =>
  json(`/api/system/network/services/${encodeURIComponent(name)}/enabled`, jsonBody('POST', { enabled }))
export const addNetworkAlias = (body) =>
  json('/api/system/network/alias/add', jsonBody('POST', body))
export const removeNetworkAlias = (body) =>
  json('/api/system/network/alias/remove', jsonBody('POST', body))
export const setNetworkDhcp = (name) =>
  json(`/api/system/network/services/${encodeURIComponent(name)}/dhcp`, { method: 'POST' })
export const setNetworkManual = (name, body) =>
  json(`/api/system/network/services/${encodeURIComponent(name)}/manual`, jsonBody('POST', body))
export const setNetworkDns = (name, servers) =>
  json(`/api/system/network/services/${encodeURIComponent(name)}/dns`, jsonBody('POST', { servers }))
export const setWifiPower = (state) =>
  json(`/api/system/network/wifi/${encodeURIComponent(state)}`, { method: 'POST' })
export const lookupNetworkDns = (host) =>
  json(`/api/system/network/dns-lookup?host=${encodeURIComponent(host)}`)
export const setContainerPorts = (container, ports) =>
  json(`/api/system/network/docker/ports/${encodeURIComponent(container)}`, jsonBody('POST', { ports }))
export const connectContainerNetwork = (mode, network, container, force = false) =>
  json(`/api/system/network/docker/${mode === 'disconnect' ? 'disconnect' : 'connect'}`, jsonBody('POST', {
    network,
    container,
    force: mode === 'disconnect' && force,
  }))

// Settings / diagnostics
export const getSystemSettings = () => json('/api/settings/system')
// Alert thresholds, defaults merged in server-side. The storage page reads these
// so its SMART notice grades a disk with the same limits the alert sweep uses --
// a page that said "temperature fine" while the alert log said otherwise would be
// a bug the operator cannot diagnose.
export const getThresholds = () => json('/api/settings/thresholds')
export const setPowerSetting = (key, value) =>
  json('/api/settings/power', jsonBody('POST', { key, value: Number(value) }))
export const generateDiagnostics = () => json('/api/diagnostics')

// Tools domain
export const getToolsCatalog = () => json('/api/tools/catalog')
export const getSystemDiagnostics = () => json('/api/system/diagnostics')
export const getToolsSyslog = (minutes, level, limit = 100) => {
  const query = new URLSearchParams({
    minutes: String(minutes),
    level,
    limit: String(limit),
  })
  return json(`/api/tools/syslog?${query}`)
}
export const getSystemProcesses = (limit = 40) =>
  json(`/api/system/processes?limit=${limit}`)
export const getDockerDiskUsage = () => json('/api/docker/df')
export const getDockerContainerSizes = () => json('/api/docker/sizes')
export const pruneDocker = (what) =>
  json('/api/tools/docker/prune', jsonBody('POST', { what, confirm: true }))
export const getSystemScheduler = () => json('/api/system/scheduler')
export const getToolsAgents = () => json('/api/tools/agents')
export const getToolsHardware = () => json('/api/tools/hardware')
export const getToolsUpdates = (force = false) =>
  json(force ? '/api/tools/updates?force=true' : '/api/tools/updates')
export const applyServerHubUpdate = (stash = false) =>
  json('/api/tools/updates/apply', jsonBody('POST', { confirm: true, stash: !!stash }))
export const applyBrewUpgrade = () =>
  json('/api/tools/updates/brew', jsonBody('POST', { confirm: true }))
export const getToolsAbout = () => json('/api/tools/about')
export const pingHost = (host, count = 3) =>
  json('/api/tools/net/ping', jsonBody('POST', { host, count }))
export const lookupDns = (name) =>
  json('/api/tools/net/dns', jsonBody('POST', { name }))
export const flushDns = () => json('/api/tools/net/flush-dns', { method: 'POST' })

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
export const uninstallService = (sid, { remove_data = false } = {}) =>
  json(`/api/services/${encodeURIComponent(sid)}/uninstall`, jsonBody('POST', { remove_data }))

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

export const getSmartOverview = () => json('/api/smart')
export const startSmartTest = (device, kind = 'short') =>
  json('/api/smart/test', jsonBody('POST', { device, kind }))

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

const SHARING_ADMIN_TIMEOUT = 180000

export const getShares = () => json('/api/shares')
export const createShare = (body) => json('/api/shares/smb', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body),
}, SHARING_ADMIN_TIMEOUT)
export const updateShare = (recordName, body) =>
  json(`/api/shares/smb/${encodeURIComponent(recordName)}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  }, SHARING_ADMIN_TIMEOUT)
export const removeShare = (recordName) =>
  json(`/api/shares/smb/${encodeURIComponent(recordName)}?confirm=true`, {
    method: 'DELETE',
  }, SHARING_ADMIN_TIMEOUT)
// Per-user share access = the shared directory's filesystem ACL.
export const getShareAcl = (path) =>
  json(`/api/shares/acl?path=${encodeURIComponent(path)}`)
export const setShareAcl = (path, username, level) =>
  json('/api/shares/acl', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ path, username, level }),
  }, SHARING_ADMIN_TIMEOUT)
export const setSystemSharing = (serviceId, enabled) =>
  json(`/api/shares/system/${encodeURIComponent(serviceId)}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ enabled }),
  }, SHARING_ADMIN_TIMEOUT)
export const openSharingSettings = () =>
  json('/api/shares/open-system-settings', { method: 'POST' })
export const getLogSources = () => json('/api/logs')
export const getLogTail = (id, lines = 200) =>
  json(`/api/logs/${encodeURIComponent(id)}?lines=${lines}`)
export const getSettings = () => json('/api/settings')
export const getLauncherStatus = () => json('/api/launcher')
export const openLauncherApp = () => json('/api/launcher/open', { method: 'POST' })
export const setLauncherLogin = (enabled) => json('/api/launcher/login', {
  method: 'PUT',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ enabled }),
})
export const controlPanelService = (action) =>
  json(`/api/launcher/panel/${encodeURIComponent(action)}`, { method: 'POST' })
export const putSettings = (body) =>
  json('/api/settings', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
// Tiered history: backend picks the layer (raw 90s / 5m / 1h) for the span and
// caps the point count; response adds { tier, since, until } next to points.
export const getMetricsRange = (range) => json(`/api/metrics?range=${encodeURIComponent(range)}`)
export const getAlerts = (limit = 50) => json(`/api/alerts?limit=${limit}`)
// Read-only: there is deliberately no writer or clear endpoint for the audit
// trail, so this module exposes only the reader.
export const getAuthAudit = (limit = 100) => json(`/api/audit/auth?limit=${limit}`)
export const testNotify = () => json('/api/alerts/test', { method: 'POST' })
export const forceAlertCheck = () => json('/api/alerts/check', { method: 'POST' })
// Notification channels (multi-channel alert outlets). Secrets are write-only:
// responses carry has.<field> booleans, never the stored values.
export const getNotifyChannels = () => json('/api/alerts/channels')
export const createNotifyChannel = (body) =>
  json('/api/alerts/channels', jsonBody('POST', body))
export const updateNotifyChannel = (id, body) =>
  json(`/api/alerts/channels/${encodeURIComponent(id)}`, jsonBody('PUT', body))
export const deleteNotifyChannel = (id) =>
  json(`/api/alerts/channels/${encodeURIComponent(id)}`, { method: 'DELETE' })
export const testNotifyChannel = (id) =>
  json(`/api/alerts/channels/${encodeURIComponent(id)}/test`, { method: 'POST' })
// UPS / battery power monitoring
export const getUps = (force = false) => json(`/api/ups${force ? '?force=true' : ''}`)
export const putUpsSettings = (body) => json('/api/ups/settings', jsonBody('PUT', body))
// Safe-shutdown policy: `plan` backs the settings form (unaudited read of the
// resolved stop sequence + catalogs); `drill` is the deliberate dry-run button
// (admin browser session, audited). Neither ever stops anything.
export const getUpsShutdownPlan = () => json('/api/ups/shutdown/plan')
export const runUpsShutdownDrill = () => json('/api/ups/shutdown/drill', { method: 'POST' })
// Writes the macOS pmset UPS halt level (root via the admin-password flow).
export const putUpsHalt = (body) => json('/api/ups/halt', jsonBody('PUT', body))
export const getBackups = () => json('/api/backups')
// A dump gets 600s server-side (per target, for Postgres) and holds a per-job
// lock for the whole run. Aborting at the default 30s told the operator the
// backup had timed out while it was still running, and the retry they reached
// for was refused as "already running" until it finished.
const BACKUP_TIMEOUT = 620000
export const backupPostgres = () =>
  json('/api/backups/postgres', { method: 'POST' }, BACKUP_TIMEOUT)
export const backupImmich = () =>
  json('/api/backups/immich', { method: 'POST' }, BACKUP_TIMEOUT)
export const backupConfigs = () =>
  json('/api/backups/configs', { method: 'POST' }, BACKUP_TIMEOUT)
// Panel scheduler (user-defined cron jobs) — distinct from getScheduler(),
// which lists the read-only launchd timers.
export const getSchedulerJobs = () => json('/api/scheduler/jobs')
export const createSchedulerJob = (body) =>
  json('/api/scheduler/jobs', jsonBody('POST', body))
export const updateSchedulerJob = (id, body) =>
  json(`/api/scheduler/jobs/${encodeURIComponent(id)}`, jsonBody('PUT', body))
export const deleteSchedulerJob = (id) =>
  json(`/api/scheduler/jobs/${encodeURIComponent(id)}`, { method: 'DELETE' })
export const enableSchedulerJob = (id, enabled) =>
  json(`/api/scheduler/jobs/${encodeURIComponent(id)}/enable`, jsonBody('POST', { enabled }))
export const runSchedulerJobNow = (id) =>
  json(`/api/scheduler/jobs/${encodeURIComponent(id)}/run-now`, { method: 'POST' })
export const getSchedulerJobRuns = (id, limit = 20) =>
  json(`/api/scheduler/jobs/${encodeURIComponent(id)}/runs?limit=${limit}`)
// rsync backup helpers: binary capabilities + dry-run preview.  The backend
// caps a preview at 120s (rsync_svc.PREVIEW_TIMEOUT) and kills the process
// group past that, so the client only needs that ceiling plus transport slack.
export const getRsyncBinary = () => json('/api/backups/rsync/binary')
export const rsyncPreview = (body) =>
  json('/api/backups/rsync/preview', jsonBody('POST', body), 130000)
export const getCatalog = () => json('/api/catalog')
const CATALOG_INSTALL_TIMEOUT = 900000 // brew cask / pull can exceed 30s

export async function installCatalog(id, variables = {}) {
  const url = `/api/catalog/${encodeURIComponent(id)}/install`
  const body = JSON.stringify({ confirm: true, variables })
  for (let attempt = 0; attempt < 3; attempt++) {
    const r = await json(
      url,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...adminPasswordHeaders(),
        },
        body,
      },
      CATALOG_INSTALL_TIMEOUT,
    )
    if (r.error !== 'password_required' && r.error !== 'password_incorrect') return r
    const incorrect = r.error === 'password_incorrect'
    if (incorrect) clearAdminPassword()
    let password = incorrect ? '' : getAdminPassword()
    if (!password) password = await promptAdminPassword(incorrect)
    if (!password) return r
    setAdminPassword(password)
  }
  return json(
    url,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...adminPasswordHeaders(),
      },
      body,
    },
    CATALOG_INSTALL_TIMEOUT,
  )
}
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

// Remote template catalog source (admin action; sync may download many files)
const CATALOG_SYNC_TIMEOUT = 120000
export const getCatalogRemote = () => json('/api/catalog/remote')
export const setCatalogRemoteSource = (url) =>
  json('/api/catalog/remote', jsonBody('PUT', { url }))
export const checkCatalogRemoteUpdates = () =>
  json('/api/catalog/remote/check', { method: 'POST' }, CATALOG_SYNC_TIMEOUT)
export const restoreCatalogBuiltin = (id) =>
  json('/api/catalog/remote/restore', jsonBody('POST', { id }))

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
export const getSensors = (force = false, { light = false } = {}) =>
  json(`/api/system/sensors?force=${force ? 'true' : 'false'}${light ? '&light=true' : ''}`)
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

// WireGuard. Peer creation runs `wg` plus a config rewrite and an interface
// sync, and `wg-quick up/down` can wait on a macOS authorization sheet, so these
// get more headroom than the default timeout.
const WG_ACTION_TIMEOUT = 190000
const WG_CONTROL_TIMEOUT = 200000

export const getWireguard = (force = false) =>
  // Reads still need root for `wg show`; attach the cached administrator
  // password when one exists so remote management sees live tunnel state.
  json(`/api/wireguard?force=${force ? 'true' : 'false'}`, { headers: adminPasswordHeaders() })
export const getWireguardReadiness = () =>
  json('/api/wireguard/readiness', { headers: adminPasswordHeaders() })
export const getWireguardSettings = () => json('/api/wireguard/settings')
export const putWireguardSettings = (body) =>
  json('/api/wireguard/settings', jsonBody('PUT', body))
export const getWireguardNextIp = () => json('/api/wireguard/next-ip')
export const getWireguardConf = (reveal = false) =>
  json(`/api/wireguard/conf?reveal=${reveal ? 'true' : 'false'}`)
export const addWireguardPeer = (body) =>
  json('/api/wireguard/peers', jsonBody('POST', body), WG_ACTION_TIMEOUT)
export const batchAddWireguardPeers = (body) =>
  json('/api/wireguard/peers/batch', jsonBody('POST', body), WG_CONTROL_TIMEOUT)
export const deleteWireguardPeer = (pubkey) =>
  json('/api/wireguard/peers/delete', jsonBody('POST', { pubkey, confirm: true }), WG_ACTION_TIMEOUT)
export const importWireguardPeer = (body) =>
  json('/api/wireguard/peers/import', jsonBody('POST', body), WG_ACTION_TIMEOUT)
export const setWireguardPsk = (pubkey, op) =>
  json('/api/wireguard/peers/psk', jsonBody('POST', { pubkey, op }), WG_ACTION_TIMEOUT)
// The pubkey rides in the query string, never the path: keys are raw base64
// and a "/" encoded as %2F would be decoded back into a path separator before
// Starlette routes the request, 404-ing every key that contains one.
export const getWireguardPeerConfig = (pubkey, format = 'wg') =>
  json(`/api/wireguard/peers/config?pubkey=${encodeURIComponent(pubkey)}&format=${encodeURIComponent(format)}`)
export const controlWireguardInterface = (action) =>
  json('/api/wireguard/interface', jsonBody('POST', { action }), WG_CONTROL_TIMEOUT)
export const syncWireguard = () =>
  json('/api/wireguard/sync', { method: 'POST' }, WG_ACTION_TIMEOUT)
export const pingWireguardPeers = () =>
  json('/api/wireguard/ping', { method: 'POST' }, WG_CONTROL_TIMEOUT)
export const setWireguardForwarding = (enabled) =>
  json('/api/wireguard/forwarding', jsonBody('POST', { enabled }), WG_CONTROL_TIMEOUT)
export const remediateWireguard = (target, enabled = true) =>
  json('/api/wireguard/remediate', jsonBody('POST', { target, enabled }), WG_CONTROL_TIMEOUT)
/** Download URL for a peer config. A navigation, not a fetch, so the browser
 *  handles the attachment; the session cookie authorizes it. */
export const wireguardPeerDownloadUrl = (pubkey, format = 'wg') =>
  `/api/wireguard/peers/download?pubkey=${encodeURIComponent(pubkey)}&format=${encodeURIComponent(format)}`

// Power & remote desktop
export const getPower = () => json('/api/system/power')
export const powerAction = (action, confirm = true) =>
  json('/api/system/power/action', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action, confirm }),
  })
export const setWol = (enabled) =>
  json('/api/system/power/wol', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ enabled }),
  })
export function openContainerLogs(name, { tail = 200, follow = true } = {}) {
  const q = new URLSearchParams({
    tail: String(tail),
    follow: follow ? 'true' : 'false',
  })
  return new EventSource(`/api/containers/${encodeURIComponent(name)}/logs?${q}`)
}

const PHOTOSHUB_ACTION_TIMEOUT = 600000
export const getPhotosHubStatus = () => json('/api/photoshub/status')
export const getPhotosHubConfig = () => json('/api/photoshub/config')
export const patchPhotosHubConfig = (body) => json('/api/photoshub/config', jsonBody('PATCH', body))
export const getPhotosHubPending = () => json('/api/photoshub/pending-delete')
// A URL, not a request: the browser loads previews itself via <img>, so the
// panel session authorises them and the Immich API key stays on the server.
export const photosHubThumbUrl = (id) =>
  `/api/photoshub/pending-delete/thumb/${encodeURIComponent(id)}`
export const postPhotosHubAction = (action) =>
  json('/api/photoshub/action', jsonBody('POST', { action }), PHOTOSHUB_ACTION_TIMEOUT)
export const postPhotosHubPendingRemove = (ids) =>
  json('/api/photoshub/pending-delete/remove', jsonBody('POST', { ids }))
export const getPhotosHubLogs = (name) => json(`/api/photoshub/logs/${name}`)

// ── Ollama local LLM (hub/routers/ollama_api.py) ─────────────────────────────
// The quick test proxies one bounded /api/generate; a cold model spends tens of
// seconds loading before it answers, and the backend allows the generation 120s.
const OLLAMA_TEST_TIMEOUT = 130000
export const getOllamaStatus = (force = false) =>
  json(`/api/ollama/status${force ? '?force=true' : ''}`)
export const startOllamaPull = (model) =>
  json('/api/ollama/pull', jsonBody('POST', { model }))
export const getOllamaPullLog = () => json('/api/ollama/pull/log')
export const deleteOllamaModel = (model) =>
  json('/api/ollama/models/delete', jsonBody('POST', { model, confirm: true }))
export const unloadOllamaModel = (model) =>
  json('/api/ollama/models/unload', jsonBody('POST', { model }))
export const testOllamaModel = (model, prompt, numPredict = 128) =>
  json('/api/ollama/test', jsonBody('POST', { model, prompt, num_predict: numPredict }), OLLAMA_TEST_TIMEOUT)

/**
 * One in-panel chat turn. The backend streams Ollama NDJSON; *onChunk* is
 * called with the accumulated assistant `{ content, thinking, done }` after
 * each line so the page can paint tokens as they arrive. The resolved value
 * is the same shape as a finished chunk.
 *
 * Validation failures (bad model, empty prompt) arrive as a normal JSON
 * error *before* the stream starts — same coded-error path as json().
 */
export async function chatOllamaModel(model, messages, numPredict = 128, { onChunk, signal } = {}) {
  const ctrl = new AbortController()
  const onAbort = () => ctrl.abort()
  if (signal) {
    if (signal.aborted) ctrl.abort()
    else signal.addEventListener('abort', onAbort, { once: true })
  }
  const timer = setTimeout(() => ctrl.abort(), OLLAMA_TEST_TIMEOUT)
  try {
    const r = await fetch('/api/ollama/chat', {
      ...jsonBody('POST', { model, messages, num_predict: numPredict }),
      signal: ctrl.signal,
    })
    if (!r.ok) {
      const j = await r.json().catch(() => ({}))
      const err = new Error(errorText(j, r.statusText))
      err.status = r.status
      err.body = j
      err.code = (j?.detail && typeof j.detail === 'object' && j.detail.code) || null
      if (r.status === 401 && !authLost) {
        authLost = true
        try {
          window.dispatchEvent(new CustomEvent(AUTH_LOST_EVENT, { detail: { url: '/api/ollama/chat' } }))
        } catch { /* ignore */ }
      }
      throw err
    }
    const reader = r.body?.getReader?.()
    if (!reader) {
      throw new Error(t('err.request_failed'))
    }
    const decoder = new TextDecoder()
    let buf = ''
    let content = ''
    let thinking = ''
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      buf += decoder.decode(value, { stream: true })
      const lines = buf.split('\n')
      buf = lines.pop() ?? ''
      for (const line of lines) {
        const trimmed = line.trim()
        if (!trimmed) continue
        let chunk
        try {
          chunk = JSON.parse(trimmed)
        } catch {
          continue
        }
        if (chunk.error) {
          const err = new Error(String(chunk.error))
          err.status = 502
          throw err
        }
        const msg = chunk.message || {}
        if (msg.content) content += msg.content
        if (msg.thinking) thinking += msg.thinking
        const snap = { ok: true, model, content, thinking, done: Boolean(chunk.done) }
        if (signal?.aborted) {
          const err = new Error('aborted')
          err.name = 'AbortError'
          throw err
        }
        onChunk?.(snap)
        if (chunk.done) return snap
      }
    }
    if (signal?.aborted) {
      const err = new Error('aborted')
      err.name = 'AbortError'
      throw err
    }
    const snap = { ok: true, model, content, thinking, done: true }
    onChunk?.(snap)
    return snap
  } catch (e) {
    if (e.name === 'AbortError') {
      const userAborted = Boolean(signal?.aborted)
      const err = new Error(t(userAborted ? 'err.cancelled' : 'err.timeout'))
      err.status = 0
      err.code = userAborted ? 'cancelled' : 'timeout'
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
    if (signal) signal.removeEventListener('abort', onAbort)
  }
}

// ── In-panel assistant (hub/routers/assistant_api.py) ────────────────────────
// Find is a catalog match. Brief/ask may wait on the resident model the same
// way /api/ollama/chat does, so they share that 130s ceiling.
export const getAssistantCatalog = (locale = 'zh-CN') =>
  json(`/api/assistant/catalog?locale=${encodeURIComponent(locale)}`)
export const askAssistant = (query, { locale = 'zh-CN', action = 'auto', history = [], path = '', signal } = {}) =>
  json('/api/assistant/ask', { ...jsonBody('POST', { query, locale, action, history, path }), signal }, OLLAMA_TEST_TIMEOUT)
