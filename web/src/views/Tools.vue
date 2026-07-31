<template>
  <div class="tools-page">
    <div class="page-title">
      <h1>{{ t('tools.title') }}</h1>
      <span class="meta">{{ t('tools.meta') }}</span>
    </div>

    <div class="tools-tabs">
      <button
        v-for="tb in tabs"
        :key="tb.id"
        type="button"
        class="tools-tab"
        :class="{ active: tab===tb.id }"
        @click="switchTab(tb.id)"
      >
        {{ t(tb.labelKey) }}
      </button>
    </div>
    <div class="toolbar">
      <button type="button" class="primary" @click="reload" :disabled="loading">{{ t('common.refresh') }}</button>
    </div>

    <!-- Tools home tiles -->
    <template v-if="tab==='home'">
      <p class="hint" v-if="catalog.hint_key || catalog.hint" style="margin-top:0">
        {{ catalog.hint_key ? t(catalog.hint_key) : catalog.hint }}
      </p>
      <div class="tool-grid">
        <button
          v-for="tile in catalog.tiles || []"
          :key="tile.id"
          type="button"
          class="tool-tile"
          @click="openTile(tile)"
        >
          <div class="tile-label">{{ tileLabel(tile) }}</div>
          <div class="tile-desc">{{ tileDesc(tile) }}</div>
        </button>
      </div>
    </template>

    <!-- System info / diagnostics -->
    <template v-else-if="tab==='diag' && diag">
      <div class="dash-grid">
        <div class="tile span-4">
          <h3>{{ t('tools.host') }}</h3>
          <div class="kv">
            <div class="k">{{ t('tools.hostname') }}</div><div class="mono">{{ diag.hostname }}</div>
            <div class="k">CPU</div><div class="mono" style="font-size:11px">{{ diag.cpu || '—' }}</div>
            <div class="k">{{ t('tools.cores') }}</div><div>{{ diag.ncpu ?? '—' }}</div>
            <div class="k">{{ t('tools.memory') }}</div><div>{{ diag.mem_gb ?? '—' }} GB</div>
            <div class="k">{{ t('tools.load') }}</div><div class="mono">{{ (diag.load||[]).join(' / ') }}</div>
            <div class="k">{{ t('tools.uptime') }}</div><div class="mono">{{ diag.uptime_human || '—' }}</div>
            <div class="k">{{ t('tools.root_disk') }}</div>
            <div class="mono">{{ diag.root_disk_pct ?? '—' }}% · {{ t('common.free') }} {{ diag.root_disk_free_gb ?? '—' }} GB</div>
            <div class="k">{{ t('tools.platform') }}</div><div class="mono" style="font-size:11px">{{ diag.platform }}</div>
          </div>
        </div>
        <div class="tile span-4">
          <h3>{{ t('tools.runtime') }}</h3>
          <div class="kv">
            <div class="k">OrbStack</div>
            <div><span class="badge" :class="diag.orbstack?'ok':'down'">{{ diag.orbstack ? t('common.running') : t('common.off') }}</span></div>
            <div class="k">docker</div><div class="mono">{{ diag.docker_cli }}</div>
            <div class="k">orb</div><div class="mono">{{ diag.orb_cli }}</div>
            <div class="k">Python</div><div>{{ diag.python }}</div>
            <div class="k">Host IP</div><div class="mono">{{ diag.host_ip || '—' }}</div>
            <div class="k">{{ t('tools.metrics_pts') }}</div><div>{{ diag.metrics_points }} / 1h</div>
            <div class="k">{{ t('tools.time') }}</div><div class="mono">{{ diag.ts }}</div>
            <div class="k">{{ t('tools.version') }}</div><div>ServerHub {{ diag.version || '—' }}</div>
          </div>
        </div>
        <div class="tile span-4">
          <h3>{{ t('tools.diagnostics') }}</h3>
          <p class="hint" style="margin-top:0">{{ t('tools.diagnostics_hint') }}</p>
          <div class="btns" style="flex-direction:column;align-items:stretch">
            <a class="btn primary" href="/api/diagnostics/download">{{ t('tools.download_diag') }}</a>
            <button @click="genDiag" :disabled="loading">{{ t('tools.gen_diag') }}</button>
            <router-link class="btn" to="/health">{{ t('tools.fcp') }}</router-link>
            <router-link class="btn" to="/settings">{{ t('nav.settings') }}</router-link>
            <router-link class="btn" to="/maintenance">{{ t('nav.maintenance') }}</router-link>
          </div>
          <p class="hint" v-if="diagMsg" style="margin-top:10px">{{ diagMsg }}</p>
        </div>
      </div>
    </template>

    <!-- Syslog -->
    <template v-else-if="tab==='syslog'">
      <div class="toolbar">
        <select v-model="syslogLevel" @change="loadSyslog">
          <option value="error">{{ t('tools.syslog_err') }}</option>
          <option value="fault">{{ t('tools.syslog_fault') }}</option>
          <option value="default">{{ t('tools.syslog_default') }}</option>
          <option value="all">{{ t('tools.syslog_all') }}</option>
        </select>
        <select v-model.number="syslogMinutes" @change="loadSyslog">
          <option :value="15">15m</option>
          <option :value="60">1h</option>
          <option :value="360">6h</option>
          <option :value="1440">24h</option>
        </select>
        <button @click="loadSyslog" :disabled="loading">{{ t('common.refresh') }}</button>
        <span class="meta">{{ t('tools.lines_n', { n: syslog.count ?? 0 }) }}</span>
      </div>
      <p class="hint">{{ syslog.hint || t('tools.syslog_hint') }}</p>
      <div class="log-box mono" v-if="(syslog.lines||[]).length">
        <div v-for="(ln,i) in syslog.lines" :key="i">{{ ln }}</div>
      </div>
      <div v-else class="placeholder">{{ syslog.message || t('tools.no_data') }}</div>
    </template>

    <!-- Processes -->
    <template v-else-if="tab==='proc'">
      <div class="toolbar">
        <input v-model="procQ" type="text" :placeholder="t('tools.filter_proc')" style="min-width:180px"  :aria-label="t('tools.filter_proc')"/>
      </div>
      <div class="table-wrap">
        <table class="dense">
          <thead>
            <tr>
              <th>PID</th><th>{{ t('tools.user') }}</th><th>CPU%</th><th>MEM%</th><th>TIME</th><th>{{ t('tools.command') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="p in filteredProc" :key="p.pid + p.command">
              <td class="mono">{{ p.pid }}</td>
              <td>{{ p.user }}</td>
              <td class="mono">{{ p.cpu.toFixed(1) }}</td>
              <td class="mono">{{ p.mem.toFixed(1) }}</td>
              <td class="mono">{{ p.time }}</td>
              <td class="mono" style="max-width:480px;overflow:hidden;text-overflow:ellipsis" :title="p.command">{{ p.command }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </template>

    <!-- Docker -->
    <template v-else-if="tab==='docker'">
      <h2 class="section-title">docker system df</h2>
      <div class="table-wrap" style="margin-bottom:12px">
        <table class="dense">
          <thead>
            <tr>
              <th>{{ t('tools.type') }}</th>
              <th>{{ t('tools.col_total') }}</th>
              <th>{{ t('tools.col_active') }}</th>
              <th>{{ t('common.size') }}</th>
              <th>{{ t('tools.col_reclaim') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="(l,i) in (df.lines||[])" :key="i">
              <td>{{ l.type }}</td>
              <td>{{ l.total }}</td>
              <td>{{ l.active }}</td>
              <td>{{ l.size }}</td>
              <td>{{ l.reclaimable }}</td>
            </tr>
            <tr v-if="!(df.lines||[]).length">
              <td colspan="5" style="color:var(--sub)">{{ df.engine_up === false ? t('tools.engine_off') : t('tools.no_data') }}</td>
            </tr>
          </tbody>
        </table>
      </div>

      <h2 class="section-title">{{ t('tools.docker_cleanup') }}</h2>
      <p class="hint" style="margin-top:0">{{ t('tools.docker_cleanup_hint') }}</p>
      <div class="btns" style="margin-bottom:14px;flex-wrap:wrap">
        <button :disabled="loading" @click="doPrune('dangling')">{{ t('tools.prune_dangling') }}</button>
        <button :disabled="loading" @click="doPrune('build')">{{ t('tools.prune_build') }}</button>
        <button :disabled="loading" @click="doPrune('volumes')">{{ t('tools.prune_volumes') }}</button>
        <button :disabled="loading" class="warn" @click="doPrune('all_unused')">{{ t('tools.prune_all') }}</button>
      </div>
      <p class="hint" v-if="pruneMsg">{{ pruneMsg }}</p>

      <h2 class="section-title">{{ t('tools.container_size') }}</h2>
      <div class="table-wrap">
        <table class="dense">
          <thead><tr><th>{{ t('common.name') }}</th><th>{{ t('tools.image') }}</th><th>{{ t('common.status') }}</th><th>{{ t('common.size') }}</th></tr></thead>
          <tbody>
            <tr v-for="c in sizes" :key="c.name">
              <td><strong>{{ c.name }}</strong></td>
              <td class="mono">{{ c.image }}</td>
              <td>{{ c.status }}</td>
              <td class="mono">{{ c.size }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </template>

    <!-- Scheduler + agents -->
    <template v-else-if="tab==='sched'">
      <div class="toolbar">
        <router-link class="btn primary" to="/scheduler">{{ t('tools.open_scheduler') }}</router-link>
        <router-link class="btn" to="/maintenance">{{ t('nav.maintenance') }}</router-link>
        <span class="meta" style="color:var(--sub)">{{ t('tools.tasks_n', { n: timers.length }) }}</span>
      </div>
      <h2 class="section-title">{{ t('tools.timers') }}</h2>
      <div class="table-wrap" style="margin-bottom:14px">
        <table class="dense">
          <thead>
            <tr>
              <th>{{ t('tools.col_label') }}</th>
              <th>{{ t('scheduler.interval') }}</th>
              <th>{{ t('scheduler.calendar') }}</th>
              <th>{{ t('tools.command') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="row in timers" :key="row.label">
              <td class="mono">{{ row.label }}</td>
              <td>{{ row.interval_sec ? row.interval_sec + 's' : '—' }}</td>
              <td class="mono" style="font-size:11px">{{ formatCal(row.calendar) }}</td>
              <td class="mono" style="max-width:360px;overflow:hidden;text-overflow:ellipsis" :title="row.program">{{ row.program }}</td>
            </tr>
            <tr v-if="!timers.length">
              <td colspan="4" style="color:var(--sub)">{{ t('tools.no_timers') }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <h2 class="section-title">{{ t('tools.agents') }}</h2>
      <p class="hint" style="margin-top:0">{{ agents.hint }} · {{ agents.count ?? 0 }}</p>
      <div class="table-wrap">
        <table class="dense">
          <thead>
            <tr>
              <th>Label</th>
              <th>RunAtLoad</th>
              <th>KeepAlive</th>
              <th>Timer</th>
              <th>{{ t('tools.command') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="a in (agents.agents||[])" :key="a.label">
              <td class="mono" style="font-size:11px">{{ a.label }}</td>
              <td>{{ a.run_at_load ? '✓' : '—' }}</td>
              <td>{{ a.keep_alive ? '✓' : '—' }}</td>
              <td class="mono">{{ a.interval_sec ? a.interval_sec + 's' : (a.calendar ? 'cal' : '—') }}</td>
              <td class="mono" style="max-width:280px;overflow:hidden;text-overflow:ellipsis" :title="a.program">{{ a.program }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </template>

    <!-- Hardware -->
    <template v-else-if="tab==='hw'">
      <div class="two-col" v-if="hw">
        <div class="card" v-for="(sec, key) in (hw.sections||{})" :key="key">
          <h2 class="section-title" style="margin-top:0">{{ key }} · {{ sec.data_type }}</h2>
          <pre class="mono hw-pre">{{ sec.text || '—' }}</pre>
        </div>
      </div>
      <div class="card" style="margin-top:12px" v-if="(hw?.disks||[]).length">
        <h2 class="section-title" style="margin-top:0">{{ t('tools.disks') }}</h2>
        <table class="dense">
          <thead><tr><th>ID</th><th>{{ t('common.name') }}</th><th>{{ t('common.size') }}</th><th>SSD</th><th>{{ t('common.status') }}</th></tr></thead>
          <tbody>
            <tr v-for="d in hw.disks" :key="d.id">
              <td class="mono">{{ d.id }}</td>
              <td>{{ d.name }}</td>
              <td class="mono">{{ d.size_gb != null ? d.size_gb + ' GB' : '—' }}</td>
              <td>{{ d.ssd ? 'SSD' : 'HDD' }}</td>
              <td><span class="badge">{{ d.power_state || '—' }}</span></td>
            </tr>
          </tbody>
        </table>
      </div>
      <div v-if="!hw" class="placeholder">{{ t('common.loading') }}</div>
    </template>

    <!-- Updates -->
    <template v-else-if="tab==='updates'">
      <div class="two-col">
        <div class="card">
          <h2 class="section-title" style="margin-top:0">Homebrew</h2>
          <p class="hint" style="margin-top:0">
            {{ t('tools.outdated_n', { n: updates.brew?.count ?? 0 }) }}
          </p>
          <ul class="mono update-list" v-if="(updates.brew?.outdated||[]).length">
            <li v-for="(ln,i) in updates.brew.outdated" :key="i">{{ ln }}</li>
          </ul>
          <div v-else class="sub">{{ t('tools.up_to_date') }}</div>
        </div>
        <div class="card">
          <h2 class="section-title" style="margin-top:0">macOS</h2>
          <div class="mono" style="font-size:12px;white-space:pre-wrap;max-height:280px;overflow:auto">
            {{ (updates.macos?.lines||[]).join('\n') || updates.macos?.raw || '—' }}
          </div>
        </div>
      </div>
      <p class="hint">{{ updates.hint || t('tools.updates_hint') }}</p>
      <div class="btns">
        <router-link class="btn primary" to="/maintenance">{{ t('nav.maintenance') }}</router-link>
        <button @click="loadUpdates" :disabled="loading">{{ t('common.refresh') }}</button>
      </div>
    </template>

    <!-- Network tools -->
    <template v-else-if="tab==='net'">
      <div class="two-col">
        <div class="card">
          <h2 class="section-title" style="margin-top:0">Ping</h2>
          <div class="form-row">
            <input v-model="pingHost" type="text" :placeholder="t('tools.ping_host_ph')"  :aria-label="t('tools.ping_host_ph')"/>
            <button class="primary" :disabled="loading" @click="doPing">Ping</button>
          </div>
          <pre class="mono net-out" v-if="pingOut" role="log" aria-live="polite">{{ pingOut }}</pre>
        </div>
        <div class="card">
          <h2 class="section-title" style="margin-top:0">DNS</h2>
          <div class="form-row">
            <input v-model="dnsName" type="text" placeholder="example.com"  aria-label="example.com"/>
            <button class="primary" :disabled="loading" @click="doDns">Lookup</button>
            <button :disabled="loading" @click="doFlushDns">{{ t('tools.flush_dns') }}</button>
          </div>
          <pre class="mono net-out" v-if="dnsOut" role="log" aria-live="polite">{{ dnsOut }}</pre>
        </div>
      </div>
      <div class="card" style="margin-top:12px">
        <h2 class="section-title" style="margin-top:0">{{ t('tools.listen_ports') }}</h2>
        <div class="toolbar">
          <button @click="loadPorts" :disabled="loading">{{ t('common.refresh') }}</button>
          <router-link class="btn" to="/network">{{ t('nav.network') }}</router-link>
          <span class="meta">{{ ports.count ?? 0 }}</span>
        </div>
        <table class="dense">
          <thead>
            <tr>
              <th>{{ t('tools.command') }}</th>
              <th>PID</th>
              <th>{{ t('tools.user') }}</th>
              <th>{{ t('tools.listen') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="(p,i) in (ports.ports||[])" :key="i">
              <td class="mono">{{ p.command }}</td>
              <td class="mono">{{ p.pid }}</td>
              <td>{{ p.user }}</td>
              <td class="mono">{{ p.name }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </template>

    <!-- About -->
    <template v-else-if="tab==='about'">
      <div class="two-col" v-if="about">
        <div class="card">
          <h2 class="section-title" style="margin-top:0">{{ about.name }} v{{ about.version }}</h2>
          <p class="hint" style="margin-top:0">{{ about.tagline_key ? t(about.tagline_key) : (about.tagline || '') }}</p>
          <div class="kv">
            <div class="k">{{ t('tools.host_ip') }}</div><div class="mono">{{ about.host_ip || '—' }}</div>
            <div class="k">{{ t('tools.platform') }}</div><div class="mono" style="font-size:11px">{{ about.platform }}</div>
            <div class="k">Python</div><div>{{ about.python }}</div>
            <div class="k">{{ t('tools.base_path') }}</div><div class="mono" style="font-size:11px;word-break:break-all">{{ about.base }}</div>
          </div>
        </div>
        <div class="card">
          <h2 class="section-title" style="margin-top:0">{{ t('tools.credits') }}</h2>
          <ul class="hint" style="margin:0;padding-left:18px;line-height:1.7">
            <li v-for="(x,i) in aboutCredits" :key="i">{{ x }}</li>
          </ul>
          <div class="btns" style="margin-top:12px;flex-wrap:wrap">
            <router-link
              v-for="l in (about.links||[])"
              :key="l.href"
              class="btn"
              :to="l.href"
            >{{ l.label_key ? t(l.label_key) : l.label }}</router-link>
          </div>
        </div>
      </div>
    </template>

    <div v-else-if="tab!=='home' && loading" class="placeholder">{{ t('common.loading') }}</div>
  </div>
</template>

<script setup>
import { computed, inject, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import {
  flushDns,
  generateDiagnostics,
  getDockerContainerSizes,
  getDockerDiskUsage,
  getListeningPorts,
  getScheduler,
  getSystemDiagnostics,
  getSystemProcesses,
  getSystemScheduler,
  getToolsAbout,
  getToolsAgents,
  getToolsCatalog,
  getToolsHardware,
  getToolsSyslog,
  getToolsUpdates,
  lookupDns,
  pingHost as pingHostApi,
  pruneDocker,
} from '../api/client'
import { injectI18n } from '../i18n'

const toast = inject('toast')
const router = useRouter()
const { t } = injectI18n()

const tab = ref('home')
const loading = ref(false)
const catalog = ref({ tiles: [] })
const diag = ref(null)
const diagMsg = ref('')
const processes = ref([])
const procQ = ref('')
const df = ref({})
const sizes = ref([])
const timers = ref([])
const agents = ref({ agents: [] })
const syslog = ref({ lines: [] })
const syslogLevel = ref('error')
const syslogMinutes = ref(60)
const hw = ref(null)
const updates = ref({})
const about = ref(null)
const ports = ref({ ports: [] })
const pingHost = ref('')
const pingOut = ref('')
const dnsName = ref('apple.com')
const dnsOut = ref('')
const pruneMsg = ref('')

const tabs = [
  { id: 'home', labelKey: 'tools.tab_home' },
  { id: 'diag', labelKey: 'tools.tab_diag' },
  { id: 'syslog', labelKey: 'tools.tab_syslog' },
  { id: 'proc', labelKey: 'tools.tab_proc' },
  { id: 'hw', labelKey: 'tools.tab_hw' },
  { id: 'docker', labelKey: 'tools.tab_docker' },
  { id: 'sched', labelKey: 'tools.tab_sched' },
  { id: 'updates', labelKey: 'tools.tab_updates' },
  { id: 'net', labelKey: 'tools.tab_net' },
  { id: 'about', labelKey: 'tools.tab_about' },
]

const filteredProc = computed(() => {
  const q = procQ.value.trim().toLowerCase()
  if (!q) return processes.value
  return processes.value.filter(p =>
    (p.command || '').toLowerCase().includes(q)
    || (p.user || '').toLowerCase().includes(q)
    || String(p.pid).includes(q)
  )
})

const aboutCredits = computed(() => {
  const a = about.value || {}
  if (a.credit_keys?.length) return a.credit_keys.map((k) => t(k))
  return a.credits || []
})

function tileLabel(tile) {
  if (tile?.label_key) return t(tile.label_key)
  return tile?.label || tile?.id || ''
}
function tileDesc(tile) {
  if (tile?.desc_key) return t(tile.desc_key)
  return tile?.desc || ''
}

function formatCal(c) {
  if (!c) return '—'
  return typeof c === 'object' ? JSON.stringify(c) : String(c)
}

function switchTab(id) {
  tab.value = id
  reload()
}

function openTile(tile) {
  if (tile.href) {
    router.push(tile.href)
    return
  }
  if (tile.action === 'download_diag') {
    window.location.href = '/api/diagnostics/download'
    return
  }
  if (tile.tab) {
    tab.value = tile.tab
    reload()
  }
}

async function loadCatalog() {
  try {
    catalog.value = await getToolsCatalog()
  } catch (e) { toast('❌ ' + e.message) }
}

async function loadDiag() {
  try {
    diag.value = await getSystemDiagnostics()
  } catch (e) { toast('❌ ' + e.message) }
}

async function genDiag() {
  loading.value = true
  try {
    const j = await generateDiagnostics()
    if (j.saved_path) {
      diagMsg.value = j.saved_path
      toast('✅ ' + t('tools.diag_done'))
    } else {
      diagMsg.value = t('tools.diag_save_failed', { error: j.save_error || t('common.failed') })
      toast('❌ ' + diagMsg.value)
    }
  } catch (e) { toast('❌ ' + e.message) }
  finally { loading.value = false }
}

async function loadSyslog() {
  loading.value = true
  try {
    syslog.value = await getToolsSyslog(syslogMinutes.value, syslogLevel.value, 100)
  } catch (e) { toast('❌ ' + e.message) }
  finally { loading.value = false }
}

async function loadProc() {
  try {
    const j = await getSystemProcesses(40)
    processes.value = j.processes || []
  } catch (e) { toast('❌ ' + e.message) }
}

async function loadDocker() {
  try {
    const [a, b] = await Promise.all([
      getDockerDiskUsage(),
      getDockerContainerSizes(),
    ])
    df.value = a
    sizes.value = b.containers || []
  } catch (e) { toast('❌ ' + e.message) }
}

async function doPrune(what) {
  const labels = {
    dangling: t('tools.prune_dangling'),
    build: t('tools.prune_build'),
    volumes: t('tools.prune_volumes'),
    all_unused: t('tools.prune_all'),
  }
  if (!confirm(t('tools.prune_confirm', { what: labels[what] || what }))) return
  loading.value = true
  pruneMsg.value = ''
  try {
    const j = await pruneDocker(what)
    pruneMsg.value = j.message || ''
    toast(j.ok ? '✅ ' + (j.message || 'ok') : '❌ ' + (j.message || 'fail'))
    if (j.df) df.value = j.df
    await loadDocker()
  } catch (e) { toast('❌ ' + e.message) }
  finally { loading.value = false }
}

async function loadSched() {
  try {
    let j
    try {
      j = await getScheduler()
    } catch (e) {
      if (e.status !== 404) throw e
      j = await getSystemScheduler()
    }
    timers.value = j.timers || []
    agents.value = await getToolsAgents()
  } catch (e) { toast('❌ ' + e.message) }
}

async function loadHw() {
  loading.value = true
  try {
    hw.value = await getToolsHardware()
  } catch (e) { toast('❌ ' + e.message) }
  finally { loading.value = false }
}

async function loadUpdates() {
  loading.value = true
  try {
    updates.value = await getToolsUpdates()
  } catch (e) { toast('❌ ' + e.message) }
  finally { loading.value = false }
}

async function loadAbout() {
  try {
    about.value = await getToolsAbout()
  } catch (e) { toast('❌ ' + e.message) }
}

async function loadPorts() {
  try {
    ports.value = await getListeningPorts(50)
  } catch (e) { toast('❌ ' + e.message) }
}

async function doPing() {
  loading.value = true
  pingOut.value = ''
  try {
    const j = await pingHostApi(pingHost.value, 3)
    pingOut.value = j.output || j.message || ''
    toast(j.ok ? '✅ ping ok' : '❌ ping fail')
  } catch (e) { toast('❌ ' + e.message) }
  finally { loading.value = false }
}

async function doDns() {
  loading.value = true
  dnsOut.value = ''
  try {
    const j = await lookupDns(dnsName.value)
    if (j.ok) {
      dnsOut.value = (j.results || []).map(x => `${x.family} ${x.ip}`).join('\n')
        + (j.dig ? `\n\ndig:\n${j.dig}` : '')
    } else {
      dnsOut.value = j.message || 'fail'
    }
  } catch (e) { toast('❌ ' + e.message) }
  finally { loading.value = false }
}

async function doFlushDns() {
  loading.value = true
  try {
    const j = await flushDns()
    toast(j.ok ? '✅ ' + j.message : '❌ ' + j.message)
    dnsOut.value = (j.detail || []).join('\n')
  } catch (e) { toast('❌ ' + e.message) }
  finally { loading.value = false }
}

function reload() {
  if (tab.value === 'home') loadCatalog()
  else if (tab.value === 'diag') loadDiag()
  else if (tab.value === 'syslog') loadSyslog()
  else if (tab.value === 'proc') loadProc()
  else if (tab.value === 'docker') loadDocker()
  else if (tab.value === 'sched') loadSched()
  else if (tab.value === 'hw') loadHw()
  else if (tab.value === 'updates') loadUpdates()
  else if (tab.value === 'net') { loadPorts() }
  else if (tab.value === 'about') loadAbout()
}

onMounted(() => {
  loadCatalog()
})
</script>

<style scoped>
.tools-page {
  color: var(--txt);
  min-width: 0;
  overflow-x: hidden;
}

.hint-line,
.hint {
  color: var(--sub);
  font-size: 12px;
  line-height: 1.5;
  margin: 0 0 12px;
  word-break: break-word;
}

/* Top tab bar — wrap fully, no overflow off page */
.tools-tabs {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin-bottom: 8px;
  max-width: 100%;
}

.tools-tab {
  font-size: 12px;
  padding: 6px 11px;
  line-height: 1.3;
  white-space: nowrap;
  color: var(--sub);
  background: var(--card);
  border: 1px solid var(--line);
  border-radius: 6px;
  cursor: pointer;
  max-width: 100%;
}

.tools-tab:hover {
  border-color: var(--accent);
  color: var(--txt);
}

.tools-tab.active {
  color: var(--txt);
  font-weight: 600;
  border-color: var(--accent);
  background: color-mix(in srgb, var(--accent) 12%, var(--card));
}

/* Home tiles */
.tool-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
  gap: 10px;
  align-items: stretch;
  max-width: 100%;
}

.tool-tile {
  display: flex;
  flex-direction: column;
  align-items: stretch;
  text-align: left;
  padding: 12px 12px 14px;
  border-radius: 10px;
  border: 1px solid var(--line);
  background: var(--card);
  color: var(--txt);
  cursor: pointer;
  min-height: 108px;
  min-width: 0;
  max-width: 100%;
  height: 100%;
  box-sizing: border-box;
  overflow: hidden;
  transition: border-color .15s, transform .1s;
  /* reset global button look */
  font: inherit;
  font-weight: 400;
}

.tool-tile:hover {
  border-color: var(--accent);
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(0,0,0,.06);
}

.tile-label {
  font-weight: 700;
  font-size: 14px;
  line-height: 1.35;
  margin-bottom: 4px;
  color: var(--txt);
  white-space: normal;
  overflow-wrap: anywhere;
  word-break: break-word;
  hyphens: auto;
}

.tile-desc {
  font-size: 12px;
  line-height: 1.45;
  color: var(--sub);
  margin-top: 6px;
  white-space: normal;
  overflow-wrap: anywhere;
  word-break: break-word;
  display: -webkit-box;
  -webkit-box-orient: vertical;
  -webkit-line-clamp: 3;
  line-clamp: 3;
  overflow: hidden;
  flex: 1 1 auto;
}

.log-box {
  background: var(--card);
  border: 1px solid var(--line);
  border-radius: 8px;
  padding: 10px 12px;
  max-height: 480px;
  overflow: auto;
  font-size: 11px;
  line-height: 1.45;
  color: var(--txt);
  word-break: break-word;
}

.hw-pre {
  white-space: pre-wrap;
  word-break: break-word;
  font-size: 11px;
  max-height: 240px;
  overflow: auto;
  margin: 0;
  line-height: 1.4;
  color: var(--txt);
}

.update-list {
  margin: 0;
  padding-left: 18px;
  font-size: 12px;
  max-height: 280px;
  overflow: auto;
  line-height: 1.5;
  color: var(--txt);
  word-break: break-word;
}

.form-row {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
  align-items: center;
  margin-bottom: 10px;
}

.form-row input {
  flex: 1;
  min-width: 140px;
  max-width: 100%;
  box-sizing: border-box;
}

.net-out {
  font-size: 11px;
  white-space: pre-wrap;
  word-break: break-word;
  max-height: 220px;
  overflow: auto;
  margin: 0;
  background: var(--bg);
  color: var(--txt);
  border: 1px solid var(--line);
  padding: 8px;
  border-radius: 6px;
}

button.warn {
  border-color: var(--warn);
}

@media (max-width: 520px) {
  .tool-grid {
    grid-template-columns: 1fr 1fr;
  }
  .tools-tab {
    font-size: 11px;
    padding: 5px 8px;
  }
}
</style>
