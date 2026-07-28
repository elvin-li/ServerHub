<template>
  <div class="dash">
    <!-- Skeleton loading state -->
    <template v-if="!host && !sensors">
      <div class="host-strip">
        <div class="host-main">
          <div class="skeleton skeleton-title" style="width:140px"></div>
          <div class="skeleton skeleton-text" style="width:280px"></div>
        </div>
      </div>
      <div class="dash-grid">
        <div class="tile span-4" v-for="i in 3" :key="i">
          <div class="skeleton skeleton-title"></div>
          <div class="skeleton skeleton-card"></div>
        </div>
        <div class="tile span-6" v-for="i in 2" :key="'b'+i">
          <div class="skeleton skeleton-title"></div>
          <div class="skeleton skeleton-card" style="height:80px"></div>
        </div>
      </div>
    </template>

    <template v-else>
    <!-- Host strip — Unraid / Glances header -->
    <div class="host-strip">
      <div class="host-main">
        <div class="host-name">{{ host?.hostname || '—' }}</div>
        <div class="host-meta">
          <span>{{ host?.cpu || 'CPU' }}</span>
          <span class="dot">·</span>
          <span>{{ t('dashboard.cores', { n: ncpu }) }}</span>
          <span class="dot">·</span>
          <span>{{ memTotal }} GB RAM</span>
          <span class="dot">·</span>
          <span>{{ host?.lan_ip || host?.host_ip || '—' }}</span>
          <span class="dot">·</span>
          <span>{{ t('dashboard.uptime', { t: uptimeText }) }}</span>
        </div>
      </div>
      <div class="host-pills">
        <span class="pill" :class="engineUp ? 'ok' : 'down'">
          OrbStack {{ engineUp ? t('common.on') : t('common.off') }}
        </span>
        <span class="pill" :class="healthOk ? 'ok' : 'down'">
          {{ healthSummary }}
        </span>
        <span class="pill">{{ sensors?.ts || status?.ts || '…' }}</span>
       <button class="tiny" @click="refreshAll" :disabled="loading">{{ t('common.refresh') }}</button>
      <span class="pwr-group">
         <a class="tiny primary"
           :class="{ disabled: !ss.running }"
           :href="ss.running ? ss.vnc_url : undefined"
           :title="ss.running ? t('power.connect') : t('power.off')"
         ><Monitor :size="14" /></a>
         <button v-if="!ss.running" class="tiny primary" :disabled="ssBusy || loading" @click="enableSS" :title="t('power.enable_ss')"><Play :size="13" /></button>
         <button v-else class="tiny danger" :disabled="ssBusy" @click="disableSS" :title="t('power.disable_ss')"><Square :size="13" /></button>
         <button class="tiny" :disabled="!ss.vnc_url" @click="copyVnc" :title="t('power.copy')"><Copy :size="13" /></button>
      </span>
      <span class="pwr-group">
          <button class="tiny" @click="doPower('sleep')" :disabled="pwrBusy" title="Sleep"><Moon :size="13" /></button>
          <button class="tiny" @click="doPower('restart')" :disabled="pwrBusy" title="Restart"><RefreshCw :size="13" /></button>
          <button class="tiny danger" @click="doPower('shutdown')" :disabled="pwrBusy" title="Shutdown"><Power :size="13" /></button>
      </span>
      </div>
    </div>

    <div class="dash-grid">
      <!-- ===== CPU + Load ===== -->
      <div class="tile span-4 res-card">
        <h3>
          {{ t('dashboard.cpu') }}
          <span style="display:inline-flex;align-items:center;gap:6px;margin-left:auto">
            <span class="badge" :class="cpuBadge">{{ cpuUsed }}%</span>
            <span class="range-btns">
              <button class="tiny" :class="metricMins===60?'primary':''" @click="setMetricMins(60)">1h</button>
              <button class="tiny" :class="metricMins===360?'primary':''" @click="setMetricMins(360)">6h</button>
              <button class="tiny" :class="metricMins===1440?'primary':''" @click="setMetricMins(1440)">24h</button>
              <button class="tiny" :class="metricMins===2880?'primary':''" @click="setMetricMins(2880)">48h</button>
            </span>
          </span>
        </h3>
        <div class="res-head cpu-head">
          <div class="big">{{ cpuUsed }}<small>%</small></div>
        </div>
        <div class="cpu-facts">
          <div><span>user</span><b>{{ fmtN(cpu.user) }}%</b></div>
          <div><span>sys</span><b>{{ fmtN(cpu.sys) }}%</b></div>
          <div><span>idle</span><b>{{ fmtN(cpu.idle) }}%</b></div>
          <div><span>{{ t('dashboard.thermal_status') }}</span><b :class="thermal.pressure === 'warning' ? 'temp-warn' : ''">{{ thermalStatus }}</b></div>
        </div>
        <StackBar
          :segments="cpuStack"
          :total="100"
          unit="%"
        />
        <LineChart
          style="margin-top:8px"
          :height="80"
          :min="0"
          :max="100"
          percent
          :series="cpuChartSeries"
          unit="%"
        />
        <div class="sub" style="margin-top:6px">
          Load {{ fmtN(load1) }} / {{ fmtN(load5) }} / {{ fmtN(load15) }}
          · {{ t('dashboard.load_capacity', { p: loadPct }) }}
          <span class="badge" style="margin-left:4px">{{ t('dashboard.cores', { n: ncpu }) }}</span>
        </div>
      </div>

      <!-- ===== Memory ===== -->
      <div class="tile span-4 res-card">
        <h3>
          {{ t('dashboard.memory') }}
          <span class="badge" :class="memBadge">{{ t('dashboard.pressure_pct', { p: memUsedPct }) }}</span>
        </h3>
        <div class="res-head">
          <div class="big">{{ memAvailGb }}<small> {{ t('dashboard.gb_available') }}</small></div>
          <div class="res-side">
            <div class="kv-mini">
              <span>{{ t('dashboard.pressure') }}</span><b>{{ memUsedPct }}%</b>
              <span>{{ t('dashboard.free_rate') }}</span><b>{{ memFreePct }}%</b>
              <span>{{ t('dashboard.total') }}</span><b>{{ memTotal }} GB</b>
            </div>
          </div>
        </div>
        <div class="pct-bar thick" :class="memBarClass">
          <i :style="{ width: memUsedPct + '%' }"></i>
        </div>
        <div class="sub" style="margin-top:6px">
          {{ t('dashboard.mem_hint') }}
          <template v-if="mem.phys_used_gb != null">
            {{ t('dashboard.mem_allocated', { used: fmtN(mem.phys_used_gb), total: memTotal }) }}
          </template>
        </div>
        <div class="mem-break">
          <div class="mb">
            <span class="k">{{ t('dashboard.wired') }}</span>
            <span class="v">{{ fmtN(mem.wired_gb) }} GB</span>
          </div>
          <div class="mb">
            <span class="k">{{ t('dashboard.compressed') }}</span>
            <span class="v">{{ fmtN(mem.compressor_gb) }} GB</span>
          </div>
          <div class="mb">
            <span class="k">{{ t('dashboard.cache_approx') }}</span>
            <span class="v">{{ fmtN(mem.cache_gb) }} GB</span>
          </div>
        </div>
        <LineChart
          style="margin-top:6px"
          :height="72"
          :min="0"
          :max="100"
          percent
          :series="memChartSeries"
          unit="%"
        />
      </div>

      <!-- ===== Disk + SMART ===== -->
      <div class="tile span-4 res-card">
        <h3>
          {{ t('dashboard.disk_smart') }}
          <span class="disk-badges">
            <span class="badge" :class="barClass(diskPct) || ''">{{ diskPct }}%</span>
            <span class="badge" :class="smartSummaryClass">{{ smartSummary }}</span>
          </span>
        </h3>
        <div class="res-head disk-head">
          <div class="big">{{ formatCapacityGb(diskUsed) }}<small> / {{ formatCapacityGb(diskTotal) }}</small></div>
          <div class="sub">{{ t('dashboard.disk_free_short', { free: formatCapacityGb(diskFree) }) }}</div>
        </div>
        <div class="pct-bar thick" :class="barClass(diskPct)">
          <i :style="{ width: diskPct + '%' }"></i>
        </div>
        <div class="disk-list">
          <div v-for="d in smartDisks" :key="d.id" class="disk-item">
            <div class="disk-primary">
              <strong :title="d.smart?.model || d.name || d.id">{{ d.name || d.smart?.model || d.id }}</strong>
              <span class="disk-primary-meta">
                <span v-if="formatDiskSize(d)" class="disk-capacity">{{ formatDiskSize(d) }}</span>
                <span class="badge" :class="smartBadgeClass(d)">{{ smartHealthLabel(d) }}</span>
              </span>
            </div>
            <div v-if="d.smart" class="disk-facts">
              <span class="disk-temp">{{ d.smart.temp || '—' }}</span>
              <span>{{ t('dashboard.wear') }} <b>{{ d.smart.wear || '—' }}</b></span>
              <span>{{ t('dashboard.written') }} <b>{{ d.smart.written || '—' }}</b></span>
              <span v-if="d.smart.media_errors != null">{{ t('dashboard.media_errors') }} <b>{{ d.smart.media_errors }}</b></span>
            </div>
            <div v-else class="disk-unavailable" :title="d.error || ''">{{ t('dashboard.smart_unavailable_short') }}</div>
          </div>
          <div v-if="!smartDisks.length" class="disk-empty">{{ t('dashboard.no_smart_disks') }}</div>
        </div>
        <LineChart
          style="margin-top:5px"
          :height="52"
          :min="0"
          :max="100"
          percent
          :series="diskChartSeries"
          unit="%"
        />
      </div>

      <!-- ===== Network + processes ===== -->
      <div class="tile span-4">
        <h3>{{ t('dashboard.net_proc') }}</h3>
        <div class="net-stats">
          <div class="ns">
            <div class="k">↓ RX</div>
            <div class="v2">{{ formatBps(net.rx_bps) }}</div>
          </div>
          <div class="ns">
            <div class="k">↑ TX</div>
            <div class="v2">{{ formatBps(net.tx_bps) }}</div>
          </div>
          <div class="ns">
            <div class="k">{{ t('dashboard.process') }}</div>
            <div class="v2">{{ cpu.proc_total ?? '—' }} <small class="sub">run {{ cpu.proc_running ?? '—' }}</small></div>
          </div>
        </div>
        <h2 class="section-title" style="margin-top:10px">{{ t('dashboard.top_cpu') }}</h2>
        <div class="table-wrap">
          <table class="dense">
            <thead>
              <tr><th>{{ t('dashboard.col_process') }}</th><th>CPU%</th><th>MEM%</th><th>RSS</th></tr>
            </thead>
            <tbody>
              <tr v-for="p in topProcs" :key="p.pid">
                <td :title="'pid '+p.pid"><strong>{{ p.name }}</strong></td>
                <td class="mono">
                  {{ p.cpu }}
                  <span class="mini-bar"><i :style="{ width: Math.min(100, p.cpu) + '%' }"></i></span>
                </td>
                <td class="mono">{{ p.mem }}</td>
                <td class="mono">{{ p.rss_mb }}M</td>
              </tr>
              <tr v-if="!topProcs.length">
                <td colspan="4" style="color:var(--sub)">{{ t('common.loading') }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- ===== Storage array ===== -->
      <div class="tile span-4">
        <h3>
          {{ t('dashboard.array') }}
          <router-link class="btn tiny" to="/main">{{ t('common.open') }}</router-link>
        </h3>
        <table class="dense">
          <thead>
            <tr>
              <th>{{ t('dashboard.col_mount') }}</th>
              <th>{{ t('dashboard.col_type') }}</th>
              <th>{{ t('dashboard.col_capacity') }}</th>
              <th>{{ t('dashboard.col_used') }}</th>
              <th>{{ t('dashboard.col_free') }}</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="v in (storage?.volumes || []).slice(0, 8)" :key="v.mount">
              <td class="mono">{{ shortMount(v) }}</td>
              <td><span class="badge accent">{{ v.kind }}</span></td>
              <td>{{ v.total_gb }} GB</td>
              <td>{{ v.used_gb }} GB</td>
              <td>{{ v.avail_gb }} GB</td>
              <td style="min-width:100px">
                <strong :style="{ color: v.pct >= 90 ? 'var(--down)' : (v.pct >= 75 ? 'var(--warn)' : 'inherit') }">{{ v.pct }}%</strong>
                <div class="pct-bar" :class="barClass(v.pct)" style="margin-top:3px">
                  <i :style="{ width: v.pct + '%' }"></i>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <!-- ===== Docker ===== -->
      <div class="tile span-4">
        <h3>
          Docker
          <span class="badge">{{ containers.length }}</span>
          <span v-if="cstatsStale" class="badge warn" :title="t('dashboard.stats_stale_hint')">
            {{ t('dashboard.stats_stale') }}
          </span>
          <router-link class="btn tiny" to="/containers">{{ t('common.manage') }}</router-link>
        </h3>
        <table class="dense">
          <thead>
            <tr><th></th><th>{{ t('dashboard.col_name') }}</th><th>{{ t('dashboard.col_status') }}</th><th>{{ t('dashboard.col_cpu') }}</th><th>{{ t('dashboard.col_mem') }}</th><th></th></tr>
          </thead>
          <tbody>
            <tr v-for="c in containers.slice(0, 10)" :key="c.id">
              <td><span class="led" :class="led(c.state)"></span></td>
              <td>
                <strong>{{ c.name }}</strong>
                <div class="mono" style="color:var(--sub);font-size:10px">{{ shortImage(c.image) }}</div>
              </td>
              <td style="font-size:11px">{{ c.status }}</td>
              <td class="mono">
                {{ cstats[c.id]?.cpu || '—' }}
                <span v-if="cpuNum(cstats[c.id]?.cpu)!=null" class="mini-bar">
                  <i :style="{ width: Math.min(100, cpuNum(cstats[c.id]?.cpu)) + '%' }"></i>
                </span>
              </td>
              <td class="mono">{{ cstats[c.id]?.mem_pct || cstats[c.id]?.mem || '—' }}</td>
              <td>
                <a v-if="c.url" class="btn tiny primary" :href="c.url" target="_blank">WebUI</a>
              </td>
            </tr>
            <tr v-if="!containers.length">
              <td colspan="6" style="color:var(--sub)">{{ t('dashboard.no_containers') }}</td>
            </tr>
          </tbody>
        </table>
      </div>

      <!-- ===== Attention ===== -->
      <div class="tile span-4">
        <h3>
          {{ t('dashboard.attention') }}
          <span class="badge" :class="attention.length ? 'down' : 'ok'">{{ attention.length }}</span>
          <span class="sub" style="font-weight:500;text-transform:none;letter-spacing:0">
            {{ t('dashboard.services_count', { total: status?.service_total ?? '—', ok: status?.counts?.ok ?? 0 }) }}
          </span>
        </h3>
        <div v-if="!attention.length" class="sub ok-msg">{{ t('dashboard.all_ok') }}</div>
        <div v-else class="alert-list">
          <div v-for="s in attention.slice(0, 10)" :key="s.id" class="alert-item">
            <span class="led" :class="led(s.state)"></span>
            <div style="flex:1;min-width:0">
              <div class="name">{{ s.name }}</div>
              <div class="detail" style="margin:0">{{ s.group }} · {{ s.detail }}</div>
            </div>
            <button
              v-for="a in (s.actions || []).filter(x => ['start','restart'].includes(x)).slice(0,1)"
              :key="a"
              class="tiny primary"
              :disabled="busy"
              @click="act(s, a)"
            >{{ labels[a] || a }}</button>
          </div>
        </div>
        <h3 style="margin-top:12px">{{ t('dashboard.recent_alerts') }}</h3>
        <div v-if="!alerts.length" class="sub">{{ t('common.none') }}</div>
        <div v-for="(a,i) in alerts.slice(0,5)" :key="i" class="alert-item">
          <span class="led" :class="a.level === 'ok' ? 'on' : (a.level === 'warn' ? 'warn' : 'err')"></span>
          <div style="flex:1">
            <div class="name">{{ a.name }}</div>
            <div class="detail" style="margin:0">{{ fmt(a.t) }} · {{ a.message }}</div>
          </div>
        </div>
      </div>

      <!-- ===== Ports ===== -->
      <div class="tile span-4">
        <h3>
          {{ t('dashboard.ports') }}
          <router-link class="btn tiny" to="/network">{{ t('nav.network') }}</router-link>
        </h3>
        <table class="dense">
          <thead><tr><th>{{ t('dashboard.col_process') }}</th><th>{{ t('dashboard.col_port') }}</th><th>{{ t('dashboard.col_addr') }}</th></tr></thead>
          <tbody>
            <tr v-for="(p,i) in ports.slice(0, 12)" :key="i">
              <td>{{ p.process }}</td>
              <td class="mono">{{ p.port }}</td>
              <td class="mono" style="font-size:10px">{{ p.address }}</td>
            </tr>
            <tr v-if="!ports.length"><td colspan="3" style="color:var(--sub)">—</td></tr>
          </tbody>
        </table>
      </div>

      <!-- ===== Health + Bookmarks ===== -->
      <div class="tile span-4">
        <h3>
          {{ t('dashboard.health') }}
          <router-link class="btn tiny" to="/health">{{ t('dashboard.scan') }}</router-link>
          <router-link class="btn tiny" to="/bookmarks">{{ t('common.all') }}</router-link>
        </h3>
        <div class="health-grid" v-if="health?.summary">
          <div class="hg ok"><div class="n">{{ health.summary.ok }}</div><div class="l">{{ t('health.passed') }}</div></div>
          <div class="hg warn"><div class="n">{{ health.summary.warn }}</div><div class="l">{{ t('health.warnings') }}</div></div>
          <div class="hg err"><div class="n">{{ health.summary.error }}</div><div class="l">{{ t('health.errors') }}</div></div>
        </div>
        <div class="failed-checks" v-if="failedChecks.length">
          <div v-for="c in failedChecks.slice(0, 3)" :key="c.id" class="alert-item">
            <span class="led" :class="c.level === 'error' ? 'err' : 'warn'"></span>
            <div style="flex:1">
              <div class="name">{{ c.name }}</div>
              <div class="detail" style="margin:0">{{ c.detail }}</div>
            </div>
          </div>
        </div>
        <div class="sub" style="margin-top:8px" v-if="status?.adaptive">
          {{ t('dashboard.adaptive') }}：
          {{ t('dashboard.adaptive_line', {
            auto: status.adaptive.auto_labeled || 0,
            orphan: status.adaptive.orphan_count || 0,
            compose: (status.adaptive.compose_projects || []).length,
            nginx: (status.adaptive.nginx_sites || []).length,
          }) }}
        </div>
        <div class="bm-grid" v-if="bookmarks.length" style="margin-top:10px">
          <a
            v-for="b in bookmarks.slice(0, 9)"
            :key="b.url"
            class="bm-card"
            :class="bmClass(b)"
            :href="b.url"
            target="_blank"
            rel="noopener"
            :title="b.url"
          >
            <span class="led" :class="bmLed(b)"></span>
            <span class="bm-name">{{ b.name }}</span>
            <span class="bm-meta">{{ bmLabel(b) }}</span>
          </a>
        </div>
      </div>
    </div>
    </template>
  </div>
</template>

<script setup>
import { computed, inject, onMounted, onUnmounted, ref } from 'vue'
import { Monitor, Play, Square, Copy, Moon, RefreshCw, Power } from '@lucide/vue'
import { startVisibleInterval } from '../lib/poll'
import LineChart from '../components/LineChart.vue'
import StackBar from '../components/StackBar.vue'
import {
  doAction, disableScreenSharing, enableScreenSharing, getAlerts, getBookmarks,
  getContainers, getHealthChecks, getHost, getMetrics, getPower, getStatus,
  getStorage, getListeningPorts, getSensors, powerAction,
} from '../api/client'
import { injectI18n } from '../i18n'

const toast = inject('toast')
const { t } = injectI18n()

const status = ref(null)
const storage = ref(null)
const host = ref(null)
const metrics = ref([])
const alerts = ref([])
const containers = ref([])
const cstats = ref({})
// When the CPU/MEM figures in cstats were last actually collected.  The 90s
// heavy tick deliberately skips `docker stats` (it costs ~2s), so those columns
// would otherwise freeze at whatever the first paint captured with no hint to
// the operator that they are no longer live.
const cstatsAt = ref(0)
//: True once the displayed CPU/MEM figures are older than two heavy ticks.
// Ticked by the 12s light interval.  Date.now() on its own is not a reactive
// dependency, so without this ref the staleness badge would be computed once
// and then never re-evaluated.
const clock = ref(Date.now())
const cstatsStale = computed(
  () => cstatsAt.value > 0 && clock.value - cstatsAt.value > 180000
)
const ports = ref([])
const sensors = ref(null)
const bookmarks = ref([])
const health = ref(null)
const busy = ref(false)
const loading = ref(false)
const pwrBusy = ref(false)
const ssBusy = ref(false)
const powerData = ref({})
const metricMins = ref(60)
let timer = null
let heavyTimer = null
const labels = computed(() => ({
  restart: t('dashboard.act_restart'),
  stop: t('dashboard.act_stop'),
  start: t('dashboard.act_start'),
  run: t('dashboard.act_run'),
}))

const sys = computed(() => status.value?.system || {})
const cpu = computed(() => sensors.value?.cpu || {})
const mem = computed(() => sensors.value?.memory || {})
const net = computed(() => sensors.value?.network || {})
const thermal = computed(() => cpu.value?.thermal || sensors.value?.thermal || {})
const smartDisks = computed(() => storage.value?.disks || [])
const topProcs = computed(() => sensors.value?.top_processes || [])
const engineUp = computed(() => !!status.value?.engine_up)
const ss = computed(() => powerData.value?.screen_sharing || {})
const ncpu = computed(() => cpu.value.ncpu || sys.value.ncpu || host.value?.ncpu || 1)

const load1 = computed(() => cpu.value.load1 ?? sys.value.load1)
const load5 = computed(() => cpu.value.load5 ?? sys.value.load5)
const load15 = computed(() => cpu.value.load15 ?? sys.value.load15)
const loadPct = computed(() => cpu.value.load_pct ?? sys.value.load_pct ?? 0)
const cpuUsed = computed(() => {
  const v = sensors.value?.cpu_used_pct ?? cpu.value.used_pct
  return v != null ? Number(v) : 0
})
const cpuBadge = computed(() => {
  if (cpuUsed.value >= 90) return 'down'
  if (cpuUsed.value >= 70) return 'warn'
  return 'ok'
})
const thermalStatus = computed(() =>
  thermal.value.pressure === 'warning'
    ? t('dashboard.thermal_warning')
    : (thermal.value.pressure === 'normal' ? t('dashboard.thermal_normal') : t('dashboard.thermal_unknown'))
)
function smartIsOk(d) {
  const h = String(d?.smart?.health || '').toUpperCase()
  return !!d?.smart && (h.includes('PASSED') || h === 'OK')
}
function smartBadgeClass(d) {
  if (!d?.smart) return ''
  return smartIsOk(d) ? 'ok' : 'down'
}
function smartHealthLabel(d) {
  if (!d?.smart) return t('dashboard.smart_na')
  return smartIsOk(d) ? t('dashboard.smart_passed') : (d.smart.health || t('dashboard.smart_warning'))
}
function formatDiskSize(d) {
  if (d?.size) return d.size
  const gb = Number(d?.size_gb)
  if (!Number.isFinite(gb) || gb <= 0) return ''
  return gb >= 1024 ? `${(gb / 1024).toFixed(gb >= 10240 ? 0 : 1)} TB` : `${Math.round(gb)} GB`
}
function formatCapacityGb(value) {
  const gb = Number(value)
  if (!Number.isFinite(gb)) return '—'
  if (gb >= 1024) return `${(gb / 1024).toFixed(gb >= 10240 ? 0 : 2)} TB`
  return `${fmtN(gb)} GB`
}
const smartReadableCount = computed(() => smartDisks.value.filter(d => d.smart).length)
const smartHasWarning = computed(() => smartDisks.value.some(d => d.smart && !smartIsOk(d)))
const smartSummaryClass = computed(() => smartHasWarning.value ? 'down' : (smartReadableCount.value ? 'ok' : ''))
const smartSummary = computed(() => t('dashboard.smart_summary', {
  ok: smartReadableCount.value,
  total: smartDisks.value.length,
}))
const cpuStack = computed(() => [
  { label: 'user', value: cpu.value.user || 0, color: 'var(--accent)' },
  { label: 'sys', value: cpu.value.sys || 0, color: 'var(--warn)' },
  { label: 'idle', value: cpu.value.idle || 0, color: 'var(--bar-track)' },
])
const memTotal = computed(() => mem.value.total_gb ?? '—')
// pressure-based (macOS); NOT PhysMem cache-inflated used%
const memUsedPct = computed(() => {
  if (mem.value.pressure_used_pct != null) return mem.value.pressure_used_pct
  if (mem.value.used_pct != null) return mem.value.used_pct
  if (sys.value.mem_free_pct != null) return 100 - sys.value.mem_free_pct
  return 0
})
const memFreePct = computed(() =>
  mem.value.pressure_free_pct ?? mem.value.free_pct ?? sys.value.mem_free_pct ?? '—'
)
const memAvailGb = computed(() =>
  mem.value.available_gb ?? mem.value.free_gb ?? '—'
)
// Looser thresholds: pressure 12% is fine; red only when truly tight
const memBadge = computed(() => {
  const p = Number(memUsedPct.value) || 0
  if (p >= 85) return 'down'
  if (p >= 70) return 'warn'
  return 'ok'
})
const memBarClass = computed(() => {
  const p = Number(memUsedPct.value) || 0
  if (p >= 85) return 'danger'
  if (p >= 70) return 'warn'
  return ''
})

const diskArray = computed(() => storage.value?.array || {})
const diskUsed = computed(() => diskArray.value.used_gb ?? sensors.value?.disk?.root_used_gb ?? sys.value.disk_used_gb ?? '—')
const diskTotal = computed(() => diskArray.value.total_gb ?? sensors.value?.disk?.root_total_gb ?? sys.value.disk_total_gb ?? '—')
const diskFree = computed(() => diskArray.value.free_gb ?? sensors.value?.disk?.root_free_gb ?? sys.value.disk_free_gb ?? '—')
const diskPct = computed(() => {
  const total = Number(diskTotal.value)
  const used = Number(diskUsed.value)
  if (Number.isFinite(total) && total > 0 && Number.isFinite(used)) return Math.round(used / total * 100)
  return sensors.value?.disk?.root_pct ?? sys.value.disk_pct ?? 0
})

const uptimeText = computed(() =>
  sensors.value?.uptime?.uptime_text || sys.value.uptime || '—'
)

const healthOk = computed(() => health.value?.healthy !== false && !(health.value?.summary?.error > 0))
const healthSummary = computed(() => {
  if (!health.value) return '…'
  if (health.value.healthy) return '✅ ' + t('common.healthy')
  const e = health.value.summary?.error || 0
  const w = health.value.summary?.warn || 0
  return e ? `❌ ${e}` : `⚠️ ${w}`
})
const failedChecks = computed(() => (health.value?.checks || []).filter(c => !c.ok))

const attention = computed(() => {
  if (!status.value) return []
  const list = []
  for (const g of status.value.groups || []) {
    for (const s of g.services || []) {
      // 主动停止(stopped)不算需要关注；仅 warn/down
      if (s.state && s.state !== 'ok' && s.state !== 'stopped') list.push(s)
    }
  }
  return list
})

function bmHealth(b) {
  if (b?.health) return b.health
  return b?.ok ? 'ok' : 'error'
}
function bmClass(b) {
  const h = bmHealth(b)
  if (h === 'stopped') return 'stopped'
  if (h === 'error' || b?.ok === false) return 'down'
  return ''
}
function bmLed(b) {
  const h = bmHealth(b)
  if (h === 'ok') return 'on'
  if (h === 'stopped') return 'off'
  return 'err'
}
function bmLabel(b) {
  const h = bmHealth(b)
  if (h === 'ok') return b.ms != null ? b.ms + ' ms' : t('dashboard.bm_up')
  if (h === 'stopped') return t('dashboard.bm_stopped')
  return t('dashboard.bm_down')
}

const cpuChartSeries = computed(() => [
  {
    name: t('dashboard.chart_cpu'),
    values: (metrics.value || []).map(p => p.cpu_used_pct ?? null),
    color: 'var(--accent)',
  },
  {
    name: t('dashboard.chart_load_cap'),
    values: (metrics.value || []).map(p => {
      if (p.load_pct != null) return Math.min(100, p.load_pct)
      if (p.load1 != null) return Math.min(100, (p.load1 / (p.ncpu || ncpu.value || 1)) * 100)
      return null
    }),
    color: 'var(--warn)',
    width: 1.5,
  },
])

const memChartSeries = computed(() => [
  {
    name: t('dashboard.chart_mem_pressure'),
    values: (metrics.value || []).map(p => {
      if (p.mem_used_pct != null) return p.mem_used_pct
      if (p.mem_free_pct != null) return 100 - p.mem_free_pct
      return null
    }),
    color: 'var(--ok)',
  },
])

const diskChartSeries = computed(() => [
  {
    name: t('dashboard.chart_disk'),
    values: (metrics.value || []).map(p => p.disk_pct ?? null),
    color: 'var(--warn)',
  },
])

function setMetricMins(m) {
  metricMins.value = m
  loadMetrics()
}
async function loadPower() {
  try {
    powerData.value = await getPower()
  } catch {}
}
async function doPower(action) {
  const names = { sleep: t('power.sleep'), restart: t('power.restart'), shutdown: t('power.shutdown') }
  if (!confirm(t('power.confirm1', { a: names[action] }))) return
  if (action !== 'sleep' && !confirm(t('power.confirm2', { a: names[action] }))) return
  pwrBusy.value = true
  try {
    const r = await powerAction(action, true)
    toast(r.ok ? `✅ ${r.message}` : `❌ ${r.message}`)
  } catch (e) {
    toast('❌ ' + e.message)
  }
  pwrBusy.value = false
}
async function enableSS() {
  ssBusy.value = true
  try {
    const r = await enableScreenSharing()
    toast(r.ok ? `✅ ${r.message}` : `⚠️ ${r.message}`)
    await loadPower()
  } catch (e) {
    toast('❌ ' + e.message)
  }
  ssBusy.value = false
}
async function disableSS() {
  if (!confirm(t('power.confirm_disable_ss'))) return
  ssBusy.value = true
  try {
    const r = await disableScreenSharing()
    toast(r.ok ? `✅ ${r.message}` : `⚠️ ${r.message}`)
    await loadPower()
  } catch (e) {
    toast('❌ ' + e.message)
  }
  ssBusy.value = false
}
function copyVnc() {
  const text = ss.value?.vnc_url
  if (!text) return
  try {
    navigator.clipboard.writeText(text)
    toast('✅ ' + t('power.copied'))
  } catch {
    toast('❌ ' + text)
  }
}
function barClass(pct) {
  if (pct >= 90) return 'danger'
  if (pct >= 75) return 'warn'
  return ''
}
function shortMount(v) {
  if (v.mount === '/') return t('dashboard.mount_system')
  if (v.mount === '/System/Volumes/Data') return 'Data'
  if (v.mount.startsWith('/Volumes/')) return v.mount.slice(9)
  if (v.kind === 'orbstack') return t('dashboard.mount_orbstack')
  return v.mount
}
function shortImage(img) {
  if (!img) return ''
  const s = String(img).split('/').pop()
  return s.length > 36 ? s.slice(0, 34) + '…' : s
}
function led(state) {
  if (state === 'ok') return 'on'
  if (state === 'warn') return 'warn'
  if (state === 'stopped') return 'off'
  return 'err'
}
function fmt(ts) {
  return ts ? new Date(ts * 1000).toLocaleString() : ''
}
function fmtN(v) {
  if (v == null || Number.isNaN(v)) return '—'
  return typeof v === 'number' ? (Math.abs(v) >= 10 ? Math.round(v * 10) / 10 : Number(v.toFixed(2))) : v
}
function cpuNum(s) {
  if (!s) return null
  const n = parseFloat(String(s).replace('%', ''))
  return Number.isFinite(n) ? n : null
}
function formatBps(bps) {
  if (bps == null) return '—'
  if (bps < 1024) return `${bps} B/s`
  if (bps < 1024 ** 2) return `${(bps / 1024).toFixed(1)} KB/s`
  if (bps < 1024 ** 3) return `${(bps / 1024 ** 2).toFixed(1)} MB/s`
  return `${(bps / 1024 ** 3).toFixed(2)} GB/s`
}

async function refresh() {
  try { status.value = await getStatus() } catch {}
}
async function loadSensors(force = false) {
  try {
    // Prefer cache (server TTL ~6s); force only on manual refresh
    sensors.value = await getSensors(force)
  } catch {}
}
async function loadMetrics() {
  try {
    const m = await getMetrics(metricMins.value)
    metrics.value = m.points || []
  } catch {}
}
async function refreshHeavy(forceSensors = false, withDockerStats = false) {
  loading.value = true
  // stats=false avoids ~2s docker stats on every heavy tick; cache on server is 15s when true
  await Promise.all([
    loadMetrics(),
    loadSensors(forceSensors),
    getStorage(true).then(s => { storage.value = s }).catch(() => {}),
    getHost().then(h => { host.value = h }).catch(() => {}),
    getAlerts(12).then(a => { alerts.value = a.alerts || [] }).catch(() => {}),
    getContainers(withDockerStats).then(c => {
      containers.value = c.containers || []
      // The 90s tick asks for stats=false (docker stats costs ~2s), so the
      // response carries an empty map and the previous numbers are kept.
      // Record when they were actually measured: otherwise the CPU/MEM columns
      // silently show minutes-old values with nothing marking them stale.
      if (c.stats && Object.keys(c.stats).length) {
        cstats.value = c.stats
        cstatsAt.value = Date.now()
      }
    }).catch(() => {}),
    // Cheap lsof-only endpoint: the full /api/system/network overview fans out
    // networksetup per service plus docker network inspect per network, which
    // is far too much work for one tile that renders 12 rows.
    getListeningPorts(40).then(p => { ports.value = p.ports || [] }).catch(() => {}),
    getBookmarks().then(b => { bookmarks.value = b.bookmarks || [] }).catch(() => {}),
    getHealthChecks().then(h => { health.value = h }).catch(() => {}),
    loadPower(),
  ])
  loading.value = false
}
async function refreshAll() {
  await Promise.all([refresh(), refreshHeavy(true, true)])
}
async function act(svc, action) {
  busy.value = true
  const r = await doAction(svc.id, action)
  toast(r.ok ? `✅ ${svc.name}` : `❌ ${(r.message || '').slice(0, 80)}`)
  busy.value = false
  setTimeout(refresh, 1000)
}

onMounted(() => {
  refresh()
  // first paint: include docker stats once
  refreshHeavy(true, true)
  // light: status + sensors from cache; pause when tab hidden
  timer = startVisibleInterval(() => {
    refresh()
    loadSensors(false)
    clock.value = Date.now()
  }, 12000)
  // heavy: no docker stats; manual refresh still pulls stats
  heavyTimer = startVisibleInterval(() => refreshHeavy(false, false), 90000)
})
onUnmounted(() => {
  if (typeof timer === 'function') timer()
  if (typeof heavyTimer === 'function') heavyTimer()
})
</script>

<style scoped>
.dash { }
.dash-grid { gap: 10px; }
.dash-grid > .tile { min-width: 0; overflow: hidden; }
.alert-item > * { min-width: 0; overflow-wrap: anywhere; }
.host-strip {
  display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between;
  gap: 10px; margin-bottom: 12px;
  padding: 12px 16px;
  background: var(--card);
  border: 1px solid var(--line);
  border-left: 3px solid var(--accent);
  border-radius: var(--radius);
  box-shadow: var(--card-shadow);
}
.host-name { font-size: 18px; font-weight: 800; letter-spacing: -.2px; }
.host-meta { color: var(--sub); font-size: 12px; margin-top: 4px; display: flex; flex-wrap: wrap; gap: 5px; }
.host-meta .dot { opacity: .35; }
.host-pills { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; }
.host-pills .pill {
  background: var(--btn); border: 1px solid var(--line);
  color: var(--txt); padding: 4px 10px; border-radius: 999px; font-size: 11px; font-weight: 600;
}
.host-pills .pill.ok { background: color-mix(in srgb, var(--ok) 14%, transparent); color: var(--ok); border-color: transparent; }
.host-pills .pill.down { background: color-mix(in srgb, var(--down) 12%, transparent); color: var(--down); border-color: transparent; }

.res-card .big {
  font-size: 28px; font-weight: 800; line-height: 1.1;
  letter-spacing: -0.5px;
}
.res-card .big small {
  font-size: 13px; font-weight: 600; color: var(--sub); margin-left: 2px;
}
.res-head {
  display: flex; justify-content: space-between; align-items: flex-start;
  gap: 8px; margin-bottom: 8px;
}
.cpu-head { margin-bottom: 4px; }
.cpu-facts { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 5px; margin-bottom: 8px; }
.cpu-facts > div { min-width: 0; padding: 5px 6px; border: 1px solid var(--line); border-radius: 4px; background: var(--bg); }
.cpu-facts span, .cpu-facts b { display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.cpu-facts span { color: var(--sub); font-size: 9px; text-transform: uppercase; letter-spacing: .3px; }
.cpu-facts b { margin-top: 2px; color: var(--txt); font: 700 11px ui-monospace, Menlo, monospace; }

.pct-bar.thick { height: 9px; margin-top: 4px; }
.load-rows { margin-top: 8px; display: flex; flex-direction: column; gap: 4px; }
.load-row { display: grid; grid-template-columns: 28px 1fr 42px; gap: 8px; align-items: center; font-size: 11px; }
.lr-l { color: var(--sub); font-weight: 700; }
.lr-bar { height: 7px; background: var(--bar-track); border-radius: 3px; overflow: hidden; }
.lr-bar i { display: block; height: 100%; border-radius: 3px; transition: width .4s ease; }
.lr-v { text-align: right; }

.mem-break {
  display: grid; grid-template-columns: repeat(3, 1fr); gap: 6px;
  margin-top: 8px;
}
.mb {
  background: var(--bg); border-radius: 4px; padding: 5px 8px;
  border: 1px solid var(--line);
}
.mb .k { font-size: 9px; color: var(--sub); text-transform: uppercase; letter-spacing: .3px; }
.mb .v { font-size: 13px; font-weight: 700; margin-top: 2px; font-family: ui-monospace, Menlo, monospace; }

.temp-warn { color: var(--warn) !important; }
.disk-badges { display: inline-flex; align-items: center; gap: 4px; }
.disk-head { align-items: end; }
.disk-head .sub { margin: 0; white-space: nowrap; }
.disk-list { display: flex; flex-direction: column; gap: 4px; margin-top: 8px; }
.disk-item { min-width: 0; padding: 5px 8px; border: 1px solid var(--line); border-radius: 4px; background: var(--bg); }
.disk-primary { display: flex; align-items: center; justify-content: space-between; gap: 6px; min-width: 0; }
.disk-primary strong { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 11px; }
.disk-primary-meta { flex: 0 0 auto; display: inline-flex; align-items: center; gap: 4px; }
.disk-capacity { color: var(--txt); font: 700 10px ui-monospace, Menlo, monospace; white-space: nowrap; }
.disk-facts { display: flex; flex-wrap: wrap; gap: 2px 8px; margin-top: 3px; color: var(--sub); font-size: 10px; line-height: 1.3; }
.disk-facts b { color: var(--txt); font-family: ui-monospace, Menlo, monospace; }
.disk-temp { color: var(--txt); font-weight: 700; font-family: ui-monospace, Menlo, monospace; }
.disk-unavailable, .disk-empty { margin-top: 2px; color: var(--sub); font-size: 10px; line-height: 1.25; }

.net-stats {
  display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px;
}
.ns {
  background: var(--bg); border: 1px solid var(--line); border-radius: 4px; padding: 10px;
}
.ns .k { font-size: 9px; color: var(--sub); text-transform: uppercase; letter-spacing: .3px; }
.ns .v2 { font-size: 15px; font-weight: 800; margin-top: 3px; font-family: ui-monospace, Menlo, monospace; }

.chart-intro {
  display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 8px;
  font-size: 12px; color: var(--sub);
}
.chart-intro b { color: var(--txt); font-family: ui-monospace, Menlo, monospace; }
.range-btns { display: inline-flex; gap: 3px; }
.pwr-group { display: inline-flex; align-items: center; gap: 3px; margin-left: 4px; }
.pwr-group .tiny { font-size: 12px; padding: 2px 6px; text-decoration: none; display: inline-flex; align-items: center; justify-content: center; }
.pwr-group a.tiny.disabled { opacity: .4; pointer-events: none; cursor: not-allowed; }
.hint-line { margin-top: 8px; font-size: 11px; color: var(--sub); line-height: 1.5; }
.ok-msg { color: var(--ok); font-weight: 600; padding: 8px 0; }

.health-grid {
  display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px;
}
.hg {
  text-align: center; padding: 12px 6px; border-radius: 4px;
  border: 1px solid var(--line); background: var(--bg);
}
.hg .n { font-size: 24px; font-weight: 800; }
.hg .l { font-size: 9px; color: var(--sub); text-transform: uppercase; margin-top: 3px; letter-spacing: .3px; }
.hg.ok .n { color: var(--ok); }
.hg.warn .n { color: var(--warn); }
.hg.err .n { color: var(--down); }
.failed-checks { margin-top: 10px; display: flex; flex-direction: column; gap: 4px; }

/* Bookmark health — equal cards, aligned grid */
.bm-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(145px, 1fr));
  gap: 8px;
}
.bm-card {
  display: grid;
  grid-template-columns: 14px 1fr;
  grid-template-rows: auto auto;
  column-gap: 8px;
  row-gap: 4px;
  align-items: center;
  min-height: 56px;
  padding: 10px 12px;
  background: var(--bg);
  border: 1px solid var(--line);
  border-radius: var(--radius);
  color: var(--txt);
  text-decoration: none;
  transition: border-color .15s, background .15s, transform .1s;
}
.bm-card:hover { border-color: var(--accent); background: var(--table-hover); transform: translateY(-1px); }
.bm-card.down { border-color: color-mix(in srgb, var(--down) 45%, var(--line)); }
.bm-card.stopped { border-color: color-mix(in srgb, #888 35%, var(--line)); opacity: 0.85; }
.bm-card .led { grid-row: 1 / span 2; align-self: center; }
.bm-name {
  grid-column: 2;
  font-size: 12px;
  font-weight: 700;
  line-height: 1.25;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  min-width: 0;
  color: var(--accent);
}
.bm-card.down .bm-name { color: var(--down); }
.bm-card.stopped .bm-name { color: var(--sub); }
.bm-meta {
  grid-column: 2;
  font-size: 11px;
  color: var(--sub);
  font-variant-numeric: tabular-nums;
  font-family: ui-monospace, Menlo, monospace;
  line-height: 1.2;
}

/* === Mobile responsive === */
@media (max-width: 640px) {
  .host-strip { flex-direction: column; align-items: flex-start; padding: 10px 12px; gap: 8px; }
  .host-name { font-size: 15px; }
  .host-meta { font-size: 11px; }
  .host-pills { gap: 4px; }
  .host-pills .pill { padding: 3px 8px; font-size: 10px; }
  .cpu-facts { grid-template-columns: repeat(2, 1fr); }
  .mem-break { grid-template-columns: repeat(2, 1fr); }
  .net-stats { grid-template-columns: 1fr 1fr; }
  .health-grid { grid-template-columns: repeat(2, 1fr); }
  .bm-grid { grid-template-columns: repeat(auto-fill, minmax(120px, 1fr)); gap: 6px; }
  .bm-card { padding: 8px 10px; min-height: 48px; }
  .res-card .big { font-size: 22px; }
  .disk-primary { flex-wrap: wrap; }
  .disk-facts { font-size: 9px; }
  .load-row { grid-template-columns: 24px 1fr 36px; font-size: 10px; }
  .chart-intro { font-size: 11px; gap: 8px; }
  .range-btns { margin-top: 4px; }
}
@media (max-width: 380px) {
  .cpu-facts { grid-template-columns: 1fr 1fr; gap: 4px; }
  .net-stats { grid-template-columns: 1fr; }
  .health-grid { grid-template-columns: 1fr 1fr; }
  .mem-break { grid-template-columns: 1fr; }
}
</style>
