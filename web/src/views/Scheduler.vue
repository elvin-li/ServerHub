<template>
  <div>
    <div class="page-title">
      <h1>{{ t('pages.scheduler') }}</h1>
      <span class="meta">{{ t('pages.scheduler_meta') }}</span>
    </div>

    <div class="tabs">
      <button :class="{ active: tab === 'panel' }" :aria-pressed="tab === 'panel'" @click="tab = 'panel'">
        {{ t('sched.tab_panel') }}
      </button>
      <button :class="{ active: tab === 'system' }" :aria-pressed="tab === 'system'" @click="tab = 'system'">
        {{ t('sched.tab_system') }}
      </button>
    </div>

    <!-- ── panel jobs (user-defined cron) ─────────────────────────────── -->
    <div v-if="tab === 'panel'">
      <div class="toolbar">
        <button class="primary" @click="openCreate">{{ t('sched.new_job') }}</button>
        <button :disabled="jobsBusy" @click="loadJobs">{{ t('common.refresh') }}</button>
        <span class="meta" style="color:var(--sub)" v-if="jobsLoaded">{{ jobs.length }} {{ t('sched.jobs_count') }}</span>
      </div>

      <div class="tile" style="margin-bottom:12px;border-left:3px solid var(--accent)">
        <p style="font-size:12px;color:var(--sub);line-height:1.55;margin:0">{{ t('sched.panel_hint') }}</p>
      </div>

      <LoadFailure v-if="jobsError" :detail="jobsError" :retry="loadJobs" :busy="jobsBusy" />
      <SkeletonLoader v-if="!jobsLoaded" :cols="6" :rows="4" />
      <div v-else class="table-wrap">
        <table class="dense fit-m">
          <thead>
            <tr>
              <th>{{ t('sched.name') }}</th>
              <th class="col-hide-m">{{ t('sched.type') }}</th>
              <th class="col-hide-m">{{ t('sched.cron') }}</th>
              <th class="col-hide-m">{{ t('sched.next_run') }}</th>
              <th class="col-hide-m">{{ t('sched.last_run') }}</th>
              <th>{{ t('sched.enabled') }}</th>
              <th>{{ t('common.actions') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="job in jobs" :key="job.id">
              <td>
                <strong>{{ finiteText(job.name) }}</strong>
                <div class="show-m sub">{{ t(`sched.type_${job.type}`) }} · {{ finiteText(job.cron) }}</div>
                <div v-if="job.enabled" class="show-m sub">{{ fmt(job.next_run) }}</div>
                <div class="show-m sub">
                  <span v-if="job.running">{{ t('sched.running') }}</span>
                  <span v-else-if="job.last">{{ t(`sched.status_${job.last.status}`) }} · {{ fmt(job.last.ts) }}</span>
                  <span v-else>{{ t('sched.never') }}</span>
                </div>
              </td>
              <td class="col-hide-m"><span class="badge accent">{{ t(`sched.type_${job.type}`) }}</span></td>
              <td class="mono col-hide-m" style="font-size:11px">{{ finiteText(job.cron) }}</td>
              <td class="col-hide-m" style="font-size:12px">{{ job.enabled ? fmt(job.next_run) : '—' }}</td>
              <td class="col-hide-m">
                <span v-if="job.running" class="badge warn">{{ t('sched.running') }}</span>
                <span v-else-if="job.last" class="badge" :class="job.last.status === 'ok' ? 'ok' : 'warn'">
                  {{ t(`sched.status_${job.last.status}`) }} · {{ fmt(job.last.ts) }}
                </span>
                <span v-else class="meta">{{ t('sched.never') }}</span>
              </td>
              <td>
                <input type="checkbox" :checked="job.enabled" :aria-label="t('sched.enabled')"
                       @change="toggle(job, $event.target.checked)" />
              </td>
              <td>
                <div class="btns" style="gap:4px">
                  <button class="tiny" :disabled="job.running" @click="runNow(job)">{{ t('sched.run_now') }}</button>
                  <button class="tiny hide-m" @click="openRuns(job)">{{ t('sched.history') }}</button>
                  <button class="tiny" @click="openEdit(job)">{{ t('common.edit') }}</button>
                  <button class="tiny" @click="removeJob(job)">{{ t('common.delete') }}</button>
                </div>
              </td>
            </tr>
            <tr v-if="!jobs.length && !jobsError">
              <td colspan="7" style="color:var(--sub)">{{ t('sched.no_jobs') }}</td>
            </tr>
          </tbody>
        </table>
      </div>

      <!-- bridged system-managed schedules (read-only) -->
      <div v-if="systemJobs.length" class="tile" style="margin-top:12px">
        <h2 style="margin-top:0">{{ t('sched.managed_title') }}</h2>
        <p class="meta" style="font-size:11px;color:var(--sub)">{{ t('sched.managed_smart_hint') }}</p>
        <div class="table-wrap" style="margin-top:6px">
        <table class="dense fit-m">
          <tbody>
            <tr v-for="s in systemJobs" :key="s.id">
              <td>
                <strong>{{ finiteText(s.name) }}</strong> <span class="badge">{{ t('sched.readonly') }}</span>
                <div class="show-m sub">{{ s.enabled ? finiteText(s.interval) : t('sched.disabled') }}{{ s.enabled ? ' · ' + fmt(s.next_run) : '' }}</div>
              </td>
              <td class="col-hide-m">{{ s.enabled ? finiteText(s.interval) : t('sched.disabled') }}</td>
              <td class="col-hide-m" style="font-size:12px">{{ s.enabled ? fmt(s.next_run) : '—' }}</td>
              <td><router-link class="btn tiny" to="/main">{{ t('sched.managed_edit_link') }}</router-link></td>
            </tr>
          </tbody>
        </table>
        </div>
      </div>
    </div>

    <!-- ── system tab: launchd timers (read-only, unchanged) ──────────── -->
    <div v-else>
      <div class="toolbar">
        <button class="primary" @click="load" :disabled="loading">{{ t('common.refresh') }}</button>
        <span class="meta" style="color:var(--sub)" v-if="data">{{ finiteN(data.count) }} {{ t('scheduler.timers') }}</span>
      </div>

      <div class="tile" style="margin-bottom:12px;border-left:3px solid var(--accent)">
        <p style="font-size:12px;color:var(--sub);line-height:1.55;margin:0">
          {{ t('scheduler.hint') }}
        </p>
      </div>

      <LoadFailure v-if="loadError" :detail="loadError" :retry="load" :busy="loading" />
      <SkeletonLoader v-if="!loaded" variant="tiles" :rows="3" :span="4" :tile-height="34" style="margin-bottom:12px" />
      <div class="dash-grid" style="margin-bottom:12px" v-else-if="data">
        <div class="tile span-4">
          <h2>{{ t('scheduler.timers') }}</h2>
          <div class="v">{{ finiteN(data.count) }}</div>
        </div>
        <div class="tile span-4">
          <h2>{{ t('scheduler.interval_type') }}</h2>
          <div class="v">{{ intervalCount }}</div>
          <div class="sub">StartInterval</div>
        </div>
        <div class="tile span-4">
          <h2>{{ t('scheduler.calendar_type') }}</h2>
          <div class="v">{{ calendarCount }}</div>
          <div class="sub">StartCalendarInterval</div>
        </div>
      </div>

      <div class="toolbar">
        <input v-model="q" type="text" :placeholder="t('scheduler.filter_ph')" style="min-width:200px" :aria-label="t('scheduler.filter_ph')" />
      </div>

      <SkeletonLoader v-if="!loaded" :cols="5" :rows="6" />
      <div v-else class="table-wrap">
        <table class="dense fit-m">
          <thead>
            <tr>
              <th>{{ t('scheduler.label') }}</th>
              <th>{{ t('common.type') }}</th>
              <th>{{ t('scheduler.interval') }}</th>
              <th class="col-hide-m">{{ t('scheduler.calendar') }}</th>
              <th class="col-hide-m">{{ t('scheduler.program') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="row in filtered" :key="row.label">
              <td class="mono">
                <strong>{{ finiteText(row.label) }}</strong>
                <div v-if="formatCal(row.calendar)" class="show-m sub">{{ formatCal(row.calendar) }}</div>
                <div v-if="row.program" class="show-m sub">{{ finiteText(row.program) }}</div>
              </td>
              <td>
                <span class="badge accent">{{ row.interval_sec ? t('scheduler.interval_type') : t('scheduler.calendar_type') }}</span>
              </td>
              <td>{{ row.interval_sec ? formatInterval(row.interval_sec) : '—' }}</td>
              <td class="mono col-hide-m" style="font-size:11px">{{ formatCal(row.calendar) }}</td>
              <td class="mono col-hide-m" style="max-width:420px;overflow:hidden;text-overflow:ellipsis;font-size:11px" :title="finiteText(row.program)">
                {{ finiteText(row.program) }}
              </td>
            </tr>
            <tr v-if="!filtered.length && !loadError">
              <td colspan="5" style="color:var(--sub)">
                {{ loading ? t('common.loading') : t('common.none') }}
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <div class="toolbar" style="margin-top:12px">
        <router-link class="btn" to="/tools">{{ t('nav.tools') }}</router-link>
        <router-link class="btn" to="/maintenance">{{ t('nav.maintenance') }}</router-link>
      </div>
    </div>

    <!-- create / edit modal -->
    <div ref="formPanel" v-if="editorOpen" class="modal-bg" @click.self="closeEditor" role="presentation">
      <div class="modal" style="max-width:560px;max-height:90vh;overflow:auto" role="dialog" aria-modal="true" aria-labelledby="sched-form-title">
        <div class="row" style="margin-bottom:10px">
          <span id="sched-form-title" class="name">{{ editing ? t('sched.edit_job') : t('sched.new_job') }}</span>
          <button class="tiny" @click="closeEditor">{{ t('common.close') }}</button>
        </div>
        <ScheduleJobForm :job="editing" :busy="jobsBusy" @save="saveJob" @cancel="closeEditor" />
      </div>
    </div>

    <!-- run history modal -->
    <div ref="runsPanel" v-if="runsFor" class="modal-bg" @click.self="runsFor = null" role="presentation">
      <div class="modal" style="max-width:640px;max-height:90vh;overflow:auto" role="dialog" aria-modal="true" aria-labelledby="sched-runs-title">
        <div class="row" style="margin-bottom:10px">
          <span id="sched-runs-title" class="name">{{ t('sched.runs_title', { name: finiteText(runsFor.name) }) }}</span>
          <button class="tiny" @click="runsFor = null">{{ t('common.close') }}</button>
        </div>
        <div v-if="runsError" class="meta" style="color:var(--down-text)">{{ finiteText(runsError) }}</div>
        <div v-else-if="!runsLoaded" class="meta">{{ t('common.loading') }}</div>
        <div v-else-if="!runs.length" class="meta">{{ t('sched.runs_empty') }}</div>
        <div v-for="(run, i) in runs" :key="i" style="border:1px solid var(--line);border-radius:4px;padding:8px;margin-bottom:8px">
          <div style="font-size:12px;margin-bottom:4px">
            <span class="badge" :class="run.status === 'ok' ? 'ok' : 'warn'">{{ t(`sched.status_${run.status}`) }}</span>
            <span class="mono" style="margin-left:8px">{{ fmt(run.ts) }}</span>
            <span class="meta" style="margin-left:8px">{{ t('sched.col_duration') }}: {{ withUnit(run.duration, 's') }} · rc={{ finiteN(run.rc) }} · {{ t(`sched.trigger_${run.trigger}`) }}</span>
          </div>
          <pre v-if="run.tail" class="log" style="max-height:160px;font-size:11px;margin:0">{{ finiteText(run.tail) }}</pre>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, inject, onBeforeUnmount, onMounted, ref } from 'vue'
import {
  createSchedulerJob,
  deleteSchedulerJob,
  enableSchedulerJob,
  getScheduler,
  getSchedulerJobRuns,
  getSchedulerJobs,
  runSchedulerJobNow,
  updateSchedulerJob,
} from '../api/client'
import { injectI18n } from '../i18n'
import { finiteN, finiteText, fmtTs, withUnit } from '../lib/finite'
import { useDismissable } from '../composables/useDismissable'
import SkeletonLoader from '../components/SkeletonLoader.vue'
import LoadFailure from '../components/LoadFailure.vue'
import ScheduleJobForm from '../components/ScheduleJobForm.vue'

const toast = inject('toast')
const { t } = injectI18n()
const tab = ref('panel')

// ── panel jobs state ─────────────────────────────────────────────────────
const jobs = ref([])
const systemJobs = ref([])
const jobsLoaded = ref(false)
const jobsBusy = ref(false)
const jobsError = ref('')
const editorOpen = ref(false)
const editing = ref(null)
const runsFor = ref(null)
const runs = ref([])
const runsLoaded = ref(false)
const runsError = ref('')
const formPanel = ref(null)
const runsPanel = ref(null)
useDismissable(editorOpen, () => { editorOpen.value = false }, formPanel)
useDismissable(() => Boolean(runsFor.value), () => { runsFor.value = null }, runsPanel)

// Unmount alone cannot stop this loop: it only clears the *armed* timer, but a
// loadJobs() that was already in flight lands afterwards and re-arms — with a
// job still running, the unmounted page then polls the API every 7s forever.
let pollStopped = false

function fmt(ts) {
  return fmtTs(ts)
}

async function loadJobs() {
  if (pollStopped) return
  jobsBusy.value = true
  try {
    const d = await getSchedulerJobs()
    if (pollStopped) return
    jobs.value = Array.isArray(d?.jobs) ? d.jobs : []
    systemJobs.value = Array.isArray(d?.system) ? d.system : []
    jobsError.value = ''
  } catch (e) {
    if (pollStopped) return
    jobsError.value = finiteText(e.message || String(e), '')
  } finally {
    if (!pollStopped) {
      jobsBusy.value = false
      jobsLoaded.value = true
    }
  }
  schedulePoll()
}

// While any job is running, refresh every few seconds so the "running" badge
// and last-run status update themselves; the timer stops as soon as nothing
// is running, so an idle page polls nothing.
let pollTimer = null
function schedulePoll() {
  if (pollStopped || pollTimer) return
  if (!jobs.value.some(j => j.running)) return
  pollTimer = setTimeout(() => {
    pollTimer = null
    if (pollStopped) return
    // Skip the fetch while the tab is hidden but keep the loop armed, so the
    // badge catches up shortly after the operator returns instead of a hidden
    // tab asking the host for job status all night.
    if (typeof document !== 'undefined' && document.hidden) schedulePoll()
    else loadJobs()
  }, 7000)
}

onBeforeUnmount(() => {
  pollStopped = true
  if (pollTimer) clearTimeout(pollTimer)
  pollTimer = null
})

function openCreate() {
  editing.value = null
  editorOpen.value = true
}

function openEdit(job) {
  editing.value = job
  editorOpen.value = true
}

function closeEditor() {
  editorOpen.value = false
  editing.value = null
}

async function saveJob(body) {
  jobsBusy.value = true
  try {
    if (editing.value) await updateSchedulerJob(editing.value.id, body)
    else await createSchedulerJob(body)
    if (pollStopped) return
    toast('✅ ' + t('sched.saved'))
    closeEditor()
    await loadJobs()
  } catch (e) {
    if (pollStopped) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (!pollStopped) jobsBusy.value = false
  }
}

async function toggle(job, enabled) {
  try {
    await enableSchedulerJob(job.id, enabled)
    if (pollStopped) return
    await loadJobs()
  } catch (e) {
    if (pollStopped) return
    toast('❌ ' + finiteText(e.message))
    await loadJobs()
  }
}

async function runNow(job) {
  const key = job.type === 'stack_backup'
    ? 'backups.confirm_stack_run'
    : job.type === 'rsync'
      ? 'backups.confirm_rsync_run'
      : 'sched.confirm_run'
  if (!confirm(t(key, { name: finiteText(job.name) }))) return
  try {
    await runSchedulerJobNow(job.id)
    if (pollStopped) return
    toast('✅ ' + t('sched.started', { name: finiteText(job.name) }))
    await loadJobs()
  } catch (e) {
    if (pollStopped) return
    toast('❌ ' + finiteText(e.message))
  }
}

async function removeJob(job) {
  if (!confirm(t('sched.confirm_delete', { name: finiteText(job.name) }))) return
  try {
    await deleteSchedulerJob(job.id)
    if (pollStopped) return
    toast('✅ ' + t('sched.deleted'))
    await loadJobs()
  } catch (e) {
    if (pollStopped) return
    toast('❌ ' + finiteText(e.message))
  }
}

async function openRuns(job) {
  runsFor.value = job
  runsLoaded.value = false
  runsError.value = ''
  try {
    const d = await getSchedulerJobRuns(job.id, 30)
    if (pollStopped) return
    runs.value = Array.isArray(d?.runs) ? d.runs : []
  } catch (e) {
    if (pollStopped) return
    runsError.value = finiteText(e.message || String(e), '')
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (!pollStopped) runsLoaded.value = true
  }
}

// ── launchd (system) tab state — unchanged read-only view ────────────────
const data = ref(null)
const loading = ref(false)
const loaded = ref(false)
const loadError = ref('')
const q = ref('')

const intervalCount = computed(() =>
  (data.value?.timers || []).filter(t => t.interval_sec).length
)
const calendarCount = computed(() =>
  (data.value?.timers || []).filter(t => t.calendar && !t.interval_sec).length
    || (data.value?.timers || []).filter(t => t.calendar).length
)

const filtered = computed(() => {
  const list = data.value?.timers || []
  const qq = q.value.trim().toLowerCase()
  if (!qq) return list
  return list.filter(t =>
    (t.label || '').toLowerCase().includes(qq)
    || (t.program || '').toLowerCase().includes(qq)
  )
})

function formatInterval(sec) {
  const n = Number(sec)
  if (!Number.isFinite(n) || n < 0) return '—'
  if (n >= 86400) return t('scheduler.unit_days', { n: Math.round(n / 86400), sec: n })
  if (n >= 3600) return t('scheduler.unit_hours', { n: Math.round(n / 3600), sec: n })
  if (n >= 60) return t('scheduler.unit_minutes', { n: Math.round(n / 60), sec: n })
  return `${n}s`
}
function formatCal(c) {
  if (!c) return '—'
  if (typeof c === 'object') return JSON.stringify(c)
  return finiteText(c)
}

async function load() {
  loading.value = true
  try {
    const next = await getScheduler()
    if (pollStopped) return
    data.value = next
    loadError.value = ''
  } catch (e) {
    if (pollStopped) return
    loadError.value = finiteText(e.message || String(e), '')
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (!pollStopped) {
      loading.value = false
      loaded.value = true
    }
  }
}

onMounted(() => {
  loadJobs()
  load()
})
</script>
