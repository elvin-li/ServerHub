<template>
  <div>
    <div class="page-title">
      <h1>{{ t('backups.title') }}</h1>
      <span class="meta">{{ finiteText(root, '') || 'Services/backups' }}</span>
    </div>
    <div class="toolbar">
      <button class="primary" :disabled="busy" @click="doPg">{{ pgLabel }}</button>
      <button v-if="immich.available" :disabled="busy" @click="doImmich">{{ t('backups.immich') }}</button>
      <button :disabled="busy" @click="doCfg">{{ t('backups.cfg') }}</button>
      <button :disabled="busy" @click="refresh">{{ t('backups.refresh_list') }}</button>
    </div>
    <!-- role=status: this card is the only durable record of what a backup
         button just did (the toast is gone in four seconds), and it filled in
         silently for a screen reader. -->
    <div v-if="msg" class="card" style="margin-bottom:12px;white-space:pre-wrap;font-size:13px" role="status" aria-live="polite">{{ finiteText(msg) }}</div>

    <div v-if="layers" class="tile" style="margin-bottom:12px" data-test="immich-layers">
      <div class="row">
        <h3 style="margin:0">{{ t('backups.immich_layers_title') }}</h3>
        <router-link class="tiny" to="/photoshub">{{ t('backups.immich_open_photoshub') }}</router-link>
      </div>
      <p class="meta" style="font-size:11px;color:var(--sub);margin:6px 0 10px">
        {{ t('backups.immich_layers_desc') }}
      </p>
      <div class="dash-grid">
        <div class="tile span-4">
          <h3>{{ t('backups.layer_db') }}</h3>
          <div class="v" style="font-size:15px">{{ finiteText(layers.db?.last?.name, '') || t('photoshub.never') }}</div>
          <div class="meta">
            <template v-if="layers.db?.last">{{ sizeMb(layers.db.last.size_mb) }} · :{{ finiteN(layers.db.port) }}</template>
            <template v-else>{{ t('backups.layer_db_hint') }}</template>
          </div>
        </div>
        <div class="tile span-4">
          <h3>{{ t('backups.layer_originals') }}</h3>
          <div class="v" style="font-size:15px">{{ originalsHeadline }}</div>
          <div class="meta">{{ finiteText(layers.originals?.backup?.last_success, '') || finiteText(layers.originals?.path, '') || t('photoshub.never') }}</div>
          <div v-if="finiteText(layers.originals?.size_human, '')" class="meta">{{ finiteText(layers.originals.size_human) }}</div>
        </div>
        <div class="tile span-4">
          <h3>{{ t('backups.layer_bridge') }}</h3>
          <div class="v" style="font-size:15px">{{ layerPresent(layers.bridge) }}</div>
          <div class="meta">{{ finiteText(layers.bridge?.last_success, '') || finiteText(layers.bridge?.path) }}</div>
          <div v-if="finiteN(layers.bridge?.exported_files, null) != null" class="meta">{{ t('backups.layer_bridge_files', { n: finiteN(layers.bridge.exported_files) }) }}</div>
        </div>
        <div class="tile span-4">
          <h3>{{ t('backups.layer_generated') }}</h3>
          <div class="v" style="font-size:15px">{{ layerPresent(layers.generated) }}</div>
          <div class="meta">{{ generatedSummary }}</div>
        </div>
        <div class="tile span-4">
          <h3>{{ t('backups.layer_external') }}</h3>
          <div class="v" style="font-size:15px">{{ finiteText(layers.external?.last_success, t('photoshub.disk_absent')) }}</div>
          <div class="meta">{{ finiteText(layers.external?.reason, '') || (layers.external?.ok === false ? t('common.issues') : '') }}</div>
        </div>
      </div>
    </div>

    <!-- A task type with no jobs has no table of its own, so its only "New task"
         button lives here. Shown whenever *either* type is empty: gating this on
         both being empty meant one rsync job hid the stack card and this block at
         the same time, leaving no way to create a stack backup anywhere. -->
    <LoadFailure v-if="jobsError" :detail="jobsError" :retry="loadJobs" />
    <details v-if="jobsLoaded && !jobsError && (!rsyncJobs.length || !stackJobs.length)" class="tile" style="margin-bottom:12px" data-test="backup-advanced">
      <summary class="advanced-sum">{{ t('backups.advanced_generic') }}</summary>
      <p class="meta" style="font-size:11px;color:var(--sub);margin:8px 0 12px">{{ t('backups.advanced_generic_desc') }}</p>
      <div v-if="!rsyncJobs.length" class="tile" style="margin-bottom:12px">
        <div class="row">
          <h3 style="margin:0">{{ t('backups.rsync_title') }}</h3>
          <button class="tiny primary" @click="openJobEditor('rsync', null)">{{ t('backups.new_task') }}</button>
        </div>
        <p class="meta" style="font-size:11px;color:var(--sub);margin:6px 0">{{ t('backups.rsync_desc') }}</p>
      </div>
      <div v-if="!stackJobs.length" class="tile">
        <div class="row">
          <h3 style="margin:0">{{ t('backups.stack_title') }}</h3>
          <button class="tiny primary" @click="openJobEditor('stack_backup', null)">{{ t('backups.new_task') }}</button>
        </div>
        <p class="meta" style="font-size:11px;color:var(--sub);margin:6px 0">{{ t('backups.stack_desc') }}</p>
      </div>
    </details>

    <!-- ── scheduled rsync sync tasks ─────────────────────────────────── -->
    <div v-if="rsyncJobs.length" class="tile" style="margin-bottom:12px">
      <div class="row">
        <h3 style="margin:0">{{ t('backups.rsync_title') }}</h3>
        <button class="tiny primary" @click="openJobEditor('rsync', null)">{{ t('backups.new_task') }}</button>
      </div>
      <p class="meta" style="font-size:11px;color:var(--sub);margin:6px 0">
        {{ t('backups.rsync_desc') }}
        <span v-if="rsyncBinary && !rsyncBinary.available" style="color:var(--warn-text)"> {{ t('backups.rsync_missing') }}</span>
        <span v-else-if="rsyncBinary" class="mono"> · {{ finiteText(rsyncBinary.variant) }} {{ finiteText(rsyncBinary.version) }}</span>
      </p>
      <SkeletonLoader v-if="!jobsLoaded" :cols="5" :rows="2" />
      <div v-else class="table-wrap">
      <table class="dense fit-m">
        <tbody>
          <tr v-for="job in rsyncJobs" :key="job.id">
            <td>
              <strong>{{ finiteText(job.name) }}</strong>
              <div class="show-m sub mono">{{ finiteText(job.params.src) }} → {{ finiteText(job.params.dest) }}</div>
              <div class="show-m sub mono">{{ finiteText(job.cron) }}</div>
            </td>
            <td class="mono col-hide-m" style="font-size:11px;max-width:280px;overflow:hidden;text-overflow:ellipsis"
                :title="finiteText(job.params.src) + ' → ' + finiteText(job.params.dest)">
              {{ finiteText(job.params.src) }} → {{ finiteText(job.params.dest) }}
            </td>
            <td class="mono col-hide-m" style="font-size:11px">{{ finiteText(job.cron) }}</td>
            <td>
              <span v-if="job.running" class="badge warn">{{ t('sched.running') }}</span>
              <span v-else-if="job.last" class="badge" :class="job.last.status === 'ok' ? 'ok' : 'warn'">{{ t(`sched.status_${job.last.status}`) }}</span>
              <span v-else class="meta">{{ t('sched.never') }}</span>
            </td>
            <td>
              <div class="btns" style="gap:4px">
                <button class="tiny hide-m" @click="openPreview(job)">{{ t('backups.dry_run') }}</button>
                <button class="tiny" :disabled="job.running" @click="runJob(job)">{{ t('sched.run_now') }}</button>
                <button class="tiny" @click="openJobEditor('rsync', job)">{{ t('common.edit') }}</button>
                <button class="tiny" @click="removeJob(job)">{{ t('common.delete') }}</button>
              </div>
            </td>
          </tr>
          <tr v-if="!rsyncJobs.length && jobsLoaded">
            <td colspan="5" class="empty-row" style="font-size:12px">{{ t('backups.no_tasks') }}</td>
          </tr>
        </tbody>
      </table>
      </div>
    </div>

    <!-- ── scheduled compose-stack (appdata) backups ──────────────────── -->
    <div v-if="stackJobs.length" class="tile" style="margin-bottom:12px">
      <div class="row">
        <h3 style="margin:0">{{ t('backups.stack_title') }}</h3>
        <button class="tiny primary" @click="openJobEditor('stack_backup', null)">{{ t('backups.new_task') }}</button>
      </div>
      <p class="meta" style="font-size:11px;color:var(--sub);margin:6px 0">{{ t('backups.stack_desc') }}</p>
      <SkeletonLoader v-if="!jobsLoaded" :cols="5" :rows="2" />
      <div v-else class="table-wrap">
      <table class="dense fit-m">
        <tbody>
          <tr v-for="job in stackJobs" :key="job.id">
            <td>
              <strong>{{ finiteText(job.name) }}</strong>
              <div class="show-m sub mono">{{ finiteText(job.params.stack_id) }}</div>
              <div class="show-m sub">{{ t('backups.retain_n', { n: finiteN(job.params.retain, 14) }) }} · {{ finiteText(job.cron) }}</div>
            </td>
            <td class="mono col-hide-m" style="font-size:11px">{{ finiteText(job.params.stack_id) }}</td>
            <td class="col-hide-m" style="font-size:11px">{{ t('backups.retain_n', { n: finiteN(job.params.retain, 14) }) }}</td>
            <td class="mono col-hide-m" style="font-size:11px">{{ finiteText(job.cron) }}</td>
            <td>
              <div class="btns" style="gap:4px">
                <span v-if="job.running" class="badge warn">{{ t('sched.running') }}</span>
                <span v-else-if="job.last" class="badge" :class="job.last.status === 'ok' ? 'ok' : 'warn'">{{ t(`sched.status_${job.last.status}`) }}</span>
                <button class="tiny" :disabled="job.running" @click="runJob(job)">{{ t('sched.run_now') }}</button>
                <button class="tiny" @click="openJobEditor('stack_backup', job)">{{ t('common.edit') }}</button>
                <button class="tiny" @click="removeJob(job)">{{ t('common.delete') }}</button>
              </div>
            </td>
          </tr>
          <tr v-if="!stackJobs.length && jobsLoaded">
            <td colspan="5" class="empty-row" style="font-size:12px">{{ t('backups.no_tasks') }}</td>
          </tr>
        </tbody>
      </table>
      </div>
    </div>

    <!-- The banner is not part of the chain below: when a background re-read
         fails, the artefact rows the operator was reading stay on screen
         under it instead of being replaced wholesale (the LoadFailure
         contract — same as Containers and the Users accounts table).  Only a
         failed *first* load, with nothing fetched yet, renders the banner
         alone — a header-only table under it used to look like an empty
         backup listing, on the page where "not listed" reads as "gone". -->
    <LoadFailure v-if="loadError" :detail="loadError" :retry="refresh" :busy="busy" />
    <SkeletonLoader v-if="!loaded && !loadError" :cols="4" :rows="5" />
    <div v-else-if="!loadError || backups.length" class="table-wrap backups-artefacts">
      <table class="dense fit-m">
        <thead>
          <tr>
            <th>{{ t('backups.file') }}</th>
            <th class="col-hide-m">{{ t('backups.dir') }}</th>
            <th>{{ t('backups.size') }}</th>
            <th>{{ t('backups.time') }}</th>
            <th class="col-hide-m">{{ t('backups.restore') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="b in backups" :key="b.path">
            <td class="mono">
              {{ finiteText(b.name) }}
              <div v-if="finiteText(b.dir, '')" class="show-m sub">{{ finiteText(b.dir) }}</div>
              <div v-if="b.restore" class="show-m sub">
                <button class="tiny" type="button" @click="copyRestore(b.restore)">{{ t('common.copy') }}</button>
                {{ t('backups.restore') }}
              </div>
            </td>
            <td class="mono col-hide-m" style="font-size:11px">{{ finiteText(b.dir) }}</td>
            <td>{{ sizeMb(b.size_mb) }}</td>
            <td>{{ fmt(b.mtime) }}</td>
            <td class="col-hide-m" style="font-size:11px;max-width:280px">
              <button v-if="b.restore" class="tiny" type="button" :title="t('backups.restore_copy')" @click="copyRestore(b.restore)">{{ t('common.copy') }}</button>
              <span v-if="b.restore" class="mono sub" :title="finiteText(b.restore)">{{ finiteText(b.restore) }}</span>
            </td>
          </tr>
          <tr v-if="!backups.length && !loadError">
            <td colspan="5" class="empty-row">{{ t('backups.empty') }}</td>
          </tr>
        </tbody>
      </table>
      <!-- The table is capped, so say so. Without this the older backups look
           deleted rather than merely unlisted, which is the opposite of what a
           backups page should tell you.
           role=status: this count is the only summary of how many backups
           exist, and it appears/updates silently after every finished backup
           or refresh for a screen reader — same treatment as the Ollama
           model count and the VMs/Health header counts. -->
      <p v-if="hiddenCount" class="meta" style="margin-top:8px" role="status">
        {{ t('backups.truncated', { shown: backups.length, total: finiteN(total) }) }}
      </p>
    </div>

    <!-- task create/edit modal (rsync or stack backup) -->
    <div ref="jobPanel" v-if="jobEditor" class="modal-bg" @click.self="jobEditor = null" role="presentation">
      <div class="modal" style="max-width:560px;max-height:90vh;overflow:auto" role="dialog" aria-modal="true" aria-labelledby="backups-job-title">
        <div class="row" style="margin-bottom:10px">
          <span id="backups-job-title" class="name">
            {{ jobEditor.job ? t('sched.edit_job') : t('backups.new_task') }}
          </span>
          <button class="tiny" @click="jobEditor = null">{{ t('common.close') }}</button>
        </div>
        <ScheduleJobForm :job="jobEditor.job" :allowed-types="[jobEditor.type]" :busy="busy"
                         @save="saveJob" @cancel="jobEditor = null" />
      </div>
    </div>

    <!-- rsync dry-run preview modal -->
    <div ref="previewPanel" v-if="previewFor" class="modal-bg" @click.self="previewFor = null" role="presentation">
      <div class="modal" style="max-width:640px;max-height:90vh;overflow:auto" role="dialog" aria-modal="true" aria-labelledby="backups-preview-title">
        <div class="row" style="margin-bottom:10px">
          <span id="backups-preview-title" class="name">{{ t('backups.preview_title', { name: finiteText(previewFor.name) }) }}</span>
          <button class="tiny" @click="previewFor = null">{{ t('common.close') }}</button>
        </div>
        <div v-if="previewBusy" class="meta">{{ t('common.loading') }}</div>
        <!-- role=alert: the dry-run result loads after the dialog already holds
             focus, so the panel-focus read never covers a failure — same as the
             Scheduler run-history and MainArray SMART overview errors. -->
        <div v-else-if="previewError" class="meta" style="color:var(--down-text)" role="alert">{{ finiteText(previewError) }}</div>
        <template v-else-if="preview">
          <div style="margin-bottom:8px;font-size:12px">
            <span class="badge accent" style="margin-right:6px">{{ t('sched.preview_creates', { n: finiteN(preview.creates) }) }}</span>
            <span class="badge accent" style="margin-right:6px">{{ t('sched.preview_updates', { n: finiteN(preview.updates) }) }}</span>
            <span class="badge" :class="preview.deletes ? 'warn' : ''">{{ t('sched.preview_deletes', { n: finiteN(preview.deletes) }) }}</span>
            <span class="meta mono" style="margin-left:8px" v-if="preview.binary">{{ finiteText(preview.binary.variant) }} {{ finiteText(preview.binary.version) }}</span>
          </div>
          <div v-if="!preview.total" class="meta">{{ t('sched.preview_empty') }}</div>
          <div v-else style="max-height:300px;overflow:auto;font-family:ui-monospace,Menlo,monospace;font-size:11px;white-space:pre">
            <div v-for="(line, i) in preview.samples" :key="i">{{ finiteText(line) }}</div>
          </div>
        </template>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, inject, onMounted, onUnmounted, ref } from 'vue'
import {
  backupConfigs,
  backupImmich,
  backupPostgres,
  createSchedulerJob,
  deleteSchedulerJob,
  getBackups,
  getRsyncBinary,
  getSchedulerJobs,
  rsyncPreview,
  runSchedulerJobNow,
  updateSchedulerJob,
} from '../api/client'
import { injectI18n } from '../i18n'
import { copyToClipboard } from '../lib/clipboard'
import { finiteN, finiteText, fmtTs } from '../lib/finite'
import { useDismissable } from '../composables/useDismissable'
import SkeletonLoader from '../components/SkeletonLoader.vue'
import LoadFailure from '../components/LoadFailure.vue'
import ScheduleJobForm from '../components/ScheduleJobForm.vue'

const toast = inject('toast')
const { t } = injectI18n()
const backups = ref([])
const root = ref('')
const busy = ref(false)
const msg = ref('')
// Separates "listing not fetched yet" from "no backups exist", which the empty
// row could not express: a fresh page claimed there were no backups at all.
const loaded = ref(false)
const loadError = ref('')
// The API caps the rows it returns but reports how many exist, so the page can
// tell "these are all of them" apart from "these are the newest 40".
const total = ref(0)
const hiddenCount = computed(() => Math.max(0, total.value - backups.value.length))
const postgresTargets = ref([])
const immich = ref({ available: false, last: null, layers: null })
const layers = computed(() => immich.value.layers || null)
const generatedSummary = computed(() => {
  const dirs = layers.value?.generated?.dirs || []
  if (!dirs.length) return finiteText(layers.value?.generated?.path)
  return dirs.map((d) => `${finiteText(d.name)}${d.present ? '' : '?'}`).join(' · ')
})
const originalsHeadline = computed(() => {
  const layer = layers.value?.originals
  if (!layer) return '—'
  if (layer.pct != null) return t('backups.layer_originals_pct', { n: finiteN(layer.pct) })
  return layerPresent(layer)
})
const pgLabel = computed(() => {
  const names = postgresTargets.value.map((t) => t.id).filter(Boolean)
  if (names.length === 1) return t('backups.pg_named', { name: finiteText(names[0]) })
  if (names.length > 1) return t('backups.pg')
  return t('backups.pg')
})

// Scheduled backup tasks (rsync + stack) ride on the panel scheduler.
const jobs = ref([])
const jobsLoaded = ref(false)
const jobsError = ref('')
const rsyncBinary = ref(null)
const jobEditor = ref(null)          // { type, job|null }
const previewFor = ref(null)
const preview = ref(null)
const previewBusy = ref(false)
const previewError = ref('')
const jobPanel = ref(null)
const previewPanel = ref(null)
useDismissable(() => Boolean(jobEditor.value), () => { jobEditor.value = null }, jobPanel)
useDismissable(() => Boolean(previewFor.value), () => { previewFor.value = null }, previewPanel)

let pageAlive = true
let backupsGeneration = 0
let jobsGeneration = 0

const rsyncJobs = computed(() => jobs.value.filter((j) => j.type === 'rsync'))
const stackJobs = computed(() => jobs.value.filter((j) => j.type === 'stack_backup'))

function fmt(t) {
  return fmtTs(t, '')
}

function sizeMb(value) {
  const n = Number(value)
  return Number.isFinite(n) ? `${n} MB` : '—'
}

function layerPresent(layer) {
  if (!layer) return '—'
  return layer.present ? t('backups.layer_present') : t('backups.layer_missing')
}

async function copyRestore(text) {
  if (!text) return
  const ok = await copyToClipboard(text)
  if (!pageAlive) return
  toast(ok ? '✅ ' + t('common.copied') : '❌ ' + t('common.copy_failed'))
}

async function refresh(manual = false) {
  const generation = ++backupsGeneration
  try {
    const d = await getBackups()
    if (generation !== backupsGeneration || !pageAlive) return
    backups.value = d.backups || []
    root.value = d.root || ''
    // A panel that predates `total` sends none; falling back to the row count
    // keeps the note hidden rather than claiming everything is truncated.
    const reported = finiteN(d.total, null)
    total.value = reported == null ? (d.backups || []).length : reported
    postgresTargets.value = d.postgres_targets || []
    immich.value = d.immich || { available: false, last: null, layers: null }
    loadError.value = ''
  } catch (e) {
    if (generation !== backupsGeneration || !pageAlive) return
    loadError.value = finiteText(e.message || String(e), '')
    // loadJobs() re-reads the artefact list when a running task ends — that
    // is background timing, and its failure must not toast over whatever the
    // operator moved on to; the LoadFailure banner already carries the state.
    // User-initiated reloads (mount, retry click) pass `manual` and toast.
    if (manual) toast('❌ ' + finiteText(e.message))
  } finally {
    if (generation === backupsGeneration) loaded.value = true
  }
}

async function loadJobs(manual = false) {
  const generation = ++jobsGeneration
  const wasRunning = jobs.value.some((j) => j.running)
  try {
    const d = await getSchedulerJobs()
    if (generation !== jobsGeneration || !pageAlive) return
    jobs.value = Array.isArray(d?.jobs) ? d.jobs : []
    jobsError.value = ''
    jobsPollFailures = 0
    // A finished run leaves new artefacts behind; pick them up without asking
    // the operator to press "Refresh list" to see the backup they just made.
    if (wasRunning && !jobs.value.some((j) => j.running)) void refresh()
  } catch (e) {
    if (generation !== jobsGeneration || !pageAlive) return
    jobsError.value = finiteText(e.message || String(e), '')
    jobsPollFailures += 1
    // The 7s running-job loop calls this without arguments: with the panel
    // down mid-backup it used to re-toast the same failure every tick.  The
    // on-screen jobsError banner carries the state; only the retry button
    // (whose click event lands in `manual`) still toasts.
    if (manual) toast('❌ ' + finiteText(e.message))
  } finally {
    if (generation === jobsGeneration) jobsLoaded.value = true
  }
  scheduleJobsPoll()
}

// While a backup task is running, re-read the job list every few seconds so
// the "Running…" badge and last-run status resolve on their own — the same
// loop the Scheduler page uses for the same jobs.  An idle page arms no timer,
// and a hidden tab keeps the loop armed without asking the host for status.
let jobsPollTimer = null
// With the panel dead mid-backup, the stale `running` flag keeps this loop
// alive forever — back it off like lib/poll.js (1.5^n, capped at 6x) instead
// of asking a host that is not answering every 7 seconds.
let jobsPollFailures = 0
const JOBS_POLL_MS = 7000
function jobsPollDelay() {
  return Math.min(JOBS_POLL_MS * Math.pow(1.5, jobsPollFailures), JOBS_POLL_MS * 6)
}
function scheduleJobsPoll() {
  if (!pageAlive || jobsPollTimer) return
  if (!jobs.value.some((j) => j.running)) return
  jobsPollTimer = setTimeout(() => {
    jobsPollTimer = null
    if (!pageAlive) return
    if (typeof document !== 'undefined' && document.hidden) scheduleJobsPoll()
    else void loadJobs()
  }, jobsPollDelay())
}

async function loadBinary() {
  try {
    const info = await getRsyncBinary()
    if (!pageAlive) return
    rsyncBinary.value = typeof info?.available === 'boolean' ? info : null
  } catch {
    if (!pageAlive) return
    rsyncBinary.value = null
  }
}

function openJobEditor(type, job) {
  jobEditor.value = { type, job }
}

async function saveJob(body) {
  busy.value = true
  try {
    if (jobEditor.value?.job) await updateSchedulerJob(jobEditor.value.job.id, body)
    else await createSchedulerJob(body)
    if (!pageAlive) return
    toast('✅ ' + t('sched.saved'))
    jobEditor.value = null
    await loadJobs()
  } catch (e) {
    if (!pageAlive) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (pageAlive) busy.value = false
  }
}

async function runJob(job) {
  const confirmKey = job.type === 'stack_backup'
    ? 'backups.confirm_stack_run'
    : 'backups.confirm_rsync_run'
  if (!confirm(t(confirmKey, { name: finiteText(job.name, '') || finiteText(job.id) }))) return
  try {
    await runSchedulerJobNow(job.id)
    if (!pageAlive) return
    toast('✅ ' + t('sched.started', { name: finiteText(job.name) }))
    await loadJobs()
  } catch (e) {
    if (!pageAlive) return
    toast('❌ ' + finiteText(e.message))
  }
}

async function removeJob(job) {
  if (!confirm(t('sched.confirm_delete', { name: finiteText(job.name) }))) return
  try {
    await deleteSchedulerJob(job.id)
    if (!pageAlive) return
    toast('✅ ' + t('sched.deleted'))
    await loadJobs()
  } catch (e) {
    if (!pageAlive) return
    toast('❌ ' + finiteText(e.message))
  }
}

async function openPreview(job) {
  previewFor.value = job
  preview.value = null
  previewError.value = ''
  previewBusy.value = true
  try {
    const next = await rsyncPreview(job.params || {})
    if (!pageAlive) return
    preview.value = next
  } catch (e) {
    if (!pageAlive) return
    previewError.value = finiteText(e.message || String(e), '')
  } finally {
    if (pageAlive) previewBusy.value = false
  }
}

async function doPg() {
  const names = postgresTargets.value.map((t) => finiteText(t.id, '')).filter(Boolean).join(', ') || 'PostgreSQL'
  if (!confirm(t('backups.confirm_pg', { names }))) return
  busy.value = true
  msg.value = t('backups.backing_up')
  try {
    const r = await backupPostgres()
    if (!pageAlive) return
    msg.value = (r.ok ? '✅ ' : '❌ ') + (finiteText(r.message, '') || '') + (finiteText(r.path, '') ? `\n${finiteText(r.path)} (${sizeMb(r.size_mb)})` : '')
    toast(r.ok ? '✅ ' + t('backups.pg_done') : '❌ ' + t('backups.pg_failed'))
    if (r.ok) await refresh(true)
  } catch (e) {
    if (!pageAlive) return
    toast('❌ ' + finiteText(e.message))
    msg.value = finiteText(e.message, '')
  } finally {
    if (pageAlive) busy.value = false
  }
}

async function doImmich() {
  if (!confirm(t('backups.confirm_immich'))) return
  busy.value = true
  msg.value = t('backups.backing_up')
  try {
    const r = await backupImmich()
    if (!pageAlive) return
    msg.value = (r.ok ? '✅ ' : '❌ ') + (finiteText(r.message, '') || '') + (finiteText(r.path, '') ? `\n${finiteText(r.path)} (${sizeMb(r.size_mb)})` : '')
    toast(r.ok ? '✅ ' + t('backups.immich_done') : '❌ ' + t('backups.pg_failed'))
    if (r.ok) await refresh(true)
  } catch (e) {
    if (!pageAlive) return
    toast('❌ ' + finiteText(e.message))
    msg.value = finiteText(e.message, '')
  } finally {
    if (pageAlive) busy.value = false
  }
}

async function doCfg() {
  if (!confirm(t('backups.confirm_cfg'))) return
  busy.value = true
  msg.value = t('backups.packing')
  try {
    const r = await backupConfigs()
    if (!pageAlive) return
    msg.value = (r.ok ? '✅ ' : '❌ ') + (finiteText(r.message, '') || '') + (finiteText(r.path, '') ? `\n${finiteText(r.path)}` : '')
    toast(r.ok ? '✅ ' + t('backups.cfg_done') : '❌ ' + t('common.failed'))
    if (r.ok) await refresh(true)
  } catch (e) {
    if (!pageAlive) return
    toast('❌ ' + finiteText(e.message))
    msg.value = finiteText(e.message, '')
  } finally {
    if (pageAlive) busy.value = false
  }
}

onMounted(() => {
  pageAlive = true
  // The first load counts as user-initiated: nothing is on screen yet, so a
  // failure toasts as well as raising the LoadFailure banner.
  refresh(true)
  loadJobs()
  loadBinary()
})

onUnmounted(() => {
  pageAlive = false
  backupsGeneration += 1
  jobsGeneration += 1
  if (jobsPollTimer) clearTimeout(jobsPollTimer)
  jobsPollTimer = null
})
</script>

<style scoped>
.advanced-sum {
  cursor: pointer;
  font-size: 13px;
  font-weight: 600;
}
.advanced-sum:focus-visible {
  outline: 2px solid var(--accent);
  outline-offset: 2px;
}
</style>
