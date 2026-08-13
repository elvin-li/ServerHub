<template>
  <div>
    <div class="page-title">
      <h1>{{ t('backups.title') }}</h1>
      <span class="meta">{{ root || 'Services/backups' }}</span>
    </div>
    <div class="toolbar">
      <button class="primary" :disabled="busy" @click="doPg">{{ t('backups.pg') }}</button>
      <button :disabled="busy" @click="doCfg">{{ t('backups.cfg') }}</button>
      <button :disabled="busy" @click="refresh">{{ t('backups.refresh_list') }}</button>
    </div>
    <div v-if="msg" class="card" style="margin-bottom:12px;white-space:pre-wrap;font-size:13px">{{ msg }}</div>

    <!-- ── scheduled rsync sync tasks ─────────────────────────────────── -->
    <div class="tile" style="margin-bottom:12px">
      <div class="row">
        <h3 style="margin:0">{{ t('backups.rsync_title') }}</h3>
        <button class="tiny primary" @click="openJobEditor('rsync', null)">{{ t('backups.new_task') }}</button>
      </div>
      <p class="meta" style="font-size:11px;color:var(--sub);margin:6px 0">
        {{ t('backups.rsync_desc') }}
        <span v-if="rsyncBinary && !rsyncBinary.available" style="color:var(--warn,#c60)"> {{ t('backups.rsync_missing') }}</span>
        <span v-else-if="rsyncBinary" class="mono"> · {{ rsyncBinary.variant }} {{ rsyncBinary.version }}</span>
      </p>
      <SkeletonLoader v-if="!jobsLoaded" :cols="5" :rows="2" />
      <div v-else class="table-wrap">
      <table class="dense">
        <tbody>
          <tr v-for="job in rsyncJobs" :key="job.id">
            <td><strong>{{ job.name }}</strong></td>
            <td class="mono" style="font-size:11px;max-width:280px;overflow:hidden;text-overflow:ellipsis"
                :title="job.params.src + ' → ' + job.params.dest">
              {{ job.params.src }} → {{ job.params.dest }}
            </td>
            <td class="mono" style="font-size:11px">{{ job.cron }}</td>
            <td>
              <span v-if="job.running" class="badge warn">{{ t('sched.running') }}</span>
              <span v-else-if="job.last" class="badge" :class="job.last.status === 'ok' ? 'ok' : 'warn'">{{ t(`sched.status_${job.last.status}`) }}</span>
              <span v-else class="meta">{{ t('sched.never') }}</span>
            </td>
            <td>
              <div class="btns" style="gap:4px">
                <button class="tiny" @click="openPreview(job)">{{ t('backups.dry_run') }}</button>
                <button class="tiny" :disabled="job.running" @click="runJob(job)">{{ t('sched.run_now') }}</button>
                <button class="tiny" @click="openJobEditor('rsync', job)">{{ t('common.edit') }}</button>
                <button class="tiny" @click="removeJob(job)">{{ t('common.delete') }}</button>
              </div>
            </td>
          </tr>
          <tr v-if="!rsyncJobs.length && jobsLoaded">
            <td colspan="5" style="color:var(--sub);font-size:12px">{{ t('backups.no_tasks') }}</td>
          </tr>
        </tbody>
      </table>
      </div>
    </div>

    <!-- ── scheduled compose-stack (appdata) backups ──────────────────── -->
    <div class="tile" style="margin-bottom:12px">
      <div class="row">
        <h3 style="margin:0">{{ t('backups.stack_title') }}</h3>
        <button class="tiny primary" @click="openJobEditor('stack_backup', null)">{{ t('backups.new_task') }}</button>
      </div>
      <p class="meta" style="font-size:11px;color:var(--sub);margin:6px 0">{{ t('backups.stack_desc') }}</p>
      <SkeletonLoader v-if="!jobsLoaded" :cols="5" :rows="2" />
      <div v-else class="table-wrap">
      <table class="dense">
        <tbody>
          <tr v-for="job in stackJobs" :key="job.id">
            <td><strong>{{ job.name }}</strong></td>
            <td class="mono" style="font-size:11px">{{ job.params.stack_id }}</td>
            <td style="font-size:11px">{{ t('backups.retain_n', { n: job.params.retain || 14 }) }}</td>
            <td class="mono" style="font-size:11px">{{ job.cron }}</td>
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
            <td colspan="5" style="color:var(--sub);font-size:12px">{{ t('backups.no_tasks') }}</td>
          </tr>
        </tbody>
      </table>
      </div>
    </div>

    <LoadFailure v-if="loadError" :detail="loadError" :retry="refresh" :busy="busy" />
    <SkeletonLoader v-if="!loaded" :cols="4" :rows="5" />
    <div v-else class="table-wrap backups-artefacts">
      <table class="dense">
        <thead>
          <tr><th>{{ t('backups.file') }}</th><th>{{ t('backups.dir') }}</th><th>{{ t('backups.size') }}</th><th>{{ t('backups.time') }}</th></tr>
        </thead>
        <tbody>
          <tr v-for="b in backups" :key="b.path">
            <td class="mono">{{ b.name }}</td>
            <td class="mono" style="font-size:11px">{{ b.dir }}</td>
            <td>{{ b.size_mb }} MB</td>
            <td>{{ fmt(b.mtime) }}</td>
          </tr>
          <tr v-if="!backups.length && !loadError">
            <td colspan="4" style="color:var(--sub)">{{ t('backups.empty') }}</td>
          </tr>
        </tbody>
      </table>
      <!-- The table is capped, so say so. Without this the older backups look
           deleted rather than merely unlisted, which is the opposite of what a
           backups page should tell you. -->
      <p v-if="hiddenCount" class="meta" style="margin-top:8px">
        {{ t('backups.truncated', { shown: backups.length, total }) }}
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
          <span id="backups-preview-title" class="name">{{ t('backups.preview_title', { name: previewFor.name }) }}</span>
          <button class="tiny" @click="previewFor = null">{{ t('common.close') }}</button>
        </div>
        <div v-if="previewBusy" class="meta">{{ t('common.loading') }}</div>
        <div v-else-if="previewError" class="meta" style="color:var(--err,#c33)">{{ previewError }}</div>
        <template v-else-if="preview">
          <div style="margin-bottom:8px;font-size:12px">
            <span class="badge accent" style="margin-right:6px">{{ t('sched.preview_creates', { n: preview.creates }) }}</span>
            <span class="badge accent" style="margin-right:6px">{{ t('sched.preview_updates', { n: preview.updates }) }}</span>
            <span class="badge" :class="preview.deletes ? 'warn' : ''">{{ t('sched.preview_deletes', { n: preview.deletes }) }}</span>
            <span class="meta mono" style="margin-left:8px" v-if="preview.binary">{{ preview.binary.variant }} {{ preview.binary.version }}</span>
          </div>
          <div v-if="!preview.total" class="meta">{{ t('sched.preview_empty') }}</div>
          <div v-else style="max-height:300px;overflow:auto;font-family:ui-monospace,Menlo,monospace;font-size:11px;white-space:pre">
            <div v-for="(line, i) in preview.samples" :key="i">{{ line }}</div>
          </div>
        </template>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, inject, onMounted, ref } from 'vue'
import {
  backupConfigs,
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

// Scheduled backup tasks (rsync + stack) ride on the panel scheduler.
const jobs = ref([])
const jobsLoaded = ref(false)
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

const rsyncJobs = computed(() => jobs.value.filter((j) => j.type === 'rsync'))
const stackJobs = computed(() => jobs.value.filter((j) => j.type === 'stack_backup'))

function fmt(t) {
  return t ? new Date(t * 1000).toLocaleString() : ''
}

async function refresh() {
  try {
    const d = await getBackups()
    backups.value = d.backups || []
    root.value = d.root || ''
    // A panel that predates `total` sends none; falling back to the row count
    // keeps the note hidden rather than claiming everything is truncated.
    total.value = d.total ?? (d.backups || []).length
    loadError.value = ''
  } catch (e) {
    loadError.value = e.message || String(e)
    toast('❌ ' + e.message)
  } finally {
    loaded.value = true
  }
}

async function loadJobs() {
  try {
    const d = await getSchedulerJobs()
    jobs.value = Array.isArray(d?.jobs) ? d.jobs : []
  } catch (e) {
    toast('❌ ' + e.message)
  } finally {
    jobsLoaded.value = true
  }
}

async function loadBinary() {
  try {
    const info = await getRsyncBinary()
    rsyncBinary.value = typeof info?.available === 'boolean' ? info : null
  } catch {
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
    toast('✅ ' + t('sched.saved'))
    jobEditor.value = null
    await loadJobs()
  } catch (e) {
    toast('❌ ' + e.message)
  } finally {
    busy.value = false
  }
}

async function runJob(job) {
  try {
    await runSchedulerJobNow(job.id)
    toast('✅ ' + t('sched.started', { name: job.name }))
    await loadJobs()
  } catch (e) {
    toast('❌ ' + e.message)
  }
}

async function removeJob(job) {
  if (!confirm(t('sched.confirm_delete', { name: job.name }))) return
  try {
    await deleteSchedulerJob(job.id)
    toast('✅ ' + t('sched.deleted'))
    await loadJobs()
  } catch (e) {
    toast('❌ ' + e.message)
  }
}

async function openPreview(job) {
  previewFor.value = job
  preview.value = null
  previewError.value = ''
  previewBusy.value = true
  try {
    preview.value = await rsyncPreview(job.params || {})
  } catch (e) {
    previewError.value = e.message || String(e)
  } finally {
    previewBusy.value = false
  }
}

async function doPg() {
  if (!confirm(t('backups.confirm_pg'))) return
  busy.value = true
  msg.value = t('backups.backing_up')
  try {
    const r = await backupPostgres()
    msg.value = (r.ok ? '✅ ' : '❌ ') + (r.message || '') + (r.path ? `\n${r.path} (${r.size_mb} MB)` : '')
    toast(r.ok ? '✅ ' + t('backups.pg_done') : '❌ ' + t('backups.pg_failed'))
    if (r.ok) await refresh()
  } catch (e) {
    toast('❌ ' + e.message)
    msg.value = String(e.message)
  } finally {
    busy.value = false
  }
}

async function doCfg() {
  busy.value = true
  msg.value = t('backups.packing')
  try {
    const r = await backupConfigs()
    msg.value = (r.ok ? '✅ ' : '❌ ') + (r.message || '') + (r.path ? `\n${r.path}` : '')
    toast(r.ok ? '✅ ' + t('backups.cfg_done') : '❌ ' + t('common.failed'))
    if (r.ok) await refresh()
  } catch (e) {
    toast('❌ ' + e.message)
    msg.value = String(e.message)
  } finally {
    busy.value = false
  }
}

onMounted(() => {
  refresh()
  loadJobs()
  loadBinary()
})
</script>
