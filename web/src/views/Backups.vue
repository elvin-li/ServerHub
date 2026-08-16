<template>
  <div>
    <div class="page-title">
      <h1>{{ t('backups.title') }}</h1>
      <span class="meta">{{ root || 'Services/backups' }}</span>
    </div>
    <div class="toolbar">
      <button class="primary" :disabled="busy" @click="doPg">{{ pgLabel }}</button>
      <button v-if="immich.available" :disabled="busy" @click="doImmich">{{ t('backups.immich') }}</button>
      <button :disabled="busy" @click="doCfg">{{ t('backups.cfg') }}</button>
      <button :disabled="busy" @click="refresh">{{ t('backups.refresh_list') }}</button>
    </div>
    <div v-if="msg" class="card" style="margin-bottom:12px;white-space:pre-wrap;font-size:13px">{{ msg }}</div>

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
          <div class="v" style="font-size:15px">{{ layers.db?.last?.name || t('photoshub.never') }}</div>
          <div class="meta">
            <template v-if="layers.db?.last">{{ layers.db.last.size_mb }} MB · :{{ layers.db.port }}</template>
            <template v-else>{{ t('backups.layer_db_hint') }}</template>
          </div>
        </div>
        <div class="tile span-4">
          <h3>{{ t('backups.layer_originals') }}</h3>
          <div class="v" style="font-size:15px">{{ originalsHeadline }}</div>
          <div class="meta">{{ layers.originals?.backup?.last_success || layers.originals?.path || t('photoshub.never') }}</div>
          <div v-if="layers.originals?.size_human" class="meta">{{ layers.originals.size_human }}</div>
        </div>
        <div class="tile span-4">
          <h3>{{ t('backups.layer_bridge') }}</h3>
          <div class="v" style="font-size:15px">{{ layerPresent(layers.bridge) }}</div>
          <div class="meta">{{ layers.bridge?.last_success || layers.bridge?.path || '—' }}</div>
          <div v-if="layers.bridge?.exported_files != null" class="meta">{{ t('backups.layer_bridge_files', { n: layers.bridge.exported_files }) }}</div>
        </div>
        <div class="tile span-4">
          <h3>{{ t('backups.layer_generated') }}</h3>
          <div class="v" style="font-size:15px">{{ layerPresent(layers.generated) }}</div>
          <div class="meta">{{ generatedSummary }}</div>
        </div>
        <div class="tile span-4">
          <h3>{{ t('backups.layer_external') }}</h3>
          <div class="v" style="font-size:15px">{{ layers.external?.last_success || t('photoshub.disk_absent') }}</div>
          <div class="meta">{{ layers.external?.reason || (layers.external?.ok === false ? t('common.issues') : '') }}</div>
        </div>
      </div>
    </div>

    <!-- A task type with no jobs has no table of its own, so its only "New task"
         button lives here. Shown whenever *either* type is empty: gating this on
         both being empty meant one rsync job hid the stack card and this block at
         the same time, leaving no way to create a stack backup anywhere. -->
    <details v-if="jobsLoaded && (!rsyncJobs.length || !stackJobs.length)" class="tile" style="margin-bottom:12px" data-test="backup-advanced">
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
        <span v-if="rsyncBinary && !rsyncBinary.available" style="color:var(--warn,#c60)"> {{ t('backups.rsync_missing') }}</span>
        <span v-else-if="rsyncBinary" class="mono"> · {{ rsyncBinary.variant }} {{ rsyncBinary.version }}</span>
      </p>
      <SkeletonLoader v-if="!jobsLoaded" :cols="5" :rows="2" />
      <div v-else class="table-wrap">
      <table class="dense fit-m">
        <tbody>
          <tr v-for="job in rsyncJobs" :key="job.id">
            <td>
              <strong>{{ job.name }}</strong>
              <div class="show-m sub mono">{{ job.params.src }} → {{ job.params.dest }}</div>
              <div class="show-m sub mono">{{ job.cron }}</div>
            </td>
            <td class="mono col-hide-m" style="font-size:11px;max-width:280px;overflow:hidden;text-overflow:ellipsis"
                :title="job.params.src + ' → ' + job.params.dest">
              {{ job.params.src }} → {{ job.params.dest }}
            </td>
            <td class="mono col-hide-m" style="font-size:11px">{{ job.cron }}</td>
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
            <td colspan="5" style="color:var(--sub);font-size:12px">{{ t('backups.no_tasks') }}</td>
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
              <strong>{{ job.name }}</strong>
              <div class="show-m sub mono">{{ job.params.stack_id }}</div>
              <div class="show-m sub">{{ t('backups.retain_n', { n: job.params.retain || 14 }) }} · {{ job.cron }}</div>
            </td>
            <td class="mono col-hide-m" style="font-size:11px">{{ job.params.stack_id }}</td>
            <td class="col-hide-m" style="font-size:11px">{{ t('backups.retain_n', { n: job.params.retain || 14 }) }}</td>
            <td class="mono col-hide-m" style="font-size:11px">{{ job.cron }}</td>
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
              {{ b.name }}
              <div v-if="b.dir" class="show-m sub">{{ b.dir }}</div>
              <div v-if="b.restore" class="show-m sub">
                <button class="tiny" type="button" @click="copyRestore(b.restore)">{{ t('common.copy') }}</button>
                {{ t('backups.restore') }}
              </div>
            </td>
            <td class="mono col-hide-m" style="font-size:11px">{{ b.dir }}</td>
            <td>{{ b.size_mb }} MB</td>
            <td>{{ fmt(b.mtime) }}</td>
            <td class="col-hide-m" style="font-size:11px;max-width:280px">
              <button v-if="b.restore" class="tiny" type="button" :title="t('backups.restore_copy')" @click="copyRestore(b.restore)">{{ t('common.copy') }}</button>
              <span v-if="b.restore" class="mono sub" :title="b.restore">{{ b.restore }}</span>
            </td>
          </tr>
          <tr v-if="!backups.length && !loadError">
            <td colspan="5" style="color:var(--sub)">{{ t('backups.empty') }}</td>
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
  if (!dirs.length) return layers.value?.generated?.path || '—'
  return dirs.map((d) => `${d.name}${d.present ? '' : '?'}`).join(' · ')
})
const originalsHeadline = computed(() => {
  const layer = layers.value?.originals
  if (!layer) return '—'
  if (layer.pct != null) return t('backups.layer_originals_pct', { n: layer.pct })
  return layerPresent(layer)
})
const pgLabel = computed(() => {
  const names = postgresTargets.value.map((t) => t.id).filter(Boolean)
  if (names.length === 1) return t('backups.pg_named', { name: names[0] })
  if (names.length > 1) return t('backups.pg')
  return t('backups.pg')
})

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

function layerPresent(layer) {
  if (!layer) return '—'
  return layer.present ? t('backups.layer_present') : t('backups.layer_missing')
}

async function copyRestore(text) {
  if (!text) return
  const ok = await copyToClipboard(text)
  toast(ok ? '✅ ' + t('common.copied') : '❌ ' + t('common.copy_failed'))
}

async function refresh() {
  try {
    const d = await getBackups()
    backups.value = d.backups || []
    root.value = d.root || ''
    // A panel that predates `total` sends none; falling back to the row count
    // keeps the note hidden rather than claiming everything is truncated.
    total.value = d.total ?? (d.backups || []).length
    postgresTargets.value = d.postgres_targets || []
    immich.value = d.immich || { available: false, last: null, layers: null }
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
  const names = postgresTargets.value.map((t) => t.id).filter(Boolean).join(', ') || 'PostgreSQL'
  if (!confirm(t('backups.confirm_pg', { names }))) return
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

async function doImmich() {
  if (!confirm(t('backups.confirm_immich'))) return
  busy.value = true
  msg.value = t('backups.backing_up')
  try {
    const r = await backupImmich()
    msg.value = (r.ok ? '✅ ' : '❌ ') + (r.message || '') + (r.path ? `\n${r.path} (${r.size_mb} MB)` : '')
    toast(r.ok ? '✅ ' + t('backups.immich_done') : '❌ ' + t('backups.pg_failed'))
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
