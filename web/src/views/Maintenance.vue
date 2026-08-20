<template>
  <div>
    <div class="page-title">
      <h1>{{ t('maintenance.title') }}</h1>
      <span class="meta">{{ t('maintenance.meta') }}</span>
    </div>
    <div class="toolbar">
      <button class="primary" @click="refresh">{{ t('common.refresh') }}</button>
      <input v-model="q" type="text" :placeholder="t('maintenance.filter_ph')"  :aria-label="t('maintenance.filter_ph')"/>
    </div>
    <!-- loadError was only rendered inside the empty-table row, so once the table
         had rows the 15s poll could fail indefinitely while stale task and run
         state stayed on screen with nothing marking it. Shown here it is visible
         in both states. -->
    <div v-if="loadError && tasks.length" class="placeholder" role="alert" style="margin-bottom:10px">
      {{ finiteText(loadError) }}
    </div>
    <div class="table-wrap">
      <table class="dense fit-m">
        <thead>
          <tr>
            <th>{{ t('maintenance.task') }}</th>
            <th class="col-hide-m">{{ t('maintenance.desc') }}</th>
            <th>{{ t('common.status') }}</th>
            <th>{{ t('common.actions') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="task in filtered" :key="task.id">
            <td>
              <strong>{{ finiteText(task.name) }}</strong>
              <div class="mono" style="color:var(--sub)">{{ finiteText(task.id) }}</div>
              <div v-if="finiteText(task.desc, '')" class="show-m sub">{{ finiteText(task.desc) }}</div>
            </td>
            <td class="col-hide-m" style="max-width:360px">{{ finiteText(task.desc) }}</td>
            <td>
              <span v-if="task.running" class="badge warn">{{ t('maintenance.running') }}</span>
              <span v-else-if="task.rc === 0" class="badge ok">✅ {{ finiteText(task.finished) }}</span>
              <span v-else-if="task.rc != null" class="badge down">❌ {{ finiteN(task.rc) }}</span>
              <span v-else class="badge">{{ t('maintenance.ready') }}</span>
            </td>
            <td class="ops">
              <button class="tiny primary" :disabled="task.running || anyRunning" @click="run(task)">{{ t('maintenance.run') }}</button>
              <button class="tiny" @click="openLog(task)">{{ t('maintenance.log') }}</button>
            </td>
          </tr>
          <tr v-if="!filtered.length">
            <td colspan="4" style="color:var(--sub)">
              {{ tasks.length ? t('common.none') : (finiteText(loadError, '') || (loaded ? t('common.none') : t('common.loading'))) }}
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <div ref="logPanel" v-if="logOpen" class="modal-bg" @click.self="closeLog" role="presentation">
      <div class="modal" role="dialog" aria-modal="true" aria-labelledby="maint-log-title">
        <div class="row" style="margin-bottom:10px">
          <span id="maint-log-title" class="name">📋 {{ finiteText(logTitle) }}</span>
          <button class="tiny" @click="closeLog">{{ t('common.close') }}</button>
        </div>
        <pre>{{ finiteText(logText) }}</pre>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, inject, onMounted, onUnmounted, ref } from 'vue'
import { getMaintenance, getMaintenanceLog, runMaintenance } from '../api/client'
import { injectI18n } from '../i18n'
import { finiteN, finiteText } from '../lib/finite'
import { startVisibleInterval } from '../lib/poll'
import { useDismissable } from '../composables/useDismissable'

const toast = inject('toast')
const { t } = injectI18n()
const tasks = ref([])
const q = ref('')
const loadError = ref('')
// Same trap as Users accounts: `loadError || "loading"` treats a successful
// empty list as still pending, so the table kept saying "loading" after the
// first read came back with nothing.
const loaded = ref(false)
const logOpen = ref(false)
const logPanel = ref(null)
const logTitle = ref('')
const logText = ref('')
const curId = ref(null)
let pollTimer = null
let pollGeneration = 0
let listTimer = null

const anyRunning = computed(() => tasks.value.some(row => row.running))
const filtered = computed(() => {
  const qq = q.value.trim().toLowerCase()
  if (!qq) return tasks.value
  return tasks.value.filter(row =>
    (row.name || '').toLowerCase().includes(qq)
    || (row.id || '').toLowerCase().includes(qq)
    || (row.desc || '').toLowerCase().includes(qq)
  )
})

let listGeneration = 0

async function refresh() {
  const generation = ++listGeneration
  try {
    const list = await getMaintenance()
    if (generation !== listGeneration || !pageAlive) return false
    tasks.value = Array.isArray(list) ? list : (list?.tasks || [])
    loadError.value = ''
    return true
  } catch (e) {
    if (generation !== listGeneration || !pageAlive) return false
    loadError.value = e.message || String(e)
    return false
  } finally {
    if (generation === listGeneration && pageAlive) loaded.value = true
  }
}

async function run(task) {
  if (anyRunning.value) return
  // Always confirm. Every maintenance entry is an arbitrary shell command that
  // runs against the host (brew upgrade, HA update, container rebuild), so the
  // safe default cannot be "fire on one click". Previously this was gated on
  // task.confirm, which defaults to false in the API (hub/routers/api.py) and is
  // absent from the documented example task, so the destructive entries shipped
  // unguarded.
  if (!confirm(t('maintenance.confirm_run', { name: finiteText(task.name) }))) return
  const generation = listGeneration
  task.running = true
  try {
    await runMaintenance(task.id)
    if (generation !== listGeneration || !pageAlive) return
    toast('🚀 ' + t('maintenance.started', { name: finiteText(task.name) }))
    openLog(task)
    await refresh()
  } catch (e) {
    if (generation !== listGeneration || !pageAlive) return
    task.running = false
    toast('❌ ' + finiteText(e.message || e))
  }
}

function stopLogPolling() {
  pollGeneration += 1
  if (pollTimer) clearTimeout(pollTimer)
  pollTimer = null
}

async function pollLog(generation) {
  const id = curId.value
  if (!id || generation !== pollGeneration || !pageAlive) return
  try {
    const j = await getMaintenanceLog(id)
    if (generation !== pollGeneration || curId.value !== id || !pageAlive) return
    logText.value = finiteText(j.log, '') + (j.running ? '\n⏳…' : (j.rc == null ? '' : '\n' + t('maintenance.log_end', { rc: finiteN(j.rc) })))
    if (!j.running) {
      stopLogPolling()
      void refresh()
      return
    }
  } catch (e) {
    if (generation !== pollGeneration || !pageAlive) return
    // Say so instead of leaving the modal on maintenance.log_loading forever.
    // The loop still re-arms so a transient failure recovers on its own.
    logText.value = `${logText.value === t('maintenance.log_loading') ? '' : logText.value || ''}\n⚠ ${finiteText(e.message || e)}`.trim()
  }
  if (generation === pollGeneration && curId.value === id && pageAlive) {
    pollTimer = setTimeout(() => { void pollLog(generation) }, 1500)
  }
}

function openLog(task) {
  stopLogPolling()
  curId.value = task.id
  logTitle.value = finiteText(task.name)
  logOpen.value = true
  logText.value = t('maintenance.log_loading')
  const generation = pollGeneration
  void pollLog(generation)
}
function closeLog() {
  logOpen.value = false
  curId.value = null
  stopLogPolling()
}

let pageAlive = true
onMounted(() => {
  pageAlive = true
  void refresh()
  listTimer = startVisibleInterval(refresh, 15000)
})
onUnmounted(() => {
  pageAlive = false
  listGeneration += 1
  if (typeof listTimer === 'function') listTimer()
  listTimer = null
  stopLogPolling()
})

// Escape dismisses each dialog, focus returns to whatever opened it, and Tab
// cannot wander to the page behind the overlay.
useDismissable(logOpen, () => { closeLog() }, logPanel)
</script>
