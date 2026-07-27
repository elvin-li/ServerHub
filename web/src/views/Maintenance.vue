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
    <div class="table-wrap">
      <table class="dense">
        <thead>
          <tr>
            <th>{{ t('maintenance.task') }}</th>
            <th>{{ t('maintenance.desc') }}</th>
            <th>{{ t('common.status') }}</th>
            <th>{{ t('common.actions') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="task in filtered" :key="task.id">
            <td>
              <strong>{{ task.name }}</strong>
              <div class="mono" style="color:var(--sub)">{{ task.id }}</div>
            </td>
            <td style="max-width:360px">{{ task.desc }}</td>
            <td>
              <span v-if="task.running" class="badge warn">{{ t('maintenance.running') }}</span>
              <span v-else-if="task.rc === 0" class="badge ok">✅ {{ task.finished }}</span>
              <span v-else-if="task.rc != null" class="badge down">❌ {{ task.rc }}</span>
              <span v-else class="badge">{{ t('maintenance.ready') }}</span>
            </td>
            <td class="ops">
              <button class="tiny primary" :disabled="task.running || anyRunning" @click="run(task)">{{ t('maintenance.run') }}</button>
              <button class="tiny" @click="openLog(task)">{{ t('maintenance.log') }}</button>
            </td>
          </tr>
          <tr v-if="!filtered.length">
            <td colspan="4" style="color:var(--sub)">
              {{ tasks.length ? t('common.none') : (loadError || t('common.loading')) }}
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <div ref="logPanel" v-if="logOpen" class="modal-bg" @click.self="closeLog" role="presentation">
      <div class="modal" role="dialog" aria-modal="true" aria-labelledby="maint-log-title">
        <div class="row" style="margin-bottom:10px">
          <span id="maint-log-title" class="name">📋 {{ logTitle }}</span>
          <button class="tiny" @click="closeLog">{{ t('common.close') }}</button>
        </div>
        <pre>{{ logText }}</pre>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, inject, onMounted, onUnmounted, ref } from 'vue'
import { getMaintenance, getMaintenanceLog, runMaintenance } from '../api/client'
import { injectI18n } from '../i18n'
import { useDismissable } from '../composables/useDismissable'

const toast = inject('toast')
const { t } = injectI18n()
const tasks = ref([])
const q = ref('')
const loadError = ref('')
const logOpen = ref(false)
const logPanel = ref(null)
const logTitle = ref('')
const logText = ref('')
const curId = ref(null)
let pollTimer = null
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

async function refresh() {
  try {
    const list = await getMaintenance()
    tasks.value = Array.isArray(list) ? list : (list?.tasks || [])
    loadError.value = ''
  } catch (e) {
    loadError.value = e.message || String(e)
    // keep previous tasks if any
  }
}

async function run(task) {
  if (task.confirm && !confirm(t('maintenance.confirm_run', { name: task.name }))) return
  try {
    await runMaintenance(task.id)
    toast('🚀 ' + t('maintenance.started', { name: task.name }))
    openLog(task)
    refresh()
  } catch (e) {
    toast('❌ ' + (e.message || e))
  }
}

async function pollLog() {
  if (!curId.value) return
  try {
    const j = await getMaintenanceLog(curId.value)
    logText.value = j.log + (j.running ? '\n⏳…' : (j.rc == null ? '' : '\n' + t('maintenance.log_end', { rc: j.rc })))
    if (!j.running) {
      clearInterval(pollTimer)
      pollTimer = null
      refresh()
    }
  } catch {}
}

function openLog(task) {
  curId.value = task.id
  logTitle.value = task.name
  logOpen.value = true
  logText.value = t('maintenance.log_loading')
  pollLog()
  if (pollTimer) clearInterval(pollTimer)
  pollTimer = setInterval(pollLog, 1500)
}
function closeLog() {
  logOpen.value = false
  curId.value = null
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null }
}

onMounted(() => {
  refresh()
  // list is cheap but 4s was wasteful; 15s is enough for task status
  listTimer = setInterval(() => {
    if (typeof document !== 'undefined' && document.hidden) return
    refresh()
  }, 15000)
})
onUnmounted(() => {
  clearInterval(listTimer)
  if (pollTimer) clearInterval(pollTimer)
})


// Escape dismisses each dialog, focus returns to whatever opened it, and Tab
// cannot wander to the page behind the overlay.
useDismissable(logOpen, () => { closeLog() }, logPanel)
</script>
