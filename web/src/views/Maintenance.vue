<template>
  <div>
    <div class="page-title">
      <h1>{{ t('maintenance.title') }}</h1>
      <span class="meta">{{ t('maintenance.meta') }}</span>
    </div>
    <div class="toolbar">
      <button class="primary" @click="refresh">{{ t('common.refresh') }}</button>
      <input v-model="q" type="text" :placeholder="t('maintenance.filter_ph')"  :aria-label="t('maintenance.filter_ph')"/>
      <!-- role=status: the count is the only feedback the filter box gives,
           and it changed silently for a screen reader. Same pattern as the
           Services filter count. -->
      <span class="meta-count" role="status">{{ asArray(filtered).length }} / {{ asArray(tasks).length }}</span>
    </div>
    <!-- The standard failed-load banner every sibling list page uses. The old
         inline placeholder only rendered once the table had rows, so a failed
         *first* read fell into the empty-table row: error text with no retry
         and no role=alert, silently, on the page whose whole job is running
         host commands. LoadFailure covers both states — first load and a
         re-poll over stale rows — and offers the retry. -->
    <LoadFailure v-if="loadError" :detail="loadError" :retry="refresh" />
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
          <tr v-for="task in asArray(filtered)" :key="finiteText(asRecord(task).id)">
            <td>
              <strong>{{ finiteText(asRecord(task).name) }}</strong>
              <div class="mono" style="color:var(--sub)">{{ finiteText(asRecord(task).id) }}</div>
              <div v-if="finiteText(asRecord(task).desc, '')" class="show-m sub">{{ finiteText(asRecord(task).desc) }}</div>
            </td>
            <td class="col-hide-m" style="max-width:360px">{{ finiteText(asRecord(task).desc) }}</td>
            <td>
              <span v-if="asRecord(task).running" class="badge warn">{{ t('maintenance.running') }}</span>
              <span v-else-if="asRecord(task).rc === 0" class="badge ok">✅ {{ finiteText(asRecord(task).finished) }}</span>
              <span v-else-if="asRecord(task).rc != null" class="badge down">❌ {{ finiteN(asRecord(task).rc) }}</span>
              <span v-else class="badge">{{ t('maintenance.ready') }}</span>
            </td>
            <td class="ops">
              <button class="tiny primary" :disabled="asRecord(task).running || anyRunning" @click="run(task)">{{ t('maintenance.run') }}</button>
              <button class="tiny" @click="openLog(task)">{{ t('maintenance.log') }}</button>
            </td>
          </tr>
          <!-- Gated on !loadError like Brew/Audit/Scheduler: the LoadFailure
               banner is the whole story for a failed read, and an empty claim
               under it would be false. -->
          <tr v-if="!asArray(filtered).length && !loadError">
            <td colspan="4" class="empty-row">
              <template v-if="!loaded">{{ t('common.loading') }}</template>
              <!-- A configured-empty page deserves a pointer to where tasks are
                   defined, not a bare "None": the list only ever fills from the
                   maintenance: section of services.yaml (see the example file). -->
              <template v-else-if="!asArray(tasks).length">
                {{ t('maintenance.empty_hint') }}
                <span class="mono">services.yaml → maintenance:</span>
              </template>
              <!-- Tasks exist but the filter hid them all: say the filter
                   missed (the Brew/Health/Services common.no_match split),
                   not a bare "None" that reads as configured-empty. -->
              <template v-else>{{ t('common.no_match') }}</template>
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
        <!-- role=log + polite live region: the poll appends the finish line
             (maintenance.log_end with the exit code) inside this pre, and a
             screen reader heard nothing when the job ended. Same convention
             as the Compose/Apps/Containers job logs. -->
        <pre role="log" aria-live="polite">{{ finiteText(logText) }}</pre>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, inject, onMounted, onUnmounted, ref } from 'vue'
import { getMaintenance, getMaintenanceLog, runMaintenance } from '../api/client'
import { injectI18n } from '../i18n'
import { asArray, asRecord, finiteN, finiteText } from '../lib/finite'
import { startVisibleInterval } from '../lib/poll'
import { useDismissable } from '../composables/useDismissable'
import LoadFailure from '../components/LoadFailure.vue'

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

const anyRunning = computed(() => asArray(tasks.value).some(row => asRecord(row).running))
const filtered = computed(() => {
  const list = asArray(tasks.value)
  const qq = q.value.trim().toLowerCase()
  if (!qq) return list
  // String(...): the API deliberately serves an under-cap int name/desc
  // verbatim (YAML `desc: 123`), and `(row.desc || '').toLowerCase()` threw
  // on it — typing one character in the filter box blanked the whole page.
  // asRecord: a leftover list cell that is not a mapping (null / string)
  // used to throw on ``row.name`` and blank the whole page.
  return list.filter(row => {
    const rec = asRecord(row)
    return String(rec.name ?? '').toLowerCase().includes(qq)
      || String(rec.id ?? '').toLowerCase().includes(qq)
      || String(rec.desc ?? '').toLowerCase().includes(qq)
  })
})

let listGeneration = 0

async function refresh() {
  const generation = ++listGeneration
  try {
    const list = await getMaintenance()
    if (generation !== listGeneration || !pageAlive) return false
    // asArray first: a leftover mapping (or ``{tasks: …}`` envelope) used
    // to throw on ``.length`` / ``.filter`` / ``v-for``.  asRecord on the
    // envelope, then asArray of ``.tasks``, fail-closes a hostile nested
    // list.  Each row is asRecord so a leftover null cell cannot throw
    // later.  Do not wrap a Set as asArray — this payload is never a Set.
    const rows = asArray(list)
    const fromEnvelope = asArray(asRecord(list).tasks)
    tasks.value = (rows.length ? rows : fromEnvelope).map((row) => asRecord(row))
    loadError.value = ''
    return true
  } catch (e) {
    if (generation !== listGeneration || !pageAlive) return false
    loadError.value = finiteText(e.message || String(e), '')
    return false
  } finally {
    if (generation === listGeneration && pageAlive) loaded.value = true
  }
}

async function run(task) {
  const rec = asRecord(task)
  if (anyRunning.value) return
  // Always confirm. Every maintenance entry is an arbitrary shell command that
  // runs against the host (brew upgrade, HA update, container rebuild), so the
  // safe default cannot be "fire on one click". Previously this was gated on
  // task.confirm, which defaults to false in the API (hub/routers/api.py) and is
  // absent from the documented example task, so the destructive entries shipped
  // unguarded.
  if (!confirm(t('maintenance.confirm_run', { name: finiteText(rec.name) }))) return
  const generation = listGeneration
  rec.running = true
  try {
    const r = asRecord(await runMaintenance(rec.id))
    if (generation !== listGeneration || !pageAlive) return
    toast('🚀 ' + t('maintenance.started', { name: finiteText(rec.name) }))
    openLog(rec)
    await refresh()
  } catch (e) {
    if (generation !== listGeneration || !pageAlive) return
    rec.running = false
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
    const j = asRecord(await getMaintenanceLog(id))
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
  const rec = asRecord(task)
  curId.value = rec.id
  logTitle.value = finiteText(rec.name)
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
