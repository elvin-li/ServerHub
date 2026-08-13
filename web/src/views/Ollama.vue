<template>
  <div>
    <div class="page-title">
      <h1>{{ t('ollama.title') }}</h1>
      <span class="meta">{{ t('ollama.meta') }} · {{ data?.ts || '…' }}</span>
    </div>

    <div class="toolbar">
      <button class="primary" :disabled="loading" @click="refreshNow">{{ t('common.refresh') }}</button>
      <router-link class="btn-link" to="/logs">{{ t('ollama.logs_link') }}</router-link>
    </div>

    <LoadFailure v-if="loadError" :detail="loadError" :retry="refreshNow" :busy="loading" />
    <SkeletonLoader v-if="!loaded" variant="tiles" :rows="2" :span="6" :tile-height="56" />

    <!-- Ollama absent: clear empty state + a path to install it -->
    <div v-else-if="data && !data.installed" class="card-block absent">
      <h2>{{ t('ollama.absent_title') }}</h2>
      <p class="meta">{{ t('ollama.absent_body') }}</p>
      <router-link class="btn-link" to="/apps">{{ t('ollama.absent_cta') }}</router-link>
    </div>

    <template v-else-if="data">
      <!-- Service card -->
      <div class="card-block" style="margin-bottom:14px">
        <div class="section-head">
          <h2>{{ t('ollama.service_title') }}</h2>
          <span class="badge" :class="serviceBadge.cls">{{ serviceBadge.text }}</span>
        </div>
        <div class="svc-grid">
          <div>
            <div class="meta">{{ t('ollama.service_label') }}</div>
            <div class="mono">{{ data.service?.label || '—' }}</div>
          </div>
          <div>
            <div class="meta">{{ t('ollama.version') }}</div>
            <div class="mono">{{ data.version || '—' }}</div>
          </div>
          <div>
            <div class="meta">API</div>
            <div class="mono">{{ data.url }}</div>
          </div>
          <div v-if="data.service?.pid">
            <div class="meta">PID</div>
            <div class="mono">{{ data.service.pid }}</div>
          </div>
        </div>
        <div class="toolbar" style="margin:10px 0 0">
          <button class="tiny primary" :disabled="svcBusy || !data.service?.label" @click="act('start')">{{ t('services.act_start') }}</button>
          <button class="tiny danger" :disabled="svcBusy || !data.service?.label" @click="act('stop')">{{ t('services.act_stop') }}</button>
          <button class="tiny" :disabled="svcBusy || !data.service?.label" @click="act('restart')">{{ t('services.act_restart') }}</button>
        </div>
      </div>

      <!-- Resident models -->
      <div class="card-block" style="margin-bottom:14px">
        <div class="section-head">
          <h2>{{ t('ollama.resident_title') }}</h2>
          <span class="meta">{{ t('ollama.resident_hint') }}</span>
        </div>
        <div class="table-wrap">
          <table class="dense">
            <thead>
              <tr>
                <th>{{ t('ollama.col_model') }}</th>
                <th>{{ t('ollama.col_vram') }}</th>
                <th>{{ t('ollama.col_context') }}</th>
                <th>{{ t('ollama.col_expires') }}</th>
                <th>{{ t('common.actions') }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="m in resident" :key="m.name">
                <td class="mono">{{ m.name }}</td>
                <td>{{ fmtSize(m.size_vram || m.size) }}</td>
                <td class="mono">{{ m.context_length || '—' }}</td>
                <td>{{ m.forever ? t('ollama.resident_forever') : fmtDate(m.expires_at) }}</td>
                <td class="ops">
                  <button class="tiny" :disabled="unloading" @click="unload(m)">{{ t('ollama.act_unload') }}</button>
                </td>
              </tr>
              <tr v-if="!resident.length">
                <td colspan="5" style="color:var(--sub)">
                  {{ data.reachable ? t('ollama.resident_empty') : t('ollama.daemon_unreachable') }}
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Installed models -->
      <div class="card-block" style="margin-bottom:14px">
        <div class="section-head">
          <h2>{{ t('ollama.models_title') }}</h2>
          <span class="meta">{{ models.length ? t('ollama.models_count', { n: models.length }) : '' }}</span>
        </div>
        <div class="table-wrap">
          <table class="dense">
            <thead>
              <tr>
                <th>{{ t('ollama.col_model') }}</th>
                <th>{{ t('ollama.col_size') }}</th>
                <th>{{ t('ollama.col_family') }}</th>
                <th>{{ t('ollama.col_quant') }}</th>
                <th>{{ t('ollama.col_caps') }}</th>
                <th>{{ t('ollama.col_modified') }}</th>
                <th>{{ t('common.actions') }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="m in models" :key="m.name">
                <td class="mono">{{ m.name }}</td>
                <td>{{ fmtSize(m.size) }}</td>
                <td>{{ m.family || '—' }} <span v-if="m.parameter_size" class="meta">{{ m.parameter_size }}</span></td>
                <td class="mono">{{ m.quantization || '—' }}</td>
                <td>
                  <span v-for="c in m.capabilities" :key="c" class="badge cap">{{ c }}</span>
                  <span v-if="!(m.capabilities || []).length">—</span>
                </td>
                <td class="meta">{{ fmtDate(m.modified) }}</td>
                <td class="ops">
                  <button class="tiny danger" @click="openDelete(m)">{{ t('ollama.act_delete') }}</button>
                </td>
              </tr>
              <tr v-if="!models.length">
                <td colspan="7" style="color:var(--sub)">
                  {{ data.reachable ? t('ollama.models_empty') : t('ollama.daemon_unreachable') }}
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Pull a model -->
      <div class="card-block" style="margin-bottom:14px">
        <div class="section-head">
          <h2>{{ t('ollama.pull_title') }}</h2>
          <span class="meta">{{ t('ollama.pull_hint') }}</span>
        </div>
        <div class="toolbar" style="margin-bottom:8px">
          <input
            v-model="pullName"
            type="text"
            class="mono"
            style="min-width:220px"
            :placeholder="t('ollama.pull_ph')"
            :aria-label="t('ollama.pull_name_label')"
            @keydown.enter="startPull"
          />
          <button class="primary" :disabled="pullBusy || pullInfo?.running || !pullName.trim()" @click="startPull">
            {{ pullInfo?.running ? t('ollama.pull_running_short') : t('ollama.act_pull') }}
          </button>
        </div>
        <div v-if="pullInfo && (pullInfo.running || pullInfo.log)">
          <div class="meta" style="margin-bottom:6px">
            <span v-if="pullInfo.running">⏳ {{ t('ollama.pull_running', { name: pullInfo.model || '' }) }}</span>
            <span v-else-if="pullInfo.rc === 0">✅ {{ t('ollama.pull_done_ok') }}</span>
            <span v-else-if="pullInfo.rc != null">❌ {{ t('ollama.pull_done_fail', { rc: pullInfo.rc }) }}</span>
          </div>
          <pre class="logbox" aria-live="polite">{{ pullInfo.log || t('maintenance.log_loading') }}</pre>
        </div>
      </div>

      <!-- Quick test -->
      <div class="card-block">
        <div class="section-head">
          <h2>{{ t('ollama.test_title') }}</h2>
          <span class="meta">{{ t('ollama.test_hint') }}</span>
        </div>
        <div class="toolbar" style="margin-bottom:8px;flex-wrap:wrap">
          <select v-model="testModel" :aria-label="t('ollama.test_model_label')">
            <option v-for="m in models" :key="m.name" :value="m.name">{{ m.name }}</option>
          </select>
          <input
            v-model="testPrompt"
            type="text"
            style="flex:1;min-width:200px"
            :placeholder="t('ollama.test_prompt_ph')"
            :aria-label="t('ollama.test_prompt_label')"
            maxlength="2000"
            @keydown.enter="runTest"
          />
          <button class="primary" :disabled="testBusy || !testModel || !testPrompt.trim()" @click="runTest">
            {{ testBusy ? t('ollama.testing') : t('ollama.act_test') }}
          </button>
        </div>
        <div v-if="testResult" class="meta" style="margin-bottom:6px">
          <span v-if="testResult.ok">
            ✅ {{ testResult.model }} ·
            {{ t('ollama.test_stats', { s: testResult.duration_s, tps: testResult.tokens_per_s ?? '—' }) }}
            <span v-if="testShowsThinking"> · {{ t('ollama.test_thinking_note') }}</span>
          </span>
          <span v-else>❌ {{ t('ollama.test_failed') }}</span>
        </div>
        <pre v-if="testResult || testBusy" class="logbox" aria-live="polite">{{ testText }}</pre>
      </div>
    </template>

    <!-- Typed-confirm delete dialog -->
    <div v-if="deleteTarget" class="modal-bg" @click.self="closeDelete" role="presentation">
      <div ref="deletePanel" class="modal" role="dialog" aria-modal="true" aria-labelledby="ollama-del-title">
        <div class="row" style="margin-bottom:10px">
          <span id="ollama-del-title" class="name">{{ t('ollama.delete_title') }}</span>
          <button class="tiny" @click="closeDelete">{{ t('common.close') }}</button>
        </div>
        <p style="margin:0 0 10px">
          {{ t('ollama.delete_body', { name: deleteTarget.name, size: fmtSize(deleteTarget.size) }) }}
        </p>
        <input
          v-model="deleteText"
          type="text"
          class="mono"
          style="width:100%;margin-bottom:10px"
          :placeholder="deleteTarget.name"
          :aria-label="t('ollama.delete_type_label')"
        />
        <div class="row">
          <button
            class="danger"
            :disabled="deleteText.trim() !== deleteTarget.name || deleting"
            @click="doDelete"
          >{{ t('ollama.delete_confirm') }}</button>
          <button @click="closeDelete">{{ t('common.cancel') }}</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, inject, onMounted, onUnmounted, ref } from 'vue'
import {
  deleteOllamaModel,
  doAction,
  getOllamaPullLog,
  getOllamaStatus,
  startOllamaPull,
  testOllamaModel,
  unloadOllamaModel,
} from '../api/client'
import { injectI18n } from '../i18n'
import { startVisibleInterval } from '../lib/poll'
import { useDismissable } from '../composables/useDismissable'
import SkeletonLoader from '../components/SkeletonLoader.vue'
import LoadFailure from '../components/LoadFailure.vue'

const toast = inject('toast')
const { t } = injectI18n()

const data = ref(null)
const loaded = ref(false)
const loading = ref(false)
const loadError = ref('')

const svcBusy = ref(false)
const unloading = ref(false)

const pullName = ref('')
const pullBusy = ref(false)
const pullInfo = ref(null)

const testModel = ref('')
const testPrompt = ref('')
const testBusy = ref(false)
const testResult = ref(null)

const deleteTarget = ref(null)
const deleteText = ref('')
const deleting = ref(false)
const deletePanel = ref(null)

let statusTimer = null
let actionTimer = null
let pullTimer = null
let pullGeneration = 0

const models = computed(() => (Array.isArray(data.value?.models) ? data.value.models : []))
const resident = computed(() => (Array.isArray(data.value?.resident) ? data.value.resident : []))

const serviceBadge = computed(() => {
  if (!data.value) return { cls: '', text: '' }
  if (data.value.reachable) return { cls: 'ok', text: t('ollama.state_running') }
  if (data.value.service?.running) return { cls: 'warn', text: t('ollama.state_starting') }
  return { cls: 'down', text: t('ollama.state_stopped') }
})

// Thinking models can spend the whole capped token budget reasoning, leaving
// `response` empty; the trace is then the only output worth showing.
const testShowsThinking = computed(() =>
  Boolean(testResult.value?.ok && !testResult.value.response && testResult.value.thinking))

const testText = computed(() => {
  if (testBusy.value) return t('ollama.testing')
  const r = testResult.value
  if (!r) return ''
  return r.response || r.thinking || r.error || ''
})

function fmtSize(n) {
  const v = Number(n) || 0
  if (v >= 1e9) return (v / 1e9).toFixed(1) + ' GB'
  if (v >= 1e6) return (v / 1e6).toFixed(0) + ' MB'
  if (v > 0) return (v / 1e3).toFixed(0) + ' KB'
  return '—'
}

function fmtDate(s) {
  return (s || '').slice(0, 16).replace('T', ' ') || '—'
}

/** One status read. Returns false on failure so lib/poll.js backs off. */
async function refresh(force = false) {
  loading.value = true
  try {
    const j = await getOllamaStatus(force)
    data.value = j
    loadError.value = ''
    if (!testModel.value && Array.isArray(j?.models) && j.models.length) {
      testModel.value = j.models[0].name
    }
    // A pull started elsewhere (or before a navigation) resumes its log tail.
    if (j?.pull?.running && !pullTimer) startPullPolling()
    return true
  } catch (e) {
    loadError.value = e.message || String(e)
    return false
  } finally {
    loaded.value = true
    loading.value = false
  }
}

function refreshNow() {
  void refresh(true)
}

// ── service control (existing /api/action channel; target = launchd label) ──
async function act(action) {
  const label = data.value?.service?.label
  if (!label) return
  if (action === 'stop' && !confirm(t('ollama.confirm_stop', { name: label }))) return
  svcBusy.value = true
  try {
    const r = await doAction(label, action)
    toast(r.ok ? `✅ ${label} · ${action}` : `❌ ${r.message || action}`)
    if (r.ok) {
      if (actionTimer) clearTimeout(actionTimer)
      actionTimer = setTimeout(() => {
        actionTimer = null
        void refresh(true)
      }, 1200)
    }
  } catch (e) {
    toast('❌ ' + (e.message || e))
  } finally {
    svcBusy.value = false
  }
}

// ── resident model unload ────────────────────────────────────────────────────
async function unload(m) {
  if (!confirm(t('ollama.confirm_unload', { name: m.name }))) return
  unloading.value = true
  try {
    await unloadOllamaModel(m.name)
    toast('✅ ' + t('ollama.unloaded', { name: m.name }))
    void refresh(true)
  } catch (e) {
    toast('❌ ' + (e.message || e))
  } finally {
    unloading.value = false
  }
}

// ── typed-confirm delete ─────────────────────────────────────────────────────
function openDelete(m) {
  deleteTarget.value = m
  deleteText.value = ''
}
function closeDelete() {
  deleteTarget.value = null
  deleteText.value = ''
}
async function doDelete() {
  const target = deleteTarget.value
  if (!target || deleteText.value.trim() !== target.name) return
  deleting.value = true
  try {
    await deleteOllamaModel(target.name)
    toast('✅ ' + t('ollama.deleted', { name: target.name }))
    closeDelete()
    void refresh(true)
  } catch (e) {
    toast('❌ ' + (e.message || e))
  } finally {
    deleting.value = false
  }
}

// Escape closes, focus is trapped in the panel and returned on close.
useDismissable(() => !!deleteTarget.value, () => closeDelete(), deletePanel)

// ── pull job (serialized log tail, same shape as the Maintenance page) ──────
function stopPullPolling() {
  pullGeneration += 1
  if (pullTimer) clearTimeout(pullTimer)
  pullTimer = null
}

async function pollPullLog(generation) {
  if (generation !== pullGeneration) return
  try {
    const j = await getOllamaPullLog()
    if (generation !== pullGeneration) return
    pullInfo.value = j
    if (!j.running) {
      stopPullPolling()
      void refresh(true)
      return
    }
  } catch (e) {
    if (generation !== pullGeneration) return
    // Transient failure: say so in the box and keep tailing.
    pullInfo.value = { ...(pullInfo.value || {}), log: `${pullInfo.value?.log || ''}\n⚠ ${e.message || e}`.trim() }
  }
  if (generation === pullGeneration) {
    pullTimer = setTimeout(() => { void pollPullLog(generation) }, 1500)
  }
}

function startPullPolling() {
  stopPullPolling()
  const generation = pullGeneration
  void pollPullLog(generation)
}

async function startPull() {
  const name = pullName.value.trim()
  if (!name || pullBusy.value || pullInfo.value?.running) return
  pullBusy.value = true
  try {
    await startOllamaPull(name)
    toast('🚀 ' + t('ollama.pull_started', { name }))
    pullName.value = ''
    startPullPolling()
  } catch (e) {
    toast('❌ ' + (e.message || e))
  } finally {
    pullBusy.value = false
  }
}

/** A pull started before this navigation resumes its tail immediately; the
 *  status snapshot is server-cached for 30s, so it cannot be the trigger.
 *  The probe already carries the log, so the loop is armed for the *next*
 *  tick instead of refetching what it just received. */
async function resumePullTail() {
  try {
    const j = await getOllamaPullLog()
    if (j?.running) {
      pullInfo.value = j
      stopPullPolling()
      const generation = pullGeneration
      pullTimer = setTimeout(() => { void pollPullLog(generation) }, 1500)
    }
  } catch {
    // No tail to resume — the status poll reports the daemon state anyway.
  }
}

// ── quick test ───────────────────────────────────────────────────────────────
async function runTest() {
  if (testBusy.value || !testModel.value || !testPrompt.value.trim()) return
  testBusy.value = true
  testResult.value = null
  try {
    testResult.value = await testOllamaModel(testModel.value, testPrompt.value)
  } catch (e) {
    testResult.value = { ok: false, error: e.message || String(e) }
  } finally {
    testBusy.value = false
  }
}

onMounted(() => {
  void refresh()
  void resumePullTail()
  statusTimer = startVisibleInterval(refresh, 10000)
})

onUnmounted(() => {
  if (typeof statusTimer === 'function') statusTimer()
  statusTimer = null
  if (actionTimer) clearTimeout(actionTimer)
  actionTimer = null
  stopPullPolling()
})
</script>

<style scoped>
.card-block {
  background: var(--card, var(--panel, #fff));
  border-radius: 12px;
  padding: 14px 16px;
  border: 1px solid var(--border, rgba(0, 0, 0, .06));
}
.section-head {
  display: flex;
  align-items: baseline;
  gap: 10px;
  margin-bottom: 10px;
}
.section-head h2 {
  margin: 0;
  font-size: 1.05rem;
}
.svc-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: 10px;
}
.absent {
  text-align: center;
  padding: 32px 16px;
}
.absent h2 { margin: 0 0 8px; }
.absent p { margin: 0 0 14px; }
.badge.cap {
  margin-right: 4px;
  font-size: 10px;
}
.logbox {
  max-height: 280px;
  overflow: auto;
  font-size: 11px;
  background: rgba(0, 0, 0, .04);
  padding: 10px;
  border-radius: 8px;
  white-space: pre-wrap;
  word-break: break-word;
}
.btn-link {
  display: inline-flex;
  align-items: center;
  padding: 6px 10px;
  border-radius: 8px;
  border: 1px solid var(--border, #ddd);
  text-decoration: none;
  color: inherit;
  font-size: 13px;
}
</style>
