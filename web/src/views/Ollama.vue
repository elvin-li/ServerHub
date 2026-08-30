<template>
  <div>
    <div class="page-title">
      <h1>{{ t('ollama.title') }}</h1>
      <span class="meta">{{ t('ollama.meta') }} · {{ finiteText(data?.ts, '…') }}</span>
    </div>

    <div class="toolbar">
      <button class="primary" :disabled="loading" @click="refreshNow">{{ t('common.refresh') }}</button>
      <router-link class="btn-link" to="/logs">{{ t('ollama.logs_link') }}</router-link>
      <router-link class="btn-link" to="/settings?tab=advanced">{{ t('ollama.settings_link') }}</router-link>
    </div>

    <LoadFailure v-if="loadError" :detail="loadError" :retry="refreshNow" :busy="loading" />
    <SkeletonLoader v-if="!loaded" variant="tiles" :rows="2" :span="6" :tile-height="56" />

    <!-- Ollama absent: clear empty state + a path to install it -->
    <div v-else-if="data && !asRecord(data).installed" class="card-block absent">
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
        <div v-if="asArray(duplicateLabels).length" class="notice warn" role="alert">
          {{ t('ollama.duplicate_agents', { labels: asArray(duplicateLabels).map(l => finiteText(l, '')).filter(Boolean).join(', ') }) }}
        </div>
        <div v-if="asRecord(data).url_rejected" class="notice warn" role="alert" data-test="ollama-url-rejected">
          {{ t('ollama.url_rejected', { url: finiteText(asRecord(data).url) }) }}
        </div>
        <div class="svc-grid">
          <div>
            <div class="meta">{{ t('ollama.service_label') }}</div>
            <div class="mono">{{ finiteText(asRecord(asRecord(data).service).label) }}</div>
          </div>
          <div>
            <div class="meta">{{ t('ollama.version') }}</div>
            <div class="mono">{{ finiteText(asRecord(data).version) }}</div>
          </div>
          <div>
            <div class="meta">{{ t('ollama.api') }}</div>
            <div class="mono api-line">
              <span>{{ finiteText(asRecord(data).url) }}</span>
              <!-- Two identical "Copy" buttons sit in this card copying
                   different URLs; a form-controls listing cannot tell them
                   apart without the field name. The visible "Copy" text stays
                   first in the name (WCAG 2.5.3). -->
              <button class="tiny" type="button" :aria-label="t('ollama.copy_name', { name: t('ollama.api') })" @click="copyText(asRecord(data).url)">{{ t('common.copy') }}</button>
            </div>
          </div>
          <div>
            <div class="meta">{{ t('ollama.openai_api') }}</div>
            <div class="mono api-line">
              <span>{{ finiteText(openaiCompatUrl) }}</span>
              <button class="tiny" type="button" :aria-label="t('ollama.copy_name', { name: t('ollama.openai_api') })" @click="copyText(openaiCompatUrl)">{{ t('common.copy') }}</button>
            </div>
          </div>
          <div v-if="asRecord(asRecord(data).service).pid">
            <div class="meta">{{ t('ollama.pid') }}</div>
            <div class="mono">{{ finiteN(asRecord(asRecord(data).service).pid) }}</div>
          </div>
        </div>
        <p v-if="asRecord(asRecord(data).service).inferred" class="meta" style="margin:8px 0 0">
          {{ t('ollama.listing_missed') }}
        </p>
        <div class="toolbar" style="margin:10px 0 0">
          <button class="tiny primary" :disabled="svcBusy || !asRecord(asRecord(data).service).label || asRecord(data).reachable" @click="act('start')">{{ t('services.act_start') }}</button>
          <button class="tiny danger" :disabled="svcBusy || !asRecord(asRecord(data).service).label" @click="act('stop')">{{ t('services.act_stop') }}</button>
          <button class="tiny" :disabled="svcBusy || !asRecord(asRecord(data).service).label" @click="act('restart')">{{ t('services.act_restart') }}</button>
        </div>
      </div>

      <!-- Resident models -->
      <div class="card-block" style="margin-bottom:14px">
        <div class="section-head">
          <h2>{{ t('ollama.resident_title') }}</h2>
          <span class="meta">{{ t('ollama.resident_hint') }}</span>
        </div>
        <div class="table-wrap">
          <table class="dense fit-m">
            <thead>
              <tr>
                <th>{{ t('ollama.col_model') }}</th>
                <th>{{ t('ollama.col_vram') }}</th>
                <th class="col-hide-m">{{ t('ollama.col_context') }}</th>
                <th class="col-hide-m">{{ t('ollama.col_expires') }}</th>
                <th>{{ t('common.actions') }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="m in asArray(resident)" :key="finiteText(asRecord(m).name)">
                <td class="mono">
                  {{ finiteText(asRecord(m).name) }}
                  <div class="show-m sub">{{ finiteN(asRecord(m).context_length) }} · {{ asRecord(m).forever ? t('ollama.resident_forever') : fmtDate(asRecord(m).expires_at) }}</div>
                </td>
                <td>{{ fmtSize(asRecord(m).size_vram || asRecord(m).size) }}</td>
                <td class="mono col-hide-m">{{ finiteN(asRecord(m).context_length) }}</td>
                <td class="col-hide-m">{{ asRecord(m).forever ? t('ollama.resident_forever') : fmtDate(asRecord(m).expires_at) }}</td>
                <td class="ops">
                  <button class="tiny" :disabled="unloading" @click="unload(m)">{{ t('ollama.act_unload') }}</button>
                </td>
              </tr>
              <tr v-if="!asArray(resident).length">
                <td colspan="5" class="empty-row">
                  {{ emptyListText('ollama.resident_empty') }}
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
          <!-- role=status: the count is the 10s poll's (and a finished
               pull/delete's) only summary and changed silently for a screen
               reader — same treatment as the VMs and Health header counts. -->
          <span v-if="asArray(models).length" class="meta" role="status">{{ t('ollama.models_count', { n: finiteN(asArray(models).length) }) }}</span>
        </div>
        <div class="table-wrap">
          <table class="dense fit-m">
            <thead>
              <tr>
                <th>{{ t('ollama.col_model') }}</th>
                <th>{{ t('ollama.col_size') }}</th>
                <th class="col-hide-m">{{ t('ollama.col_family') }}</th>
                <th class="col-hide-m">{{ t('ollama.col_quant') }}</th>
                <th class="col-hide-m">{{ t('ollama.col_caps') }}</th>
                <th class="col-hide-m">{{ t('ollama.col_modified') }}</th>
                <th>{{ t('common.actions') }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="m in asArray(models)" :key="finiteText(asRecord(m).name)">
                <td class="mono">
                  {{ finiteText(asRecord(m).name) }}
                  <div class="show-m sub">{{ finiteText(asRecord(m).family) }}{{ finiteText(asRecord(m).parameter_size, '') ? ' ' + finiteText(asRecord(m).parameter_size) : '' }} · {{ finiteText(asRecord(m).quantization) }}</div>
                  <div v-if="asArray(asRecord(m).capabilities).length" class="show-m sub">{{ asArray(asRecord(m).capabilities).map(c => finiteText(c, '')).filter(Boolean).join(', ') }}</div>
                </td>
                <td>{{ fmtSize(asRecord(m).size) }}</td>
                <td class="col-hide-m">{{ finiteText(asRecord(m).family) }} <span v-if="finiteText(asRecord(m).parameter_size, '')" class="meta">{{ finiteText(asRecord(m).parameter_size) }}</span></td>
                <td class="mono col-hide-m">{{ finiteText(asRecord(m).quantization) }}</td>
                <td class="col-hide-m">
                  <span v-for="c in asArray(asRecord(m).capabilities)" :key="finiteText(c)" class="badge cap">{{ finiteText(c) }}</span>
                  <span v-if="!asArray(asRecord(m).capabilities).length">—</span>
                </td>
                <td class="meta col-hide-m">{{ fmtDate(asRecord(m).modified) }}</td>
                <td class="ops">
                  <button class="tiny danger" @click="openDelete(m)">{{ t('ollama.act_delete') }}</button>
                </td>
              </tr>
              <tr v-if="!asArray(models).length">
                <td colspan="7" class="empty-row">
                  {{ emptyListText('ollama.models_empty') }}
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
            class="mono pull-name"
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
            <span v-if="pullInfo.running">⏳ {{ t('ollama.pull_running', { name: finiteText(pullInfo.model, '') }) }}</span>
            <span v-else-if="pullInfo.rc === 0">✅ {{ t('ollama.pull_done_ok') }}</span>
            <span v-else-if="pullInfo.rc != null">❌ {{ t('ollama.pull_done_fail', { rc: finiteN(pullInfo.rc) }) }}</span>
          </div>
          <pre class="logbox" aria-live="polite">{{ finiteText(pullInfo.log, '') || t('maintenance.log_loading') }}</pre>
        </div>
      </div>

      <!-- In-panel chat -->
      <div class="card-block" style="margin-bottom:14px">
        <div class="section-head">
          <h2>{{ t('ollama.chat_title') }}</h2>
          <span class="meta">{{ t('ollama.chat_hint') }}</span>
        </div>
        <p v-if="!data.reachable" class="meta" style="margin:0 0 8px">{{ t('ollama.chat_unreachable') }}</p>
        <p v-else-if="!asArray(models).length" class="meta" style="margin:0 0 8px">{{ t('ollama.chat_no_model') }}</p>
        <div ref="chatLog" class="chat-log" :aria-live="asArray(chatMessages).length ? 'polite' : undefined">
          <div v-if="!asArray(chatMessages).length" class="meta">{{ t('ollama.chat_empty') }}</div>
          <div
            v-for="(m, i) in asArray(chatMessages)"
            :key="i"
            class="chat-msg"
            :class="asRecord(m).role"
          >
            <div class="chat-role">{{ asRecord(m).role === 'user' ? t('ollama.chat_you') : t('ollama.chat_assistant') }}</div>
            <pre v-if="asRecord(m).thinking && !asRecord(m).content" class="chat-thinking">{{ finiteText(asRecord(m).thinking) }}</pre>
            <details v-else-if="asRecord(m).thinking" class="chat-thinking-wrap">
              <summary>{{ t('ollama.chat_thinking') }}</summary>
              <pre class="chat-thinking">{{ finiteText(asRecord(m).thinking) }}</pre>
            </details>
            <div v-if="asRecord(m).content || asRecord(m).pending" class="chat-body">{{ finiteText(asRecord(m).content, '') || t('ollama.chat_sending') }}</div>
            <div v-if="asRecord(m).error" class="chat-error">{{ finiteText(asRecord(m).error) }}</div>
          </div>
        </div>
        <div class="toolbar" style="flex-wrap:wrap">
          <select v-model="chatModel" :aria-label="t('ollama.chat_model_label')" :disabled="chatBusy">
            <option v-for="m in asArray(models)" :key="'chat-' + finiteText(asRecord(m).name)" :value="asRecord(m).name">{{ finiteText(asRecord(m).name) }}</option>
          </select>
          <textarea
            v-model="chatInput"
            class="chat-input"
            rows="2"
            maxlength="2000"
            :placeholder="t('ollama.chat_input_ph')"
            :aria-label="t('ollama.chat_input_label')"
            :disabled="chatBusy || !data.reachable || !chatModel"
            @keydown.enter.exact.prevent="sendChat"
          />
          <button
            class="primary"
            :disabled="chatSendDisabled"
            @click="sendChat"
          >{{ chatBusy ? t('ollama.chat_sending') : t('ollama.chat_send') }}</button>
          <button :disabled="!asArray(chatMessages).length || chatBusy" @click="clearChat">{{ t('ollama.chat_clear') }}</button>
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
            <option v-for="m in asArray(models)" :key="'test-' + finiteText(asRecord(m).name)" :value="asRecord(m).name">{{ finiteText(asRecord(m).name) }}</option>
          </select>
          <input
            v-model="testPrompt"
            type="text"
            class="test-prompt"
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
            ✅ {{ finiteText(testResult.model) }} ·
            {{ t('ollama.test_stats', { s: finiteN(testResult.duration_s), tps: finiteN(testResult.tokens_per_s) }) }}
            <span v-if="testShowsThinking"> · {{ t('ollama.test_thinking_note') }}</span>
          </span>
          <span v-else>❌ {{ t('ollama.test_failed') }}</span>
        </div>
        <pre v-if="testResult || testBusy" class="logbox" aria-live="polite">{{ testText }}</pre>
      </div>
    </template>

    <template v-if="data">
      <div class="card-block" style="margin-bottom:14px" data-test="ollama-settings">
        <div class="section-head">
          <h2>{{ t('ollama.settings_title') }}</h2>
          <span class="meta">{{ t('ollama.settings_hint') }}</span>
        </div>
        <!-- Latched like the WireGuard settings dialog: the form falls back to
             literal defaults on a failed read, and Save sends every field, so
             saving on top of a failure silently wiped a configured LaunchAgent
             label. The old catch was fully silent — no toast, no inline text —
             and Save stayed enabled. -->
        <div
          v-if="!ollamaSettingsLoaded && ollamaSettingsError"
          class="notice warn"
          role="alert"
          data-test="ollama-settings-failed"
        >
          {{ t('ollama.settings_load_failed') }}
          <div class="mono" style="margin-top:4px;font-size:11px">{{ finiteText(ollamaSettingsError) }}</div>
          <button class="tiny" type="button" style="margin-top:6px" :disabled="ollamaSaving" @click="loadOllamaSettings">
            {{ t('common.retry') }}
          </button>
        </div>
        <div class="settings-grid">
          <label>{{ t('ollama.settings_url') }}</label>
          <input
            v-model="ollamaForm.url"
            type="text"
            :aria-label="t('ollama.settings_url')"
          />
          <label>{{ t('ollama.settings_label') }}</label>
          <input
            v-model="ollamaForm.label"
            type="text"
            :placeholder="t('ollama.settings_label_ph')"
            :aria-label="t('ollama.settings_label')"
          />
        </div>
        <div class="toolbar" style="margin:10px 0 0">
          <button class="tiny primary" :disabled="ollamaSaving || !ollamaSettingsLoaded" @click="saveOllamaSettings">
            {{ t('common.save') }}
          </button>
        </div>
      </div>
      <div class="card-block" data-test="ollama-clients">
        <div class="section-head">
          <h2>{{ t('ollama.clients_title') }}</h2>
          <span class="meta">{{ t('ollama.clients_hint') }}</span>
        </div>
        <ul class="clients-list">
          <li>{{ t('ollama.clients_cursor') }}</li>
          <li>{{ t('ollama.clients_lan') }}</li>
        </ul>
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
          {{ t('ollama.delete_body', { name: finiteText(asRecord(deleteTarget).name), size: fmtSize(asRecord(deleteTarget).size) }) }}
        </p>
        <input
          v-model="deleteText"
          type="text"
          class="mono"
          style="width:100%;margin-bottom:10px"
          :placeholder="finiteText(asRecord(deleteTarget).name, '')"
          :aria-label="t('ollama.delete_type_label')"
        />
        <div class="row">
          <button
            class="danger"
            :disabled="deleteText.trim() !== asRecord(deleteTarget).name || deleting"
            @click="doDelete"
          >{{ t('ollama.delete_confirm') }}</button>
          <button @click="closeDelete">{{ t('common.cancel') }}</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, inject, nextTick, onMounted, onUnmounted, ref } from 'vue'
import {
  chatOllamaModel,
  deleteOllamaModel,
  doAction,
  getOllamaPullLog,
  getOllamaStatus,
  getSettings,
  putSettings,
  startOllamaPull,
  testOllamaModel,
  unloadOllamaModel,
} from '../api/client'
import { injectI18n } from '../i18n'
import { copyToClipboard } from '../lib/clipboard'
import { asArray, asRecord, finiteText } from '../lib/finite'
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

const chatModel = ref('')
const chatInput = ref('')
const chatBusy = ref(false)
const chatMessages = ref([])
const chatLog = ref(null)
let chatAbort = null

const deleteTarget = ref(null)
const deleteText = ref('')
const deleting = ref(false)
const deletePanel = ref(null)

const ollamaForm = ref({ url: 'http://127.0.0.1:11434', label: '' })
const ollamaSaving = ref(false)
// Whether ollamaForm reflects the server's real settings. Save is blocked
// until it does: on a failed read the form holds fallbacks (default URL, empty
// label), and saveOllamaSettings sends both fields, so saving on top of a
// failed load silently cleared a configured LaunchAgent label — with a success
// toast. Latched rather than toasted because a toast is gone by the time the
// user reaches the Save button.
const ollamaSettingsLoaded = ref(false)
const ollamaSettingsError = ref('')

let statusTimer = null
let actionTimer = null
let pullTimer = null
let pullGeneration = 0

const models = computed(() => asArray(asRecord(data.value).models).map((row) => asRecord(row)))
const resident = computed(() => asArray(asRecord(data.value).resident).map((row) => asRecord(row)))
const duplicateLabels = computed(() => {
  const c = asArray(asRecord(asRecord(data.value).service).candidates)
  return c.length > 1 ? c : []
})

const openaiCompatUrl = computed(() => {
  const base = (finiteText(asRecord(data.value).url, '') || 'http://127.0.0.1:11434').replace(/\/$/, '')
  return finiteText(`${base}/v1`, '')
})

const serviceBadge = computed(() => {
  const row = asRecord(data.value)
  if (!data.value) return { cls: '', text: '' }
  if (row.reachable) return { cls: 'ok', text: t('ollama.state_running') }
  if (asRecord(row.service).running) return { cls: 'warn', text: t('ollama.state_starting') }
  return { cls: 'down', text: t('ollama.state_stopped') }
})

// Thinking models can spend the whole capped token budget reasoning, leaving
// `response` empty; the trace is then the only output worth showing.
const testShowsThinking = computed(() =>
  Boolean(testResult.value?.ok && !testResult.value.response && testResult.value.thinking))

const testText = computed(() => {
  if (testBusy.value) return t('ollama.testing')
  const r = testResult.value
  if (!r) return t('ollama.testing')
  return finiteText(r.response, '') || finiteText(r.thinking, '') || finiteText(r.error, '') || (r.ok ? '—' : t('ollama.test_failed'))
})

const chatSendDisabled = computed(() =>
  chatBusy.value
  || !data.value?.reachable
  || !chatModel.value
  || !chatInput.value.trim())

function defaultChatModel(j) {
  const row = asRecord(j)
  const res = asArray(row.resident).map((item) => asRecord(item))
  if (res[0]?.name) return res[0].name
  const mods = asArray(row.models).map((item) => asRecord(item))
  return mods[0]?.name || ''
}

async function scrollChat() {
  await nextTick()
  if (!pageAlive) return
  const el = chatLog.value
  if (el) el.scrollTop = el.scrollHeight
}

function finiteN(v) {
  const n = Number(v)
  return Number.isFinite(n) ? n : '—'
}

/** What an empty resident/models table really means.
 *
 * The daemon can answer /api/version and still fail /api/tags or /api/ps —
 * status() keeps reachable=true then and puts the reason in `error`, which
 * this page never rendered: the tables claimed "no models" over a failed
 * read (the same false-empty the unreachable branch already avoids). */
function emptyListText(emptyKey) {
  if (!data.value?.reachable) return t('ollama.daemon_unreachable')
  if (data.value?.error) return t('ollama.list_error', { error: finiteText(data.value.error, '') })
  return t(emptyKey)
}

function fmtSize(n) {
  const v = Number(n)
  if (!Number.isFinite(v) || v <= 0) return '—'
  if (v >= 1e9) return (v / 1e9).toFixed(1) + ' GB'
  if (v >= 1e6) return (v / 1e6).toFixed(0) + ' MB'
  return (v / 1e3).toFixed(0) + ' KB'
}

function fmtDate(s) {
  if (s == null || s === '') return '—'
  if (typeof s === 'number') return Number.isFinite(s) ? finiteText(new Date(s).toISOString().slice(0, 16).replace('T', ' ')) : '—'
  const text = String(s)
  if (text === 'Infinity' || text === '-Infinity' || text === 'NaN') return '—'
  return text.slice(0, 16).replace('T', ' ') || '—'
}

async function copyText(text) {
  if (!text) return
  const ok = await copyToClipboard(text)
  if (!pageAlive) return
  toast(ok ? '✅ ' + t('common.copied') : '❌ ' + t('common.copy_failed'))
}

async function loadOllamaSettings() {
  const generation = loadGeneration
  try {
    const s = asRecord(await getSettings())
    if (generation !== loadGeneration || !pageAlive) return
    ollamaForm.value = {
      url: asRecord(s.ollama).url || asRecord(data.value).url || 'http://127.0.0.1:11434',
      label: asRecord(s.ollama).label || '',
    }
    ollamaSettingsLoaded.value = true
    ollamaSettingsError.value = ''
  } catch (e) {
    if (generation !== loadGeneration || !pageAlive) return
    ollamaSettingsLoaded.value = false
    ollamaSettingsError.value = finiteText(e.message || e, '')
    ollamaForm.value = {
      url: asRecord(data.value).url || 'http://127.0.0.1:11434',
      label: ollamaForm.value.label || '',
    }
  }
}

async function saveOllamaSettings() {
  // Refuse to write when the current settings were never read back: the PUT
  // below would consist of this form's fallbacks.
  if (!ollamaSettingsLoaded.value) {
    toast('❌ ' + t('ollama.settings_load_failed'))
    return
  }
  const generation = loadGeneration
  ollamaSaving.value = true
  try {
    await putSettings({
      ollama: {
        url: ollamaForm.value.url.trim(),
        label: ollamaForm.value.label.trim(),
      },
    })
    if (generation !== loadGeneration || !pageAlive) return
    toast('✅ ' + t('ollama.settings_saved'))
    await refresh(true)
    await loadOllamaSettings()
  } catch (e) {
    if (generation !== loadGeneration || !pageAlive) return
    toast('❌ ' + finiteText(e.message || e))
  } finally {
    // refresh() bumps loadGeneration, so a generation match here would leave
    // Save stuck disabled after a successful write.
    if (pageAlive) ollamaSaving.value = false
  }
}

/** One status read. Returns false on failure so lib/poll.js backs off. */
async function refresh(force = false) {
  // Background 10s polls must not flip `loading`: that disables Refresh and
  // made the page feel like it was reloading on every tick.
  const generation = ++loadGeneration
  if (!loaded.value || force) loading.value = true
  try {
    const j = asRecord(await getOllamaStatus(force))
    if (generation !== loadGeneration || !pageAlive) return false
    data.value = {
      ...j,
      models: asArray(j.models).map((row) => asRecord(row)),
      resident: asArray(j.resident).map((row) => asRecord(row)),
      service: asRecord(j.service),
    }
    loadError.value = ''
    if (!testModel.value && asArray(j.models).length) {
      testModel.value = asRecord(asArray(j.models)[0]).name
    }
    if (!chatModel.value) chatModel.value = defaultChatModel(j)
    // A pull started elsewhere (or before a navigation) resumes its log tail.
    if (generation === loadGeneration && pageAlive && j?.pull?.running && !pullTimer) startPullPolling()
    return true
  } catch (e) {
    if (generation !== loadGeneration || !pageAlive) return false
    loadError.value = e.message || String(e)
    return false
  } finally {
    if (generation === loadGeneration && pageAlive) {
      loaded.value = true
      loading.value = false
    }
  }
}

function refreshNow() {
  void refresh(true)
}

// ── service control (existing /api/action channel; target = launchd label) ──
async function act(action) {
  const label = finiteText(data.value?.service?.label, '')
  if (!label) return
  if (action === 'stop' && !confirm(t('ollama.confirm_stop', { name: finiteText(label) }))) return
  if (action === 'restart' && !confirm(t('services.confirm_restart', { name: finiteText(label) }))) return
  const generation = loadGeneration
  svcBusy.value = true
  try {
    const r = asRecord(await doAction(label, action))
    if (generation !== loadGeneration || !pageAlive) return
    toast(r.ok ? `✅ ${label} · ${action}` : `❌ ${finiteText(r.message, '') || action}`)
    if (r.ok) {
      if (actionTimer) clearTimeout(actionTimer)
      actionTimer = setTimeout(() => {
        actionTimer = null
        if (generation !== loadGeneration || !pageAlive) return
        void refresh(true)
      }, 1200)
    }
  } catch (e) {
    if (generation !== loadGeneration || !pageAlive) return
    toast('❌ ' + finiteText(e.message || e))
  } finally {
    // refresh() bumps loadGeneration on the 10s poll, so a generation match
    // would leave Start/Stop stuck after a successful action.
    if (pageAlive) svcBusy.value = false
  }
}

// ── resident model unload ────────────────────────────────────────────────────
async function unload(m) {
  const row = asRecord(m)
  if (!confirm(t('ollama.confirm_unload', { name: finiteText(row.name) }))) return
  const generation = loadGeneration
  unloading.value = true
  try {
    const r = asRecord(await unloadOllamaModel(row.name))
    if (generation !== loadGeneration || !pageAlive) return
    toast('✅ ' + t('ollama.unloaded', { name: finiteText(row.name) }))
    void refresh(true)
  } catch (e) {
    if (generation !== loadGeneration || !pageAlive) return
    toast('❌ ' + finiteText(e.message || e))
  } finally {
    if (pageAlive) unloading.value = false
  }
}

// ── typed-confirm delete ─────────────────────────────────────────────────────
function openDelete(m) {
  deleteTarget.value = asRecord(m)
  deleteText.value = ''
}
function closeDelete() {
  deleteTarget.value = null
  deleteText.value = ''
}
async function doDelete() {
  const target = asRecord(deleteTarget.value)
  if (!target.name || deleteText.value.trim() !== target.name) return
  const generation = loadGeneration
  deleting.value = true
  try {
    const r = asRecord(await deleteOllamaModel(target.name))
    if (generation !== loadGeneration || !pageAlive) return
    toast('✅ ' + t('ollama.deleted', { name: finiteText(target.name) }))
    closeDelete()
    void refresh(true)
  } catch (e) {
    if (generation !== loadGeneration || !pageAlive) return
    toast('❌ ' + finiteText(e.message || e))
  } finally {
    if (pageAlive) deleting.value = false
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
    const j = asRecord(await getOllamaPullLog())
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
    pullInfo.value = { ...asRecord(pullInfo.value), log: `${pullInfo.value?.log || ''}\n⚠ ${e.message || e}`.trim() }
  }
  if (generation === pullGeneration) {
    pullTimer = setTimeout(() => { void pollPullLog(generation) }, 1500)
  }
}

function startPullPolling() {
  if (!pageAlive) return
  stopPullPolling()
  const generation = pullGeneration
  void pollPullLog(generation)
}

async function startPull() {
  const name = pullName.value.trim()
  if (!name || pullBusy.value || pullInfo.value?.running) return
  const generation = loadGeneration
  pullBusy.value = true
  try {
    const r = asRecord(await startOllamaPull(name))
    if (generation !== loadGeneration || !pageAlive) return
    toast('🚀 ' + t('ollama.pull_started', { name: finiteText(name) }))
    pullName.value = ''
    startPullPolling()
  } catch (e) {
    if (generation !== loadGeneration || !pageAlive) return
    toast('❌ ' + finiteText(e.message || e))
  } finally {
    if (pageAlive) pullBusy.value = false
  }
}

/** A pull started before this navigation resumes its tail immediately; the
 *  status snapshot is server-cached for 30s, so it cannot be the trigger.
 *  The probe already carries the log, so the loop is armed for the *next*
 *  tick instead of refetching what it just received. */
async function resumePullTail() {
  try {
    const j = asRecord(await getOllamaPullLog())
    if (!pageAlive) return
    if (j.running) {
      pullInfo.value = j
      stopPullPolling()
      const generation = pullGeneration
      pullTimer = setTimeout(() => { void pollPullLog(generation) }, 1500)
    }
  } catch {
    // No tail to resume — the status poll reports the daemon state anyway.
  }
}

// ── in-panel chat ────────────────────────────────────────────────────────────
async function sendChat() {
  const text = chatInput.value.trim()
  if (chatBusy.value || !data.value?.reachable || !chatModel.value || !text) return
  chatInput.value = ''
  chatMessages.value.push({ role: 'user', content: text })
  const pending = { role: 'assistant', content: '', thinking: '', pending: true, error: '' }
  chatMessages.value.push(pending)
  chatBusy.value = true
  chatAbort = new AbortController()
  // The just-pushed user turn is not pending; include it. Drop empty assistant stubs.
  const payload = chatMessages.value
    .filter((m) => !m.pending && (m.role === 'user' || (m.role === 'assistant' && m.content)))
    .map((m) => ({ role: m.role, content: m.content }))
  void scrollChat()
  try {
    await chatOllamaModel(chatModel.value, payload, 128, {
      signal: chatAbort.signal,
      onChunk(snap) {
        if (!pageAlive) return
        pending.content = snap.content || ''
        pending.thinking = snap.thinking || ''
        pending.pending = !snap.done
        void scrollChat()
      },
    })
    if (!pageAlive) return
    pending.pending = false
  } catch (e) {
    if (!pageAlive) return
    pending.pending = false
    pending.error = e.message || String(e)
  } finally {
    if (pageAlive) {
      chatBusy.value = false
      chatAbort = null
      void scrollChat()
    }
  }
}

function clearChat() {
  if (!asArray(chatMessages.value).length) return
  if (!confirm(t('ollama.chat_clear_confirm'))) return
  if (chatAbort) chatAbort.abort()
  chatMessages.value = []
}

// ── quick test ───────────────────────────────────────────────────────────────
async function runTest() {
  if (testBusy.value || !testModel.value || !testPrompt.value.trim()) return
  const generation = loadGeneration
  testBusy.value = true
  testResult.value = null
  try {
    const next = asRecord(await testOllamaModel(testModel.value, testPrompt.value))
    if (generation !== loadGeneration || !pageAlive) return
    testResult.value = next
  } catch (e) {
    if (generation !== loadGeneration || !pageAlive) return
    testResult.value = { ok: false, error: e.message || String(e) }
  } finally {
    if (pageAlive) testBusy.value = false
  }
}

let pageAlive = true
let loadGeneration = 0
onMounted(() => {
  pageAlive = true
  void refresh()
  void loadOllamaSettings()
  void resumePullTail()
  statusTimer = startVisibleInterval(refresh, 10000)
})

onUnmounted(() => {
  pageAlive = false
  loadGeneration += 1
  if (typeof statusTimer === 'function') statusTimer()
  statusTimer = null
  if (actionTimer) clearTimeout(actionTimer)
  actionTimer = null
  stopPullPolling()
  if (chatAbort) chatAbort.abort()
  chatAbort = null
})
</script>

<style scoped>
.card-block {
  background: var(--card);
  border-radius: 12px;
  padding: 14px 16px;
  border: 1px solid var(--line);
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
  grid-template-columns: repeat(auto-fit, minmax(min(100%, 160px), 1fr));
  gap: 10px;
}
.api-line {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}
.settings-grid {
  display: grid;
  grid-template-columns: 110px 1fr;
  gap: 8px 12px;
  align-items: center;
}
.settings-grid label { color: var(--sub); font-size: 12px; }
.clients-list {
  margin: 0;
  padding-left: 18px;
  color: var(--txt);
  font-size: 13px;
  line-height: 1.55;
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
  border: 1px solid var(--line);
  text-decoration: none;
  color: inherit;
  font-size: 13px;
}
.notice.warn {
  margin: 0 0 10px;
  padding: 8px 10px;
  border-radius: 8px;
  border-left: 3px solid var(--warn, #c90);
  background: rgba(204, 153, 0, .08);
  font-size: 13px;
}
.chat-log {
  max-height: 360px;
  overflow: auto;
  display: flex;
  flex-direction: column;
  gap: 10px;
  margin-bottom: 10px;
  min-height: 72px;
}
.chat-msg {
  padding: 8px 10px;
  border-radius: 8px;
  background: rgba(0, 0, 0, .04);
  max-width: 85%;
}
.chat-msg.user {
  align-self: flex-end;
  background: rgba(0, 90, 200, .08);
}
.chat-msg.assistant {
  align-self: flex-start;
}
.chat-role {
  font-size: 11px;
  color: var(--sub, #666);
  margin-bottom: 4px;
}
.chat-body {
  white-space: pre-wrap;
  word-break: break-word;
  font-size: 13px;
}
.chat-thinking,
.chat-thinking-wrap pre {
  font-size: 11px;
  color: var(--sub, #666);
  white-space: pre-wrap;
  word-break: break-word;
  margin: 0 0 6px;
}
.chat-error {
  margin-top: 6px;
  font-size: 12px;
  /* --down-text, not the raw hue: --down is a fill colour and measures
     2.2-3.8:1 as text on the dark themes' cards. */
  color: var(--down-text);
}
.chat-input {
  flex: 1;
  min-width: 200px;
  min-height: 42px;
  resize: vertical;
}
.test-prompt { flex: 1; min-width: 200px; }
.pull-name { min-width: 220px; flex: 1 1 180px; }
@media (max-width: 640px) {
  .section-head { flex-wrap: wrap; }
  .settings-grid { grid-template-columns: 1fr; }
  .chat-input, .test-prompt, .pull-name { min-width: 0; width: 100%; }
}
</style>
