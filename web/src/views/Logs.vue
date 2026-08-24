<template>
  <div>
    <div class="page-title">
      <h1>{{ t('logs.title') }}</h1>
      <span class="meta">{{ t('logs.meta') }}</span>
    </div>
    <div class="toolbar">
      <select v-model="sourceId" :aria-label="t('logs.source_label')" @change="load">
        <option v-for="s in sources" :key="s.id" :value="s.id">
          {{ finiteText(s.name) }}{{ s.exists ? ' · ' + fmtSize(s.size) : t('logs.missing') }}
        </option>
      </select>
      <select v-model.number="lines" :aria-label="t('logs.lines_label')" @change="load">
        <option :value="100">{{ t('logs.lines_n', { n: 100 }) }}</option>
        <option :value="200">{{ t('logs.lines_n', { n: 200 }) }}</option>
        <option :value="500">{{ t('logs.lines_n', { n: 500 }) }}</option>
        <option :value="1000">{{ t('logs.lines_n', { n: 1000 }) }}</option>
        <option :value="2000">{{ t('logs.lines_n', { n: 2000 }) }}</option>
      </select>
      <input v-model="filter" type="text" :placeholder="t('logs.filter_ph')" style="min-width:160px"  :aria-label="t('logs.filter_ph')"/>
      <button class="primary" :disabled="loading" @click="load">{{ t('common.refresh') }}</button>
      <label style="font-size:12px;color:var(--sub);display:flex;align-items:center;gap:6px">
        <input type="checkbox" v-model="auto" /> {{ t('logs.auto') }}
      </label>
      <button class="tiny hide-m" @click="copyLog">{{ t('logs.copy') }}</button>
      <button class="tiny hide-m" @click="downloadLog">{{ t('logs.download') }}</button>
    </div>
    <div v-if="meta" class="detail" style="margin-bottom:8px;white-space:normal">
      <span class="mono">{{ finiteText(meta.path) }}</span>
      · {{ fmtSize(meta.size) }}
      · {{ t('logs.lines_n', { n: fmtCount(meta.lines) }) }}
      <span v-if="filter"> · {{ t('logs.matched', { n: finiteN(displayLines.length) }) }}</span>
    </div>
    <LoadFailure v-if="loadError" :detail="loadError" :retry="retry" :busy="loading" />
    <pre v-if="!loaded" class="log-viewer">{{ t('common.loading') }}</pre>
    <pre v-else-if="displayText" class="log-viewer">{{ finiteText(displayText) }}</pre>
    <pre v-else-if="!loadError" class="log-viewer">{{ t('logs.empty') }}</pre>
  </div>
</template>

<script setup>
import { computed, inject, onMounted, onUnmounted, ref, watch } from 'vue'
import { getLogSources, getLogTail } from '../api/client'
import { injectI18n } from '../i18n'
import { copyToClipboard } from '../lib/clipboard'
import { finiteN, finiteText } from '../lib/finite'
import { startVisibleInterval } from '../lib/poll'
import LoadFailure from '../components/LoadFailure.vue'

const toast = inject('toast')
const { t } = injectI18n()
const sources = ref([])
const sourceId = ref('')
const lines = ref(200)
const text = ref('')
const meta = ref(null)
const loading = ref(false)
const loaded = ref(false)
const loadError = ref('')
const auto = ref(true)
const filter = ref('')
let timer = null
let loadGeneration = 0
let pageAlive = true

const displayLines = computed(() => {
  const f = filter.value.trim().toLowerCase()
  const all = (text.value || '').split('\n')
  if (!f) return all
  return all.filter(l => l.toLowerCase().includes(f))
})
const displayText = computed(() => displayLines.value.map((l) => finiteText(l, '')).join('\n'))

function fmtSize(n) {
  if (n == null || n === 0) return '0 B'
  const u = ['B', 'KB', 'MB', 'GB']
  let i = 0
  let v = Number(n)
  if (!Number.isFinite(v) || v < 0) return '—'
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++ }
  return `${v < 10 && i > 0 ? v.toFixed(1) : Math.round(v)} ${u[i]}`
}
function fmtCount(n) {
  const v = Number(n)
  return Number.isFinite(v) && v >= 0 ? v : '—'
}

async function loadSources() {
  const generation = loadGeneration
  try {
    const d = await getLogSources()
    if (generation !== loadGeneration || !pageAlive) return false
    sources.value = d.sources || []
    if (!sourceId.value && sources.value.length) sourceId.value = sources.value[0].id
    loadError.value = ''
    return true
  } catch (e) {
    if (generation !== loadGeneration || !pageAlive) return false
    loadError.value = e.message || String(e)
    toast('❌ ' + finiteText(e.message))
    return false
  }
}

async function load() {
  if (!sourceId.value) {
    loaded.value = true
    return true
  }
  const generation = ++loadGeneration
  const requestedSource = sourceId.value
  const requestedLines = lines.value
  loading.value = true
  try {
    const d = await getLogTail(requestedSource, requestedLines)
    if (generation !== loadGeneration || !pageAlive || requestedSource !== sourceId.value || requestedLines !== lines.value) return true
    meta.value = d
    text.value = d.log || ''
    loadError.value = ''
    return true
  } catch (e) {
    if (generation !== loadGeneration || !pageAlive) return false
    loadError.value = e.message || String(e)
    toast('❌ ' + finiteText(e.message))
    return false
  } finally {
    if (generation === loadGeneration && pageAlive) {
      loading.value = false
      loaded.value = true
    }
  }
}

function retry() {
  if (sources.value.length) return load()
  return loadSources().then((ok) => { if (ok) return load() })
}

async function copyLog() {
  const generation = loadGeneration
  const ok = await copyToClipboard(displayText.value)
  if (generation !== loadGeneration || !pageAlive) return
  toast(ok ? t('common.copied') : '❌ ' + t('common.copy_failed'))
}
function downloadLog() {
  const blob = new Blob([displayText.value || ''], { type: 'text/plain' })
  const a = document.createElement('a')
  a.href = URL.createObjectURL(blob)
  a.download = `${sourceId.value || 'log'}.txt`
  a.click()
  URL.revokeObjectURL(a.href)
}

function stopAutoRefresh() {
  if (typeof timer === 'function') timer()
  timer = null
}
function startAutoRefresh() {
  if (!pageAlive) return
  stopAutoRefresh()
  if (auto.value) timer = startVisibleInterval(load, 6000)
}

watch(auto, (_on, _prev, onCleanup) => {
  if (!pageAlive) return
  startAutoRefresh()
  onCleanup(stopAutoRefresh)
})

onMounted(async () => {
  pageAlive = true
  await loadSources()
  if (!pageAlive) return
  await load()
  if (!pageAlive) return
  startAutoRefresh()
})
onUnmounted(() => {
  pageAlive = false
  loadGeneration += 1
  if (typeof timer === 'function') timer()
  timer = null
})
</script>

<style scoped>
.log-viewer {
  white-space: pre-wrap;
  word-break: break-all;
  font-size: 11px;
  line-height: 1.5;
  max-height: 72vh;
  overflow: auto;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  padding: 12px 14px;
  background: color-mix(in srgb, var(--header) 4%, var(--card));
  border: 1px solid var(--line);
  border-radius: var(--radius);
  box-shadow: inset 0 1px 3px rgba(0,0,0,.04);
  color: var(--txt);
}
</style>
