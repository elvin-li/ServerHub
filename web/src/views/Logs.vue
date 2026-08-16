<template>
  <div>
    <div class="page-title">
      <h1>{{ t('logs.title') }}</h1>
      <span class="meta">{{ t('logs.meta') }}</span>
    </div>
    <div class="toolbar">
      <select v-model="sourceId" @change="load">
        <option v-for="s in sources" :key="s.id" :value="s.id">
          {{ s.name }}{{ s.exists ? ' · ' + fmtSize(s.size) : t('logs.missing') }}
        </option>
      </select>
      <select v-model.number="lines" @change="load">
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
      <span class="mono">{{ meta.path }}</span>
      · {{ fmtSize(meta.size) }}
      · {{ t('logs.lines_n', { n: meta.lines }) }}
      <span v-if="filter"> · {{ t('logs.matched', { n: displayLines.length }) }}</span>
    </div>
    <pre class="log-viewer">{{ displayText || t('logs.empty') }}</pre>
  </div>
</template>

<script setup>
import { computed, inject, onMounted, onUnmounted, ref, watch } from 'vue'
import { getLogSources, getLogTail } from '../api/client'
import { injectI18n } from '../i18n'
import { startVisibleInterval } from '../lib/poll'

const toast = inject('toast')
const { t } = injectI18n()
const sources = ref([])
const sourceId = ref('')
const lines = ref(200)
const text = ref('')
const meta = ref(null)
const loading = ref(false)
const auto = ref(true)
const filter = ref('')
let timer = null
let loadGeneration = 0

const displayLines = computed(() => {
  const f = filter.value.trim().toLowerCase()
  const all = (text.value || '').split('\n')
  if (!f) return all
  return all.filter(l => l.toLowerCase().includes(f))
})
const displayText = computed(() => displayLines.value.join('\n'))

function fmtSize(n) {
  if (n == null || n === 0) return '0 B'
  const u = ['B', 'KB', 'MB', 'GB']
  let i = 0
  let v = Number(n)
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++ }
  return `${v < 10 && i > 0 ? v.toFixed(1) : Math.round(v)} ${u[i]}`
}

async function loadSources() {
  try {
    const d = await getLogSources()
    sources.value = d.sources || []
    if (!sourceId.value && sources.value.length) sourceId.value = sources.value[0].id
  } catch (e) { toast('❌ ' + e.message) }
}

async function load() {
  if (!sourceId.value) return true
  const generation = ++loadGeneration
  const requestedSource = sourceId.value
  const requestedLines = lines.value
  loading.value = true
  try {
    const d = await getLogTail(requestedSource, requestedLines)
    if (generation !== loadGeneration || requestedSource !== sourceId.value || requestedLines !== lines.value) return true
    meta.value = d
    text.value = d.log || ''
    return true
  } catch (e) {
    if (generation === loadGeneration) toast('❌ ' + e.message)
    return false
  } finally {
    if (generation === loadGeneration) loading.value = false
  }
}

async function copyLog() {
  // The success toast used to fire unconditionally on a call that was neither
  // awaited nor caught, so on a non-secure context (where navigator.clipboard is
  // undefined and `?.` short-circuits) or a denied permission the user was told
  // the copy worked when nothing had been copied.
  try {
    if (!navigator.clipboard) throw new Error(t('common.copy_failed'))
    await navigator.clipboard.writeText(displayText.value || '')
    toast(t('common.copied'))
  } catch {
    toast('❌ ' + t('common.copy_failed'))
  }
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
  stopAutoRefresh()
  if (auto.value) timer = startVisibleInterval(load, 6000)
}

watch(auto, startAutoRefresh)

onMounted(async () => {
  await loadSources()
  await load()
  startAutoRefresh()
})
onUnmounted(() => {
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
