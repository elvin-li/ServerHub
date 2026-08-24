<template>
  <div>
    <div class="page-title">
      <h1>{{ t('audit.title') }}</h1>
      <span class="meta">{{ t('audit.meta') }}</span>
    </div>

    <div class="toolbar">
      <button class="primary" :disabled="busy" @click="refresh(true)">{{ t('common.refresh') }}</button>
      <span class="meta">{{ t('audit.redaction_note') }}</span>
    </div>

    <LoadFailure v-if="loadError" :detail="loadError" :retry="refresh" :busy="busy" />
    <SkeletonLoader v-if="!loaded" :cols="6" :rows="8" />
    <div v-else-if="!entries.length && !loadError" class="placeholder">{{ t('audit.empty') }}</div>
    <template v-else>
      <div class="table-wrap">
        <table class="dense fit-m">
          <thead>
            <tr>
              <th class="col-hide-m">{{ t('audit.time') }}</th>
              <th>{{ t('audit.event') }}</th>
              <th>{{ t('audit.account') }}</th>
              <th class="col-hide-m">{{ t('audit.client') }}</th>
              <th>{{ t('audit.outcome') }}</th>
              <th class="col-hide-m">{{ t('audit.detail') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="(e, i) in rows" :key="i">
              <td class="mono col-hide-m">{{ fmt(e.ts) }}</td>
              <td class="mono">
                {{ finiteText(e.event) }}
                <div class="show-m sub">{{ fmt(e.ts) }}</div>
                <div v-if="finiteText(e.client, '')" class="show-m sub">{{ finiteText(e.client) }}</div>
                <div v-if="detail(e)" class="show-m sub">{{ detail(e) }}</div>
              </td>
              <td><strong>{{ finiteText(e.username) }}</strong></td>
              <td class="mono col-hide-m">{{ finiteText(e.client) }}</td>
              <td>
                <span class="badge" :class="badgeClass(e.outcome)">{{ finiteText(e.outcome) }}</span>
              </td>
              <td class="col-hide-m" style="max-width:320px;font-size:11px">{{ detail(e) }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <p class="meta">{{ t('audit.retained', { n: finiteN(entries.length), max: finiteN(maxRetained) }) }}</p>
    </template>
  </div>
</template>

<script setup>
import { computed, inject, onMounted, onUnmounted, ref } from 'vue'
import { getAuthAudit } from '../api/client'
import { injectI18n } from '../i18n'
import { finiteN, finiteText } from '../lib/finite'
import { startVisibleInterval } from '../lib/poll'
import SkeletonLoader from '../components/SkeletonLoader.vue'
import LoadFailure from '../components/LoadFailure.vue'

const toast = inject('toast')
const { t } = injectI18n()

const entries = ref([])
const maxRetained = ref(0)
// Without this the page rendered "no audit records" for the whole first request:
// `!entries.length` cannot tell "not fetched yet" from "fetched, and empty".
const loaded = ref(false)
const loadError = ref('')
// In-flight guard for refresh(); also drives the button's :disabled.
const busy = ref(false)
let pageAlive = true
let loadGeneration = 0

// Newest first on screen: an operator opening this page is looking at what just
// happened, not at the start of the file. The API returns oldest-first because
// that is the natural order of an append-only log.
const rows = computed(() => entries.value.slice().reverse())

function fmt(ts) {
  if (ts == null || ts === '') return ''
  const d = new Date(ts)
  // Invalid leftover values (Infinity, NaN, junk strings) used to be returned
  // verbatim, so the time column printed the word "Infinity".
  return Number.isNaN(d.getTime()) ? '' : d.toLocaleString()
}

function badgeClass(outcome) {
  if (outcome === 'success') return 'ok'
  if (outcome === 'failure') return 'down'
  return 'warn'
}

// Anything the backend added beyond the fixed columns, shown verbatim. Secrets
// are dropped server-side both on write and on read, so there is nothing to
// filter here.
const KNOWN = new Set(['ts', 'event', 'username', 'client', 'outcome'])
function detail(e) {
  return Object.entries(e)
    .filter(([k]) => !KNOWN.has(k))
    .map(([k, v]) => `${finiteText(k)}=${finiteText(v)}`)
    .join(' · ')
}

async function refresh(manual = false) {
  // Re-entry guard so repeated Refresh clicks do not issue concurrent reads whose
  // responses can resolve out of order into the shared `entries`.
  if (busy.value) return
  const generation = ++loadGeneration
  busy.value = true
  try {
    const d = await getAuthAudit(200)
    if (generation !== loadGeneration || !pageAlive) return
    entries.value = d.entries || []
    const retained = Number(d.retained_lines)
    maxRetained.value = Number.isFinite(retained) && retained >= 0 ? retained : 0
    loadError.value = ''
  } catch (e) {
    if (generation !== loadGeneration || !pageAlive) return false
    loadError.value = e.message || String(e)
    // Background ticks stay silent: LoadFailure already marks the failure, and
    // a toast per interval while the panel is down is pure noise.  Returning
    // false is lib/poll's opt-in sentinel for backoff.
    if (manual) toast('❌ ' + finiteText(e.message))
    return false
  } finally {
    if (generation === loadGeneration && pageAlive) {
      loaded.value = true
      busy.value = false
    }
  }
}

let stopPoll = null

onMounted(() => {
  pageAlive = true
  void refresh(true)
  // Sign-ins land while the page is open; without a poll the log was frozen at
  // whatever the first read returned.  Visibility-aware, silent on background
  // failures, backed off while the panel is unreachable.
  stopPoll = startVisibleInterval(refresh, 30000)
})

onUnmounted(() => {
  pageAlive = false
  loadGeneration += 1
  if (typeof stopPoll === 'function') stopPoll()
  stopPoll = null
})
</script>
