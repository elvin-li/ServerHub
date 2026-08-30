<template>
  <div>
    <div class="page-title">
      <h1>{{ t('audit.title') }}</h1>
      <span class="meta">{{ t('audit.meta') }}</span>
    </div>

    <div class="toolbar">
      <button class="primary" :disabled="busy" @click="refresh(true)">{{ t('common.refresh') }}</button>
      <input v-model="q" type="text" :placeholder="t('audit.filter_ph')" :aria-label="t('audit.filter_ph')" />
      <!-- role=status: the count is the only feedback the filter box gives,
           and it changed silently for a screen reader. Same pattern as the
           Services filter count. -->
      <span class="meta-count" role="status">{{ finiteN(asArray(filteredRows).length) }} / {{ finiteN(asArray(rows).length) }}</span>
      <span class="meta">{{ t('audit.redaction_note') }}</span>
    </div>

    <LoadFailure v-if="loadError" :detail="loadError" :retry="refresh" :busy="busy" />
    <SkeletonLoader v-if="!loaded" :cols="6" :rows="8" />
    <div v-else-if="!asArray(entries).length && !loadError" class="placeholder">{{ t('audit.empty') }}</div>
    <!-- Rows are the gate, not "else": with nothing fetched and the read failed,
         the else-branch rendered a table whose only row said "None" — an empty
         claim for an API failure. The banner above is the whole story; stale
         rows still render when a re-poll fails, which is the LoadFailure
         contract. -->
    <template v-else-if="asArray(entries).length">
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
            <tr v-for="(e, i) in asArray(filteredRows)" :key="finiteText(asRecord(e).ts) + ':' + finiteText(asRecord(e).event) + ':' + finiteText(asRecord(e).username) + ':' + i">
              <td class="mono col-hide-m">{{ fmt(asRecord(e).ts) }}</td>
              <td class="mono">
                {{ finiteText(asRecord(e).event) }}
                <div class="show-m sub">{{ fmt(asRecord(e).ts) }}</div>
                <div v-if="finiteText(asRecord(e).client, '')" class="show-m sub">{{ finiteText(asRecord(e).client) }}</div>
                <div v-if="detail(e)" class="show-m sub">{{ detail(e) }}</div>
              </td>
              <td><strong>{{ finiteText(asRecord(e).username) }}</strong></td>
              <td class="mono col-hide-m">{{ finiteText(asRecord(e).client) }}</td>
              <td>
                <span class="badge" :class="badgeClass(asRecord(e).outcome)">{{ finiteText(asRecord(e).outcome) }}</span>
              </td>
              <td class="col-hide-m" style="max-width:320px;font-size:11px">{{ detail(e) }}</td>
            </tr>
            <!-- This row only renders on a filter miss: the table itself is
                 gated on entries.length, so an empty log never reaches here
                 (it gets the audit.empty placeholder above). "None" claimed
                 the log was empty when the filter simply missed — the same
                 filter-miss/no-data split as Tools, Network and Health. -->
            <tr v-if="!asArray(filteredRows).length">
              <td colspan="6" class="empty-row">{{ t('common.no_match') }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <p class="meta">{{ t('audit.retained', { n: finiteN(asArray(entries).length), max: finiteN(maxRetained) }) }}</p>
    </template>
  </div>
</template>

<script setup>
import { computed, inject, onMounted, onUnmounted, ref } from 'vue'
import { getAuthAudit } from '../api/client'
import { injectI18n } from '../i18n'
import { asArray, asRecord, asTrimmed, finiteN, finiteText, jsonText } from '../lib/finite'
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
const rows = computed(() => {
  try {
    return asArray(entries.value).slice().reverse().map((e) => asRecord(e)).filter(
      (e) => e != null && typeof e === 'object' && !Array.isArray(e),
    )
  } catch {
    return []
  }
})

// Text filter over every rendered column — the same convention as the
// Maintenance task filter.  200 rows of mixed sign-ins need "which of these
// touched user X / came from client Y" to be one keystroke, not a scan.
const q = ref('')

function fieldText(value) {
  if (value != null && typeof value === 'object') return jsonText(value, '')
  try {
    return String(finiteText(value, ''))
  } catch {
    return ''
  }
}

const filteredRows = computed(() => {
  try {
    const list = asArray(rows.value)
    const needle = asTrimmed(q.value).toLowerCase()
    if (!needle) return list
    return list.filter((e) => {
      try {
        const row = asRecord(e)
        const hay = `${fieldText(row.event)} ${fieldText(row.username)} ${fieldText(row.client)} ${fieldText(row.outcome)} ${detail(e)}`
        return hay.toLowerCase().includes(needle)
      } catch {
        return false
      }
    })
  } catch {
    return []
  }
})

function fmt(ts) {
  if (ts == null || ts === '') return ''
  try {
    const d = new Date(ts)
    // Invalid leftover values (Infinity, NaN, junk strings) used to be returned
    // verbatim, so the time column printed the word "Infinity".
    return Number.isNaN(d.getTime()) ? '' : d.toLocaleString()
  } catch {
    return ''
  }
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
  try {
    return Object.entries(asRecord(e))
      .filter(([k]) => !KNOWN.has(k))
      .map(([k, v]) => `${finiteText(k)}=${finiteText(v)}`)
      .join(' · ')
  } catch {
    return ''
  }
}

async function refresh(manual = false) {
  // Re-entry guard so repeated Refresh clicks do not issue concurrent reads whose
  // responses can resolve out of order into the shared `entries`.
  if (busy.value) return
  const generation = ++loadGeneration
  busy.value = true
  try {
    const d = asRecord(await getAuthAudit(200))
    if (generation !== loadGeneration || !pageAlive) return
    try {
      entries.value = asArray(d.entries).slice()
    } catch {
      entries.value = []
    }
    const retained = finiteN(d.retained_lines, null)
    maxRetained.value = retained != null && Number.isFinite(retained) && retained >= 0 ? retained : 0
    loadError.value = ''
  } catch (e) {
    if (generation !== loadGeneration || !pageAlive) return false
    try {
      loadError.value = finiteText(e && e.message, '') || 'error'
    } catch {
      loadError.value = 'error'
    }
    // Background ticks stay silent: LoadFailure already marks the failure, and
    // a toast per interval while the panel is down is pure noise.  Returning
    // false is lib/poll's opt-in sentinel for backoff.
    if (manual) toast('❌ ' + finiteText(e && e.message))
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
