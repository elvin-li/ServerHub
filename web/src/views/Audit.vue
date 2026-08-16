<template>
  <div>
    <div class="page-title">
      <h1>{{ t('audit.title') }}</h1>
      <span class="meta">{{ t('audit.meta') }}</span>
    </div>

    <div class="toolbar">
      <button class="primary" :disabled="busy" @click="refresh">{{ t('common.refresh') }}</button>
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
                {{ e.event }}
                <div class="show-m sub">{{ fmt(e.ts) }}</div>
                <div v-if="e.client" class="show-m sub">{{ e.client }}</div>
                <div v-if="detail(e)" class="show-m sub">{{ detail(e) }}</div>
              </td>
              <td><strong>{{ e.username || '—' }}</strong></td>
              <td class="mono col-hide-m">{{ e.client || '—' }}</td>
              <td>
                <span class="badge" :class="badgeClass(e.outcome)">{{ e.outcome || '—' }}</span>
              </td>
              <td class="col-hide-m" style="max-width:320px;font-size:11px">{{ detail(e) }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <p class="meta">{{ t('audit.retained', { n: entries.length, max: maxRetained }) }}</p>
    </template>
  </div>
</template>

<script setup>
import { computed, inject, onMounted, ref } from 'vue'
import { getAuthAudit } from '../api/client'
import { injectI18n } from '../i18n'
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

// Newest first on screen: an operator opening this page is looking at what just
// happened, not at the start of the file. The API returns oldest-first because
// that is the natural order of an append-only log.
const rows = computed(() => entries.value.slice().reverse())

function fmt(ts) {
  if (!ts) return ''
  const d = new Date(ts)
  return Number.isNaN(d.getTime()) ? ts : d.toLocaleString()
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
    .map(([k, v]) => `${k}=${v}`)
    .join(' · ')
}

async function refresh() {
  // Re-entry guard so repeated Refresh clicks do not issue concurrent reads whose
  // responses can resolve out of order into the shared `entries`.
  if (busy.value) return
  busy.value = true
  try {
    const d = await getAuthAudit(200)
    entries.value = d.entries || []
    maxRetained.value = d.retained_lines || 0
    loadError.value = ''
  } catch (e) {
    loadError.value = e.message || String(e)
    toast('❌ ' + e.message)
  } finally {
    loaded.value = true
    busy.value = false
  }
}

onMounted(refresh)
</script>
