<template>
  <div>
    <div class="page-title">
      <h1>{{ t('audit.title') }}</h1>
      <span class="meta">{{ t('audit.meta') }}</span>
    </div>

    <div class="toolbar">
      <button class="primary" @click="refresh">{{ t('common.refresh') }}</button>
      <span class="meta">{{ t('audit.redaction_note') }}</span>
    </div>

    <div v-if="!entries.length" class="placeholder">{{ t('audit.empty') }}</div>
    <template v-else>
      <div class="table-wrap">
        <table class="dense">
          <thead>
            <tr>
              <th>{{ t('audit.time') }}</th>
              <th>{{ t('audit.event') }}</th>
              <th>{{ t('audit.account') }}</th>
              <th>{{ t('audit.client') }}</th>
              <th>{{ t('audit.outcome') }}</th>
              <th>{{ t('audit.detail') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="(e, i) in rows" :key="i">
              <td class="mono">{{ fmt(e.ts) }}</td>
              <td class="mono">{{ e.event }}</td>
              <td><strong>{{ e.username || '—' }}</strong></td>
              <td class="mono">{{ e.client || '—' }}</td>
              <td>
                <span class="badge" :class="badgeClass(e.outcome)">{{ e.outcome || '—' }}</span>
              </td>
              <td style="max-width:320px;font-size:11px">{{ detail(e) }}</td>
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

const toast = inject('toast')
const { t } = injectI18n()

const entries = ref([])
const maxRetained = ref(0)

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
  try {
    const d = await getAuthAudit(200)
    entries.value = d.entries || []
    maxRetained.value = d.retained_lines || 0
  } catch (e) {
    toast('❌ ' + e.message)
  }
}

onMounted(refresh)
</script>
