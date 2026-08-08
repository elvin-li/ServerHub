<template>
  <div>
    <div class="page-title">
      <h1>{{ t('pages.health') }}</h1>
      <span class="meta">{{ t('pages.health_meta') }} · {{ data?.ts || '…' }}</span>
    </div>

    <div class="toolbar">
      <button class="primary" @click="load" :disabled="loading">{{ t('health.rescan') }}</button>
      <span class="meta" v-if="data?.summary" style="color:var(--sub)">
        {{ t('health.passed') }} {{ data.summary.ok }} · {{ t('health.warnings') }} {{ data.summary.warn }} · {{ t('health.errors') }} {{ data.summary.error }}
        · {{ data.summary.total }}
      </span>
      <span v-if="data" class="badge" :class="data.healthy ? 'ok' : 'down'" style="margin-left:4px">
        {{ data.healthy ? t('common.healthy') : t('common.issues') }}
      </span>
    </div>

    <LoadFailure v-if="loadError" :detail="loadError" :retry="load" :busy="loading" />
    <SkeletonLoader v-if="!loaded" variant="tiles" :rows="4" :span="3" :tile-height="34" style="margin-bottom:12px" />
    <div class="dash-grid" style="margin-bottom:12px" v-else-if="data?.summary">
      <div class="tile span-3">
        <h3>{{ t('health.passed') }}</h3>
        <div class="v" style="color:var(--ok)">{{ data.summary.ok }}</div>
      </div>
      <div class="tile span-3">
        <h3>{{ t('health.warnings') }}</h3>
        <div class="v" style="color:var(--warn)">{{ data.summary.warn }}</div>
      </div>
      <div class="tile span-3">
        <h3>{{ t('health.errors') }}</h3>
        <div class="v" style="color:var(--down)">{{ data.summary.error }}</div>
      </div>
      <div class="tile span-3">
        <h3>{{ t('health.overall') }}</h3>
        <div class="v" style="font-size:16px">{{ data.healthy ? '✅ OK' : '⚠️' }}</div>
      </div>
    </div>

    <div class="tabs">
      <button :class="{ active: filter==='all' }" :aria-pressed="filter === 'all'" @click="filter='all'">{{ t('common.all') }}</button>
      <button :class="{ active: filter==='issues' }" :aria-pressed="filter === 'issues'" @click="filter='issues'">{{ t('health.only_issues') }}</button>
      <button :class="{ active: filter==='error' }" :aria-pressed="filter === 'error'" @click="filter='error'">{{ t('health.errors') }}</button>
      <button :class="{ active: filter==='warn' }" :aria-pressed="filter === 'warn'" @click="filter='warn'">{{ t('health.warnings') }}</button>
    </div>

    <SkeletonLoader v-if="!loaded" :cols="5" :rows="7" :label="t('common.scanning')" />
    <div v-else class="table-wrap">
      <table class="dense">
        <thead>
          <tr>
            <th style="width:36px"></th>
            <th>{{ t('health.check') }}</th>
            <th>{{ t('health.level') }}</th>
            <th>{{ t('health.detail') }}</th>
            <th>{{ t('health.fix') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="c in filtered" :key="c.id">
            <td><span class="led" :class="led(c)"></span></td>
            <td><strong>{{ c.name }}</strong></td>
            <td>
              <span class="badge" :class="levelBadge(c)">{{ levelLabel(c) }}</span>
            </td>
            <td class="mono" style="max-width:320px;font-size:11px">{{ c.detail }}</td>
            <td style="font-size:11px;color:var(--sub);max-width:280px">{{ c.fix || (c.ok ? '—' : '') }}</td>
          </tr>
          <tr v-if="!filtered.length && !loadError">
            <td colspan="5" style="color:var(--sub)">{{ loading ? t('common.scanning') : t('common.no_match') }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script setup>
import { computed, inject, onMounted, ref } from 'vue'
import { getHealthChecks } from '../api/client'
import { injectI18n } from '../i18n'
import SkeletonLoader from '../components/SkeletonLoader.vue'
import LoadFailure from '../components/LoadFailure.vue'

const toast = inject('toast')
const { t } = injectI18n()
const data = ref(null)
const loading = ref(false)
const loaded = ref(false)
const loadError = ref('')
const filter = ref('all')

const filtered = computed(() => {
  const list = data.value?.checks || []
  if (filter.value === 'all') return list
  if (filter.value === 'issues') return list.filter(c => !c.ok)
  if (filter.value === 'error') return list.filter(c => !c.ok && c.level === 'error')
  if (filter.value === 'warn') return list.filter(c => !c.ok && c.level === 'warn')
  return list
})

function led(c) {
  if (c.ok) return 'on'
  if (c.level === 'warn') return 'warn'
  return 'err'
}
function levelLabel(c) {
  if (c.ok) return t('common.pass')
  if (c.level === 'error') return t('common.error')
  if (c.level === 'warn') return t('common.warn')
  return c.level
}
function levelBadge(c) {
  if (c.ok) return 'ok'
  if (c.level === 'error') return 'down'
  if (c.level === 'warn') return 'warn'
  return ''
}

async function load() {
  loading.value = true
  try {
    data.value = await getHealthChecks()
    loadError.value = ''
  } catch (e) {
    loadError.value = e.message || String(e)
    toast('❌ ' + e.message)
  }
  loading.value = false
  loaded.value = true
}

onMounted(load)
</script>
