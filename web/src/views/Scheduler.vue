<template>
  <div>
    <div class="page-title">
      <h1>{{ t('pages.scheduler') }}</h1>
      <span class="meta">{{ t('pages.scheduler_meta') }}</span>
    </div>

    <div class="toolbar">
      <button class="primary" @click="load" :disabled="loading">{{ t('common.refresh') }}</button>
      <span class="meta" style="color:var(--sub)" v-if="data">{{ data.count }} {{ t('scheduler.timers') }}</span>
    </div>

    <div class="tile" style="margin-bottom:12px;border-left:3px solid var(--accent)">
      <p style="font-size:12px;color:var(--sub);line-height:1.55;margin:0">
        {{ t('scheduler.hint') }}
      </p>
    </div>

    <SkeletonLoader v-if="!loaded" variant="tiles" :rows="3" :span="4" :tile-height="34" style="margin-bottom:12px" />
    <div class="dash-grid" style="margin-bottom:12px" v-else-if="data">
      <div class="tile span-4">
        <h3>{{ t('scheduler.timers') }}</h3>
        <div class="v">{{ data.count }}</div>
      </div>
      <div class="tile span-4">
        <h3>{{ t('scheduler.interval_type') }}</h3>
        <div class="v">{{ intervalCount }}</div>
        <div class="sub">StartInterval</div>
      </div>
      <div class="tile span-4">
        <h3>{{ t('scheduler.calendar_type') }}</h3>
        <div class="v">{{ calendarCount }}</div>
        <div class="sub">StartCalendarInterval</div>
      </div>
    </div>

    <div class="toolbar">
      <input v-model="q" type="text" :placeholder="t('scheduler.filter_ph')" style="min-width:200px"  :aria-label="t('scheduler.filter_ph')"/>
    </div>

    <SkeletonLoader v-if="!loaded" :cols="5" :rows="6" />
    <div v-else class="table-wrap">
      <table class="dense">
        <thead>
          <tr>
            <th>{{ t('scheduler.label') }}</th>
            <th>{{ t('common.type') }}</th>
            <th>{{ t('scheduler.interval') }}</th>
            <th>{{ t('scheduler.calendar') }}</th>
            <th>{{ t('scheduler.program') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="row in filtered" :key="row.label">
            <td class="mono"><strong>{{ row.label }}</strong></td>
            <td>
              <span class="badge accent">{{ row.interval_sec ? t('scheduler.interval_type') : t('scheduler.calendar_type') }}</span>
            </td>
            <td>{{ row.interval_sec ? formatInterval(row.interval_sec) : '—' }}</td>
            <td class="mono" style="font-size:11px">{{ formatCal(row.calendar) }}</td>
            <td class="mono" style="max-width:420px;overflow:hidden;text-overflow:ellipsis;font-size:11px" :title="row.program">
              {{ row.program || '—' }}
            </td>
          </tr>
          <tr v-if="!filtered.length">
            <td colspan="5" style="color:var(--sub)">
              {{ loading ? t('common.loading') : t('common.none') }}
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <div class="toolbar" style="margin-top:12px">
      <router-link class="btn" to="/tools">{{ t('nav.tools') }}</router-link>
      <router-link class="btn" to="/maintenance">{{ t('nav.maintenance') }}</router-link>
    </div>
  </div>
</template>

<script setup>
import { computed, inject, onMounted, ref } from 'vue'
import { getScheduler } from '../api/client'
import { injectI18n } from '../i18n'
import SkeletonLoader from '../components/SkeletonLoader.vue'

const toast = inject('toast')
const { t } = injectI18n()
const data = ref(null)
const loading = ref(false)
const loaded = ref(false)
const q = ref('')

const intervalCount = computed(() =>
  (data.value?.timers || []).filter(t => t.interval_sec).length
)
const calendarCount = computed(() =>
  (data.value?.timers || []).filter(t => t.calendar && !t.interval_sec).length
    || (data.value?.timers || []).filter(t => t.calendar).length
)

const filtered = computed(() => {
  const list = data.value?.timers || []
  const qq = q.value.trim().toLowerCase()
  if (!qq) return list
  return list.filter(t =>
    (t.label || '').toLowerCase().includes(qq)
    || (t.program || '').toLowerCase().includes(qq)
  )
})

function formatInterval(sec) {
  if (sec >= 86400) return t('scheduler.unit_days', { n: Math.round(sec / 86400), sec })
  if (sec >= 3600) return t('scheduler.unit_hours', { n: Math.round(sec / 3600), sec })
  if (sec >= 60) return t('scheduler.unit_minutes', { n: Math.round(sec / 60), sec })
  return `${sec}s`
}
function formatCal(c) {
  if (!c) return '—'
  return typeof c === 'object' ? JSON.stringify(c) : String(c)
}

async function load() {
  loading.value = true
  try { data.value = await getScheduler() }
  catch (e) { toast('❌ ' + e.message) }
  loading.value = false
  loaded.value = true
}

onMounted(load)
</script>
