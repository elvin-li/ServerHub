<template>
  <div>
    <div class="page-title">
      <h1>{{ t('brew.title') }}</h1>
      <span class="meta">{{ t('brew.meta') }}</span>
    </div>
    <div class="toolbar">
      <button class="primary" @click="refresh" :disabled="busy">{{ t('common.refresh') }}</button>
      <input v-model="q" type="text" :placeholder="t('brew.filter_ph')"  :aria-label="t('brew.filter_ph')"/>
    </div>
    <LoadFailure v-if="loadError" :detail="loadError" :retry="refresh" :busy="busy" />
    <SkeletonLoader v-if="!loaded" :cols="5" :rows="6" />
    <div v-else class="table-wrap">
      <table class="dense fit-m">
        <thead>
          <tr>
            <th><span class="sr-only">{{ t('common.status_led') }}</span></th>
            <th>{{ t('brew.service') }}</th>
            <th>{{ t('common.status') }}</th>
            <th class="col-hide-m">{{ t('brew.user') }}</th>
            <th>{{ t('common.actions') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="s in filtered" :key="s.id">
            <td><span class="led" :class="s.state==='ok'?'on':(s.state==='warn'?'warn':'err')"></span></td>
            <td>
              <strong>{{ finiteText(s.name) }}</strong>
              <div v-if="finiteText(s.file, '')" class="mono" style="color:var(--sub);font-size:10px">{{ finiteText(s.file) }}</div>
              <div v-if="finiteText(s.user, '')" class="show-m sub">{{ finiteText(s.user) }}</div>
            </td>
            <td>
              <span class="badge" :class="s.state==='ok'?'ok':(s.state==='warn'?'warn':'')">{{ finiteText(s.status) }}</span>
            </td>
            <td class="mono col-hide-m">{{ finiteText(s.user) }}</td>
            <td class="ops">
              <button
                v-for="a in s.actions || []"
                :key="a"
                class="tiny"
                :class="{ primary: a==='start', danger: a==='stop', 'hide-m': a==='restart' }"
                :disabled="busy"
                @click="act(s, a)"
              >{{ finiteText(labels[a], '') || finiteText(a) }}</button>
            </td>
          </tr>
          <tr v-if="!filtered.length && !loadError">
            <td colspan="5" class="empty-row">{{ t('brew.empty') }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script setup>
import { computed, inject, onMounted, onUnmounted, ref } from 'vue'
import { brewAction, getBrewServices } from '../api/client'
import { injectI18n } from '../i18n'
import { finiteText } from '../lib/finite'
import SkeletonLoader from '../components/SkeletonLoader.vue'
import LoadFailure from '../components/LoadFailure.vue'

const toast = inject('toast')
const { t } = injectI18n()
const services = ref([])
const busy = ref(false)
const q = ref('')
// The worst false-empty case in the app: `brew services list` is allowed 20s,
// and for all of it this table asserted that no brew services were installed.
const loaded = ref(false)
const loadError = ref('')
let refreshTimer = null
let pageAlive = true
let loadGeneration = 0

function scheduleRefresh() {
  if (refreshTimer) clearTimeout(refreshTimer)
  refreshTimer = setTimeout(() => {
    refreshTimer = null
    if (!pageAlive) return
    void refresh()
  }, 800)
}

const labels = computed(() => ({
  start: t('services.act_start'),
  stop: t('services.act_stop'),
  restart: t('services.act_restart'),
}))

const filtered = computed(() => {
  const qq = q.value.trim().toLowerCase()
  if (!qq) return services.value
  return services.value.filter(s => (s.name || '').toLowerCase().includes(qq))
})

async function refresh() {
  const generation = ++loadGeneration
  try {
    const j = await getBrewServices()
    if (generation !== loadGeneration || !pageAlive) return
    services.value = j.services || []
    loadError.value = ''
  } catch (e) {
    if (generation !== loadGeneration || !pageAlive) return
    loadError.value = e.message || String(e)
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (generation === loadGeneration) loaded.value = true
  }
}

async function act(s, action) {
  if (action === 'stop' && !confirm(t('brew.confirm_stop', { name: finiteText(s.name) }))) return
  if (action === 'restart' && !confirm(t('brew.confirm_restart', { name: finiteText(s.name) }))) return
  const generation = loadGeneration
  busy.value = true
  try {
    const j = await brewAction(s.id, action)
    if (generation !== loadGeneration || !pageAlive) return
    toast(j.ok ? `✅ ${finiteText(s.name)}` : `❌ ${finiteText(j.message)}`)
    if (j.ok) scheduleRefresh()
  } catch (e) {
    if (generation !== loadGeneration || !pageAlive) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (pageAlive) busy.value = false
  }
}

onMounted(() => {
  pageAlive = true
  void refresh()
})
onUnmounted(() => {
  pageAlive = false
  loadGeneration += 1
  if (refreshTimer) clearTimeout(refreshTimer)
  refreshTimer = null
})
</script>
