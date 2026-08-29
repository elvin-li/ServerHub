<template>
  <div>
    <div class="page-title">
      <h1>{{ t('brew.title') }}</h1>
      <span class="meta">{{ t('brew.meta') }}</span>
    </div>
    <div class="toolbar">
      <button class="primary" @click="refresh" :disabled="busy">{{ t('common.refresh') }}</button>
      <input v-model="q" type="text" :placeholder="t('brew.filter_ph')"  :aria-label="t('brew.filter_ph')"/>
      <!-- role=status: the count is the only feedback the filter box gives,
           and it changed silently for a screen reader. Same pattern as the
           Services filter count. -->
      <span class="meta-count" role="status">{{ asArray(filtered).length }} / {{ asArray(services).length }}</span>
      <!-- role=status: brew actions run for seconds (brew services itself is
           slow enough that the list call gets 20s) and every button greys out
           for the duration; a sighted user watches the disabled toolbar, a
           screen-reader user otherwise hears nothing between the click and
           the finish toast. Same shape as the PhotosHub/Shares busy notes. -->
      <span v-if="busy" class="meta" role="status" aria-live="polite" data-test="brew-busy">{{ busyNote }}</span>
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
          <tr v-for="s in asArray(filtered)" :key="finiteText(asRecord(s).id)">
            <!-- aria-hidden: the LED repeats the Status badge's started/stopped
                 text in colour only (same as the Health check LED). -->
            <td><span class="led" :class="asRecord(s).state==='ok'?'on':(asRecord(s).state==='warn'?'warn':'err')" aria-hidden="true"></span></td>
            <td>
              <strong>{{ finiteText(asRecord(s).name) }}</strong>
              <div v-if="finiteText(asRecord(s).file, '')" class="mono" style="color:var(--sub);font-size:10px">{{ finiteText(asRecord(s).file) }}</div>
              <div v-if="finiteText(asRecord(s).user, '')" class="show-m sub">{{ finiteText(asRecord(s).user) }}</div>
            </td>
            <td>
              <span class="badge" :class="asRecord(s).state==='ok'?'ok':(asRecord(s).state==='warn'?'warn':'')">{{ finiteText(asRecord(s).status) }}</span>
            </td>
            <td class="mono col-hide-m">{{ finiteText(asRecord(s).user) }}</td>
            <td class="ops">
              <button
                v-for="a in asArray(asRecord(s).actions)"
                :key="finiteText(a)"
                class="tiny"
                :class="{ primary: a==='start', danger: a==='stop', 'hide-m': a==='restart' }"
                :disabled="busy"
                @click="act(s, a)"
              >{{ finiteText(labels[a], '') || finiteText(a) }}</button>
            </td>
          </tr>
          <tr v-if="!asArray(filtered).length && !loadError">
            <!-- A filter that matched nothing is not "No Homebrew services
                 found": that claim beside a non-empty count misreports the
                 host (same split as the Network ports and Tools process
                 tables). -->
            <td colspan="5" class="empty-row">{{ q.trim() ? t('common.no_match') : t('brew.empty') }}</td>
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
import { asArray, asRecord, finiteText } from '../lib/finite'
import SkeletonLoader from '../components/SkeletonLoader.vue'
import LoadFailure from '../components/LoadFailure.vue'

const toast = inject('toast')
const { t } = injectI18n()
const services = ref([])
const busy = ref(false)
// What the busy note announces: set before `busy` flips on, cleared with it.
const busyAction = ref('')
const busyName = ref('')
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

const busyNote = computed(() => t('brew.action_running', {
  action: finiteText(labels.value[busyAction.value], '') || finiteText(busyAction.value),
  name: busyName.value,
}))

const filtered = computed(() => {
  const list = asArray(services.value).map((row) => asRecord(row))
  const qq = q.value.trim().toLowerCase()
  if (!qq) return list
  return list.filter(s => finiteText(s.name, '').toLowerCase().includes(qq))
})

async function refresh() {
  const generation = ++loadGeneration
  try {
    const j = asRecord(await getBrewServices())
    if (generation !== loadGeneration || !pageAlive) return
    services.value = asArray(j.services).map((row) => asRecord(row))
    loadError.value = ''
  } catch (e) {
    if (generation !== loadGeneration || !pageAlive) return
    loadError.value = finiteText(e.message || String(e), '')
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (generation === loadGeneration) loaded.value = true
  }
}

async function act(s, action) {
  const row = asRecord(s)
  if (action === 'stop' && !confirm(t('brew.confirm_stop', { name: finiteText(row.name) }))) return
  if (action === 'restart' && !confirm(t('brew.confirm_restart', { name: finiteText(row.name) }))) return
  const generation = loadGeneration
  busyAction.value = action
  busyName.value = finiteText(row.name)
  busy.value = true
  try {
    const j = asRecord(await brewAction(row.id, action))
    if (generation !== loadGeneration || !pageAlive) return
    toast(j.ok ? `✅ ${finiteText(row.name)}` : `❌ ${finiteText(j.message)}`)
    if (j.ok) scheduleRefresh()
  } catch (e) {
    if (generation !== loadGeneration || !pageAlive) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (pageAlive) {
      busy.value = false
      busyAction.value = ''
      busyName.value = ''
    }
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
