<template>
  <div>
    <div class="page-title">
      <h1>{{ t('alerts.title') }}</h1>
      <span class="meta">{{ t('alerts.meta') }}</span>
    </div>
    <div class="toolbar">
      <button class="primary" :disabled="busy" @click="refresh(true)">{{ t('common.refresh') }}</button>
      <button :disabled="busy" @click="check">{{ t('alerts.check_now') }}</button>
      <button class="hide-m" :disabled="busy" @click="test">{{ t('alerts.test_notify') }}</button>
      <router-link class="btn" to="/settings">{{ t('alerts.notify_settings') }}</router-link>
    </div>
    <LoadFailure v-if="loadError" :detail="loadError" :retry="refresh" :busy="busy" />
    <SkeletonLoader v-if="!loaded" :cols="5" :rows="6" />
    <div v-else-if="!asArray(alerts).length && !loadError" class="placeholder">{{ t('alerts.empty') }}</div>
    <!-- Rows are the gate, not "else": with nothing fetched and the read failed,
         the else-branch rendered the level tabs and a table whose only row said
         "no alerts match this filter" — a filter excuse for an API failure. The
         banner above is the whole story; stale rows still render when a re-poll
         fails, which is the LoadFailure contract. -->
    <template v-else-if="asArray(alerts).length">
    <!-- Same level tabs the Health page uses: with 100 mixed rows, finding the
         one that is red should not require scanning past every resolved ok. -->
    <div class="tabs">
      <button :class="{ active: filter==='all' }" :aria-pressed="filter === 'all'" @click="filter='all'">{{ t('common.all') }}</button>
      <button :class="{ active: filter==='issues' }" :aria-pressed="filter === 'issues'" @click="filter='issues'">{{ t('alerts.only_issues') }}</button>
      <button :class="{ active: filter==='down' }" :aria-pressed="filter === 'down'" @click="filter='down'">{{ t('alerts.only_down') }}</button>
      <button :class="{ active: filter==='warn' }" :aria-pressed="filter === 'warn'" @click="filter='warn'">{{ t('alerts.only_warn') }}</button>
      <!-- The tabs shrink the table below; announce the result like the text
           filters do (filterCounts.test.js) — a sighted user watches rows
           disappear, a screen-reader user otherwise hears nothing at all. -->
      <span class="meta-count" role="status" style="margin-left:auto;align-self:center">
        {{ asArray(filtered).length }} / {{ asArray(alerts).length }}
      </span>
    </div>
    <div class="table-wrap">
      <table class="dense fit-m">
        <thead>
          <tr>
            <th class="col-hide-m">{{ t('alerts.time') }}</th>
            <th>{{ t('alerts.level') }}</th>
            <th>{{ t('alerts.service') }}</th>
            <th class="col-hide-m">{{ t('alerts.event') }}</th>
            <th class="col-hide-m">{{ t('alerts.detail') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="(a,i) in asArray(filtered)" :key="i">
            <td class="mono col-hide-m">{{ fmt(a.t) }}</td>
            <!-- Keyed on `level` alone, deliberately: a disk that is dying has to
                 read as urgently as a service that is down, so `smart` + `down`
                 lands on the same red .badge.down as a service down. The kind tag
                 below says what broke without competing with that. -->
            <td><span class="badge" :class="a.level === 'ok' ? 'ok' : a.level">{{ finiteText(a.level) }}</span></td>
            <td>
              <span v-if="kindLabel(a)" class="badge" style="margin-right:4px">{{ kindLabel(a) }}</span>
              <strong>{{ finiteText(a.name) }}</strong>
              <div class="show-m sub">{{ fmt(a.t) }}</div>
              <div v-if="a.event" class="show-m sub">{{ finiteText(a.event) }}</div>
              <div v-if="a.message" class="show-m sub">{{ finiteText(a.message) }}</div>
            </td>
            <td class="col-hide-m">{{ finiteText(a.event) }}</td>
            <td class="col-hide-m" style="max-width:320px;font-size:11px">{{ finiteText(a.message) }}</td>
          </tr>
          <tr v-if="!asArray(filtered).length">
            <td colspan="5" class="empty-row">{{ t('alerts.filter_empty') }}</td>
          </tr>
        </tbody>
      </table>
    </div>
    </template>
  </div>
</template>

<script setup>
import { computed, inject, onMounted, onUnmounted, ref } from 'vue'
import { forceAlertCheck, getAlerts, testNotify } from '../api/client'
import { injectI18n } from '../i18n'
import { asArray, finiteText, fmtTs } from '../lib/finite'
import { startVisibleInterval } from '../lib/poll'
import SkeletonLoader from '../components/SkeletonLoader.vue'
import LoadFailure from '../components/LoadFailure.vue'

const toast = inject('toast')
const { t } = injectI18n()
const alerts = ref([])
const busy = ref(false)
// "No alerts" is the good news on this page, so showing it before the first
// response lands is the most misleading possible placeholder.
const loaded = ref(false)
const loadError = ref('')
// Level tabs, mirroring the Health page: all | issues (anything not ok) |
// down | warn.  'ok' rows are resolutions, useful context but never urgent.
const filter = ref('all')
const filtered = computed(() => {
  const rows = asArray(alerts.value)
  if (filter.value === 'issues') return rows.filter((a) => a?.level !== 'ok')
  if (filter.value === 'down' || filter.value === 'warn') {
    return rows.filter((a) => a?.level === filter.value)
  }
  return rows
})
let pageAlive = true
let loadGeneration = 0

function fmt(t) {
  return fmtTs(t, '')
}

//: Alert `kind` -> the i18n leaf naming what the row is about.  The list mixes
//: sources -- services, resource usage and SMART disk health all land in the same
//: table -- and `name` alone does not separate them, so a disk problem read as
//: just another service going down.  Unlisted kinds render no tag rather than a
//: raw backend token.
const KIND_LABELS = { service: 'kind_service', resource: 'kind_resource', smart: 'kind_smart' }

function kindLabel(a) {
  const leaf = KIND_LABELS[a?.kind]
  return leaf ? t(`alerts.${leaf}`) : ''
}

async function refresh(manual = false) {
  if (busy.value) return
  const generation = ++loadGeneration
  busy.value = true
  try {
    const d = await getAlerts(100)
    if (generation !== loadGeneration || !pageAlive) return
    alerts.value = asArray(d.alerts)
    loadError.value = ''
  } catch (e) {
    if (generation !== loadGeneration || !pageAlive) return false
    loadError.value = e.message || String(e)
    // A background tick that fails must not re-toast every interval while the
    // panel is unreachable — LoadFailure already marks the state on screen.
    // The `false` return is lib/poll's opt-in sentinel for backoff.
    if (manual) toast('❌ ' + finiteText(e.message))
    return false
  } finally {
    if (generation === loadGeneration && pageAlive) {
      busy.value = false
      loaded.value = true
    }
  }
}

async function check() {
  if (busy.value) return
  const generation = ++loadGeneration
  busy.value = true
  try {
    const r = await forceAlertCheck()
    if (generation !== loadGeneration || !pageAlive) return
    toast(t('alerts.inspect_done', { n: asArray(r.emitted).length }))
    const d = await getAlerts(100)
    if (generation !== loadGeneration || !pageAlive) return
    alerts.value = asArray(d.alerts)
  } catch (e) {
    if (generation !== loadGeneration || !pageAlive) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (generation === loadGeneration && pageAlive) busy.value = false
  }
}

async function test() {
  if (busy.value) return
  const generation = ++loadGeneration
  busy.value = true
  try {
    const r = await testNotify()
    if (generation !== loadGeneration || !pageAlive) return
    toast(r.ok ? '✅ ' + t('common.sent') : '❌ ' + finiteText(r.message, ''))
  } catch (e) {
    if (generation !== loadGeneration || !pageAlive) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (generation === loadGeneration && pageAlive) busy.value = false
  }
}

let stopPoll = null

onMounted(() => {
  pageAlive = true
  void refresh(true)
  // Alert state changes on the server's own check cadence; without a poll the
  // page showed whatever was true when it was opened until a manual refresh.
  // Visibility-aware like every other polling page, silent on background
  // failures, with lib/poll backoff while the panel is unreachable.
  stopPoll = startVisibleInterval(refresh, 30000)
})
onUnmounted(() => {
  pageAlive = false
  loadGeneration += 1
  if (typeof stopPoll === 'function') stopPoll()
  stopPoll = null
})
</script>
