<template>
  <div>
    <div class="page-title">
      <h1>{{ t('alerts.title') }}</h1>
      <span class="meta">{{ t('alerts.meta') }}</span>
    </div>
    <div class="toolbar">
      <button class="primary" :disabled="busy" @click="refresh">{{ t('common.refresh') }}</button>
      <button :disabled="busy" @click="check">{{ t('alerts.check_now') }}</button>
      <button :disabled="busy" @click="test">{{ t('alerts.test_notify') }}</button>
      <router-link class="btn" to="/settings">{{ t('alerts.notify_settings') }}</router-link>
    </div>
    <SkeletonLoader v-if="!loaded" :cols="5" :rows="6" />
    <div v-else-if="!alerts.length" class="placeholder">{{ t('alerts.empty') }}</div>
    <div v-else class="table-wrap">
      <table class="dense">
        <thead>
          <tr><th>{{ t('alerts.time') }}</th><th>{{ t('alerts.level') }}</th><th>{{ t('alerts.service') }}</th><th>{{ t('alerts.event') }}</th><th>{{ t('alerts.detail') }}</th></tr>
        </thead>
        <tbody>
          <tr v-for="(a,i) in alerts" :key="i">
            <td class="mono">{{ fmt(a.t) }}</td>
            <td><span class="badge" :class="a.level === 'ok' ? 'ok' : a.level">{{ a.level }}</span></td>
            <td><strong>{{ a.name }}</strong></td>
            <td>{{ a.event }}</td>
            <td style="max-width:320px;font-size:11px">{{ a.message }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script setup>
import { inject, onMounted, ref } from 'vue'
import { forceAlertCheck, getAlerts, testNotify } from '../api/client'
import { injectI18n } from '../i18n'
import SkeletonLoader from '../components/SkeletonLoader.vue'

const toast = inject('toast')
const { t } = injectI18n()
const alerts = ref([])
const busy = ref(false)
// "No alerts" is the good news on this page, so showing it before the first
// response lands is the most misleading possible placeholder.
const loaded = ref(false)

function fmt(t) {
  return t ? new Date(t * 1000).toLocaleString() : ''
}

async function refresh() {
  if (busy.value) return
  busy.value = true
  try {
    const d = await getAlerts(100)
    alerts.value = d.alerts || []
  } catch (e) {
    toast('❌ ' + e.message)
  } finally {
    busy.value = false
    loaded.value = true
  }
}

async function check() {
  if (busy.value) return
  busy.value = true
  try {
    const r = await forceAlertCheck()
    toast(t('alerts.inspect_done', { n: r.emitted?.length || 0 }))
    const d = await getAlerts(100)
    alerts.value = d.alerts || []
  } catch (e) {
    toast('❌ ' + e.message)
  } finally {
    busy.value = false
  }
}

async function test() {
  if (busy.value) return
  busy.value = true
  try {
    const r = await testNotify()
    toast(r.ok ? '✅ ' + t('common.sent') : '❌ ' + (r.message || ''))
  } catch (e) {
    toast('❌ ' + e.message)
  } finally {
    busy.value = false
  }
}

onMounted(refresh)
</script>
