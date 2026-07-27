<template>
  <div>
    <div class="page-title">
      <h1>{{ t('alerts.title') }}</h1>
      <span class="meta">{{ t('alerts.meta') }}</span>
    </div>
    <div class="toolbar">
      <button class="primary" @click="refresh">{{ t('common.refresh') }}</button>
      <button @click="check">{{ t('alerts.check_now') }}</button>
      <button @click="test">{{ t('alerts.test_notify') }}</button>
      <router-link class="btn" to="/settings">{{ t('alerts.notify_settings') }}</router-link>
    </div>
    <div v-if="!alerts.length" class="placeholder">{{ t('alerts.empty') }}</div>
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

const toast = inject('toast')
const { t } = injectI18n()
const alerts = ref([])

function fmt(t) {
  return t ? new Date(t * 1000).toLocaleString() : ''
}

async function refresh() {
  try {
    const d = await getAlerts(100)
    alerts.value = d.alerts || []
  } catch (e) {
    toast('❌ ' + e.message)
  }
}

async function check() {
  try {
    const r = await forceAlertCheck()
    toast(t('alerts.inspect_done', { n: r.emitted?.length || 0 }))
    refresh()
  } catch (e) {
    toast('❌ ' + e.message)
  }
}

async function test() {
  try {
    const r = await testNotify()
    toast(r.ok ? '✅ ' + t('common.sent') : '❌ ' + (r.message || ''))
  } catch (e) {
    toast('❌ ' + e.message)
  }
}

onMounted(refresh)
</script>
