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
    <LoadFailure v-if="loadError" :detail="loadError" :retry="refresh" :busy="busy" />
    <SkeletonLoader v-if="!loaded" :cols="5" :rows="6" />
    <div v-else-if="!alerts.length && !loadError" class="placeholder">{{ t('alerts.empty') }}</div>
    <div v-else class="table-wrap">
      <table class="dense">
        <thead>
          <tr><th>{{ t('alerts.time') }}</th><th>{{ t('alerts.level') }}</th><th>{{ t('alerts.service') }}</th><th>{{ t('alerts.event') }}</th><th>{{ t('alerts.detail') }}</th></tr>
        </thead>
        <tbody>
          <tr v-for="(a,i) in alerts" :key="i">
            <td class="mono">{{ fmt(a.t) }}</td>
            <!-- Keyed on `level` alone, deliberately: a disk that is dying has to
                 read as urgently as a service that is down, so `smart` + `down`
                 lands on the same red .badge.down as a service down. The kind tag
                 below says what broke without competing with that. -->
            <td><span class="badge" :class="a.level === 'ok' ? 'ok' : a.level">{{ a.level }}</span></td>
            <td>
              <span v-if="kindLabel(a)" class="badge" style="margin-right:4px">{{ kindLabel(a) }}</span>
              <strong>{{ a.name }}</strong>
            </td>
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
import LoadFailure from '../components/LoadFailure.vue'

const toast = inject('toast')
const { t } = injectI18n()
const alerts = ref([])
const busy = ref(false)
// "No alerts" is the good news on this page, so showing it before the first
// response lands is the most misleading possible placeholder.
const loaded = ref(false)
const loadError = ref('')

function fmt(t) {
  return t ? new Date(t * 1000).toLocaleString() : ''
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

async function refresh() {
  if (busy.value) return
  busy.value = true
  try {
    const d = await getAlerts(100)
    alerts.value = d.alerts || []
    loadError.value = ''
  } catch (e) {
    loadError.value = e.message || String(e)
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
