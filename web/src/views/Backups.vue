<template>
  <div>
    <div class="page-title">
      <h1>{{ t('backups.title') }}</h1>
      <span class="meta">{{ root || 'Services/backups' }}</span>
    </div>
    <div class="toolbar">
      <button class="primary" :disabled="busy" @click="doPg">{{ t('backups.pg') }}</button>
      <button :disabled="busy" @click="doCfg">{{ t('backups.cfg') }}</button>
      <button :disabled="busy" @click="refresh">{{ t('backups.refresh_list') }}</button>
    </div>
    <div v-if="msg" class="card" style="margin-bottom:12px;white-space:pre-wrap;font-size:13px">{{ msg }}</div>
    <LoadFailure v-if="loadError" :detail="loadError" :retry="refresh" :busy="busy" />
    <SkeletonLoader v-if="!loaded" :cols="4" :rows="5" />
    <div v-else class="table-wrap">
      <table class="dense">
        <thead>
          <tr><th>{{ t('backups.file') }}</th><th>{{ t('backups.dir') }}</th><th>{{ t('backups.size') }}</th><th>{{ t('backups.time') }}</th></tr>
        </thead>
        <tbody>
          <tr v-for="b in backups" :key="b.path">
            <td class="mono">{{ b.name }}</td>
            <td class="mono" style="font-size:11px">{{ b.dir }}</td>
            <td>{{ b.size_mb }} MB</td>
            <td>{{ fmt(b.mtime) }}</td>
          </tr>
          <tr v-if="!backups.length && !loadError">
            <td colspan="4" style="color:var(--sub)">{{ t('backups.empty') }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script setup>
import { inject, onMounted, ref } from 'vue'
import { backupConfigs, backupPostgres, getBackups } from '../api/client'
import { injectI18n } from '../i18n'
import SkeletonLoader from '../components/SkeletonLoader.vue'
import LoadFailure from '../components/LoadFailure.vue'

const toast = inject('toast')
const { t } = injectI18n()
const backups = ref([])
const root = ref('')
const busy = ref(false)
const msg = ref('')
// Separates "listing not fetched yet" from "no backups exist", which the empty
// row could not express: a fresh page claimed there were no backups at all.
const loaded = ref(false)
const loadError = ref('')

function fmt(t) {
  return t ? new Date(t * 1000).toLocaleString() : ''
}

async function refresh() {
  try {
    const d = await getBackups()
    backups.value = d.backups || []
    root.value = d.root || ''
    loadError.value = ''
  } catch (e) {
    loadError.value = e.message || String(e)
    toast('❌ ' + e.message)
  } finally {
    loaded.value = true
  }
}

async function doPg() {
  if (!confirm(t('backups.confirm_pg'))) return
  busy.value = true
  msg.value = t('backups.backing_up')
  try {
    const r = await backupPostgres()
    msg.value = (r.ok ? '✅ ' : '❌ ') + (r.message || '') + (r.path ? `\n${r.path} (${r.size_mb} MB)` : '')
    toast(r.ok ? '✅ ' + t('backups.pg_done') : '❌ ' + t('backups.pg_failed'))
    if (r.ok) await refresh()
  } catch (e) {
    toast('❌ ' + e.message)
    msg.value = String(e.message)
  } finally {
    busy.value = false
  }
}

async function doCfg() {
  busy.value = true
  msg.value = t('backups.packing')
  try {
    const r = await backupConfigs()
    msg.value = (r.ok ? '✅ ' : '❌ ') + (r.message || '') + (r.path ? `\n${r.path}` : '')
    toast(r.ok ? '✅ ' + t('backups.cfg_done') : '❌ ' + t('common.failed'))
    if (r.ok) await refresh()
  } catch (e) {
    toast('❌ ' + e.message)
    msg.value = String(e.message)
  } finally {
    busy.value = false
  }
}

onMounted(refresh)
</script>
