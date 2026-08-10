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
          <tr>
            <th>{{ t('backups.file') }}</th>
            <th>{{ t('backups.dir') }}</th>
            <th>{{ t('backups.size') }}</th>
            <th>{{ t('backups.time') }}</th>
            <th>{{ t('backups.restore') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="b in backups" :key="b.path">
            <td class="mono">{{ b.name }}</td>
            <td class="mono" style="font-size:11px">{{ b.dir }}</td>
            <td>{{ b.size_mb }} MB</td>
            <td>{{ fmt(b.mtime) }}</td>
            <!-- The command, not a button. None of these artefacts had a restore
                 path written down anywhere, and the TeslaMate dump is a pg_dump
                 custom-format archive whose ".sql.bak" name points at psql, which
                 cannot read it. Restoring overwrites live data, so it stays the
                 operator's deliberate act. -->
            <td v-if="b.restore" style="max-width:340px">
              <code
                class="mono restore-cmd"
                :title="t('backups.restore_copy')"
                @click="copyRestore(b.restore)"
              >{{ b.restore }}</code>
            </td>
            <td v-else style="color:var(--sub)">—</td>
          </tr>
          <tr v-if="!backups.length && !loadError">
            <td colspan="5" style="color:var(--sub)">{{ t('backups.empty') }}</td>
          </tr>
        </tbody>
      </table>
      <!-- The table is capped, so say so. Without this the older backups look
           deleted rather than merely unlisted, which is the opposite of what a
           backups page should tell you. -->
      <p v-if="hiddenCount" class="meta" style="margin-top:8px">
        {{ t('backups.truncated', { shown: backups.length, total }) }}
      </p>
    </div>
  </div>
</template>

<script setup>
import { computed, inject, onMounted, ref } from 'vue'
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
// The API caps the rows it returns but reports how many exist, so the page can
// tell "these are all of them" apart from "these are the newest 40".
const total = ref(0)
const hiddenCount = computed(() => Math.max(0, total.value - backups.value.length))

function fmt(t) {
  return t ? new Date(t * 1000).toLocaleString() : ''
}

async function copyRestore(command) {
  try {
    await navigator.clipboard.writeText(command)
    toast('✅ ' + t('common.copied'))
  } catch {
    toast('❌ ' + t('common.copy_failed'))
  }
}

async function refresh() {
  try {
    const d = await getBackups()
    backups.value = d.backups || []
    root.value = d.root || ''
    // A panel that predates `total` sends none; falling back to the row count
    // keeps the note hidden rather than claiming everything is truncated.
    total.value = d.total ?? (d.backups || []).length
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

<style scoped>
.restore-cmd {
  display: block;
  font-size: 10px;
  line-height: 1.45;
  color: var(--sub);
  cursor: pointer;
  word-break: break-all;
}
.restore-cmd:hover { color: var(--fg); }
</style>
