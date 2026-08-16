<template>
  <div>
    <div class="page-title">
      <h1>{{ t('photoshub.title') }}</h1>
      <span class="meta">{{ t('photoshub.meta') }} · {{ data?.ts || '…' }}</span>
    </div>

    <div class="toolbar" style="flex-wrap:wrap;gap:8px">
      <button class="primary" @click="load" :disabled="loading">{{ t('common.refresh') }}</button>
      <template v-if="ready">
        <button @click="run('sync')" :disabled="busy">{{ t('photoshub.act_sync') }}</button>
        <button @click="run('originals')" :disabled="busy">{{ t('photoshub.act_originals') }}</button>
        <button @click="run('doctor')" :disabled="busy">{{ t('photoshub.act_doctor') }}</button>
        <button @click="run('external-backup')" :disabled="busy">{{ t('photoshub.act_ext_backup') }}</button>
        <button @click="run('delete-review')" :disabled="busy || data?.gates?.allow_delete_channel === false">
          {{ t('photoshub.act_delete_review') }}
        </button>
        <button @click="run('cleanup')" :disabled="busy || data?.gates?.allow_cleanup === false">
          {{ t('photoshub.act_cleanup') }}
        </button>
        <button @click="run('enable-delete')" :disabled="busy || !data?.gates?.originals_ready">
          {{ t('photoshub.act_enable_delete') }}
        </button>
        <button @click="run('configure-people')" :disabled="busy">{{ t('photoshub.act_people') }}</button>
        <a v-if="immichHref" class="btn-link" :href="immichHref" target="_blank" rel="noopener">Immich</a>
        <a v-if="panelHref" class="btn-link" :href="panelHref" target="_blank" rel="noopener">{{ t('photoshub.status_panel') }}</a>
      </template>
    </div>

    <LoadFailure v-if="loadError" :detail="loadError" :retry="load" :busy="loading" />
    <SkeletonLoader v-if="!loaded" variant="tiles" :rows="4" :span="3" :tile-height="40" style="margin-bottom:12px" />

    <div v-else-if="data && !data.photoshub_ok" class="card-block absent" data-test="photoshub-absent">
      <h2>{{ t('photoshub.absent_title') }}</h2>
      <p class="meta">{{ t('photoshub.absent_body') }}</p>
    </div>

    <template v-else-if="data">
      <div class="dash-grid" style="margin-bottom:14px">
        <div class="tile span-3">
          <h3>{{ t('photoshub.originals_pct') }}</h3>
          <div class="v" :style="{ color: originalsColor }">{{ originalsLabel }}</div>
          <div class="meta">{{ data.originals?.originals_present }}/{{ data.originals?.assets_active }}</div>
        </div>
        <div class="tile span-3">
          <h3>{{ t('photoshub.bridge') }}</h3>
          <div class="v" style="font-size:15px">{{ data.bridge?.mode || '—' }}</div>
          <div class="meta">{{ data.bridge?.last_success || t('photoshub.never') }} · {{ data.bridge?.exported_files ?? '—' }} files</div>
        </div>
        <div class="tile span-3">
          <h3>{{ t('photoshub.delete_gate') }}</h3>
          <div class="v" style="font-size:15px">{{ data.gates?.allow_delete_channel ? t('photoshub.enabled') : t('photoshub.frozen') }}</div>
          <div class="meta">{{ t('photoshub.pending') }} {{ pending?.count ?? data.delete_review?.pending_count ?? 0 }}</div>
        </div>
        <div class="tile span-3">
          <h3>{{ t('photoshub.ext_backup') }}</h3>
          <div class="v" style="font-size:15px">{{ data.external_backup?.last_success || t('photoshub.disk_absent') }}</div>
          <div class="meta">{{ data.external_backup?.ok === false ? t('common.issues') : '' }}</div>
        </div>
      </div>

      <div class="card-block" style="margin-bottom:14px" data-test="photoshub-pending">
        <div class="section-head">
          <h2>{{ t('photoshub.delete_title') }}</h2>
          <span class="meta">{{ t('photoshub.delete_hint') }}</span>
        </div>
        <div class="toolbar" style="margin-bottom:8px;flex-wrap:wrap">
          <button class="primary" @click="loadPending" :disabled="pendingLoading">{{ t('photoshub.refresh_pending') }}</button>
          <button @click="run('delete-review')" :disabled="busy || data?.gates?.allow_delete_channel === false">
            {{ t('photoshub.map_to_photos') }}
          </button>
          <button @click="removeSelected" :disabled="!selected.length || pendingLoading">
            {{ t('photoshub.remove_selected') }} ({{ selected.length }})
          </button>
        </div>
        <p class="meta" v-if="pending?.gated" style="color:var(--warn)">{{ t('photoshub.gated_warn') }}</p>
        <div class="table-wrap">
          <table class="dense fit-m">
            <thead>
              <tr>
                <th style="width:36px"><input type="checkbox" :checked="allSelected" @change="toggleAll" /></th>
                <th>{{ t('photoshub.filename') }}</th>
                <th class="col-hide-m">{{ t('photoshub.taken') }}</th>
                <th class="col-hide-m">{{ t('photoshub.type') }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="a in pending?.assets || []" :key="a.id">
                <td><input type="checkbox" :value="a.id" v-model="selected" /></td>
                <td class="mono" style="font-size:12px">
                  {{ a.originalFileName }}
                  <div v-if="a.localDateTime" class="show-m sub">{{ a.localDateTime }}</div>
                  <div v-if="a.type" class="show-m sub">{{ a.type }}</div>
                </td>
                <td class="meta col-hide-m">{{ a.localDateTime || '—' }}</td>
                <td class="col-hide-m">{{ a.type || '—' }}</td>
              </tr>
              <tr v-if="!(pending?.assets || []).length">
                <td colspan="4" class="meta">{{ pendingLoading ? t('common.scanning') : t('photoshub.no_pending') }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <div class="card-block" v-if="lastAction">
        <div class="section-head">
          <h2>{{ t('photoshub.last_action') }}: {{ lastAction.action }}</h2>
          <span class="badge" :class="lastAction.ok ? 'ok' : 'down'">{{ lastAction.ok ? t('common.ok') : t('common.fail') }}</span>
        </div>
        <pre class="mono logbox" aria-live="polite">{{ lastAction.stdout || lastAction.stderr || '—' }}</pre>
      </div>

      <div class="card-block" style="margin-top:14px">
        <div class="section-head">
          <h2>{{ t('photoshub.logs') }}</h2>
          <div class="tabs">
            <button v-for="n in logNames" :key="n" :class="{ active: logName===n }" :aria-pressed="logName===n" @click="switchLog(n)">{{ n }}</button>
          </div>
        </div>
        <pre class="mono logbox" aria-live="polite">{{ (logData?.lines || []).join('\n') || '—' }}</pre>
      </div>
    </template>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import {
  getPhotosHubStatus,
  getPhotosHubPending,
  postPhotosHubAction,
  postPhotosHubPendingRemove,
  getPhotosHubLogs,
} from '../api/client'
import { injectI18n } from '../i18n'
import LoadFailure from '../components/LoadFailure.vue'
import SkeletonLoader from '../components/SkeletonLoader.vue'

const { t } = injectI18n()
const data = ref(null)
const pending = ref(null)
const loaded = ref(false)
const loading = ref(false)
const pendingLoading = ref(false)
const busy = ref(false)
const loadError = ref('')
const selected = ref([])
const lastAction = ref(null)
const logName = ref('bridge')
const logData = ref(null)
const logNames = ['bridge', 'delete', 'cleanup', 'external', 'errors']

const ready = computed(() => Boolean(data.value?.photoshub_ok))
const originalsLabel = computed(() => {
  const p = data.value?.originals?.local_original_pct
  return p == null ? '—' : `${p}%`
})
const originalsColor = computed(() => {
  const p = data.value?.originals?.local_original_pct ?? 0
  if (p >= 99) return 'var(--ok)'
  if (p >= 50) return 'var(--warn)'
  return 'var(--down)'
})
const allSelected = computed(() => {
  const assets = pending.value?.assets || []
  return assets.length > 0 && selected.value.length === assets.length
})
const immichHref = computed(() => safeHttpUrl(data.value?.links?.immich))
const panelHref = computed(() => safeHttpUrl(data.value?.links?.panel))

function safeHttpUrl(raw) {
  const text = String(raw || '').trim()
  try {
    const url = new URL(text)
    if (url.protocol === 'http:' || url.protocol === 'https:') return text
  } catch {
    /* ignore */
  }
  return ''
}

async function load() {
  loading.value = true
  loadError.value = ''
  try {
    data.value = await getPhotosHubStatus()
    loaded.value = true
    if (data.value?.photoshub_ok) {
      await Promise.all([loadPending(), switchLog(logName.value)])
    } else {
      pending.value = null
      logData.value = null
    }
  } catch (e) {
    loadError.value = String(e?.message || e)
  } finally {
    loading.value = false
  }
}

async function loadPending() {
  if (!data.value?.photoshub_ok) return
  pendingLoading.value = true
  try {
    pending.value = await getPhotosHubPending()
    selected.value = []
  } catch (e) {
    loadError.value = String(e?.message || e)
  } finally {
    pendingLoading.value = false
  }
}

async function run(action) {
  if (action === 'enable-delete' && !confirm(t('photoshub.confirm_enable_delete'))) return
  if (action === 'cleanup' && !confirm(t('photoshub.confirm_cleanup'))) return
  busy.value = true
  try {
    lastAction.value = await postPhotosHubAction(action)
    data.value = lastAction.value.status_after || (await getPhotosHubStatus())
    if (action === 'delete-review') await loadPending()
  } catch (e) {
    lastAction.value = { action, ok: false, stderr: String(e?.message || e) }
  } finally {
    busy.value = false
  }
}

async function removeSelected() {
  if (!selected.value.length) return
  if (!confirm(t('photoshub.confirm_remove'))) return
  pendingLoading.value = true
  try {
    await postPhotosHubPendingRemove(selected.value)
    await loadPending()
  } catch (e) {
    loadError.value = String(e?.message || e)
  } finally {
    pendingLoading.value = false
  }
}

function toggleAll(ev) {
  const on = ev.target.checked
  selected.value = on ? (pending.value?.assets || []).map(a => a.id) : []
}

async function switchLog(n) {
  if (!data.value?.photoshub_ok) return
  logName.value = n
  try {
    logData.value = await getPhotosHubLogs(n)
  } catch {
    logData.value = { lines: [] }
  }
}

onMounted(load)
</script>

<style scoped>
.card-block {
  background: var(--card, var(--panel, #fff));
  border-radius: 12px;
  padding: 14px 16px;
  border: 1px solid var(--border, rgba(0,0,0,.06));
}
.absent h2 { margin: 0 0 8px; font-size: 1.1rem; }
.section-head {
  display: flex;
  align-items: baseline;
  gap: 10px;
  margin-bottom: 10px;
}
.section-head h2 {
  margin: 0;
  font-size: 1.05rem;
}
.logbox {
  max-height: 280px;
  overflow: auto;
  font-size: 11px;
  background: rgba(0,0,0,.04);
  padding: 10px;
  border-radius: 8px;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}
.btn-link {
  display: inline-flex;
  align-items: center;
  padding: 6px 10px;
  border-radius: 8px;
  border: 1px solid var(--border, #ddd);
  text-decoration: none;
  color: inherit;
  font-size: 13px;
}
@media (max-width: 640px) {
  .section-head { flex-wrap: wrap; }
}
</style>
