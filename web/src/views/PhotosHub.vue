<template>
  <div>
    <div class="page-title">
      <h1>{{ t('photoshub.title') }}</h1>
      <span class="meta">{{ t('photoshub.meta') }} · {{ finiteText(data?.ts, '…') }}</span>
    </div>

    <div v-if="ready" class="tabs">
      <button
        v-for="tb in tabs"
        :key="tb.id"
        :class="{ active: tab === tb.id }"
        :aria-pressed="tab === tb.id"
        @click="switchTab(tb.id)"
      >{{ tabLabel(tb) }}</button>
    </div>

    <div class="toolbar" style="flex-wrap:wrap;gap:8px">
      <button class="primary" @click="load" :disabled="loading">{{ t('common.refresh') }}</button>
      <template v-if="ready && tab === 'overview'">
        <button @click="run('sync')" :disabled="busy">{{ t('photoshub.act_sync') }}</button>
        <button @click="run('originals')" :disabled="busy">{{ t('photoshub.act_originals') }}</button>
        <button @click="run('doctor')" :disabled="busy">{{ t('photoshub.act_doctor') }}</button>
        <a v-if="immichHref" class="btn-link" :href="finiteText(immichHref, '')" target="_blank" rel="noopener">Immich</a>
        <a v-if="panelHref" class="btn-link" :href="finiteText(panelHref, '')" target="_blank" rel="noopener">{{ t('photoshub.status_panel') }}</a>
      </template>
      <span v-if="busy" class="meta">{{ t('photoshub.action_running', { action: actionLabel(busyAction) }) }}</span>
    </div>

    <LoadFailure v-if="loadError" :detail="loadError" :retry="load" :busy="loading" />
    <SkeletonLoader v-if="!loaded" variant="tiles" :rows="4" :span="3" :tile-height="40" style="margin-bottom:12px" />

    <div v-else-if="data && !data.photoshub_ok" class="card-block absent" data-test="photoshub-absent">
      <h2>{{ t('photoshub.absent_title') }}</h2>
      <p class="meta">{{ t('photoshub.absent_body') }}</p>
    </div>

    <template v-else-if="data">
      <div v-if="lastAction && tab === 'overview'" class="card-block action-banner" data-test="photoshub-last-action">
        <div class="section-head" style="margin-bottom:0">
          <h2>{{ t('photoshub.last_action') }}: {{ actionLabel(lastAction.action) }}</h2>
          <span class="badge" :class="lastAction.ok ? 'ok' : 'down'">{{ lastAction.ok ? t('common.ok') : t('common.fail') }}</span>
          <button class="tiny" type="button" @click="switchTab('logs')">{{ t('photoshub.view_output') }}</button>
        </div>
      </div>

      <template v-if="tab === 'overview'">
        <div class="dash-grid" style="margin-bottom:14px">
          <div class="tile span-3">
            <h3>{{ t('photoshub.originals_pct') }}</h3>
            <div class="v" :style="{ color: originalsColor }">{{ originalsLabel }}</div>
            <div class="meta">{{ finiteN(data.originals?.originals_present) }}/{{ finiteN(data.originals?.assets_active) }}</div>
          </div>
          <div class="tile span-3">
            <h3>{{ t('photoshub.bridge') }}</h3>
            <div class="v" style="font-size:15px">{{ finiteText(data.bridge?.mode) }}</div>
            <div class="meta">{{ finiteText(data.bridge?.last_success, t('photoshub.never')) }} · {{ t('photoshub.files_n', { n: finiteN(data.bridge?.exported_files) }) }}</div>
          </div>
          <div class="tile span-3">
            <h3>{{ t('photoshub.delete_gate') }}</h3>
            <div class="v" style="font-size:15px">{{ data.gates?.allow_delete_channel ? t('photoshub.enabled') : t('photoshub.frozen') }}</div>
            <div class="meta">{{ t('photoshub.pending') }} {{ finiteN(pendingCount) }}</div>
          </div>
          <div class="tile span-3">
            <h3>{{ t('photoshub.people_title') }}</h3>
            <div class="v" style="font-size:15px">{{ peopleLabel }}</div>
            <div class="meta">{{ peopleMeta }}</div>
          </div>
          <div class="tile span-3">
            <h3>{{ t('photoshub.library_backup') }}</h3>
            <div class="v" style="font-size:15px">{{ finiteText(data.backup?.last_success, t('photoshub.never')) }}</div>
            <div v-if="data.backup?.size_human" class="meta">{{ finiteText(data.backup.size_human) }}</div>
            <div v-else-if="data.backup?.ok === false" class="meta">{{ t('common.issues') }}</div>
          </div>
          <div class="tile span-3">
            <h3>{{ t('photoshub.ext_backup') }}</h3>
            <div class="v" style="font-size:15px">{{ finiteText(data.external_backup?.last_success, t('photoshub.disk_absent')) }}</div>
            <div class="meta">{{ externalIssue }}</div>
          </div>
        </div>
      </template>

      <div v-else-if="tab === 'pending'" class="card-block" style="margin-bottom:14px" data-test="photoshub-pending">
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
        <p v-if="pendingError" class="meta" data-test="photoshub-pending-error" style="color:var(--down-text)" role="alert">{{ finiteText(pendingError) }}</p>
        <p class="meta" v-if="pending?.gated || data?.gates?.allow_delete_channel === false" style="color:var(--warn-text)">
          {{ t('photoshub.gated_warn') }}
        </p>
        <p v-if="(pending?.assets || []).length" class="meta select-all">
          <label>
            <input type="checkbox" :checked="allSelected" @change="toggleAll" />
            {{ t('photoshub.select_all') }}
          </label>
        </p>
        <p v-if="!pendingError && !(pending?.assets || []).length" class="meta" data-test="photoshub-pending-empty">
          {{ pendingLoading ? t('common.scanning') : t('photoshub.no_pending') }}
        </p>
        <div v-else class="review-grid" data-test="photoshub-pending-grid">
          <label
            v-for="a in pending?.assets || []"
            :key="a.id"
            class="review-tile"
            :class="{ picked: selected.includes(a.id) }"
          >
            <input
              type="checkbox"
              :value="a.id"
              v-model="selected"
              :aria-label="finiteText(a.originalFileName, '') || finiteText(a.id)"
            />
            <img
              v-if="!thumbFailed[a.id]"
              :src="photosHubThumbUrl(a.id)"
              :alt="finiteText(a.originalFileName, '')"
              loading="lazy"
              decoding="async"
              @error="thumbFailed[a.id] = true"
            />
            <span v-else class="review-noimg meta">{{ finiteText(a.type, '') || t('photoshub.no_preview') }}</span>
            <span class="review-cap">
              <span class="mono name">{{ finiteText(a.originalFileName) }}</span>
              <span v-if="a.localDateTime" class="sub">{{ finiteText(a.localDateTime) }}</span>
            </span>
          </label>
        </div>
      </div>

      <div v-else-if="tab === 'settings'" class="settings-grid" data-test="photoshub-settings">
        <!-- role="alert": the config read fails after the tab is already on
             screen, and unlike pendingError below this one shipped silent. -->
        <p v-if="settingsError" class="meta" data-test="photoshub-settings-error" style="grid-column:1/-1;color:var(--down-text)" role="alert">{{ finiteText(settingsError) }}</p>
        <div class="card-block">
          <div class="section-head">
            <h2>{{ t('photoshub.people_title') }}</h2>
            <span class="meta">{{ t('photoshub.people_hint') }}</span>
          </div>
          <!-- No aria-label on these: each input already has a for/id label
               carrying "child · field", and the shorter aria-label overrode it
               — both birthday inputs were announced identically as "birthday"
               with nothing saying whose. -->
          <div class="form-grid">
            <label for="ph-yuanbao-name">{{ t('photoshub.child_yuanbao') }} · {{ t('photoshub.person_name') }}</label>
            <input id="ph-yuanbao-name" v-model="form.yuanbao_name" type="text" maxlength="40" />
            <label for="ph-yuanbao-bday">{{ t('photoshub.child_yuanbao') }} · {{ t('photoshub.birthday') }}</label>
            <input id="ph-yuanbao-bday" v-model="form.yuanbao_birthday" type="text" maxlength="10" placeholder="YYYY-MM" />
            <label for="ph-erbao-name">{{ t('photoshub.child_erbao') }} · {{ t('photoshub.person_name') }}</label>
            <input id="ph-erbao-name" v-model="form.erbao_name" type="text" maxlength="40" />
            <label for="ph-erbao-bday">{{ t('photoshub.child_erbao') }} · {{ t('photoshub.birthday') }}</label>
            <input id="ph-erbao-bday" v-model="form.erbao_birthday" type="text" maxlength="10" placeholder="YYYY-MM" />
          </div>
        </div>

        <div class="card-block">
          <div class="section-head">
            <h2>{{ t('photoshub.albums_title') }}</h2>
            <span class="meta">{{ t('photoshub.albums_hint') }}</span>
          </div>
          <div class="form-grid">
            <label for="ph-album-pending">{{ t('photoshub.album_pending') }}</label>
            <input id="ph-album-pending" v-model="form.album_pending" type="text" maxlength="80" />
            <label for="ph-album-yuanbao">{{ t('photoshub.album_yuanbao') }}</label>
            <input id="ph-album-yuanbao" v-model="form.album_yuanbao" type="text" maxlength="80" />
            <label for="ph-album-erbao">{{ t('photoshub.album_erbao') }}</label>
            <input id="ph-album-erbao" v-model="form.album_erbao" type="text" maxlength="80" />
          </div>
        </div>

        <div class="card-block">
          <div class="section-head">
            <h2>{{ t('photoshub.links_title') }}</h2>
            <span class="meta">{{ t('photoshub.links_hint') }}</span>
          </div>
          <div class="form-grid">
            <label for="ph-immich-public">{{ t('photoshub.immich_public') }}</label>
            <input id="ph-immich-public" v-model="form.immich_public" type="url" maxlength="200" />
            <label for="ph-immich-api">{{ t('photoshub.immich_api') }}</label>
            <input id="ph-immich-api" v-model="form.immich_base" type="url" maxlength="200" />
            <label for="ph-panel-url">{{ t('photoshub.panel_url') }}</label>
            <input id="ph-panel-url" v-model="form.panel_url" type="url" maxlength="200" />
            <label>{{ t('photoshub.api_key') }}</label>
            <div class="mono">{{ cfg?.immich?.has_api_key ? t('photoshub.api_key_present') : t('photoshub.api_key_missing') }}</div>
          </div>
        </div>

        <div class="card-block">
          <div class="section-head">
            <h2>{{ t('photoshub.paths_title') }}</h2>
            <span class="meta">{{ t('photoshub.paths_hint') }}</span>
          </div>
          <div class="form-grid readonly">
            <label>{{ t('photoshub.path_library') }}</label>
            <div class="mono path">{{ finiteText(cfg?.paths?.photos_library) }}</div>
            <label>{{ t('photoshub.path_bridge') }}</label>
            <div class="mono path">{{ finiteText(cfg?.paths?.bridge_dir) }}</div>
            <label>{{ t('photoshub.path_inbox') }}</label>
            <div class="mono path">{{ finiteText(cfg?.paths?.inbox_dir) }}</div>
            <label>{{ t('photoshub.path_backup') }}</label>
            <div class="mono path">{{ finiteText(cfg?.paths?.backup_dir) }}</div>
            <label>{{ t('photoshub.path_media') }}</label>
            <div class="mono path">{{ finiteText(cfg?.paths?.media_location) }}</div>
            <label>{{ t('photoshub.handbook') }}</label>
            <div class="mono path">{{ finiteText(data.links?.handbook) }}</div>
          </div>
        </div>

        <div class="card-block">
          <div class="section-head">
            <h2>{{ t('photoshub.gates_title') }}</h2>
            <span class="meta">{{ t('photoshub.gates_hint') }}</span>
          </div>
          <p class="meta">
            {{ t('photoshub.min_originals') }} {{ finiteN(cfg?.gates?.min_local_original_pct, 99) }}%
            · {{ t('photoshub.force_fallback') }}: {{ cfg?.bridge?.force_fallback ? t('common.on') : t('common.off') }}
            · {{ t('photoshub.db_check') }}: {{ finiteText(data.bridge?.photos_db_quick_check) }}
          </p>
          <p v-if="cfg?.bridge?.note" class="hint">{{ finiteText(cfg.bridge.note) }}</p>
          <div class="toolbar" style="flex-wrap:wrap;margin-top:8px">
            <button @click="run('enable-delete')" :disabled="busy || !data?.gates?.originals_ready">
              {{ t('photoshub.act_enable_delete') }}
            </button>
            <button @click="run('enable-cleanup')" :disabled="busy || !data?.gates?.originals_ready">
              {{ t('photoshub.act_enable_cleanup') }}
            </button>
            <button @click="run('cleanup')" :disabled="busy || data?.gates?.allow_cleanup === false">
              {{ t('photoshub.act_cleanup') }}
            </button>
          </div>
        </div>

        <div class="card-block">
          <div class="section-head">
            <h2>{{ t('photoshub.maintenance_title') }}</h2>
            <span class="meta">{{ t('photoshub.maintenance_hint') }}</span>
          </div>
          <div class="toolbar" style="flex-wrap:wrap">
            <button @click="run('backup')" :disabled="busy">{{ t('photoshub.act_backup') }}</button>
            <button @click="run('external-backup')" :disabled="busy">{{ t('photoshub.act_ext_backup') }}</button>
            <button @click="run('configure-people')" :disabled="busy">{{ t('photoshub.act_people') }}</button>
          </div>
        </div>

        <div class="toolbar" style="grid-column:1/-1">
          <button class="primary" type="button" :disabled="saving || !cfg" @click="saveSettings">{{ t('common.save') }}</button>
          <button type="button" :disabled="saving" @click="loadConfig({ force: true })">{{ t('common.reload') }}</button>
        </div>
      </div>

      <template v-else-if="tab === 'logs'">
        <div class="card-block" v-if="lastAction" data-test="photoshub-action-log">
          <div class="section-head">
            <h2>{{ t('photoshub.last_action') }}: {{ actionLabel(lastAction.action) }}</h2>
            <span class="badge" :class="lastAction.ok ? 'ok' : 'down'">{{ lastAction.ok ? t('common.ok') : t('common.fail') }}</span>
          </div>
          <pre v-if="lastAction.stdout || lastAction.stderr" class="mono logbox" aria-live="polite">{{ finiteText(lastAction.stdout, '') || finiteText(lastAction.stderr) }}</pre>
          <pre v-else class="mono logbox">{{ '—' }}</pre>
        </div>

        <div class="card-block" style="margin-top:14px">
          <div class="section-head">
            <h2>{{ t('photoshub.logs') }}</h2>
            <div class="tabs">
              <button v-for="n in logNames" :key="finiteText(n)" :class="{ active: logName===n }" :aria-pressed="logName===n" @click="switchLog(n)">{{ finiteText(n) }}</button>
            </div>
          </div>
          <p v-if="logError" class="hint bad" role="alert">{{ finiteText(logError) }}</p>
          <pre v-if="(logData?.lines || []).length" class="mono logbox" aria-live="polite">{{ (logData?.lines || []).map(l => finiteText(l, '')).filter(Boolean).join('\n') }}</pre>
          <pre v-else class="mono logbox">{{ '—' }}</pre>
        </div>
      </template>
    </template>
  </div>
</template>

<script setup>
import { computed, inject, onMounted, onUnmounted, ref } from 'vue'
import {
  getPhotosHubStatus,
  getPhotosHubConfig,
  patchPhotosHubConfig,
  getPhotosHubPending,
  photosHubThumbUrl,
  postPhotosHubAction,
  postPhotosHubPendingRemove,
  getPhotosHubLogs,
} from '../api/client'
import { injectI18n } from '../i18n'
import { finiteN, finiteText, withUnit } from '../lib/finite'
import LoadFailure from '../components/LoadFailure.vue'
import SkeletonLoader from '../components/SkeletonLoader.vue'

const toast = inject('toast', () => {})
const { t } = injectI18n()
const TABS = ['overview', 'pending', 'settings', 'logs']
const tabs = TABS.map((id) => ({ id }))

const data = ref(null)
const cfg = ref(null)
const pending = ref(null)
const loaded = ref(false)
const loading = ref(false)
const pendingLoading = ref(false)
const saving = ref(false)
const busy = ref(false)
const busyAction = ref('')
const loadError = ref('')
const settingsError = ref('')
const pendingError = ref('')
const selected = ref([])
//: asset id -> true once its preview 404s/502s, so the tile stops retrying and
//: shows the asset type instead of a broken-image glyph.
const thumbFailed = ref({})
const lastAction = ref(null)
const logName = ref('bridge')
const logData = ref(null)
const logError = ref('')
const logNames = ['bridge', 'delete', 'cleanup', 'backup', 'external', 'errors']
const form = ref(emptyForm())
let pageAlive = true
let loadGeneration = 0

function initialTab() {
  try {
    const wanted = new URLSearchParams(window.location.search).get('tab') || ''
    return TABS.includes(wanted) ? wanted : 'overview'
  } catch {
    return 'overview'
  }
}
const tab = ref(initialTab())

const ready = computed(() => Boolean(data.value?.photoshub_ok))
const originalsLabel = computed(() => withUnit(data.value?.originals?.local_original_pct, '%'))
// The -text tints, not the raw hues: this value lands as *ink* on the tile,
// and --ok / --warn / --down are fill colours that fail AA as text
// (contrast.test.js pins this computed's return values).
const originalsColor = computed(() => {
  const p = finiteN(data.value?.originals?.local_original_pct, 0)
  if (p >= 99) return 'var(--ok-text)'
  if (p >= 50) return 'var(--warn-text)'
  return 'var(--down-text)'
})
const allSelected = computed(() => {
  const assets = pending.value?.assets || []
  return assets.length > 0 && selected.value.length === assets.length
})
const immichHref = computed(() => safeHttpUrl(data.value?.links?.immich))
const panelHref = computed(() => safeHttpUrl(data.value?.links?.panel))
const pendingCount = computed(() => {
  const n = finiteN(pending.value?.count, null)
  return n == null ? null : n
})
const externalIssue = computed(() => {
  const ext = data.value?.external_backup
  if (!ext || ext.ok !== false) return ''
  if (ext.reason === 'volume_missing') return ''
  return t('common.issues')
})
const formDirty = computed(() => {
  if (!cfg.value) return false
  return JSON.stringify(form.value) !== JSON.stringify(formFromConfig(cfg.value))
})
const peopleLabel = computed(() => {
  const p = data.value?.people || {}
  const names = [p.yuanbao?.name, p.erbao?.name].map(n => finiteText(n, '')).filter(Boolean)
  return names.join(' · ') || '—'
})
const peopleMeta = computed(() => {
  const p = data.value?.people || {}
  const bits = [p.yuanbao?.birthday, p.erbao?.birthday].map(n => finiteText(n, '')).filter(Boolean)
  return bits.join(' · ')
})

function emptyForm() {
  return formFromConfig(null)
}

function formFromConfig(c) {
  return {
    yuanbao_name: finiteText(c?.people?.yuanbao?.name, ''),
    yuanbao_birthday: c?.people?.yuanbao?.birthday || '',
    erbao_name: finiteText(c?.people?.erbao?.name, ''),
    erbao_birthday: c?.people?.erbao?.birthday || '',
    album_pending: c?.albums?.pending_delete || '',
    album_yuanbao: c?.albums?.yuanbao || '',
    album_erbao: c?.albums?.erbao || '',
    immich_base: c?.immich?.base_url || '',
    immich_public: c?.immich?.public_url || '',
    panel_url: c?.panel?.url || '',
  }
}

function applyForm(c) {
  form.value = formFromConfig(c)
}

function tabLabel(tb) {
  if (tb.id === 'pending' && pendingCount.value) {
    return `${t('photoshub.tab_pending')} (${pendingCount.value})`
  }
  return t(`photoshub.tab_${tb.id}`)
}

function actionLabel(action) {
  const keys = {
    sync: 'act_sync',
    originals: 'act_originals',
    doctor: 'act_doctor',
    backup: 'act_backup',
    'external-backup': 'act_ext_backup',
    'delete-review': 'act_delete_review',
    cleanup: 'act_cleanup',
    'enable-delete': 'act_enable_delete',
    'enable-cleanup': 'act_enable_cleanup',
    'configure-people': 'act_people',
  }
  const key = keys[action]
  return key ? t(`photoshub.${key}`) : finiteText(action, '')
}

function safeHttpUrl(raw) {
  const text = finiteText(raw, '').trim()
  try {
    const url = new URL(text)
    if (url.protocol === 'http:' || url.protocol === 'https:') return finiteText(text, '')
  } catch {
    /* ignore */
  }
  return ''
}

function rememberTab(id) {
  try {
    const url = new URL(window.location.href)
    url.searchParams.set('tab', id)
    // Keep the existing entry's state: vue-router keeps its scroll position and
    // navigation bookkeeping there, and replacing it with null breaks back and
    // forward for the rest of the session.
    history.replaceState(history.state, '', url)
  } catch {
    /* ignore */
  }
}

async function switchTab(id) {
  if (!TABS.includes(id)) return
  tab.value = id
  rememberTab(id)
  if (!data.value?.photoshub_ok) return
  if (id === 'pending') await loadPending()
  if (id === 'settings') await loadConfig()
  if (id === 'logs') await switchLog(logName.value)
}

async function load() {
  const generation = ++loadGeneration
  loading.value = true
  loadError.value = ''
  try {
    const snap = await getPhotosHubStatus()
    if (generation !== loadGeneration || !pageAlive) return
    data.value = snap
    loaded.value = true
    if (data.value?.photoshub_ok) {
      const jobs = []
      if (tab.value === 'pending') jobs.push(loadPending())
      if (tab.value === 'settings') jobs.push(loadConfig())
      if (tab.value === 'logs') jobs.push(switchLog(logName.value))
      await Promise.all(jobs)
    } else {
      pending.value = null
      logData.value = null
      cfg.value = null
      settingsError.value = ''
      pendingError.value = ''
    }
  } catch (e) {
    if (generation !== loadGeneration || !pageAlive) return
    loadError.value = String(e?.message || e)
  } finally {
    if (generation === loadGeneration) {
      loading.value = false
      loaded.value = true
    }
  }
}

async function loadConfig({ force = false } = {}) {
  if (!data.value?.photoshub_ok) return
  const generation = loadGeneration
  settingsError.value = ''
  try {
    const next = await getPhotosHubConfig()
    if (generation !== loadGeneration || !pageAlive) return
    const keepForm = Boolean(cfg.value) && formDirty.value && !force
    cfg.value = next
    if (!keepForm) applyForm(next)
  } catch (e) {
    if (generation !== loadGeneration || !pageAlive) return
    settingsError.value = finiteText(e?.message || e, '')
  }
}

async function saveSettings() {
  const generation = loadGeneration
  saving.value = true
  try {
    const f = form.value
    // The API treats immich.base_url and albums.pending_delete as required and
    // rejects the *whole* patch when either arrives empty, so on a
    // half-configured install every save failed -- including one that only
    // touched a birthday. An absent key means "leave this alone", which is the
    // right request for a field the operator has not filled in yet.
    const albums = { yuanbao: f.album_yuanbao, erbao: f.album_erbao }
    if (f.album_pending) albums.pending_delete = f.album_pending
    const immich = { public_url: f.immich_public }
    if (f.immich_base) immich.base_url = f.immich_base
    const next = await patchPhotosHubConfig({
      people: {
        yuanbao: { name: f.yuanbao_name, birthday: f.yuanbao_birthday },
        erbao: { name: f.erbao_name, birthday: f.erbao_birthday },
      },
      albums,
      immich,
      panel: { url: f.panel_url },
    })
    if (generation !== loadGeneration || !pageAlive) return
    cfg.value = next
    applyForm(cfg.value)
    const snap = await getPhotosHubStatus()
    if (generation !== loadGeneration || !pageAlive) return
    data.value = snap
    toast('✅ ' + t('photoshub.settings_saved'))
  } catch (e) {
    if (generation !== loadGeneration || !pageAlive) return
    toast('❌ ' + finiteText(e?.message || e))
  } finally {
    // load() bumps loadGeneration and Refresh is not gated on saving.
    if (pageAlive) saving.value = false
  }
}

async function loadPending() {
  if (!data.value?.photoshub_ok) return
  const generation = loadGeneration
  pendingLoading.value = true
  pendingError.value = ''
  try {
    const next = await getPhotosHubPending()
    if (generation !== loadGeneration || !pageAlive) return
    pending.value = next
    selected.value = []
    // A refresh is the operator retrying, so give previews that failed last
    // time (Immich still starting, a transient 502) another chance.
    thumbFailed.value = {}
  } catch (e) {
    if (generation !== loadGeneration || !pageAlive) return
    pendingError.value = finiteText(e?.message || e, '')
  } finally {
    // load() bumps loadGeneration; a generation match would leave the
    // pending refresh button stuck on "scanning".
    if (pageAlive) pendingLoading.value = false
  }
}

async function run(action) {
  if (action === 'sync' && !confirm(t('photoshub.confirm_sync'))) return
  if (action === 'doctor' && !confirm(t('photoshub.confirm_doctor'))) return
  if (action === 'enable-delete' && !confirm(t('photoshub.confirm_enable_delete'))) return
  if (action === 'enable-cleanup' && !confirm(t('photoshub.confirm_enable_cleanup'))) return
  if (action === 'cleanup' && !confirm(t('photoshub.confirm_cleanup'))) return
  if (action === 'backup' && !confirm(t('photoshub.confirm_backup'))) return
  if (action === 'external-backup' && !confirm(t('photoshub.confirm_ext_backup'))) return
  if (action === 'originals' && !confirm(t('photoshub.confirm_originals'))) return
  if (action === 'configure-people' && !confirm(t('photoshub.confirm_people'))) return
  if (action === 'delete-review' && !confirm(t('photoshub.confirm_delete_review'))) return
  const generation = loadGeneration
  busy.value = true
  busyAction.value = action
  try {
    const next = await postPhotosHubAction(action)
    if (generation !== loadGeneration || !pageAlive) return
    lastAction.value = next
    const after = next.status_after || (await getPhotosHubStatus())
    if (generation !== loadGeneration || !pageAlive) return
    data.value = after
    if (action === 'delete-review') await loadPending()
    if (tab.value === 'settings') await loadConfig()
    if (generation !== loadGeneration || !pageAlive) return
    toast(lastAction.value.ok
      ? '✅ ' + actionLabel(action)
      : '❌ ' + (finiteText(lastAction.value.stderr, '') || actionLabel(action)))
  } catch (e) {
    if (generation !== loadGeneration || !pageAlive) return
    lastAction.value = { action, ok: false, stderr: finiteText(e?.message || e, '') }
    toast('❌ ' + finiteText(e?.message || e))
  } finally {
    // load() bumps loadGeneration; a generation match would leave the
    // action buttons stuck after a successful run.
    if (pageAlive) {
      busy.value = false
      busyAction.value = ''
    }
  }
}

async function removeSelected() {
  if (!selected.value.length) return
  if (!confirm(t('photoshub.confirm_remove'))) return
  const generation = loadGeneration
  pendingLoading.value = true
  try {
    await postPhotosHubPendingRemove(selected.value)
    if (generation !== loadGeneration || !pageAlive) return
    await loadPending()
    if (generation !== loadGeneration || !pageAlive) return
    toast('✅ ' + t('photoshub.remove_selected'))
  } catch (e) {
    // A failed removal is not a failed page load: routing it to loadError put a
    // whole-page failure banner with a "reload everything" retry above a page
    // that had loaded fine, and left it there until the next full load.
    if (generation !== loadGeneration || !pageAlive) return
    pendingError.value = finiteText(e?.message || e, '')
    toast('❌ ' + finiteText(e?.message || e))
  } finally {
    // load() bumps loadGeneration; a generation match would leave Remove
    // stuck after a successful write.
    if (pageAlive) pendingLoading.value = false
  }
}

function toggleAll(ev) {
  const on = ev.target.checked
  selected.value = on ? (pending.value?.assets || []).map(a => a.id) : []
}

async function switchLog(n) {
  if (!data.value?.photoshub_ok) return
  const generation = loadGeneration
  logName.value = n
  try {
    const next = await getPhotosHubLogs(n)
    if (generation !== loadGeneration || !pageAlive) return
    logData.value = next
    logError.value = ''
  } catch (e) {
    if (generation !== loadGeneration || !pageAlive) return
    logError.value = String(e?.message || e)
  }
}

onMounted(() => {
  pageAlive = true
  void load()
})
onUnmounted(() => {
  pageAlive = false
  loadGeneration += 1
})
</script>

<style scoped>
.card-block {
  background: var(--card);
  border-radius: 12px;
  padding: 14px 16px;
  border: 1px solid var(--line);
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
.settings-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 14px;
}
.form-grid {
  display: grid;
  grid-template-columns: 150px 1fr;
  gap: 8px 12px;
  align-items: center;
  font-size: 13px;
}
.form-grid label { color: var(--sub); font-weight: 600; font-size: 11px; }
.form-grid input { width: 100%; }
.form-grid.readonly { align-items: start; }
.path { font-size: 12px; overflow-wrap: anywhere; }
.hint { margin: 6px 0 0; color: var(--sub); font-size: 12px; line-height: 1.5; }
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
  border: 1px solid var(--line);
  text-decoration: none;
  color: inherit;
  font-size: 13px;
}
.action-banner { margin-bottom: 14px; }
.select-all { margin: 0 0 8px; }
.select-all label { display: inline-flex; align-items: center; gap: 6px; cursor: pointer; }
/* auto-fill, not auto-fit: a two-photo album should show two tiles at their
   real size rather than stretching them across the whole row. */
.review-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(132px, 1fr));
  gap: 10px;
}
.review-tile {
  position: relative;
  display: flex;
  flex-direction: column;
  gap: 4px;
  padding: 6px;
  border: 1px solid var(--line);
  border-radius: 10px;
  cursor: pointer;
}
.review-tile.picked { border-color: var(--down); background: rgba(220, 60, 60, .07); }
.review-tile input { position: absolute; top: 10px; left: 10px; z-index: 1; }
.review-tile img,
.review-noimg {
  width: 100%;
  aspect-ratio: 1;
  border-radius: 6px;
  background: rgba(0,0,0,.06);
  object-fit: cover;
}
.review-noimg { display: flex; align-items: center; justify-content: center; font-size: 11px; }
.review-cap { display: flex; flex-direction: column; min-width: 0; }
.review-cap .name {
  font-size: 11px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.review-cap .sub { font-size: 10px; }
@media (max-width: 860px) {
  .settings-grid { grid-template-columns: 1fr; }
}
@media (max-width: 640px) {
  .section-head { flex-wrap: wrap; }
  .form-grid { grid-template-columns: 1fr; }
  .review-grid { grid-template-columns: repeat(auto-fill, minmax(104px, 1fr)); }
}
</style>
