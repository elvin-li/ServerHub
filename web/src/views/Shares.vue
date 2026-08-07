<template>
  <div class="sharing-page" :aria-busy="loading || busy">
    <div class="page-title">
      <h1>{{ t('shares.title') }}</h1>
      <span class="meta">
        {{ data
          ? t('shares.summary', { shares: shareCount, services: coreServices.length })
          : t('shares.meta') }}
      </span>
    </div>

    <div class="toolbar sharing-toolbar">
      <button class="primary" :disabled="loading || busy" @click="refresh">
        <RefreshCw :size="15" :class="{ spinning: loading }" />
        {{ t('common.refresh') }}
      </button>
      <button :disabled="busy" @click="openSettings">
        <Settings :size="15" />
        {{ t('shares.open_system_settings') }}
      </button>
      <span v-if="busyLabel" class="authorization-note" role="status" aria-live="polite">
        <LoaderCircle :size="15" class="spinning" />{{ busyLabel }}
      </span>
    </div>

    <div v-if="!data" class="card page-placeholder" role="status" aria-live="polite">
      {{ loading ? t('common.loading') : t('shares.unavailable') }}
    </div>

    <template v-else>
      <section class="card host-overview" aria-labelledby="sharing-host-title">
        <div class="host-identity">
          <div class="host-icon"><Server :size="22" /></div>
          <div class="host-copy">
            <span id="sharing-host-title" class="section-title">{{ t('shares.this_mac') }}</span>
            <strong>{{ data.host?.name || t('shares.unknown') }}</strong>
            <code>{{ data.host?.address || '—' }}</code>
          </div>
        </div>
        <div class="host-stats" :aria-label="t('shares.overview_summary')">
          <div>
            <span>{{ t('shares.shared_folders') }}</span>
            <strong>{{ shareCount }}</strong>
          </div>
          <div>
            <span>{{ t('shares.core_services') }}</span>
            <strong>{{ activeCoreCount }}/{{ coreServices.length }}</strong>
          </div>
        </div>
        <div class="host-links btns">
          <a v-if="data.host?.smb_url" class="btn primary" :href="data.host.smb_url">
            <FolderOpen :size="15" />{{ t('shares.connect_files') }}
          </a>
          <a v-if="data.host?.vnc_url" class="btn" :href="data.host.vnc_url">
            <Monitor :size="15" />{{ t('shares.connect_screen') }}
          </a>
        </div>
      </section>

      <section aria-labelledby="shared-folders-title">
        <div class="section-bar">
          <div>
            <h2 id="shared-folders-title" class="section-title">{{ t('shares.shared_folders') }}</h2>
            <p class="hint">{{ t('shares.shared_folders_hint') }}</p>
          </div>
          <button class="primary" :disabled="busy" @click="openCreate">
            <Plus :size="15" />{{ t('shares.add_folder') }}
          </button>
        </div>

        <div v-if="!data.smb?.length" class="card empty-state">
          <FolderOpen :size="26" />
          <div>
            <strong>{{ t('shares.smb_empty') }}</strong>
            <span>{{ t('shares.smb_example') }}</span>
          </div>
        </div>
        <div v-else class="card share-list">
          <article v-for="share in data.smb" :key="share.record_name" class="share-row">
            <div class="folder-icon"><Folder :size="18" /></div>
            <div class="share-copy">
              <strong>{{ share.smb_name || share.name }}</strong>
              <code class="path">{{ share.path }}</code>
              <a v-if="share.url" :href="share.url">{{ share.url }}</a>
            </div>
            <div class="share-badges">
              <span v-if="share.guest" class="badge warn"><Users :size="12" />{{ t('shares.guest') }}</span>
              <span v-else class="badge ok"><LockKeyhole :size="12" />{{ t('shares.secure') }}</span>
              <span v-if="share.readonly" class="badge">{{ t('shares.readonly') }}</span>
              <span v-if="share.encrypted" class="badge accent">{{ t('shares.encrypted') }}</span>
            </div>
            <div class="share-actions btns">
              <button class="tiny" :aria-label="t('shares.edit_named', { name: share.smb_name || share.name })" :disabled="busy" @click="openEdit(share)">
                <Pencil :size="15" />{{ t('shares.edit_action') }}
              </button>
              <button class="tiny danger-button" :aria-label="t('shares.remove_named', { name: share.smb_name || share.name })" :disabled="busy" @click="removeShare(share)">
                <Trash2 :size="15" />{{ t('shares.remove_action') }}
              </button>
            </div>
          </article>
        </div>
      </section>

      <section class="sharing-grid" :aria-label="t('shares.system_sharing')">
        <div class="card service-card" aria-labelledby="core-services-title">
          <div class="card-heading">
            <div>
              <h2 id="core-services-title" class="section-title">{{ t('shares.core_services') }}</h2>
              <p class="hint">{{ t('shares.core_services_hint') }}</p>
            </div>
          </div>
          <div class="service-list">
            <article v-for="service in coreServices" :key="service.id" class="service-row">
              <div class="service-icon" :class="`service-${service.id}`">
                <component :is="serviceIcon(service.id)" :size="17" />
              </div>
              <div class="service-copy">
                <strong>{{ t(`shares.service_${service.id}`) }}</strong>
                <span>{{ t(`shares.service_${service.id}_hint`) }}</span>
              </div>
              <div class="service-action">
                <span class="badge" :class="stateClass(service.enabled)">{{ stateText(service.enabled) }}</span>
                <button
                  v-if="typeof service.enabled === 'boolean'"
                  class="mac-switch"
                  role="switch"
                  :aria-label="t('shares.toggle_service', { name: t(`shares.service_${service.id}`) })"
                  :aria-checked="service.enabled ? 'true' : 'false'"
                  :disabled="busy"
                  @click="toggleService(service)"
                ><span></span></button>
              </div>
            </article>
            <p v-if="!coreServices.length" class="inline-empty">{{ t('shares.no_core_services') }}</p>
          </div>
        </div>

        <div class="card managed-card" aria-labelledby="managed-services-title">
          <div class="card-heading">
            <div>
              <h2 id="managed-services-title" class="section-title">{{ t('shares.managed_services') }}</h2>
              <p class="hint">{{ t('shares.managed_services_hint') }}</p>
            </div>
            <span class="badge accent">{{ t('shares.managed_by_macos') }}</span>
          </div>
          <div class="managed-grid">
            <article v-for="service in managedServices" :key="service.id" class="managed-service">
              <div class="service-icon" :class="`service-${service.id}`">
                <component :is="serviceIcon(service.id)" :size="17" />
              </div>
              <div>
                <strong>{{ t(`shares.service_${service.id}`) }}</strong>
                <span>{{ t(`shares.service_${service.id}_hint`) }}</span>
              </div>
            </article>
          </div>
          <p v-if="!managedServices.length" class="inline-empty">{{ t('shares.no_managed_services') }}</p>
          <p v-else class="managed-note"><Settings :size="14" />{{ t('shares.managed_services_note') }}</p>
        </div>
      </section>

      <section v-if="data.file_services?.length" aria-labelledby="file-services-title">
        <div class="section-bar">
          <div>
            <h2 id="file-services-title" class="section-title">{{ t('shares.file_services') }}</h2>
            <p class="hint">{{ t('shares.file_services_hint') }}</p>
          </div>
        </div>
        <div class="card file-service-list">
          <article v-for="service in data.file_services" :key="service.id" class="file-service-row">
            <div class="service-icon service-file"><Globe2 :size="17" /></div>
            <strong>{{ service.name }}</strong>
            <span class="badge" :class="service.state === 'ok' ? 'ok' : 'stopped'">
              {{ service.state === 'ok' ? t('common.running') : t('common.off') }}
            </span>
            <a v-if="service.url" class="btn tiny" :href="service.url" target="_blank" rel="noopener">
              {{ t('common.open') }}<ExternalLink :size="13" />
            </a>
          </article>
        </div>
      </section>
    </template>

    <div v-if="sheetOpen" class="share-sheet-backdrop" role="presentation" @click.self="closeSheet">
      <section ref="sheetPanel" class="share-sheet" role="dialog" aria-modal="true" aria-labelledby="share-sheet-title" tabindex="-1">
        <header>
          <button class="sheet-cancel" :disabled="busy" @click="closeSheet">{{ t('common.cancel') }}</button>
          <h2 id="share-sheet-title">{{ editing ? t('shares.edit_share') : t('shares.new_share') }}</h2>
          <button class="sheet-save" :disabled="busy || !formValid" @click="saveShare">{{ t('common.save') }}</button>
        </header>
        <div class="sheet-body">
          <label v-if="!editing">
            <span>{{ t('shares.path') }}</span>
            <input v-model.trim="form.path" type="text" autocomplete="off" :placeholder="t('shares.path_placeholder')" />
            <small>{{ t('shares.path_hint') }}</small>
          </label>
          <label v-if="!editing">
            <span>{{ t('shares.record_name') }}</span>
            <input v-model.trim="form.name" type="text" maxlength="64" autocomplete="off" />
          </label>
          <label>
            <span>{{ t('shares.smb_name') }}</span>
            <input v-model.trim="form.smb_name" type="text" maxlength="64" autocomplete="off" />
          </label>
          <div class="sheet-options">
            <label class="option-row">
              <span><strong>{{ t('shares.guest') }}</strong><small>{{ t('shares.guest_hint') }}</small></span>
              <input v-model="form.guest" type="checkbox" />
            </label>
            <label class="option-row">
              <span><strong>{{ t('shares.readonly') }}</strong><small>{{ t('shares.readonly_hint') }}</small></span>
              <input v-model="form.readonly" type="checkbox" />
            </label>
            <label class="option-row">
              <span><strong>{{ t('shares.encrypted') }}</strong><small>{{ t('shares.encrypted_hint') }}</small></span>
              <input v-model="form.encrypted" type="checkbox" />
            </label>
          </div>
          <p class="sheet-security"><ShieldCheck :size="17" />{{ t('shares.native_auth_hint') }}</p>
        </div>
      </section>
    </div>
  </div>
</template>

<script setup>
import { computed, inject, onMounted, ref } from 'vue'
import {
  Archive, Bluetooth, ExternalLink, Folder, FolderOpen, Globe2, HardDriveDownload,
  Laptop, LoaderCircle, LockKeyhole, Monitor, Music2, Pencil, Plus, Printer,
  RefreshCw, Router, Server, Settings, ShieldCheck, TerminalSquare, Trash2, Users,
  Workflow,
} from '@lucide/vue'
import {
  createShare, getShares, openSharingSettings, removeShare as removeShareRequest,
  setSystemSharing, updateShare,
} from '../api/client'
import { useDismissable } from '../composables/useDismissable'
import { injectI18n } from '../i18n'

const toast = inject('toast')
const { t } = injectI18n()
const data = ref(null)
const loading = ref(false)
const busy = ref(false)
const busyLabel = ref('')
const editing = ref(null)
const sheetOpen = ref(false)
const sheetPanel = ref(null)
const emptyForm = () => ({ path: '', name: '', smb_name: '', guest: false, readonly: false, encrypted: false })
const form = ref(emptyForm())

const iconMap = {
  screen_sharing: Monitor,
  remote_login: TerminalSquare,
  remote_apple_events: Workflow,
  content_caching: HardDriveDownload,
  remote_management: Laptop,
  media_sharing: Music2,
  printer_sharing: Printer,
  internet_sharing: Router,
  bluetooth_sharing: Bluetooth,
}
const serviceIcon = (id) => iconMap[id] || Archive
const systemServices = computed(() => data.value?.system_services || [])
const coreServices = computed(() => systemServices.value.filter((service) => service.controllable))
const managedServices = computed(() => systemServices.value.filter((service) => !service.controllable))
const shareCount = computed(() => data.value?.smb?.length || 0)
const activeCoreCount = computed(() => coreServices.value.filter((service) => service.enabled === true).length)
const stateClass = (enabled) => enabled === true ? 'ok' : enabled === false ? 'stopped' : 'warn'
const stateText = (enabled) => enabled === true
  ? t('common.on')
  : enabled === false ? t('common.off') : t('shares.status_unavailable')
const formValid = computed(() => Boolean(
  form.value.smb_name.trim()
  && (editing.value || (form.value.path.trim() && form.value.name.trim())),
))

useDismissable(sheetOpen, closeSheet, sheetPanel)

async function refresh() {
  if (loading.value) return
  loading.value = true
  try { data.value = await getShares() }
  catch (error) { toast(`❌ ${error.message}`) }
  finally { loading.value = false }
}

function openCreate() {
  editing.value = null
  form.value = emptyForm()
  sheetOpen.value = true
}

function openEdit(share) {
  editing.value = share
  form.value = {
    path: share.path || '',
    name: share.record_name || share.name || '',
    smb_name: share.smb_name || '',
    guest: Boolean(share.guest),
    readonly: Boolean(share.readonly),
    encrypted: Boolean(share.encrypted),
  }
  sheetOpen.value = true
}

function closeSheet() {
  if (busy.value) return
  sheetOpen.value = false
  editing.value = null
}

async function saveShare() {
  if (busy.value || !formValid.value) return
  if (form.value.guest && !confirm(t('shares.confirm_guest'))) return
  busy.value = true
  busyLabel.value = t('shares.waiting_for_admin')
  try {
    const result = editing.value
      ? await updateShare(editing.value.record_name, {
        smb_name: form.value.smb_name,
        guest: form.value.guest,
        readonly: form.value.readonly,
        encrypted: form.value.encrypted,
      })
      : await createShare({ ...form.value })
    toast(`✅ ${result.message || t('shares.saved')}`)
    sheetOpen.value = false
    editing.value = null
    await refresh()
  } catch (error) {
    toast(`❌ ${error.message}`)
    await refresh()
  } finally {
    busy.value = false
    busyLabel.value = ''
  }
}

async function removeShare(share) {
  if (busy.value || !confirm(t('shares.confirm_remove', { name: share.smb_name || share.name }))) return
  busy.value = true
  busyLabel.value = t('shares.waiting_for_admin')
  try {
    await removeShareRequest(share.record_name)
    toast(`✅ ${t('shares.removed')}`)
  } catch (error) { toast(`❌ ${error.message}`) }
  finally {
    busy.value = false
    busyLabel.value = ''
    await refresh()
  }
}

async function toggleService(service) {
  if (busy.value || typeof service.enabled !== 'boolean') return
  const target = !service.enabled
  if (target && !confirm(t('shares.confirm_enable_service', { name: t(`shares.service_${service.id}`) }))) return
  if (!target && service.id === 'screen_sharing' && !confirm(t('shares.confirm_disable_screen'))) return
  busy.value = true
  busyLabel.value = t('shares.waiting_for_admin')
  try {
    await setSystemSharing(service.id, target)
    toast(`✅ ${t('shares.service_updated')}`)
  } catch (error) { toast(`❌ ${error.message}`) }
  finally {
    busy.value = false
    busyLabel.value = ''
    await refresh()
  }
}

async function openSettings() {
  if (busy.value) return
  busy.value = true
  try { await openSharingSettings() }
  catch (error) { toast(`❌ ${error.message}`) }
  finally { busy.value = false }
}

onMounted(refresh)
</script>

<style scoped>
.sharing-page { max-width:1180px; margin:0 auto; padding-bottom:36px; }
.sharing-toolbar button,.sharing-toolbar .btn,.host-links .btn,.share-actions button,.file-service-row .btn { display:inline-flex; align-items:center; justify-content:center; gap:6px; }
.authorization-note { display:inline-flex; align-items:center; gap:6px; margin-left:auto; color:var(--sub); font-size:11px; }
.page-placeholder { padding:28px; color:var(--sub); text-align:center; }
.host-overview { display:grid; grid-template-columns:minmax(220px,1fr) auto auto; align-items:center; gap:20px; margin-bottom:14px; }
.host-identity { display:flex; align-items:center; gap:12px; min-width:0; }
.host-icon,.folder-icon,.service-icon { display:grid; place-items:center; flex:0 0 auto; color:#fff; }
.host-icon { width:42px; height:42px; border-radius:var(--radius); background:var(--accent); }
.host-copy { display:flex; flex-direction:column; min-width:0; gap:2px; }
.host-copy .section-title { margin:0; }
.host-copy strong { overflow:hidden; font-size:15px; text-overflow:ellipsis; white-space:nowrap; }
.host-copy code { color:var(--sub); font-size:11px; }
.host-stats { display:flex; gap:20px; }
.host-stats div { display:flex; flex-direction:column; min-width:72px; }
.host-stats span { color:var(--sub); font-size:10px; }
.host-stats strong { font-size:18px; }
.host-links { justify-content:flex-end; }
.section-bar,.card-heading { display:flex; align-items:center; justify-content:space-between; gap:12px; }
.section-bar { margin:17px 0 8px; }
.section-bar .section-title,.card-heading .section-title { margin:0; }
.section-bar .hint,.card-heading .hint { margin:3px 0 0; }
.share-list { padding:0; overflow:hidden; }
.share-row { display:grid; grid-template-columns:auto minmax(180px,1fr) auto auto; align-items:center; gap:12px; min-height:72px; padding:10px 12px; }
.share-row + .share-row,.service-row + .service-row,.file-service-row + .file-service-row { border-top:1px solid var(--line); }
.folder-icon { width:34px; height:34px; border-radius:var(--radius); background:var(--accent); }
.share-copy { display:flex; flex-direction:column; min-width:0; gap:2px; }
.share-copy strong { font-size:13px; }
.share-copy .path { overflow:hidden; color:var(--sub); font-size:10.5px; text-overflow:ellipsis; white-space:nowrap; }
.share-copy a { color:var(--accent); font-size:10.5px; text-decoration:none; }
.share-badges { display:flex; flex-wrap:wrap; justify-content:flex-end; gap:4px; }
.share-badges .badge { display:inline-flex; align-items:center; gap:3px; }
.danger-button { color:var(--down); }
.empty-state { display:flex; align-items:center; justify-content:center; gap:12px; min-height:92px; color:var(--sub); text-align:left; }
.empty-state > div { display:flex; flex-direction:column; gap:3px; }
.empty-state strong { color:var(--txt); font-size:13px; }
.empty-state span { font-size:11px; }
.sharing-grid { display:grid; grid-template-columns:minmax(0,1.15fr) minmax(0,.85fr); gap:10px; margin-top:18px; }
.service-card,.managed-card { padding:0; overflow:hidden; }
.card-heading { min-height:62px; padding:10px 12px; border-bottom:1px solid var(--line); }
.service-list { display:flex; flex-direction:column; }
.service-row { display:grid; grid-template-columns:auto minmax(0,1fr) auto; align-items:center; gap:10px; min-height:66px; padding:8px 12px; }
.service-icon { width:31px; height:31px; border-radius:var(--radius); background:#777; }
.service-screen_sharing { background:#2397a8; }.service-remote_login { background:#635bba; }.service-remote_apple_events { background:#9f4db5; }.service-content_caching { background:#d27d00; }.service-remote_management { background:#287ed1; }.service-media_sharing { background:#d93669; }.service-printer_sharing { background:#349ac2; }.service-internet_sharing { background:#2b9e52; }.service-bluetooth_sharing { background:#287ed1; }.service-file { background:#287ed1; }
.service-copy { display:flex; flex-direction:column; min-width:0; gap:2px; }
.service-copy strong,.managed-service strong,.file-service-row strong { font-size:12px; }
.service-copy span,.managed-service span { color:var(--sub); font-size:10.5px; line-height:1.35; }
.service-action { display:flex; align-items:center; gap:8px; }
.mac-switch { position:relative; width:38px; height:22px; min-width:38px; padding:0; border:0; border-radius:var(--radius-pill); background:#999; }
.mac-switch span { position:absolute; top:2px; left:2px; width:18px; height:18px; border-radius:50%; background:#fff; box-shadow:0 1px 3px rgba(0,0,0,.28); transition:transform .16s ease; }
.mac-switch[aria-checked="true"] { background:var(--ok); }
.mac-switch[aria-checked="true"] span { transform:translateX(16px); }
.managed-grid { display:grid; grid-template-columns:1fr 1fr; gap:1px; background:var(--line); }
.managed-service { display:flex; align-items:flex-start; gap:9px; min-height:79px; padding:10px; background:var(--card); }
.managed-service > div:last-child { display:flex; flex-direction:column; gap:3px; min-width:0; }
.managed-note { display:flex; align-items:center; gap:6px; margin:0; padding:9px 12px; border-top:1px solid var(--line); color:var(--sub); font-size:10.5px; }
.inline-empty { margin:0; padding:18px 12px; color:var(--sub); font-size:11px; }
.file-service-list { padding:0; overflow:hidden; }
.file-service-row { display:grid; grid-template-columns:auto minmax(0,1fr) auto auto; align-items:center; gap:10px; min-height:56px; padding:8px 12px; }
.share-sheet-backdrop { position:fixed; inset:0; z-index:1000; display:flex; align-items:flex-end; justify-content:center; padding:20px; background:rgba(0,0,0,.38); backdrop-filter:blur(8px); }
.share-sheet { width:min(560px,100%); max-height:90vh; overflow:auto; border:1px solid var(--line); border-radius:var(--radius); color:var(--txt); background:var(--card); box-shadow:0 20px 70px rgba(0,0,0,.32); }
.share-sheet header { position:sticky; top:0; z-index:1; display:grid; grid-template-columns:1fr auto 1fr; align-items:center; min-height:52px; padding:0 12px; border-bottom:1px solid var(--line); background:var(--card); }
.share-sheet header h2 { margin:0; font-size:14px; }
.sheet-cancel,.sheet-save { border:0; background:transparent; color:var(--accent); }
.sheet-cancel { justify-self:start; }.sheet-save { justify-self:end; font-weight:700; }
.sheet-body { display:flex; flex-direction:column; gap:14px; padding:16px; }
.sheet-body > label { display:flex; flex-direction:column; gap:6px; }
.sheet-body label > span { font-size:11px; font-weight:600; }
.sheet-body input[type="text"] { min-height:40px; padding:0 10px; border:1px solid var(--line); border-radius:var(--radius); color:var(--txt); background:var(--bg); }
.sheet-body small { color:var(--sub); font-size:10.5px; }
.sheet-options { border:1px solid var(--line); border-radius:var(--radius); overflow:hidden; }
.option-row { display:flex; align-items:center; justify-content:space-between; gap:14px; min-height:54px; padding:8px 10px; }
.option-row + .option-row { border-top:1px solid var(--line); }
.option-row > span { display:flex; flex-direction:column; gap:2px; }
.option-row input { width:19px; height:19px; accent-color:var(--accent); }
.sheet-security { display:flex; gap:7px; align-items:flex-start; margin:0; padding:10px; border-left:3px solid var(--accent); color:var(--sub); background:color-mix(in srgb,var(--accent) 7%,var(--card)); font-size:10.5px; line-height:1.45; }
.sheet-security svg { flex:0 0 auto; color:var(--accent); }
.spinning { animation:spin 1s linear infinite; }
button:disabled { opacity:.48; cursor:not-allowed; }
@keyframes spin { to { transform:rotate(360deg); } }
@media (max-width:900px) {
  .host-overview { grid-template-columns:minmax(0,1fr) auto; }
  .host-links { grid-column:1/-1; justify-content:flex-start; }
  .sharing-grid { grid-template-columns:1fr; }
}
@media (max-width:640px) {
  .sharing-toolbar { align-items:stretch; }
  .authorization-note { width:100%; margin:2px 0 0; }
  .host-overview { grid-template-columns:1fr; gap:12px; }
  .host-stats { justify-content:space-between; }
  .host-links { display:grid; grid-template-columns:1fr 1fr; }
  .section-bar { align-items:flex-end; }
  .share-row { grid-template-columns:auto minmax(0,1fr); }
  .share-badges,.share-actions { grid-column:2; justify-content:flex-start; }
  .share-actions button { min-height:36px; }
  .managed-grid { grid-template-columns:1fr; }
  .service-row { grid-template-columns:auto minmax(0,1fr); }
  .service-action { grid-column:2; justify-content:space-between; }
  .file-service-row { grid-template-columns:auto minmax(0,1fr) auto; }
  .file-service-row .btn { grid-column:2/4; justify-self:start; }
  .share-sheet-backdrop { padding:0; }
  .share-sheet { width:100%; max-height:94vh; border-radius:var(--radius) var(--radius) 0 0; }
}
@media (prefers-reduced-motion:reduce) { .mac-switch span,.spinning { transition:none; animation:none; } }
</style>
