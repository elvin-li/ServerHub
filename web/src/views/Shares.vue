<template>
  <div class="sharing-page" :aria-busy="loading || busy">
    <header class="sharing-header">
      <div>
        <p class="eyebrow">macOS</p>
        <h1>{{ t('shares.title') }}</h1>
        <p>{{ t('shares.meta') }}</p>
      </div>
      <button class="icon-button" :disabled="loading || busy" :aria-label="t('common.refresh')" @click="refresh">
        <RefreshCw :size="18" :class="{ spinning: loading }" />
      </button>
    </header>

    <section class="mac-card host-card" aria-labelledby="sharing-host-title">
      <div class="host-icon"><Server :size="28" /></div>
      <div class="host-copy">
        <span id="sharing-host-title" class="section-kicker">{{ t('shares.this_mac') }}</span>
        <strong>{{ data?.host?.name || t('shares.unknown') }}</strong>
        <span>{{ data?.host?.address || '—' }}</span>
      </div>
      <div class="host-links">
        <a v-if="data?.host?.smb_url" class="soft-button" :href="data.host.smb_url">
          <FolderOpen :size="16" />{{ t('shares.connect_files') }}
        </a>
        <a v-if="data?.host?.vnc_url" class="soft-button" :href="data.host.vnc_url">
          <Monitor :size="16" />{{ t('shares.connect_screen') }}
        </a>
      </div>
    </section>

    <section aria-labelledby="system-sharing-title">
      <div class="section-heading">
        <div>
          <h2 id="system-sharing-title">{{ t('shares.system_sharing') }}</h2>
          <p>{{ t('shares.system_sharing_hint') }}</p>
        </div>
        <button class="text-button" :disabled="busy" @click="openSettings">
          <Settings :size="16" />{{ t('shares.open_system_settings') }}
        </button>
      </div>

      <div class="mac-card grouped-list">
        <article v-for="service in data?.system_services || []" :key="service.id" class="setting-row">
          <div class="service-icon" :class="`service-${service.id}`">
            <component :is="serviceIcon(service.id)" :size="19" />
          </div>
          <div class="setting-copy">
            <strong>{{ t(`shares.service_${service.id}`) }}</strong>
            <span>{{ t(`shares.service_${service.id}_hint`) }}</span>
            <small v-if="service.detail">{{ service.detail }}</small>
          </div>
          <div class="setting-action">
            <span class="state-label" :class="stateClass(service.enabled)">
              {{ stateText(service.enabled) }}
            </span>
            <button
              v-if="service.controllable && service.enabled !== null"
              class="mac-switch"
              role="switch"
              :aria-label="t('shares.toggle_service', { name: t(`shares.service_${service.id}`) })"
              :aria-checked="service.enabled ? 'true' : 'false'"
              :disabled="busy"
              @click="toggleService(service)"
            ><span></span></button>
            <button v-else class="row-link" :disabled="busy" @click="openSettings">
              {{ t('shares.details') }}<ChevronRight :size="16" />
            </button>
          </div>
        </article>
      </div>
      <p v-if="busyLabel" class="authorization-note" role="status" aria-live="polite">
        <LoaderCircle :size="16" class="spinning" />{{ busyLabel }}
      </p>
    </section>

    <section aria-labelledby="shared-folders-title">
      <div class="section-heading">
        <div>
          <h2 id="shared-folders-title">{{ t('shares.shared_folders') }}</h2>
          <p>{{ t('shares.shared_folders_hint') }}</p>
        </div>
        <button class="blue-button" :disabled="busy" @click="openCreate">
          <Plus :size="16" />{{ t('shares.add_folder') }}
        </button>
      </div>

      <div v-if="!(data?.smb || []).length" class="mac-card empty-state">
        <FolderOpen :size="30" />
        <strong>{{ t('shares.smb_empty') }}</strong>
        <span>{{ t('shares.smb_example') }}</span>
      </div>
      <div v-else class="mac-card grouped-list share-list">
        <article v-for="share in data.smb" :key="share.record_name" class="share-row">
          <div class="folder-icon"><Folder :size="20" /></div>
          <div class="share-copy">
            <strong>{{ share.smb_name || share.name }}</strong>
            <span class="path">{{ share.path }}</span>
            <a v-if="share.url" :href="share.url">{{ share.url }}</a>
          </div>
          <div class="share-badges">
            <span v-if="share.guest" class="privacy-badge warning"><Users :size="13" />{{ t('shares.guest') }}</span>
            <span v-else class="privacy-badge"><LockKeyhole :size="13" />{{ t('shares.secure') }}</span>
            <span v-if="share.readonly" class="privacy-badge">{{ t('shares.readonly') }}</span>
            <span v-if="share.encrypted" class="privacy-badge">{{ t('shares.encrypted') }}</span>
          </div>
          <div class="share-actions">
            <button :aria-label="t('shares.edit_named', { name: share.smb_name || share.name })" :disabled="busy" @click="openEdit(share)">
              <Pencil :size="16" />
            </button>
            <button class="danger-icon" :aria-label="t('shares.remove_named', { name: share.smb_name || share.name })" :disabled="busy" @click="removeShare(share)">
              <Trash2 :size="16" />
            </button>
          </div>
        </article>
      </div>
    </section>

    <section v-if="(data?.file_services || []).length" aria-labelledby="file-services-title">
      <div class="section-heading">
        <div>
          <h2 id="file-services-title">{{ t('shares.file_services') }}</h2>
          <p>{{ t('shares.file_services_hint') }}</p>
        </div>
      </div>
      <div class="mac-card grouped-list">
        <article v-for="service in data.file_services" :key="service.id" class="setting-row">
          <div class="service-icon service-file"><Globe2 :size="19" /></div>
          <div class="setting-copy"><strong>{{ service.name }}</strong><span>{{ service.detail }}</span></div>
          <div class="setting-action">
            <span class="state-label" :class="service.state === 'ok' ? 'state-on' : 'state-off'">
              {{ service.state === 'ok' ? t('common.running') : t('common.off') }}
            </span>
            <a v-if="service.url" class="row-link" :href="service.url" target="_blank" rel="noopener">
              {{ t('common.open') }}<ExternalLink :size="14" />
            </a>
          </div>
        </article>
      </div>
    </section>

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
  Archive, Bluetooth, ChevronRight, ExternalLink, Folder, FolderOpen, Globe2,
  HardDriveDownload, Laptop, LoaderCircle, LockKeyhole, Monitor, Music2,
  Pencil, Plus, Printer, RefreshCw, Router, Server, Settings, ShieldCheck,
  TerminalSquare, Trash2, Users, Workflow,
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
const stateClass = (enabled) => enabled === true ? 'state-on' : enabled === false ? 'state-off' : 'state-unknown'
const stateText = (enabled) => enabled === true ? t('common.on') : enabled === false ? t('common.off') : t('shares.unknown')
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
.sharing-page { --apple-blue:#007aff; --apple-green:#34c759; --apple-red:#ff3b30; max-width:980px; margin:0 auto; padding-bottom:40px; font-family:-apple-system,BlinkMacSystemFont,"SF Pro Text","PingFang SC",sans-serif; }
.sharing-header { display:flex; justify-content:space-between; align-items:flex-start; gap:20px; margin-bottom:20px; }
.sharing-header h1 { margin:0; font-size:30px; letter-spacing:-.03em; }
.sharing-header p { margin:5px 0 0; color:var(--sub); }
.eyebrow { color:var(--apple-blue)!important; font-size:11px; font-weight:700; letter-spacing:.12em; text-transform:uppercase; }
.mac-card { background:color-mix(in srgb,var(--card) 94%,transparent); border:1px solid color-mix(in srgb,var(--line) 78%,transparent); border-radius:18px; box-shadow:0 8px 26px rgba(0,0,0,.055); overflow:hidden; }
.host-card { display:grid; grid-template-columns:auto 1fr auto; align-items:center; gap:16px; padding:20px; margin-bottom:30px; }
.host-icon,.folder-icon,.service-icon { display:grid; place-items:center; flex:0 0 auto; }
.host-icon { width:54px; height:54px; border-radius:14px; color:white; background:linear-gradient(145deg,#5ac8fa,#007aff); }
.host-copy { display:flex; flex-direction:column; gap:2px; min-width:0; }
.host-copy strong { font-size:17px; }
.host-copy span:last-child,.section-kicker { color:var(--sub); font-size:12px; }
.host-links { display:flex; flex-wrap:wrap; justify-content:flex-end; gap:8px; }
.soft-button,.blue-button,.text-button,.icon-button { display:inline-flex; align-items:center; justify-content:center; gap:7px; min-height:38px; border-radius:10px; text-decoration:none; font-weight:600; }
.soft-button { padding:0 12px; color:var(--apple-blue); background:rgba(0,122,255,.09); }
.blue-button { padding:0 14px; border:0; color:#fff; background:var(--apple-blue); }
.text-button { border:0; padding:0 8px; color:var(--apple-blue); background:transparent; }
.icon-button { width:40px; border:1px solid var(--line); color:var(--txt); background:var(--card); }
.section-heading { display:flex; justify-content:space-between; align-items:flex-end; gap:16px; margin:28px 4px 10px; }
.section-heading h2 { margin:0; font-size:15px; letter-spacing:-.01em; }
.section-heading p { margin:4px 0 0; color:var(--sub); font-size:12px; }
.grouped-list article + article { border-top:1px solid color-mix(in srgb,var(--line) 72%,transparent); }
.setting-row { display:grid; grid-template-columns:auto minmax(0,1fr) auto; align-items:center; gap:13px; min-height:76px; padding:11px 16px; }
.service-icon { width:34px; height:34px; border-radius:9px; color:#fff; background:#8e8e93; }
.service-screen_sharing { background:#30b0c7; }.service-remote_login { background:#5856d6; }.service-remote_apple_events { background:#af52de; }.service-content_caching { background:#ff9f0a; }.service-remote_management { background:#007aff; }.service-media_sharing { background:#ff2d55; }.service-printer_sharing { background:#5ac8fa; }.service-internet_sharing { background:#34c759; }.service-bluetooth_sharing { background:#0a84ff; }.service-file { background:#64d2ff; }
.setting-copy { display:flex; flex-direction:column; min-width:0; gap:2px; }
.setting-copy strong { font-size:14px; }.setting-copy span,.setting-copy small { color:var(--sub); font-size:11px; line-height:1.35; overflow-wrap:anywhere; }
.setting-action { display:flex; align-items:center; justify-content:flex-end; gap:10px; }
.state-label { font-size:11px; font-weight:600; }.state-on { color:var(--apple-green); }.state-off { color:var(--sub); }.state-unknown { color:#ff9f0a; }
.mac-switch { position:relative; width:46px; height:28px; min-width:46px; padding:0; border:0; border-radius:999px; background:#b8b8bd; transition:background .18s ease; }
.mac-switch span { position:absolute; top:2px; left:2px; width:24px; height:24px; border-radius:50%; background:#fff; box-shadow:0 1px 4px rgba(0,0,0,.28); transition:transform .18s ease; }
.mac-switch[aria-checked="true"] { background:var(--apple-green); }.mac-switch[aria-checked="true"] span { transform:translateX(18px); }
.row-link { display:inline-flex; align-items:center; gap:2px; border:0; color:var(--apple-blue); background:transparent; font-size:12px; text-decoration:none; white-space:nowrap; }
.authorization-note { display:flex; align-items:center; justify-content:flex-end; gap:7px; margin:8px 4px 0; color:var(--sub); font-size:12px; }
.share-row { display:grid; grid-template-columns:auto minmax(180px,1fr) auto auto; align-items:center; gap:13px; min-height:82px; padding:12px 16px; }
.folder-icon { width:38px; height:38px; border-radius:10px; color:#fff; background:linear-gradient(145deg,#64d2ff,#0a84ff); }
.share-copy { display:flex; flex-direction:column; min-width:0; gap:2px; }.share-copy strong { font-size:14px; }.share-copy .path { color:var(--sub); font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:11px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }.share-copy a { color:var(--apple-blue); font-size:11px; text-decoration:none; }
.share-badges { display:flex; flex-wrap:wrap; justify-content:flex-end; gap:5px; }.privacy-badge { display:inline-flex; align-items:center; gap:4px; padding:4px 7px; border-radius:999px; color:var(--sub); background:color-mix(in srgb,var(--btn) 88%,transparent); font-size:10px; }.privacy-badge.warning { color:#9a5b00; background:rgba(255,159,10,.14); }
.share-actions { display:flex; gap:5px; }.share-actions button { display:grid; place-items:center; width:36px; height:36px; padding:0; border:0; border-radius:9px; color:var(--apple-blue); background:rgba(0,122,255,.08); }.share-actions .danger-icon { color:var(--apple-red); background:rgba(255,59,48,.08); }
.empty-state { display:flex; flex-direction:column; align-items:center; gap:7px; padding:34px; color:var(--sub); text-align:center; }.empty-state strong { color:var(--txt); }
.share-sheet-backdrop { position:fixed; inset:0; z-index:1000; display:flex; align-items:flex-end; justify-content:center; padding:20px; background:rgba(0,0,0,.38); backdrop-filter:blur(10px); }
.share-sheet { width:min(560px,100%); max-height:90vh; overflow:auto; border:1px solid rgba(255,255,255,.18); border-radius:20px; color:var(--txt); background:var(--card); box-shadow:0 24px 80px rgba(0,0,0,.32); }
.share-sheet header { position:sticky; top:0; z-index:1; display:grid; grid-template-columns:1fr auto 1fr; align-items:center; min-height:54px; padding:0 14px; border-bottom:1px solid var(--line); background:color-mix(in srgb,var(--card) 92%,transparent); backdrop-filter:blur(16px); }.share-sheet header h2 { margin:0; font-size:15px; }.sheet-cancel,.sheet-save { border:0; background:transparent; color:var(--apple-blue); }.sheet-cancel { justify-self:start; }.sheet-save { justify-self:end; font-weight:700; }
.sheet-body { display:flex; flex-direction:column; gap:16px; padding:20px; }.sheet-body > label { display:flex; flex-direction:column; gap:7px; }.sheet-body label > span { font-size:12px; font-weight:600; }.sheet-body input[type="text"] { min-height:42px; padding:0 12px; border:1px solid var(--line); border-radius:10px; color:var(--txt); background:var(--bg); }.sheet-body small { color:var(--sub); font-size:11px; }
.sheet-options { border:1px solid var(--line); border-radius:13px; overflow:hidden; }.option-row { display:flex; align-items:center; justify-content:space-between; gap:16px; min-height:58px; padding:9px 12px; }.option-row + .option-row { border-top:1px solid var(--line); }.option-row > span { display:flex; flex-direction:column; gap:2px; }.option-row input { width:20px; height:20px; accent-color:var(--apple-green); }
.sheet-security { display:flex; gap:8px; align-items:flex-start; margin:0; padding:11px; border-radius:11px; color:var(--sub); background:rgba(0,122,255,.07); font-size:11px; line-height:1.45; }.sheet-security svg { flex:0 0 auto; color:var(--apple-blue); }
.spinning { animation:spin 1s linear infinite; }button:disabled { opacity:.48; cursor:not-allowed; }
@keyframes spin { to { transform:rotate(360deg); } }
@media (max-width:720px) { .sharing-header h1 { font-size:25px; }.host-card { grid-template-columns:auto 1fr; }.host-links { grid-column:1/-1; justify-content:stretch; }.host-links a { flex:1; }.section-heading { align-items:center; }.setting-row { grid-template-columns:auto minmax(0,1fr); }.setting-action { grid-column:2; justify-content:flex-start; }.share-row { grid-template-columns:auto minmax(0,1fr) auto; }.share-badges { grid-column:2; justify-content:flex-start; }.share-actions { grid-column:3; grid-row:1/3; flex-direction:column; }.share-sheet-backdrop { padding:0; }.share-sheet { width:100%; max-height:94vh; border-radius:20px 20px 0 0; } }
@media (prefers-reduced-motion:reduce) { .mac-switch,.mac-switch span,.spinning { transition:none; animation:none; } }
</style>
