<template>
  <div>
    <div class="page-title">
      <h1>{{ t('pages.main') }}</h1>
      <span class="meta">{{ t('pages.main_meta') }}</span>
    </div>
    <div class="toolbar">
      <button class="primary" @click="refresh" :disabled="loading || busy">{{ t('common.refresh') }}</button>
      <span class="meta" style="color:var(--sub)">
        {{ t('main_extra.summary_counts', { disks: (data?.power_disks || []).length, vols: data?.volumes?.length || 0 }) }}
      </span>
      <span v-if="data?.array" class="badge" :class="data.array.status === 'started' ? 'ok' : 'warn'">
        Array {{ data.array.status }}
      </span>
    </div>

    <!-- Unraid-style array summary -->
    <div class="dash-grid" style="margin-bottom:12px" v-if="data?.array || data?.totals">
      <div class="tile span-3">
        <h3>{{ t('main.array_status') }}</h3>
        <div class="v" style="font-size:16px;color:var(--ok)">{{ data?.array?.status || 'started' }}</div>
        <div class="sub">{{ data?.array?.system_count ?? 0 }} + {{ data?.array?.data_count ?? 0 }}</div>
      </div>
      <div class="tile span-3">
        <h3>{{ t('main.capacity') }}</h3>
        <div class="v" style="font-size:16px">{{ data?.array?.total_tb ?? '—' }} <span style="font-size:12px;font-weight:500;color:var(--sub)">TB</span></div>
        <div class="sub">{{ t('common.used') }} {{ data?.array?.used_tb }} · {{ t('common.free') }} {{ data?.array?.free_tb }} TB</div>
        <div class="sub" style="margin-top:4px;font-size:10px" v-if="data?.array?.note">{{ data.array.note }}</div>
      </div>
      <div class="tile span-3">
        <h3>{{ t('main.physical') }}</h3>
        <div class="v">{{ data?.array?.disk_count ?? (data?.disks || []).length }}</div>
        <div class="sub">SMART</div>
      </div>
      <div class="tile span-3">
        <h3>{{ t('main.unassigned') }}</h3>
        <div class="v">{{ unassigned.length }}</div>
      </div>
    </div>

    <h2 class="section-title">{{ t('main.array_devices') }}</h2>
    <div class="table-wrap" style="margin-bottom:12px">
      <table class="dense">
        <thead>
          <tr>
            <th></th>
            <th>{{ t('main_extra.role') }}</th>
            <th>{{ t('dashboard.col_mount') }}</th>
            <th>{{ t('main_extra.th_kind') }}</th>
            <th>{{ t('main_extra.th_fs') }}</th>
            <th>{{ t('main_extra.th_total') }}</th>
            <th>{{ t('main_extra.th_used') }}</th>
            <th>{{ t('main_extra.th_avail') }}</th>
            <th>{{ t('main_extra.th_pct') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="d in arrayDevices" :key="d.mount">
            <td><span class="led on"></span></td>
            <td>
              <span class="badge" :class="d.kind === 'system' ? 'accent' : 'ok'">
                {{ d.kind === 'system' ? 'Cache/System' : 'Data' }}
              </span>
            </td>
            <td class="mono">
              <strong>{{ d.mount }}</strong>
              <div class="sub" style="font-size:10px" v-if="d.disk_id">
                {{ d.disk_id }}
                <span v-if="d.shared_pool" class="badge warn" style="margin-left:4px">{{ t('main_extra.shared_pool') }}</span>
              </div>
            </td>
            <td>{{ d.kind }}</td>
            <td class="mono">{{ d.filesystem }}</td>
            <td>{{ d.total_gb }} GB</td>
            <td>{{ d.used_gb }} GB</td>
            <td>{{ d.avail_gb }} GB</td>
            <td style="min-width:100px">
              {{ d.pct }}%
              <div class="pct-bar" :class="d.pct>=90?'danger':d.pct>=75?'warn':''" style="margin-top:3px">
                <i :style="{ width: d.pct + '%' }"></i>
              </div>
            </td>
          </tr>
          <tr v-if="!arrayDevices.length">
            <td colspan="9" style="color:var(--sub)">{{ t('main_extra.empty_array_vols') }}</td>
          </tr>
        </tbody>
      </table>
    </div>

    <h2 class="section-title">{{ t('main.unassigned_devices') }}</h2>
    <div class="table-wrap" style="margin-bottom:12px">
      <table class="dense">
        <thead>
          <tr>
            <th></th>
            <th>{{ t('main_extra.device') }}</th>
            <th>{{ t('common.name') }}</th>
            <th>{{ t('main_extra.th_kind') }}</th>
            <th>{{ t('main_extra.th_power') }}</th>
            <th>{{ t('main_extra.th_mount') }}</th>
            <th>{{ t('common.actions') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="d in unassigned" :key="d.id">
            <td><span class="led" :class="powerLed(d)"></span></td>
            <td class="mono">{{ d.device }}</td>
            <td><strong>{{ d.name }}</strong></td>
            <td><span class="badge" :class="kindBadge(d)">{{ kindLabel(d) }}</span></td>
            <td><span class="badge" :class="powerBadge(d)">{{ powerLabel(d.power_state) }}</span></td>
            <td class="mono" style="font-size:11px">
              <span v-if="!(d.volumes||[]).length" style="color:var(--sub)">{{ t('main_extra.not_mounted') }}</span>
              <div v-for="v in d.volumes || []" :key="v.mount">{{ v.mount }}</div>
            </td>
            <td class="ops">
              <button v-if="(d.actions||[]).includes('wake')" class="tiny primary" :disabled="busy" @click="power(d, 'wake')">{{ t('main_extra.act_wake_mount') }}</button>
              <button v-if="(d.actions||[]).includes('sleep')" class="tiny" :disabled="busy || d.system" @click="power(d, 'sleep')">{{ t('main_extra.act_sleep') }}</button>
              <button v-if="(d.actions||[]).includes('eject')" class="tiny danger" :disabled="busy || d.system" @click="power(d, 'eject')">{{ t('main.eject') }}</button>
            </td>
          </tr>
          <tr v-if="!unassigned.length">
            <td colspan="7" style="color:var(--sub)">{{ t('main_extra.empty_unassigned') }}</td>
          </tr>
        </tbody>
      </table>
    </div>

    <div class="tile" style="margin-bottom:12px;border-left:3px solid var(--accent)">
      <h3 style="margin:0 0 6px">{{ t('main.tip_title') }}</h3>
      <p style="font-size:12px;color:var(--sub);line-height:1.55;margin:0">
        {{ t('main.tip_body') }}
      </p>
    </div>

    <h2 class="section-title">{{ t('main.power') }}</h2>
    <div class="table-wrap">
      <table class="dense">
        <thead>
          <tr>
            <th></th>
            <th>{{ t('main_extra.device') }}</th>
            <th>{{ t('common.name') }}</th>
            <th>{{ t('main_extra.th_kind') }}</th>
            <th>{{ t('main_extra.protocol') }}</th>
            <th>{{ t('dashboard.col_capacity') }}</th>
            <th>{{ t('main_extra.power_state') }}</th>
            <th>{{ t('main_extra.mounted_vols') }}</th>
            <th>{{ t('common.actions') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="d in powerDisks" :key="d.id">
            <td>
              <span
                class="led"
                :class="powerLed(d)"
                :title="d.power_state"
              ></span>
            </td>
            <td class="mono">{{ d.device }}</td>
            <td>
              <strong>{{ d.name }}</strong>
              <div class="sub" style="font-size:11px">{{ d.hint }}</div>
            </td>
            <td>
              <span class="badge" :class="kindBadge(d)">{{ kindLabel(d) }}</span>
            </td>
            <td>{{ d.protocol || '—' }}</td>
            <td>{{ d.size_gb != null ? d.size_gb + ' GB' : '—' }}</td>
            <td>
              <span class="badge" :class="powerBadge(d)">{{ powerLabel(d.power_state) }}</span>
            </td>
            <td class="mono" style="font-size:11px">
              <div v-for="v in d.volumes || []" :key="v.mount">{{ v.mount }}</div>
              <span v-if="!(d.volumes||[]).length" style="color:var(--sub)">—</span>
            </td>
            <td class="ops">
              <button
                v-if="(d.actions||[]).includes('sleep')"
                class="tiny"
                :disabled="busy || d.system"
                @click="power(d, 'sleep')"
              >{{ t('main.sleep') }}</button>
              <button
                v-if="(d.actions||[]).includes('wake')"
                class="tiny primary"
                :disabled="busy"
                @click="power(d, 'wake')"
              >{{ t('main.wake') }}</button>
              <button
                v-if="(d.actions||[]).includes('eject')"
                class="tiny danger"
                :disabled="busy || d.system"
                @click="power(d, 'eject')"
              >{{ t('main.eject') }}</button>
              <span v-if="!(d.actions||[]).length" class="sub">—</span>
            </td>
          </tr>
          <tr v-if="!powerDisks.length">
            <td colspan="9" style="color:var(--sub)">{{ t('main_extra.empty_disks') }}</td>
          </tr>
        </tbody>
      </table>
    </div>
    <pre v-if="lastMsg" style="margin:8px 0 12px;font-size:11px;white-space:pre-wrap;background:var(--bg);padding:8px;border-radius:4px;max-height:120px;overflow:auto" role="status" aria-live="polite">{{ lastMsg }}</pre>

    <h2 class="section-title">{{ t('main.smart') }}</h2>
    <div class="table-wrap">
      <table class="dense">
        <thead>
          <tr>
            <th></th>
            <th>{{ t('main_extra.device') }}</th>
            <th>{{ t('main_extra.model') }}</th>
            <th>{{ t('main_extra.protocol') }}</th>
            <th>{{ t('main_extra.temp') }}</th>
            <th>{{ t('main_extra.health') }}</th>
            <th>{{ t('main_extra.wear') }}</th>
            <th>{{ t('main_extra.written') }}</th>
            <th>{{ t('main_extra.power_on') }}</th>
            <th>{{ t('dashboard.col_capacity') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="d in data?.disks || []" :key="d.id">
            <td><span class="led" :class="d.smart?.health === 'PASSED' || d.smart ? 'on' : (d.error ? 'err' : 'off')"></span></td>
            <td class="mono">{{ d.device || d.id }}</td>
            <td>
              <strong>{{ d.name || d.id }}</strong>
              <div class="mono" style="color:var(--sub)">{{ d.smart?.model || d.smart?.serial || '' }}</div>
            </td>
            <td>{{ d.protocol || '—' }}{{ d.ssd ? ' · SSD' : '' }}</td>
            <td>{{ d.smart?.temp || '—' }}</td>
            <td>
              <span class="badge" :class="d.smart?.health === 'PASSED' ? 'ok' : ''">
                {{ d.smart?.health || (d.error ? 'N/A' : '—') }}
              </span>
            </td>
            <td>{{ d.smart?.wear || '—' }}</td>
            <td>{{ d.smart?.written || '—' }}</td>
            <td class="mono">{{ d.smart?.power_on || '—' }}</td>
            <td>{{ d.size || '—' }}</td>
          </tr>
        </tbody>
      </table>
    </div>

    <h2 class="section-title">{{ t('main.volumes') }}</h2>
    <div class="table-wrap">
      <table class="dense">
        <thead>
          <tr>
            <th>{{ t('dashboard.col_mount') }}</th>
            <th>{{ t('main_extra.disk') }}</th>
            <th>{{ t('main_extra.th_fs') }}</th>
            <th>{{ t('main_extra.th_kind') }}</th>
            <th>{{ t('main_extra.th_total') }}</th>
            <th>{{ t('main_extra.th_used') }}</th>
            <th>{{ t('main_extra.th_avail') }}</th>
            <th>{{ t('main_extra.th_pct') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="v in data?.volumes || []" :key="v.mount">
            <td class="mono"><strong>{{ v.mount }}</strong></td>
            <td class="mono">{{ v.disk_id || '—' }}</td>
            <td class="mono">{{ v.filesystem }}</td>
            <td>
              <span class="badge accent">{{ v.kind }}</span>
              <span v-if="v.disk_id && sharedDiskIds.has(v.disk_id)" class="badge warn">{{ t('main_extra.shared') }}</span>
            </td>
            <td>{{ v.total_gb }} GB</td>
            <td>{{ v.used_gb }} GB</td>
            <td>{{ v.avail_gb }} GB</td>
            <td style="min-width:120px">
              <strong :style="{ color: v.pct >= 90 ? 'var(--down)' : (v.pct >= 75 ? 'var(--warn)' : 'inherit') }">{{ v.pct }}%</strong>
              <div class="pct-bar" :class="v.pct>=90?'danger':v.pct>=75?'warn':''" style="margin-top:3px">
                <i :style="{ width: v.pct + '%' }"></i>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- Disk management (diskutil) -->
    <h2 class="section-title">{{ t('main_extra.manage') }}</h2>
    <div class="tile" style="margin-bottom:10px;border-left:3px solid var(--accent)">
      <p style="font-size:12px;color:var(--sub);line-height:1.55;margin:0">
        {{ t('main_extra.manage_hint') }} {{ data?.managed?.hint || '' }}
      </p>
    </div>
    <div class="toolbar">
      <label style="font-size:12px;color:var(--sub);display:flex;align-items:center;gap:6px">
        <input type="checkbox" v-model="showSystemVols" /> {{ t('main_extra.show_system') }}
      </label>
      <button @click="refresh" :disabled="loading || busy">{{ t('main_extra.refresh_list') }}</button>
    </div>
    <div class="table-wrap">
      <table class="dense">
        <thead>
          <tr>
            <th>{{ t('main_extra.device') }}</th>
            <th>{{ t('common.name') }}</th>
            <th>FS</th>
            <th>{{ t('dashboard.col_capacity') }}</th>
            <th>{{ t('dashboard.col_mount') }}</th>
            <th>{{ t('common.actions') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="v in managedVols" :key="v.id">
            <td class="mono">
              <strong>{{ v.id }}</strong>
              <div class="sub" style="font-size:10px" v-if="v.is_whole">{{ t('main_extra.whole') }}</div>
              <div class="sub" style="font-size:10px" v-else-if="v.whole_disk">∈ {{ v.whole_disk }}</div>
            </td>
            <td>
              {{ v.volume_name || v.name }}
              <span v-if="v.system" class="badge down">{{ t('main_extra.system') }}</span>
            </td>
            <td class="mono">{{ v.fs || '—' }}</td>
            <td>{{ v.size_gb != null ? v.size_gb + ' GB' : '—' }}</td>
            <td class="mono" style="font-size:11px">
              <span v-if="v.mount">{{ v.mount }}</span>
              <span v-else style="color:var(--sub)">{{ t('main_extra.not_mounted') }}</span>
            </td>
            <td class="ops">
              <button v-if="(v.actions||[]).includes('mount')" class="tiny primary" :disabled="busy" @click="manage(v, 'mount')">{{ t('main_extra.mount') }}</button>
              <button v-if="(v.actions||[]).includes('unmount')" class="tiny" :disabled="busy" @click="manage(v, 'unmount')">{{ t('main_extra.unmount') }}</button>
              <button v-if="(v.actions||[]).includes('mountDisk')" class="tiny primary" :disabled="busy" @click="manage(v, 'mountDisk')">{{ t('main_extra.mount_disk') }}</button>
              <button v-if="(v.actions||[]).includes('unmountDisk')" class="tiny" :disabled="busy" @click="manage(v, 'unmountDisk')">{{ t('main_extra.unmount_disk') }}</button>
              <button v-if="(v.actions||[]).includes('eject')" class="tiny" :disabled="busy" @click="manage(v, 'eject')">{{ t('main.eject') }}</button>
              <button v-if="(v.actions||[]).includes('rename')" class="tiny" :disabled="busy" @click="openRename(v)">{{ t('main_extra.rename') }}</button>
              <button v-if="(v.actions||[]).includes('eraseVolume')" class="tiny danger" :disabled="busy" @click="openFormat(v, false)">{{ t('main_extra.format') }}</button>
              <button v-if="(v.actions||[]).includes('eraseDisk')" class="tiny danger" :disabled="busy" @click="openFormat(v, true)">{{ t('main_extra.erase_disk') }}</button>
              <span v-if="!(v.actions||[]).length" class="sub">{{ t('main_extra.locked') }}</span>
            </td>
          </tr>
          <tr v-if="!managedVols.length">
            <td colspan="6" style="color:var(--sub)">{{ t('main_extra.no_vols') }}</td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- Rename modal -->
    <div ref="renamePanel" v-if="renameTarget" class="modal-bg" @click.self="renameTarget=null" role="presentation">
      <div class="modal" style="max-width:420px" role="dialog" aria-modal="true" aria-labelledby="array-rename-title">
        <div class="row" style="margin-bottom:10px">
          <span id="array-rename-title" class="name">{{ t('main_extra.rename') }} · {{ renameTarget.id }}</span>
          <button class="tiny" @click="renameTarget=null">{{ t('common.close') }}</button>
        </div>
        <label style="font-size:12px;color:var(--sub)">{{ t('main_extra.new_name') }}</label>
        <input v-model="renameName" type="text" style="width:100%;margin:8px 0 12px" @keyup.enter="doRename" :aria-label="t('main_extra.new_name')" />
        <div class="btns">
          <button class="primary" :disabled="busy || !renameName.trim()" @click="doRename">{{ t('common.confirm') }}</button>
          <button @click="renameTarget=null">{{ t('common.cancel') }}</button>
        </div>
      </div>
    </div>

    <!-- Format modal -->
    <div ref="formatPanel" v-if="formatTarget" class="modal-bg" @click.self="formatTarget=null" role="presentation">
      <div class="modal" style="max-width:480px" role="dialog" aria-modal="true" aria-labelledby="array-format-title">
        <div class="row" style="margin-bottom:10px">
          <span id="array-format-title" class="name" style="color:var(--down)">
            {{ formatWhole ? t('main_extra.erase_disk') : t('main_extra.format') }} · {{ formatTarget.id }}
          </span>
          <button class="tiny" @click="formatTarget=null">{{ t('common.close') }}</button>
        </div>
        <p style="font-size:12px;color:var(--down);line-height:1.5;margin-bottom:10px">
          ⚠️ {{ t('main_extra.format_warn') }}
        </p>
        <div class="form-grid-m">
          <label>{{ t('main_extra.fs') }}</label>
          <select v-model="formatFs" :aria-label="t('main_extra.fs')">
            <option v-for="f in fsTypes" :key="f" :value="f">{{ f }}</option>
          </select>
          <label>{{ t('main_extra.vol_name') }}</label>
          <input v-model="formatName" type="text" :aria-label="t('main_extra.vol_name')" />
          <label>{{ t('main_extra.confirm') }}</label>
          <input v-model="formatConfirm" type="text" :placeholder="t('main_extra.format_type_ph', { name: formatTarget.volume_name || formatTarget.id })"  :aria-label="t('main_extra.format_type_ph', { name: formatTarget.volume_name || formatTarget.id })"/>
        </div>
        <p style="font-size:11px;color:var(--sub);margin:8px 0 12px">
          {{ t('main_extra.format_confirm_hint', { name: formatTarget.volume_name || formatTarget.id }) }}
        </p>
        <div class="btns">
          <button class="danger" :disabled="busy || !canFormat" @click="doFormat">{{ t('main_extra.format_ok') }}</button>
          <button @click="formatTarget=null">{{ t('common.cancel') }}</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, inject, onMounted, onUnmounted, ref } from 'vue'
import { getStorage } from '../api/client'
import { injectI18n } from '../i18n'
import { useDismissable } from '../composables/useDismissable'

const toast = inject('toast')
const { t } = injectI18n()
const data = ref(null)
const loading = ref(false)
const busy = ref(false)
const lastMsg = ref('')
const showSystemVols = ref(false)
const renameTarget = ref(null)
const renamePanel = ref(null)
const renameName = ref('')
const formatTarget = ref(null)
const formatPanel = ref(null)
const formatWhole = ref(false)
const formatFs = ref('ExFAT')
const formatName = ref('')
const formatConfirm = ref('')
let timer = null

const powerDisks = computed(() => data.value?.power_disks || [])
const arrayDevices = computed(() => data.value?.array?.devices || (data.value?.volumes || []).filter(v =>
  v.kind === 'system' || v.kind === 'external'
))
const sharedDiskIds = computed(() => {
  const s = new Set()
  for (const g of data.value?.array?.capacity_groups || []) {
    if (g.mode === 'shared_pool' && g.disk_id) s.add(g.disk_id)
  }
  return s
})
const managedVols = computed(() => {
  const list = data.value?.managed?.volumes || []
  if (showSystemVols.value) return list
  return list.filter(v => !v.system)
})
const fsTypes = computed(() => data.value?.managed?.fs_types || ['APFS', 'ExFAT', 'JHFS+', 'MS-DOS'])
const canFormat = computed(() => {
  if (!formatTarget.value) return false
  const expect = (formatTarget.value.volume_name || formatTarget.value.id || '').trim()
  const got = formatConfirm.value.trim()
  return got && (got === expect || got === formatTarget.value.id)
})
// Unassigned: non-system disks that are offline, spun down, or have no volumes
const unassigned = computed(() => {
  return (powerDisks.value || []).filter(d => {
    if (d.system) return false
    const vols = d.volumes || []
    if (!vols.length) return true
    if (d.power_state === 'spun_down' || d.power_state === 'offline' || d.power_state === 'idle') return true
    return false
  })
})

function powerLed(d) {
  if (d.power_state === 'active') return 'on'
  if (d.power_state === 'spun_down' || d.power_state === 'offline') return 'off'
  if (d.power_state === 'idle') return 'warn'
  return 'off'
}
function powerLabel(s) {
  return ({ active: t('main_extra.power_active'), idle: t('main_extra.power_idle'), spun_down: t('main_extra.power_spun_down'), offline: t('main_extra.power_offline') })[s] || t('main_extra.power_unknown')
}
function powerBadge(d) {
  if (d.power_state === 'active') return 'ok'
  if (d.power_state === 'spun_down') return 'warn'
  if (d.power_state === 'offline') return 'down'
  return ''
}
function kindLabel(d) {
  if (d.system) return t('main_extra.kind_system')
  if (d.kind === 'removable') return t('main_extra.kind_removable')
  if (d.rotational || d.kind === 'hdd' || d.kind === 'external_hdd') return t('main_extra.kind_hdd')
  if (d.ssd) return 'SSD'
  return d.kind || t('main_extra.kind_disk')
}
function kindBadge(d) {
  if (d.system) return 'down'
  if (d.rotational || d.kind === 'hdd' || d.kind === 'external_hdd') return 'warn'
  if (d.ssd) return 'ok'
  return 'accent'
}

async function refresh() {
  loading.value = true
  try { data.value = await getStorage() }
  catch (e) { toast('❌ ' + e.message) }
  loading.value = false
}

async function power(d, action) {
  const labels = { sleep: t('main_extra.act_sleep'), wake: t('main_extra.act_wake'), eject: t('main_extra.act_eject') }
  const tip = {
    sleep: t('main_extra.confirm_sleep', { id: d.id }),
    wake: t('main_extra.confirm_wake', { id: d.id }),
    eject: t('main_extra.confirm_eject', { id: d.id }),
  }
  if (!confirm(tip[action] || labels[action])) return
  busy.value = true
  lastMsg.value = t('main_extra.running')
  try {
    const r = await fetch(`/api/storage/disks/${encodeURIComponent(d.id)}/power`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action }),
    })
    const j = await r.json().catch(() => ({}))
    if (!r.ok) throw new Error(j.detail || j.message || t('main_extra.failed'))
    lastMsg.value = (j.message || '') + (j.log ? '\n' + (j.log || []).join('\n') : '')
    toast(j.ok ? `✅ ${labels[action]} ${d.id}` : `❌ ${j.message}`)
    setTimeout(refresh, 1000)
  } catch (e) {
    toast('❌ ' + e.message)
    lastMsg.value = e.message
  }
  busy.value = false
}

async function manage(v, action) {
  const tips = {
    mount: `${t('main_extra.mount')} ${v.id}?`,
    unmount: `${t('main_extra.unmount')} ${v.id} (${v.mount || t('main_extra.not_mounted')})?`,
    mountDisk: `${t('main_extra.mount_disk')} ${v.id}?`,
    unmountDisk: `${t('main_extra.unmount_disk')} ${v.id}?`,
    eject: `${t('main.eject')} ${v.id}?`,
  }
  if (!confirm(tips[action] || action)) return
  busy.value = true
  lastMsg.value = t('main_extra.running')
  try {
    const r = await fetch(`/api/storage/manage/${encodeURIComponent(v.id)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action }),
    })
    const j = await r.json().catch(() => ({}))
    if (!r.ok) throw new Error(typeof j.detail === 'string' ? j.detail : (j.message || t('main_extra.failed')))
    lastMsg.value = (j.message || '') + (j.log ? '\n' + (j.log || []).join('\n') : '')
    toast(j.ok ? `✅ ${action} ${v.id}` : `❌ ${j.message}`)
    setTimeout(refresh, 800)
  } catch (e) {
    toast('❌ ' + e.message)
    lastMsg.value = e.message
  }
  busy.value = false
}

function openRename(v) {
  renameTarget.value = v
  renameName.value = v.volume_name || v.name || ''
}
async function doRename() {
  if (!renameTarget.value || !renameName.value.trim()) return
  busy.value = true
  try {
    const r = await fetch(`/api/storage/manage/${encodeURIComponent(renameTarget.value.id)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'rename', name: renameName.value.trim() }),
    })
    const j = await r.json().catch(() => ({}))
    if (!r.ok) throw new Error(typeof j.detail === 'string' ? j.detail : (j.message || t('main_extra.failed')))
    toast(j.ok ? '✅ ' + t('main_extra.renamed') : `❌ ${j.message}`)
    lastMsg.value = j.message || ''
    renameTarget.value = null
    setTimeout(refresh, 800)
  } catch (e) {
    toast('❌ ' + e.message)
  }
  busy.value = false
}

function openFormat(v, whole) {
  formatTarget.value = v
  formatWhole.value = whole
  formatFs.value = whole ? 'APFS' : (v.fs && String(v.fs).toLowerCase().includes('fat') ? 'ExFAT' : 'ExFAT')
  formatName.value = v.volume_name || 'UNTITLED'
  formatConfirm.value = ''
}
async function doFormat() {
  if (!formatTarget.value || !canFormat.value) return
  if (!confirm(t('main_extra.format_last_confirm'))) return
  busy.value = true
  lastMsg.value = t('main_extra.formatting')
  try {
    const r = await fetch(`/api/storage/manage/${encodeURIComponent(formatTarget.value.id)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        action: formatWhole.value ? 'eraseDisk' : 'eraseVolume',
        name: formatName.value.trim() || 'UNTITLED',
        fs: formatFs.value,
        confirm: true,
        confirm_name: formatConfirm.value.trim(),
      }),
    })
    const j = await r.json().catch(() => ({}))
    if (!r.ok) throw new Error(typeof j.detail === 'string' ? j.detail : (j.message || t('main_extra.failed')))
    lastMsg.value = (j.message || '') + (j.log ? '\n' + (j.log || []).join('\n') : '')
    toast(j.ok ? '✅ ' + t('main_extra.formatted') : `❌ ${j.message}`)
    formatTarget.value = null
    setTimeout(refresh, 1200)
  } catch (e) {
    toast('❌ ' + e.message)
    lastMsg.value = e.message
  }
  busy.value = false
}

onMounted(() => {
  refresh()
  timer = setInterval(() => {
    if (typeof document !== 'undefined' && document.hidden) return
    refresh()
  }, 45000)
})
onUnmounted(() => clearInterval(timer))


// Escape dismisses each dialog, focus returns to whatever opened it, and Tab
// cannot wander to the page behind the overlay.
useDismissable(renameTarget, () => { renameTarget.value = null }, renamePanel)
useDismissable(formatTarget, () => { formatTarget.value = null }, formatPanel)
</script>

<style scoped>
.form-grid-m {
  display: grid;
  grid-template-columns: 100px 1fr;
  gap: 8px 12px;
  align-items: center;
  font-size: 13px;
}
.form-grid-m label { color: var(--sub); font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: .3px; }
.form-grid-m input, .form-grid-m select { width: 100%; }
@media (max-width: 640px) {
  .form-grid-m { grid-template-columns: 1fr; }
  .form-grid-m label { margin-bottom: -4px; }
}
</style>
