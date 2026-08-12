<template>
  <div>
    <div class="page-title">
      <h1>{{ t('pages.main') }}</h1>
      <span class="meta">{{ t('pages.main_meta') }}</span>
    </div>
    <div class="toolbar">
      <button class="primary" @click="refresh" :disabled="loading || busy">{{ t('common.refresh') }}</button>
      <button @click="openSmart" :disabled="smartLoading">{{ t('main.smart_btn') }}</button>
      <span class="meta" style="color:var(--sub)">
        {{ t('main_extra.summary_counts', { disks: (data?.power_disks || []).length, vols: data?.volumes?.length || 0 }) }}
      </span>
      <span v-if="data?.array" class="badge" :class="data.array.status === 'started' ? 'ok' : 'warn'">
        Array {{ data.array.status }}
      </span>
    </div>

    <!-- Storage is the page where a false empty state is most alarming: five
         separate tables would each claim there were no disks, no volumes and no
         SMART data while the first scan was still running. Gate all of them on
         one latch rather than per table, so the page fills in as a unit. -->
    <template v-if="!loaded">
      <SkeletonLoader variant="tiles" :rows="4" :span="3" :tile-height="40" style="margin-bottom:12px" />
      <SkeletonLoader :cols="9" :rows="5" />
    </template>

    <template v-else>
    <!-- Without this a failed scan fell through to the tables' own empty rows and
         reported no disks, no volumes and no SMART data on a storage page. -->
    <LoadFailure v-if="loadError" :detail="loadError" :retry="refresh" :busy="loading || busy" />
    <!-- Unraid-style array summary -->
    <div class="dash-grid" style="margin-bottom:12px" v-if="data?.array || data?.totals">
      <div class="tile span-3">
        <h3>{{ t('main.array_status') }}</h3>
        <div
          class="v"
          :style="{ fontSize: '16px', color: data?.array?.status === 'started' ? 'var(--ok)' : 'var(--warn)' }"
        >{{ data?.array?.status || t('network.unknown') }}</div>
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
          <tr v-if="!arrayDevices.length && !loadError">
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
          <tr v-if="!unassigned.length && !loadError && !pendingFull">
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
          <tr v-if="!powerDisks.length && !loadError && !pendingFull">
            <td colspan="9" style="color:var(--sub)">{{ t('main_extra.empty_disks') }}</td>
          </tr>
        </tbody>
      </table>
    </div>
    <pre v-if="lastMsg" style="margin:8px 0 12px;font-size:11px;white-space:pre-wrap;background:var(--bg);padding:8px;border-radius:4px;max-height:120px;overflow:auto" role="status" aria-live="polite">{{ lastMsg }}</pre>

    <h2 class="section-title">{{ t('main.smart') }}</h2>

    <!-- SMART health notice.  Three tiers, and the split between them is the whole
         point.  Red is reserved for what the drive itself calls a failure: overall
         health not PASSED, unreadable-now sectors, or a Pre-fail attribute that has
         crossed the vendor's own threshold.  A raw counter that is merely non-zero
         while the drive still answers PASSED is amber -- this host's external SSD
         reports 55 reallocated sectors against a normalised 100 with a threshold of
         10, and painting that "about to fail" on day one is how an operator learns
         to ignore disk alerts.  Unreadable SMART is grey: macOS has no ATA/SCSI
         passthrough over USB or Thunderbolt bridges, so unknown is not broken.
         Grading lives in smartGrade(), which mirrors hub/alerts.py _smart_reasons()
         so this page and the alert list can never disagree about the same disk. -->
    <div v-if="smartNotice.down.length" class="tile" style="margin-bottom:8px;border-left:3px solid var(--down)">
      <h3 style="margin:0 0 6px">
        <span class="led err" style="margin-right:6px"></span>{{ t('main_extra.smart_bad_title', { n: smartNotice.down.length }) }}
      </h3>
      <div v-for="d in smartNotice.down" :key="d.id" style="font-size:12px;line-height:1.6">
        <strong class="mono">{{ d.label }}</strong>
        <span style="color:var(--sub)"> · {{ d.reasons }}</span>
      </div>
    </div>
    <div v-if="smartNotice.warn.length" class="tile" style="margin-bottom:8px;border-left:3px solid var(--warn)">
      <h3 style="margin:0 0 6px">
        <span class="led warn" style="margin-right:6px"></span>{{ t('main_extra.smart_watch_title', { n: smartNotice.warn.length }) }}
      </h3>
      <div v-for="d in smartNotice.warn" :key="d.id" style="font-size:12px;line-height:1.6">
        <strong class="mono">{{ d.label }}</strong>
        <span style="color:var(--sub)"> · {{ d.reasons }}</span>
      </div>
      <p style="font-size:11px;color:var(--sub);line-height:1.55;margin:6px 0 0">{{ t('main_extra.smart_watch_hint') }}</p>
    </div>
    <div v-if="smartNotice.unknown.length" class="tile" style="margin-bottom:8px;border-left:3px solid var(--line)">
      <h3 style="margin:0 0 6px;color:var(--sub)">
        <span class="led off" style="margin-right:6px"></span>{{ t('main_extra.smart_unknown_title', { n: smartNotice.unknown.length }) }}
      </h3>
      <div v-for="d in smartNotice.unknown" :key="d.id" style="font-size:12px;line-height:1.6">
        <strong class="mono">{{ d.label }}</strong>
        <span style="color:var(--sub)"> · {{ d.reasons }}</span>
      </div>
      <p style="font-size:11px;color:var(--sub);line-height:1.55;margin:6px 0 0">{{ t('main_extra.smart_unknown_hint') }}</p>
    </div>

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
            <!-- Was `d.smart ? 'on' : (d.error ? 'err' : 'off')`, which lit green for
                 a drive reporting FAILED (it has a smart dict) and red for a healthy
                 external disk macOS cannot read (it has an error) -- both backwards.
                 The LED now follows the same grade as the notice above. -->
            <td><span class="led" :class="smartLed(d)" :title="smartGrade(d)"></span></td>
            <td class="mono">{{ d.device || d.id }}</td>
            <td>
              <strong>{{ d.name || d.id }}</strong>
              <div class="mono" style="color:var(--sub)">{{ d.smart?.model || d.smart?.serial || '' }}</div>
            </td>
            <td>{{ d.protocol || '—' }}{{ d.ssd ? ' · SSD' : '' }}</td>
            <td>{{ d.smart?.temp || '—' }}</td>
            <td>
              <span class="badge" :class="smartBadge(d)">
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
          <tr v-if="!managedVols.length && !loadError && !pendingFull">
            <td colspan="6" style="color:var(--sub)">{{ t('main_extra.no_vols') }}</td>
          </tr>
        </tbody>
      </table>
    </div>
    </template>

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
        <div class="field-grid">
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

    <!-- SMART modal -->
    <div ref="smartPanel" v-if="smartModal" class="modal-bg" @click.self="smartModal=false" role="presentation">
      <div class="modal" style="max-width:920px" role="dialog" aria-modal="true" aria-labelledby="smart-modal-title">
        <div class="row" style="margin-bottom:10px">
          <span id="smart-modal-title" class="name">{{ t('main_extra.smart_title') }}</span>
          <button class="tiny" @click="smartModal=false">{{ t('common.close') }}</button>
        </div>
        <div class="sub" style="margin-bottom:10px;display:flex;gap:12px;flex-wrap:wrap;font-size:11px">
          <span v-if="smartData?.ts">{{ smartData.ts }}</span>
          <span :style="{ color: smartData?.passwordless_sudo ? 'var(--ok)' : 'var(--warn)' }">
            {{ smartData?.passwordless_sudo ? t('main_extra.smart_sudo_ok') : t('main_extra.smart_sudo_no') }}
          </span>
          <span :style="{ color: smartData?.smartctl_installed ? 'var(--ok)' : 'var(--down)' }">
            {{ smartData?.smartctl_installed ? t('main_extra.smartctl_yes') : t('main_extra.smartctl_no') }}
          </span>
        </div>
        <div v-if="smartLoading" style="text-align:center;padding:20px;color:var(--sub)">{{ t('main_extra.scanning') }}</div>
        <div v-else>
          <div v-if="!smartMerged.length" style="color:var(--sub)">{{ t('main_extra.smart_no_devices') }}</div>
          <div v-else class="table-wrap" style="max-height:400px;overflow:auto">
            <table class="dense">
              <thead>
                <tr>
                  <th>{{ t('main_extra.device') }}</th>
                  <th>{{ t('main_extra.model') }}</th>
                  <th>{{ t('main_extra.protocol') }}</th>
                  <th>{{ t('main_extra.temp') }}</th>
                  <th>{{ t('main_extra.health') }}</th>
                  <th>{{ t('main_extra.wear') }}</th>
                  <th>{{ t('main_extra.power_on') }}</th>
                  <th>{{ t('main_extra.smart_caps') }}</th>
                  <th>{{ t('common.actions') }}</th>
                </tr>
              </thead>
              <tbody>
                <template v-for="m in smartMerged" :key="m.id">
                <tr>
                  <td class="mono">
                    <strong>{{ m.id }}</strong>
                    <div v-if="m.error" class="sub" style="font-size:10px;color:var(--warn)">{{ m.error }}</div>
                  </td>
                  <td>
                    <strong>{{ m.smart?.model || m.smart?.serial || '—' }}</strong>
                    <div class="sub mono" style="font-size:10px">{{ m.size || '—' }}</div>
                  </td>
                  <td style="font-size:11px">{{ m.protocol || '—' }}{{ m.ssd ? ' · SSD' : '' }}</td>
                  <td>{{ m.smart?.temp || '—' }}</td>
                  <td>
                    <span class="badge" :class="m.smart?.health === 'PASSED' ? 'ok' : (m.smart?.health ? 'warn' : '')">
                      {{ m.smart?.health || '—' }}
                    </span>
                  </td>
                  <td>{{ m.smart?.wear || '—' }}</td>
                  <td class="mono">{{ m.smart?.power_on || '—' }}</td>
                  <td style="font-size:11px">
                    <span v-if="m.caps?.supported?.length">{{ m.caps.supported.join(', ') }}</span>
                    <span v-else style="color:var(--sub)">{{ t('main_extra.smart_unsupported') }}</span>
                    <div v-if="m.caps?.reason" class="sub" style="font-size:10px;color:var(--warn)">{{ m.caps.reason }}</div>
                    <div v-if="m.progress?.running" class="sub" style="font-size:10px;color:var(--ok)">{{ t('main_extra.smart_running', { pct: m.progress.percent_remaining || '?' }) }}</div>
                    <div v-if="m.lastResult" class="sub" style="font-size:10px">{{ m.lastResult }} · {{ m.logCount || 0 }} {{ t('main_extra.smart_logs') }}</div>
                  </td>
                  <td class="ops">
                    <button v-if="m.smart?.attrs?.length" class="tiny" @click="toggleSmartDetail(m.id)">
                      {{ smartExpanded.has(m.id) ? '▲' : '▼' }} {{ m.smart.attrs.length }}
                    </button>
                    <template v-if="m.caps?.supported?.length">
                      <button
                        v-for="k in m.caps.supported.filter(x => x !== 'offline')" :key="k"
                        class="tiny primary"
                        :disabled="busy || smartTestBusy"
                        @click="runSmartTest(m, k)"
                      >{{ smartTestLabel(k) }}</button>
                    </template>
                  </td>
                </tr>
                <tr v-if="smartExpanded.has(m.id) && m.smart?.attrs?.length">
                  <td :colspan="9" style="padding:0;background:var(--bg2,#f6f6f6)">
                    <div style="padding:6px 10px;max-height:300px;overflow:auto">
                      <table class="dense" style="width:100%">
                        <thead>
                          <tr>
                            <th style="font-size:10px;width:40px">ID</th>
                            <th style="font-size:10px">{{ t('common.name') }}</th>
                            <th style="font-size:10px" v-if="m.smart.attrs[0]?.raw !== undefined">{{ t('main_extra.smart_value') }}</th>
                            <th style="font-size:10px" v-if="m.smart.attrs[0]?.worst !== undefined">{{ t('main_extra.smart_worst') }}</th>
                            <th style="font-size:10px" v-if="m.smart.attrs[0]?.thresh !== undefined">{{ t('main_extra.smart_thresh') }}</th>
                            <th style="font-size:10px" v-if="m.smart.attrs[0]?.type !== undefined">{{ t('main_extra.smart_attr_type') }}</th>
                            <th style="font-size:10px">{{ m.smart.attrs[0]?.raw !== undefined ? t('main_extra.smart_raw') : t('common.status') }}</th>
                          </tr>
                        </thead>
                        <tbody>
                          <tr v-for="a in m.smart.attrs" :key="a.id">
                            <td class="mono" style="font-size:10px">{{ a.id }}</td>
                            <td style="font-size:11px">{{ a.name }}</td>
                            <td v-if="a.raw !== undefined" class="mono" style="font-size:10px">{{ a.value }}</td>
                            <td v-if="a.worst !== undefined" class="mono" style="font-size:10px">{{ a.worst }}</td>
                            <td v-if="a.thresh !== undefined" class="mono" style="font-size:10px">{{ a.thresh }}</td>
                            <td v-if="a.type !== undefined" style="font-size:10px">
                              <span class="badge" :class="a.type === 'Pre-fail' ? 'warn' : ''" style="font-size:9px">{{ a.type }}</span>
                            </td>
                            <td class="mono" style="font-size:10px">{{ a.raw !== undefined ? a.raw : a.value }}</td>
                          </tr>
                        </tbody>
                      </table>
                    </div>
                  </td>
                </tr>
                </template>
              </tbody>
            </table>
          </div>
          <div v-if="smartData?.history?.length" style="margin-top:12px">
            <h4 style="font-size:12px;margin-bottom:6px">{{ t('main_extra.smart_history') }}</h4>
            <div class="table-wrap" style="max-height:160px;overflow:auto">
              <table class="dense">
                <thead>
                  <tr>
                    <th style="font-size:10px">{{ t('common.time') }}</th>
                    <th style="font-size:10px">{{ t('main_extra.device') }}</th>
                    <th style="font-size:10px">{{ t('main_extra.th_type') }}</th>
                    <th style="font-size:10px">{{ t('common.status') }}</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="(h, i) in smartData.history.slice(0, 15)" :key="i">
                    <td class="mono" style="font-size:10px">{{ h.ts ? new Date(h.ts * 1000).toLocaleString() : '—' }}</td>
                    <td class="mono" style="font-size:10px">{{ h.device || '—' }}</td>
                    <td style="font-size:10px">{{ h.kind || '—' }}</td>
                    <td>
                      <span class="badge" :class="h.ok ? 'ok' : 'warn'" style="font-size:10px">
                        {{ h.ok ? 'OK' : (h.error || h.message || 'Error') }}
                      </span>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, inject, onMounted, onUnmounted, ref } from 'vue'
import { getStorage, getThresholds, manageStorageDevice, setDiskPower, getSmartOverview, startSmartTest } from '../api/client'
import { injectI18n } from '../i18n'
import { startVisibleInterval } from '../lib/poll'
import { useDismissable } from '../composables/useDismissable'
import SkeletonLoader from '../components/SkeletonLoader.vue'
import LoadFailure from '../components/LoadFailure.vue'

const toast = inject('toast')
const { t } = injectI18n()
const data = ref(null)
const loading = ref(false)
const loaded = ref(false)
const loadError = ref('')
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
const smartModal = ref(false)
const smartPanel = ref(null)
const smartData = ref(null)
const smartLoading = ref(false)
const smartTestBusy = ref(false)
const smartExpanded = ref(new Set())
//: Same defaults as system_settings_svc.DEFAULT_THRESHOLDS.  Kept so the soft
//: checks still grade correctly before /api/settings/thresholds answers, and if it
//: never answers: a page that silently stopped warning about a 70°C disk because
//: one auxiliary request failed would be worse than one using the shipped limits.
const SMART_THRESHOLD_DEFAULTS = { smart_temp_c: 60, smart_wear_pct: 90, smart_spare_pct: 10 }
const smartThresholds = ref({ ...SMART_THRESHOLD_DEFAULTS })
let timer = null
const refreshTimers = new Set()
// Progressive first paint: the light overview (capacity + SMART) renders in
// ~300ms, then the full payload backfills power state and managed volumes.
// loadSeq guards that backfill so it can never overwrite a newer refresh.
const pendingFull = ref(false)
let loadSeq = 0

function scheduleRefresh(delay) {
  const id = setTimeout(() => {
    refreshTimers.delete(id)
    void refresh()
  }, delay)
  refreshTimers.add(id)
}

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

// Merge self-test capabilities (/api/smart) with SMART attributes (/api/storage disks)
const smartMerged = computed(() => {
  const testDevices = smartData.value?.devices || []
  const storageDisks = data.value?.disks || []
  const storageMap = new Map()
  for (const d of storageDisks) storageMap.set(d.id, d)
  const merged = testDevices.map(td => {
    const sd = storageMap.get(td.id)
    return {
      id: td.id, device: td.device,
      smart: sd?.smart || null, error: sd?.error || null,
      protocol: sd?.protocol, ssd: sd?.ssd, size: sd?.size,
      caps: td.capabilities, lastResult: td.last_result,
      logCount: td.log_count, failures: td.failures, progress: td.progress,
    }
  })
  const testIds = new Set(testDevices.map(d => d.id))
  for (const sd of storageDisks) {
    if (!testIds.has(sd.id)) {
      merged.push({
        id: sd.id, device: sd.device,
        smart: sd.smart || null, error: sd.error || null,
        protocol: sd.protocol, ssd: sd.ssd, size: sd.size,
        caps: null, lastResult: '', logCount: 0, failures: 0, progress: null,
      })
    }
  }
  return merged
})

/* SMART grading -- a port of hub/alerts.py `_smart_reasons`.
 *
 * Duplicated rather than derived from the alert list on purpose: the alerts
 * endpoint only reports disks whose level *changed* (edge-triggered, plus a
 * cooldown re-announce), so a disk that has been warning quietly for a week is not
 * in it, and this page has to be able to state the current condition of every disk
 * it lists.  The cost of the copy is that the two must stay in step; the reason
 * table below is ordered exactly like the Python one to make a drift visible.
 */

/** The number inside a smartctl field, or null when there isn't one.
 *
 * Nothing in the payload is a number: temperature arrives as "37 Celsius", wear
 * and spare as "0%" / "100%", the NVMe critical-warning bitmap as "0x00".  null
 * rather than 0 when nothing parses, because here "unreadable" and "zero" mean
 * opposite things -- 0 media errors is a healthy disk, an unparseable media-error
 * field is a disk we know nothing about, and only the first may read as fine.
 */
function smartNum(raw) {
  if (raw == null || typeof raw === 'boolean') return null
  if (typeof raw === 'number') return Number.isFinite(raw) ? raw : null
  const s = String(raw).trim()
  if (!s) return null
  // The critical-warning bitmap is printed in hex; a decimal scan would read
  // "0x02" (spare below threshold) as 0 and drop the warning silently.
  if (s.toLowerCase().startsWith('0x')) {
    const hex = Number.parseInt(s, 16)
    return Number.isNaN(hex) ? null : hex
  }
  const m = s.replace(/,/g, '').match(/-?\d+(?:\.\d+)?/)
  if (!m) return null
  const v = Number.parseFloat(m[0])
  return Number.isNaN(v) ? null : v
}

/** Split the tripped checks for one disk into [fatal, worth-watching]. */
function smartReasons(smart) {
  const th = smartThresholds.value
  const down = []
  const warn = []

  // The drive's own overall verdict, and the most authoritative signal there is:
  // the firmware has already weighed its attributes against the vendor's failure
  // thresholds.  Anything that is not PASSED/OK is fatal, "WARNING" included --
  // smartctl uses that word for a crossed vendor threshold, which is a different
  // thing from our own soft warn level below.
  const health = String(smart.health || '').trim()
  if (health && !['PASSED', 'OK'].includes(health.toUpperCase().replace(/!+$/, ''))) {
    down.push(t('main_extra.smart_r_health', { v: health }))
  }

  // Media errors are already data loss; a pending sector is one the drive tried to
  // read, could not, and has not remapped -- unreadable *now*.  Hence `> 0`.
  for (const field of ['media_errors', 'pending']) {
    const v = smartNum(smart[field])
    if (v != null && v > 0) down.push(t(`main_extra.smart_r_${field}`, { v: Math.round(v) }))
  }

  // The vendor's own pre-fail verdict from the attribute table.  This is what
  // separates red from amber: the raw counters alone are a bad severity signal, so
  // "crossed the threshold the vendor set" is the fatal test, and a non-zero raw
  // count is only the warn below.
  for (const attr of smart.attrs || []) {
    if (!attr || typeof attr !== 'object' || String(attr.type || '') !== 'Pre-fail') continue
    const value = smartNum(attr.value)
    // A threshold of 0 means the vendor declared no failure point for this
    // attribute, so there is nothing to be below.
    const thresh = smartNum(attr.thresh)
    if (value == null || thresh == null || thresh <= 0) continue
    if (value <= thresh) {
      down.push(t('main_extra.smart_r_prefail', {
        name: String(attr.name || attr.id || '?'),
        v: Math.round(value),
        lim: Math.round(thresh),
      }))
    }
  }

  // Reallocated sectors: real information, not an emergency by itself.  The drive
  // has already moved the data, and on an SSD with a large over-provisioning pool a
  // few dozen is unremarkable.  What matters is growth.  Stated as a bare count
  // because this same string is reused inside a red notice, where a reassuring
  // clause would contradict the headline.
  const realloc = smartNum(smart.reallocated)
  if (realloc != null && realloc > 0) {
    warn.push(t('main_extra.smart_r_reallocated', { v: Math.round(realloc) }))
  }

  // NVMe critical warning bitmap: any bit set is the controller reporting a fault
  // (spare exhausted, degraded reliability, read-only, over temperature).
  const crit = String(smart.critical_warning || '').trim()
  const critNum = smartNum(crit)
  if (critNum != null && critNum > 0) {
    down.push(t('main_extra.smart_r_critical_warning', { v: crit }))
  }

  // The soft checks, read from the configured thresholds.  `spare` gets `<=`:
  // Available Spare is the share of the over-provisioning pool still unused, so it
  // counts *down*, and comparing it like the others would make a disk with 2% spare
  // left look healthier than a brand-new one.
  for (const [leaf, source, limitKey, hotterIsWorse] of [
    ['temp', 'temp', 'smart_temp_c', true],
    ['wear', 'wear', 'smart_wear_pct', true],
    ['spare', 'available_spare', 'smart_spare_pct', false],
  ]) {
    const v = smartNum(smart[source])
    const lim = smartNum(th[limitKey])
    if (v == null || lim == null) continue
    if (hotterIsWorse ? v >= lim : v <= lim) {
      warn.push(t(`main_extra.smart_r_${leaf}`, { v: Math.round(v), lim: Math.round(lim) }))
    }
  }
  return [down, warn]
}

/** 'down' | 'warn' | 'ok' | 'unknown' for one disk from /api/storage or /api/smart. */
function smartGrade(d) {
  const smart = d?.smart
  // Unknown, not broken, and never red: macOS gives userspace no ATA/SCSI
  // passthrough over USB or Thunderbolt bridges, so smartctl answers "not
  // supported by device" for a perfectly healthy external disk.  The alert sweep
  // skips these entirely for the same reason.
  if (!smart || typeof smart !== 'object' || d.error) return 'unknown'
  const [down, warn] = smartReasons(smart)
  if (down.length) return 'down'
  if (warn.length) return 'warn'
  return 'ok'
}

function smartLed(d) {
  return { down: 'err', warn: 'warn', ok: 'on' }[smartGrade(d)] || 'off'
}

function smartBadge(d) {
  return { down: 'down', warn: 'warn', ok: 'ok' }[smartGrade(d)] || ''
}

//: The three tiers the notice renders, each disk listed once at the worst level it
//: earned -- a failing disk usually trips several checks at once, and five separate
//: lines for one disk would bury the other disks.
const smartNotice = computed(() => {
  const out = { down: [], warn: [], unknown: [] }
  for (const d of smartMerged.value) {
    const label = [d.smart?.model || d.name || d.id, d.device].filter(Boolean).join(' ')
    const grade = smartGrade(d)
    if (grade === 'unknown') {
      // Only when the read actually failed.  A /api/smart device with no matching
      // storage entry has neither SMART nor an error, and inventing a row for it
      // would report a problem nobody has.
      if (d.error) out.unknown.push({ id: d.id, label, reasons: d.error })
      continue
    }
    if (grade === 'ok') continue
    const [down, warn] = smartReasons(d.smart)
    out[grade].push({
      id: d.id,
      label,
      reasons: (grade === 'down' ? [...down, ...warn] : warn).join(' · '),
    })
  }
  return out
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
  loadSeq++
  loading.value = true
  try {
    data.value = await getStorage()
    loadError.value = ''
  } catch (e) {
    loadError.value = e.message || String(e)
    toast('❌ ' + e.message)
  } finally {
    loading.value = false
    loaded.value = true
  }
}

// First paint only: the polling interval and every manual refresh keep using
// refresh() above, so this staged path runs exactly once per page visit.
async function loadInitial() {
  const mySeq = ++loadSeq
  loading.value = true
  try {
    data.value = await getStorage(true)
    loadError.value = ''
  } catch (e) {
    loadError.value = e.message || String(e)
    toast('❌ ' + e.message)
  } finally {
    loading.value = false
    loaded.value = true
  }
  pendingFull.value = true
  try {
    const full = await getStorage()
    if (mySeq === loadSeq) {
      data.value = full
      loadError.value = ''
    }
  } catch (e) {
    // Keep the light data on screen; the next poll or a manual refresh retries
    // the full payload.  Only a total failure shows the load error.
    if (mySeq === loadSeq && !data.value) {
      loadError.value = e.message || String(e)
    }
  } finally {
    if (mySeq === loadSeq) pendingFull.value = false
  }
}

// Auxiliary and deliberately fire-and-forget.  These only retune the three soft
// checks, so a failure falls back to the shipped defaults instead of taking the
// storage page's failure banner with it -- and it is read once per visit rather
// than on the 45s poll, because an operator editing a threshold is reloading the
// settings page, not staring at this one.
async function loadSmartThresholds() {
  try {
    const th = await getThresholds()
    smartThresholds.value = {
      smart_temp_c: smartNum(th?.smart_temp_c) ?? SMART_THRESHOLD_DEFAULTS.smart_temp_c,
      smart_wear_pct: smartNum(th?.smart_wear_pct) ?? SMART_THRESHOLD_DEFAULTS.smart_wear_pct,
      smart_spare_pct: smartNum(th?.smart_spare_pct) ?? SMART_THRESHOLD_DEFAULTS.smart_spare_pct,
    }
  } catch {
    // Defaults already in place; nothing to report to the operator.
  }
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
    const j = await setDiskPower(d.id, action)
    lastMsg.value = (j.message || '') + (j.log ? '\n' + (j.log || []).join('\n') : '')
    toast(j.ok ? `✅ ${labels[action]} ${d.id}` : `❌ ${j.message}`)
    if (j.ok) scheduleRefresh(1000)
  } catch (e) {
    toast('❌ ' + e.message)
    lastMsg.value = e.message
  } finally {
    busy.value = false
  }
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
    const j = await manageStorageDevice(v.id, { action })
    lastMsg.value = (j.message || '') + (j.log ? '\n' + (j.log || []).join('\n') : '')
    toast(j.ok ? `✅ ${action} ${v.id}` : `❌ ${j.message}`)
    if (j.ok) scheduleRefresh(800)
  } catch (e) {
    toast('❌ ' + e.message)
    lastMsg.value = e.message
  } finally {
    busy.value = false
  }
}

function openRename(v) {
  renameTarget.value = v
  renameName.value = v.volume_name || v.name || ''
}
async function doRename() {
  if (!renameTarget.value || !renameName.value.trim()) return
  busy.value = true
  try {
    const j = await manageStorageDevice(renameTarget.value.id, {
      action: 'rename',
      name: renameName.value.trim(),
    })
    toast(j.ok ? '✅ ' + t('main_extra.renamed') : `❌ ${j.message}`)
    lastMsg.value = j.message || ''
    if (j.ok) {
      renameTarget.value = null
      scheduleRefresh(800)
    }
  } catch (e) {
    toast('❌ ' + e.message)
  } finally {
    busy.value = false
  }
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
    const j = await manageStorageDevice(formatTarget.value.id, {
      action: formatWhole.value ? 'eraseDisk' : 'eraseVolume',
      name: formatName.value.trim() || 'UNTITLED',
      fs: formatFs.value,
      confirm: true,
      confirm_name: formatConfirm.value.trim(),
    })
    lastMsg.value = (j.message || '') + (j.log ? '\n' + (j.log || []).join('\n') : '')
    toast(j.ok ? '✅ ' + t('main_extra.formatted') : `❌ ${j.message}`)
    if (j.ok) {
      formatTarget.value = null
      scheduleRefresh(1200)
    }
  } catch (e) {
    toast('❌ ' + e.message)
    lastMsg.value = e.message
  } finally {
    busy.value = false
  }
}

onMounted(() => {
  void loadInitial()
  void loadSmartThresholds()
  timer = startVisibleInterval(refresh, 45000)
})
onUnmounted(() => {
  if (timer) timer()
  for (const id of refreshTimers) clearTimeout(id)
  refreshTimers.clear()
})


// Escape dismisses each dialog, focus returns to whatever opened it, and Tab
// cannot wander to the page behind the overlay.
useDismissable(renameTarget, () => { renameTarget.value = null }, renamePanel)
useDismissable(formatTarget, () => { formatTarget.value = null }, formatPanel)
useDismissable(smartModal, () => { smartModal.value = false }, smartPanel)

async function openSmart() {
  smartModal.value = true
  smartLoading.value = true
  try {
    smartData.value = await getSmartOverview()
  } catch (e) {
    toast('❌ ' + e.message)
  } finally {
    smartLoading.value = false
  }
}

async function runSmartTest(dev, kind) {
  if (!confirm(`${t('main_extra.smart_start')} ${kind} → ${dev.id}?`)) return
  smartTestBusy.value = true
  try {
    const j = await startSmartTest(dev.device, kind)
    toast(j.ok ? `✅ ${t('main_extra.smart_started')}` : `❌ ${j.message || j.error}`)
    if (j.ok) {
      setTimeout(async () => {
        try { smartData.value = await getSmartOverview() } catch {}
      }, 3000)
    }
  } catch (e) {
    toast('❌ ' + e.message)
  } finally {
    smartTestBusy.value = false
  }
}

function toggleSmartDetail(diskId) {
  const s = new Set(smartExpanded.value)
  if (s.has(diskId)) s.delete(diskId)
  else s.add(diskId)
  smartExpanded.value = s
}

function smartTestLabel(kind) {
  const map = { short: t('main_extra.smart_short'), long: t('main_extra.smart_long'), extended: t('main_extra.smart_long'), conveyance: t('main_extra.smart_conveyance') }
  return `${t('main_extra.smart_start')} ${map[kind] || kind}`
}
</script>

<style scoped>
/* Layout comes from the global .field-grid; this page just keeps its label
   column at the width it has always had. */
</style>
