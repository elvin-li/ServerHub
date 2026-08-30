<template>
  <div>
    <!-- No visible page title on this layout; see Dashboard.vue. -->
    <h1 class="sr-only">{{ t('nav.main') }}</h1>
    <div class="toolbar">
      <button class="primary" @click="refresh" :disabled="loading || busy">{{ t('common.refresh') }}</button>
      <button @click="openSmart" :disabled="smartLoading">{{ t('main.smart_btn') }}</button>
      <span class="meta" style="color:var(--sub)">
        {{ t('main_extra.summary_counts', { disks: asArray(data?.power_disks).length, vols: asArray(data?.volumes).length }) }}
      </span>
      <span v-if="data?.array" class="badge" :class="data.array.status === 'started' ? 'ok' : 'warn'">
        {{ t('main_extra.array_state', { state: finiteText(data.array.status) }) }}
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
        <h2>{{ t('main.array_status') }}</h2>
        <div
          class="v"
          :style="{ fontSize: '16px', color: data?.array?.status === 'started' ? 'var(--ok-text)' : 'var(--warn-text)' }"
        >{{ finiteText(data?.array?.status, '') || t('network.unknown') }}</div>
        <div class="sub">{{ finiteN(data?.array?.system_count, 0) }} + {{ finiteN(data?.array?.data_count, 0) }}</div>
      </div>
      <div class="tile span-3">
        <h2>{{ t('main.capacity') }}</h2>
        <div class="v" style="font-size:16px">{{ finiteN(data?.array?.total_tb) }} <span style="font-size:12px;font-weight:500;color:var(--sub)">TB</span></div>
        <div class="sub">{{ t('common.used') }} {{ finiteN(data?.array?.used_tb) }} · {{ t('common.free') }} {{ finiteN(data?.array?.free_tb) }} TB</div>
      </div>
      <div class="tile span-3">
        <h2>{{ t('main.physical') }}</h2>
        <div class="v">{{ finiteN(data?.array?.disk_count, asArray(data?.disks).length) }}</div>
        <div class="sub">SMART</div>
      </div>
      <div class="tile span-3">
        <h2>{{ t('main.unassigned') }}</h2>
        <div class="v">{{ asArray(unassigned).length }}</div>
      </div>
    </div>

    <h2 class="section-title">{{ t('main.array_devices') }}</h2>
    <div class="table-wrap" style="margin-bottom:12px">
      <table class="dense fit-m">
        <thead>
          <tr>
            <!-- Status LED. The column is drawn as a dot, so its name has to be
                 spoken rather than shown or the row starts with a blank cell. -->
            <th><span class="sr-only">{{ t('common.status_led') }}</span></th>
            <th class="col-hide-m">{{ t('main_extra.role') }}</th>
            <th>{{ t('dashboard.col_mount') }}</th>
            <th class="col-hide-m">{{ t('main_extra.th_kind') }}</th>
            <th class="col-hide-m">{{ t('main_extra.th_fs') }}</th>
            <th>{{ t('main_extra.th_total') }}</th>
            <th class="col-hide-m">{{ t('main_extra.th_used') }}</th>
            <th class="col-hide-m">{{ t('main_extra.th_avail') }}</th>
            <th>{{ t('main_extra.th_pct') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="d in asArray(arrayDevices)" :key="finiteText(asRecord(d).mount)">
            <td><span class="led on"></span></td>
            <td class="col-hide-m">
              <span class="badge" :class="asRecord(d).kind === 'system' ? 'accent' : 'ok'">
                {{ asRecord(d).kind === 'system' ? 'Cache/System' : 'Data' }}
              </span>
            </td>
            <td class="mono">
              <strong>{{ finiteText(asRecord(d).mount) }}</strong>
              <div class="sub" style="font-size:10px" v-if="finiteText(asRecord(d).disk_id, '')">
                {{ finiteText(asRecord(d).disk_id) }}
                <span v-if="asRecord(d).shared_pool" class="badge warn" style="margin-left:4px">{{ t('main_extra.shared_pool') }}</span>
              </div>
              <div class="show-m sub">{{ finiteText(asRecord(d).kind) }} · {{ finiteText(asRecord(d).filesystem) }} · {{ fmtGb(asRecord(d).used_gb) }} / {{ fmtGb(asRecord(d).avail_gb) }}</div>
            </td>
            <td class="col-hide-m">{{ finiteText(asRecord(d).kind) }}</td>
            <td class="mono col-hide-m">{{ finiteText(asRecord(d).filesystem) }}</td>
            <td>{{ fmtGb(asRecord(d).total_gb) }}</td>
            <td class="col-hide-m">{{ fmtGb(asRecord(d).used_gb) }}</td>
            <td class="col-hide-m">{{ fmtGb(asRecord(d).avail_gb) }}</td>
            <td style="min-width:100px">
              {{ withUnit(asRecord(d).pct, '%') }}
              <div class="pct-bar" :class="asRecord(d).pct>=90?'danger':asRecord(d).pct>=75?'warn':''" style="margin-top:3px">
                <i :style="{ width: barPct(asRecord(d).pct) + '%' }"></i>
              </div>
            </td>
          </tr>
          <tr v-if="!asArray(arrayDevices).length && !loadError">
            <td colspan="9" class="empty-row">{{ t('main_extra.empty_array_vols') }}</td>
          </tr>
        </tbody>
      </table>
    </div>

    <h2 class="section-title">{{ t('main.unassigned_devices') }}</h2>
    <div class="table-wrap" style="margin-bottom:12px">
      <table class="dense fit-m">
        <thead>
          <tr>
            <th><span class="sr-only">{{ t('common.status_led') }}</span></th>
            <th>{{ t('main_extra.device') }}</th>
            <th>{{ t('common.name') }}</th>
            <th class="col-hide-m">{{ t('main_extra.th_kind') }}</th>
            <th class="col-hide-m">{{ t('main_extra.th_power') }}</th>
            <th class="col-hide-m">{{ t('main_extra.th_mount') }}</th>
            <th>{{ t('common.actions') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="d in asArray(unassigned)" :key="finiteText(asRecord(d).id)">
            <td><span class="led" :class="powerLed(d)"></span></td>
            <td class="mono">{{ finiteText(asRecord(d).device) }}</td>
            <td>
              <strong>{{ finiteText(asRecord(d).name) }}</strong>
              <div class="show-m sub">{{ kindLabel(d) }} · {{ powerLabel(d.power_state) }}</div>
              <div v-if="asArray(asRecord(d).volumes).length" class="show-m sub mono">
                <div v-for="v in asArray(asRecord(d).volumes)" :key="finiteText(asRecord(v).mount)">{{ finiteText(asRecord(v).mount) }}</div>
              </div>
            </td>
            <td class="col-hide-m"><span class="badge" :class="kindBadge(d)">{{ kindLabel(d) }}</span></td>
            <td class="col-hide-m"><span class="badge" :class="powerBadge(d)">{{ powerLabel(d.power_state) }}</span></td>
            <td class="mono col-hide-m" style="font-size:11px">
              <span v-if="!asArray(asRecord(d).volumes).length" style="color:var(--sub)">{{ t('main_extra.not_mounted') }}</span>
              <div v-for="v in asArray(asRecord(d).volumes)" :key="finiteText(asRecord(v).mount)">{{ finiteText(asRecord(v).mount) }}</div>
            </td>
            <td class="ops">
              <button v-if="asArray(asRecord(d).actions).includes('wake')" class="tiny primary" :disabled="busy" @click="power(d, 'wake')">{{ t('main_extra.act_wake_mount') }}</button>
              <button v-if="asArray(asRecord(d).actions).includes('sleep')" class="tiny" :disabled="busy || d.system" @click="power(d, 'sleep')">{{ t('main_extra.act_sleep') }}</button>
              <button v-if="asArray(asRecord(d).actions).includes('eject')" class="tiny danger" :disabled="busy || d.system" @click="power(d, 'eject')">{{ t('main.eject') }}</button>
            </td>
          </tr>
          <tr v-if="!asArray(unassigned).length && !loadError && !pendingFull">
            <td colspan="7" class="empty-row">{{ t('main_extra.empty_unassigned') }}</td>
          </tr>
        </tbody>
      </table>
    </div>

    <div class="tile" style="margin-bottom:12px;border-left:3px solid var(--accent)">
      <h2 style="margin:0 0 6px">{{ t('main.tip_title') }}</h2>
      <p style="font-size:12px;color:var(--sub);line-height:1.55;margin:0">
        {{ t('main.tip_body') }}
      </p>
    </div>

    <h2 class="section-title">{{ t('main.power') }}</h2>
    <div class="table-wrap">
      <table class="dense fit-m">
        <thead>
          <tr>
            <th><span class="sr-only">{{ t('common.status_led') }}</span></th>
            <th>{{ t('main_extra.device') }}</th>
            <th>{{ t('common.name') }}</th>
            <th class="col-hide-m">{{ t('main_extra.th_kind') }}</th>
            <th class="col-hide-m">{{ t('main_extra.protocol') }}</th>
            <th class="col-hide-m">{{ t('dashboard.col_capacity') }}</th>
            <th>{{ t('main_extra.power_state') }}</th>
            <th class="col-hide-m">{{ t('main_extra.mounted_vols') }}</th>
            <th>{{ t('common.actions') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="d in asArray(powerDisks)" :key="finiteText(asRecord(d).id)">
            <td>
              <span
                class="led"
                :class="powerLed(d)"
                :title="finiteText(asRecord(d).power_state)"
              ></span>
            </td>
            <td class="mono">{{ finiteText(asRecord(d).device) }}</td>
            <td>
              <strong>{{ finiteText(asRecord(d).name) }}</strong>
              <div class="sub" style="font-size:11px">{{ finiteText(asRecord(d).hint) }}</div>
              <div class="show-m sub">{{ kindLabel(d) }} · {{ finiteText(asRecord(d).protocol) }}{{ sizeGb(asRecord(d).size_gb) ? ' · ' + sizeGb(asRecord(d).size_gb) : '' }}</div>
              <div v-if="asArray(asRecord(d).volumes).length" class="show-m sub mono">
                <div v-for="v in asArray(asRecord(d).volumes)" :key="'m-'+finiteText(asRecord(v).mount)">{{ finiteText(asRecord(v).mount) }}</div>
              </div>
            </td>
            <td class="col-hide-m">
              <span class="badge" :class="kindBadge(d)">{{ kindLabel(d) }}</span>
            </td>
            <td class="col-hide-m">{{ finiteText(asRecord(d).protocol) }}</td>
            <td class="col-hide-m">{{ finiteText(sizeGb(asRecord(d).size_gb)) }}</td>
            <td>
              <span class="badge" :class="powerBadge(d)">{{ powerLabel(d.power_state) }}</span>
            </td>
            <td class="mono col-hide-m" style="font-size:11px">
              <div v-for="v in asArray(asRecord(d).volumes)" :key="finiteText(asRecord(v).mount)">{{ finiteText(asRecord(v).mount) }}</div>
              <span v-if="!asArray(asRecord(d).volumes).length" style="color:var(--sub)">—</span>
            </td>
            <td class="ops">
              <button
                v-if="asArray(asRecord(d).actions).includes('sleep')"
                class="tiny"
                :disabled="busy || d.system"
                @click="power(d, 'sleep')"
              >{{ t('main.sleep') }}</button>
              <button
                v-if="asArray(asRecord(d).actions).includes('wake')"
                class="tiny primary"
                :disabled="busy"
                @click="power(d, 'wake')"
              >{{ t('main.wake') }}</button>
              <button
                v-if="asArray(asRecord(d).actions).includes('eject')"
                class="tiny danger"
                :disabled="busy || d.system"
                @click="power(d, 'eject')"
              >{{ t('main.eject') }}</button>
              <span v-if="!asArray(asRecord(d).actions).length" class="sub">—</span>
            </td>
          </tr>
          <tr v-if="!asArray(powerDisks).length && !loadError && !pendingFull">
            <td colspan="9" class="empty-row">{{ t('main_extra.empty_disks') }}</td>
          </tr>
        </tbody>
      </table>
    </div>
    <pre v-if="lastMsg" style="margin:8px 0 12px;font-size:11px;white-space:pre-wrap;background:var(--bg);padding:8px;border-radius:4px;max-height:120px;overflow:auto" role="status" aria-live="polite">{{ finiteText(lastMsg) }}</pre>

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
    <div v-if="asArray(smartNotice.down).length" class="tile" style="margin-bottom:8px;border-left:3px solid var(--down)">
      <h3 style="margin:0 0 6px">
        <span class="led err" style="margin-right:6px"></span>{{ t('main_extra.smart_bad_title', { n: asArray(smartNotice.down).length }) }}
      </h3>
      <div v-for="d in asArray(smartNotice.down)" :key="finiteText(asRecord(d).id)" style="font-size:12px;line-height:1.6">
        <strong class="mono">{{ finiteText(asRecord(d).label) }}</strong>
        <span style="color:var(--sub)"> · {{ finiteText(asRecord(d).reasons) }}</span>
      </div>
    </div>
    <div v-if="asArray(smartNotice.warn).length" class="tile" style="margin-bottom:8px;border-left:3px solid var(--warn)">
      <h3 style="margin:0 0 6px">
        <span class="led warn" style="margin-right:6px"></span>{{ t('main_extra.smart_watch_title', { n: asArray(smartNotice.warn).length }) }}
      </h3>
      <div v-for="d in asArray(smartNotice.warn)" :key="finiteText(asRecord(d).id)" style="font-size:12px;line-height:1.6">
        <strong class="mono">{{ finiteText(asRecord(d).label) }}</strong>
        <span style="color:var(--sub)"> · {{ finiteText(asRecord(d).reasons) }}</span>
      </div>
      <p style="font-size:11px;color:var(--sub);line-height:1.55;margin:6px 0 0">{{ t('main_extra.smart_watch_hint') }}</p>
    </div>
    <div v-if="asArray(smartNotice.unknown).length" class="tile" style="margin-bottom:8px;border-left:3px solid var(--line)">
      <h3 style="margin:0 0 6px;color:var(--sub)">
        <span class="led off" style="margin-right:6px"></span>{{ t('main_extra.smart_unknown_title', { n: asArray(smartNotice.unknown).length }) }}
      </h3>
      <div v-for="d in asArray(smartNotice.unknown)" :key="finiteText(asRecord(d).id)" style="font-size:12px;line-height:1.6">
        <strong class="mono">{{ finiteText(asRecord(d).label) }}</strong>
        <span style="color:var(--sub)"> · {{ finiteText(asRecord(d).reasons) }}</span>
      </div>
      <p style="font-size:11px;color:var(--sub);line-height:1.55;margin:6px 0 0">{{ t('main_extra.smart_unknown_hint') }}</p>
    </div>

    <div class="table-wrap">
      <table class="dense fit-m">
        <thead>
          <tr>
            <th><span class="sr-only">{{ t('common.status_led') }}</span></th>
            <th>{{ t('main_extra.device') }}</th>
            <th>{{ t('main_extra.model') }}</th>
            <th class="col-hide-m">{{ t('main_extra.protocol') }}</th>
            <th>{{ t('main_extra.temp') }}</th>
            <th>{{ t('main_extra.health') }}</th>
            <th class="col-hide-m">{{ t('main_extra.wear') }}</th>
            <th class="col-hide-m">{{ t('main_extra.written') }}</th>
            <th class="col-hide-m">{{ t('main_extra.power_on') }}</th>
            <th class="col-hide-m">{{ t('dashboard.col_capacity') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="d in asArray(asRecord(data).disks)" :key="finiteText(asRecord(d).id)">
            <!-- Was `d.smart ? 'on' : (d.error ? 'err' : 'off')`, which lit green for
                 a drive reporting FAILED (it has a smart dict) and red for a healthy
                 external disk macOS cannot read (it has an error) -- both backwards.
                 The LED now follows the same grade as the notice above. -->
            <td><span class="led" :class="smartLed(d)" :title="smartGrade(d)"></span></td>
            <td class="mono">{{ finiteText(asRecord(d).device, '') || finiteText(asRecord(d).id) }}</td>
            <td>
              <strong>{{ finiteText(asRecord(d).name, '') || finiteText(asRecord(d).id) }}</strong>
              <div class="mono" style="color:var(--sub)">{{ finiteText(asRecord(asRecord(d).smart).model, '') || finiteText(asRecord(asRecord(d).smart).serial, '') }}</div>
              <div class="show-m sub">{{ finiteText(asRecord(d).protocol) }}{{ asRecord(d).ssd ? ' · SSD' : '' }}{{ finiteText(asRecord(d).size, '') ? ' · ' + finiteText(asRecord(d).size) : '' }}</div>
              <div v-if="asRecord(asRecord(d).smart).wear || asRecord(asRecord(d).smart).written || asRecord(asRecord(d).smart).power_on" class="show-m sub">
                {{ [asRecord(asRecord(d).smart).wear, asRecord(asRecord(d).smart).written, asRecord(asRecord(d).smart).power_on].map(v => finiteText(v, '')).filter(Boolean).join(' · ') }}
              </div>
            </td>
            <td class="col-hide-m">{{ finiteText(asRecord(d).protocol) }}{{ asRecord(d).ssd ? ' · SSD' : '' }}</td>
            <td>{{ finiteText(asRecord(asRecord(d).smart).temp) }}</td>
            <td>
              <span class="badge" :class="smartBadge(d)">
                {{ finiteText(asRecord(asRecord(d).smart).health, '') || (asRecord(d).error ? 'N/A' : '—') }}
              </span>
            </td>
            <td class="col-hide-m">{{ finiteText(asRecord(asRecord(d).smart).wear) }}</td>
            <td class="col-hide-m">{{ finiteText(asRecord(asRecord(d).smart).written) }}</td>
            <td class="mono col-hide-m">{{ finiteText(asRecord(asRecord(d).smart).power_on) }}</td>
            <td class="col-hide-m">{{ finiteText(asRecord(d).size) }}</td>
          </tr>
          <tr v-if="!asArray(asRecord(data).disks).length && !loadError">
            <td colspan="10" class="empty-row">{{ t('main_extra.empty_disks') }}</td>
          </tr>
          <tr v-if="!(data?.disks || []).length && !loadError">
            <td colspan="10" class="empty-row">{{ t('main_extra.empty_disks') }}</td>
          </tr>
        </tbody>
      </table>
    </div>

    <h2 class="section-title">{{ t('main.volumes') }}</h2>
    <div class="table-wrap">
      <table class="dense fit-m">
        <thead>
          <tr>
            <th>{{ t('dashboard.col_mount') }}</th>
            <th class="col-hide-m">{{ t('main_extra.disk') }}</th>
            <th class="col-hide-m">{{ t('main_extra.th_fs') }}</th>
            <th class="col-hide-m">{{ t('main_extra.th_kind') }}</th>
            <th>{{ t('main_extra.th_total') }}</th>
            <th class="col-hide-m">{{ t('main_extra.th_used') }}</th>
            <th class="col-hide-m">{{ t('main_extra.th_avail') }}</th>
            <th>{{ t('main_extra.th_pct') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="v in asArray(asRecord(data).volumes)" :key="finiteText(asRecord(v).mount)">
            <td class="mono">
              <strong>{{ finiteText(asRecord(v).mount) }}</strong>
              <div class="show-m sub">{{ finiteText(asRecord(v).kind) }} · {{ finiteText(asRecord(v).filesystem) }}{{ finiteText(asRecord(v).disk_id, '') ? ' · ' + finiteText(asRecord(v).disk_id) : '' }}</div>
              <div class="show-m sub">{{ fmtGb(asRecord(v).used_gb) }} / {{ fmtGb(asRecord(v).avail_gb) }}</div>
            </td>
            <td class="mono col-hide-m">{{ finiteText(asRecord(v).disk_id) }}</td>
            <td class="mono col-hide-m">{{ finiteText(asRecord(v).filesystem) }}</td>
            <td class="col-hide-m">
              <span class="badge accent">{{ finiteText(asRecord(v).kind) }}</span>
              <span v-if="asRecord(v).disk_id && sharedDiskIds.has(asRecord(v).disk_id)" class="badge warn">{{ t('main_extra.shared') }}</span>
            </td>
            <td>{{ fmtGb(asRecord(v).total_gb) }}</td>
            <td class="col-hide-m">{{ fmtGb(asRecord(v).used_gb) }}</td>
            <td class="col-hide-m">{{ fmtGb(asRecord(v).avail_gb) }}</td>
            <td style="min-width:120px">
              <strong :style="{ color: asRecord(v).pct >= 90 ? 'var(--down-text)' : (asRecord(v).pct >= 75 ? 'var(--warn-text)' : 'inherit') }">{{ withUnit(asRecord(v).pct, '%') }}</strong>
              <div class="pct-bar" :class="asRecord(v).pct>=90?'danger':asRecord(v).pct>=75?'warn':''" style="margin-top:3px">
                <i :style="{ width: barPct(asRecord(v).pct) + '%' }"></i>
              </div>
            </td>
          </tr>
          <tr v-if="!asArray(asRecord(data).volumes).length && !loadError">
            <td colspan="8" class="empty-row">{{ t('main_extra.empty_volumes') }}</td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- Disk management (diskutil) -->
    <h2 class="section-title">{{ t('main_extra.manage') }}</h2>
    <div class="tile" style="margin-bottom:10px;border-left:3px solid var(--accent)">
      <p style="font-size:12px;color:var(--sub);line-height:1.55;margin:0">
        {{ t('main_extra.manage_hint') }} {{ finiteText(data?.managed?.hint, '') }}
      </p>
    </div>
    <div class="toolbar">
      <label style="font-size:12px;color:var(--sub);display:flex;align-items:center;gap:6px">
        <input type="checkbox" v-model="showSystemVols" /> {{ t('main_extra.show_system') }}
      </label>
      <button @click="refresh" :disabled="loading || busy">{{ t('main_extra.refresh_list') }}</button>
    </div>
    <div class="table-wrap">
      <table class="dense fit-m">
        <thead>
          <tr>
            <th>{{ t('main_extra.device') }}</th>
            <th>{{ t('common.name') }}</th>
            <th class="col-hide-m">FS</th>
            <th class="col-hide-m">{{ t('dashboard.col_capacity') }}</th>
            <th class="col-hide-m">{{ t('dashboard.col_mount') }}</th>
            <th>{{ t('common.actions') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="v in asArray(managedVols)" :key="finiteText(asRecord(v).id)">
            <td class="mono">
              <strong>{{ finiteText(asRecord(v).id) }}</strong>
              <div class="sub" style="font-size:10px" v-if="asRecord(v).is_whole">{{ t('main_extra.whole') }}</div>
              <div class="sub" style="font-size:10px" v-else-if="asRecord(v).whole_disk">∈ {{ finiteText(asRecord(v).whole_disk) }}</div>
            </td>
            <td>
              {{ finiteText(asRecord(v).volume_name, '') || finiteText(asRecord(v).name) }}
              <span v-if="asRecord(v).system" class="badge down">{{ t('main_extra.system') }}</span>
              <div class="show-m sub">{{ finiteText(asRecord(v).fs) }}{{ sizeGb(asRecord(v).size_gb) ? ' · ' + sizeGb(asRecord(v).size_gb) : '' }}</div>
              <div v-if="asRecord(v).mount" class="show-m sub mono">{{ finiteText(asRecord(v).mount) }}</div>
            </td>
            <td class="mono col-hide-m">{{ finiteText(asRecord(v).fs) }}</td>
            <td class="col-hide-m">{{ finiteText(sizeGb(asRecord(v).size_gb)) }}</td>
            <td class="mono col-hide-m" style="font-size:11px">
              <span v-if="asRecord(v).mount">{{ finiteText(asRecord(v).mount) }}</span>
              <span v-else style="color:var(--sub)">{{ t('main_extra.not_mounted') }}</span>
            </td>
            <td class="ops">
              <button v-if="asArray(asRecord(v).actions).includes('mount')" class="tiny primary" :disabled="busy" @click="manage(v, 'mount')">{{ t('main_extra.mount') }}</button>
              <button v-if="asArray(asRecord(v).actions).includes('unmount')" class="tiny" :disabled="busy" @click="manage(v, 'unmount')">{{ t('main_extra.unmount') }}</button>
              <button v-if="asArray(asRecord(v).actions).includes('mountDisk')" class="tiny primary" :disabled="busy" @click="manage(v, 'mountDisk')">{{ t('main_extra.mount_disk') }}</button>
              <button v-if="asArray(asRecord(v).actions).includes('unmountDisk')" class="tiny" :disabled="busy" @click="manage(v, 'unmountDisk')">{{ t('main_extra.unmount_disk') }}</button>
              <button v-if="asArray(asRecord(v).actions).includes('eject')" class="tiny" :disabled="busy" @click="manage(v, 'eject')">{{ t('main.eject') }}</button>
              <button v-if="asArray(asRecord(v).actions).includes('rename')" class="tiny" :disabled="busy" @click="openRename(v)">{{ t('main_extra.rename') }}</button>
              <button v-if="asArray(asRecord(v).actions).includes('eraseVolume')" class="tiny danger" :disabled="busy" @click="openFormat(v, false)">{{ t('main_extra.format') }}</button>
              <button v-if="asArray(asRecord(v).actions).includes('eraseDisk')" class="tiny danger" :disabled="busy" @click="openFormat(v, true)">{{ t('main_extra.erase_disk') }}</button>
              <span v-if="!asArray(asRecord(v).actions).length" class="sub">{{ t('main_extra.locked') }}</span>
            </td>
          </tr>
          <!-- "No volumes" is a diagnosis; hiding system volumes is a filter.
               With the toggle off and only system volumes present, the table
               claimed the disk had no volumes at all — say the filter missed
               instead, like every other filtered table. -->
          <tr v-if="!asArray(managedVols).length && !loadError && !pendingFull">
            <td colspan="6" class="empty-row">{{ asArray(asRecord(asRecord(data).managed).volumes).length ? t('common.no_match') : t('main_extra.no_vols') }}</td>
          </tr>
        </tbody>
      </table>
    </div>
    </template>

    <!-- Rename modal -->
    <div ref="renamePanel" v-if="renameTarget" class="modal-bg" @click.self="renameTarget=null" role="presentation">
      <div class="modal" style="max-width:420px" role="dialog" aria-modal="true" aria-labelledby="array-rename-title">
        <div class="row" style="margin-bottom:10px">
          <span id="array-rename-title" class="name">{{ t('main_extra.rename') }} · {{ finiteText(renameTarget.id) }}</span>
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
          <span id="array-format-title" class="name" style="color:var(--down-text)">
            {{ formatWhole ? t('main_extra.erase_disk') : t('main_extra.format') }} · {{ finiteText(formatTarget.id) }}
          </span>
          <button class="tiny" @click="formatTarget=null">{{ t('common.close') }}</button>
        </div>
        <p style="font-size:12px;color:var(--down-text);line-height:1.5;margin-bottom:10px">
          ⚠️ {{ t('main_extra.format_warn') }}
        </p>
        <div class="field-grid">
          <label>{{ t('main_extra.fs') }}</label>
          <select v-model="formatFs" :aria-label="t('main_extra.fs')">
            <option v-for="f in asArray(fsTypes)" :key="finiteText(f)" :value="finiteText(f)">{{ finiteText(f) }}</option>
          </select>
          <label>{{ t('main_extra.vol_name') }}</label>
          <input v-model="formatName" type="text" :aria-label="t('main_extra.vol_name')" />
          <label>{{ t('main_extra.confirm') }}</label>
          <!-- The aria-label used to repeat the placeholder, so the control was
               announced as its example value instead of what it is; the grid
               <label> above carries the real name. -->
          <input v-model="formatConfirm" type="text" :placeholder="t('main_extra.format_type_ph', { name: finiteText(formatTarget.volume_name, '') || finiteText(formatTarget.id) })" :aria-label="t('main_extra.confirm')"/>
        </div>
        <p style="font-size:11px;color:var(--sub);margin:8px 0 12px">
          {{ t('main_extra.format_confirm_hint', { name: finiteText(formatTarget.volume_name, '') || finiteText(formatTarget.id) }) }}
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
          <span v-if="finiteText(smartData?.ts, '')">{{ finiteText(smartData.ts) }}</span>
          <template v-if="smartData">
            <span :style="{ color: smartData.passwordless_sudo ? 'var(--ok-text)' : 'var(--warn-text)' }">
              {{ asRecord(smartData).passwordless_sudo ? t('main_extra.smart_sudo_ok') : t('main_extra.smart_sudo_no') }}
            </span>
            <span :style="{ color: smartData.smartctl_installed ? 'var(--ok-text)' : 'var(--down-text)' }">
              {{ asRecord(smartData).smartctl_installed ? t('main_extra.smartctl_yes') : t('main_extra.smartctl_no') }}
            </span>
          </template>
          <span v-else-if="smartError" style="color:var(--down-text)">{{ finiteText(smartError) }}</span>
        </div>
        <!-- role=status: the scan runs after the dialog already holds focus,
             so without a live region a screen reader hears nothing between
             opening the modal and the table appearing. -->
        <div v-if="smartLoading" role="status" style="text-align:center;padding:20px;color:var(--sub)">{{ t('main_extra.scanning') }}</div>
        <div v-else>
          <!-- The overview loads after the dialog already holds focus, so the
               panel-focus read never covers a failure — same as the Scheduler
               run-history and Shares ACL errors. -->
          <div v-if="smartError && !smartData" role="alert" style="color:var(--down-text)">{{ finiteText(smartError) }}</div>
          <div v-else-if="!asArray(smartMerged).length" style="color:var(--sub)">{{ t('main_extra.smart_no_devices') }}</div>
          <div v-else class="table-wrap" style="max-height:400px;overflow:auto">
            <table class="dense fit-m">
              <thead>
                <tr>
                  <th>{{ t('main_extra.device') }}</th>
                  <th>{{ t('main_extra.model') }}</th>
                  <th class="col-hide-m">{{ t('main_extra.protocol') }}</th>
                  <th>{{ t('main_extra.temp') }}</th>
                  <th>{{ t('main_extra.health') }}</th>
                  <th class="col-hide-m">{{ t('main_extra.wear') }}</th>
                  <th class="col-hide-m">{{ t('main_extra.power_on') }}</th>
                  <th class="col-hide-m">{{ t('main_extra.smart_caps') }}</th>
                  <th>{{ t('common.actions') }}</th>
                </tr>
              </thead>
              <tbody>
                <template v-for="m in asArray(smartMerged)" :key="finiteText(asRecord(m).id)">
                <tr>
                  <td class="mono">
                    <strong>{{ finiteText(asRecord(m).id) }}</strong>
                    <div v-if="asRecord(m).error" class="sub" style="font-size:10px;color:var(--warn-text)">{{ finiteText(asRecord(m).error) }}</div>
                  </td>
                  <td>
                    <strong>{{ finiteText(asRecord(asRecord(m).smart).model, '') || finiteText(asRecord(asRecord(m).smart).serial) }}</strong>
                    <div class="sub mono" style="font-size:10px">{{ finiteText(asRecord(m).size) }}</div>
                    <div class="show-m sub">{{ finiteText(asRecord(m).protocol) }}{{ asRecord(m).ssd ? ' · SSD' : '' }}{{ finiteText(asRecord(asRecord(m).smart).wear, '') ? ' · ' + finiteText(asRecord(asRecord(m).smart).wear) : '' }}</div>
                  </td>
                  <td class="col-hide-m" style="font-size:11px">{{ finiteText(asRecord(m).protocol) }}{{ asRecord(m).ssd ? ' · SSD' : '' }}</td>
                  <td>{{ finiteText(asRecord(asRecord(m).smart).temp) }}</td>
                  <td>
                    <span class="badge" :class="asRecord(asRecord(m).smart).health === 'PASSED' ? 'ok' : (asRecord(asRecord(m).smart).health ? 'warn' : '')">
                      {{ finiteText(asRecord(asRecord(m).smart).health) }}
                    </span>
                  </td>
                  <td class="col-hide-m">{{ finiteText(asRecord(asRecord(m).smart).wear) }}</td>
                  <td class="mono col-hide-m">{{ finiteText(asRecord(asRecord(m).smart).power_on) }}</td>
                  <td class="col-hide-m" style="font-size:11px">
                    <span v-if="asArray(asRecord(asRecord(m).caps).supported).length">{{ asArray(asRecord(asRecord(m).caps).supported).map(n => finiteText(n, '')).filter(Boolean).join(', ') }}</span>
                    <span v-else style="color:var(--sub)">{{ t('main_extra.smart_unsupported') }}</span>
                    <div v-if="finiteText(asRecord(asRecord(m).caps).reason, '')" class="sub" style="font-size:10px;color:var(--warn-text)">{{ finiteText(asRecord(asRecord(m).caps).reason) }}</div>
                    <div v-if="asRecord(asRecord(m).progress).running" class="sub" style="font-size:10px;color:var(--ok-text)">{{ t('main_extra.smart_running', { pct: finiteN(asRecord(asRecord(m).progress).percent_remaining, '?') }) }}</div>
                    <div v-if="finiteText(asRecord(m).lastResult, '')" class="sub" style="font-size:10px">{{ finiteText(asRecord(m).lastResult) }} · {{ finiteN(asRecord(m).logCount, 0) }} {{ t('main_extra.smart_logs') }}</div>
                  </td>
                  <td class="ops">
                    <!-- The visible face is a glyph and a count, so the
                         accessible name was "▼ 12" — nothing says what
                         expands. aria-expanded carries the open state. -->
                    <button
                      v-if="asArray(asRecord(asRecord(m).smart).attrs).length"
                      class="tiny"
                      :aria-label="t('main_extra.smart_attrs_toggle', { id: finiteText(asRecord(m).id) })"
                      :aria-expanded="smartExpanded.has(asRecord(m).id)"
                      @click="toggleSmartDetail(asRecord(m).id)"
                    >
                      {{ smartExpanded.has(asRecord(m).id) ? '▲' : '▼' }} {{ asArray(asRecord(asRecord(m).smart).attrs).length }}
                    </button>
                    <template v-if="asArray(asRecord(asRecord(m).caps).supported).length">
                      <button
                        v-for="k in asArray(asRecord(asRecord(m).caps).supported).filter(x => x !== 'offline')" :key="k"
                        class="tiny primary"
                        :disabled="busy || smartTestBusy"
                        @click="runSmartTest(m, k)"
                      >{{ smartTestLabel(k) }}</button>
                    </template>
                  </td>
                </tr>
                <tr v-if="smartExpanded.has(asRecord(m).id) && asArray(asRecord(asRecord(m).smart).attrs).length">
                  <td :colspan="9" style="padding:0;background:var(--table-alt)">
                    <div style="padding:6px 10px;max-height:300px;overflow:auto">
                      <table class="dense fit-m" style="width:100%">
                        <thead>
                          <tr>
                            <th style="font-size:10px;width:40px">ID</th>
                            <th style="font-size:10px">{{ t('common.name') }}</th>
                            <th style="font-size:10px" v-if="asRecord(asArray(asRecord(asRecord(m).smart).attrs)[0]).raw !== undefined">{{ t('main_extra.smart_value') }}</th>
                            <th class="col-hide-m" style="font-size:10px" v-if="asRecord(asArray(asRecord(asRecord(m).smart).attrs)[0]).worst !== undefined">{{ t('main_extra.smart_worst') }}</th>
                            <th class="col-hide-m" style="font-size:10px" v-if="asRecord(asArray(asRecord(asRecord(m).smart).attrs)[0]).thresh !== undefined">{{ t('main_extra.smart_thresh') }}</th>
                            <th class="col-hide-m" style="font-size:10px" v-if="asRecord(asArray(asRecord(asRecord(m).smart).attrs)[0]).type !== undefined">{{ t('main_extra.smart_attr_type') }}</th>
                            <th style="font-size:10px">{{ asRecord(asArray(asRecord(asRecord(m).smart).attrs)[0]).raw !== undefined ? t('main_extra.smart_raw') : t('common.status') }}</th>
                          </tr>
                        </thead>
                        <tbody>
                          <tr v-for="a in asArray(asRecord(asRecord(m).smart).attrs)" :key="finiteN(asRecord(a).id)">
                            <td class="mono" style="font-size:10px">{{ finiteN(asRecord(a).id) }}</td>
                            <td style="font-size:11px">
                              {{ finiteText(asRecord(a).name) }}
                              <div v-if="asRecord(a).type" class="show-m sub">{{ finiteText(asRecord(a).type) }}{{ finiteText(asRecord(a).worst, '') ? ' · W' + finiteText(asRecord(a).worst) : '' }}{{ finiteText(asRecord(a).thresh, '') ? ' · T' + finiteText(asRecord(a).thresh) : '' }}</div>
                            </td>
                            <td v-if="asRecord(a).raw !== undefined" class="mono" style="font-size:10px">{{ finiteText(asRecord(a).value) }}</td>
                            <td class="mono col-hide-m" v-if="asRecord(a).worst !== undefined" style="font-size:10px">{{ finiteText(asRecord(a).worst) }}</td>
                            <td class="mono col-hide-m" v-if="asRecord(a).thresh !== undefined" style="font-size:10px">{{ finiteText(asRecord(a).thresh) }}</td>
                            <td class="col-hide-m" v-if="asRecord(a).type !== undefined" style="font-size:10px">
                              <span class="badge" :class="asRecord(a).type === 'Pre-fail' ? 'warn' : ''" style="font-size:9px">{{ finiteText(asRecord(a).type) }}</span>
                            </td>
                            <td class="mono" style="font-size:10px">{{ asRecord(a).raw !== undefined ? finiteText(asRecord(a).raw) : finiteText(asRecord(a).value) }}</td>
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
          <div v-if="asArray(smartData?.history).length" style="margin-top:12px">
            <h4 style="font-size:12px;margin-bottom:6px">{{ t('main_extra.smart_history') }}</h4>
            <div class="table-wrap" style="max-height:160px;overflow:auto">
              <table class="dense fit-m">
                <thead>
                  <tr>
                    <th style="font-size:10px">{{ t('common.time') }}</th>
                    <th style="font-size:10px">{{ t('main_extra.device') }}</th>
                    <th class="col-hide-m" style="font-size:10px">{{ t('main_extra.th_type') }}</th>
                    <th style="font-size:10px">{{ t('common.status') }}</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="(h, i) in asArray(asRecord(smartData).history).slice(0, 15)" :key="finiteText(asRecord(h).ts) + ':' + finiteText(asRecord(h).device) + ':' + i">
                    <td class="mono" style="font-size:10px">{{ fmtTs(asRecord(h).ts) }}</td>
                    <td class="mono" style="font-size:10px">
                      {{ finiteText(asRecord(h).device) }}
                      <div v-if="asRecord(h).kind" class="show-m sub">{{ finiteText(asRecord(h).kind) }}</div>
                    </td>
                    <td class="col-hide-m" style="font-size:10px">{{ finiteText(asRecord(h).kind) }}</td>
                    <td>
                      <span class="badge" :class="asRecord(h).ok ? 'ok' : 'warn'" style="font-size:10px">
                        {{ asRecord(h).ok ? t('common.ok') : (finiteText(asRecord(h).error, '') || finiteText(asRecord(h).message, '') || t('common.error')) }}
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
import { asArray, asRecord, barPct, finiteN, finiteText, fmtGb, fmtTs, withUnit } from '../lib/finite'
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
const smartError = ref('')
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
let pageAlive = true

function scheduleRefresh(delay) {
  const generation = loadSeq
  const id = setTimeout(() => {
    refreshTimers.delete(id)
    if (generation !== loadSeq || !pageAlive) return
    void refresh()
  }, delay)
  refreshTimers.add(id)
}

const powerDisks = computed(() => asArray(asRecord(data.value).power_disks).map((d) => asRecord(d)))
const arrayDevices = computed(() => {
  const devices = asArray(asRecord(asRecord(data.value).array).devices).map((d) => asRecord(d))
  if (devices.length) return devices
  return asArray(asRecord(data.value).volumes).map((v) => asRecord(v)).filter((v) =>
    v.kind === 'system' || v.kind === 'external'
  )
})
const sharedDiskIds = computed(() => {
  const s = new Set()
  for (const g of asArray(asRecord(asRecord(data.value).array).capacity_groups).map((row) => asRecord(row))) {
    if (g.mode === 'shared_pool' && g.disk_id) s.add(g.disk_id)
  }
  return s
})
const managedVols = computed(() => {
  const list = asArray(asRecord(asRecord(data.value).managed).volumes).map((v) => asRecord(v))
  if (showSystemVols.value) return list
  return list.filter((v) => !v.system)
})
const fsTypes = computed(() => {
  const types = asArray(asRecord(asRecord(data.value).managed).fs_types)
  return types.length ? types : ['APFS', 'ExFAT', 'JHFS+', 'MS-DOS']
})
const canFormat = computed(() => {
  const target = asRecord(formatTarget.value)
  if (!target.id && !target.volume_name) return false
  const expect = (finiteText(target.volume_name, '') || finiteText(target.id, '')).trim()
  const got = formatConfirm.value.trim()
  return got && (got === expect || got === target.id)
})
// Unassigned: non-system disks that are offline, spun down, or have no volumes
const unassigned = computed(() => {
  return asArray(powerDisks.value).map((d) => asRecord(d)).filter((d) => {
    if (d.system) return false
    const vols = asArray(asRecord(d).volumes)
    if (!vols.length) return true
    if (d.power_state === 'spun_down' || d.power_state === 'offline' || d.power_state === 'idle') return true
    return false
  })
})

// Merge self-test capabilities (/api/smart) with SMART attributes (/api/storage disks)
const smartMerged = computed(() => {
  const testDevices = asArray(asRecord(smartData.value).devices).map((d) => asRecord(d))
  const storageDisks = asArray(asRecord(data.value).disks).map((d) => asRecord(d))
  const storageMap = new Map()
  for (const d of storageDisks) storageMap.set(d.id, d)
  const merged = testDevices.map((td) => {
    const sd = asRecord(storageMap.get(td.id))
    return asRecord({
      id: td.id, device: td.device,
      smart: sd.smart || null, error: sd.error || null,
      protocol: sd.protocol, ssd: sd.ssd, size: sd.size,
      caps: td.capabilities, lastResult: td.last_result,
      logCount: td.log_count, failures: td.failures, progress: td.progress,
    })
  })
  const testIds = new Set(testDevices.map((d) => d.id))
  for (const sd of storageDisks) {
    if (!testIds.has(sd.id)) {
      merged.push(asRecord({
        id: sd.id, device: sd.device,
        smart: sd.smart || null, error: sd.error || null,
        protocol: sd.protocol, ssd: sd.ssd, size: sd.size,
        caps: null, lastResult: '', logCount: 0, failures: 0, progress: null,
      }))
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
    down.push(t('main_extra.smart_r_health', { v: finiteText(health) }))
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
  for (const attr of asArray(smart.attrs)) {
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
  for (const d of asArray(smartMerged.value)) {
    const label = [finiteText(d.smart?.model, '') || finiteText(d.name, '') || finiteText(d.id, ''), finiteText(d.device, '')].filter(Boolean).join(' ')
    const grade = smartGrade(d)
    if (grade === 'unknown') {
      // Only when the read actually failed.  A /api/smart device with no matching
      // storage entry has neither SMART nor an error, and inventing a row for it
      // would report a problem nobody has.
      if (d.error) out.unknown.push({ id: d.id, label, reasons: finiteText(d.error) })
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
function sizeGb(value) {
  const n = Number(value)
  return Number.isFinite(n) ? `${n} GB` : ''
}
function wrapStorage(next) {
  const row = asRecord(next)
  const arr = asRecord(row.array)
  const managed = asRecord(row.managed)
  return {
    ...row,
    power_disks: asArray(row.power_disks).map((d) => {
      const disk = asRecord(d)
      return { ...disk, volumes: asArray(disk.volumes).map((v) => asRecord(v)) }
    }),
    volumes: asArray(row.volumes).map((v) => asRecord(v)),
    disks: asArray(row.disks).map((d) => {
      const disk = asRecord(d)
      return { ...disk, smart: asRecord(disk.smart), volumes: asArray(disk.volumes).map((v) => asRecord(v)) }
    }),
    array: {
      ...arr,
      devices: asArray(arr.devices).map((d) => asRecord(d)),
      capacity_groups: asArray(arr.capacity_groups).map((g) => asRecord(g)),
    },
    managed: {
      ...managed,
      volumes: asArray(managed.volumes).map((v) => asRecord(v)),
      fs_types: asArray(managed.fs_types).length ? asArray(managed.fs_types) : ['APFS', 'ExFAT', 'JHFS+', 'MS-DOS'],
    },
  }
}
function wrapSmart(next) {
  const row = asRecord(next)
  return {
    ...row,
    devices: asArray(row.devices).map((d) => asRecord(d)),
    history: asArray(row.history).map((h) => asRecord(h)),
  }
}
function kindLabel(d) {
  const row = asRecord(d)
  if (row.system) return t('main_extra.kind_system')
  if (row.kind === 'removable') return t('main_extra.kind_removable')
  if (row.rotational || row.kind === 'hdd' || row.kind === 'external_hdd') return t('main_extra.kind_hdd')
  if (row.ssd) return 'SSD'
  return finiteText(row.kind, '') || t('main_extra.kind_disk')
}
function kindBadge(d) {
  const row = asRecord(d)
  if (row.system) return 'down'
  if (row.rotational || row.kind === 'hdd' || row.kind === 'external_hdd') return 'warn'
  if (row.ssd) return 'ok'
  return 'accent'
}

async function refresh(manual = false) {
  const mySeq = ++loadSeq
  loading.value = true
  try {
    const next = asRecord(await getStorage())
    if (mySeq !== loadSeq || !pageAlive) return
    data.value = wrapStorage(next)
    loadError.value = ''
  } catch (e) {
    if (mySeq !== loadSeq || !pageAlive) return
    loadError.value = finiteText(e.message || String(e), '')
    // Background 45s ticks stay silent: LoadFailure already marks the state on
    // screen, and re-toasting every interval while the panel is down is noise.
    // The retry button passes its click event as `manual`, so it still toasts.
    if (manual) toast('❌ ' + finiteText(e.message))
    // Failed tick → lib/poll.js backoff while the server stays unreachable.
    return false
  } finally {
    if (mySeq === loadSeq) {
      loading.value = false
      loaded.value = true
    }
  }
}

// First paint only: the polling interval and every manual refresh keep using
// refresh() above, so this staged path runs exactly once per page visit.
async function loadInitial() {
  const mySeq = ++loadSeq
  loading.value = true
  try {
    const next = asRecord(await getStorage(true))
    if (mySeq !== loadSeq || !pageAlive) return
    data.value = wrapStorage(next)
    loadError.value = ''
  } catch (e) {
    if (mySeq !== loadSeq || !pageAlive) return
    loadError.value = finiteText(e.message || String(e), '')
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (mySeq === loadSeq) {
      loading.value = false
      loaded.value = true
    }
  }
  pendingFull.value = true
  try {
    const full = asRecord(await getStorage())
    if (mySeq === loadSeq && pageAlive) {
      data.value = wrapStorage(full)
      loadError.value = ''
    }
  } catch (e) {
    // Keep the light data on screen; the next poll or a manual refresh retries
    // the full payload.  Only a total failure shows the load error.
    if (mySeq === loadSeq && pageAlive && !data.value) {
      loadError.value = finiteText(e.message || String(e), '')
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
  const mySeq = loadSeq
  try {
    const th = asRecord(await getThresholds())
    if (mySeq !== loadSeq || !pageAlive) return
    smartThresholds.value = {
      smart_temp_c: smartNum(th.smart_temp_c) ?? SMART_THRESHOLD_DEFAULTS.smart_temp_c,
      smart_wear_pct: smartNum(th.smart_wear_pct) ?? SMART_THRESHOLD_DEFAULTS.smart_wear_pct,
      smart_spare_pct: smartNum(th.smart_spare_pct) ?? SMART_THRESHOLD_DEFAULTS.smart_spare_pct,
    }
  } catch {
    // Defaults already in place; nothing to report to the operator.
  }
}

async function power(d, action) {
  const row = asRecord(d)
  const labels = { sleep: t('main_extra.act_sleep'), wake: t('main_extra.act_wake'), eject: t('main_extra.act_eject') }
  const tip = {
    sleep: t('main_extra.confirm_sleep', { id: finiteText(row.id) }),
    wake: t('main_extra.confirm_wake', { id: finiteText(row.id) }),
    eject: t('main_extra.confirm_eject', { id: finiteText(row.id) }),
  }
  if (!confirm(tip[action] || labels[action])) return
  const generation = loadSeq
  busy.value = true
  lastMsg.value = t('main_extra.running')
  try {
    const j = asRecord(await setDiskPower(row.id, action))
    if (generation !== loadSeq || !pageAlive) return
    lastMsg.value = (finiteText(j.message, '') || '') + (j.log ? '\n' + asArray(j.log).map(n => finiteText(n, '')).filter(Boolean).join('\n') : '')
    toast(j.ok ? `✅ ${labels[action]} ${finiteText(row.id)}` : `❌ ${finiteText(j.message)}`)
    if (j.ok) scheduleRefresh(1000)
  } catch (e) {
    if (generation !== loadSeq || !pageAlive) return
    toast('❌ ' + finiteText(e.message))
    lastMsg.value = finiteText(e.message, '')
  } finally {
    // The 45s poll's refresh() bumps loadSeq while an action is in flight.
    if (pageAlive) busy.value = false
  }
}

async function manage(v, action) {
  const row = asRecord(v)
  const tips = {
    mount: `${t('main_extra.mount')} ${finiteText(row.id)}?`,
    unmount: `${t('main_extra.unmount')} ${finiteText(row.id)} (${finiteText(row.mount, '') || t('main_extra.not_mounted')})?`,
    mountDisk: `${t('main_extra.mount_disk')} ${finiteText(row.id)}?`,
    unmountDisk: `${t('main_extra.unmount_disk')} ${finiteText(row.id)}?`,
    eject: `${t('main.eject')} ${finiteText(row.id)}?`,
  }
  if (!confirm(tips[action] || action)) return
  const generation = loadSeq
  busy.value = true
  lastMsg.value = t('main_extra.running')
  try {
    const j = asRecord(await manageStorageDevice(row.id, { action }))
    if (generation !== loadSeq || !pageAlive) return
    lastMsg.value = (finiteText(j.message, '') || '') + (j.log ? '\n' + asArray(j.log).map(n => finiteText(n, '')).filter(Boolean).join('\n') : '')
    toast(j.ok ? `✅ ${action} ${finiteText(row.id)}` : `❌ ${finiteText(j.message)}`)
    if (j.ok) scheduleRefresh(800)
  } catch (e) {
    if (generation !== loadSeq || !pageAlive) return
    toast('❌ ' + finiteText(e.message))
    lastMsg.value = finiteText(e.message, '')
  } finally {
    if (pageAlive) busy.value = false
  }
}

function openRename(v) {
  const row = asRecord(v)
  renameTarget.value = row
  renameName.value = finiteText(row.volume_name, '') || finiteText(row.name, '')
}
async function doRename() {
  if (!renameTarget.value || !renameName.value.trim()) return
  const generation = loadSeq
  busy.value = true
  try {
    const j = asRecord(await manageStorageDevice(renameTarget.value.id, {
      action: 'rename',
      name: renameName.value.trim(),
    }))
    if (generation !== loadSeq || !pageAlive) return
    toast(j.ok ? '✅ ' + t('main_extra.renamed') : `❌ ${finiteText(j.message)}`)
    lastMsg.value = finiteText(j.message, '')
    if (j.ok) {
      renameTarget.value = null
      scheduleRefresh(800)
    }
  } catch (e) {
    if (generation !== loadSeq || !pageAlive) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (pageAlive) busy.value = false
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
  const generation = loadSeq
  busy.value = true
  lastMsg.value = t('main_extra.formatting')
  try {
    const j = asRecord(await manageStorageDevice(formatTarget.value.id, {
      action: formatWhole.value ? 'eraseDisk' : 'eraseVolume',
      name: formatName.value.trim() || 'UNTITLED',
      fs: formatFs.value,
      confirm: true,
      confirm_name: formatConfirm.value.trim(),
    }))
    if (generation !== loadSeq || !pageAlive) return
    lastMsg.value = (finiteText(j.message, '') || '') + (j.log ? '\n' + asArray(j.log).map(n => finiteText(n, '')).filter(Boolean).join('\n') : '')
    toast(j.ok ? '✅ ' + t('main_extra.formatted') : `❌ ${finiteText(j.message)}`)
    if (j.ok) {
      formatTarget.value = null
      scheduleRefresh(1200)
    }
  } catch (e) {
    if (generation !== loadSeq || !pageAlive) return
    toast('❌ ' + finiteText(e.message))
    lastMsg.value = finiteText(e.message, '')
  } finally {
    if (pageAlive) busy.value = false
  }
}

onMounted(() => {
  pageAlive = true
  void loadInitial()
  void loadSmartThresholds()
  timer = startVisibleInterval(refresh, 45000)
})
onUnmounted(() => {
  pageAlive = false
  loadSeq += 1
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
  const seq = loadSeq
  smartModal.value = true
  smartLoading.value = true
  smartError.value = ''
  try {
    const next = wrapSmart(await getSmartOverview())
    if (seq !== loadSeq || !pageAlive) return
    smartData.value = next
  } catch (e) {
    if (seq !== loadSeq || !pageAlive) return
    smartError.value = finiteText(e.message || String(e), '')
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (pageAlive) smartLoading.value = false
  }
}

async function runSmartTest(dev, kind) {
  if (!confirm(t('main_extra.confirm_smart', { kind, id: finiteText(asRecord(dev).id) }))) return
  const generation = loadSeq
  smartTestBusy.value = true
  try {
    const j = asRecord(await startSmartTest(dev.device, kind))
    if (generation !== loadSeq || !pageAlive) return
    toast(j.ok ? `✅ ${t('main_extra.smart_started')}` : `❌ ${finiteText(j.message, '') || finiteText(j.error)}`)
    if (j.ok) {
      const seq = loadSeq
      const id = setTimeout(async () => {
        refreshTimers.delete(id)
        try {
          const next = wrapSmart(await getSmartOverview())
          if (seq !== loadSeq || !pageAlive) return
          smartData.value = next
        } catch {}
      }, 3000)
      refreshTimers.add(id)
    }
  } catch (e) {
    if (generation !== loadSeq || !pageAlive) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (pageAlive) smartTestBusy.value = false
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
