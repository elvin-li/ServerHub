<template>
  <div class="svc-page">
    <!-- No visible page title on this layout; see Dashboard.vue. -->
    <h1 class="sr-only">{{ t('services.title') }}</h1>
    <!-- Problems banner -->
    <div v-if="asArray(status?.problems).length" class="problems-bar">
      <strong>{{ t('services.problems') }}</strong>
      <!-- LEDs: warn vs down reached a sighted reader in colour alone, so
           hide the paint and spell the state — same treatment as the
           Containers rows and Dashboard cards. ledText reuses the state-chip
           words, so no new locale strings. -->
      <span v-for="p in asArray(status.problems).slice(0, 8)" :key="p.id" class="prob-chip" @click="openDetail(p)" tabindex="0" role="button" @keydown.enter.prevent="openDetail(p)" @keydown.space.prevent="openDetail(p)">
        <span class="led" :class="ledOf(p.state)" aria-hidden="true"></span>
        <span class="sr-only">{{ ledText(p.state) }}</span>
        {{ finiteText(p.name) }}
      </span>
      <button v-if="canManage" type="button" class="tiny primary" :disabled="busy || !downIds.length" @click="bulkAction(downIds, 'start')">
        {{ t('services.start_all_down') }}
      </button>
      <button v-if="canManage" type="button" class="tiny" :disabled="busy || !warnIds.length" @click="bulkAction(warnIds, 'restart')">
        {{ t('services.restart_all_warn') }}
      </button>
    </div>

    <!-- Quick links -->
    <div v-if="asArray(status?.links).length" class="quick-links">
      <a v-for="l in status.links" :key="finiteText(l.url)" class="btn tiny" :href="finiteText(l.url, '')" target="_blank" rel="noopener">{{ finiteText(l.name) }}</a>
    </div>

    <!-- Toolbar: one row — refresh, filter, selects, then the compact toggle cluster -->
    <div class="toolbar svc-toolbar">
      <button class="primary" type="button" :disabled="loading" @click="refresh(true)">{{ t('common.refresh') }}</button>
      <input v-model="q" type="text" class="search" :placeholder="t('services.filter_ph')"  :aria-label="t('services.filter_ph')"/>
      <select v-model="kindF" class="cat-select" :aria-label="t('services.filter_kind')">
        <option value="">{{ t('services.kind_all') }}</option>
        <option v-for="k in kindOptions" :key="k" :value="k">{{ kindLabel(k) }}</option>
      </select>
      <select v-model="groupF" class="cat-select" :aria-label="t('services.filter_group')">
        <option value="">{{ t('services.group_all') }}</option>
        <option v-for="g in groupOptions" :key="g" :value="g">{{ displayGroup(g) }}</option>
      </select>
      <select v-model="sortBy" class="cat-select" :aria-label="t('common.sort_by')">
        <option value="group">{{ t('services.sort_group') }}</option>
        <option value="name">{{ t('services.sort_name') }}</option>
        <option value="state">{{ t('services.sort_state') }}</option>
        <option value="kind">{{ t('services.sort_kind') }}</option>
      </select>
      <span class="toolbar-toggles">
        <label class="chk"><input type="checkbox" v-model="onlyBad" /> {{ t('services.only_bad') }}</label>
        <label class="chk"><input type="checkbox" v-model="dense" /> {{ t('services.dense') }}</label>
        <!-- role=status: the count is the only feedback the filter box and
             state chips give, and it changed silently for a screen reader. -->
        <span class="meta-count" role="status">{{ filtered.length }} / {{ flat.length }}</span>
      </span>
      <span class="meta svc-summary" v-if="status">
        {{ t('services.summary', {
          ok: finiteN(status.counts?.ok, 0),
          warn: finiteN(status.counts?.warn, 0),
          down: finiteN(status.counts?.down, 0),
          stopped: finiteN(status.counts?.stopped, 0),
          ts: finiteText(status.ts),
        }) }}
        · {{ finiteN(status.service_total, flat.length) }} {{ t('services.total_unit') }}
        <span v-if="!status.engine_up" class="warn-tag">{{ t('services.engine_down') }}</span>
      </span>
    </div>

    <!-- State chips: status shortcuts, kept as their own visual row -->
    <div class="state-chips">
      <button type="button" class="chip" :class="{ active: stateF === '' }" :aria-pressed="stateF === ''" @click="stateF = ''">
        {{ t('common.all') }} {{ flat.length }}
      </button>
      <button type="button" class="chip chip-ok" :class="{ active: stateF === 'ok' }" :aria-pressed="stateF === 'ok'" @click="stateF = stateF === 'ok' ? '' : 'ok'">
        {{ t('services.state_ok') }} {{ finiteN(status?.counts?.ok, 0) }}
      </button>
      <button type="button" class="chip chip-warn" :class="{ active: stateF === 'warn' }" :aria-pressed="stateF === 'warn'" @click="stateF = stateF === 'warn' ? '' : 'warn'">
        {{ t('services.state_warn') }} {{ finiteN(status?.counts?.warn, 0) }}
      </button>
      <button type="button" class="chip chip-down" :class="{ active: stateF === 'down' }" :aria-pressed="stateF === 'down'" @click="stateF = stateF === 'down' ? '' : 'down'">
        {{ t('services.state_down') }} {{ finiteN(status?.counts?.down, 0) }}
      </button>
      <button type="button" class="chip chip-muted" :class="{ active: stateF === 'stopped' }" :aria-pressed="stateF === 'stopped'" @click="stateF = stateF === 'stopped' ? '' : 'stopped'">
        {{ t('services.state_stopped') }} {{ finiteN(status?.counts?.stopped, 0) }}
      </button>
    </div>

    <!-- First load: neither the dense table's empty row nor the card grid's
         placeholder can distinguish "not fetched" from "nothing installed", and
         the services scan shells out per launchd job, so that window is long
         enough to read. -->
    <LoadFailure v-if="loadError" :detail="loadError" :retry="() => refresh(true)" :busy="loading" />
    <SkeletonLoader v-if="!loaded" :variant="dense ? 'table' : 'cards'" :cols="8" :rows="8" />

    <!-- Dense table.  On a failed *first* load nothing was fetched, so the
         banner stands alone: the table used to render its column headers
         above nothing (the empty-row is loadError-suppressed), claiming a
         listing that never arrived.  When a 15s re-poll fails the stale rows
         stay on screen under the banner instead (the LoadFailure contract —
         same as Containers and the Users accounts table). -->
    <template v-else-if="dense">
      <div v-if="flat.length || !loadError" class="table-wrap">
        <table class="dense svc-table fit-m">
          <thead>
            <tr>
              <th v-if="canManage" class="col-check"><input type="checkbox" :checked="allSelected" :aria-label="t('common.select_all')" @change="toggleSelectAll" /></th>
              <th><span class="sr-only">{{ t('common.status_led') }}</span></th>
              <th>{{ t('common.name') }}</th>
              <th class="col-hide-m">{{ t('services.group') }}</th>
              <th class="col-hide-m">{{ t('services.kind') }}</th>
              <th>{{ t('services.port') }}</th>
              <th class="col-hide-m">{{ t('services.detail') }}</th>
              <th>{{ t('common.actions') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="s in filtered"
              :key="s.id"
              :class="{ selected: selected.has(s.id), bad: s.state === 'down' || s.state === 'warn' }"
              @click="openDetail(s)" tabindex="0" @keydown.enter.prevent="openDetail(s)" @keydown.space.prevent="openDetail(s)"
            >
              <td v-if="canManage" class="col-check" @click.stop>
                <!-- Named per row, like the Files list: thirty checkboxes all
                     called "Select this row" cannot be told apart in a screen
                     reader's form-controls listing. -->
                <input type="checkbox" :checked="selected.has(s.id)" :aria-label="t('common.select_row_name', { name: finiteText(s.name, '') || finiteText(s.id) })" @change="toggleSelect(s.id)" />
              </td>
              <!-- The sr-only column header names the column, but the cell
                   itself was empty: colour alone said whether the row runs. -->
              <td>
                <span class="led" :class="ledOf(s.state)" aria-hidden="true"></span>
                <span class="sr-only">{{ ledText(s.state) }}</span>
              </td>
              <td>
                <strong>{{ finiteText(s.name) }}</strong>
                <span v-if="signatureOf(s)" class="chip chip-sig chip-inline" :title="signatureOf(s).confidence === 'high' ? finiteText(signatureOf(s).name) : `${finiteText(signatureOf(s).name)}?`">
                  {{ signatureOf(s).confidence === 'high' ? finiteText(signatureOf(s).name) : `${finiteText(signatureOf(s).name)}?` }}
                </span>
                <div class="mono sub-id">{{ finiteText(s.id) }}</div>
                <div class="show-m sub">{{ displayGroup(s.group) }} · {{ kindLabel(s.kind) }}</div>
                <div v-if="finiteText(s.detail, '')" class="show-m sub">{{ finiteText(s.detail) }}</div>
              </td>
              <td class="col-hide-m">{{ displayGroup(s.group) }}</td>
              <td class="col-hide-m"><span class="badge kind-badge">{{ kindLabel(s.kind) }}</span></td>
              <td class="mono">{{ portOf(s) }}</td>
              <td class="detail-cell col-hide-m" :title="finiteText(s.detail)">{{ finiteText(s.detail) }}</td>
              <td class="actions-cell" @click.stop>
                <ServiceActions :service="s" :busy="busy" variant="table" @act="onAction(s, $event)" @logs="openLogs(s)" @more="openDetail(s)" />
              </td>
            </tr>
            <tr v-if="!filtered.length && !loadError">
              <!-- A filter that misses and a host with nothing discovered are
                   different answers (Tools/Network/Containers pattern). -->
              <td :colspan="canManage ? 8 : 7" class="empty-row">{{ flat.length ? t('common.no_match') : t('services.empty') }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <div v-if="selected.size" class="bulk-bar">
        <!-- role=status: checking rows gives no audible feedback otherwise —
             the count lives in a bar that only exists while something is
             selected, so a screen-reader user heard nothing change. -->
        <span role="status">{{ t('services.selected_n', { n: selected.size }) }}</span>
        <button type="button" class="tiny primary" :disabled="busy" @click="bulkAction([...selected], 'start')">{{ t('services.act_start') }}</button>
        <button type="button" class="tiny" :disabled="busy" @click="bulkAction([...selected], 'restart')">{{ t('services.act_restart') }}</button>
        <button type="button" class="tiny danger" :disabled="busy" @click="bulkAction([...selected], 'stop')">{{ t('services.act_stop') }}</button>
        <button type="button" class="tiny" @click="selected = new Set()">{{ t('common.cancel') }}</button>
      </div>
    </template>

    <!-- Card grid by group -->
    <template v-else>
      <template v-for="g in filteredGroups" :key="g.group">
        <h2 class="section-title">{{ displayGroup(g.group) }} <span class="meta-count">{{ g.services.length }}</span></h2>
        <div class="grid svc-grid">
          <!-- The button role sits on the name, not the <article>: the card also
               holds the ServiceActions buttons and a control may not contain
               other controls (ARIA nested-interactive) — same split as the
               Compose stack list. @click stays on the card for mouse users. -->
          <article v-for="s in g.services" :key="s.id" class="card svc-card" :class="s.state" @click="openDetail(s)">
            <div class="row">
              <span class="led" :class="ledOf(s.state)" aria-hidden="true"></span>
              <span class="sr-only">{{ ledText(s.state) }}</span>
              <span class="name" :title="finiteText(s.id)" tabindex="0" role="button" @keydown.enter.prevent="openDetail(s)" @keydown.space.prevent="openDetail(s)">{{ finiteText(s.name) }}</span>
              <span class="badge">{{ kindLabel(s.kind) }}</span>
              <span v-if="signatureOf(s)" class="chip chip-sig" :title="signatureOf(s).confidence === 'high' ? finiteText(signatureOf(s).name) : `${finiteText(signatureOf(s).name)}?`">
                {{ signatureOf(s).confidence === 'high' ? finiteText(signatureOf(s).name) : `${finiteText(signatureOf(s).name)}?` }}
              </span>
            </div>
            <div class="detail" :title="finiteText(s.detail)">{{ finiteText(s.detail) }}</div>
            <ServiceActions :service="s" :busy="busy" variant="card" @act="onAction(s, $event)" @logs="openLogs(s)" @more="openDetail(s)" @click.stop />
          </article>
        </div>
      </template>
      <div v-if="!filtered.length && !loadError" class="placeholder">{{ flat.length ? t('common.no_match') : t('services.empty') }}</div>
    </template>

    <!-- Detail drawer -->
    <ServiceDetailDrawer
      v-if="detail"
      :service="detail"
      :busy="busy"
      :can-manage="canManage"
      :can-uninstall="canUninstall(detail)"
      :log="detailLog"
      :log-source="detailLogSource"
      @close="closeDrawer"
      @act="onAction(detail, $event)"
      @load-logs="loadDetailLogs"
      @adopt="adopt"
      @save-script="saveScript"
      @forget="forgetScript"
      @save-override="saveOverride"
      @hide="hideService"
      @uninstall="openUninstall(detail)"
    />

    <!-- Logs modal (standalone) -->
    <ServiceLogsModal v-if="logModal" :entry="logModal" @close="logModal = null" @refresh="reloadLogModal" />

    <!-- Uninstall confirmation: spells out exactly what is removed vs kept -->
    <div ref="uninstallPanel" v-if="uninstallModal" class="modal-bg" @click.self="uninstallModal = null" role="presentation">
      <div class="modal uninstall-modal" role="dialog" aria-modal="true" aria-labelledby="svc-uninstall-title">
        <div class="drawer-head">
          <h2 id="svc-uninstall-title" class="drawer-title">{{ t('services.uninstall_title', { name: finiteText(uninstallModal.name) }) }}</h2>
          <button type="button" @click="uninstallModal = null">{{ t('common.close') }}</button>
        </div>
        <div class="mono sub-id" style="margin-bottom:10px">{{ finiteText(uninstallModal.plist) }}</div>
        <section class="uninstall-sec">
          <h3 class="danger-text">{{ t('services.uninstall_removes') }}</h3>
          <ul class="plain-list">
            <li>{{ t('services.uninstall_item_registration') }}</li>
            <li>{{ t('services.uninstall_item_plist') }}</li>
            <li>{{ t('services.uninstall_item_override') }}</li>
            <li v-if="uninstallModal.removeData">{{ t('services.uninstall_item_program') }}</li>
          </ul>
        </section>
        <section class="uninstall-sec">
          <h3>{{ t('services.uninstall_keeps') }}</h3>
          <ul class="plain-list">
            <li v-if="!uninstallModal.removeData">{{ t('services.uninstall_item_program') }}</li>
            <li v-if="!uninstallModal.removeData">{{ t('services.uninstall_item_config') }}</li>
            <li v-if="!uninstallModal.removeData">{{ t('services.uninstall_item_data') }}</li>
            <li>{{ t('services.uninstall_item_logs') }}</li>
          </ul>
        </section>
        <label v-if="uninstallModal.can_remove_data" class="chk" style="margin:10px 0;display:flex">
          <input v-model="uninstallModal.removeData" type="checkbox" />
          {{ t('services.uninstall_also_delete_tree') }}
        </label>
        <p v-if="uninstallModal.removeData && uninstallModal.remove_data_path" class="hint">
          {{ t('services.uninstall_tree_hint', { path: finiteText(uninstallModal.remove_data_path) }) }}
        </p>
        <p class="hint">{{ t('services.uninstall_reversible') }}</p>
        <div class="drawer-actions" style="margin-top:12px">
          <button type="button" class="danger" :disabled="busy" @click="confirmUninstall">{{ t('services.uninstall_confirm') }}</button>
          <button type="button" @click="uninstallModal = null">{{ t('common.cancel') }}</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, inject, onMounted, onUnmounted, ref } from 'vue'
import { startVisibleInterval } from '../lib/poll'
import {
  adoptService,
  bulkServiceAction,
  doAction,
  forgetServiceScript,
  getServiceDetail,
  getServiceLogs,
  getServices,
  getServiceUninstallPreview,
  setServiceHidden,
  uninstallService,
  updateServiceOverride,
  updateServiceScript,
} from '../api/client'
import { injectI18n } from '../i18n'
import { groupI18nKey } from '../i18n/groupLabels'
import { authState } from '../lib/authState'
import { asArray, finiteN, finiteText } from '../lib/finite'
import { canLogs, ledOf, portOf, serviceLabels, signatureOf } from '../lib/serviceActions'
import { useDismissable } from '../composables/useDismissable'
import SkeletonLoader from '../components/SkeletonLoader.vue'
import LoadFailure from '../components/LoadFailure.vue'
import ServiceActions from '../components/ServiceActions.vue'
import ServiceDetailDrawer from '../components/ServiceDetailDrawer.vue'
import ServiceLogsModal from '../components/ServiceLogsModal.vue'

const toast = inject('toast')
const { t } = injectI18n()
const { actLabel, kindLabel } = serviceLabels(t)

function displayGroup(name) {
  const key = groupI18nKey(name)
  return key ? t(key) : finiteText(name)
}

// Spelled-out twin of ledOf() for the LEDs (problems bar, table rows, cards):
// colour reaches a sighted reader and nobody else. Reuses the state-chip
// words, so no new locale strings (Dashboard/Containers pattern).
function ledText(state) {
  if (state === 'ok') return t('services.state_ok')
  if (state === 'warn') return t('services.state_warn')
  if (state === 'stopped') return t('services.state_stopped')
  return t('services.state_down')
}

// Members get a read-only page: mutating controls (bulk actions, hide,
// override editing) are admin-only and the backend refuses them anyway.
const canManage = computed(() => authState.canManage)

const status = ref(null)
const busy = ref(false)
const loading = ref(false)
// Latched at the end of the first refresh, success or failure, so the skeleton
// never survives a settled load.
const loaded = ref(false)
const loadError = ref('')
// Phones get the card grid: a 560px-min table only sideways-scrolls the page.
const dense = ref(
  typeof window === 'undefined' || typeof window.matchMedia !== 'function'
    ? true
    : !window.matchMedia('(max-width: 640px)').matches,
)
const q = ref('')
const onlyBad = ref(false)
const kindF = ref('')
const groupF = ref('')
const stateF = ref('')
const sortBy = ref('group')
const selected = ref(new Set())
const detail = ref(null)
const detailLog = ref(null)
const detailLogSource = ref('')
const logModal = ref(null)
const uninstallModal = ref(null)
const uninstallPanel = ref(null)
let timer = null
const refreshTimers = new Set()
let pageAlive = true
let detailGeneration = 0
let logGeneration = 0

function later(fn, ms) {
  const id = setTimeout(() => {
    refreshTimers.delete(id)
    if (!pageAlive) return
    fn()
  }, ms)
  refreshTimers.add(id)
}

const flat = computed(() => {
  const list = []
  for (const g of asArray(status.value?.groups)) {
    for (const s of asArray(g.services)) list.push(s)
  }
  return list
})

const kindOptions = computed(() => {
  const set = new Set(flat.value.map(s => s.kind).filter(Boolean))
  return [...set].sort()
})

const groupOptions = computed(() => {
  const set = new Set(flat.value.map(s => s.group).filter(Boolean))
  return [...set].sort()
})

const downIds = computed(() => flat.value.filter(s => s.state === 'down').map(s => s.id))
const warnIds = computed(() => flat.value.filter(s => s.state === 'warn').map(s => s.id))

const stateRank = { down: 0, warn: 1, stopped: 2, ok: 3, unknown: 4 }

const filtered = computed(() => {
  let list = flat.value
  if (onlyBad.value) list = list.filter(s => s.state !== 'ok' && s.state !== 'stopped')
  if (stateF.value) list = list.filter(s => s.state === stateF.value)
  if (kindF.value) list = list.filter(s => s.kind === kindF.value)
  if (groupF.value) list = list.filter(s => s.group === groupF.value)
  const qq = q.value.trim().toLowerCase()
  if (qq) {
    list = list.filter(s =>
      (s.name || '').toLowerCase().includes(qq)
      || (s.id || '').toLowerCase().includes(qq)
      || (s.group || '').toLowerCase().includes(qq)
      || displayGroup(s.group).toLowerCase().includes(qq)
      || (s.kind || '').toLowerCase().includes(qq)
      || (s.detail || '').toLowerCase().includes(qq)
      || String(s.port || '').includes(qq)
      || (s.url || '').toLowerCase().includes(qq)
      || (signatureOf(s)?.name || '').toLowerCase().includes(qq)
      || (signatureOf(s)?.category || '').toLowerCase().includes(qq)
    )
  }
  const sb = sortBy.value
  list = [...list].sort((a, b) => {
    if (sb === 'state') return (stateRank[a.state] ?? 9) - (stateRank[b.state] ?? 9) || (a.name || '').localeCompare(b.name || '')
    if (sb === 'name') return (a.name || '').localeCompare(b.name || '')
    if (sb === 'kind') return (a.kind || '').localeCompare(b.kind || '') || (a.name || '').localeCompare(b.name || '')
    // group
    return (a.group || '').localeCompare(b.group || '') || (a.name || '').localeCompare(b.name || '')
  })
  return list
})

const filteredGroups = computed(() => {
  const map = new Map()
  for (const s of filtered.value) {
    const g = s.group || t('services.other_group')
    if (!map.has(g)) map.set(g, [])
    map.get(g).push(s)
  }
  return [...map.entries()].map(([group, services]) => ({ group, services }))
})

const allSelected = computed(() => filtered.value.length > 0 && filtered.value.every(s => selected.value.has(s.id)))

function toggleSelect(id) {
  const n = new Set(selected.value)
  if (n.has(id)) n.delete(id)
  else n.add(id)
  selected.value = n
}

function toggleSelectAll(e) {
  if (e.target.checked) selected.value = new Set(filtered.value.map(s => s.id))
  else selected.value = new Set()
}

async function refresh(force = false) {
  loading.value = true
  try {
    const next = await getServices(force)
    if (!pageAlive) return
    status.value = next
    loadError.value = ''
  } catch (e) {
    if (!pageAlive) return false
    loadError.value = finiteText(e.message || String(e), '')
    // The 15s tick passes force=false, so background failures stay silent —
    // LoadFailure already marks the state on screen, and a toast per interval
    // while the panel is down is pure noise. Manual paths pass force=true.
    if (force) toast('❌ ' + finiteText(e.message || e))
    // Tell the 15s poller the tick failed so lib/poll.js backs off while the
    // server stays unreachable.
    return false
  } finally {
    if (pageAlive) {
      loading.value = false
      loaded.value = true
    }
  }
}

async function onAction(svc, action) {
  // restart included: it interrupts a running service, which is the same class of
  // disruption as stop and deserves the same prompt.
  if (['stop', 'remove', 'kill', 'restart'].includes(action) && !confirm(t('services.confirm_action', { name: finiteText(svc.name), action: actLabel(action) }))) return
  busy.value = true
  toast(t('services.running_action', { name: finiteText(svc.name), action: actLabel(action) }))
  try {
    const r = await doAction(svc.id, action)
    if (!pageAlive) return
    toast(r.ok ? `✅ ${finiteText(svc.name)}` : `❌ ${finiteText(r.message, '').slice(0, 90)}`)
  } catch (e) {
    if (!pageAlive) return
    toast('❌ ' + finiteText(e.message || e))
  } finally {
    if (pageAlive) busy.value = false
    later(() => refresh(true), 1000)
    const id = svc.id
    later(() => {
      if (detail.value?.id === id) openDetail(svc, true)
    }, 1200)
  }
}

async function bulkAction(ids, action) {
  if (!ids.length) return
  // Confirm anything that interrupts running services, not just stop. "Restart
  // all warn" and the bulk-bar Restart both hit every selected service at once,
  // which is a wider blast radius than a single stop.
  if (['stop', 'restart'].includes(action)
    && !confirm(t('services.confirm_bulk', { n: ids.length, action: actLabel(action) }))) return
  busy.value = true
  toast(t('services.bulk_running', { n: ids.length, action: actLabel(action) }))
  try {
    const result = await bulkServiceAction(ids, action)
    if (!pageAlive) return
    toast(result.ok ? `✅ ${finiteN(result.ok_count, 0)}` : `⚠ ok ${finiteN(result.ok_count, 0)} / fail ${finiteN(result.fail_count, 0)}`)
  } catch (e) {
    if (!pageAlive) return
    toast('❌ ' + finiteText(e.message || e))
  } finally {
    if (pageAlive) {
      busy.value = false
      selected.value = new Set()
    }
    later(() => refresh(true), 1200)
  }
}

async function openDetail(svc, silent = false) {
  const generation = ++detailGeneration
  if (!silent) detailLog.value = null
  try {
    const next = await getServiceDetail(svc.id)
    if (generation !== detailGeneration || !pageAlive) return
    detail.value = next
  } catch (e) {
    if (generation !== detailGeneration || !pageAlive) return
    if (e.status === 404) {
      detail.value = { ...svc, can_logs: canLogs(svc), can_edit: true }
    } else {
      toast('❌ ' + finiteText(e.message || e))
    }
  }
}

// ── Uninstall ────────────────────────────────────────────────────────────────
// Only launch agents can be uninstalled.  The backend enforces this too (and
// refuses the panel's own agents), but hiding the button avoids offering an
// action that is guaranteed to fail.
function canUninstall(s) {
  return Boolean(authState.canManage && s && s.kind === 'launchd' && s.id)
}

async function openUninstall(svc) {
  busy.value = true
  try {
    const preview = await getServiceUninstallPreview(svc.id)
    if (!pageAlive) return
    uninstallModal.value = {
      id: svc.id,
      name: finiteText(svc.name, '') || finiteText(svc.id),
      plist: preview.plist,
      can_remove_data: Boolean(preview.can_remove_data),
      remove_data_path: preview.remove_data_path || '',
      removeData: false,
    }
  } catch (e) {
    if (!pageAlive) return
    toast('❌ ' + finiteText(e.message || e))
  }
  if (pageAlive) busy.value = false
}

async function confirmUninstall() {
  const target = uninstallModal.value
  if (!target) return
  busy.value = true
  toast(t('services.uninstall_running', { name: finiteText(target.name) }))
  try {
    const r = await uninstallService(target.id, { remove_data: Boolean(target.removeData) })
    if (!pageAlive) return
    const backup = String(finiteText(r.backup, '')).split('/').pop()
    toast(t('services.uninstall_done', { name: finiteText(target.name), backup: finiteText(backup) }))
    uninstallModal.value = null
    closeDrawer()
    await refresh(true)
  } catch (e) {
    if (!pageAlive) return
    toast('❌ ' + finiteText(e.message || e))
  }
  if (pageAlive) busy.value = false
}

function closeDrawer() {
  detailGeneration += 1
  detail.value = null
  detailLog.value = null
}

async function adopt(body) {
  if (!detail.value?.can_adopt) return
  busy.value = true
  try {
    const r = await adoptService(detail.value.id, body)
    if (!pageAlive) return
    toast(`✅ ${t('services.adopt_done', { name: finiteText(r.entry?.name, '') || finiteText(r.id) })}`)
    closeDrawer()
    await refresh(true)
  } catch (e) {
    if (!pageAlive) return
    toast('❌ ' + finiteText(e.message || e))
  } finally {
    if (pageAlive) busy.value = false
  }
}

async function saveScript(body) {
  if (!detail.value?.can_edit_script) return
  busy.value = true
  try {
    const saved = detail.value
    await updateServiceScript(saved.id, body)
    if (!pageAlive) return
    toast(`✅ ${t('common.save')}`)
    await Promise.all([refresh(true), openDetail(saved, true)])
  } catch (e) {
    if (!pageAlive) return
    toast('❌ ' + finiteText(e.message || e))
  } finally {
    if (pageAlive) busy.value = false
  }
}

async function forgetScript() {
  if (!detail.value?.can_forget) return
  if (!confirm(t('services.confirm_forget', { name: finiteText(detail.value.name) }))) return
  busy.value = true
  try {
    await forgetServiceScript(detail.value.id)
    if (!pageAlive) return
    toast(`✅ ${t('services.forgotten')}`)
    closeDrawer()
    await refresh(true)
  } catch (e) {
    if (!pageAlive) return
    toast('❌ ' + finiteText(e.message || e))
  } finally {
    if (pageAlive) busy.value = false
  }
}

async function saveOverride(body) {
  if (!detail.value) return
  busy.value = true
  try {
    const saved = detail.value
    await updateServiceOverride(saved.id, body)
    if (!pageAlive) return
    toast(`✅ ${t('common.save')}`)
    // Both re-reads observe the same just-written override and neither feeds the
    // other: refresh() rewrites the list, openDetail() rewrites the drawer. Run
    // them together so saving costs one full service scan, not a scan followed
    // by a detail fetch. `saved` is captured because the drawer may be closed by
    // the time these resolve.
    await Promise.all([refresh(true), openDetail(saved, true)])
  } catch (e) {
    if (!pageAlive) return
    toast('❌ ' + finiteText(e.message || e))
  } finally {
    if (pageAlive) busy.value = false
  }
}

async function hideService() {
  if (!detail.value) return
  if (!confirm(t('services.confirm_hide', { name: finiteText(detail.value.name) }))) return
  busy.value = true
  try {
    await setServiceHidden(detail.value.id, true)
    if (!pageAlive) return
    toast(`✅ ${t('services.hidden')}`)
    closeDrawer()
    await refresh(true)
  } catch (e) {
    if (!pageAlive) return
    toast('❌ ' + finiteText(e.message || e))
  } finally {
    if (pageAlive) busy.value = false
  }
}

async function openLogs(svc) {
  const generation = ++logGeneration
  try {
    const result = await getServiceLogs(svc.id, 200)
    if (generation !== logGeneration || !pageAlive) return
    logModal.value = { id: svc.id, name: finiteText(svc.name), source: result.source, log: result.log }
  } catch (e) {
    if (generation !== logGeneration || !pageAlive) return
    toast('❌ ' + finiteText(e.message || e))
  }
}

async function reloadLogModal() {
  if (!logModal.value) return
  await openLogs(logModal.value)
}

async function loadDetailLogs() {
  if (!detail.value) return
  const generation = detailGeneration
  const id = detail.value.id
  try {
    const result = await getServiceLogs(id, 200)
    if (generation !== detailGeneration || !pageAlive) return
    detailLog.value = result.log || ''
    detailLogSource.value = result.source || ''
  } catch (e) {
    if (generation !== detailGeneration || !pageAlive) return
    detailLog.value = finiteText(e.message || e, '')
    detailLogSource.value = 'error'
  }
}

onMounted(() => {
  pageAlive = true
  refresh()
  timer = startVisibleInterval(() => refresh(false), 15000)
})
onUnmounted(() => {
  pageAlive = false
  detailGeneration += 1
  logGeneration += 1
  if (typeof timer === 'function') timer()
  for (const id of refreshTimers) clearTimeout(id)
  refreshTimers.clear()
})


// Escape dismisses the uninstall dialog, focus returns to whatever opened it,
// and Tab cannot wander to the page behind the overlay. The drawer and the
// logs modal wire their own useDismissable internally.
useDismissable(uninstallModal, () => { uninstallModal.value = null }, uninstallPanel)
</script>

<style scoped>
.svc-page { min-width: 0; }
.svc-toolbar { flex-wrap: wrap; gap: 8px; }
.svc-toolbar .search { min-width: 200px; flex: 1; }
.svc-summary { color: var(--sub); font-size: 12px; line-height: 1.4; min-width: 0; }
.toolbar-toggles { display: inline-flex; align-items: center; gap: 10px; white-space: nowrap; }
/* Size and colour come from the global .meta-count. */
.meta-count { font-weight: 600; }
/* Flat --down on the page canvas is 3.25:1 at this size; the --down-text token
   keeps it unmistakably the alarm red while clearing AA, same as button.danger. */
.warn-tag {
  margin-left: 8px; color: var(--down-text); font-weight: 600; font-size: 12px;
}
.problems-bar {
  display: flex; flex-wrap: wrap; align-items: center; gap: 8px;
  padding: 10px 14px; margin-bottom: 12px;
  background: color-mix(in srgb, var(--down) 5%, var(--card));
  border: 1px solid color-mix(in srgb, var(--down) 25%, var(--line));
  border-left: 3px solid var(--down);
  border-radius: var(--radius);
  font-size: 12px;
}
.prob-chip {
  display: inline-flex; align-items: center; gap: 5px;
  padding: 3px 10px; border-radius: var(--radius-pill); background: var(--bg);
  border: 1px solid var(--line); cursor: pointer;
  transition: border-color .12s, background .12s;
}
.prob-chip:hover { border-color: var(--accent); background: var(--table-hover); }
.quick-links {
  display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 12px;
}
.state-chips {
  display: flex; flex-wrap: wrap; gap: 6px; margin: 0 0 12px;
}
.chip {
  border: 1px solid var(--line); background: var(--card); color: var(--txt);
  border-radius: var(--radius-pill); padding: 3px 10px; font-size: 12px; cursor: pointer;
  font-weight: 500; transition: border-color .12s, box-shadow .12s;
}
.chip.active { border-color: var(--accent); box-shadow: 0 0 0 1px var(--accent); }
.chip-ok.active, .chip-ok { border-color: color-mix(in srgb, var(--ok) 50%, var(--line)); }
.chip-warn.active { border-color: var(--warn); }
.chip-down.active { border-color: var(--down); }
.chip-muted { opacity: .85; }
/* --accent-text, not --accent: this is 10-12px label text on --card, and the
   raw accent measures 2.3-4.0:1 there in most themes (contrast.test.js). */
.chip-sig {
  border-color: color-mix(in srgb, var(--accent) 55%, var(--line)); color: var(--accent-text); font-weight: 600; cursor: default;
  display: inline-block; white-space: nowrap; overflow-wrap: normal; word-break: normal;
  max-width: 100%; overflow: hidden; text-overflow: ellipsis; vertical-align: middle;
}
.chip-inline { margin-left: 6px; padding: 1px 7px; font-size: 10px; vertical-align: middle; }
.chk { font-size: 12px; color: var(--sub); display: inline-flex; align-items: center; gap: 5px; }

.svc-table tr { cursor: pointer; transition: background .1s; }
.svc-table tr:hover { background: var(--table-hover); }
.svc-table tr.selected { background: color-mix(in srgb, var(--accent) 10%, transparent); }
:global([data-theme="macos"] .svc-table tr.selected),
:global([data-theme="macos"] .svc-table tr.selected td),
:global([data-theme="macos"] .svc-table tr.selected:hover),
:global([data-theme="macos"] .svc-table tr.selected:hover td),
:global([data-theme="macos-dark"] .svc-table tr.selected),
:global([data-theme="macos-dark"] .svc-table tr.selected td),
:global([data-theme="macos-dark"] .svc-table tr.selected:hover),
:global([data-theme="macos-dark"] .svc-table tr.selected:hover td) {
  background: var(--accent-fill);
  color: var(--on-accent);
  box-shadow: none;
}
:global([data-theme="macos"] .svc-table tr.selected .sub-id),
:global([data-theme="macos"] .svc-table tr.selected .detail-cell),
:global([data-theme="macos-dark"] .svc-table tr.selected .sub-id),
:global([data-theme="macos-dark"] .svc-table tr.selected .detail-cell) {
  /* The row's fill is --accent-fill; its ink has to be the paired token. */
  color: var(--on-accent);
}
.svc-table tr.bad { box-shadow: inset 3px 0 0 var(--down); }
.col-check { width: 32px; }
.sub-id { font-size: 10px; color: var(--sub); margin-top: 2px; }
.detail-cell { max-width: 220px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 12px; color: var(--sub); }
.actions-cell { vertical-align: middle; }
.svc-table .actions-cell :deep(.act-row) { align-items: center; }
.kind-badge { font-size: 10px; }
.empty-row { text-align: center; color: var(--sub); padding: 24px; }
.bulk-bar {
  position: sticky; bottom: 10px; margin-top: 12px;
  display: flex; flex-wrap: wrap; gap: 8px; align-items: center;
  padding: 10px 14px; background: var(--card); border: 1px solid var(--accent);
  border-radius: var(--radius); box-shadow: 0 4px 20px rgba(0,0,0,.15);
  z-index: 5;
}

.svc-grid { margin-bottom: 16px; }
.svc-card { cursor: pointer; transition: border-color .15s, transform .1s; }
.svc-card:hover { transform: translateY(-1px); }
.svc-card .row { display: flex; align-items: center; gap: 8px; margin-bottom: 6px; }
.svc-card .name { font-weight: 600; flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.svc-card .detail { font-size: 12px; color: var(--sub); margin-bottom: 8px; min-height: 1.4em; }

/* Uninstall confirmation (the drawer and logs modal carry their own copies). */
.drawer-head { display: flex; justify-content: space-between; gap: 12px; align-items: flex-start; margin-bottom: 14px; }
.drawer-title { margin: 0; font-size: 18px; font-weight: 700; }
.drawer-actions { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 14px; }
.plain-list { margin: 0; padding-left: 18px; font-size: 11px; }

@media (max-width: 640px) {
  .detail-cell { max-width: 100px; }
  .svc-toolbar .search { min-width: 0; flex: 1 1 140px; }
}
</style>
