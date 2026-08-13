<template>
  <div class="svc-page">
    <div class="page-title">
      <h1>{{ t('services.title') }}</h1>
      <span class="meta" v-if="status">
        {{ t('services.summary', {
          ok: status.counts?.ok ?? 0,
          warn: status.counts?.warn ?? 0,
          down: status.counts?.down ?? 0,
          stopped: status.counts?.stopped ?? 0,
          ts: status.ts,
        }) }}
        · {{ status.service_total ?? flat.length }} {{ t('services.total_unit') }}
        <span v-if="!status.engine_up" class="warn-tag">{{ t('services.engine_down') }}</span>
      </span>
    </div>

    <!-- Problems banner -->
    <div v-if="(status?.problems || []).length" class="problems-bar">
      <strong>{{ t('services.problems') }}</strong>
      <span v-for="p in (status.problems || []).slice(0, 8)" :key="p.id" class="prob-chip" @click="openDetail(p)" tabindex="0" role="button" @keydown.enter.prevent="openDetail(p)" @keydown.space.prevent="openDetail(p)">
        <span class="led" :class="ledOf(p.state)"></span>
        {{ p.name }}
      </span>
      <button v-if="canManage" type="button" class="tiny primary" :disabled="busy || !downIds.length" @click="bulkAction(downIds, 'start')">
        {{ t('services.start_all_down') }}
      </button>
      <button v-if="canManage" type="button" class="tiny" :disabled="busy || !warnIds.length" @click="bulkAction(warnIds, 'restart')">
        {{ t('services.restart_all_warn') }}
      </button>
    </div>

    <!-- Quick links -->
    <div v-if="(status?.links || []).length" class="quick-links">
      <a v-for="l in status.links" :key="l.url" class="btn tiny" :href="l.url" target="_blank" rel="noopener">{{ l.name }}</a>
    </div>

    <!-- Toolbar -->
    <div class="toolbar svc-toolbar">
      <button class="primary" type="button" :disabled="loading" @click="refresh(true)">{{ t('common.refresh') }}</button>
      <input v-model="q" type="text" class="search" :placeholder="t('services.filter_ph')"  :aria-label="t('services.filter_ph')"/>
      <select v-model="kindF" class="cat-select">
        <option value="">{{ t('services.kind_all') }}</option>
        <option v-for="k in kindOptions" :key="k" :value="k">{{ kindLabel(k) }}</option>
      </select>
      <select v-model="groupF" class="cat-select">
        <option value="">{{ t('services.group_all') }}</option>
        <option v-for="g in groupOptions" :key="g" :value="g">{{ g }}</option>
      </select>
      <select v-model="sortBy" class="cat-select">
        <option value="group">{{ t('services.sort_group') }}</option>
        <option value="name">{{ t('services.sort_name') }}</option>
        <option value="state">{{ t('services.sort_state') }}</option>
        <option value="kind">{{ t('services.sort_kind') }}</option>
      </select>
      <label class="chk"><input type="checkbox" v-model="onlyBad" /> {{ t('services.only_bad') }}</label>
      <label class="chk"><input type="checkbox" v-model="dense" /> {{ t('services.dense') }}</label>
      <span class="meta-count">{{ filtered.length }} / {{ flat.length }}</span>
    </div>

    <!-- State chips -->
    <div class="state-chips">
      <button type="button" class="chip" :class="{ active: stateF === '' }" @click="stateF = ''">
        {{ t('common.all') }} {{ flat.length }}
      </button>
      <button type="button" class="chip chip-ok" :class="{ active: stateF === 'ok' }" @click="stateF = stateF === 'ok' ? '' : 'ok'">
        {{ t('services.state_ok') }} {{ status?.counts?.ok ?? 0 }}
      </button>
      <button type="button" class="chip chip-warn" :class="{ active: stateF === 'warn' }" @click="stateF = stateF === 'warn' ? '' : 'warn'">
        {{ t('services.state_warn') }} {{ status?.counts?.warn ?? 0 }}
      </button>
      <button type="button" class="chip chip-down" :class="{ active: stateF === 'down' }" @click="stateF = stateF === 'down' ? '' : 'down'">
        {{ t('services.state_down') }} {{ status?.counts?.down ?? 0 }}
      </button>
      <button type="button" class="chip chip-muted" :class="{ active: stateF === 'stopped' }" @click="stateF = stateF === 'stopped' ? '' : 'stopped'">
        {{ t('services.state_stopped') }} {{ status?.counts?.stopped ?? 0 }}
      </button>
    </div>

    <!-- First load: neither the dense table's empty row nor the card grid's
         placeholder can distinguish "not fetched" from "nothing installed", and
         the services scan shells out per launchd job, so that window is long
         enough to read. -->
    <LoadFailure v-if="loadError" :detail="loadError" :retry="() => refresh(true)" :busy="loading" />
    <SkeletonLoader v-if="!loaded" :variant="dense ? 'table' : 'cards'" :cols="8" :rows="8" />

    <!-- Dense table -->
    <template v-else-if="dense">
      <div class="table-wrap">
        <table class="dense svc-table">
          <thead>
            <tr>
              <th v-if="canManage" class="col-check"><input type="checkbox" :checked="allSelected" @change="toggleSelectAll" /></th>
              <th></th>
              <th>{{ t('common.name') }}</th>
              <th>{{ t('services.group') }}</th>
              <th>{{ t('services.kind') }}</th>
              <th>{{ t('services.port') }}</th>
              <th>{{ t('services.detail') }}</th>
              <th>{{ t('common.actions') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="s in filtered"
              :key="s.id"
              :class="{ selected: selected.has(s.id), bad: s.state === 'down' || s.state === 'warn' }"
              @click="openDetail(s)" tabindex="0" role="button" @keydown.enter.prevent="openDetail(s)" @keydown.space.prevent="openDetail(s)"
            >
              <td v-if="canManage" class="col-check" @click.stop>
                <input type="checkbox" :checked="selected.has(s.id)" @change="toggleSelect(s.id)" />
              </td>
              <td><span class="led" :class="ledOf(s.state)"></span></td>
              <td>
                <strong>{{ s.name }}</strong>
                <div class="mono sub-id">{{ s.id }}</div>
              </td>
              <td>{{ s.group }}</td>
              <td><span class="badge kind-badge">{{ kindLabel(s.kind) }}</span></td>
              <td class="mono">{{ portOf(s) }}</td>
              <td class="detail-cell" :title="s.detail">{{ s.detail }}</td>
              <td class="actions-cell" @click.stop>
                <div class="act-row">
                  <a v-if="s.url" class="act-btn link primary" :href="s.url" target="_blank" rel="noopener" @click.stop>{{ t('services.open') }}</a>
                  <button v-if="canAct(s, 'start')" type="button" class="act-btn primary" :disabled="busy" @click="onAction(s, 'start')">{{ t('services.act_start') }}</button>
                  <button v-if="canAct(s, 'stop')" type="button" class="act-btn" :disabled="busy" @click="onAction(s, 'stop')">{{ t('services.act_stop') }}</button>
                  <button v-if="canAct(s, 'restart')" type="button" class="act-btn" :disabled="busy" @click="onAction(s, 'restart')">{{ t('services.act_restart') }}</button>
                  <button v-if="canAct(s, 'run')" type="button" class="act-btn" :disabled="busy" @click="onAction(s, 'run')">{{ t('services.act_run') }}</button>
                  <button v-if="canAct(s, 'pause')" type="button" class="act-btn" :disabled="busy" @click="onAction(s, 'pause')">{{ t('services.act_pause') }}</button>
                  <button v-if="canAct(s, 'unpause')" type="button" class="act-btn" :disabled="busy" @click="onAction(s, 'unpause')">{{ t('services.act_unpause') }}</button>
                  <button v-if="canLogs(s)" type="button" class="act-btn" @click="openLogs(s)">{{ t('services.logs') }}</button>
                  <button type="button" class="act-btn" @click="openDetail(s)" tabindex="0" role="button" @keydown.enter.prevent="openDetail(s)" @keydown.space.prevent="openDetail(s)">{{ t('services.more') }}</button>
                </div>
              </td>
            </tr>
            <tr v-if="!filtered.length && !loadError">
              <td :colspan="canManage ? 8 : 7" class="empty-row">{{ t('services.empty') }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <div v-if="selected.size" class="bulk-bar">
        <span>{{ t('services.selected_n', { n: selected.size }) }}</span>
        <button type="button" class="tiny primary" :disabled="busy" @click="bulkAction([...selected], 'start')">{{ t('services.act_start') }}</button>
        <button type="button" class="tiny" :disabled="busy" @click="bulkAction([...selected], 'restart')">{{ t('services.act_restart') }}</button>
        <button type="button" class="tiny danger" :disabled="busy" @click="bulkAction([...selected], 'stop')">{{ t('services.act_stop') }}</button>
        <button type="button" class="tiny" @click="selected = new Set()">{{ t('common.cancel') }}</button>
      </div>
    </template>

    <!-- Card grid by group -->
    <template v-else>
      <template v-for="g in filteredGroups" :key="g.group">
        <h2 class="section-title">{{ g.group }} <span class="meta-count">{{ g.services.length }}</span></h2>
        <div class="grid svc-grid">
          <article v-for="s in g.services" :key="s.id" class="card svc-card" :class="s.state" @click="openDetail(s)" tabindex="0" role="button" @keydown.enter.prevent="openDetail(s)" @keydown.space.prevent="openDetail(s)">
            <div class="row">
              <span class="led" :class="ledOf(s.state)"></span>
              <span class="name" :title="s.id">{{ s.name }}</span>
              <span class="badge">{{ kindLabel(s.kind) }}</span>
            </div>
            <div class="detail" :title="s.detail">{{ s.detail }}</div>
            <div class="btns" @click.stop>
              <a v-if="s.url" class="btn primary tiny" :href="s.url" target="_blank" rel="noopener">{{ t('services.open') }}</a>
              <button v-for="a in primaryActs(s)" :key="a" type="button" class="tiny" :class="{ danger: a === 'stop', primary: a === 'start' }" :disabled="busy" @click="onAction(s, a)">{{ actLabel(a) }}</button>
              <button v-if="canLogs(s)" type="button" class="tiny" @click="openLogs(s)">{{ t('services.logs') }}</button>
              <button type="button" class="tiny" @click="openDetail(s)" tabindex="0" role="button" @keydown.enter.prevent="openDetail(s)" @keydown.space.prevent="openDetail(s)">{{ t('services.more') }}</button>
            </div>
          </article>
        </div>
      </template>
      <div v-if="!filtered.length && !loadError" class="placeholder">{{ t('services.empty') }}</div>
    </template>

    <!-- Detail drawer -->
    <div v-if="detail" class="drawer-bg" @click.self="closeDrawer" role="presentation">
      <aside ref="detailPanel" class="drawer svc-drawer" role="dialog" aria-modal="true" aria-labelledby="svc-detail-title" tabindex="-1">
        <div class="drawer-head">
          <div>
            <h2 id="svc-detail-title" class="drawer-title">{{ detail.name }}</h2>
            <div class="app-badges" style="margin-top:6px">
              <span class="chip">{{ kindLabel(detail.kind) }}</span>
              <span class="chip" :class="stateChipClass(detail.state)">{{ stateLabel(detail.state) }}</span>
              <span v-if="detail.auto" class="chip chip-muted">auto</span>
              <span v-if="detail.signature" class="chip chip-sig" :title="detail.signature.category">
                {{ detail.signature.confidence === 'high' ? detail.signature.name : `${detail.signature.name}?` }}
              </span>
            </div>
            <div class="mono sub-id">{{ detail.id }}</div>
          </div>
          <button type="button" @click="closeDrawer">{{ t('common.close') }}</button>
        </div>

        <div class="drawer-actions">
          <a v-if="detail.url" class="btn primary" :href="detail.url" target="_blank" rel="noopener">{{ t('services.open') }}</a>
          <button v-if="canAct(detail, 'start')" type="button" class="primary" :disabled="busy" @click="onAction(detail, 'start')">{{ t('services.act_start') }}</button>
          <button v-if="canAct(detail, 'stop')" type="button" :disabled="busy" @click="onAction(detail, 'stop')">{{ t('services.act_stop') }}</button>
          <button v-if="canAct(detail, 'restart')" type="button" :disabled="busy" @click="onAction(detail, 'restart')">{{ t('services.act_restart') }}</button>
          <button v-if="canAct(detail, 'run')" type="button" :disabled="busy" @click="onAction(detail, 'run')">{{ t('services.act_run') }}</button>
          <button v-if="canAct(detail, 'pause')" type="button" :disabled="busy" @click="onAction(detail, 'pause')">{{ t('services.act_pause') }}</button>
          <button v-if="canAct(detail, 'unpause')" type="button" :disabled="busy" @click="onAction(detail, 'unpause')">{{ t('services.act_unpause') }}</button>
          <button v-if="detail.can_logs !== false && canLogs(detail)" type="button" @click="loadDetailLogs">{{ t('services.logs') }}</button>
          <button v-if="canManage" type="button" class="danger" :disabled="busy" @click="hideService">{{ t('services.hide') }}</button>
          <button v-if="canUninstall(detail)" type="button" class="danger" :disabled="busy" @click="openUninstall(detail)">{{ t('services.uninstall') }}</button>
        </div>

        <section class="drawer-sec">
          <h3>{{ t('services.sec_info') }}</h3>
          <div class="kv">
            <div class="k">{{ t('services.detail') }}</div><div>{{ detail.detail || '—' }}</div>
            <div class="k">{{ t('services.group') }}</div><div>{{ detail.group || '—' }}</div>
            <div class="k">URL</div><div class="mono">{{ detail.url || '—' }}</div>
            <div class="k">{{ t('services.port') }}</div><div class="mono">{{ portOf(detail) }}</div>
            <div v-if="detail.image" class="k">Image</div><div v-if="detail.image" class="mono">{{ detail.image }}</div>
            <div v-if="detail.restart_policy" class="k">Restart</div><div v-if="detail.restart_policy">{{ detail.restart_policy }}</div>
            <div v-if="detail.compose_project" class="k">Compose</div><div v-if="detail.compose_project" class="mono">{{ detail.compose_project }} / {{ detail.compose_service }}</div>
            <div v-if="detail.plist" class="k">plist</div><div v-if="detail.plist" class="mono break">{{ detail.plist }}</div>
            <div v-if="detail.program" class="k">Program</div><div v-if="detail.program" class="mono break">{{ detail.program }}</div>
            <div v-if="detail.run_at_load != null" class="k">RunAtLoad</div><div v-if="detail.run_at_load != null">{{ detail.run_at_load ? t('common.yes') : t('common.no') }}</div>
            <div v-if="detail.start_cmd" class="k">start</div><div v-if="detail.start_cmd" class="mono break">{{ detail.start_cmd }}</div>
            <div v-if="detail.stop_cmd" class="k">stop</div><div v-if="detail.stop_cmd" class="mono break">{{ detail.stop_cmd }}</div>
          </div>
          <div v-if="(detail.ports || []).length" class="ports-list mono">
            <div v-for="(p, i) in detail.ports" :key="i">{{ typeof p === 'object' ? JSON.stringify(p) : p }}</div>
          </div>
          <div v-if="(detail.links || []).length" class="quick-links" style="margin-top:8px">
            <a v-for="l in detail.links" :key="l.url" class="btn tiny" :href="l.url" target="_blank" rel="noopener">{{ l.name }}</a>
          </div>
        </section>

        <section class="drawer-sec" v-if="(detail.mounts || []).length">
          <h3>{{ t('services.sec_mounts') }}</h3>
          <ul class="plain-list mono">
            <li v-for="(m, i) in detail.mounts.slice(0, 12)" :key="i">{{ m.source }} → {{ m.destination }} {{ m.rw === false ? '(ro)' : '' }}</li>
          </ul>
        </section>

        <section class="drawer-sec" v-if="(detail.env_sample || []).length">
          <h3>{{ t('services.sec_env') }}</h3>
          <pre class="log mini-log">{{ (detail.env_sample || []).join('\n') }}</pre>
        </section>

        <section class="drawer-sec" v-if="detail.launchctl">
          <h3>launchctl</h3>
          <pre class="log mini-log">{{ detail.launchctl }}</pre>
        </section>

        <!-- Adopt auto-discovered listener into services.yaml -->
        <section class="drawer-sec" v-if="detail.can_adopt">
          <h3>{{ t('services.sec_adopt') }}</h3>
          <p class="hint-line">{{ t('services.adopt_hint') }}</p>
          <div v-if="detail.signature" class="hint-line">
            {{ t('services.identified_as', {
              name: detail.signature.name,
              category: detail.signature.category,
            }) }}
            <span v-if="detail.signature.confidence !== 'high'">({{ t('services.identified_guess') }})</span>
          </div>
          <div class="form-grid">
            <label>{{ t('common.name') }}
              <input v-model="adoptForm.name" type="text" />
            </label>
            <label>{{ t('services.group') }}
              <input v-model="adoptForm.group" type="text" />
            </label>
            <label>URL
              <input v-model="adoptForm.url" type="text" placeholder="http://…" />
            </label>
            <label>{{ t('services.adopt_ports') }}
              <input v-model="adoptForm.ports" type="text" placeholder="8080, 8443" />
            </label>
          </div>
          <div class="mono sub-id" style="margin-top:4px">id: {{ adoptForm.id }}</div>
          <div class="drawer-actions" style="margin-top:8px">
            <button type="button" class="primary" :disabled="busy" @click="adopt">{{ t('services.adopt') }}</button>
          </div>
        </section>

        <!-- Edit override (writes services.yaml — administrators only) -->
        <section class="drawer-sec" v-if="canManage">
          <h3>{{ t('services.sec_override') }}</h3>
          <p class="hint-line">{{ t('services.override_hint') }}</p>
          <div class="form-grid">
            <label>{{ t('common.name') }}
              <input v-model="editForm.name" type="text" />
            </label>
            <label>{{ t('services.group') }}
              <input v-model="editForm.group" type="text" />
            </label>
            <label>URL
              <input v-model="editForm.url" type="text" placeholder="http://…" />
            </label>
            <label>{{ t('services.port') }}
              <input v-model.number="editForm.port" type="number" min="1" max="65535" />
            </label>
          </div>
          <div class="drawer-actions" style="margin-top:8px">
            <button type="button" class="primary" :disabled="busy" @click="saveOverride">{{ t('common.save') }}</button>
            <button type="button" :disabled="busy" @click="resetEditForm">{{ t('common.cancel') }}</button>
          </div>
        </section>

        <!-- Logs in drawer -->
        <section class="drawer-sec" v-if="detailLog !== null">
          <h3>{{ t('services.logs') }} <span class="meta-count mono">{{ detailLogSource }}</span></h3>
          <div class="drawer-actions" style="margin-bottom:6px">
            <button type="button" class="tiny" @click="loadDetailLogs">{{ t('common.refresh') }}</button>
            <button type="button" class="tiny" @click="copyLog">{{ t('services.copy_log') }}</button>
          </div>
          <pre class="log">{{ detailLog || t('services.log_empty') }}</pre>
        </section>
      </aside>
    </div>

    <!-- Logs modal (standalone) -->
    <div ref="logPanel" v-if="logModal" class="modal-bg" @click.self="logModal = null" role="presentation">
      <div class="modal log-modal" role="dialog" aria-modal="true" aria-labelledby="svc-log-title">
        <div class="drawer-head">
          <div>
            <h2 id="svc-log-title" class="drawer-title">{{ logModal.name || logModal.id }} — {{ t('services.logs') }}</h2>
            <div class="mono sub-id">{{ logModal.source }}</div>
          </div>
          <div class="drawer-actions">
            <button type="button" class="tiny" @click="reloadLogModal">{{ t('common.refresh') }}</button>
            <button type="button" class="tiny" @click="copyModalLog">{{ t('services.copy_log') }}</button>
            <button type="button" @click="logModal = null">{{ t('common.close') }}</button>
          </div>
        </div>
        <pre class="log">{{ logModal.log || t('services.log_empty') }}</pre>
      </div>
    </div>

    <!-- Uninstall confirmation: spells out exactly what is removed vs kept -->
    <div ref="uninstallPanel" v-if="uninstallModal" class="modal-bg" @click.self="uninstallModal = null" role="presentation">
      <div class="modal uninstall-modal" role="dialog" aria-modal="true" aria-labelledby="svc-uninstall-title">
        <div class="drawer-head">
          <h2 id="svc-uninstall-title" class="drawer-title">{{ t('services.uninstall_title', { name: uninstallModal.name }) }}</h2>
          <button type="button" @click="uninstallModal = null">{{ t('common.close') }}</button>
        </div>
        <div class="mono sub-id" style="margin-bottom:10px">{{ uninstallModal.plist }}</div>
        <section class="uninstall-sec">
          <h3 class="danger-text">{{ t('services.uninstall_removes') }}</h3>
          <ul class="plain-list">
            <li>{{ t('services.uninstall_item_registration') }}</li>
            <li>{{ t('services.uninstall_item_plist') }}</li>
          </ul>
        </section>
        <section class="uninstall-sec">
          <h3>{{ t('services.uninstall_keeps') }}</h3>
          <ul class="plain-list">
            <li>{{ t('services.uninstall_item_program') }}</li>
            <li>{{ t('services.uninstall_item_config') }}</li>
            <li>{{ t('services.uninstall_item_data') }}</li>
            <li>{{ t('services.uninstall_item_logs') }}</li>
          </ul>
        </section>
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
import { computed, inject, onMounted, onUnmounted, reactive, ref } from 'vue'
import { startVisibleInterval } from '../lib/poll'
import {
  adoptService,
  bulkServiceAction,
  doAction,
  getServiceDetail,
  getServiceLogs,
  getServices,
  getServiceUninstallPreview,
  getStatus,
  setServiceHidden,
  uninstallService,
  updateServiceOverride,
} from '../api/client'
import { injectI18n } from '../i18n'
import { authState } from '../lib/authState'
import { useDismissable } from '../composables/useDismissable'
import SkeletonLoader from '../components/SkeletonLoader.vue'
import LoadFailure from '../components/LoadFailure.vue'

const toast = inject('toast')
const { t } = injectI18n()

// Members get a read-only page: mutating controls (bulk actions, hide,
// override editing) are admin-only and the backend refuses them anyway.
const canManage = computed(() => authState.canManage)

const status = ref(null)
const busy = ref(false)
const loading = ref(false)
// Latched at the end of the first refresh, including the 404 fallback path, so a
// server old enough to lack /api/services still leaves the skeleton behind.
const loaded = ref(false)
const loadError = ref('')
const dense = ref(true)
const q = ref('')
const onlyBad = ref(false)
const kindF = ref('')
const groupF = ref('')
const stateF = ref('')
const sortBy = ref('group')
const selected = ref(new Set())
const detail = ref(null)
const detailPanel = ref(null)
const detailLog = ref(null)
const detailLogSource = ref('')
const logModal = ref(null)
const logPanel = ref(null)
const uninstallModal = ref(null)
const uninstallPanel = ref(null)
const editForm = reactive({ name: '', group: '', url: '', port: null })
const adoptForm = reactive({ id: '', name: '', group: '', url: '', ports: '' })
let timer = null

const CONTROL_ACTS = new Set(['start', 'stop', 'restart', 'run', 'pause', 'unpause', 'remove', 'kill'])

const flat = computed(() => {
  const list = []
  for (const g of status.value?.groups || []) {
    for (const s of g.services || []) list.push(s)
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
      || (s.kind || '').toLowerCase().includes(qq)
      || (s.detail || '').toLowerCase().includes(qq)
      || String(s.port || '').includes(qq)
      || (s.url || '').toLowerCase().includes(qq)
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

function ledOf(state) {
  if (state === 'ok') return 'on'
  if (state === 'warn') return 'warn'
  if (state === 'stopped') return 'off'
  return 'err'
}

function kindLabel(k) {
  const map = {
    launchd: t('services.kind_launchd'),
    container: t('services.kind_container'),
    app: t('services.kind_app'),
    'app-engine': t('services.kind_engine'),
    script: t('services.kind_script'),
    vm: t('services.kind_vm'),
    auto: t('services.kind_auto'),
  }
  return map[k] || k || '—'
}

function stateLabel(st) {
  const map = {
    ok: t('services.state_ok'),
    warn: t('services.state_warn'),
    down: t('services.state_down'),
    stopped: t('services.state_stopped'),
  }
  return map[st] || st || '—'
}

function stateChipClass(st) {
  if (st === 'ok') return 'chip-ok'
  if (st === 'warn') return 'chip-warn'
  if (st === 'down') return 'chip-down'
  return 'chip-muted'
}

function actLabel(a) {
  const map = {
    start: t('services.act_start'),
    stop: t('services.act_stop'),
    restart: t('services.act_restart'),
    run: t('services.act_run'),
    pause: t('services.act_pause'),
    unpause: t('services.act_unpause'),
  }
  return map[a] || a
}

function portOf(s) {
  if (s.port != null) return `:${s.port}`
  if (Array.isArray(s.ports) && s.ports.length) {
    const first = s.ports[0]
    return typeof first === 'object' ? JSON.stringify(first) : String(first)
  }
  const m = (s.detail || '').match(/:(\d{2,5})\b/)
  return m ? `:${m[1]}` : '—'
}

function canAct(s, act) {
  if (!s) return false
  if ((s.actions || []).includes(act)) return true
  // Soft fallbacks only when the server sent no action list at all (older
  // servers / the /api/status fallback).  When it did, it is authoritative:
  // guessing here rendered Start/Stop buttons for entries the backend has no
  // way to control (adopted scripts without commands, auto-discovered ports),
  // and every such click failed.
  if (Array.isArray(s.actions)) return false
  if (act === 'start' && (s.state === 'down' || s.state === 'stopped')) return true
  if (act === 'stop' && s.state === 'ok') return true
  if (act === 'restart' && s.state === 'ok') return true
  return false
}

function canLogs(s) {
  if (!s) return false
  if (s.can_logs === false) return false
  if ((s.actions || []).includes('logs')) return true
  return ['container', 'launchd', 'script'].includes(s.kind)
}

function primaryActs(s) {
  return (s.actions || []).filter(a => CONTROL_ACTS.has(a)).slice(0, 3)
}

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
    status.value = await getServices(force)
    loadError.value = ''
  } catch (e) {
    if (e.status !== 404) {
      loadError.value = e.message || String(e)
      toast(`❌ ${e.message || e}`)
      return
    }
    try {
      // Older servers expose only the classic status endpoint. The client does
      // not currently accept a force flag here, so use its supported signature.
      status.value = await getStatus()
      // The 404 was expected on an older server and the fallback worked, so this
      // is a success: latching the 404 here would show a permanent error banner
      // on every old install.
      loadError.value = ''
    } catch (fallbackError) {
      loadError.value = fallbackError.message || String(fallbackError)
      toast(`❌ ${fallbackError.message || fallbackError}`)
    }
  } finally {
    loading.value = false
    loaded.value = true
  }
}

async function onAction(svc, action) {
  // restart included: it interrupts a running service, which is the same class of
  // disruption as stop and deserves the same prompt.
  if (['stop', 'remove', 'kill', 'restart'].includes(action) && !confirm(t('services.confirm_action', { name: svc.name, action: actLabel(action) }))) return
  busy.value = true
  toast(t('services.running_action', { name: svc.name, action: actLabel(action) }))
  try {
    const r = await doAction(svc.id, action)
    toast(r.ok ? `✅ ${svc.name}` : `❌ ${(r.message || '').slice(0, 90)}`)
  } catch (e) {
    toast(`❌ ${e.message || e}`)
  } finally {
    busy.value = false
    setTimeout(() => refresh(true), 1000)
    if (detail.value?.id === svc.id) setTimeout(() => openDetail(svc, true), 1200)
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
    toast(result.ok ? `✅ ${result.ok_count}` : `⚠ ok ${result.ok_count || 0} / fail ${result.fail_count || 0}`)
  } catch (e) {
    toast(`❌ ${e.message || e}`)
  } finally {
    busy.value = false
  }
  selected.value = new Set()
  setTimeout(() => refresh(true), 1200)
}

async function openDetail(svc, silent = false) {
  if (!silent) detailLog.value = null
  try {
    detail.value = await getServiceDetail(svc.id)
    resetEditForm()
  } catch (e) {
    if (e.status === 404) {
      detail.value = { ...svc, can_logs: canLogs(svc), can_edit: true }
      resetEditForm()
    } else {
      toast(`❌ ${e.message || e}`)
    }
  }
}

// ── Uninstall ────────────────────────────────────────────────────────────────
// Only launch agents can be uninstalled.  The backend enforces this too (and
// refuses the panel's own agents), but hiding the button avoids offering an
// action that is guaranteed to fail.
function canUninstall(s) {
  return Boolean(s && s.kind === 'launchd' && s.id)
}

async function openUninstall(svc) {
  busy.value = true
  try {
    const preview = await getServiceUninstallPreview(svc.id)
    uninstallModal.value = { id: svc.id, name: svc.name || svc.id, plist: preview.plist }
  } catch (e) {
    toast(`❌ ${e.message || e}`)
  }
  busy.value = false
}

async function confirmUninstall() {
  const target = uninstallModal.value
  if (!target) return
  busy.value = true
  toast(t('services.uninstall_running', { name: target.name }))
  try {
    const r = await uninstallService(target.id)
    const backup = String(r.backup || '').split('/').pop()
    toast(t('services.uninstall_done', { name: target.name, backup }))
    uninstallModal.value = null
    closeDrawer()
    await refresh(true)
  } catch (e) {
    toast(`❌ ${e.message || e}`)
  }
  busy.value = false
}

function closeDrawer() {
  detail.value = null
  detailLog.value = null
}

function resetEditForm() {
  const d = detail.value || {}
  const ov = d.override || {}
  editForm.name = ov.name != null ? ov.name : (d.name || '')
  editForm.group = ov.group != null ? ov.group : (d.group || '')
  editForm.url = ov.url != null ? ov.url : (d.url || '')
  editForm.port = ov.port != null ? ov.port : (d.port ?? null)
  const ad = d.adopt_defaults || {}
  adoptForm.id = ad.id || ''
  adoptForm.name = ad.name || ''
  adoptForm.group = ad.group || ''
  adoptForm.url = ad.url || ''
  adoptForm.ports = (ad.ports || []).join(', ')
}

async function adopt() {
  if (!detail.value?.can_adopt) return
  busy.value = true
  try {
    const ports = adoptForm.ports
      .split(/[\s,]+/)
      .map(p => parseInt(p, 10))
      .filter(p => Number.isInteger(p) && p >= 1 && p <= 65535)
    const r = await adoptService(detail.value.id, {
      id: adoptForm.id || null,
      name: adoptForm.name || null,
      group: adoptForm.group || null,
      url: adoptForm.url || null,
      ports: ports.length ? ports : null,
    })
    toast(`✅ ${t('services.adopt_done', { name: r.entry?.name || r.id })}`)
    closeDrawer()
    await refresh(true)
  } catch (e) {
    toast(`❌ ${e.message || e}`)
  } finally {
    busy.value = false
  }
}

async function saveOverride() {
  if (!detail.value) return
  busy.value = true
  try {
    const body = {
      name: editForm.name || null,
      group: editForm.group || null,
      url: editForm.url || null,
      port: editForm.port || null,
    }
    const saved = detail.value
    await updateServiceOverride(saved.id, body)
    toast(`✅ ${t('common.save')}`)
    // Both re-reads observe the same just-written override and neither feeds the
    // other: refresh() rewrites the list, openDetail() rewrites the drawer. Run
    // them together so saving costs one full service scan, not a scan followed
    // by a detail fetch. `saved` is captured because the drawer may be closed by
    // the time these resolve.
    await Promise.all([refresh(true), openDetail(saved, true)])
  } catch (e) {
    toast(`❌ ${e.message || e}`)
  } finally {
    busy.value = false
  }
}

async function hideService() {
  if (!detail.value) return
  if (!confirm(t('services.confirm_hide', { name: detail.value.name }))) return
  busy.value = true
  try {
    await setServiceHidden(detail.value.id, true)
    toast(`✅ ${t('services.hidden')}`)
    closeDrawer()
    await refresh(true)
  } catch (e) {
    toast(`❌ ${e.message || e}`)
  } finally {
    busy.value = false
  }
}

async function openLogs(svc) {
  try {
    const result = await getServiceLogs(svc.id, 200)
    logModal.value = { id: svc.id, name: svc.name, source: result.source, log: result.log }
  } catch (e) {
    toast(`❌ ${e.message || e}`)
  }
}

async function reloadLogModal() {
  if (!logModal.value) return
  await openLogs(logModal.value)
}

async function loadDetailLogs() {
  if (!detail.value) return
  try {
    const result = await getServiceLogs(detail.value.id, 200)
    detailLog.value = result.log || ''
    detailLogSource.value = result.source || ''
  } catch (e) {
    detailLog.value = String(e.message || e)
    detailLogSource.value = 'error'
  }
}

async function copyLog() {
  try {
    await navigator.clipboard.writeText(detailLog.value || '')
    toast('✅')
  } catch {
    toast('❌')
  }
}

async function copyModalLog() {
  try {
    await navigator.clipboard.writeText(logModal.value?.log || '')
    toast('✅')
  } catch {
    toast('❌')
  }
}

onMounted(() => {
  refresh()
  timer = startVisibleInterval(() => refresh(false), 15000)
})
onUnmounted(() => { if (typeof timer === 'function') timer() })


// Escape dismisses each dialog, focus returns to whatever opened it, and Tab
// cannot wander to the page behind the overlay.
useDismissable(detail, () => { closeDrawer() }, detailPanel)
useDismissable(logModal, () => { logModal.value = null }, logPanel)
useDismissable(uninstallModal, () => { uninstallModal.value = null }, uninstallPanel)
</script>

<style scoped>
.svc-page { min-width: 0; }
.svc-toolbar { flex-wrap: wrap; gap: 8px; }
.svc-toolbar .search { min-width: 200px; flex: 1; }
/* Size and colour come from the global .meta-count. */
.meta-count { font-weight: 600; }
.warn-tag {
  margin-left: 8px; color: var(--down); font-weight: 600; font-size: 12px;
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
  display: flex; flex-wrap: wrap; gap: 6px; margin: 0 0 14px;
}
.chip {
  border: 1px solid var(--line); background: var(--card); color: var(--txt);
  border-radius: var(--radius-pill); padding: 4px 12px; font-size: 12px; cursor: pointer;
  font-weight: 500; transition: border-color .12s, box-shadow .12s;
}
.chip.active { border-color: var(--accent); box-shadow: 0 0 0 1px var(--accent); }
.chip-ok.active, .chip-ok { border-color: color-mix(in srgb, var(--ok) 50%, var(--line)); }
.chip-warn.active { border-color: var(--warn); }
.chip-down.active { border-color: var(--down); }
.chip-muted { opacity: .85; }
.chip-sig { border-color: color-mix(in srgb, var(--accent) 55%, var(--line)); color: var(--accent); font-weight: 600; }
.chk { font-size: 12px; color: var(--sub); display: inline-flex; align-items: center; gap: 5px; }

.svc-table tr { cursor: pointer; transition: background .1s; }
.svc-table tr:hover { background: var(--table-hover); }
.svc-table tr.selected { background: color-mix(in srgb, var(--accent) 10%, transparent); }
.svc-table tr.bad { box-shadow: inset 3px 0 0 var(--down); }
.col-check { width: 32px; }
.sub-id { font-size: 10px; color: var(--sub); margin-top: 2px; }
.detail-cell { max-width: 220px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 12px; color: var(--sub); }
.kind-badge { font-size: 10px; }
.act-row { display: flex; flex-wrap: wrap; gap: 4px; }
.act-btn {
  font-size: 11px; padding: 3px 9px; border-radius: var(--radius);
  border: 1px solid var(--line); background: var(--card); color: var(--txt); cursor: pointer;
  text-decoration: none; display: inline-flex; align-items: center;
  transition: border-color .12s, background .12s;
}
.act-btn:hover { border-color: var(--accent); }
.act-btn.primary, .act-btn.link.primary { border-color: var(--accent); color: var(--accent); font-weight: 600; }
.act-btn:disabled { opacity: .4; cursor: not-allowed; }
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
.svc-card .btns { display: flex; flex-wrap: wrap; gap: 4px; }

.svc-drawer { overflow: auto; width: min(640px, 100vw); }
.drawer-head { display: flex; justify-content: space-between; gap: 12px; align-items: flex-start; margin-bottom: 14px; }
.drawer-title { margin: 0; font-size: 18px; font-weight: 700; }
.drawer-actions { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 14px; }
.drawer-sec { margin-bottom: 16px; padding-top: 10px; border-top: 1px solid var(--line); }
.drawer-sec h3 { margin: 0 0 8px; font-size: 11px; color: var(--sub); text-transform: uppercase; letter-spacing: .5px; font-weight: 700; }
.hint-line { font-size: 12px; color: var(--sub); margin: 0 0 8px; }
.form-grid {
  display: grid; grid-template-columns: 1fr 1fr; gap: 8px;
}
.form-grid label {
  display: flex; flex-direction: column; gap: 4px; font-size: 12px; color: var(--sub);
}
.form-grid input { width: 100%; }
.break { word-break: break-all; }
.ports-list { font-size: 11px; color: var(--sub); margin-top: 6px; }
.plain-list { margin: 0; padding-left: 18px; font-size: 11px; }
.mini-log { max-height: 160px; }
.log-modal { width: min(900px, 96vw); height: min(80vh, 720px); }
.log-modal .log { flex: 1; min-height: 0; }
.app-badges { display: flex; flex-wrap: wrap; gap: 4px; }

@media (max-width: 700px) {
  .form-grid { grid-template-columns: 1fr; }
  .detail-cell { max-width: 100px; }
}
</style>
