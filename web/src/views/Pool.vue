<template>
  <div>
    <div class="page-title">
      <h1>{{ t('pool.title') }}</h1>
      <span class="meta">{{ t('pool.meta') }}</span>
    </div>

    <div class="toolbar">
      <button class="primary" @click="refresh" :disabled="loading || busy">{{ t('common.refresh') }}</button>
      <span v-if="loaded" class="badge" :class="view?.configured ? 'ok' : ''">
        {{ view?.configured ? t('pool.state_configured', { n: asArray(view?.members).length }) : t('pool.state_unconfigured') }}
      </span>
      <span class="badge accent">{{ t('pool.badge_no_raid') }}</span>
    </div>

    <!-- What this is, and what it deliberately is not. -->
    <div class="tile" style="margin-bottom:12px;border-left:3px solid var(--accent)">
      <h2 style="margin:0 0 6px">{{ t('pool.model_title') }}</h2>
      <p class="note">{{ t('pool.model_body') }}</p>
    </div>

    <!-- A single merged mount point needs a union filesystem that is not
         installed; say so rather than letting the page imply one path. -->
    <div
      v-if="view && !view.union?.single_mount_supported"
      class="tile"
      style="margin-bottom:12px;border-left:3px solid var(--warn)"
    >
      <h2 style="margin:0 0 6px">{{ t('pool.union_title') }}</h2>
      <p class="note">{{ t('pool.union_body') }}</p>
      <p class="note" style="margin-top:6px">{{ t('pool.union_available') }}</p>
    </div>

    <!-- Configured members that are not mounted right now. -->
    <div
      v-if="asArray(view?.missing_members).length"
      class="tile"
      style="margin-bottom:12px;border-left:3px solid var(--warn)"
    >
      <h2 style="margin:0 0 6px">{{ t('pool.missing_title') }}</h2>
      <p class="note">{{ t('pool.missing_body') }}</p>
      <p class="mono" style="font-size:11px;margin:6px 0 0">
        <span v-for="m in asArray(view.missing_members)" :key="finiteText(m)" style="margin-right:10px">{{ finiteText(m) }}</span>
      </p>
    </div>

    <!-- Three tables here list pool members, spare candidates and faults. Before
         the first response all three read as "none", which on a storage page
         looks like the pool lost its disks rather than like a pending request. -->
    <template v-if="!loaded">
      <SkeletonLoader variant="tiles" :rows="4" :span="3" :tile-height="52" style="margin-bottom:12px" />
      <SkeletonLoader :cols="8" :rows="4" />
    </template>

    <template v-else>
    <!-- A failed read would otherwise render as "no members, no candidates, no
         faults", which on a storage pool reads like the pool lost its disks. -->
    <LoadFailure v-if="loadError" :detail="loadError" :retry="refresh" :busy="loading || busy" />
    <h2 class="section-title">
      {{ t('pool.summary_title') }}
      <span class="badge" :class="preview ? 'warn' : 'ok'" style="margin-left:6px">
        {{ preview ? t('pool.summary_preview') : t('pool.summary_saved') }}
      </span>
    </h2>
    <div class="dash-grid" style="margin-bottom:12px">
      <div class="tile span-3">
        <h3>{{ t('pool.sum_total') }}</h3>
        <div class="v" style="font-size:16px">
          {{ finiteN(asRecord(shownSummary).total_gb) }} <span class="unit">GB</span>
        </div>
        <div class="sub">{{ t('pool.sum_members', { n: finiteN(asRecord(shownSummary).member_count, 0) }) }}</div>
      </div>
      <div class="tile span-3">
        <h3>{{ t('pool.sum_used') }}</h3>
        <div class="v" style="font-size:16px">
          {{ finiteN(asRecord(shownSummary).used_gb) }} <span class="unit">GB</span>
        </div>
        <div class="sub">{{ t('common.free') }} {{ fmtGb(asRecord(shownSummary).avail_gb) }}</div>
        <div class="pct-bar" :class="barClass(asRecord(shownSummary).pct)" style="margin-top:6px">
          <i :style="{ width: barPct(asRecord(shownSummary).pct) + '%' }"></i>
        </div>
      </div>
      <div class="tile span-3">
        <h3>{{ t('pool.sum_largest') }}</h3>
        <div class="v" style="font-size:16px">
          {{ finiteN(asRecord(shownSummary).largest_single_file_gb) }} <span class="unit">GB</span>
        </div>
        <div class="sub">{{ t('pool.sum_largest_hint') }}</div>
      </div>
      <div class="tile span-3">
        <h3>{{ t('pool.sum_next_write') }}</h3>
        <div class="v mono" style="font-size:13px">{{ finiteText(shownTarget) }}</div>
        <div class="sub">{{ t('pool.sum_next_write_hint') }}</div>
      </div>
    </div>

    <h2 class="section-title">{{ t('pool.members_title') }}</h2>
    <div class="table-wrap" style="margin-bottom:12px">
      <table class="dense fit-m">
        <caption class="sr-only">{{ t('pool.members_caption') }}</caption>
        <thead>
          <tr>
            <th scope="col">{{ t('pool.th_mount') }}</th>
            <th class="col-hide-m" scope="col">{{ t('pool.th_disk') }}</th>
            <th class="col-hide-m" scope="col">{{ t('pool.th_fs') }}</th>
            <th class="col-hide-m" scope="col">{{ t('pool.th_total') }}</th>
            <th class="col-hide-m" scope="col">{{ t('pool.th_used') }}</th>
            <th class="col-hide-m" scope="col">{{ t('pool.th_avail') }}</th>
            <th scope="col">{{ t('pool.th_pct') }}</th>
            <th scope="col">{{ t('common.actions') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="m in asArray(selectedMembers)" :key="finiteText(asRecord(m).mount)">
            <td class="mono">
              <strong>{{ finiteText(asRecord(m).mount) }}</strong>
              <div class="show-m sub">{{ finiteText(asRecord(m).disk_id) }} · {{ finiteText(asRecord(m).filesystem) }}</div>
              <div class="show-m sub">{{ fmtGb(asRecord(m).used_gb) }} / {{ fmtGb(asRecord(m).avail_gb) }}</div>
            </td>
            <td class="mono col-hide-m">{{ finiteText(asRecord(m).disk_id) }}</td>
            <td class="mono col-hide-m">{{ finiteText(asRecord(m).filesystem) }}</td>
            <td class="col-hide-m">{{ fmtGb(asRecord(m).total_gb) }}</td>
            <td class="col-hide-m">{{ fmtGb(asRecord(m).used_gb) }}</td>
            <td class="col-hide-m">{{ fmtGb(asRecord(m).avail_gb) }}</td>
            <td style="min-width:100px">
              {{ withUnit(asRecord(m).pct, '%') }}
              <div class="pct-bar" :class="barClass(asRecord(m).pct)" style="margin-top:3px">
                <i :style="{ width: barPct(asRecord(m).pct) + '%' }"></i>
              </div>
            </td>
            <td class="ops">
              <button
                class="tiny"
                :disabled="busy"
                :aria-label="t('pool.remove_aria', { mount: finiteText(asRecord(m).mount) })"
                @click="removeMember(asRecord(m).mount)"
              >{{ t('pool.remove') }}</button>
            </td>
          </tr>
          <tr v-if="!asArray(selectedMembers).length && !loadError">
            <td colspan="8" class="empty-row">{{ t('pool.empty_members') }}</td>
          </tr>
        </tbody>
      </table>
    </div>
    <p class="note" style="margin:-6px 0 12px">{{ t('pool.remove_note') }}</p>

    <h2 class="section-title">{{ t('pool.candidates_title') }}</h2>
    <div class="table-wrap" style="margin-bottom:12px">
      <table class="dense fit-m">
        <caption class="sr-only">{{ t('pool.candidates_caption') }}</caption>
        <thead>
          <tr>
            <th scope="col">{{ t('pool.th_mount') }}</th>
            <th class="col-hide-m" scope="col">{{ t('pool.th_disk') }}</th>
            <th class="col-hide-m" scope="col">{{ t('pool.th_fs') }}</th>
            <th class="col-hide-m" scope="col">{{ t('pool.th_total') }}</th>
            <th scope="col">{{ t('pool.th_avail') }}</th>
            <th scope="col">{{ t('common.actions') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="c in asArray(availableCandidates)" :key="finiteText(asRecord(c).mount)">
            <td class="mono">
              <strong>{{ finiteText(asRecord(c).mount) }}</strong>
              <div class="show-m sub">{{ finiteText(asRecord(c).disk_id) }} · {{ finiteText(asRecord(c).filesystem) }}</div>
              <div class="show-m sub">{{ fmtGb(asRecord(c).total_gb) }}</div>
            </td>
            <td class="mono col-hide-m">{{ finiteText(asRecord(c).disk_id) }}</td>
            <td class="mono col-hide-m">{{ finiteText(asRecord(c).filesystem) }}</td>
            <td class="col-hide-m">{{ fmtGb(asRecord(c).total_gb) }}</td>
            <td>{{ fmtGb(asRecord(c).avail_gb) }}</td>
            <td class="ops">
              <button
                class="tiny primary"
                :disabled="busy"
                :aria-label="t('pool.add_aria', { mount: finiteText(asRecord(c).mount) })"
                @click="addMember(asRecord(c).mount)"
              >{{ t('pool.add') }}</button>
            </td>
          </tr>
          <!-- Two different truths share this row: with every eligible disk
               already selected, "no eligible disks" would wrongly claim the
               host lost its disks (the common.no_match split Brew/Tools pin). -->
          <tr v-if="!asArray(availableCandidates).length && !loadError">
            <td colspan="6" class="empty-row" role="status">
              {{ asArray(allCandidates).length ? t('pool.all_in_pool') : t('pool.empty_candidates') }}
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <h2 class="section-title">{{ t('pool.fault_title') }}</h2>
    <div class="tile" style="margin-bottom:10px;border-left:3px solid var(--ok)">
      <p class="note">{{ t('pool.fault_body') }}</p>
    </div>
    <div class="table-wrap" style="margin-bottom:12px">
      <table class="dense fit-m">
        <caption class="sr-only">{{ t('pool.fault_caption') }}</caption>
        <thead>
          <tr>
            <th scope="col">{{ t('pool.th_mount') }}</th>
            <th class="col-hide-m" scope="col">{{ t('pool.th_disk') }}</th>
            <th scope="col">{{ t('pool.th_at_risk') }}</th>
            <th scope="col">{{ t('pool.th_survives') }}</th>
            <th class="col-hide-m" scope="col">{{ t('pool.th_others') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="r in asArray(shownFaults)" :key="finiteText(asRecord(r).mount)">
            <td class="mono">
              <strong>{{ finiteText(asRecord(r).mount) }}</strong>
              <div class="show-m sub">{{ finiteText(asRecord(r).disk_id) }}</div>
            </td>
            <td class="mono col-hide-m">{{ finiteText(asRecord(r).disk_id) }}</td>
            <td style="color:var(--warn-text)">{{ fmtGb(asRecord(r).at_risk_gb) }}</td>
            <td style="color:var(--ok-text)">{{ fmtGb(asRecord(r).survives_gb) }}</td>
            <td class="col-hide-m">
              <span class="badge ok">{{ t('pool.others_unaffected') }}</span>
            </td>
          </tr>
          <tr v-if="!asArray(shownFaults).length && !loadError">
            <td colspan="5" class="empty-row">{{ t('pool.empty_faults') }}</td>
          </tr>
        </tbody>
      </table>
    </div>

    <h2 class="section-title">{{ t('pool.config_title') }}</h2>
    <div class="tile" style="margin-bottom:12px">
      <div class="field-grid">
        <label for="pool-name">{{ t('pool.name_label') }}</label>
        <input id="pool-name" v-model="poolName" type="text" maxlength="64" :placeholder="t('pool.name_ph')" />

        <label for="pool-policy">{{ t('pool.policy_label') }}</label>
        <select id="pool-policy" v-model="policy">
          <option v-for="p in asArray(policies)" :key="finiteText(p)" :value="finiteText(p)">{{ policyLabel(p) }}</option>
        </select>

        <label for="pool-minfree">{{ t('pool.min_free_label') }}</label>
        <input id="pool-minfree" v-model.number="minFreeGb" type="number" min="0" step="1" />
      </div>
      <p class="note" style="margin-top:8px">{{ t('pool.policy_hint') }}</p>
      <p class="note" style="margin-top:4px">{{ t('pool.min_free_hint') }}</p>
      <div class="btns" style="margin-top:12px">
        <button :disabled="busy || !selected.length" @click="doPreview">{{ t('pool.preview') }}</button>
        <button class="primary" :disabled="busy || !selected.length" @click="doSave">{{ t('pool.save') }}</button>
        <button class="danger" :disabled="busy || !view?.configured" @click="clearOpen = true">
          {{ t('pool.clear') }}
        </button>
      </div>
    </div>

    <pre
      v-if="lastMsg"
      style="margin:8px 0 12px;font-size:11px;white-space:pre-wrap;background:var(--bg);padding:8px;border-radius:4px;max-height:120px;overflow:auto"
      role="status"
      aria-live="polite"
    >{{ finiteText(lastMsg) }}</pre>
    </template>

    <!-- Clearing is metadata-only.  The wording has to make that unmistakable,
         because the button sits next to disk actions that really do erase. -->
    <div ref="clearPanel" v-if="clearOpen" class="modal-bg" @click.self="clearOpen = false" role="presentation">
      <div class="modal" style="max-width:460px" role="dialog" aria-modal="true" aria-labelledby="pool-clear-title">
        <div class="row" style="margin-bottom:10px">
          <span id="pool-clear-title" class="name">{{ t('pool.clear_title') }}</span>
          <button class="tiny" @click="clearOpen = false">{{ t('common.close') }}</button>
        </div>
        <p class="note" style="margin-bottom:8px">{{ t('pool.clear_body') }}</p>
        <p class="note" style="margin-bottom:12px;color:var(--ok-text)">{{ t('pool.clear_safe') }}</p>
        <div class="btns">
          <button class="danger" :disabled="busy" @click="doClear">{{ t('pool.clear_ok') }}</button>
          <button @click="clearOpen = false">{{ t('common.cancel') }}</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, inject, onMounted, onUnmounted, ref, watch } from 'vue'
import { clearStoragePool, getStoragePool, planStoragePool, saveStoragePool } from '../api/client'
import { injectI18n } from '../i18n'
import { asArray, asRecord, barPct, finiteN, finiteText, fmtGb, withUnit } from '../lib/finite'
import { useDismissable } from '../composables/useDismissable'
import SkeletonLoader from '../components/SkeletonLoader.vue'
import LoadFailure from '../components/LoadFailure.vue'

const toast = inject('toast')
const { t } = injectI18n()

const view = ref(null)
const preview = ref(null)
const loading = ref(false)
const loaded = ref(false)
const loadError = ref('')
const busy = ref(false)
const lastMsg = ref('')
const clearOpen = ref(false)
const clearPanel = ref(null)

const selected = ref([])
const poolName = ref('pool')
const policy = ref('most-free')
const minFreeGb = ref(0)

let pageAlive = true
let loadGeneration = 0

const policies = computed(() => {
  const list = asArray(asRecord(view.value).policies)
  return list.length ? list : ['most-free', 'least-used-pct', 'round-robin']
})

/** Every poolable volume the backend reported, members and unassigned alike. */
const allCandidates = computed(() => [
  ...asArray(view.value?.members).map((row) => asRecord(row)),
  ...asArray(view.value?.unassigned).map((row) => asRecord(row)),
])

const selectedMembers = computed(() => {
  const by = new Map(asArray(allCandidates.value).map((c) => [asRecord(c).mount, asRecord(c)]))
  return asArray(selected.value).map((m) => by.get(m)).filter(Boolean).map((row) => asRecord(row))
})

const availableCandidates = computed(() => {
  const chosen = new Set(asArray(selected.value))
  return asArray(allCandidates.value).map((c) => asRecord(c)).filter((c) => !chosen.has(c.mount))
})

/** Preview numbers when one is loaded, otherwise the saved pool's. */
const shownSummary = computed(() => asRecord(preview.value?.summary || view.value?.summary))
const shownTarget = computed(() => preview.value?.next_write_target ?? view.value?.next_write_target)
const shownFaults = computed(() => asArray(preview.value?.fault_model || view.value?.fault_model).map((row) => asRecord(row)))

function barClass(pct) {
  if (pct >= 90) return 'danger'
  if (pct >= 75) return 'warn'
  return ''
}

function policyLabel(p) {
  const keys = {
    'most-free': 'pool.policy_most_free',
    'least-used-pct': 'pool.policy_least_used',
    'round-robin': 'pool.policy_round_robin',
  }
  return keys[p] ? t(keys[p]) : p
}

function mapPool(raw) {
  const data = asRecord(raw)
  return {
    ...data,
    members: asArray(data.members).map((row) => asRecord(row)),
    unassigned: asArray(data.unassigned).map((row) => asRecord(row)),
    fault_model: asArray(data.fault_model).map((row) => asRecord(row)),
    summary: asRecord(data.summary),
  }
}

/** Adopt whatever the backend says is saved, discarding any local edits. */
function syncFromView(raw) {
  const data = mapPool(raw)
  view.value = data
  preview.value = null
  selected.value = asArray(data.members).map((m) => asRecord(m).mount)
  poolName.value = finiteText(data.name, '') || 'pool'
  minFreeGb.value = Number(finiteN(data.min_free_gb, 0)) || 0
  if (data.policy) policy.value = data.policy
}

async function refresh() {
  const generation = ++loadGeneration
  loading.value = true
  try {
    const data = mapPool(asRecord(await getStoragePool(true)))
    if (generation !== loadGeneration || !pageAlive) return
    syncFromView(data)
    loadError.value = ''
  } catch (e) {
    if (generation !== loadGeneration || !pageAlive) return
    loadError.value = finiteText(e.message || String(e), '')
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (generation === loadGeneration) {
      loading.value = false
      loaded.value = true
    }
  }
}

function addMember(mount) {
  if (!asArray(selected.value).includes(mount)) selected.value = [...asArray(selected.value), mount]
}

function removeMember(mount) {
  selected.value = asArray(selected.value).filter((m) => m !== mount)
}

// A stale preview describing a different member set is worse than none: the
// summary would contradict the table right above it.
watch(selected, () => {
  if (!pageAlive) return
  preview.value = null
})

async function doPreview() {
  const generation = loadGeneration
  busy.value = true
  try {
    const planned = mapPool(asRecord(await planStoragePool(selected.value, policy.value)))
    if (generation !== loadGeneration || !pageAlive) return
    preview.value = planned
    lastMsg.value = t('pool.msg_preview', { n: asArray(selected.value).length })
  } catch (e) {
    if (generation !== loadGeneration || !pageAlive) return
    toast('❌ ' + finiteText(e.message))
    lastMsg.value = finiteText(e.message, '')
  } finally {
    if (pageAlive) busy.value = false
  }
}

async function doSave() {
  const generation = loadGeneration
  busy.value = true
  try {
    const data = mapPool(asRecord(await saveStoragePool({
      mounts: selected.value,
      policy: policy.value,
      name: poolName.value.trim() || 'pool',
      min_free_gb: Number(minFreeGb.value) || 0,
    })))
    if (generation !== loadGeneration || !pageAlive) return
    syncFromView(data)
    lastMsg.value = t('pool.msg_saved')
    toast('✅ ' + t('pool.msg_saved'))
  } catch (e) {
    if (generation !== loadGeneration || !pageAlive) return
    toast('❌ ' + finiteText(e.message))
    lastMsg.value = finiteText(e.message, '')
  } finally {
    if (pageAlive) busy.value = false
  }
}

async function doClear() {
  const generation = loadGeneration
  busy.value = true
  try {
    const data = mapPool(asRecord(await clearStoragePool()))
    if (generation !== loadGeneration || !pageAlive) return
    syncFromView(data)
    clearOpen.value = false
    lastMsg.value = t('pool.msg_cleared')
    toast('✅ ' + t('pool.msg_cleared'))
  } catch (e) {
    if (generation !== loadGeneration || !pageAlive) return
    toast('❌ ' + finiteText(e.message))
    lastMsg.value = finiteText(e.message, '')
  } finally {
    if (pageAlive) busy.value = false
  }
}

onMounted(() => {
  pageAlive = true
  refresh()
})

onUnmounted(() => {
  pageAlive = false
  loadGeneration += 1
})

useDismissable(clearOpen, () => { clearOpen.value = false }, clearPanel)
</script>

<style scoped>
.note {
  font-size: 12px;
  color: var(--sub);
  line-height: 1.55;
  margin: 0;
}
.unit {
  font-size: 12px;
  font-weight: 500;
  color: var(--sub);
}
/* Layout comes from the global .field-grid. Two things stay local: the wider
   label column this page's longer labels need, and the field cap — a pool name
   or min-free number does not benefit from stretching across a wide screen. */
.field-grid { --field-label-w: 140px; }
.field-grid input,
.field-grid select { max-width: 320px; }
</style>
