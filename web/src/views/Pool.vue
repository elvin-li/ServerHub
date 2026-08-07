<template>
  <div>
    <div class="page-title">
      <h1>{{ t('pool.title') }}</h1>
      <span class="meta">{{ t('pool.meta') }}</span>
    </div>

    <div class="toolbar">
      <button class="primary" @click="refresh" :disabled="loading || busy">{{ t('common.refresh') }}</button>
      <span class="badge" :class="view?.configured ? 'ok' : ''">
        {{ view?.configured ? t('pool.state_configured', { n: (view?.members || []).length }) : t('pool.state_unconfigured') }}
      </span>
      <span class="badge accent">{{ t('pool.badge_no_raid') }}</span>
    </div>

    <!-- What this is, and what it deliberately is not. -->
    <div class="tile" style="margin-bottom:12px;border-left:3px solid var(--accent)">
      <h3 style="margin:0 0 6px">{{ t('pool.model_title') }}</h3>
      <p class="note">{{ t('pool.model_body') }}</p>
    </div>

    <!-- A single merged mount point needs a union filesystem that is not
         installed; say so rather than letting the page imply one path. -->
    <div
      v-if="view && !view.union?.single_mount_supported"
      class="tile"
      style="margin-bottom:12px;border-left:3px solid var(--warn)"
    >
      <h3 style="margin:0 0 6px">{{ t('pool.union_title') }}</h3>
      <p class="note">{{ t('pool.union_body') }}</p>
      <p class="note" style="margin-top:6px">{{ t('pool.union_available') }}</p>
    </div>

    <!-- Configured members that are not mounted right now. -->
    <div
      v-if="(view?.missing_members || []).length"
      class="tile"
      style="margin-bottom:12px;border-left:3px solid var(--warn)"
    >
      <h3 style="margin:0 0 6px">{{ t('pool.missing_title') }}</h3>
      <p class="note">{{ t('pool.missing_body') }}</p>
      <p class="mono" style="font-size:11px;margin:6px 0 0">
        <span v-for="m in view.missing_members" :key="m" style="margin-right:10px">{{ m }}</span>
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
          {{ shownSummary.total_gb ?? '—' }} <span class="unit">GB</span>
        </div>
        <div class="sub">{{ t('pool.sum_members', { n: shownSummary.member_count ?? 0 }) }}</div>
      </div>
      <div class="tile span-3">
        <h3>{{ t('pool.sum_used') }}</h3>
        <div class="v" style="font-size:16px">
          {{ shownSummary.used_gb ?? '—' }} <span class="unit">GB</span>
        </div>
        <div class="sub">{{ t('common.free') }} {{ shownSummary.avail_gb ?? '—' }} GB</div>
        <div class="pct-bar" :class="barClass(shownSummary.pct)" style="margin-top:6px">
          <i :style="{ width: (shownSummary.pct || 0) + '%' }"></i>
        </div>
      </div>
      <div class="tile span-3">
        <h3>{{ t('pool.sum_largest') }}</h3>
        <div class="v" style="font-size:16px">
          {{ shownSummary.largest_single_file_gb ?? '—' }} <span class="unit">GB</span>
        </div>
        <div class="sub">{{ t('pool.sum_largest_hint') }}</div>
      </div>
      <div class="tile span-3">
        <h3>{{ t('pool.sum_next_write') }}</h3>
        <div class="v mono" style="font-size:13px">{{ shownTarget || '—' }}</div>
        <div class="sub">{{ t('pool.sum_next_write_hint') }}</div>
      </div>
    </div>

    <h2 class="section-title">{{ t('pool.members_title') }}</h2>
    <div class="table-wrap" style="margin-bottom:12px">
      <table class="dense">
        <caption class="sr-only">{{ t('pool.members_caption') }}</caption>
        <thead>
          <tr>
            <th scope="col">{{ t('pool.th_mount') }}</th>
            <th scope="col">{{ t('pool.th_disk') }}</th>
            <th scope="col">{{ t('pool.th_fs') }}</th>
            <th scope="col">{{ t('pool.th_total') }}</th>
            <th scope="col">{{ t('pool.th_used') }}</th>
            <th scope="col">{{ t('pool.th_avail') }}</th>
            <th scope="col">{{ t('pool.th_pct') }}</th>
            <th scope="col">{{ t('common.actions') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="m in selectedMembers" :key="m.mount">
            <td class="mono"><strong>{{ m.mount }}</strong></td>
            <td class="mono">{{ m.disk_id || '—' }}</td>
            <td class="mono">{{ m.filesystem || '—' }}</td>
            <td>{{ m.total_gb }} GB</td>
            <td>{{ m.used_gb }} GB</td>
            <td>{{ m.avail_gb }} GB</td>
            <td style="min-width:100px">
              {{ m.pct }}%
              <div class="pct-bar" :class="barClass(m.pct)" style="margin-top:3px">
                <i :style="{ width: m.pct + '%' }"></i>
              </div>
            </td>
            <td class="ops">
              <button
                class="tiny"
                :disabled="busy"
                :aria-label="t('pool.remove_aria', { mount: m.mount })"
                @click="removeMember(m.mount)"
              >{{ t('pool.remove') }}</button>
            </td>
          </tr>
          <tr v-if="!selectedMembers.length">
            <td colspan="8" style="color:var(--sub)">{{ t('pool.empty_members') }}</td>
          </tr>
        </tbody>
      </table>
    </div>
    <p class="note" style="margin:-6px 0 12px">{{ t('pool.remove_note') }}</p>

    <h2 class="section-title">{{ t('pool.candidates_title') }}</h2>
    <div class="table-wrap" style="margin-bottom:12px">
      <table class="dense">
        <caption class="sr-only">{{ t('pool.candidates_caption') }}</caption>
        <thead>
          <tr>
            <th scope="col">{{ t('pool.th_mount') }}</th>
            <th scope="col">{{ t('pool.th_disk') }}</th>
            <th scope="col">{{ t('pool.th_fs') }}</th>
            <th scope="col">{{ t('pool.th_total') }}</th>
            <th scope="col">{{ t('pool.th_avail') }}</th>
            <th scope="col">{{ t('common.actions') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="c in availableCandidates" :key="c.mount">
            <td class="mono"><strong>{{ c.mount }}</strong></td>
            <td class="mono">{{ c.disk_id || '—' }}</td>
            <td class="mono">{{ c.filesystem || '—' }}</td>
            <td>{{ c.total_gb }} GB</td>
            <td>{{ c.avail_gb }} GB</td>
            <td class="ops">
              <button
                class="tiny primary"
                :disabled="busy"
                :aria-label="t('pool.add_aria', { mount: c.mount })"
                @click="addMember(c.mount)"
              >{{ t('pool.add') }}</button>
            </td>
          </tr>
          <tr v-if="!availableCandidates.length">
            <td colspan="6" style="color:var(--sub)">{{ t('pool.empty_candidates') }}</td>
          </tr>
        </tbody>
      </table>
    </div>

    <h2 class="section-title">{{ t('pool.fault_title') }}</h2>
    <div class="tile" style="margin-bottom:10px;border-left:3px solid var(--ok)">
      <p class="note">{{ t('pool.fault_body') }}</p>
    </div>
    <div class="table-wrap" style="margin-bottom:12px">
      <table class="dense">
        <caption class="sr-only">{{ t('pool.fault_caption') }}</caption>
        <thead>
          <tr>
            <th scope="col">{{ t('pool.th_mount') }}</th>
            <th scope="col">{{ t('pool.th_disk') }}</th>
            <th scope="col">{{ t('pool.th_at_risk') }}</th>
            <th scope="col">{{ t('pool.th_survives') }}</th>
            <th scope="col">{{ t('pool.th_others') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="r in shownFaults" :key="r.mount">
            <td class="mono"><strong>{{ r.mount }}</strong></td>
            <td class="mono">{{ r.disk_id || '—' }}</td>
            <td style="color:var(--warn)">{{ r.at_risk_gb }} GB</td>
            <td style="color:var(--ok)">{{ r.survives_gb }} GB</td>
            <td>
              <span class="badge ok">{{ t('pool.others_unaffected') }}</span>
            </td>
          </tr>
          <tr v-if="!shownFaults.length">
            <td colspan="5" style="color:var(--sub)">{{ t('pool.empty_faults') }}</td>
          </tr>
        </tbody>
      </table>
    </div>

    <h2 class="section-title">{{ t('pool.config_title') }}</h2>
    <div class="tile" style="margin-bottom:12px">
      <div class="field-grid">
        <label for="pool-name">{{ t('pool.name_label') }}</label>
        <input id="pool-name" v-model="poolName" type="text" :placeholder="t('pool.name_ph')" />

        <label for="pool-policy">{{ t('pool.policy_label') }}</label>
        <select id="pool-policy" v-model="policy">
          <option v-for="p in policies" :key="p" :value="p">{{ policyLabel(p) }}</option>
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
    >{{ lastMsg }}</pre>
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
        <p class="note" style="margin-bottom:12px;color:var(--ok)">{{ t('pool.clear_safe') }}</p>
        <div class="btns">
          <button class="danger" :disabled="busy" @click="doClear">{{ t('pool.clear_ok') }}</button>
          <button @click="clearOpen = false">{{ t('common.cancel') }}</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, inject, onMounted, ref, watch } from 'vue'
import { clearStoragePool, getStoragePool, planStoragePool, saveStoragePool } from '../api/client'
import { injectI18n } from '../i18n'
import { useDismissable } from '../composables/useDismissable'
import SkeletonLoader from '../components/SkeletonLoader.vue'

const toast = inject('toast')
const { t } = injectI18n()

const view = ref(null)
const preview = ref(null)
const loading = ref(false)
const loaded = ref(false)
const busy = ref(false)
const lastMsg = ref('')
const clearOpen = ref(false)
const clearPanel = ref(null)

const selected = ref([])
const poolName = ref('pool')
const policy = ref('most-free')
const minFreeGb = ref(0)

const policies = computed(() => view.value?.policies || ['most-free', 'least-used-pct', 'round-robin'])

/** Every poolable volume the backend reported, members and unassigned alike. */
const allCandidates = computed(() => [
  ...(view.value?.members || []),
  ...(view.value?.unassigned || []),
])

const selectedMembers = computed(() => {
  const by = new Map(allCandidates.value.map((c) => [c.mount, c]))
  return selected.value.map((m) => by.get(m)).filter(Boolean)
})

const availableCandidates = computed(() => {
  const chosen = new Set(selected.value)
  return allCandidates.value.filter((c) => !chosen.has(c.mount))
})

/** Preview numbers when one is loaded, otherwise the saved pool's. */
const shownSummary = computed(() => preview.value?.summary || view.value?.summary || {})
const shownTarget = computed(() => preview.value?.next_write_target ?? view.value?.next_write_target)
const shownFaults = computed(() => preview.value?.fault_model || view.value?.fault_model || [])

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

/** Adopt whatever the backend says is saved, discarding any local edits. */
function syncFromView(data) {
  view.value = data
  preview.value = null
  selected.value = (data.members || []).map((m) => m.mount)
  poolName.value = data.name || 'pool'
  minFreeGb.value = Number(data.min_free_gb) || 0
  if (data.policy) policy.value = data.policy
}

async function refresh() {
  loading.value = true
  try {
    syncFromView(await getStoragePool(true))
  } catch (e) {
    toast('❌ ' + e.message)
  } finally {
    loading.value = false
    loaded.value = true
  }
}

function addMember(mount) {
  if (!selected.value.includes(mount)) selected.value = [...selected.value, mount]
}

function removeMember(mount) {
  selected.value = selected.value.filter((m) => m !== mount)
}

// A stale preview describing a different member set is worse than none: the
// summary would contradict the table right above it.
watch(selected, () => { preview.value = null })

async function doPreview() {
  busy.value = true
  try {
    preview.value = await planStoragePool(selected.value, policy.value)
    lastMsg.value = t('pool.msg_preview', { n: selected.value.length })
  } catch (e) {
    toast('❌ ' + e.message)
    lastMsg.value = e.message
  } finally {
    busy.value = false
  }
}

async function doSave() {
  busy.value = true
  try {
    syncFromView(await saveStoragePool({
      mounts: selected.value,
      policy: policy.value,
      name: poolName.value.trim() || 'pool',
      min_free_gb: Number(minFreeGb.value) || 0,
    }))
    lastMsg.value = t('pool.msg_saved')
    toast('✅ ' + t('pool.msg_saved'))
  } catch (e) {
    toast('❌ ' + e.message)
    lastMsg.value = e.message
  } finally {
    busy.value = false
  }
}

async function doClear() {
  busy.value = true
  try {
    syncFromView(await clearStoragePool())
    clearOpen.value = false
    lastMsg.value = t('pool.msg_cleared')
    toast('✅ ' + t('pool.msg_cleared'))
  } catch (e) {
    toast('❌ ' + e.message)
    lastMsg.value = e.message
  } finally {
    busy.value = false
  }
}

// Action-driven page: no polling, so there is no interval to leak on unmount.
onMounted(refresh)

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
