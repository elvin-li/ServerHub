<!--
  Operator recognition rules from services.yaml service_signatures.

  Built-in signatures stay in code; this card only lists rules the operator
  added (Adopt → Remember, or by hand). Mutations emit through the API so
  the parent Settings page does not own another form model.
-->
<template>
  <div class="card svcsig">
    <h2 class="section-title" style="margin-top:0">{{ t('svcsig.title') }}</h2>
    <p class="hint" style="margin-top:0">{{ t('svcsig.hint') }}</p>
    <p class="hint" v-if="builtinCount">{{ t('svcsig.builtin', { n: builtinCount }) }}</p>

    <div class="table-wrap" v-if="asArray(rows).length">
      <table class="dense fit-m">
        <thead>
          <tr>
            <th>{{ t('common.name') }}</th>
            <th class="col-hide-m">{{ t('svcsig.category') }}</th>
            <th class="col-hide-m">{{ t('svcsig.ports') }}</th>
            <th><span class="sr-only">{{ t('common.actions') }}</span></th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="row in asArray(rows)" :key="finiteText(asRecord(row).slug)">
            <td>
              <strong>{{ finiteText(asRecord(row).name) }}</strong>
              <div class="mono sub-line">{{ finiteText(asRecord(row).slug) }}</div>
              <div class="show-m sub">{{ finiteText(asRecord(row).category) }} · {{ fmtPorts(asRecord(row).ports) }}</div>
            </td>
            <td class="col-hide-m">{{ finiteText(asRecord(row).category) }}</td>
            <td class="col-hide-m mono">{{ fmtPorts(asRecord(row).ports) }}</td>
            <td class="row-btns">
              <button type="button" class="tiny" :disabled="busy" @click="startEdit(row)">{{ t('common.edit') }}</button>
              <button type="button" class="tiny danger" :disabled="busy" @click="removeRow(row)">{{ t('common.delete') }}</button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <LoadFailure v-else-if="loadError" :detail="loadError" :retry="load" :busy="busy" />
    <div v-else-if="loaded" class="sub">{{ t('svcsig.empty') }}</div>
    <div v-else class="sub">{{ t('common.loading') }}</div>

    <div class="btns" style="margin-top:10px" v-if="!editing">
      <button type="button" class="primary" :disabled="!loaded" @click="startAdd">{{ t('svcsig.add') }}</button>
      <button type="button" :disabled="busy" @click="load">{{ t('common.refresh') }}</button>
    </div>

    <div v-if="editing" class="editor">
      <div class="form-grid">
        <label>{{ t('svcsig.slug') }}
          <input v-model="editing.slug" type="text" class="mono" :disabled="editing.existing" :aria-label="t('svcsig.slug')" />
        </label>
        <label>{{ t('common.name') }}
          <input v-model="editing.name" type="text" :aria-label="t('common.name')" />
        </label>
        <label>{{ t('svcsig.category') }}
          <input v-model="editing.category" type="text" :aria-label="t('svcsig.category')" />
        </label>
        <label>{{ t('svcsig.procs') }}
          <input v-model="editing.procs" type="text" class="mono" placeholder="redis-server, redis-ser" :aria-label="t('svcsig.procs')" />
        </label>
        <label>{{ t('svcsig.ports') }}
          <input v-model="editing.ports" type="text" class="mono" placeholder="6379, 6380" :aria-label="t('svcsig.ports')" />
        </label>
        <label>{{ t('svcsig.http') }}
          <select v-model="editing.http" :aria-label="t('svcsig.http')">
            <option value="">{{ t('svcsig.http_auto') }}</option>
            <option value="true">{{ t('svcsig.http_yes') }}</option>
            <option value="false">{{ t('svcsig.http_no') }}</option>
          </select>
        </label>
        <label>{{ t('svcsig.brew') }}
          <input v-model="editing.brew" type="text" class="mono" :aria-label="t('svcsig.brew')" />
        </label>
      </div>
      <div class="btns" style="margin-top:10px">
        <button type="button" class="primary" :disabled="busy" @click="save">{{ t('common.save') }}</button>
        <button type="button" :disabled="busy" @click="editing = null">{{ t('common.cancel') }}</button>
      </div>
    </div>
  </div>
</template>

<script setup>
import { inject, onMounted, onUnmounted, ref } from 'vue'
import { forgetServiceSignature, getServiceSignatures, upsertServiceSignature } from '../api/client'
import { injectI18n } from '../i18n'
import { asArray, asRecord, finiteN, finiteText } from '../lib/finite'
import LoadFailure from './LoadFailure.vue'

const toast = inject('toast')
const { t } = injectI18n()

const rows = ref([])
const builtinCount = ref(0)
const loaded = ref(false)
const loadError = ref('')
const busy = ref(false)
const editing = ref(null)
let pageAlive = true
let loadGeneration = 0

function httpValue(http) {
  if (http === true) return 'true'
  if (http === false) return 'false'
  return ''
}

function fmtPorts(ports) {
  const parts = asArray(ports).map((p) => finiteText(p, '')).filter(Boolean)
  return parts.length ? parts.join(', ') : '—'
}

function parseList(raw) {
  return String(raw || '')
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean)
}

async function load() {
  const generation = ++loadGeneration
  try {
    const data = await getServiceSignatures()
    if (generation !== loadGeneration || !pageAlive) return
    rows.value = asArray(data?.signatures).map((r) => asRecord(r))
    builtinCount.value = finiteN(asRecord(data).builtin_count, 0)
    loadError.value = ''
  } catch (e) {
    if (generation !== loadGeneration || !pageAlive) return
    loadError.value = finiteText(e.message || String(e), '')
    toast('❌ ' + finiteText(e.message || e))
  } finally {
    if (generation === loadGeneration) loaded.value = true
  }
}

function startAdd() {
  editing.value = {
    existing: false, slug: '', name: '', category: '',
    procs: '', ports: '', http: '', brew: '',
  }
}

function startEdit(row) {
  const rec = asRecord(row)
  editing.value = {
    existing: true,
    slug: rec.slug,
    name: rec.name || '',
    category: rec.category || '',
    procs: asArray(rec.procs).map((n) => finiteText(n, '')).filter(Boolean).join(', '),
    ports: asArray(rec.ports).map((n) => finiteText(n, '')).filter(Boolean).join(', '),
    http: httpValue(rec.http),
    brew: rec.brew || '',
  }
}

async function save() {
  const e = editing.value
  if (!e) return
  const generation = loadGeneration
  busy.value = true
  try {
    const ports = parseList(e.ports)
      .map((p) => parseInt(p, 10))
      .filter((p) => Number.isInteger(p) && p >= 1 && p <= 65535)
    const body = {
      slug: e.slug,
      name: e.name || undefined,
      category: e.category || undefined,
      procs: parseList(e.procs),
      ports,
      brew: e.brew || undefined,
    }
    if (e.http === 'true') body.http = true
    else if (e.http === 'false') body.http = false
    else body.http = null
    await upsertServiceSignature(body)
    if (generation !== loadGeneration || !pageAlive) return
    toast(`✅ ${t('svcsig.saved')}`)
    editing.value = null
    await load()
  } catch (err) {
    if (generation !== loadGeneration || !pageAlive) return
    toast('❌ ' + finiteText(err.message || err))
  } finally {
    if (pageAlive) busy.value = false
  }
}

async function removeRow(row) {
  if (!confirm(t('svcsig.confirm_delete', { slug: finiteText(asRecord(row).slug) }))) return
  const generation = loadGeneration
  busy.value = true
  try {
    await forgetServiceSignature(asRecord(row).slug)
    if (generation !== loadGeneration || !pageAlive) return
    toast(`✅ ${t('svcsig.removed')}`)
    if (asRecord(editing.value).slug === asRecord(row).slug) editing.value = null
    await load()
  } catch (e) {
    if (generation !== loadGeneration || !pageAlive) return
    toast('❌ ' + finiteText(e.message || e))
  } finally {
    if (pageAlive) busy.value = false
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
.svcsig { margin-top: 16px; }
.sub-line { font-size: 10px; color: var(--sub); margin-top: 2px; }
.row-btns { display: flex; flex-wrap: wrap; gap: 4px; justify-content: flex-end; }
.editor { margin-top: 12px; padding-top: 10px; border-top: 1px solid var(--line); }
.form-grid {
  display: grid; grid-template-columns: 1fr 1fr; gap: 8px;
}
.form-grid label {
  display: flex; flex-direction: column; gap: 4px; font-size: 12px; color: var(--sub);
}
.form-grid input, .form-grid select { width: 100%; }
@media (max-width: 640px) {
  .form-grid { grid-template-columns: 1fr; }
}
</style>
