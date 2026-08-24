<!--
  Services-page grouping rules from services.yaml group_rules.

  Built-in seeds apply while the yaml key is absent. Saving (add/delete)
  writes the list through the API so this card does not own the yaml file.
-->
<template>
  <div class="card grules">
    <h2 class="section-title" style="margin-top:0">{{ t('grules.title') }}</h2>
    <p class="hint" style="margin-top:0">{{ t('grules.hint') }}</p>
    <p class="hint" v-if="loaded && source === 'yaml'">{{ t('grules.source_yaml') }}</p>
    <p class="hint" v-else-if="loaded">{{ t('grules.source_seed') }}</p>

    <div class="table-wrap" v-if="rows.length">
      <table class="dense fit-m">
        <thead>
          <tr>
            <th>{{ t('grules.group') }}</th>
            <th class="col-hide-m">{{ t('grules.match') }}</th>
            <th><span class="sr-only">{{ t('common.actions') }}</span></th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="row in rows" :key="finiteText(row.id)">
            <td>
              <strong>{{ finiteText(row.group) }}</strong>
              <div class="mono sub-line">{{ finiteText(row.id) }}</div>
              <div class="show-m sub">{{ matchSummary(row) }}</div>
            </td>
            <td class="col-hide-m mono">{{ matchSummary(row) }}</td>
            <td class="row-btns">
              <button type="button" class="tiny danger" :disabled="busy" @click="removeRow(row)">{{ t('common.delete') }}</button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <LoadFailure v-else-if="loadError" :detail="loadError" :retry="load" :busy="busy" />
    <div v-else-if="loaded" class="sub">{{ t('grules.empty') }}</div>
    <div v-else class="sub">{{ t('common.loading') }}</div>

    <div class="btns" style="margin-top:10px" v-if="!editing">
      <button type="button" class="primary" :disabled="!loaded" @click="startAdd">{{ t('grules.add') }}</button>
      <button type="button" :disabled="busy" @click="load">{{ t('common.refresh') }}</button>
    </div>

    <div v-if="editing" class="editor">
      <div class="form-grid">
        <label>{{ t('grules.group') }}
          <input v-model="editing.group" type="text" :aria-label="t('grules.group')" />
        </label>
        <label>{{ t('grules.compose_project') }}
          <input v-model="editing.compose_project" type="text" class="mono" placeholder="xiaomihub, music-assistant" :aria-label="t('grules.compose_project')" />
        </label>
        <label>{{ t('grules.image') }}
          <input v-model="editing.image" type="text" class="mono" placeholder="miot, esphome" :aria-label="t('grules.image')" />
        </label>
        <label>{{ t('grules.launchd_prefix') }}
          <input v-model="editing.launchd_prefix" type="text" class="mono" placeholder="com.homeassistant, local.esphome" :aria-label="t('grules.launchd_prefix')" />
        </label>
        <label>{{ t('grules.ports') }}
          <input v-model="editing.ports" type="text" class="mono" placeholder="8123, 6052" :aria-label="t('grules.ports')" />
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
import { deleteGroupRule, getGroupRules, saveGroupRules } from '../api/client'
import { injectI18n } from '../i18n'
import { finiteText } from '../lib/finite'
import LoadFailure from './LoadFailure.vue'

const toast = inject('toast')
const { t } = injectI18n()

const rows = ref([])
const source = ref('seed')
const loaded = ref(false)
const loadError = ref('')
const busy = ref(false)
const editing = ref(null)
let pageAlive = true
let loadGeneration = 0

function fmtList(value) {
  const arr = Array.isArray(value) ? value : (value ? [value] : [])
  return arr.map((item) => finiteText(item, '')).filter(Boolean).join(', ')
}

function matchSummary(row) {
  if (!row || typeof row !== 'object') return '—'
  const parts = []
  const compose = fmtList(row.compose_project)
  const image = fmtList(row.image)
  const prefix = fmtList(row.launchd_prefix)
  const ports = fmtList(row.ports)
  if (compose) parts.push(compose)
  if (image) parts.push(image)
  if (prefix) parts.push(prefix)
  if (row.launchd_interval === true) parts.push('interval')
  if (ports) parts.push(ports)
  const owner = fmtList(row.auto_port_owner)
  if (owner) parts.push(owner)
  return parts.length ? parts.join(' · ') : '—'
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
    const data = await getGroupRules()
    if (generation !== loadGeneration || !pageAlive) return
    rows.value = Array.isArray(data?.rules) ? data.rules : []
    source.value = data?.source === 'yaml' ? 'yaml' : 'seed'
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
    group: '',
    compose_project: '',
    image: '',
    launchd_prefix: '',
    ports: '',
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
    const body = { group: e.group }
    const compose = parseList(e.compose_project)
    const image = parseList(e.image)
    const prefix = parseList(e.launchd_prefix)
    if (compose.length) body.compose_project = compose
    if (image.length) body.image = image
    if (prefix.length) body.launchd_prefix = prefix
    if (ports.length) body.ports = ports
    await saveGroupRules(body)
    if (generation !== loadGeneration || !pageAlive) return
    toast(`✅ ${t('grules.saved')}`)
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
  if (!confirm(t('grules.confirm_delete', { id: finiteText(row.id) }))) return
  const generation = loadGeneration
  busy.value = true
  try {
    await deleteGroupRule(row.id)
    if (generation !== loadGeneration || !pageAlive) return
    toast(`✅ ${t('grules.removed')}`)
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
.grules { margin-top: 16px; }
.sub-line { font-size: 10px; color: var(--sub); margin-top: 2px; }
.row-btns { display: flex; flex-wrap: wrap; gap: 4px; justify-content: flex-end; }
.editor { margin-top: 12px; padding-top: 10px; border-top: 1px solid var(--line); }
.form-grid {
  display: grid; grid-template-columns: 1fr 1fr; gap: 8px;
}
.form-grid label {
  display: flex; flex-direction: column; gap: 4px; font-size: 12px; color: var(--sub);
}
.form-grid input { width: 100%; }
@media (max-width: 640px) {
  .form-grid { grid-template-columns: 1fr; }
}
</style>
