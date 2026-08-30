<template>
  <div class="card notify-channels">
    <h2 class="section-title" style="margin-top:0">{{ t('notifych.title') }}</h2>
    <p class="hint" style="margin-top:0">{{ t('notifych.hint') }}</p>

    <!-- The error banner sits *above* the last known rows instead of
         replacing them: a failed refresh must not blank a list the operator
         was just reading (same rule as the bookmarks card). -->
    <div v-if="loadError" class="sub" style="color:var(--down-text)" role="alert">{{ finiteText(loadError) }}</div>
    <div class="table-wrap" v-if="asArray(channels).length">
    <table class="dense fit-m">
      <thead>
        <tr>
          <th>{{ t('common.name') }}</th>
          <th class="col-hide-m">{{ t('common.type') }}</th>
          <th class="col-hide-m">{{ t('notifych.min_level') }}</th>
          <th>{{ t('common.status') }}</th>
          <th><span class="sr-only">{{ t('common.actions') }}</span></th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="c in asArray(channels)" :key="finiteText(asRecord(c).id)">
          <td>
            <strong>{{ finiteText(asRecord(c).name) }}</strong>
            <div class="mono sub-line">{{ finiteText(asRecord(c).id) }}</div>
            <div class="show-m sub">{{ typeLabel(asRecord(c).type) }} · {{ t(`notifych.level_${asRecord(c).min_level}`) }}</div>
          </td>
          <td class="col-hide-m">{{ typeLabel(asRecord(c).type) }}</td>
          <td class="col-hide-m">
            <span class="badge" :class="levelBadge(asRecord(c).min_level)">{{ t(`notifych.level_${asRecord(c).min_level}`) }}</span>
            <span v-if="asRecord(c).notify_resolve" class="badge" style="margin-left:4px">{{ t('notifych.resolve_short') }}</span>
          </td>
          <td>
            <span class="badge" :class="asRecord(c).enabled ? 'ok' : 'warn'">
              {{ asRecord(c).enabled ? t('common.enabled') : t('common.disabled') }}
            </span>
          </td>
          <td class="row-btns">
            <button class="tiny" :disabled="busy" @click="startEdit(c)">{{ t('common.edit') }}</button>
            <button class="tiny hide-m" :disabled="busy" @click="testChannel(c)">{{ t('common.test') }}</button>
            <button class="tiny danger" :disabled="busy" @click="removeChannel(c)">{{ t('common.delete') }}</button>
          </td>
        </tr>
      </tbody>
    </table>
    </div>
    <!-- Empty only when a load actually succeeded: an error with no rows is
         the error state, not "no channels configured". -->
    <div v-else-if="loaded && !loadError" class="sub">{{ t('notifych.empty') }}</div>
    <div v-else-if="!loaded" class="sub" aria-live="polite">{{ t('common.loading') }}</div>

    <div class="btns" style="margin-top:10px" v-if="!editing">
      <button class="primary" :disabled="!loaded" @click="startAdd">{{ t('notifych.add') }}</button>
      <button :disabled="busy" @click="load">{{ t('common.refresh') }}</button>
    </div>

    <div v-if="editing" class="editor">
      <h2 class="section-title">{{ asRecord(editing).existing ? t('notifych.edit_title', { name: finiteText(asRecord(editing).name, '') || finiteText(asRecord(editing).id) }) : t('notifych.add') }}</h2>
      <div class="form-grid">
        <label>{{ t('common.type') }}</label>
        <select v-model="editing.type" :disabled="editing.existing" :aria-label="t('common.type')">
          <option v-for="ty in asArray(typeIds)" :key="ty" :value="ty">{{ typeLabel(ty) }}</option>
        </select>
        <label>{{ t('common.name') }}</label>
        <input v-model="editing.name" type="text" maxlength="80" :aria-label="t('common.name')" />
        <label>{{ t('notifych.enabled') }}</label>
        <input type="checkbox" v-model="editing.enabled" :aria-label="t('notifych.enabled')" />
        <label>{{ t('notifych.min_level') }}</label>
        <select v-model="editing.min_level" :aria-label="t('notifych.min_level')">
          <option value="info">{{ t('notifych.level_info') }}</option>
          <option value="warn">{{ t('notifych.level_warn') }}</option>
          <option value="down">{{ t('notifych.level_down') }}</option>
        </select>
        <label>{{ t('notifych.notify_resolve') }}</label>
        <input type="checkbox" v-model="editing.notify_resolve" :aria-label="t('notifych.notify_resolve')" />

        <template v-for="f in fieldsFor(editing.type)" :key="'f-' + f">
          <label>{{ fieldLabel(f) }}</label>
          <select v-if="f === 'tls'" v-model="editing.config.tls" :aria-label="fieldLabel(f)">
            <option value="starttls">STARTTLS</option>
            <option value="ssl">SSL/TLS</option>
            <option value="none">{{ t('notifych.tls_none') }}</option>
          </select>
          <input
            v-else
            v-model="editing.config[f]"
            type="text"
            :placeholder="fieldPlaceholder(f)"
            :aria-label="fieldLabel(f)"
          />
        </template>

        <template v-for="s in secretsFor(editing.type)" :key="'s-' + s">
          <label>{{ fieldLabel(s) }}</label>
          <input
            v-model="editing.secrets[s]"
            type="password"
            autocomplete="new-password"
            :placeholder="editing.has && editing.has[s] ? t('notifych.secret_keep') : fieldPlaceholder(s)"
            :aria-label="fieldLabel(s)"
          />
        </template>
      </div>
      <p class="hint">{{ t('notifych.level_hint') }}</p>
      <div class="btns" style="margin-top:8px">
        <button class="primary" :disabled="busy" @click="save">{{ t('common.save') }}</button>
        <button :disabled="busy" @click="editing = null">{{ t('common.cancel') }}</button>
      </div>
    </div>
  </div>
</template>

<script setup>
import { inject, onMounted, onUnmounted, ref } from 'vue'
import {
  createNotifyChannel, deleteNotifyChannel, getNotifyChannels,
  testNotifyChannel, updateNotifyChannel,
} from '../api/client'
import { injectI18n } from '../i18n'
import { asArray, asRecord, finiteText } from '../lib/finite'

const toast = inject('toast')
const { t } = injectI18n()

const channels = ref([])
// Field/secret lists per type, served by the backend so the form can never
// drift from what the API actually validates.
const types = ref({})
const typeIds = ref([])
const loaded = ref(false)
const loadError = ref('')
const busy = ref(false)
const editing = ref(null)
let pageAlive = true
let loadGeneration = 0

function typeLabel(ty) {
  const key = `notifych.type_${ty}`
  const label = t(key)
  return label === key ? ty : label
}

function fieldLabel(f) {
  const key = `notifych.f_${f}`
  const label = t(key)
  return label === key ? f : label
}

// Placeholders are format examples (URLs, ports, addresses), deliberately the
// same across locales, so they live here rather than in the dictionaries.
const PLACEHOLDERS = {
  host: 'smtp.example.com',
  port: '587',
  username: 'user@example.com',
  from_addr: 'serverhub@example.com',
  to: 'you@example.com, family@example.com',
  server: 'https://ntfy.sh',
  topic: 'serverhub-alerts',
  chat_id: '-1001234567890',
  webhook_url: 'https://…/webhooks/…',
  url: 'https://example.com/hook',
  ha_url: 'http://homeassistant.local:8123',
  ha_service: 'notify.notify',
}

function fieldPlaceholder(f) {
  return PLACEHOLDERS[f] || ''
}

function levelBadge(level) {
  if (level === 'down') return 'down'
  if (level === 'warn') return 'warn'
  return 'ok'
}

function softText(j, fallbackKey = 'common.fail') {
  if (j?.code) {
    const key = `err.${j.code}`
    const translated = t(key, j.params || {})
    if (translated !== key) return translated
  }
  return j?.message || t(fallbackKey)
}

function fieldsFor(ty) {
  return asArray(types.value[ty]?.fields)
}

function secretsFor(ty) {
  return asArray(types.value[ty]?.secrets)
}

async function load() {
  const generation = ++loadGeneration
  try {
    const r = asRecord(await getNotifyChannels())
    if (generation !== loadGeneration || !pageAlive) return
    channels.value = asArray(r.channels).map((c) => asRecord(c))
    types.value = asRecord(r.types)
    typeIds.value = Object.keys(types.value)
    loadError.value = ''
  } catch (e) {
    if (generation !== loadGeneration || !pageAlive) return
    loadError.value = e.message || String(e)
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (generation === loadGeneration) loaded.value = true
  }
}

function startAdd() {
  editing.value = {
    existing: false,
    id: null,
    type: 'email',
    name: '',
    enabled: true,
    min_level: 'warn',
    notify_resolve: true,
    config: {},
    secrets: {},
    has: {},
  }
}

function startEdit(c) {
  const row = asRecord(c)
  editing.value = {
    existing: true,
    id: row.id,
    type: row.type,
    name: row.name,
    enabled: row.enabled,
    min_level: row.min_level,
    notify_resolve: row.notify_resolve,
    config: { ...asRecord(row.config) },
    secrets: {},
    has: { ...asRecord(row.has) },
  }
}

async function save() {
  const e = editing.value
  if (!e) return
  const generation = loadGeneration
  busy.value = true
  try {
    // An untouched (empty) secret input means "keep the stored value"; the
    // API treats an empty string as "clear", so those are dropped here.
    const secrets = {}
    for (const [k, v] of Object.entries(asRecord(e.secrets))) {
      if (v) secrets[k] = v
    }
    const body = {
      type: e.type,
      name: e.name || undefined,
      enabled: e.enabled,
      min_level: e.min_level,
      notify_resolve: e.notify_resolve,
      config: e.config,
      secrets,
    }
    if (e.existing) {
      const r = asRecord(await updateNotifyChannel(e.id, body))
    } else {
      const r = asRecord(await createNotifyChannel(body))
    }
    if (generation !== loadGeneration || !pageAlive) return
    toast('✅ ' + t('common.save'))
    editing.value = null
    await load()
  } catch (err) {
    if (generation !== loadGeneration || !pageAlive) return
    toast('❌ ' + finiteText(err.message))
  } finally {
    if (pageAlive) busy.value = false
  }
}

async function testChannel(c) {
  const row = asRecord(c)
  const generation = loadGeneration
  busy.value = true
  try {
    const r = asRecord(await testNotifyChannel(row.id))
    if (generation !== loadGeneration || !pageAlive) return
    toast(r.ok ? '✅ ' + t('notifych.test_sent') : '❌ ' + softText(r))
  } catch (e) {
    if (generation !== loadGeneration || !pageAlive) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (pageAlive) busy.value = false
  }
}

async function removeChannel(c) {
  const row = asRecord(c)
  if (!confirm(t('notifych.delete_confirm', { name: finiteText(row.name) }))) return
  const generation = loadGeneration
  busy.value = true
  try {
    const r = asRecord(await deleteNotifyChannel(row.id))
    if (generation !== loadGeneration || !pageAlive) return
    toast('✅ ' + t('common.delete'))
    if (asRecord(editing.value).id === row.id) editing.value = null
    await load()
  } catch (e) {
    if (generation !== loadGeneration || !pageAlive) return
    toast('❌ ' + finiteText(e.message))
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
.notify-channels { grid-column: 1 / -1; }
.sub-line { color: var(--sub); font-size: 10px; }
.row-btns { display: flex; gap: 4px; justify-content: flex-end; flex-wrap: wrap; }
.editor {
  margin-top: 12px;
  padding-top: 12px;
  border-top: 1px solid var(--line);
}
.form-grid {
  display: grid;
  grid-template-columns: 150px 1fr;
  gap: 10px 14px;
  align-items: center;
  font-size: 13px;
}
.form-grid label { color: var(--sub); font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: .3px; }
.form-grid input[type=text],
.form-grid input[type=password],
.form-grid select { width: 100%; max-width: 420px; }
@media (max-width: 640px) {
  .form-grid { grid-template-columns: 1fr; gap: 5px; }
  .row-btns { justify-content: flex-start; }
}
</style>
