<template>
  <div>
    <div class="page-title">
      <h1>{{ t('sites.title') }}</h1>
      <span class="meta">{{ t('sites.meta') }}</span>
    </div>
    <div class="toolbar">
      <button class="primary" :disabled="loading" @click="load(true)">{{ t('common.refresh') }}</button>
      <template v-if="hasNginx">
        <button :disabled="busy" @click="testConf">{{ t('sites.nginx_test') }}</button>
        <button :disabled="busy" @click="reloadConf">{{ t('sites.nginx_reload') }}</button>
      </template>
      <input
        v-model="query"
        type="search"
        class="sites-search"
        :placeholder="t('sites.search')"
        :aria-label="t('sites.search')"
      />
      <select v-model="source" :aria-label="t('sites.source')">
        <option value="">{{ t('sites.all_sources') }}</option>
        <option v-for="s in sourceIds" :key="s" :value="s">{{ sourceLabel(s) }}</option>
      </select>
      <span v-if="loaded" class="sub" data-test="sites-count">{{ t('sites.count', { n: sites.length }) }}</span>
    </div>

    <LoadFailure v-if="loadError" :detail="loadError" :retry="() => load(true)" :busy="loading" />
    <p v-for="n in failedSources" :key="n.id" class="sub sites-note" data-test="source-note">
      ⚠ {{ t('sites.source_failed', { source: sourceLabel(n.id), error: n.error }) }}
    </p>

    <SkeletonLoader v-if="!loaded" :cols="5" :rows="6" />
    <div v-else class="table-wrap">
      <table class="dense fit-m">
        <thead>
          <tr>
            <th>{{ t('sites.name') }}</th>
            <th>{{ t('sites.status') }}</th>
            <th class="col-hide-m">{{ t('sites.source') }}</th>
            <th class="col-hide-m">{{ t('sites.backend') }}</th>
            <th>{{ t('sites.actions') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="s in shown" :key="s.id" data-test="site-row">
            <td>
              <strong>{{ s.name }}</strong>
              <div class="mono sub">
                <a v-if="s.url" :href="s.url" target="_blank" rel="noopener noreferrer">{{ s.url }}</a>
              </div>
              <div v-if="s.also.length" class="sub">{{ t('sites.also', { list: s.also.map(sourceLabel).join(', ') }) }}</div>
              <div class="show-m sub">{{ sourceLabel(s.source) }}<span v-if="s.backend"> · {{ s.backend }}</span></div>
            </td>
            <td>
              <span class="badge" :class="badgeClass(s.status)">{{ t(STATUS_KEYS[s.status]) }}</span>
              <div v-if="s.detail" class="sub" style="font-size:11px">{{ s.detail }}</div>
            </td>
            <td class="col-hide-m">{{ sourceLabel(s.source) }}</td>
            <td class="mono col-hide-m" style="font-size:11px">
              {{ s.backend }}
              <div v-if="s.config" class="sub">{{ s.config }}</div>
            </td>
            <td class="sites-actions">
              <a v-if="s.url" class="btn" :href="s.url" target="_blank" rel="noopener noreferrer">{{ t('common.open') }}</a>
              <button v-if="s.canViewConfig" type="button" @click="openConfig(s)">{{ t('sites.view_config') }}</button>
            </td>
          </tr>
          <tr v-if="!shown.length && !loadError">
            <td colspan="5" class="empty-row">{{ sites.length ? t('sites.no_match') : t('sites.empty') }}</td>
          </tr>
        </tbody>
      </table>
    </div>
    <pre v-if="msg" class="sites-msg" role="status" aria-live="polite">{{ msg }}</pre>

    <div ref="configPanel" v-if="config" class="modal-bg" role="presentation" @click.self="closeConfig">
      <div class="modal sites-modal" role="dialog" aria-modal="true" aria-labelledby="sites-config-title">
        <div class="modal-head">
          <h3 id="sites-config-title" class="modal-title">{{ t('sites.config_title', { path: config.path }) }}</h3>
          <button type="button" @click="closeConfig">{{ t('common.close') }}</button>
        </div>
        <pre class="sites-config" data-test="site-config">{{ config.content }}</pre>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, inject, onMounted, onUnmounted, ref } from 'vue'
import { getSiteConfig, getSites, reloadNginx, testNginx } from '../api/client'
import { injectI18n } from '../i18n'
import { asArray, asRecord, finiteN, finiteText, recGet } from '../lib/finite'
import { useDismissable } from '../composables/useDismissable'
import SkeletonLoader from '../components/SkeletonLoader.vue'
import LoadFailure from '../components/LoadFailure.vue'

// Literal keys (not 'sites.src_' + id) so the i18n coverage test can see them.
const SOURCE_KEYS = {
  nginx: 'sites.src_nginx',
  caddy: 'sites.src_caddy',
  apache: 'sites.src_apache',
  cloudflared: 'sites.src_cloudflared',
  launchd: 'sites.src_launchd',
  docker: 'sites.src_docker',
  listener: 'sites.src_listener',
}
const STATUS_KEYS = {
  ok: 'sites.st_ok',
  warn: 'sites.st_warn',
  down: 'sites.st_down',
  unknown: 'sites.st_unknown',
}
const SOURCES = Object.keys(SOURCE_KEYS)
const STATUSES = Object.keys(STATUS_KEYS)

const toast = inject('toast')
const { t } = injectI18n()
const sites = ref([])
const notes = ref([])
const loaded = ref(false)
const loading = ref(false)
const loadError = ref('')
const busy = ref(false)
const msg = ref('')
const query = ref('')
const source = ref('')
const config = ref(null)
const configPanel = ref(null)
let pageAlive = true
let loadSeq = 0

function text(v) {
  return finiteText(v, '')
}

/** One display row from a raw site record; every field is checked, since the
 *  payload is discovered from arbitrary config files. */
function normalize(raw) {
  const r = asRecord(raw)
  const actions = asArray(recGet(r, 'actions')).map(text)
  const status = text(recGet(r, 'status'))
  const url = text(recGet(r, 'url'))
  const port = finiteN(recGet(r, 'port'), null)
  const root = text(recGet(r, 'root'))
  const upstream = text(recGet(r, 'upstream'))
  return {
    id: text(recGet(r, 'id')),
    name: text(recGet(r, 'name')) || text(recGet(r, 'host')) || (port != null ? `:${port}` : '?'),
    source: text(recGet(r, 'source')),
    // Only http(s) links are rendered as anchors.
    url: /^https?:\/\//i.test(url) ? url : '',
    host: text(recGet(r, 'host')),
    port,
    status: STATUSES.includes(status) ? status : 'unknown',
    detail: text(recGet(r, 'detail')),
    backend: [root, upstream].filter(Boolean).join(' · '),
    config: text(recGet(r, 'config_path')),
    names: asArray(recGet(r, 'server_names')).map(text).filter(Boolean),
    also: asArray(recGet(r, 'also_seen_in')).map(text).filter(Boolean),
    canViewConfig: actions.includes('view_config') && Boolean(text(recGet(r, 'config_path'))),
    canReload: actions.includes('reload'),
  }
}

const sourceIds = computed(() => {
  const seen = new Set(sites.value.map((s) => s.source))
  return [...SOURCES.filter((s) => seen.has(s)), ...[...seen].filter((s) => s && !SOURCES.includes(s))]
})

const failedSources = computed(() => notes.value.filter((n) => !n.ok && n.error))

const hasNginx = computed(() => sites.value.some((s) => s.canReload))

const shown = computed(() => {
  const q = query.value.trim().toLowerCase()
  return sites.value.filter((s) => {
    if (source.value && s.source !== source.value) return false
    if (!q) return true
    return [s.name, s.url, s.host, s.backend, s.config, s.detail, String(s.port ?? ''), ...s.names]
      .some((v) => v && v.toLowerCase().includes(q))
  })
})

function sourceLabel(id) {
  return SOURCES.includes(id) ? t(SOURCE_KEYS[id]) : text(id)
}

function badgeClass(status) {
  return { ok: 'ok', warn: 'warn', down: 'down' }[status] || 'stopped'
}

async function load(force = false) {
  const seq = ++loadSeq
  loading.value = true
  try {
    const j = asRecord(await getSites(force))
    if (seq !== loadSeq || !pageAlive) return
    sites.value = asArray(recGet(j, 'sites')).map(normalize).filter((s) => s.id)
    notes.value = asArray(recGet(j, 'sources')).map((n) => {
      const r = asRecord(n)
      return { id: text(recGet(r, 'id')), ok: recGet(r, 'ok') === true, error: text(recGet(r, 'error')) }
    })
    const err = text(recGet(j, 'error'))
    loadError.value = err
  } catch (e) {
    if (seq !== loadSeq || !pageAlive) return
    loadError.value = text(e?.message || String(e))
    toast('❌ ' + finiteText(e?.message))
  } finally {
    if (seq === loadSeq) {
      loaded.value = true
      loading.value = false
    }
  }
}

async function openConfig(site) {
  try {
    const j = asRecord(await getSiteConfig(site.id))
    if (!pageAlive) return
    config.value = { path: text(recGet(j, 'path')) || site.config, content: text(recGet(j, 'content')) }
  } catch (e) {
    if (!pageAlive) return
    toast('❌ ' + finiteText(e?.message))
  }
}

function closeConfig() {
  config.value = null
}

async function testConf() {
  busy.value = true
  try {
    const j = asRecord(await testNginx())
    if (!pageAlive) return
    msg.value = text(recGet(j, 'message'))
    toast(recGet(j, 'ok') ? '✅ ' + t('sites.conf_valid') : '❌ ' + t('sites.conf_invalid'))
  } catch (e) {
    if (!pageAlive) return
    toast('❌ ' + finiteText(e?.message))
  } finally {
    if (pageAlive) busy.value = false
  }
}

async function reloadConf() {
  if (!confirm(t('sites.confirm_reload'))) return
  busy.value = true
  try {
    const j = asRecord(await reloadNginx())
    if (!pageAlive) return
    msg.value = text(recGet(j, 'message'))
    toast(recGet(j, 'ok') ? '✅ ' + t('common.reloaded') : '❌ ' + t('common.reload_failed'))
    void load(true)
  } catch (e) {
    if (!pageAlive) return
    toast('❌ ' + finiteText(e?.message))
  } finally {
    if (pageAlive) busy.value = false
  }
}

useDismissable(config, closeConfig, configPanel)

onMounted(() => {
  pageAlive = true
  // Opening the page is a refresh too: discovery runs again (a short
  // server-side cache only absorbs double loads within a few seconds).
  void load(true)
})
onUnmounted(() => {
  pageAlive = false
  loadSeq += 1
})
</script>

<style scoped>
.sites-search { min-width: 200px; flex: 1 1 200px; max-width: 360px; }
.sites-note { margin: 4px 0; }
.sites-actions { white-space: nowrap; }
.sites-actions > * + * { margin-left: 6px; }
.sites-msg { margin-top: 10px; font-size: 11px; white-space: pre-wrap; background: var(--bg); padding: 10px; border-radius: 4px; }
.sites-modal { max-width: 860px; width: 92vw; }
.sites-config { max-height: 70vh; overflow: auto; font-size: 11px; white-space: pre; }
</style>
