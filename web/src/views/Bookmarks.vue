<template>
  <div>
    <div class="page-title">
      <h1>{{ t('bookmarks.title') }}</h1>
      <span class="meta">{{ t('bookmarks.meta') }}</span>
    </div>
    <div class="toolbar">
      <button class="primary" @click="refresh(true)" :disabled="loading">{{ t('bookmarks.force') }}</button>
      <span class="meta" v-if="data">
        {{ t('bookmarks.summary', {
          up: data.up,
          stopped: data.stopped ?? 0,
          down: data.down,
          at: data.checked_at || '—',
        }) }}
      </span>
    </div>
    <SkeletonLoader v-if="!loaded" variant="cards" :rows="8" />
    <!-- Empty state: the grid is a bare v-for, so with no bookmarks the page
         showed only the static hint below and read as broken rather than empty. -->
    <div v-else-if="!(data?.bookmarks || []).length" class="placeholder">{{ t('common.none') }}</div>
    <div v-else class="bm-page-grid">
      <a
        v-for="b in data?.bookmarks || []"
        :key="b.url"
        class="bm-page-card"
        :class="cardClass(b)"
        :href="b.url"
        target="_blank"
        rel="noopener"
      >
        <div class="row">
          <span class="led" :class="ledClass(b)"></span>
          <span class="bm-title">{{ b.name }}</span>
          <span class="badge" :class="badgeClass(b)">
            {{ badgeText(b) }}
          </span>
        </div>
        <div class="bm-url mono">{{ b.url }}</div>
        <div class="bm-foot">
          <span v-if="b.ms != null">{{ b.ms }} ms</span>
          <span v-if="b.backend" class="backend">{{ backendHint(b) }}</span>
          <span v-if="b.error" class="err">{{ b.error }}</span>
        </div>
      </a>
    </div>
    <p class="hint">{{ t('bookmarks.hint') }}</p>
  </div>
</template>

<script setup>
import { inject, onMounted, ref } from 'vue'
import { getBookmarks } from '../api/client'
import { injectI18n } from '../i18n'
import SkeletonLoader from '../components/SkeletonLoader.vue'

const toast = inject('toast')
const { t } = injectI18n()
const data = ref(null)
const loading = ref(false)
// Every bookmark is probed over the network before the response returns, so an
// empty grid is the normal state for a second or more on first paint.
const loaded = ref(false)

function healthOf(b) {
  if (b?.health) return b.health
  return b?.ok ? 'ok' : 'error'
}
function cardClass(b) {
  const h = healthOf(b)
  if (h === 'stopped') return 'stopped'
  if (h === 'error') return 'down'
  return ''
}
function ledClass(b) {
  const h = healthOf(b)
  if (h === 'ok') return 'on'
  if (h === 'stopped') return 'off'
  return 'err'
}
function badgeClass(b) {
  const h = healthOf(b)
  if (h === 'ok') return 'ok'
  if (h === 'stopped') return 'stopped'
  return 'down'
}
function badgeText(b) {
  const h = healthOf(b)
  if (h === 'ok') return b.status || t('dashboard.bm_up')
  if (h === 'stopped') return t('dashboard.bm_stopped')
  return t('dashboard.bm_down')
}
function backendHint(b) {
  const bk = b.backend
  if (!bk) return ''
  const name = bk.name || bk.id || ''
  const st = bk.status || bk.state || ''
  return `${bk.kind || 'svc'}: ${name}${st ? ' · ' + st : ''}`
}

async function refresh(force = false) {
  loading.value = true
  try {
    // Shared client, not a raw fetch: it checks r.ok, so an expired session
    // fires AUTH_LOST_EVENT instead of writing the 401 body into `data`.
    data.value = await getBookmarks(force)
  } catch (e) {
    toast('❌ ' + e.message)
  }
  loading.value = false
  loaded.value = true
}

onMounted(() => refresh(false))
</script>

<style scoped>
.bm-page-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(240px, 1fr));
  gap: 8px;
}
.bm-page-card {
  display: flex;
  flex-direction: column;
  gap: 6px;
  min-height: 96px;
  padding: 12px 14px;
  background: var(--card);
  border: 1px solid var(--line);
  border-radius: var(--radius);
  text-decoration: none;
  color: inherit;
  box-shadow: var(--card-shadow);
  transition: border-color .15s, transform .1s, box-shadow .15s;
}
.bm-page-card:hover {
  border-color: var(--accent);
  transform: translateY(-1px);
  box-shadow: 0 3px 10px rgba(0,0,0,.06);
}
.bm-page-card.down { border-color: color-mix(in srgb, var(--down) 40%, var(--line)); }
.bm-page-card.stopped {
  border-color: color-mix(in srgb, #888 35%, var(--line));
  opacity: 0.9;
}
.bm-page-card .row {
  display: flex;
  align-items: center;
  gap: 8px;
  min-width: 0;
}
.bm-title {
  flex: 1;
  min-width: 0;
  font-weight: 700;
  font-size: 13px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.bm-page-card.stopped .bm-title { color: var(--sub); }
.bm-page-card.down .bm-title { color: var(--down); }
.bm-url {
  font-size: 11px;
  color: var(--sub);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.bm-foot {
  margin-top: auto;
  font-size: 11px;
  color: var(--sub);
  font-variant-numeric: tabular-nums;
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}
.bm-foot .err { color: var(--down); }
.bm-foot .backend { color: var(--sub); }
.hint {
  margin-top: 12px;
  color: var(--sub);
  font-size: 12px;
  line-height: 1.5;
}
</style>
