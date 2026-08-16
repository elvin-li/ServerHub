<template>
  <div class="files-page">
    <div class="page-title files-title">
      <h1>{{ t('files.title') }}</h1>
      <span class="meta">{{ t('files.meta') }}</span>
    </div>

    <!-- Idle gate: nothing loaded until user clicks -->
    <div v-if="!activated" class="idle-card">
      <div class="idle-icon" aria-hidden="true">📁</div>
      <h2>{{ t('files.idle_title') }}</h2>
      <p class="hint">{{ t('files.idle_hint') }}</p>
      <div class="idle-actions">
        <button type="button" class="primary" @click="activate">{{ t('files.open_builtin') }}</button>
        <button type="button" :disabled="busy" @click="openFullFB">{{ t('files.open_full') }}</button>
      </div>
      <p class="sub-hint">{{ t('files.idle_note') }}</p>
    </div>

    <template v-else>
      <div class="toolbar files-toolbar">
        <select v-model="rootId" class="cat-select" @change="onRootChange">
          <option v-for="r in roots" :key="r.id" :value="r.id">{{ r.name }}</option>
        </select>
        <button type="button" @click="loadList" :disabled="loading">{{ t('common.refresh') }}</button>
        <button type="button" :disabled="busy" @click="doMkdir">{{ t('files.mkdir') }}</button>
        <label class="upload-btn">
          {{ t('files.upload') }}
          <input type="file" multiple hidden @change="onUpload" />
        </label>
        <button type="button" class="danger" :disabled="busy || !selected.length" @click="doDeleteSelected">
          {{ t('files.delete') }}
        </button>
        <span class="meta-count" v-if="listing">{{ listing.count }} {{ t('files.items') }}</span>
        <div class="toolbar-spacer"></div>
        <button type="button" :disabled="busy" @click="openFullFB">{{ t('files.open_full') }}</button>
        <button
          v-if="fb.running"
          type="button"
          class="danger"
          :disabled="busy"
          @click="stopFB"
          :title="t('files.stop_fb_hint')"
        >{{ t('files.stop_fb') }}</button>
        <button type="button" class="tiny" @click="deactivate">{{ t('files.close_panel') }}</button>
      </div>

      <nav class="crumbs" v-if="listing">
        <button type="button" class="crumb" @click="goPath(listing.root)">{{ listing.root_id || 'root' }}</button>
        <template v-for="(c, i) in listing.crumbs" :key="c.path">
          <span class="sep">/</span>
          <button type="button" class="crumb" :class="{ current: i === listing.crumbs.length - 1 }" @click="goPath(c.path)">
            {{ c.name || '/' }}
          </button>
        </template>
      </nav>

      <div v-if="error" class="err-bar">{{ error }}</div>

      <div class="table-wrap" @dragover.prevent @drop.prevent="onDrop">
        <table class="dense files-table fit-m" v-if="listing">
          <thead>
            <tr>
              <th class="col-check"><input type="checkbox" :checked="allSelected" @change="toggleAll" /></th>
              <th>{{ t('common.name') }}</th>
              <th>{{ t('files.size') }}</th>
              <th class="col-hide-m">{{ t('files.mtime') }}</th>
              <th class="col-hide-m">{{ t('files.mode') }}</th>
              <th>{{ t('common.actions') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-if="parentPath" class="parent-row" @click="goPath(parentPath)" tabindex="0" role="button" @keydown.enter.prevent="goPath(parentPath)" @keydown.space.prevent="goPath(parentPath)">
              <td></td>
              <td colspan="5"><strong>..</strong> <span class="sub">{{ t('files.parent') }}</span></td>
            </tr>
            <tr
              v-for="it in listing.items"
              :key="it.path"
              :class="{ selected: selected.includes(it.path), dir: it.is_dir }"
              @dblclick="openItem(it)"
            >
              <td class="col-check" @click.stop>
                <input type="checkbox" :checked="selected.includes(it.path)" @change="toggleSel(it.path)" />
              </td>
              <td class="name-cell" @click="openItem(it)" tabindex="0" role="button" @keydown.enter.prevent="openItem(it)" @keydown.space.prevent="openItem(it)">
                <span class="name-inner">
                  <span class="ico" aria-hidden="true">{{ it.is_dir ? '📁' : (it.is_link ? '🔗' : '📄') }}</span>
                  <span class="name-text">{{ it.name }}</span>
                </span>
                <div class="show-m sub">{{ fmtTime(it.mtime) }}{{ it.mode ? ' · ' + it.mode : '' }}</div>
              </td>
              <td class="mono size-cell">{{ it.is_dir ? '—' : fmtSize(it.size) }}</td>
              <td class="mono sub time-cell col-hide-m">{{ fmtTime(it.mtime) }}</td>
              <td class="mono sub mode-cell col-hide-m">{{ it.mode }}</td>
              <td class="actions-cell" @click.stop>
                <div class="act-row">
                  <button v-if="it.is_file" type="button" class="act-btn" @click="download(it)">{{ t('files.download') }}</button>
                  <!-- Bound to busy like the toolbar buttons: without it a second
                       click during an in-flight delete issued a second request for
                       the same path and then reported its failure. -->
                  <button type="button" class="act-btn" :disabled="busy" @click="doRename(it)">{{ t('files.rename') }}</button>
                  <button type="button" class="act-btn danger" :disabled="busy" @click="doDeleteOne(it)">{{ t('files.delete') }}</button>
                </div>
              </td>
            </tr>
            <tr v-if="!(listing.items || []).length">
              <td colspan="6" class="empty-row">{{ t('files.empty') }}</td>
            </tr>
          </tbody>
        </table>
        <div v-else-if="loading" class="placeholder">{{ t('common.loading') }}</div>
      </div>

      <p class="drop-hint">{{ t('files.drop_hint') }}</p>
    </template>
  </div>
</template>

<script setup>
/**
 * Lazy file manager: no work until activated.
 * Built-in browser uses hub APIs only while this page is open.
 * Full FileBrowser process is started only on explicit request, and can be stopped to free RAM.
 */
import { computed, inject, onUnmounted, ref } from 'vue'
import {
  deleteFile,
  ensureFileBrowser,
  getFilesOverview,
  listFiles,
  makeDirectory,
  renameFile,
  stopFileBrowser,
  uploadFile,
} from '../api/client'
import { injectI18n } from '../i18n'

const toast = inject('toast')
const { t } = injectI18n()

const activated = ref(false)
const loading = ref(false)
const busy = ref(false)
const error = ref('')
const roots = ref([])
const rootId = ref('')
const listing = ref(null)
const selected = ref([])
const fb = ref({ running: false, url: '', installed: false })
const currentPath = ref('')
let listRequest = 0

const allSelected = computed(() => {
  const items = listing.value?.items || []
  return items.length > 0 && items.every(i => selected.value.includes(i.path))
})

const parentPath = computed(() => {
  if (!listing.value) return null
  const p = listing.value.path
  const root = listing.value.root
  if (p === root) return null
  const parts = p.replace(/\/$/, '').split('/')
  parts.pop()
  const parent = parts.join('/') || '/'
  // stay within root
  if (!parent.startsWith(root) && parent !== root) return root
  return parent
})

function fmtSize(n) {
  if (n == null || n === 0) return '0 B'
  const u = ['B', 'KB', 'MB', 'GB', 'TB']
  let i = 0
  let v = Number(n)
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++ }
  return `${v < 10 && i > 0 ? v.toFixed(1) : Math.round(v)} ${u[i]}`
}

function fmtTime(ts) {
  if (!ts) return '—'
  const d = new Date(ts * 1000)
  return d.toLocaleString()
}

async function activate() {
  activated.value = true
  error.value = ''
  // Stop if the overview failed. loadList() clears `error` on entry, so calling
  // it unconditionally erased the overview's message before it could render --
  // leaving an empty roots picker and no explanation, or, when the subsequent
  // listing happened to succeed, a page that looked entirely normal while the
  // configured roots were missing.
  const ok = await loadOverview()
  if (!ok) return
  await loadList()
}

function deactivate() {
  listRequest += 1
  activated.value = false
  loading.value = false
  listing.value = null
  selected.value = []
  error.value = ''
  // do not stop FileBrowser automatically — user may still use it elsewhere
}

async function loadOverview() {
  try {
    const j = await getFilesOverview()
    roots.value = j.roots || []
    fb.value = j.filebrowser || {}
    if (!rootId.value && roots.value.length) {
      rootId.value = roots.value[0].id
      currentPath.value = roots.value[0].path
    }
    return true
  } catch (e) {
    error.value = e.message || String(e)
    return false
  }
}

async function loadList() {
  if (!activated.value) return
  const request = ++listRequest
  const path = currentPath.value
  const root = rootId.value
  loading.value = true
  error.value = ''
  selected.value = []
  try {
    const j = await listFiles(path, root)
    if (request !== listRequest || !activated.value) return
    listing.value = j
    currentPath.value = j.path
  } catch (e) {
    if (request !== listRequest || !activated.value) return
    error.value = typeof e.message === 'string' ? e.message : String(e)
    listing.value = null
  } finally {
    if (request === listRequest) loading.value = false
  }
}

function onRootChange() {
  const r = roots.value.find(x => x.id === rootId.value)
  currentPath.value = r?.path || ''
  loadList()
}

function goPath(path) {
  currentPath.value = path
  loadList()
}

function openItem(it) {
  if (it.is_dir) {
    currentPath.value = it.path
    loadList()
  } else {
    download(it)
  }
}

function toggleSel(path) {
  if (selected.value.includes(path)) {
    selected.value = selected.value.filter(p => p !== path)
  } else {
    selected.value = [...selected.value, path]
  }
}

function toggleAll(e) {
  if (e.target.checked) {
    selected.value = (listing.value?.items || []).map(i => i.path)
  } else {
    selected.value = []
  }
}

async function doMkdir() {
  const name = prompt(t('files.mkdir_ph'))
  if (!name) return
  busy.value = true
  try {
    await makeDirectory(currentPath.value, name, rootId.value)
    toast(`✅ ${t('files.mkdir')}`)
    await loadList()
  } catch (e) {
    toast(`❌ ${e.message}`)
  } finally {
    busy.value = false
  }
}

async function doRename(it) {
  if (busy.value) return
  const name = prompt(t('files.rename_ph'), it.name)
  if (!name || name === it.name) return
  busy.value = true
  try {
    await renameFile(it.path, name, rootId.value)
    toast('✅')
    await loadList()
  } catch (e) {
    toast(`❌ ${e.message}`)
  } finally {
    busy.value = false
  }
}

async function doDeleteOne(it) {
  if (busy.value) return
  if (!confirm(t('files.confirm_delete', { name: it.name }))) return
  busy.value = true
  try {
    await deleteFile(it.path, rootId.value)
    toast('✅')
    await loadList()
  } catch (e) {
    toast(`❌ ${e.message}`)
  } finally {
    busy.value = false
  }
}

async function doDeleteSelected() {
  if (!selected.value.length) return
  if (!confirm(t('files.confirm_delete_n', { n: selected.value.length }))) return
  const paths = [...selected.value]
  busy.value = true
  let ok = 0
  let failed = 0
  try {
    for (const path of paths) {
      try {
        await deleteFile(path, rootId.value)
        ok++
      } catch (e) {
        failed++
        toast(`❌ ${path}: ${e.message}`)
      }
    }
    toast(`${failed ? '❌' : '✅'} ${ok}/${paths.length}`)
    await loadList()
  } finally {
    busy.value = false
  }
}

function download(it) {
  const q = new URLSearchParams({ path: it.path })
  if (rootId.value) q.set('root_id', rootId.value)
  window.open(`/api/files/download?${q}`, '_blank')
}

async function uploadFiles(fileList) {
  if (!fileList?.length) return
  const files = Array.from(fileList)
  busy.value = true
  let ok = 0
  let failed = 0
  try {
    for (const file of files) {
      try {
        const fd = new FormData()
        fd.append('path', currentPath.value)
        if (rootId.value) fd.append('root_id', rootId.value)
        fd.append('file', file)
        await uploadFile(fd)
        ok++
      } catch (e) {
        failed++
        toast(`❌ ${file.name}: ${e.message}`)
      }
    }
    toast(`${failed ? '❌' : '✅'} ${ok}/${files.length}`)
    await loadList()
  } finally {
    busy.value = false
  }
}

// Both entry points refuse to start a second batch while one is running.
// uploadFiles' finally clears `busy` unconditionally, so an overlapping batch let
// the first one to finish re-enable the toolbar (including Delete) while the other
// was still uploading.
function onUpload(e) {
  const files = e.target.files
  if (!busy.value) uploadFiles(files)
  e.target.value = ''
}

function onDrop(e) {
  const files = e.dataTransfer?.files
  if (files?.length && !busy.value) uploadFiles(files)
}

async function openFullFB() {
  busy.value = true
  try {
    // activate panel lightly so roots load; FB is separate process
    if (!activated.value) {
      // still only start FB — don't force builtin list
    }
    const j = await ensureFileBrowser()
    if (!j?.ok) throw new Error(j?.message || t('common.failed'))
    fb.value = j
    const url = j.url || 'http://localhost:8125'
    window.open(url, '_blank', 'noopener')
    toast(j.started ? t('files.fb_started') : t('files.fb_running'))
    // optional: enable on-demand mode so it won't auto-start at boot next time
  } catch (e) {
    toast(`❌ ${e.message}`)
  } finally {
    busy.value = false
  }
}

async function stopFB() {
  if (!confirm(t('files.confirm_stop_fb'))) return
  busy.value = true
  try {
    const j = await stopFileBrowser()
    if (!j?.ok) throw new Error(j?.message || t('common.failed'))
    fb.value = j
    toast(j.message || '✅ ' + t('common.ok'))
  } catch (e) {
    toast(`❌ ${e.message}`)
  } finally {
    busy.value = false
  }
}

// Nothing on mount — true zero cost until user clicks
onUnmounted(() => {
  listRequest += 1
  activated.value = false
  loading.value = false
  // free UI state only; backend process not touched
  listing.value = null
})
</script>

<style scoped>
.files-page { min-width: 0; }
.files-title {
  align-items: center;
  flex-wrap: nowrap;
}
.files-title h1 {
  margin: 0;
  white-space: nowrap;
  flex-shrink: 0;
}
.files-title .meta {
  text-align: right;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  min-width: 0;
}
@media (max-width: 640px) {
  .files-title {
    flex-wrap: wrap;
  }
  .files-title .meta {
    white-space: normal;
    text-align: left;
    width: 100%;
  }
}
.idle-card {
  max-width: 480px;
  margin: 48px auto;
  padding: 32px 28px;
  text-align: center;
  background: var(--card);
  border: 1px solid var(--line);
  border-radius: var(--radius-lg);
  box-shadow: var(--card-shadow, none);
}
.idle-icon { font-size: 42px; line-height: 1; margin-bottom: 12px; }
.idle-card h2 { margin: 0 0 8px; font-size: 18px; }
.idle-card .hint { color: var(--sub); font-size: 13px; margin: 0 0 18px; line-height: 1.5; }
.idle-actions { display: flex; gap: 10px; justify-content: center; flex-wrap: wrap; }
.sub-hint { margin: 16px 0 0; font-size: 11px; color: var(--sub); line-height: 1.45; }

.files-toolbar { flex-wrap: wrap; gap: 8px; align-items: center; }
.toolbar-spacer { flex: 1; }
/* .meta-count is fully covered by the global rule. */
.upload-btn {
  display: inline-flex; align-items: center;
  padding: 5px 10px; font-size: 12px;
  border: 1px solid var(--line); border-radius: var(--radius);
  background: var(--card); cursor: pointer;
}
.upload-btn:hover { border-color: var(--accent); }

.crumbs {
  display: flex; flex-wrap: wrap; align-items: center; gap: 2px;
  margin: 0 0 10px; font-size: 12px;
}
.crumb {
  background: none; border: none; color: var(--accent);
  cursor: pointer; padding: 2px 4px; font-size: 12px;
}
.crumb.current { color: var(--txt); font-weight: 600; cursor: default; }
.sep { color: var(--sub); }

.err-bar {
  padding: 8px 12px; margin-bottom: 10px; font-size: 12px;
  background: color-mix(in srgb, #c02020 10%, var(--card));
  border: 1px solid color-mix(in srgb, #c02020 35%, var(--line));
  border-radius: var(--radius);
}

.files-table tr { cursor: default; }
.files-table tr.dir { cursor: pointer; }
.files-table tr:hover { background: color-mix(in srgb, var(--accent) 6%, transparent); }
.files-table tr.selected { background: color-mix(in srgb, var(--accent) 12%, transparent); }

/* Uniform row height across all columns */
.files-table th,
.files-table td {
  vertical-align: middle;
  height: 34px;
  padding: 4px 8px;
  line-height: 1.25;
  box-sizing: border-box;
}
.col-check { width: 36px; text-align: center; }
.col-check input { vertical-align: middle; margin: 0; }

.name-cell {
  cursor: pointer;
  max-width: 0; /* allow ellipsis in table layout */
  width: 38%;
}
.name-inner {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  max-width: 100%;
  min-height: 20px;
  line-height: 20px;
  vertical-align: middle;
}
.ico {
  flex: 0 0 auto;
  width: 1.15em;
  height: 20px;
  font-size: 13px;
  line-height: 20px;
  text-align: center;
  display: inline-block;
}
.name-text {
  font-weight: 600;
  font-size: 12px;
  line-height: 20px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  min-width: 0;
}
.size-cell,
.time-cell,
.mode-cell {
  white-space: nowrap;
  font-size: 12px;
  line-height: 20px;
}
.sub { color: var(--sub); font-size: 12px; }
.actions-cell { white-space: nowrap; }
.act-row {
  display: inline-flex;
  flex-wrap: nowrap;
  align-items: center;
  gap: 4px;
  min-height: 20px;
  line-height: 20px;
}
.act-btn {
  font-size: 11px;
  line-height: 1.2;
  height: 22px;
  padding: 0 8px;
  border-radius: var(--radius-sm);
  border: 1px solid var(--line);
  background: var(--card);
  color: var(--txt);
  cursor: pointer;
  white-space: nowrap;
  box-sizing: border-box;
}
.act-btn.danger { color: var(--down); border-color: color-mix(in srgb, var(--down) 40%, var(--line)); }
.empty-row, .placeholder { text-align: center; color: var(--sub); padding: 24px; height: auto; }
.drop-hint { font-size: 11px; color: var(--sub); margin-top: 8px; }
.parent-row { cursor: pointer; }
.parent-row td { height: 34px; }

@media (max-width: 640px) {
  .files-table th,
  .files-table td {
    height: auto;
    min-height: 34px;
  }
  .name-cell { max-width: none; width: auto; }
  .name-text { white-space: normal; }
  .actions-cell { white-space: normal; }
  .act-row { flex-wrap: wrap; }
}
</style>
