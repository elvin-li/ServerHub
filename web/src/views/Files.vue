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
        <select v-model="rootId" class="cat-select" @change="onRootChange" :aria-label="t('files.root')">
          <option v-for="r in asArray(roots)" :key="finiteText(asRecord(r).id)" :value="asRecord(r).id">{{ finiteText(asRecord(r).name) }}</option>
        </select>
        <button type="button" @click="loadList" :disabled="loading">{{ t('common.refresh') }}</button>
        <button type="button" :disabled="busy" @click="doMkdir">{{ t('files.mkdir') }}</button>
        <label class="upload-btn">
          {{ t('files.upload') }}
          <!-- sr-only, not the hidden attribute: hidden removed the input from
               the tab order and the accessibility tree, so a keyboard or
               screen-reader user had no way to upload at all (drag-drop is
               mouse-only). The wrapping label still names it; the ring is
               drawn on the visible button below. -->
          <input type="file" multiple class="sr-only" @change="onUpload" />
        </label>
        <button type="button" class="danger" :disabled="busy || !asArray(selected).length" @click="doDeleteSelected">
          {{ t('files.delete') }}
        </button>
        <!-- role=status: navigation, uploads and deletes change this count and
             it changed silently for a screen reader (Modules / Services). -->
        <span class="meta-count" role="status" v-if="listing">{{ finiteN(asRecord(listing).count) }} {{ t('files.items') }}</span>
        <div class="toolbar-spacer"></div>
        <button type="button" :disabled="busy" @click="openFullFB">{{ t('files.open_full') }}</button>
        <button
          v-if="asRecord(fb).running"
          type="button"
          class="danger"
          :disabled="busy"
          @click="stopFB"
          :title="t('files.stop_fb_hint')"
        >{{ t('files.stop_fb') }}</button>
        <button type="button" class="tiny" @click="deactivate">{{ t('files.close_panel') }}</button>
      </div>

      <!-- App.vue already owns two labelled navigation landmarks; a third one
           with no name is announced as an anonymous "navigation". -->
      <nav class="crumbs" v-if="listing" :aria-label="t('files.breadcrumbs')">
        <button type="button" class="crumb" @click="goPath(asRecord(listing).root)">{{ finiteText(asRecord(listing).root_id, 'root') }}</button>
        <template v-for="(c, i) in asArray(asRecord(listing).crumbs)" :key="finiteText(asRecord(c).path)">
          <span class="sep">/</span>
          <button type="button" class="crumb" :class="{ current: i === asArray(asRecord(listing).crumbs).length - 1 }" @click="goPath(asRecord(c).path)">
            {{ finiteText(asRecord(c).name, '/') }}
          </button>
        </template>
      </nav>

      <div class="err-live" role="alert" aria-live="assertive"><div v-if="error" class="err-bar">{{ finiteText(error) }}</div></div>

      <div class="table-wrap" @dragover.prevent @drop.prevent="onDrop">
        <table class="dense files-table fit-m" v-if="listing">
          <thead>
            <tr>
              <th class="col-check"><input type="checkbox" :checked="allSelected" @change="toggleAll" :aria-label="t('files.select_all')" /></th>
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
              v-for="it in asArray(asRecord(listing).items)"
              :key="finiteText(asRecord(it).path)"
              :class="{ selected: asArray(selected).includes(asRecord(it).path), dir: asRecord(it).is_dir }"
              @dblclick="openItem(it)"
            >
              <td class="col-check" @click.stop>
                <input type="checkbox" :checked="asArray(selected).includes(asRecord(it).path)" @change="toggleSel(asRecord(it).path)" :aria-label="t('files.select_item', { name: finiteText(asRecord(it).name) })" />
              </td>
              <td class="name-cell" @click="openItem(it)" tabindex="0" role="button" @keydown.enter.prevent="openItem(it)" @keydown.space.prevent="openItem(it)">
                <span class="name-inner">
                  <span class="ico" aria-hidden="true">{{ asRecord(it).is_dir ? '📁' : (asRecord(it).is_link ? '🔗' : '📄') }}</span>
                  <span class="name-text">{{ finiteText(asRecord(it).name) }}</span>
                </span>
                <div class="show-m sub">{{ fmtTime(asRecord(it).mtime) }}{{ finiteText(asRecord(it).mode, '') ? ' · ' + finiteText(asRecord(it).mode) : '' }}</div>
              </td>
              <td class="mono size-cell">{{ asRecord(it).is_dir ? '—' : fmtSize(asRecord(it).size) }}</td>
              <td class="mono sub time-cell col-hide-m">{{ fmtTime(asRecord(it).mtime) }}</td>
              <td class="mono sub mode-cell col-hide-m">{{ finiteText(asRecord(it).mode) }}</td>
              <td class="actions-cell" @click.stop>
                <div class="act-row">
                  <button v-if="asRecord(it).is_file" type="button" class="act-btn" @click="download(it)">{{ t('files.download') }}</button>
                  <!-- Bound to busy like the toolbar buttons: without it a second
                       click during an in-flight delete issued a second request for
                       the same path and then reported its failure. -->
                  <button type="button" class="act-btn" :disabled="busy" @click="doRename(it)">{{ t('files.rename') }}</button>
                  <button type="button" class="act-btn danger" :disabled="busy" @click="doDeleteOne(it)">{{ t('files.delete') }}</button>
                </div>
              </td>
            </tr>
            <!-- A failed reload keeps the previous listing on screen; the row
                 must not claim the folder is empty when the read that would
                 prove it just failed (the banner above carries the reason). -->
            <tr v-if="!asArray(asRecord(listing).items).length">
              <td colspan="6" class="empty-row">{{ error ? t('common.load_failed') : t('files.empty') }}</td>
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
import { asArray, asRecord, finiteN, finiteText, fmtTs } from '../lib/finite'
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
let pageAlive = true

const allSelected = computed(() => {
  const items = asArray(asRecord(listing.value).items)
  return items.length > 0 && items.every(i => asArray(selected.value).includes(asRecord(i).path))
})

const parentPath = computed(() => {
  const row = asRecord(listing.value)
  if (!listing.value) return null
  const p = finiteText(row.path, '')
  const root = finiteText(row.root, '')
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
  let v = finiteN(n, null)
  if (v == null || !Number.isFinite(v) || v < 0) return '—'
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++ }
  return `${v < 10 && i > 0 ? v.toFixed(1) : Math.round(v)} ${u[i]}`
}

function fmtTime(ts) {
  return fmtTs(ts)
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
  busy.value = false
  listing.value = null
  selected.value = []
  error.value = ''
  // do not stop FileBrowser automatically — user may still use it elsewhere
}

async function loadOverview() {
  const request = ++listRequest
  try {
    const j = asRecord(await getFilesOverview())
    if (request !== listRequest) return false
    roots.value = asArray(j.roots).map((row) => asRecord(row))
    fb.value = asRecord(j.filebrowser)
    if (!rootId.value && asArray(roots.value).length) {
      const first = asRecord(asArray(roots.value)[0])
      rootId.value = first.id
      currentPath.value = first.path
    }
    return true
  } catch (e) {
    if (request !== listRequest) return false
    error.value = finiteText(e.message || String(e), '')
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
    const j = asRecord(await listFiles(path, root))
    if (request !== listRequest || !activated.value) return
    listing.value = {
      ...j,
      items: asArray(j.items).map((row) => asRecord(row)),
      crumbs: asArray(j.crumbs).map((row) => asRecord(row)),
    }
    currentPath.value = j.path
  } catch (e) {
    if (request !== listRequest || !activated.value) return
    error.value = finiteText(e.message || String(e), '')
  } finally {
    if (request === listRequest) loading.value = false
  }
}

function onRootChange() {
  const r = asRecord(asArray(roots.value).find(x => asRecord(x).id === rootId.value))
  currentPath.value = r.path || ''
  loadList()
}

function goPath(path) {
  currentPath.value = path
  loadList()
}

function openItem(it) {
  const row = asRecord(it)
  if (row.is_dir) {
    currentPath.value = row.path
    loadList()
  } else {
    download(it)
  }
}

function toggleSel(path) {
  if (asArray(selected.value).includes(path)) {
    selected.value = asArray(selected.value).filter(p => p !== path)
  } else {
    selected.value = [...asArray(selected.value), path]
  }
}

function toggleAll(e) {
  if (e.target.checked) {
    selected.value = asArray(asRecord(listing.value).items).map(i => asRecord(i).path)
  } else {
    selected.value = []
  }
}

async function doMkdir() {
  const name = prompt(t('files.mkdir_ph'))
  if (!name) return
  const request = listRequest
  busy.value = true
  try {
    const r = asRecord(await makeDirectory(currentPath.value, name, rootId.value))
    if (request !== listRequest) return
    toast(`✅ ${t('files.mkdir')}`)
    await loadList()
  } catch (e) {
    if (request !== listRequest) return
    toast(`❌ ${finiteText(e.message)}`)
  } finally {
    // loadList() bumps listRequest, so a request match would leave the
    // toolbar stuck disabled after a successful mkdir.
    if (pageAlive) busy.value = false
  }
}

async function doRename(it) {
  if (busy.value) return
  const row = asRecord(it)
  const name = prompt(t('files.rename_ph'), row.name)
  if (!name || name === row.name) return
  const request = listRequest
  busy.value = true
  try {
    const r = asRecord(await renameFile(row.path, name, rootId.value))
    if (request !== listRequest) return
    toast('✅')
    await loadList()
  } catch (e) {
    if (request !== listRequest) return
    toast(`❌ ${finiteText(e.message)}`)
  } finally {
    // loadList() bumps listRequest, so a request match would leave Rename
    // stuck disabled after a successful write.
    if (pageAlive) busy.value = false
  }
}

async function doDeleteOne(it) {
  if (busy.value) return
  const row = asRecord(it)
  const key = row.is_dir ? 'files.confirm_delete_dir' : 'files.confirm_delete'
  if (!confirm(t(key, { name: finiteText(row.name) }))) return
  const request = listRequest
  busy.value = true
  try {
    const r = asRecord(await deleteFile(row.path, rootId.value))
    if (request !== listRequest) return
    toast('✅')
    await loadList()
  } catch (e) {
    if (request !== listRequest) return
    toast(`❌ ${finiteText(e.message)}`)
  } finally {
    // loadList() bumps listRequest, so a request match would leave Delete
    // stuck disabled after a successful write.
    if (pageAlive) busy.value = false
  }
}

async function doDeleteSelected() {
  if (!asArray(selected.value).length) return
  const items = asArray(asRecord(listing.value).items)
  const hasDir = asArray(selected.value).some((path) => asRecord(items.find((it) => asRecord(it).path === path)).is_dir)
  const key = hasDir ? 'files.confirm_delete_n_dirs' : 'files.confirm_delete_n'
  if (!confirm(t(key, { n: asArray(selected.value).length }))) return
  const paths = [...asArray(selected.value)]
  const request = listRequest
  busy.value = true
  let ok = 0
  let failed = 0
  try {
    for (const path of paths) {
      try {
        const r = asRecord(await deleteFile(path, rootId.value))
        if (request !== listRequest) return
        ok++
      } catch (e) {
        if (request !== listRequest) return
        failed++
        toast(`❌ ${finiteText(path)}: ${finiteText(e.message)}`)
      }
    }
    if (request !== listRequest) return
    toast(`${failed ? '❌' : '✅'} ${ok}/${paths.length}`)
    await loadList()
  } finally {
    // loadList() bumps listRequest, so a request match would leave the
    // toolbar stuck disabled after a successful batch delete.
    if (pageAlive) busy.value = false
  }
}

function download(it) {
  const row = asRecord(it)
  const q = new URLSearchParams({ path: finiteText(row.path, '') })
  if (rootId.value) q.set('root_id', rootId.value)
  // An <a> with rel=noopener, not window.open: the download endpoint can
  // 302 through a content-type the browser will render, and a tab opened
  // without noopener gets window.opener back to the panel.
  const a = document.createElement('a')
  a.href = `/api/files/download?${q}`
  a.target = '_blank'
  a.rel = 'noopener'
  a.download = finiteText(row.name, 'download')
  document.body.appendChild(a)
  a.click()
  a.remove()
}

async function uploadFiles(fileList) {
  if (!fileList?.length) return
  const files = Array.from(fileList)
  const request = listRequest
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
        const r = asRecord(await uploadFile(fd))
        if (request !== listRequest) return
        ok++
      } catch (e) {
        if (request !== listRequest) return
        failed++
        toast(`❌ ${finiteText(file.name)}: ${finiteText(e.message)}`)
      }
    }
    if (request !== listRequest) return
    toast(`${failed ? '❌' : '✅'} ${ok}/${files.length}`)
    await loadList()
  } finally {
    // loadList() bumps listRequest, so a request match would leave Upload
    // stuck disabled after a successful batch.
    if (pageAlive) busy.value = false
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
  const request = listRequest
  busy.value = true
  try {
    // activate panel lightly so roots load; FB is separate process
    if (!activated.value) {
      // still only start FB — don't force builtin list
    }
    const j = asRecord(await ensureFileBrowser())
    if (request !== listRequest) return
    if (!j.ok) throw new Error(finiteText(j.message, '') || t('common.failed'))
    fb.value = j
    const url = finiteText(j.url, '') || 'http://localhost:8125'
    window.open(url, '_blank', 'noopener')
    toast(j.started ? t('files.fb_started') : t('files.fb_running'))
    // optional: enable on-demand mode so it won't auto-start at boot next time
  } catch (e) {
    if (request !== listRequest) return
    toast(`❌ ${finiteText(e.message)}`)
  } finally {
    // deactivate()/loadList() bump listRequest; a request match would leave
    // Open FileBrowser stuck after the user closed the builtin list.
    if (pageAlive) busy.value = false
  }
}

async function stopFB() {
  if (!confirm(t('files.confirm_stop_fb'))) return
  const request = listRequest
  busy.value = true
  try {
    const j = asRecord(await stopFileBrowser())
    if (request !== listRequest) return
    if (!j.ok) throw new Error(finiteText(j.message, '') || t('common.failed'))
    fb.value = j
    toast(finiteText(j.message, '') || '✅ ' + t('common.ok'))
  } catch (e) {
    if (request !== listRequest) return
    toast(`❌ ${finiteText(e.message)}`)
  } finally {
    if (pageAlive) busy.value = false
  }
}

// Nothing on mount — true zero cost until user clicks
onUnmounted(() => {
  pageAlive = false
  listRequest += 1
  activated.value = false
  loading.value = false
  busy.value = false
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
/* The file input inside is sr-only (kept focusable for keyboard upload), and
   the global sheet suppresses input:focus-visible outlines — so the keyboard
   ring has to be drawn on the visible button the input lives in. */
.upload-btn:has(input:focus-visible) { outline: 2px solid var(--accent); outline-offset: 2px; }

.crumbs {
  display: flex; flex-wrap: wrap; align-items: center; gap: 2px;
  margin: 0 0 10px; font-size: 12px;
}
.crumb {
  background: none; border: none; color: var(--accent-text);
  cursor: pointer; padding: 2px 4px; font-size: 12px;
}
.crumb.current { color: var(--txt); font-weight: 600; cursor: default; }
.sep { color: var(--sub); }

.err-live:empty {
  position: absolute;
  width: 0;
  height: 0;
  overflow: hidden;
}
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
:global([data-theme="macos"] .files-table tr.selected),
:global([data-theme="macos"] .files-table tr.selected td),
:global([data-theme="macos"] .files-table tr.selected:hover),
:global([data-theme="macos"] .files-table tr.selected:hover td),
:global([data-theme="macos-dark"] .files-table tr.selected),
:global([data-theme="macos-dark"] .files-table tr.selected td),
:global([data-theme="macos-dark"] .files-table tr.selected:hover),
:global([data-theme="macos-dark"] .files-table tr.selected:hover td) {
  background: var(--accent-fill);
  color: var(--on-accent);
  box-shadow: none;
}
:global([data-theme="macos"] .files-table tr.selected .sub),
:global([data-theme="macos"] .files-table tr.selected .name-text),
:global([data-theme="macos-dark"] .files-table tr.selected .sub),
:global([data-theme="macos-dark"] .files-table tr.selected .name-text) {
  /* The row's fill is --accent-fill; its ink has to be the paired token. */
  color: var(--on-accent);
}

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
.act-btn.danger { color: var(--down-text); border-color: color-mix(in srgb, var(--down) 40%, var(--line)); }
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
