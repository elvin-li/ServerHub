<template>
  <div>
    <div class="page-title">
      <h1>{{ t('compose.title') }}</h1>
      <span class="meta">{{ t('compose.meta') }}</span>
    </div>

    <div class="two-col" style="align-items:start">
      <div class="tile">
        <h2>{{ t('compose.stacks') }}</h2>
        <div class="toolbar">
          <button class="tiny primary" @click="loadStacks">{{ t('common.refresh') }}</button>
          <button class="tiny" @click="showCreate=true">{{ t('compose.new_stack') }}</button>
        </div>
        <LoadFailure v-if="loadError" :detail="loadError" :retry="loadStacks" :busy="busy" />
        <SkeletonLoader v-if="!loaded" :cols="3" :rows="4" />
        <div v-else class="table-wrap">
          <table class="dense fit-m">
            <thead>
              <tr><th>{{ t('common.name') }}</th><th>{{ t('common.status') }}</th><th></th></tr>
            </thead>
            <tbody>
              <tr
                v-for="s in stacks"
                :key="s.id"
                :style="selected===s.id ? 'background:var(--table-hover)' : ''"
                style="cursor:pointer"
                @click="select(s)"
              >
                <td>
                  <strong>{{ finiteText(s.name) }}</strong>
                  <div class="mono" style="color:var(--sub);font-size:10px">{{ finiteText(s.path) }}</div>
                </td>
                <td><span class="badge" :class="s.status==='ok'?'ok':''">{{ finiteText(s.status) }}</span></td>
                <td class="ops">
                  <button class="tiny" :disabled="!s.compose_path || busy" @click.stop="run(s,'up')">{{ t('compose.up') }}</button>
                  <button class="tiny hide-m" :disabled="!s.compose_path || busy" @click.stop="run(s,'update')">{{ t('docker.update') }}</button>
                  <button class="tiny danger" :disabled="!s.compose_path || busy" @click.stop="run(s,'down')">{{ t('compose.down') }}</button>
                </td>
              </tr>
              <tr v-if="!stacks.length && !loadError">
                <td colspan="3" style="color:var(--sub)">{{ t('common.none') }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <div class="tile">
        <h2>
          {{ t('compose.yaml_editor') }}
          <span v-if="compose" class="sub" style="text-transform:none">{{ finiteText(compose.compose_path) }}</span>
        </h2>
        <div v-if="!compose" class="placeholder" style="padding:24px">{{ t('compose.pick_stack') }}</div>
        <template v-else>
          <textarea
            v-model="editor"
            spellcheck="false"
            class="compose-editor" :aria-label="t('compose.yaml_editor')"></textarea>
          <div class="btns" style="margin-top:8px">
            <button class="primary" :disabled="busy" @click="save">{{ t('common.save') }}</button>
            <button :disabled="busy" @click="validate">{{ t('compose.validate') }}</button>
            <button :disabled="busy" @click="reloadCompose">{{ t('compose.reload_file') }}</button>
            <button :disabled="busy" @click="run({id:selected},'up')">{{ t('compose.up_full') }}</button>
          </div>
          <pre v-if="msg" style="margin-top:8px;font-size:11px;white-space:pre-wrap;max-height:140px;overflow:auto;background:var(--bg);padding:8px;border-radius:4px" role="status" aria-live="polite">{{ finiteText(msg) }}</pre>
        </template>
      </div>
    </div>

    <div v-if="jobLog" class="tile" style="margin-top:10px">
      <div class="row"><strong style="font-size:12px">{{ t('docker.job_log') }}</strong><button class="tiny" @click="closeJobLog">{{ t('common.close') }}</button></div>
      <pre v-if="jobLog" class="log" style="max-height:180px;margin-top:6px" role="log" aria-live="polite">{{ finiteText(jobLog) }}</pre>
    </div>

    <!-- create modal -->
    <div ref="createPanel" v-if="showCreate" class="modal-bg" @click.self="showCreate=false" role="presentation">
      <div class="modal" role="dialog" aria-modal="true" aria-labelledby="compose-create-title">
        <div class="row" style="margin-bottom:10px">
          <span id="compose-create-title" class="name">{{ t('compose.create_title') }}</span>
          <button class="tiny" @click="showCreate=false">{{ t('common.close') }}</button>
        </div>
        <div class="kv" style="margin-bottom:10px">
          <div class="k">ID</div>
          <input v-model="newId" type="text" placeholder="my-app" :aria-label="t('compose.stack_id')"/>
          <div class="k">{{ t('common.name') }}</div>
          <input v-model="newName" type="text" placeholder="My App" :aria-label="t('common.name')"/>
        </div>
        <textarea
          v-model="newContent"
          spellcheck="false"
          style="width:100%;min-height:220px;font-family:ui-monospace,Menlo,monospace;font-size:12px;padding:10px;border:1px solid var(--line);border-radius:4px;background:var(--bg);color:var(--txt)" :aria-label="t('compose.stack_content')"></textarea>
        <div class="btns" style="margin-top:10px">
          <button class="primary" :disabled="busy" @click="create">{{ t('compose.create_save') }}</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { inject, onMounted, onUnmounted, ref } from 'vue'
import {
  createCompose,
  getCompose,
  getStackJob,
  getStacks,
  putCompose,
  runStack,
  validateCompose,
} from '../api/client'
import { injectI18n } from '../i18n'
import { finiteText } from '../lib/finite'
import { useDismissable } from '../composables/useDismissable'
import SkeletonLoader from '../components/SkeletonLoader.vue'
import LoadFailure from '../components/LoadFailure.vue'

const toast = inject('toast')
const { t } = injectI18n()
const stacks = ref([])
const loaded = ref(false)
const loadError = ref('')
const selected = ref(null)
const compose = ref(null)
const editor = ref('')
const busy = ref(false)
const msg = ref('')
const jobLog = ref('')
const showCreate = ref(false)
const createPanel = ref(null)
const newId = ref('')
const newName = ref('')
const newContent = ref(`services:
  app:
    image: nginx:alpine
    container_name: my-app
    restart: unless-stopped
    ports:
      - "8088:80"
`)
let jobTimer = null
let jobPollGeneration = 0
let pageAlive = true
let stacksGeneration = 0
let composeGeneration = 0

function stopJobPolling() {
  jobPollGeneration += 1
  if (jobTimer) clearTimeout(jobTimer)
  jobTimer = null
  // run()/watchJob() now hold `busy` for the whole job, so releasing it here
  // covers the cancel path too. watchJob calls this first and then re-sets busy,
  // so the ordering is safe.
  busy.value = false
}

function closeJobLog() {
  stopJobPolling()
  jobLog.value = ''
}

async function loadStacks() {
  const generation = ++stacksGeneration
  try {
    const d = await getStacks()
    if (generation !== stacksGeneration || !pageAlive) return
    stacks.value = Array.isArray(d.stacks) ? d.stacks : []
    loadError.value = ''
  } catch (e) {
    if (generation !== stacksGeneration || !pageAlive) return
    loadError.value = e.message || String(e)
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (generation === stacksGeneration) loaded.value = true
  }
}

async function select(s) {
  selected.value = s.id
  await reloadCompose()
}

async function reloadCompose() {
  if (!selected.value) return
  const id = selected.value
  const generation = ++composeGeneration
  busy.value = true
  try {
    const j = await getCompose(id)
    if (generation !== composeGeneration || !pageAlive || selected.value !== id) return
    compose.value = j
    editor.value = j.content
    msg.value = ''
  } catch (e) {
    if (generation !== composeGeneration || !pageAlive || selected.value !== id) return
    compose.value = null
    editor.value = ''
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (generation === composeGeneration) busy.value = false
  }
}

async function save() {
  const id = selected.value
  if (!id) return
  const generation = composeGeneration
  busy.value = true
  try {
    const j = await putCompose(id, editor.value, true)
    if (generation !== composeGeneration || !pageAlive) return
    toast('✅ ' + t('compose.saved'))
    const backup = finiteText(j.backup, '')
    msg.value = (finiteText(j.message, '') || '') + (backup ? `\n${t('compose.backup')}: ${backup}` : '')
  } catch (e) {
    if (generation !== composeGeneration || !pageAlive) return
    toast('❌ ' + finiteText(e.message))
    msg.value = finiteText(e.message, '')
  } finally {
    if (generation === composeGeneration) busy.value = false
  }
}

async function validate() {
  const generation = composeGeneration
  busy.value = true
  try {
    const j = await validateCompose(editor.value, compose.value?.path)
    if (generation !== composeGeneration || !pageAlive) return
    msg.value = (j.ok ? `✅ ${t('compose.valid_ok')}\n` : `❌ ${t('compose.valid_fail')}\n`) + finiteText(j.message, '')
    toast(j.ok ? '✅ ' + t('compose.valid_toast_ok') : '❌ ' + t('compose.valid_toast_fail'))
  } catch (e) {
    if (generation !== composeGeneration || !pageAlive) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (generation === composeGeneration) busy.value = false
  }
}

async function create() {
  if (!newId.value.trim()) return toast('❌ ' + t('compose.id_required'))
  const generation = stacksGeneration
  busy.value = true
  try {
    const j = await createCompose(newId.value.trim(), newName.value || newId.value, newContent.value)
    if (generation !== stacksGeneration || !pageAlive) return
    toast('✅ ' + t('compose.created', { id: finiteText(j.id) }))
    showCreate.value = false
    await loadStacks()
    if (!pageAlive) return
    selected.value = j.id
    await reloadCompose()
  } catch (e) {
    if (generation !== stacksGeneration || !pageAlive) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (pageAlive) busy.value = false
  }
}

async function run(s, action) {
  const id = s.id || selected.value
  if (!id || busy.value) return
  if (action === 'down' && !confirm(t('compose.confirm_down'))) return
  if (action === 'update' && !confirm(t('apps.confirm_update', { name: finiteText(s.name, '') || finiteText(id) }))) return
  const generation = stacksGeneration
  busy.value = true
  let holdBusy = false
  try {
    const r = await runStack(id, action)
    if (!pageAlive) return
    if (generation !== stacksGeneration) return
    toast('🚀 ' + (finiteText(r.message, '') || t('compose.started')))
    if (r.job_id) {
      // Stay busy until the job actually ends, not merely until the server
      // acknowledged it. runStack returns as soon as the job is queued, so
      // clearing busy here re-enabled Up/Update/Down while compose was still
      // running and let a second operation be issued against the same stack
      // mid-flight. watchJob clears it when the job reports not-running.
      watchJob(r.job_id)
      holdBusy = true
      return
    }
  } catch (e) {
    if (!pageAlive) return
    if (generation !== stacksGeneration) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    // loadStacks() (Refresh) bumps stacksGeneration; a generation match
    // would leave Up/Down stuck after a refresh during the run.
    if (pageAlive && !holdBusy) busy.value = false
  }
}

function watchJob(id) {
  stopJobPolling()
  jobLog.value = '…'
  busy.value = true
  const generation = jobPollGeneration

  const poll = async () => {
    jobTimer = null
    // Same visibility skip as Containers.vue: keep re-arming so the job is picked
    // up again on return, without polling the host from a hidden tab.
    if (typeof document !== 'undefined' && document.hidden) {
      if (generation === jobPollGeneration) jobTimer = setTimeout(poll, 1500)
      return
    }
    try {
      const j = await getStackJob(id)
      if (generation !== jobPollGeneration) return
      jobLog.value = finiteText(j.log, '')
      if (!j.running) {
        stopJobPolling()
        if (pageAlive) busy.value = false
        void loadStacks()
        return
      }
    } catch (e) {
      if (generation !== jobPollGeneration) return
      // Surface it rather than leaving jobLog frozen on '…' forever, which is
      // what a failed first poll looked like.
      jobLog.value = `${jobLog.value === '…' ? '' : finiteText(jobLog.value, '')}\n⚠ ${finiteText(e.message, '') || finiteText(e)}`.trim()
    }
    if (generation === jobPollGeneration) jobTimer = setTimeout(poll, 1500)
  }

  void poll()
}

onMounted(() => {
  pageAlive = true
  loadStacks()
})
onUnmounted(() => {
  pageAlive = false
  stacksGeneration += 1
  composeGeneration += 1
  stopJobPolling()
})


// Escape dismisses each dialog, focus returns to whatever opened it, and Tab
// cannot wander to the page behind the overlay.
useDismissable(showCreate, () => { showCreate.value = false }, createPanel)
</script>

<style scoped>
.compose-editor {
  width: 100%;
  min-height: 380px;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 12px;
  line-height: 1.5;
  padding: 12px 14px;
  border: 1px solid var(--line);
  border-radius: 6px;
  background: color-mix(in srgb, var(--header) 3%, var(--bg));
  color: var(--txt);
  resize: vertical;
  tab-size: 2;
  transition: border-color .15s, box-shadow .15s;
}
.compose-editor:focus {
  outline: none;
  border-color: var(--accent);
  box-shadow: 0 0 0 2px color-mix(in srgb, var(--accent) 15%, transparent);
}
.tile h3 .sub {
  display: block;
  text-transform: none;
  overflow-wrap: anywhere;
  word-break: break-word;
  margin-top: 4px;
}
@media (max-width: 640px) {
  .compose-editor { min-height: 220px; }
}
</style>
