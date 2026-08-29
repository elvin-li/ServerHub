<template>
  <div>
    <div class="page-title">
      <h1>{{ t('vms.title') }}</h1>
      <!-- role=status: the VM count and hypervisor availability marks are
           Refresh's (and the 15s poll's) only answer, and they changed
           silently for a screen reader — same treatment as the Users and
           Apps toolbar counts. -->
      <span class="meta" role="status">
        {{ t('vms.meta', { utm: data?.utm_available ? '✓' : '—', orb: data?.orb_available ? '✓' : '—', n: finiteN(asArray(vms).length) }) }}
      </span>
    </div>

    <div class="toolbar">
      <button class="primary" @click="refresh" :disabled="busy">{{ t('common.refresh') }}</button>
      <button v-if="data?.orb_available" @click="showCreate=true">{{ t('vms.create_orb') }}</button>
      <span class="meta" style="color:var(--sub)">
        {{ t('vms.hint') }}
      </span>
    </div>

    <div v-if="msg" class="tile" style="margin-bottom:10px">
      <pre class="log-pre" role="status" aria-live="polite">{{ finiteText(msg) }}</pre>
    </div>

    <LoadFailure v-if="loadError" :detail="loadError" :retry="refresh" :busy="busy" />
    <SkeletonLoader v-if="!loaded" variant="cards" :rows="4" />

    <div v-else-if="!asArray(vms).length && !loadError" class="placeholder">
      {{ t('vms.empty') }}
      <span v-if="!data?.utm_available">{{ t('vms.no_utm') }}</span>
      <span v-if="!data?.orb_available">{{ t('vms.no_orb') }}</span>
    </div>

    <div v-else class="vm-grid">
      <div v-for="v in asArray(vms)" :key="finiteText(asRecord(v).id)" class="vm-card" :class="{ stopped: asRecord(v).state === 'stopped' }">
        <div class="vm-head">
          <span class="led" :class="led(asRecord(v).state)" aria-hidden="true"></span>
          <div class="vm-titles">
            <div class="vm-name">{{ finiteText(asRecord(v).name) }}</div>
            <div class="vm-sub mono">{{ finiteText(asRecord(v).backend) }} · {{ finiteText(asRecord(v).status) }} · {{ stateLabel(asRecord(v).state) }}</div>
          </div>
          <span class="badge" :class="stateBadge(asRecord(v).state)">{{ finiteText(asRecord(v).backend) }}</span>
        </div>
        <div class="vm-detail">{{ finiteText(asRecord(v).detail) }}</div>
        <div v-if="asArray(asRecord(v).ips).length" class="mono" style="font-size:11px;margin-bottom:6px">
          IP: {{ asArray(asRecord(v).ips).map(ip => finiteText(ip, '')).filter(Boolean).join(', ') }}
        </div>
        <div v-if="asRecord(v).backend === 'orb'" class="console-note">
          {{ t('vms.console_unavailable_orbstack') }}
        </div>
        <div class="btns">
          <a v-if="webUrl(v)" class="btn tiny primary" :href="finiteText(webUrl(v), '')" target="_blank" rel="noopener">WebUI</a>
          <button
            v-if="hasWebConsole(v)"
            class="tiny primary"
            type="button"
            :disabled="busy"
            @click="consoleTarget=asRecord(v)"
          >{{ t('vms.console') }}</button>
          <button
            v-for="a in asArray(displayActions(v))"
            :key="finiteText(a)"
            class="tiny"
            :class="{ primary: a==='start'||a==='restart', danger: a==='delete'||a==='kill' }"
            :disabled="busy"
            @click="act(v, a)"
          >{{ finiteText(asRecord(labels)[a], '') || finiteText(a) }}</button>
        </div>
      </div>
    </div>

    <VncConsole v-if="consoleTarget" :vm="consoleTarget" @close="consoleTarget=null" />

    <!-- Create Orb machine -->
    <div v-if="showCreate" class="modal-bg" @click.self="showCreate=false" role="presentation">
      <div
        class="modal"
        style="max-width:460px"
        role="dialog"
        aria-modal="true"
        aria-labelledby="vm-create-title"
        ref="createPanel"
      >
        <div class="row" style="margin-bottom:12px">
          <span id="vm-create-title" class="name">{{ t('vms.create_title') }}</span>
          <button class="tiny" @click="showCreate=false">{{ t('common.close') }}</button>
        </div>
        <div class="field-grid">
          <label for="vm-create-distro">{{ t('vms.distro') }}</label>
          <select id="vm-create-distro" v-model="createForm.distro" :aria-label="t('vms.distro')">
            <option v-for="d in (asArray(data?.orb_distros).length ? asArray(data.orb_distros) : asArray(distros))" :key="finiteText(d)" :value="d">{{ finiteText(d) }}</option>
          </select>
          <!-- No aria-label here: it overrode the for/id labels with the
               placeholder, so "Version" was announced as its example value. -->
          <label for="vm-create-version">{{ t('vms.version') }}</label>
          <input id="vm-create-version" v-model="createForm.version" type="text" :placeholder="t('vms.version_ph')" />
          <label for="vm-create-name">{{ t('vms.machine') }}</label>
          <input id="vm-create-name" v-model="createForm.name" type="text" :placeholder="t('vms.machine_ph')" />
        </div>
        <p style="font-size:11px;color:var(--sub);margin:10px 0">
          {{ t('vms.create_hint') }}
        </p>
        <div class="btns">
          <button class="primary" :disabled="busy" @click="doCreate">{{ t('vms.create') }}</button>
          <button @click="showCreate=false">{{ t('common.cancel') }}</button>
        </div>
      </div>
    </div>

    <!-- Clone dialog -->
    <div v-if="cloneTarget" class="modal-bg" @click.self="cloneTarget=null" role="presentation">
      <div
        class="modal"
        style="max-width:400px"
        role="dialog"
        aria-modal="true"
        aria-labelledby="vm-clone-title"
        ref="clonePanel"
      >
        <div class="row" style="margin-bottom:12px">
          <span id="vm-clone-title" class="name">{{ t('vms.clone') }} · {{ finiteText(asRecord(cloneTarget).name) }}</span>
          <button class="tiny" @click="cloneTarget=null">{{ t('common.close') }}</button>
        </div>
        <label for="vm-clone-name" style="font-size:12px;color:var(--sub)">{{ t('vms.new_name') }}</label>
        <input id="vm-clone-name" v-model="cloneName" type="text" style="width:100%;margin:8px 0 12px" :aria-label="t('vms.new_name')" />
        <div class="btns">
          <button class="primary" :disabled="busy || !cloneName.trim()" @click="doClone">{{ t('vms.clone') }}</button>
          <button @click="cloneTarget=null">{{ t('common.cancel') }}</button>
        </div>
      </div>
    </div>

    <!-- Rename dialog (display name via overrides) -->
    <div v-if="renameTarget" class="modal-bg" @click.self="renameTarget=null" role="presentation">
      <div
        class="modal"
        style="max-width:400px"
        role="dialog"
        aria-modal="true"
        aria-labelledby="vm-rename-title"
        ref="renamePanel"
      >
        <div class="row" style="margin-bottom:12px">
          <span id="vm-rename-title" class="name">{{ t('vms.rename') }} · {{ finiteText(asRecord(renameTarget).id) }}</span>
          <button class="tiny" @click="renameTarget=null">{{ t('common.close') }}</button>
        </div>
        <label for="vm-rename-name" style="font-size:12px;color:var(--sub)">{{ t('vms.display_name') }}</label>
        <input id="vm-rename-name" v-model="renameName" type="text" style="width:100%;margin:8px 0 12px" @keyup.enter="doRename" :aria-label="t('vms.display_name')" />
        <p style="font-size:11px;color:var(--sub);margin:0 0 10px">{{ t('vms.rename_hint') }}</p>
        <div class="btns">
          <button class="primary" :disabled="busy || !renameName.trim()" @click="doRename">{{ t('common.confirm') }}</button>
          <button @click="renameTarget=null">{{ t('common.cancel') }}</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, inject, onMounted, onUnmounted, ref } from 'vue'
import VncConsole from '../components/VncConsole.vue'
import { createVm, getVms, vmAction } from '../api/client'
import { startVisibleInterval } from '../lib/poll'
import { injectI18n } from '../i18n'
import { asArray, asRecord, finiteN, finiteText } from '../lib/finite'
import { useDismissable } from '../composables/useDismissable'
import SkeletonLoader from '../components/SkeletonLoader.vue'
import LoadFailure from '../components/LoadFailure.vue'

const toast = inject('toast')
const { t } = injectI18n()
const data = ref(null)
// The empty placeholder also volunteers "UTM not installed" / "OrbStack not
// installed", which is an alarming thing to assert before the probe has run.
const loaded = ref(false)
const loadError = ref('')
const busy = ref(false)
const msg = ref('')
const showCreate = ref(false)
const cloneTarget = ref(null)
const cloneName = ref('')
const renameTarget = ref(null)
const renameName = ref('')
const consoleTarget = ref(null)
const createForm = ref({ distro: 'ubuntu', version: '', name: '' })
const createPanel = ref(null)
const clonePanel = ref(null)
const renamePanel = ref(null)
const distros = ['ubuntu', 'debian', 'fedora', 'arch', 'alpine', 'rocky']
let timer = null
const refreshTimers = new Set()

function scheduleRefresh(delay) {
  const generation = loadGeneration
  const id = setTimeout(() => {
    refreshTimers.delete(id)
    if (generation !== loadGeneration || !pageAlive) return
    void refresh()
  }, delay)
  refreshTimers.add(id)
}

const labels = computed(() => ({
  start: t('vms.start'), stop: t('vms.stop'), restart: t('vms.restart'), suspend: t('vms.suspend'),
  delete: t('vms.delete'), clone: t('vms.clone'), ip: t('vms.ip'), shell: t('vms.shell'),
  rename: t('vms.rename'), kill: t('vms.kill'),
}))

const vms = computed(() => asArray(asRecord(data.value).vms).map((row) => asRecord(row)))

function led(state) {
  if (state === 'ok') return 'on'
  if (state === 'warn') return 'warn'
  if (state === 'stopped') return 'off'
  return 'err'
}
function stateLabel(state) {
  if (state === 'ok') return t('common.running')
  if (state === 'warn') return t('common.warn')
  if (state === 'stopped') return t('common.stopped')
  return t('common.error')
}
function stateBadge(state) {
  if (state === 'ok') return 'ok'
  if (state === 'warn') return 'warn'
  if (state === 'stopped') return 'stopped'
  return 'down'
}
function displayActions(v) {
  const row = asRecord(v)
  return asArray(row.actions).filter(a => a !== 'shell' || row.backend === 'orb')
}
function hasWebConsole(v) {
  const row = asRecord(v)
  return row.backend !== 'orb' && asRecord(row.console).available === true && Boolean(row.console_id)
}

/**
 * Resolve a VM WebUI URL. services.yaml stores local URLs with a {host}
 * placeholder (see hub/host_address.py) and /api/vms returns them unexpanded,
 * so substitute the host we are browsing — same rule Apps.vue uses.
 * Returns '' when the URL is missing or still unresolved, so the button hides.
 */
function webUrl(v) {
  const raw = finiteText(asRecord(v).url, '').trim()
  if (!raw) return ''
  const host = finiteText(window.location.hostname, '') || finiteText(data.value?.host_ip, '') || 'localhost'
  const out = raw
    .replaceAll('${host}', host)
    .replaceAll('{host}', host)
    .replaceAll('{{HOST_IP}}', host)
    .replaceAll('{{HOST}}', host)
  return /\{[A-Za-z]/.test(out) ? '' : finiteText(out, '')
}

function requireOk(result) {
  if (result?.ok === false) throw new Error(result.message || t('err.request_failed'))
  return result
}

let pageAlive = true
let loadGeneration = 0

async function refresh(manual = false) {
  const generation = ++loadGeneration
  try {
    const next = await getVms()
    if (generation !== loadGeneration || !pageAlive) return
    const row = asRecord(next)
    data.value = {
      ...row,
      vms: asArray(row.vms).map((item) => asRecord(item)),
      orb_distros: asArray(row.orb_distros),
    }
    loadError.value = ''
  } catch (e) {
    if (generation !== loadGeneration || !pageAlive) return false
    loadError.value = e.message || String(e)
    // Background 15s ticks stay silent: LoadFailure already marks the state on
    // screen, and re-toasting every interval while the panel is down is noise.
    // The retry button passes its click event as `manual`, so it still toasts.
    if (manual) toast('❌ ' + finiteText(e.message))
    // Failed tick → lib/poll.js backoff while the server stays unreachable.
    return false
  } finally {
    if (generation === loadGeneration) loaded.value = true
  }
}

async function act(v, action) {
  const row = asRecord(v)
  if (action === 'clone') {
    cloneTarget.value = row
    cloneName.value = finiteText(row.name, '') + '-copy'
    return
  }
  if (action === 'rename') {
    renameTarget.value = row
    renameName.value = finiteText(row.name, '')
    return
  }
  if (action === 'delete' && !confirm(t('vms.confirm_delete', { name: finiteText(row.name) }))) return
  if (action === 'stop' && !confirm(t('vms.confirm_stop', { name: finiteText(row.name) }))) return
  if (action === 'kill' && !confirm(t('vms.confirm_kill', { name: finiteText(row.name) }))) return
  // force:true is sent for every action except stop (see the vmAction call below),
  // so restart and suspend are hard operations on every backend -- not just UTM.
  // Gating the confirmation on backend === 'utm' let an orb restart/suspend go out
  // forcibly on a single click.
  if (action === 'restart' && !confirm(t('vms.confirm_restart_force', { name: finiteText(row.name) }))) return
  if (action === 'suspend' && !confirm(t('vms.confirm_restart_force', { name: finiteText(row.name) }))) return
  if (action === 'shell') {
    try {
      const j = requireOk(await vmAction(row.id, { action: 'shell' }))
      if (!pageAlive) return
      const out = asRecord(j)
      msg.value = finiteText(out.message, '') || finiteText(out.command, '')
      toast('✅ ' + t('vms.shell_below'))
    } catch (e) {
      if (!pageAlive) return
      toast('❌ ' + finiteText(e.message))
    }
    return
  }
  const generation = loadGeneration
  busy.value = true
  msg.value = t('vms.working')
  try {
    const j = requireOk(await vmAction(row.id, { action, force: action !== 'stop' }))
    if (generation !== loadGeneration || !pageAlive) return
    const out = asRecord(j)
    msg.value = finiteText(out.message, '')
    if (out.ips) msg.value = t('vms.ip_result', { ips: asArray(out.ips).map(ip => finiteText(ip, '')).filter(Boolean).join(', ') })
    toast(`✅ ${asRecord(labels.value)[action] || action}`)
    scheduleRefresh(action === 'restart' ? 3000 : 1000)
  } catch (e) {
    if (generation !== loadGeneration || !pageAlive) return
    toast('❌ ' + finiteText(e.message))
    msg.value = e.message
  } finally {
    // The 15s poll's refresh() bumps loadGeneration while an action is in flight.
    if (pageAlive) busy.value = false
  }
}

async function doClone() {
  const target = asRecord(cloneTarget.value)
  if (!target.id || !cloneName.value.trim()) return
  const generation = loadGeneration
  busy.value = true
  try {
    const j = requireOk(await vmAction(target.id, {
      action: 'clone',
      name: cloneName.value.trim(),
    }))
    if (generation !== loadGeneration || !pageAlive) return
    toast('✅ ' + t('vms.cloned'))
    msg.value = finiteText(asRecord(j).message, '')
    cloneTarget.value = null
    scheduleRefresh(1500)
  } catch (e) {
    if (generation !== loadGeneration || !pageAlive) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (pageAlive) busy.value = false
  }
}

async function doRename() {
  const target = asRecord(renameTarget.value)
  if (!target.id || !renameName.value.trim()) return
  const generation = loadGeneration
  busy.value = true
  try {
    const j = requireOk(await vmAction(target.id, {
      action: 'rename',
      name: renameName.value.trim(),
    }))
    if (generation !== loadGeneration || !pageAlive) return
    toast('✅ ' + (finiteText(asRecord(j).message, '') || t('vms.renamed')))
    renameTarget.value = null
    await refresh()
  } catch (e) {
    if (generation !== loadGeneration || !pageAlive) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (pageAlive) busy.value = false
  }
}

async function doCreate() {
  const generation = loadGeneration
  busy.value = true
  msg.value = t('vms.creating')
  try {
    let distro = createForm.value.distro
    if (createForm.value.version.trim()) {
      distro = `${distro}:${createForm.value.version.trim()}`
    }
    const j = requireOk(await createVm({
      distro,
      name: createForm.value.name.trim() || null,
    }))
    if (generation !== loadGeneration || !pageAlive) return
    toast('✅ ' + t('vms.created'))
    msg.value = finiteText(j.message, '')
    showCreate.value = false
    scheduleRefresh(2000)
  } catch (e) {
    if (generation !== loadGeneration || !pageAlive) return
    toast('❌ ' + finiteText(e.message))
    msg.value = e.message
  } finally {
    if (pageAlive) busy.value = false
  }
}

onMounted(() => {
  pageAlive = true
  refresh()
  timer = startVisibleInterval(refresh, 15000)
})
onUnmounted(() => {
  pageAlive = false
  loadGeneration += 1
  consoleTarget.value = null
  if (typeof timer === 'function') timer()
  timer = null
  for (const id of refreshTimers) clearTimeout(id)
  refreshTimers.clear()
})

// Each dialog owes the same keyboard contract: Escape dismisses it, focus moves
// in on open and returns to the trigger on close, and Tab stays inside the box.
useDismissable(showCreate, () => { showCreate.value = false }, createPanel)
useDismissable(cloneTarget, () => { cloneTarget.value = null }, clonePanel)
useDismissable(renameTarget, () => { renameTarget.value = null }, renamePanel)
</script>

<style scoped>
.vm-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(min(100%, 290px), 1fr));
  gap: 10px;
}
.vm-card {
  background: var(--card);
  border: 1px solid var(--line);
  border-radius: var(--radius);
  padding: 14px 16px;
  box-shadow: var(--card-shadow);
  transition: border-color .15s, transform .1s;
}
.vm-card:hover { border-color: color-mix(in srgb, var(--accent) 35%, var(--line)); transform: translateY(-1px); }
.vm-card.stopped {
  border-color: color-mix(in srgb, #888 30%, var(--line));
  opacity: 0.88;
}
.vm-card.stopped .vm-name { color: var(--sub); }
.vm-head {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 8px;
  flex-wrap: wrap;
}
.vm-titles { flex: 1; min-width: 0; }
.vm-name { font-weight: 700; font-size: 14px; overflow-wrap: anywhere; }
.vm-sub { font-size: 11px; color: var(--sub); margin-top: 2px; overflow-wrap: anywhere; }
.vm-detail { font-size: 12px; color: var(--sub); margin-bottom: 8px; }
.console-note { color: var(--sub); font-size: 11px; margin: 0 0 8px; }
.log-pre {
  font-size: 11px; white-space: pre-wrap; max-height: 120px; overflow: auto;
  margin: 0; font-family: ui-monospace, Menlo, monospace;
}
/* Layout comes from the global .field-grid. */
.field-grid { --field-label-w: 110px; }
</style>
