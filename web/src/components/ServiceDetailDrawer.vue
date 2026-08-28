<!--
  Detail drawer for one service: identity badges, info KV, mounts/env,
  the adopt form (auto-discovered listeners), the managed-script editor,
  the admin override editor, and the inline logs section.

  The drawer owns only its form models; every mutation is emitted so the
  parent keeps the single busy flag, the confirm prompts and the list refresh:
    close          — dismiss the drawer
    act(action)    — run a control action on this service
    load-logs      — (re)load the inline logs section
    adopt(body)    — write the adopt payload to services.yaml
    save-script(body) — rewrite the services.yaml scripts entry
    forget         — drop the managed scripts entry (parent confirms)
    save-override(body) — save the display override
    hide           — hide the service from the list
    uninstall      — open the uninstall confirmation (launch agents only)

  Logs stay a prop rather than local state: the parent clears them when a
  *different* service opens but keeps them across the silent re-read that
  follows an action, and only it knows which of the two just happened.
-->
<template>
  <div class="drawer-bg" @click.self="emit('close')" role="presentation">
    <aside ref="panel" class="drawer svc-drawer" role="dialog" aria-modal="true" aria-labelledby="svc-detail-title" tabindex="-1">
      <div class="drawer-head">
        <div>
          <h2 id="svc-detail-title" class="drawer-title">{{ finiteText(service.name) }}</h2>
          <div class="app-badges" style="margin-top:6px">
            <span class="chip">{{ kindLabel(service.kind) }}</span>
            <span class="chip" :class="stateChipClass(service.state)">{{ stateLabel(service.state) }}</span>
            <span v-if="service.auto" class="chip chip-muted">auto</span>
            <span v-if="sig" class="chip chip-sig" :title="sig.confidence === 'high' ? finiteText(sig.name) : `${finiteText(sig.name)}?`">
              {{ sig.confidence === 'high' ? finiteText(sig.name) : `${finiteText(sig.name)}?` }}
            </span>
          </div>
          <div class="mono sub-id">{{ finiteText(service.id) }}</div>
        </div>
        <button type="button" @click="emit('close')">{{ t('common.close') }}</button>
      </div>

      <ServiceActions :service="service" :busy="busy" variant="drawer" @act="emit('act', $event)" @logs="emit('load-logs')">
        <button v-if="canManage" type="button" class="danger" :disabled="busy" @click="emit('hide')">{{ t('services.hide') }}</button>
        <button v-if="canUninstall" type="button" class="danger" :disabled="busy" @click="emit('uninstall')">{{ t('services.uninstall') }}</button>
      </ServiceActions>

      <section class="drawer-sec">
        <h3>{{ t('services.sec_info') }}</h3>
        <div class="kv">
          <div class="k">{{ t('services.detail') }}</div><div>{{ finiteText(service.detail) }}</div>
          <div class="k">{{ t('services.group') }}</div><div>{{ finiteText(service.group) }}</div>
          <div class="k">URL</div><div class="mono">{{ finiteText(service.url) }}</div>
          <div class="k">{{ t('services.port') }}</div><div class="mono">{{ portOf(service) }}</div>
          <div v-if="service.image" class="k">Image</div><div v-if="service.image" class="mono">{{ finiteText(service.image) }}</div>
          <div v-if="service.restart_policy" class="k">Restart</div><div v-if="service.restart_policy">{{ finiteText(service.restart_policy) }}</div>
          <div v-if="service.compose_project" class="k">Compose</div><div v-if="service.compose_project" class="mono">{{ finiteText(service.compose_project) }} / {{ finiteText(service.compose_service) }}</div>
          <div v-if="service.plist" class="k">plist</div><div v-if="service.plist" class="mono break">{{ finiteText(service.plist) }}</div>
          <div v-if="service.program" class="k">Program</div><div v-if="service.program" class="mono break">{{ finiteText(service.program) }}</div>
          <div v-if="service.run_at_load != null" class="k">RunAtLoad</div><div v-if="service.run_at_load != null">{{ service.run_at_load ? t('common.yes') : t('common.no') }}</div>
          <div v-if="service.start_cmd" class="k">start</div><div v-if="service.start_cmd" class="mono break">{{ finiteText(service.start_cmd) }}</div>
          <div v-if="service.stop_cmd" class="k">stop</div><div v-if="service.stop_cmd" class="mono break">{{ finiteText(service.stop_cmd) }}</div>
        </div>
        <div v-if="(service.ports || []).length" class="ports-list mono">
          <div v-for="(p, i) in service.ports" :key="i">{{ finiteText(typeof p === 'object' ? JSON.stringify(p) : p) }}</div>
        </div>
        <div v-if="(service.links || []).length" class="quick-links" style="margin-top:8px">
          <a v-for="l in service.links" :key="l.url" class="btn tiny" :href="finiteText(l.url, '')" target="_blank" rel="noopener">{{ finiteText(l.name) }}</a>
        </div>
      </section>

      <section class="drawer-sec" v-if="(service.mounts || []).length">
        <h3>{{ t('services.sec_mounts') }}</h3>
        <ul class="plain-list mono">
          <li v-for="(m, i) in service.mounts.slice(0, 12)" :key="i">{{ finiteText(m.source) }} → {{ finiteText(m.destination) }} {{ m.rw === false ? '(ro)' : '' }}</li>
        </ul>
      </section>

      <section class="drawer-sec" v-if="asArray(service.env_sample).length">
        <h3>{{ t('services.sec_env') }}</h3>
        <pre class="log mini-log">{{ asArray(service.env_sample).map(n => finiteText(n, '')).filter(Boolean).join('\n') }}</pre>
      </section>

      <section class="drawer-sec" v-if="service.launchctl">
        <h3>launchctl</h3>
        <pre class="log mini-log">{{ finiteText(service.launchctl) }}</pre>
      </section>

      <!-- Adopt auto-discovered listener into services.yaml -->
      <section class="drawer-sec" v-if="service.can_adopt">
        <h3>{{ t('services.sec_adopt') }}</h3>
        <p class="hint-line">{{ t('services.adopt_hint') }}</p>
        <div v-if="sig" class="hint-line">
          {{ t('services.identified_as', {
            name: finiteText(sig.name),
            category: finiteText(sig.category),
          }) }}
          <span v-if="sig.confidence !== 'high'">({{ t('services.identified_guess') }})</span>
        </div>
        <div v-if="adoptForm.control_via === 'brew'" class="hint-line">
          {{ t('services.adopt_control_brew', { formula: finiteText(adoptForm.formula) }) }}
        </div>
        <div v-else class="hint-line">{{ t('services.adopt_control_none') }}</div>
        <div class="form-grid adopt-form">
          <label>{{ t('common.name') }}
            <input v-model="adoptForm.name" type="text" />
          </label>
          <label>{{ t('services.group') }}
            <input v-model="adoptForm.group" type="text" />
          </label>
          <label>URL
            <input v-model="adoptForm.url" type="text" placeholder="http://…" />
          </label>
          <label>{{ t('services.adopt_ports') }}
            <input v-model="adoptForm.ports" type="text" placeholder="8080, 8443" />
          </label>
          <label>{{ t('services.adopt_start') }}
            <input v-model="adoptForm.start" type="text" class="mono" placeholder="brew services start …" />
          </label>
          <label>{{ t('services.adopt_stop') }}
            <input v-model="adoptForm.stop" type="text" class="mono" placeholder="brew services stop …" />
          </label>
        </div>
        <label class="chk-line">
          <input v-model="adoptForm.remember" type="checkbox" />
          {{ t('services.adopt_remember') }}
        </label>
        <p class="hint-line">{{ t('services.adopt_remember_hint') }}</p>
        <div class="mono sub-id" style="margin-top:4px">id: {{ finiteText(adoptForm.id) }}</div>
        <div class="drawer-actions" style="margin-top:8px">
          <button type="button" class="primary" :disabled="busy" @click="submitAdopt">{{ t('services.adopt') }}</button>
        </div>
      </section>

      <!-- Rewrite the services.yaml scripts entry (adopted or hand-written) -->
      <section class="drawer-sec" v-if="canManage && service.can_edit_script">
        <h3>{{ t('services.sec_script') }}</h3>
        <p class="hint-line">{{ t('services.script_hint') }}</p>
        <div class="form-grid script-form">
          <label>{{ t('common.name') }}
            <input v-model="scriptForm.name" type="text" />
          </label>
          <label>{{ t('services.group') }}
            <input v-model="scriptForm.group" type="text" />
          </label>
          <label>URL
            <input v-model="scriptForm.url" type="text" placeholder="http://…" />
          </label>
          <label>{{ t('services.adopt_ports') }}
            <input v-model="scriptForm.ports" type="text" placeholder="8080, 8443" />
          </label>
          <label>{{ t('services.adopt_start') }}
            <input v-model="scriptForm.start" type="text" class="mono" placeholder="brew services start …" />
          </label>
          <label>{{ t('services.adopt_stop') }}
            <input v-model="scriptForm.stop" type="text" class="mono" placeholder="brew services stop …" />
          </label>
        </div>
        <div class="drawer-actions" style="margin-top:8px">
          <button type="button" class="primary" :disabled="busy" @click="submitScript">{{ t('common.save') }}</button>
          <button v-if="service.can_forget" type="button" class="danger" :disabled="busy" @click="emit('forget')">{{ t('services.forget') }}</button>
        </div>
      </section>

      <!-- Edit override (writes services.yaml — administrators only) -->
      <section class="drawer-sec" v-if="canManage">
        <h3>{{ t('services.sec_override') }}</h3>
        <p class="hint-line">{{ t('services.override_hint') }}</p>
        <div class="form-grid">
          <label>{{ t('common.name') }}
            <input v-model="editForm.name" type="text" />
          </label>
          <label>{{ t('services.group') }}
            <input v-model="editForm.group" type="text" />
          </label>
          <label>URL
            <input v-model="editForm.url" type="text" placeholder="http://…" />
          </label>
          <label>{{ t('services.port') }}
            <input v-model.number="editForm.port" type="number" min="1" max="65535" />
          </label>
        </div>
        <div class="drawer-actions" style="margin-top:8px">
          <button type="button" class="primary" :disabled="busy" @click="submitOverride">{{ t('common.save') }}</button>
          <button type="button" :disabled="busy" @click="resetForms">{{ t('common.cancel') }}</button>
        </div>
      </section>

      <!-- Logs in drawer -->
      <section class="drawer-sec" v-if="log !== null">
        <h3>{{ t('services.logs') }} <span class="meta-count mono">{{ finiteText(logSource) }}</span></h3>
        <div class="drawer-actions" style="margin-bottom:6px">
          <button type="button" class="tiny" @click="emit('load-logs')">{{ t('common.refresh') }}</button>
          <button type="button" class="tiny" @click="copyLog">{{ t('services.copy_log') }}</button>
        </div>
        <!-- Scrollable, so keyboard-reachable (same as ServiceLogsModal). -->
        <pre class="log" tabindex="0" role="region" :aria-label="t('services.logs')">{{ finiteText(log, '') || t('services.log_empty') }}</pre>
      </section>
    </aside>
  </div>
</template>

<script setup>
import { computed, inject, onUnmounted, reactive, ref, watch } from 'vue'
import { injectI18n } from '../i18n'
import { copyToClipboard } from '../lib/clipboard'
import { useDismissable } from '../composables/useDismissable'
import { asArray, finiteText } from '../lib/finite'
import { portOf, serviceLabels, signatureOf, stateChipClass } from '../lib/serviceActions'
import ServiceActions from './ServiceActions.vue'

const toast = inject('toast')
const { t } = injectI18n()
const { kindLabel, stateLabel } = serviceLabels(t)

const props = defineProps({
  /** Detail payload from /api/services/{id}/detail (or the list row on 404). */
  service: { type: Object, required: true },
  /** Disables mutating controls while the parent runs an operation. */
  busy: { type: Boolean, default: false },
  /** Admin session: shows the override editor and the hide button. */
  canManage: { type: Boolean, default: false },
  /** Uninstall offer, decided by the parent (launch agents only). */
  canUninstall: { type: Boolean, default: false },
  /** Inline log text; null keeps the whole section hidden. */
  log: { type: String, default: null },
  /** Where the log text came from, shown next to the heading. */
  logSource: { type: String, default: '' },
})

const emit = defineEmits(['close', 'act', 'load-logs', 'adopt', 'save-script', 'forget', 'save-override', 'hide', 'uninstall'])

const panel = ref(null)
const editForm = reactive({ name: '', group: '', url: '', port: null })
const adoptForm = reactive({
  id: '', name: '', group: '', url: '', ports: '',
  start: '', stop: '', control_via: '', formula: '', remember: false,
})
const scriptForm = reactive({
  name: '', group: '', url: '', ports: '', start: '', stop: '',
})
const sig = computed(() => signatureOf(props.service))

function parsePorts(raw) {
  return String(raw || '')
    .split(/[\s,]+/)
    .map((p) => parseInt(p, 10))
    .filter((p) => Number.isInteger(p) && p >= 1 && p <= 65535)
}

function resetForms() {
  const d = props.service || {}
  const ov = d.override || {}
  editForm.name = ov.name != null ? ov.name : (d.name || '')
  editForm.group = ov.group != null ? ov.group : (d.group || '')
  editForm.url = ov.url != null ? ov.url : (d.url || '')
  editForm.port = ov.port != null ? ov.port : (d.port ?? null)
  const ad = d.adopt_defaults || {}
  adoptForm.id = ad.id || ''
  adoptForm.name = ad.name || ''
  adoptForm.group = ad.group || ''
  adoptForm.url = ad.url || ''
  adoptForm.ports = asArray(ad.ports).map((n) => finiteText(n, '')).filter(Boolean).join(', ')
  adoptForm.start = ad.start || ''
  adoptForm.stop = ad.stop || ''
  adoptForm.control_via = ad.control_via || ''
  adoptForm.formula = ad.formula || ''
  adoptForm.remember = Boolean(ad.remember)
  const sc = d.script_defaults || {}
  scriptForm.name = sc.name || d.name || ''
  scriptForm.group = sc.group || d.group || ''
  scriptForm.url = sc.url || d.url || ''
  scriptForm.ports = asArray(sc.ports).map((n) => finiteText(n, '')).filter(Boolean).join(', ')
  scriptForm.start = sc.start || ''
  scriptForm.stop = sc.stop || ''
}

let pageAlive = true

// Every detail (re-)read hands down a fresh object; the forms follow it.
watch(() => props.service, () => {
  if (!pageAlive) return
  resetForms()
}, { immediate: true })

function submitAdopt() {
  const ports = parsePorts(adoptForm.ports)
  emit('adopt', {
    id: adoptForm.id || null,
    name: adoptForm.name || null,
    group: adoptForm.group || null,
    url: adoptForm.url || null,
    ports: ports.length ? ports : null,
    start: adoptForm.start,
    stop: adoptForm.stop,
    remember: Boolean(adoptForm.remember),
  })
}

function submitScript() {
  const ports = parsePorts(scriptForm.ports)
  emit('save-script', {
    name: scriptForm.name || null,
    group: scriptForm.group || null,
    url: scriptForm.url || null,
    ports: ports.length ? ports : null,
    start: scriptForm.start,
    stop: scriptForm.stop,
  })
}

function submitOverride() {
  emit('save-override', {
    name: editForm.name || null,
    group: editForm.group || null,
    url: editForm.url || null,
    port: editForm.port || null,
  })
}

onUnmounted(() => { pageAlive = false })

async function copyLog() {
  const ok = await copyToClipboard(props.log)
  if (!pageAlive) return
  toast(ok ? '✅' : '❌')
}

// Escape dismisses, focus moves in on open and back to the trigger on close,
// and Tab cannot wander behind the overlay. Watching the service prop (not a
// constant) keeps the pre-extraction behaviour: every detail re-read hands
// down a fresh object and re-runs the open branch, which moves focus back to
// the drawer's first control.
useDismissable(() => props.service, () => emit('close'), panel)
</script>

<style scoped>
.svc-drawer { overflow: auto; width: min(640px, 100%); }
.drawer-head { display: flex; justify-content: space-between; gap: 12px; align-items: flex-start; margin-bottom: 14px; }
.drawer-title { margin: 0; font-size: 18px; font-weight: 700; }
.drawer-actions { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 14px; }
.drawer-sec { margin-bottom: 16px; padding-top: 10px; border-top: 1px solid var(--line); }
.drawer-sec h3 { margin: 0 0 8px; font-size: 11px; color: var(--sub); text-transform: uppercase; letter-spacing: .5px; font-weight: 700; }
.sub-id { font-size: 10px; color: var(--sub); margin-top: 2px; }
.meta-count { font-weight: 600; }
.hint-line { font-size: 12px; color: var(--sub); margin: 0 0 8px; }
.quick-links { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 12px; }
.form-grid {
  display: grid; grid-template-columns: 1fr 1fr; gap: 8px;
}
.form-grid label {
  display: flex; flex-direction: column; gap: 4px; font-size: 12px; color: var(--sub);
}
.form-grid input { width: 100%; }
.chk-line {
  display: flex; align-items: center; gap: 8px;
  font-size: 13px; color: var(--txt); margin: 10px 0 4px;
}
.break { word-break: break-all; }
.ports-list { font-size: 11px; color: var(--sub); margin-top: 6px; }
.plain-list { margin: 0; padding-left: 18px; font-size: 11px; }
.mini-log { max-height: 160px; }
.app-badges { display: flex; flex-wrap: wrap; gap: 4px; }
.chip {
  border: 1px solid var(--line); background: var(--card); color: var(--txt);
  border-radius: var(--radius-pill); padding: 4px 12px; font-size: 12px; cursor: pointer;
  font-weight: 500; transition: border-color .12s, box-shadow .12s;
}
.chip-ok { border-color: color-mix(in srgb, var(--ok) 50%, var(--line)); }
.chip-muted { opacity: .85; }
/* Ink, so the AA tint — raw --accent is 2.3-4.0:1 on --card in most themes. */
.chip-sig {
  border-color: color-mix(in srgb, var(--accent) 55%, var(--line)); color: var(--accent-text); font-weight: 600;
  display: inline-block; white-space: nowrap; overflow-wrap: normal; word-break: normal;
  max-width: 100%; overflow: hidden; text-overflow: ellipsis;
}

@media (max-width: 640px) {
  .form-grid { grid-template-columns: 1fr; }
}
</style>
