<template>
  <div class="modal-bg" @click.self="close" role="presentation">
    <section
      ref="panelEl"
      class="modal vnc-modal"
      role="dialog"
      aria-modal="true"
      :aria-label="t('vms.console_title', { name: finiteText(vm.name) })"
    >
      <header class="vnc-header">
        <div>
          <div class="name">{{ t('vms.console_title', { name: finiteText(vm.name) }) }}</div>
          <div class="vnc-meta">
            {{ t('vms.console_protocol', { protocol: finiteText(vm.console?.protocol, '') || 'VNC' }) }}
            <span v-if="sessionInfo">
              · {{ t('vms.console_session_limits', {
                expires: finiteSecs(sessionInfo.expires_in),
                max: finiteSecs(sessionInfo.max_session_seconds),
              }) }}
            </span>
          </div>
        </div>
        <button class="tiny" type="button" @click="close">{{ t('common.close') }}</button>
      </header>

      <div class="vnc-toolbar">
        <span class="vnc-status" aria-live="polite">
          <span class="status-dot" :class="status"></span>
          {{ finiteText(statusLabel) }}
        </span>
        <label class="vnc-option">
          <input v-model="autoScale" type="checkbox" />
          {{ t('vms.console_auto_scale') }}
        </label>
        <label class="vnc-option" :title="viewOnlyLocked ? t('vms.console_view_only_locked') : ''">
          <input v-model="viewOnly" type="checkbox" :disabled="viewOnlyLocked" />
          {{ t('vms.console_view_only') }}
        </label>
        <button
          class="tiny"
          type="button"
          :disabled="!connected || viewOnly"
          @click="sendCtrlAltDel"
        >{{ t('vms.console_ctrl_alt_del') }}</button>
        <button
          class="tiny"
          type="button"
          :disabled="!fullscreenSupported"
          @click="toggleFullscreen"
        >{{ isFullscreen ? t('vms.console_exit_fullscreen') : t('vms.console_fullscreen') }}</button>
        <button
          class="tiny danger"
          type="button"
          :disabled="!rfbClient"
          @click="disconnect"
        >{{ t('vms.console_disconnect') }}</button>
      </div>

      <div ref="screenEl" class="vnc-screen" tabindex="0"></div>
      <p v-if="errorMessage" class="vnc-error" role="alert">{{ finiteText(errorMessage) }}</p>
      <p class="vnc-policy">{{ t('vms.console_policy') }}</p>
    </section>
  </div>
</template>

<script setup>
import { computed, markRaw, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { createVmConsoleSession } from '../api/client'
import { injectI18n } from '../i18n'
import { finiteText } from '../lib/finite'
import { useDismissable } from '../composables/useDismissable'

const props = defineProps({
  vm: { type: Object, required: true },
})
const emit = defineEmits(['close'])
const { t } = injectI18n()

const panelEl = ref(null)
const screenEl = ref(null)
const status = ref('loading')
const errorMessage = ref('')
const autoScale = ref(true)
const viewOnly = ref(Boolean(props.vm.console?.view_only))
const sessionViewOnly = ref(Boolean(props.vm.console?.view_only))
const sessionInfo = ref(null)
const rfbClient = ref(null)
const isFullscreen = ref(false)
const fullscreenSupported = typeof document !== 'undefined' && Boolean(document.fullscreenEnabled)
let disposed = false

const connected = computed(() => status.value === 'connected')
const viewOnlyLocked = computed(() => Boolean(props.vm.console?.view_only || sessionViewOnly.value))
const statusLabel = computed(() => t(`vms.console_status_${finiteText(status.value, 'failed')}`))

function finiteSecs(value) {
  const n = Number(value)
  return Number.isFinite(n) && n >= 0 ? n : '—'
}

function sameOriginWebSocketUrl(rawUrl) {
  const parsed = new URL(rawUrl, window.location.href)
  if (!['ws:', 'wss:', 'http:', 'https:'].includes(parsed.protocol)) {
    throw new Error(t('vms.console_invalid_url'))
  }
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  return `${protocol}//${window.location.host}${parsed.pathname}${parsed.search}${parsed.hash}`
}

async function connect() {
  try {
    // Loading noVNC here keeps it out of the initial page chunk. This component
    // is only mounted while the console modal is open.
    status.value = 'loading'
    const { default: RFB } = await import('@novnc/novnc')
    if (disposed) return

    status.value = 'requesting'
    const session = await createVmConsoleSession(props.vm.console_id)
    if (disposed) return
    sessionInfo.value = session
    sessionViewOnly.value = Boolean(session.view_only)
    viewOnly.value = Boolean(props.vm.console?.view_only || session.view_only)

    status.value = 'connecting'
    const client = new RFB(screenEl.value, sameOriginWebSocketUrl(session.ws_url), { shared: true })
    rfbClient.value = markRaw(client)
    client.scaleViewport = autoScale.value
    client.viewOnly = viewOnly.value

    client.addEventListener('connect', () => {
      if (!disposed) status.value = 'connected'
    })
    client.addEventListener('disconnect', (event) => {
      if (disposed) return
      rfbClient.value = null
      if (event.detail?.clean !== false) {
        status.value = 'disconnected'
      } else {
        status.value = 'failed'
        errorMessage.value = t('vms.console_connection_lost')
      }
    })
    client.addEventListener('securityfailure', (event) => {
      if (disposed) return
      status.value = 'failed'
      errorMessage.value = finiteText(event.detail?.reason, '') || t('vms.console_connection_failed')
    })

    // No retry loop or browser clipboard integration is registered; both
    // automatic features intentionally stay off.
  } catch (error) {
    if (disposed) return
    status.value = 'failed'
    errorMessage.value = finiteText(error?.message, '') || t('vms.console_connection_failed')
  }
}

function disconnect() {
  const client = rfbClient.value
  if (!client) return
  status.value = 'disconnecting'
  rfbClient.value = null
  try {
    client.disconnect()
  } catch {
    status.value = 'disconnected'
  }
}

function sendCtrlAltDel() {
  if (connected.value && !viewOnly.value) rfbClient.value?.sendCtrlAltDel()
}

async function toggleFullscreen() {
  if (!fullscreenSupported) return
  try {
    if (document.fullscreenElement === panelEl.value) {
      await document.exitFullscreen()
    } else {
      await panelEl.value?.requestFullscreen()
    }
    if (disposed) {
      if (document.fullscreenElement) await document.exitFullscreen().catch(() => {})
      return
    }
  } catch (error) {
    if (disposed) return
    errorMessage.value = finiteText(error?.message, '') || t('vms.console_fullscreen_failed')
  }
}

function updateFullscreenState() {
  isFullscreen.value = document.fullscreenElement === panelEl.value
}

function close() {
  disconnect()
  emit('close')
}

// The console is mounted only while open, so it is always dismissable:

watch(autoScale, (enabled) => {
  if (disposed) return
  if (rfbClient.value) rfbClient.value.scaleViewport = enabled
})
watch(viewOnly, (enabled) => {
  if (disposed) return
  if (rfbClient.value) rfbClient.value.viewOnly = enabled
})

onMounted(() => {
  document.addEventListener('fullscreenchange', updateFullscreenState)
  connect()
})

onBeforeUnmount(() => {
  disposed = true
  document.removeEventListener('fullscreenchange', updateFullscreenState)
  disconnect()
})

// The parent mounts this component only while the console is open, so the
// dialog is open for its whole lifetime.
useDismissable(computed(() => true), () => { close() }, panelEl)
</script>

<style scoped>
.vnc-modal {
  width: min(1120px, calc(100% - 28px));
  max-width: none;
  padding: 12px;
  overflow: hidden;
}
.vnc-modal:fullscreen {
  width: 100vw;
  height: 100vh;
  max-height: none;
  border-radius: 0;
  display: flex;
  flex-direction: column;
  background: var(--card);
}
.vnc-header,
.vnc-toolbar {
  display: flex;
  align-items: center;
  gap: 10px;
}
.vnc-header {
  justify-content: space-between;
  margin-bottom: 10px;
}
.vnc-meta,
.vnc-policy {
  color: var(--sub);
  font-size: 11px;
}
.vnc-toolbar {
  flex-wrap: wrap;
  margin-bottom: 8px;
}
.vnc-status {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  min-width: 120px;
  font-size: 12px;
}
.status-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: #888;
}
.status-dot.connected { background: #28a745; }
.status-dot.connecting,
.status-dot.requesting,
.status-dot.loading,
.status-dot.disconnecting { background: #d99a00; }
.status-dot.failed { background: #d33; }
.vnc-option {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  color: var(--sub);
  font-size: 12px;
}
.vnc-screen {
  width: 100%;
  height: min(68vh, 720px);
  min-height: 320px;
  overflow: hidden;
  background: #181818;
  border: 1px solid var(--line);
  border-radius: 6px;
  outline: none;
}
.vnc-modal:fullscreen .vnc-screen {
  flex: 1;
  height: auto;
  min-height: 0;
}
.vnc-error {
  margin: 8px 0 0;
  color: #d33;
  font-size: 12px;
}
.vnc-policy { margin: 7px 0 0; }
@media (max-width: 640px) {
  .vnc-screen { min-height: 240px; height: 60vh; }
}
</style>
