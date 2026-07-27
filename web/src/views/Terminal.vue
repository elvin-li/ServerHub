<template>
  <div>
    <div class="page-title">
      <h1>{{ t('terminal.title') }}</h1>
      <span class="meta">{{ t('terminal.meta') }}</span>
    </div>

    <div class="card launcher">
      <div class="toolbar terminal-picker">
        <label class="tsel">
          <span>{{ t('terminal.target') }}</span>
          <select v-model="target" :disabled="connected">
            <option value="host">{{ t('terminal.target_host') }}</option>
            <option value="container">{{ t('terminal.target_container') }}</option>
          </select>
        </label>

        <label v-if="target === 'container'" class="tsel">
          <span>{{ t('terminal.container') }}</span>
          <select v-if="containers.length" v-model="container" :disabled="connected">
            <option v-for="c in containers" :key="c.id" :value="c.id">{{ c.label }}</option>
          </select>
          <input v-else v-model="container" type="text" :disabled="connected" :placeholder="t('terminal.container_ph')"  :aria-label="t('terminal.container_ph')"/>
        </label>

        <label v-if="target === 'container'" class="tsel">
          <span>{{ t('terminal.shell') }}</span>
          <select v-model="shell" :disabled="connected">
            <option value="/bin/sh">/bin/sh</option>
            <option value="/bin/bash">/bin/bash</option>
            <option value="/bin/ash">/bin/ash</option>
          </select>
        </label>

        <button class="primary" type="button" :disabled="opening || !canOpen" @click="openTerminal">
          {{ opening ? t('terminal.running') : t('terminal.run') }}
        </button>
      </div>

      <div v-if="target === 'host' && status && !status.host_enabled" class="locked">
        <strong>{{ t('terminal.host_locked_title') }}</strong>
        <p>{{ t('terminal.host_locked_body') }}</p>
        <router-link class="btn tiny primary" to="/settings">{{ t('terminal.host_locked_cta') }}</router-link>
      </div>
      <p v-else class="hint">⚠ {{ t('terminal.danger_hint') }}</p>
    </div>

    <Teleport to="body">
      <div v-if="dialogOpen" class="terminal-backdrop" role="presentation" @mousedown.self="closeTerminal">
        <section class="terminal-dialog" role="dialog" aria-modal="true" :aria-label="t('terminal.title')">
          <header class="terminal-head">
            <div class="terminal-title">
              <span class="status-dot" :class="{ live: connected }"></span>
              <strong>{{ targetLabel }}</strong>
              <span v-if="sessionId" class="session-id">{{ sessionId }}</span>
            </div>
            <div class="terminal-actions">
              <button class="tiny terminal-action" type="button" @click="clearTerminal">{{ t('terminal.clear') }}</button>
              <button class="tiny terminal-action close-action" type="button" @click="closeTerminal" :aria-label="t('common.close')">×</button>
            </div>
          </header>
          <div ref="terminalEl" class="xterm-host" :aria-label="t('terminal.a11y_output')"></div>
          <footer class="terminal-foot">
            <span>{{ connected ? targetLabel : t('terminal.cancel') }}</span>
            <span>{{ t('terminal.keys_hint') }}</span>
          </footer>
        </section>
      </div>
    </Teleport>
  </div>
</template>

<script setup>
import { computed, inject, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { Terminal as XTerm } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import '@xterm/xterm/css/xterm.css'
import { getContainers, getTerminal } from '../api/client'
import { injectI18n } from '../i18n'

const toast = inject('toast')
const { t } = injectI18n()

const status = ref(null)
const target = ref('host')
const container = ref('')
const shell = ref('/bin/sh')
const containers = ref([])
const dialogOpen = ref(false)
const opening = ref(false)
const connected = ref(false)
const terminalEl = ref(null)
const sessionId = ref('')

let term = null
let fitAddon = null
let socket = null
let resizeObserver = null
let previousBodyOverflow = ''
let intentionalClose = false

const canOpen = computed(() => {
  if (target.value === 'host') return !!status.value?.host_enabled
  return !!container.value
})
const targetLabel = computed(() => {
  if (target.value === 'host') return t('terminal.target_host')
  const item = containers.value.find(c => c.id === container.value)
  return item?.label || container.value || t('terminal.target_container')
})

watch(container, (id) => {
  const item = containers.value.find(c => c.id === id)
  if (item?.shell) shell.value = item.shell
})

async function load() {
  try {
    status.value = await getTerminal()
  } catch (error) {
    toast?.('❌ ' + error.message)
  }
  try {
    const response = await getContainers(false)
    containers.value = (response.containers || [])
      .filter(c => c.state === 'ok' || (c.status || '').startsWith('Up'))
      .map(c => ({
        id: c.raw_name || c.id || c.name,
        label: c.name || c.raw_name,
        shell: c.shell || '/bin/sh',
      }))
      .filter(c => c.id)
    if (!container.value && containers.value.length) container.value = containers.value[0].id
  } catch {
    // Container discovery is optional; a manually entered name remains available.
  }
}

function socketUrl() {
  const scheme = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  const query = new URLSearchParams({
    target: target.value,
    cols: String(term?.cols || 100),
    rows: String(term?.rows || 30),
  })
  if (target.value === 'container') {
    query.set('container', container.value)
    query.set('shell', shell.value)
  }
  return `${scheme}//${window.location.host}/api/terminal/ws?${query}`
}

async function openTerminal() {
  if (!canOpen.value || opening.value) return
  opening.value = true
  intentionalClose = false
  dialogOpen.value = true
  previousBodyOverflow = document.body.style.overflow
  document.body.style.overflow = 'hidden'
  await nextTick()

  term = new XTerm({
    cursorBlink: true,
    cursorStyle: 'block',
    convertEol: true,
    fontFamily: 'SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace',
    fontSize: 13,
    lineHeight: 1.18,
    scrollback: 5000,
    allowProposedApi: false,
    theme: {
      background: '#0b0d10',
      foreground: '#e8eaed',
      cursor: '#f28c28',
      selectionBackground: '#31506f',
      black: '#111318',
      red: '#ff6b6b',
      green: '#69db7c',
      yellow: '#ffd43b',
      blue: '#74c0fc',
      magenta: '#da77f2',
      cyan: '#66d9e8',
      white: '#f1f3f5',
    },
  })
  fitAddon = new FitAddon()
  term.loadAddon(fitAddon)
  term.open(terminalEl.value)
  fitTerminal()
  term.focus()
  term.writeln('\x1b[90mServerHub · connecting…\x1b[0m')

  socket = new WebSocket(socketUrl())
  socket.binaryType = 'arraybuffer'
  term.onData(data => {
    if (socket?.readyState === WebSocket.OPEN) {
      socket.send(JSON.stringify({ type: 'input', data }))
    }
  })
  socket.addEventListener('message', onSocketMessage)
  socket.addEventListener('close', onSocketClose)
  socket.addEventListener('error', () => {
    term?.writeln('\r\n\x1b[31mWebSocket connection failed.\x1b[0m')
  })

  resizeObserver = new ResizeObserver(() => fitTerminal())
  resizeObserver.observe(terminalEl.value)
}

function onSocketMessage(event) {
  if (typeof event.data !== 'string') {
    term?.write(new Uint8Array(event.data))
    return
  }
  try {
    const message = JSON.parse(event.data)
    if (message.type === 'ready') {
      connected.value = true
      opening.value = false
      sessionId.value = message.session || ''
      term?.write('\r\x1b[2K')
      fitTerminal()
      term?.focus()
    } else if (message.type === 'error') {
      opening.value = false
      const code = message.code || 'terminal error'
      const key = `err.${code}`
      const localized = t(key)
      term?.writeln(`\r\n\x1b[31m${localized === key ? code : localized}\x1b[0m`)
    }
  } catch {
    term?.write(event.data)
  }
}

function onSocketClose() {
  connected.value = false
  opening.value = false
  sessionId.value = ''
  if (!intentionalClose) term?.writeln('\r\n\x1b[90m[disconnected]\x1b[0m')
}

function fitTerminal() {
  if (!term || !fitAddon || !terminalEl.value) return
  try {
    fitAddon.fit()
    if (socket?.readyState === WebSocket.OPEN) {
      socket.send(JSON.stringify({ type: 'resize', cols: term.cols, rows: term.rows }))
    }
  } catch {
    // The dialog may be closing while ResizeObserver delivers its final event.
  }
}

function clearTerminal() {
  term?.clear()
  term?.focus()
}

function closeTerminal() {
  intentionalClose = true
  resizeObserver?.disconnect()
  resizeObserver = null
  if (socket && socket.readyState < WebSocket.CLOSING) socket.close(1000, 'operator closed terminal')
  socket = null
  term?.dispose()
  term = null
  fitAddon = null
  dialogOpen.value = false
  connected.value = false
  opening.value = false
  sessionId.value = ''
  document.body.style.overflow = previousBodyOverflow
}

function onKeydown(event) {
  if (dialogOpen.value && event.key === 'Escape') closeTerminal()
}

onMounted(() => {
  load()
  window.addEventListener('keydown', onKeydown)
})
onBeforeUnmount(() => {
  window.removeEventListener('keydown', onKeydown)
  closeTerminal()
})
</script>

<style scoped>
.launcher { padding: 14px; }
.terminal-picker { align-items: end; }
.tsel { display: flex; flex-direction: column; align-items: flex-start; gap: 5px; color: var(--sub); font-size: 11px; font-weight: 700; }
.tsel select, .tsel input { min-width: 150px; font-size: 12px; padding: 6px 8px; }
.locked { border-left: 3px solid var(--warn, #e5a000); padding: 8px 12px; margin-top: 12px; }
.locked p { color: var(--sub); font-size: 12px; line-height: 1.5; margin: 6px 0 10px; max-width: 68ch; }
.hint { color: var(--sub); font-size: 11px; margin: 10px 0 0; }

.terminal-backdrop {
  position: fixed; inset: 0; z-index: 1000;
  display: grid; place-items: center;
  padding: clamp(8px, 2vw, 24px);
  background: rgba(0, 0, 0, .72);
  backdrop-filter: blur(3px);
}
.terminal-dialog {
  width: min(1180px, 96vw); height: min(760px, 92dvh);
  display: grid; grid-template-rows: auto minmax(0, 1fr) auto;
  overflow: hidden;
  border: 1px solid #333942; border-radius: 9px;
  background: #0b0d10; color: #e8eaed;
  box-shadow: 0 24px 80px rgba(0, 0, 0, .65);
}
.terminal-head {
  display: flex; align-items: center; justify-content: space-between; gap: 12px;
  min-height: 44px; padding: 7px 10px 7px 14px;
  border-bottom: 1px solid #2a2f37; background: #171a1f;
}
.terminal-title, .terminal-actions { display: flex; align-items: center; gap: 9px; min-width: 0; }
.terminal-title strong { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 13px; }
.status-dot { width: 8px; height: 8px; flex: 0 0 auto; border-radius: 50%; background: #868e96; box-shadow: 0 0 0 3px rgba(134, 142, 150, .13); }
.status-dot.live { background: #51cf66; box-shadow: 0 0 0 3px rgba(81, 207, 102, .13); }
.session-id { color: #777f89; font: 10px SFMono-Regular, Menlo, monospace; }
.terminal-action { border-color: #3a414b; background: #252a31; color: #e8eaed; }
.close-action { width: 30px; height: 30px; padding: 0; font-size: 21px; line-height: 1; }
.xterm-host { min-width: 0; min-height: 0; padding: 10px 8px 6px 12px; background: #0b0d10; overflow: hidden; }
.xterm-host :deep(.xterm) { height: 100%; }
.terminal-foot {
  display: flex; justify-content: space-between; gap: 12px;
  min-height: 28px; padding: 6px 12px;
  border-top: 1px solid #242932; background: #12151a;
  color: #7e8792; font-size: 10px;
}

@media (max-width: 640px) {
  .terminal-picker { align-items: stretch; }
  .terminal-picker > * { width: 100%; }
  .tsel select, .tsel input { width: 100%; min-width: 0; font-size: 16px; }
  .terminal-backdrop { padding: 0; }
  .terminal-dialog { width: 100vw; height: 100dvh; border: 0; border-radius: 0; }
  .terminal-head { padding-top: max(7px, env(safe-area-inset-top)); }
  .session-id, .terminal-foot span:last-child { display: none; }
  .xterm-host { padding: 8px 4px 4px 8px; }
  .terminal-foot { padding-bottom: max(6px, env(safe-area-inset-bottom)); }
}
</style>
