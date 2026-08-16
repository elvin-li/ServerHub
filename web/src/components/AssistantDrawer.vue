<template>
  <div
    v-if="open"
    class="assist-bg"
    data-test="assistant-drawer"
    @click.self="emit('close')"
    role="presentation"
  >
    <div
      ref="panel"
      class="assist-panel"
      role="dialog"
      aria-modal="true"
      :aria-label="t('assistant.title')"
      tabindex="-1"
    >
      <header class="assist-head">
        <div>
          <h2>{{ t('assistant.title') }}</h2>
          <p class="assist-sub">{{ t('assistant.hint') }}</p>
        </div>
        <button class="tiny" type="button" @click="emit('close')">{{ t('common.close') }}</button>
      </header>
      <div class="assist-chips" role="group" :aria-label="t('assistant.actions')">
        <button class="tiny primary" type="button" :disabled="busy" data-test="assistant-brief" @click="runBrief">
          {{ t('assistant.brief') }}
        </button>
        <button class="tiny" type="button" :disabled="busy" data-test="assistant-find" @click="runFind">
          {{ t('assistant.find') }}
        </button>
        <button class="tiny" type="button" :disabled="busy" data-test="assistant-page" @click="runPage">
          {{ t('assistant.page') }}
        </button>
        <button
          v-if="busy"
          class="tiny"
          type="button"
          data-test="assistant-stop"
          @click="stop"
        >
          {{ t('assistant.stop') }}
        </button>
        <router-link class="assist-ollama" to="/ollama" @click="emit('close')">
          {{ t('assistant.ollama_link') }}
        </router-link>
      </div>
      <div ref="logEl" class="assist-log" aria-live="polite">
        <p v-if="!turns.length" class="assist-empty">{{ t('assistant.empty') }}</p>
        <article v-for="(turn, i) in turns" :key="i" class="assist-turn" :class="turn.role">
          <div class="assist-who">{{ turn.role === 'user' ? t('assistant.you') : t('assistant.bot') }}</div>
          <pre class="assist-text">{{ turn.content }}</pre>
          <div v-if="turn.panels?.length" class="assist-panels">
            <button
              v-for="p in turn.panels"
              :key="p.path"
              class="tiny"
              type="button"
              @click="go(p.path)"
            >{{ p.title }} <span class="mono">{{ p.path }}</span></button>
          </div>
          <div v-if="turn.meta" class="assist-meta">{{ turn.meta }}</div>
        </article>
      </div>
      <form class="assist-form" @submit.prevent="send('auto')">
        <label class="sr-only" for="assist-input">{{ t('assistant.input_label') }}</label>
        <input
          id="assist-input"
          ref="inputEl"
          v-model="draft"
          type="text"
          maxlength="500"
          :placeholder="t('assistant.ph')"
          :disabled="busy"
          @keydown.esc.stop="emit('close')"
        />
        <button class="primary" type="submit" :disabled="busy || !draft.trim()" data-test="assistant-send">
          {{ busy ? t('assistant.thinking') : t('assistant.send') }}
        </button>
      </form>
    </div>
  </div>
</template>

<script setup>
import { nextTick, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { askAssistant } from '../api/client'
import { injectI18n } from '../i18n'
import { useDismissable } from '../composables/useDismissable'

const props = defineProps({
  open: { type: Boolean, default: false },
  seed: { type: String, default: '' },
  seedAction: { type: String, default: '' },
})
const emit = defineEmits(['close', 'go', 'consumed-seed', 'consumed-action'])
const route = useRoute()

const { t, locale } = injectI18n()
const panel = ref(null)
const inputEl = ref(null)
const logEl = ref(null)
const draft = ref('')
const busy = ref(false)
const turns = ref([])
let abortCtrl = null

useDismissable(() => props.open, () => emit('close'), panel)

watch(() => props.open, async (isOpen) => {
  if (!isOpen) {
    abortCtrl?.abort()
    return
  }
  await nextTick()
  inputEl.value?.focus()
  if (props.seedAction === 'brief' || props.seedAction === 'page') {
    const action = props.seedAction
    emit('consumed-action')
    await send(action)
    return
  }
  if (props.seed.trim()) {
    draft.value = props.seed.trim()
    emit('consumed-seed')
    await send('auto')
  }
})

function formatBrief(snap) {
  const c = snap?.counts || {}
  const lines = [
    t('assistant.brief_overview', {
      load: snap.load ?? '—',
      cpu: snap.cpu_load_pct ?? '—',
      mem: snap.mem_used_pct ?? '—',
      disk: snap.disk_root_pct ?? '—',
      diskAmt: snap.disk_root ?? '—',
      up: snap.uptime ?? '—',
    }),
    t('assistant.brief_services', {
      ok: c.ok ?? 0,
      warn: c.warn ?? 0,
      down: c.down ?? 0,
      engine: snap.engine_up ? t('common.on') : t('common.off'),
    }),
  ]
  const problems = snap.problems || []
  if (problems.length) {
    lines.push(t('assistant.brief_problems'))
    for (const p of problems.slice(0, 6)) {
      lines.push(`- ${p.name} · ${p.state} · ${p.detail || '—'}`)
    }
  } else {
    lines.push(t('assistant.brief_clear'))
  }
  return lines.join('\n')
}

function displayText(out, query) {
  if (out.kind === 'find') {
    if (!query) return t('assistant.find_browse')
    return (out.panels && out.panels.length)
      ? t('assistant.find_result')
      : t('assistant.find_none', { q: query || '' })
  }
  if (out.kind === 'page') return out.text || ''
  if (!out.used_llm && out.snapshot) return formatBrief(out.snapshot)
  return out.text || ''
}

function go(path) {
  emit('go', path)
  emit('close')
}

function historyPayload() {
  return turns.value
    .filter((row) => row.role === 'user' || row.role === 'assistant')
    .filter((row) => row.content && !row.pending)
    .slice(-6)
    .map((row) => ({ role: row.role, content: row.content }))
}

async function send(action, preset = '') {
  const query = (preset || draft.value).trim()
  if (action === 'ask' && !query) return
  if (query) {
    turns.value.push({ role: 'user', content: query })
  } else if (action === 'brief') {
    turns.value.push({ role: 'user', content: t('assistant.brief') })
  } else if (action === 'page') {
    turns.value.push({ role: 'user', content: t('assistant.page') })
  } else if (action === 'find') {
    turns.value.push({ role: 'user', content: t('assistant.find') })
  }
  draft.value = ''
  const pending = { role: 'assistant', content: t('assistant.thinking'), pending: true, panels: [] }
  turns.value.push(pending)
  busy.value = true
  abortCtrl?.abort()
  abortCtrl = new AbortController()
  await nextTick()
  logEl.value?.scrollTo?.(0, logEl.value.scrollHeight)
  try {
    const out = await askAssistant(query, {
      locale: locale.value,
      action,
      history: historyPayload().slice(0, -1),
      path: route.path || '/',
      signal: abortCtrl.signal,
    })
    pending.pending = false
    pending.content = displayText(out, query) || t('assistant.empty_reply')
    pending.panels = out.panels || []
    if (out.used_llm && out.model) {
      pending.meta = t('assistant.via_model', { model: out.model })
    } else if (out.kind === 'brief' || out.kind === 'answer') {
      pending.meta = t('assistant.via_template')
    }
  } catch (err) {
    pending.pending = false
    pending.content = err.code === 'cancelled'
      ? t('assistant.cancelled')
      : (err.message || String(err))
  } finally {
    busy.value = false
    abortCtrl = null
    await nextTick()
    logEl.value?.scrollTo?.(0, logEl.value.scrollHeight)
    inputEl.value?.focus()
  }
}

function stop() {
  abortCtrl?.abort()
}

function runBrief() {
  return send('brief')
}

function runFind() {
  return send('find')
}

function runPage() {
  return send('page')
}

defineExpose({ send })
</script>
