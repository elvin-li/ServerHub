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
      <div ref="logEl" class="assist-log" :aria-live="asArray(turns).length ? 'polite' : undefined">
        <p v-if="!asArray(turns).length" class="assist-empty">{{ t('assistant.empty') }}</p>
        <article v-for="(turn, i) in asArray(turns)" :key="finiteText(asRecord(turn).role) + ':' + i" class="assist-turn" :class="asRecord(turn).role">
          <div class="assist-who">{{ asRecord(turn).role === 'user' ? t('assistant.you') : t('assistant.bot') }}</div>
          <pre class="assist-text">{{ finiteText(asRecord(turn).content) }}</pre>
          <div v-if="asArray(asRecord(turn).panels).length" class="assist-panels">
            <button
              v-for="p in asArray(asRecord(turn).panels)"
              :key="finiteText(asRecord(p).path, '')"
              class="tiny"
              type="button"
              @click="go(asRecord(p).path)"
            >{{ finiteText(asRecord(p).title) }} <span class="mono">{{ finiteText(asRecord(p).path) }}</span></button>
          </div>
          <div v-if="asRecord(turn).meta" class="assist-meta">{{ finiteText(asRecord(turn).meta) }}</div>
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
        <button class="primary" type="submit" :disabled="busy || !asTrimmed(draft)" data-test="assistant-send">
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
import { asArray, asRecord, asTrimmed, finiteN, finiteText } from '../lib/finite'
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
let sendGeneration = 0

useDismissable(() => props.open, () => emit('close'), panel)

watch(() => props.open, async (isOpen) => {
  if (!isOpen) {
    sendGeneration += 1
    abortCtrl?.abort()
    busy.value = false
    return
  }
  const generation = sendGeneration
  await nextTick()
  if (generation !== sendGeneration || !props.open) return
  inputEl.value?.focus()
  if (props.seedAction === 'brief' || props.seedAction === 'page') {
    const action = props.seedAction
    emit('consumed-action')
    await send(action)
    return
  }
  if (asTrimmed(finiteText(props.seed, ''))) {
    draft.value = asTrimmed(finiteText(props.seed, ''))
    emit('consumed-seed')
    await send('auto')
  }
})

function formatBrief(snap) {
  const brief = asRecord(snap)
  const c = asRecord(brief.counts)
  const lines = [
    t('assistant.brief_overview', {
      load: finiteN(brief.load),
      cpu: finiteN(brief.cpu_load_pct),
      mem: finiteN(brief.mem_used_pct),
      disk: finiteN(brief.disk_root_pct),
      diskAmt: finiteText(brief.disk_root),
      up: finiteText(brief.uptime),
    }),
    t('assistant.brief_services', {
      ok: finiteN(c.ok, 0),
      warn: finiteN(c.warn, 0),
      down: finiteN(c.down, 0),
      engine: brief.engine_up ? t('common.on') : t('common.off'),
    }),
  ]
  const problems = asArray(brief.problems)
  if (problems.length) {
    lines.push(t('assistant.brief_problems'))
    for (const raw of problems.slice(0, 6)) {
      const p = asRecord(raw)
      lines.push(`- ${finiteText(p.name)} · ${finiteText(p.state)} · ${finiteText(p.detail)}`)
    }
  } else {
    lines.push(t('assistant.brief_clear'))
  }
  return lines.join('\n')
}

function displayText(out, query) {
  const reply = asRecord(out)
  if (reply.kind === 'find') {
    if (!query) return t('assistant.find_browse')
    return asArray(reply.panels).length
      ? t('assistant.find_result')
      : t('assistant.find_none', { q: finiteText(query, '') })
  }
  if (reply.kind === 'page') return finiteText(reply.text, '')
  if (!reply.used_llm && reply.snapshot) return formatBrief(reply.snapshot)
  return finiteText(reply.text, '')
}

function go(path) {
  emit('go', finiteText(path, '') || '/')
  emit('close')
}

function historyPayload() {
  return asArray(turns.value)
    .map((row) => asRecord(row))
    .filter((row) => row.role === 'user' || row.role === 'assistant')
    .filter((row) => row.content && !row.pending)
    .slice(-6)
    .map((row) => ({ role: row.role, content: finiteText(row.content, '') }))
}

async function send(action, preset = '') {
  const query = asTrimmed(preset || draft.value)
  if (action === 'ask' && !query) return
  sendGeneration += 1
  const generation = sendGeneration
  let userTurn = null
  turns.value = asArray(turns.value)
  if (query) {
    userTurn = { role: 'user', content: query }
    turns.value.push(userTurn)
  } else if (action === 'brief') {
    userTurn = { role: 'user', content: t('assistant.brief') }
    turns.value.push(userTurn)
  } else if (action === 'page') {
    userTurn = { role: 'user', content: t('assistant.page') }
    turns.value.push(userTurn)
  } else if (action === 'find') {
    userTurn = { role: 'user', content: t('assistant.find') }
    turns.value.push(userTurn)
  }
  draft.value = ''
  const pending = { role: 'assistant', content: t('assistant.thinking'), pending: true, panels: [] }
  turns.value.push(pending)
  const dropStale = () => {
    turns.value = asArray(turns.value).filter((row) => row !== pending && row !== userTurn)
  }
  busy.value = true
  abortCtrl?.abort()
  abortCtrl = new AbortController()
  await nextTick()
  if (generation !== sendGeneration || !props.open) {
    dropStale()
    if (generation === sendGeneration) busy.value = false
    return
  }
  logEl.value?.scrollTo?.(0, logEl.value.scrollHeight)
  try {
    const out = asRecord(await askAssistant(query, {
      locale: locale.value,
      action,
      history: asArray(historyPayload()).slice(0, -1),
      path: route.path || '/',
      signal: abortCtrl.signal,
    }))
    if (generation !== sendGeneration || !props.open) {
      dropStale()
      return
    }
    pending.pending = false
    pending.content = finiteText(displayText(out, query), '') || t('assistant.empty_reply')
    pending.panels = asArray(asRecord(out).panels).map((p) => asRecord(p))
    if (asRecord(out).used_llm && asRecord(out).model) {
      pending.meta = t('assistant.via_model', { model: finiteText(asRecord(out).model) })
    } else if (asRecord(out).kind === 'brief' || asRecord(out).kind === 'answer') {
      pending.meta = t('assistant.via_template')
    }
  } catch (err) {
    if (generation !== sendGeneration || !props.open) {
      dropStale()
      return
    }
    pending.pending = false
    pending.content = err.code === 'cancelled'
      ? t('assistant.cancelled')
      : finiteText(err.message || String(err))
  } finally {
    if (generation === sendGeneration) {
      busy.value = false
      abortCtrl = null
    }
    if (props.open && generation === sendGeneration) {
      await nextTick()
      if (generation !== sendGeneration || !props.open) return
      logEl.value?.scrollTo?.(0, logEl.value.scrollHeight)
      inputEl.value?.focus()
    }
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
