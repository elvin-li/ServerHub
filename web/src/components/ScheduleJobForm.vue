<template>
  <div>
    <div class="kv" style="margin-bottom:10px">
      <div class="k">{{ t('sched.name') }}</div>
      <input v-model="name" type="text" :placeholder="t('sched.name_ph')" :aria-label="t('sched.name')" />
      <div class="k">{{ t('sched.type') }}</div>
      <select v-model="type" :disabled="lockType" :aria-label="t('sched.type')">
        <option v-for="ty in asArray(allowedTypes)" :key="finiteText(ty)" :value="finiteText(ty)">{{ t(`sched.type_${ty}`) }}</option>
      </select>
      <div class="k">{{ t('sched.cron') }}</div>
      <div>
        <div class="row cron-row">
          <select v-model="preset" :aria-label="t('sched.preset_label')" @change="applyPreset">
            <option value="custom">{{ t('sched.preset_custom') }}</option>
            <option value="hourly">{{ t('sched.preset_hourly') }}</option>
            <option value="daily">{{ t('sched.preset_daily') }}</option>
            <option value="weekly">{{ t('sched.preset_weekly') }}</option>
            <option value="monthly">{{ t('sched.preset_monthly') }}</option>
          </select>
          <input v-model="cron" type="text" placeholder="30 3 * * *" :aria-label="t('sched.cron')"
                 style="flex:1;min-width:120px" @input="preset = 'custom'" />
        </div>
        <div class="meta" style="margin-top:4px;font-size:11px;color:var(--sub)">{{ finiteText(cronText) }}</div>
      </div>
      <template v-if="type === 'command' || type === 'rsync'">
        <div class="k">{{ t('sched.timeout_s') }}</div>
        <input v-model.number="timeout" type="number" min="1" max="86400" :aria-label="t('sched.timeout_s')" />
      </template>
      <div class="k">{{ t('sched.enabled') }}</div>
      <label style="display:flex;align-items:center;gap:6px;font-size:12px">
        <input v-model="enabled" type="checkbox" :aria-label="t('sched.enabled')" />
        {{ enabled ? t('common.yes') : t('common.no') }}
      </label>
    </div>

    <!-- command -->
    <template v-if="type === 'command'">
      <label class="k" for="sched-form-cmd" style="display:block;margin-bottom:4px">{{ t('sched.command') }}</label>
      <textarea id="sched-form-cmd" v-model="command" spellcheck="false" :placeholder="t('sched.command_ph')"
                style="width:100%;min-height:90px;font-family:ui-monospace,Menlo,monospace;font-size:12px;padding:8px;border:1px solid var(--line);border-radius:4px;background:var(--bg);color:var(--txt)"></textarea>
    </template>

    <!-- rsync -->
    <template v-else-if="type === 'rsync'">
      <div class="kv" style="margin-bottom:8px">
        <div class="k">{{ t('sched.rsync_direction') }}</div>
        <select v-model="direction" :aria-label="t('sched.rsync_direction')">
          <option value="push">{{ t('sched.rsync_push') }}</option>
          <option value="pull">{{ t('sched.rsync_pull') }}</option>
        </select>
        <div class="k">{{ t('sched.rsync_src') }}</div>
        <input v-model="src" type="text" placeholder="/Users/me/Services/photos" :aria-label="t('sched.rsync_src')" />
        <div class="k">{{ t('sched.rsync_dest') }}</div>
        <input v-model="dest" type="text" placeholder="/Volumes/Backup/photos" :aria-label="t('sched.rsync_dest')" />
        <div class="k">{{ t('sched.rsync_exclude') }}</div>
        <textarea v-model="excludeText" spellcheck="false" :placeholder="t('sched.rsync_exclude_ph')"
                  :aria-label="t('sched.rsync_exclude')"
                  style="width:100%;min-height:56px;font-family:ui-monospace,Menlo,monospace;font-size:12px;padding:8px;border:1px solid var(--line);border-radius:4px;background:var(--bg);color:var(--txt)"></textarea>
        <div class="k">{{ t('sched.rsync_options') }}</div>
        <div style="display:flex;flex-direction:column;gap:4px;font-size:12px">
          <label style="display:flex;align-items:center;gap:6px">
            <input v-model="del" type="checkbox" :aria-label="t('sched.rsync_delete')" />
            {{ t('sched.rsync_delete') }}
          </label>
          <span v-if="del" class="meta" style="color:var(--warn-text);font-size:11px">{{ t('sched.rsync_delete_warn') }}</span>
          <label style="display:flex;align-items:center;gap:6px">
            <input v-model="compress" type="checkbox" :aria-label="t('sched.rsync_compress')" />
            {{ t('sched.rsync_compress') }}
          </label>
        </div>
        <div class="k">{{ t('sched.rsync_bwlimit') }}</div>
        <input v-model.number="bwlimit" type="number" min="0" :aria-label="t('sched.rsync_bwlimit')" />
      </div>
      <div class="btns" style="margin-bottom:8px">
        <button :disabled="previewing || busy" @click="doPreview">
          {{ previewing ? t('common.loading') : t('sched.rsync_preview') }}
        </button>
      </div>
      <div v-if="previewError" class="meta" role="status" aria-live="polite" style="color:var(--down-text);font-size:12px;margin-bottom:8px">
        {{ finiteText(previewError) }}
      </div>
      <div v-else-if="preview" role="status" aria-live="polite"
           style="border:1px solid var(--line);border-radius:4px;padding:8px;margin-bottom:8px;font-size:12px">
        <div style="margin-bottom:6px">
          <span class="badge accent" style="margin-right:6px">{{ t('sched.preview_creates', { n: finiteN(asRecord(preview).creates) }) }}</span>
          <span class="badge accent" style="margin-right:6px">{{ t('sched.preview_updates', { n: finiteN(asRecord(preview).updates) }) }}</span>
          <span class="badge" :class="asRecord(preview).deletes ? 'warn' : ''">{{ t('sched.preview_deletes', { n: finiteN(asRecord(preview).deletes) }) }}</span>
        </div>
        <div v-if="!asRecord(preview).total" class="meta">{{ t('sched.preview_empty') }}</div>
        <div v-else style="max-height:140px;overflow:auto;font-family:ui-monospace,Menlo,monospace;font-size:11px;white-space:pre">
          <div v-for="(line, i) in asArray(asRecord(preview).samples)" :key="finiteText(line) + ':' + i">{{ finiteText(line) }}</div>
        </div>
      </div>
    </template>

    <!-- stack backup -->
    <template v-else-if="type === 'stack_backup'">
      <div class="kv" style="margin-bottom:8px">
        <div class="k">{{ t('sched.stack') }}</div>
        <select v-model="stackId" :aria-label="t('sched.stack')">
          <option v-for="s in asArray(stacks)" :key="finiteText(asRecord(s).id)" :value="asRecord(s).id">{{ finiteText(asRecord(s).name, '') || finiteText(asRecord(s).id) }}</option>
        </select>
        <div class="k">{{ t('sched.stack_retain') }}</div>
        <input v-model.number="retain" type="number" min="1" max="365" :aria-label="t('sched.stack_retain')" />
      </div>
      <!-- role=alert: a failed stack read used to be swallowed, leaving an
           empty select and a disabled Save with no stated reason. The form
           loads after the dialog holds focus, so the panel read misses it. -->
      <div v-if="stacksError" class="meta" role="alert" style="color:var(--down-text);font-size:12px;margin-bottom:8px">
        {{ t('common.load_failed') }} · {{ finiteText(stacksError) }}
      </div>
      <p class="meta" style="font-size:11px;color:var(--sub)">{{ t('sched.stack_hint') }}</p>
    </template>

    <!-- snapshot -->
    <template v-else-if="type === 'snapshot'">
      <p class="meta" style="font-size:12px;color:var(--sub)">{{ t('sched.snapshot_hint') }}</p>
    </template>

    <div class="btns" style="margin-top:10px">
      <button class="primary" :disabled="busy || !canSave" @click="save">{{ t('common.save') }}</button>
      <button :disabled="busy" @click="emit('cancel')">{{ t('common.cancel') }}</button>
    </div>
  </div>
</template>

<script setup>
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { getStacks, rsyncPreview } from '../api/client'
import { injectI18n } from '../i18n'
import { asArray, asRecord, finiteN, finiteText } from '../lib/finite'

const props = defineProps({
  job: { type: Object, default: null },
  allowedTypes: { type: Array, default: () => ['command', 'rsync', 'stack_backup', 'snapshot'] },
  busy: { type: Boolean, default: false },
})
const emit = defineEmits(['save', 'cancel'])
const { t } = injectI18n()

const lockType = computed(() => Boolean(props.job) || asArray(props.allowedTypes).length === 1)
const allowedTypes = computed(() => asArray(props.allowedTypes))

const p = asRecord(props.job?.params)
const name = ref(props.job?.name || '')
const type = ref(props.job?.type || asArray(props.allowedTypes)[0])
const cron = ref(props.job?.cron || '30 3 * * *')
const enabled = ref(props.job ? Boolean(props.job.enabled) : true)
const timeout = ref(props.job?.timeout || null)
const preset = ref('custom')
// command
const command = ref(p.command || '')
// rsync
const direction = ref(p.direction || 'push')
const src = ref(p.src || '')
const dest = ref(p.dest || '')
const excludeText = ref(asArray(p.exclude).map((n) => finiteText(n, '')).filter(Boolean).join('\n'))
const del = ref(Boolean(p.delete))
const compress = ref(Boolean(p.compress))
const bwlimit = ref(p.bwlimit_kbps || null)
// stack backup
const stackId = ref(p.stack_id || '')
const retain = ref(p.retain || 14)
const stacks = ref([])
const stacksError = ref('')

const previewing = ref(false)
const preview = ref(null)
const previewError = ref('')
let pageAlive = true
let previewGeneration = 0
let stacksGeneration = 0

const PRESETS = {
  hourly: '0 * * * *',
  daily: '30 3 * * *',
  weekly: '30 3 * * 0',
  monthly: '30 3 1 * *',
}

function applyPreset() {
  if (PRESETS[preset.value]) cron.value = PRESETS[preset.value]
}

/** Plain-language reading of the common cron shapes; raw stays authoritative. */
const cronText = computed(() => {
  const fields = cron.value.trim().split(/\s+/)
  if (fields.length !== 5) return t('sched.cron_invalid')
  const [min, hour, dom, mon, dow] = fields
  const num = (s) => (/^\d{1,2}$/.test(s) ? finiteN(s, null) : null)
  const hhmm = () => `${String(num(hour)).padStart(2, '0')}:${String(num(min)).padStart(2, '0')}`
  if (fields.every((f) => f === '*')) return t('sched.cron_every_minute')
  const step = min.match(/^\*\/(\d+)$/)
  if (step && hour === '*' && dom === '*' && mon === '*' && dow === '*') {
    return t('sched.cron_every_n_minutes', { n: finiteN(step[1]) })
  }
  if (num(min) !== null && hour === '*' && dom === '*' && mon === '*' && dow === '*') {
    return t('sched.cron_hourly_at', { m: String(num(min)).padStart(2, '0') })
  }
  if (num(min) !== null && num(hour) !== null && dom === '*' && mon === '*' && dow === '*') {
    return t('sched.cron_daily_at', { time: hhmm() })
  }
  if (num(min) !== null && num(hour) !== null && dom === '*' && mon === '*' && /^[0-7]$/.test(dow)) {
    return t('sched.cron_weekly_at', { day: t(`sched.day_${finiteN(dow, 0) % 7}`), time: hhmm() })
  }
  if (num(min) !== null && num(hour) !== null && num(dom) !== null && mon === '*' && dow === '*') {
    return t('sched.cron_monthly_at', { day: num(dom), time: hhmm() })
  }
  return t('sched.cron_custom')
})

const canSave = computed(() => {
  if (!name.value.trim() || cron.value.trim().split(/\s+/).length !== 5) return false
  if (type.value === 'command') return Boolean(command.value.trim())
  if (type.value === 'rsync') return Boolean(src.value.trim() && dest.value.trim())
  if (type.value === 'stack_backup') return Boolean(stackId.value)
  return true
})

function rsyncParams() {
  return {
    direction: direction.value,
    src: src.value.trim(),
    dest: dest.value.trim(),
    exclude: excludeText.value.split('\n').map((s) => s.trim()).filter(Boolean),
    delete: del.value,
    compress: compress.value,
    bwlimit_kbps: bwlimit.value || null,
  }
}

function buildParams() {
  if (type.value === 'command') return { command: command.value.trim() }
  if (type.value === 'rsync') return rsyncParams()
  if (type.value === 'stack_backup') return { stack_id: stackId.value, retain: retain.value || 14 }
  return {}
}

async function doPreview() {
  const generation = ++previewGeneration
  previewing.value = true
  previewError.value = ''
  preview.value = null
  try {
    const next = asRecord(await rsyncPreview(rsyncParams()))
    if (generation !== previewGeneration || !pageAlive) return
    preview.value = {
      ...asRecord(next),
      samples: asArray(asRecord(next).samples),
    }
  } catch (e) {
    if (generation !== previewGeneration || !pageAlive) return
    previewError.value = finiteText(e.message || String(e), '')
  } finally {
    // getStacks() used to share this counter; a generation match after that
    // increment left Preview stuck. pageAlive still clears while mounted.
    if (pageAlive) previewing.value = false
  }
}

function save() {
  emit('save', {
    name: name.value.trim(),
    type: type.value,
    cron: cron.value.trim(),
    enabled: enabled.value,
    timeout: timeout.value || null,
    params: buildParams(),
  })
}

onMounted(async () => {
  pageAlive = true
  if (!asArray(props.allowedTypes).includes('stack_backup')) return
  const generation = ++stacksGeneration
  try {
    const d = asRecord(await getStacks())
    if (generation !== stacksGeneration || !pageAlive) return
    stacks.value = asArray(d.stacks).map((s) => asRecord(s))
    stacksError.value = ''
    if (!stackId.value && asArray(stacks.value).length) stackId.value = asRecord(asArray(stacks.value)[0]).id
  } catch (e) {
    if (generation !== stacksGeneration || !pageAlive) return
    stacks.value = []
    stacksError.value = finiteText(e.message || String(e), '')
  }
})
onUnmounted(() => {
  pageAlive = false
  previewGeneration += 1
  stacksGeneration += 1
})
</script>

<style scoped>
.cron-row { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; }
@media (max-width: 640px) {
  .cron-row input { min-width: 0; width: 100%; }
}
</style>
