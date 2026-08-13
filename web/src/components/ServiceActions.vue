<!--
  The one place that renders a service's action buttons.

  The dense table row, the card and the detail drawer all offer the same
  operations for the same service; before this component each carried its own
  copy of the logic and they drifted. Which actions exist comes from
  lib/serviceActions.js; how they execute stays with the parent (single busy
  flag, confirm prompts, toasts), which listens to the emits below.

  Variants keep each surface's existing look:
    table  — compact .act-btn buttons, every offered control action
    card   — .tiny buttons, the server-ordered top three (primaryActs)
    drawer — full-size buttons, no "Details" button (we are the details)
  The default slot lets the drawer append its own admin buttons (hide,
  uninstall) to the same row.
-->
<template>
  <div :class="wrapClass">
    <a
      v-if="service.url"
      :class="openClass"
      :href="service.url"
      target="_blank"
      rel="noopener"
      @click.stop
    >{{ t('services.open') }}</a>
    <button
      v-for="a in acts"
      :key="a"
      type="button"
      :class="actClass(a)"
      :disabled="busy"
      @click="emit('act', a)"
    >{{ actLabel(a) }}</button>
    <button v-if="canLogs(service)" type="button" :class="plainClass" @click="emit('logs')">
      {{ t('services.logs') }}
    </button>
    <button v-if="variant !== 'drawer'" type="button" :class="plainClass" @click="emit('more')">
      {{ t('services.more') }}
    </button>
    <slot />
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { injectI18n } from '../i18n'
import { canLogs, controlActs, primaryActs, serviceLabels } from '../lib/serviceActions'

const { t } = injectI18n()
const { actLabel } = serviceLabels(t)

const props = defineProps({
  /** Service entry as served by /api/services (or its detail payload). */
  service: { type: Object, required: true },
  /** Disables the control buttons while another operation runs. */
  busy: { type: Boolean, default: false },
  /** Rendering surface: 'table' | 'card' | 'drawer'. */
  variant: {
    type: String,
    default: 'table',
    validator: (v) => ['table', 'card', 'drawer'].includes(v),
  },
})

const emit = defineEmits(['act', 'logs', 'more'])

// The card shows the server-ordered top three; the wide surfaces show every
// offered control action in canonical order. Both draw on the same predicates.
const acts = computed(() =>
  props.variant === 'card' ? primaryActs(props.service) : controlActs(props.service),
)

const wrapClass = computed(() => (
  { table: 'act-row', card: 'btns', drawer: 'drawer-acts' }[props.variant]
))

const openClass = computed(() => (
  {
    table: 'act-btn link primary',
    card: 'btn primary tiny',
    drawer: 'btn primary',
  }[props.variant]
))

const plainClass = computed(() => (
  { table: 'act-btn', card: 'tiny', drawer: '' }[props.variant]
))

function actClass(a) {
  if (props.variant === 'table') return ['act-btn', { primary: a === 'start' }]
  if (props.variant === 'card') return ['tiny', { danger: a === 'stop', primary: a === 'start' }]
  return [{ primary: a === 'start' }]
}
</script>

<style scoped>
.act-row { display: flex; flex-wrap: wrap; gap: 4px; }
.act-btn {
  font-size: 11px; padding: 3px 9px; border-radius: var(--radius);
  border: 1px solid var(--line); background: var(--card); color: var(--txt); cursor: pointer;
  text-decoration: none; display: inline-flex; align-items: center;
  transition: border-color .12s, background .12s;
}
.act-btn:hover { border-color: var(--accent); }
.act-btn.primary, .act-btn.link.primary { border-color: var(--accent); color: var(--accent); font-weight: 600; }
.act-btn:disabled { opacity: .4; cursor: not-allowed; }
.btns { display: flex; flex-wrap: wrap; gap: 4px; }
.drawer-acts { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 14px; }
</style>
