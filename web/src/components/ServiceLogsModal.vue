<!--
  Standalone log viewer for one service, opened from the table row or card.

  The parent fetches the log before showing the modal (a failed fetch toasts
  and never opens it) and owns the entry, so refresh is an emit; copying the
  already-displayed text is handled here.
-->
<template>
  <div class="modal-bg" @click.self="emit('close')" role="presentation">
    <div ref="panel" class="modal log-modal" role="dialog" aria-modal="true" aria-labelledby="svc-log-title">
      <div class="drawer-head">
        <div>
          <h2 id="svc-log-title" class="drawer-title">{{ finiteText(recGet(entry, 'name'), '') || finiteText(recGet(entry, 'id')) }} — {{ t('services.logs') }}</h2>
          <div class="mono sub-id">{{ finiteText(recGet(entry, 'source')) }}</div>
        </div>
        <div class="drawer-actions">
          <button type="button" class="tiny" @click="emit('refresh')">{{ t('common.refresh') }}</button>
          <button type="button" class="tiny" @click="copyLog">{{ t('services.copy_log') }}</button>
          <button type="button" @click="emit('close')">{{ t('common.close') }}</button>
        </div>
      </div>
      <!-- tabindex=0: the pane scrolls inside a fixed-height modal, and a
           scrollable region the keyboard cannot reach cannot be scrolled by
           one (WCAG 2.1.1). -->
      <pre class="log" tabindex="0" role="region" :aria-label="t('services.logs')">{{ finiteText(recGet(entry, 'log'), '') || t('services.log_empty') }}</pre>
    </div>
  </div>
</template>

<script setup>
import { inject, onUnmounted, ref } from 'vue'
import { injectI18n } from '../i18n'
import { finiteText, recGet } from '../lib/finite'
import { copyToClipboard } from '../lib/clipboard'
import { useDismissable } from '../composables/useDismissable'

const toast = inject('toast')
const { t } = injectI18n()

const props = defineProps({
  /** { id, name, source, log } as assembled by the parent from /api/services/{id}/logs. */
  entry: { type: Object, required: true },
})

const emit = defineEmits(['close', 'refresh'])

const panel = ref(null)

let pageAlive = true
onUnmounted(() => { pageAlive = false })

async function copyLog() {
  const ok = await copyToClipboard(recGet(props.entry, 'log'))
  if (!pageAlive) return
  toast(ok ? '✅' : '❌')
}

// The parent v-ifs this component, so its lifetime is the dialog's open
// state; watching the entry prop keeps the pre-extraction behaviour of
// re-running the open branch when a refresh replaces the entry.
useDismissable(() => props.entry, () => emit('close'), panel)
</script>

<style scoped>
.drawer-head { display: flex; justify-content: space-between; gap: 12px; align-items: flex-start; margin-bottom: 14px; flex-wrap: wrap; }
.drawer-title { margin: 0; font-size: 18px; font-weight: 700; overflow-wrap: anywhere; }
.drawer-actions { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 14px; }
.sub-id { font-size: 10px; color: var(--sub); margin-top: 2px; }
.log-modal { width: min(900px, 100%); height: min(80vh, 720px); }
.log-modal .log { flex: 1; min-height: 0; }
</style>
