<!--
  Banner for a first load that failed.

  Completes the three states a data-backed page actually has. The skeleton work
  established two of them — pending and loaded — but a failed load fell into the
  "loaded" branch and rendered the *empty* state, which is the same false claim
  the skeletons were added to remove: "no backups", "no alerts", "no disks",
  asserted because the request failed rather than because the list is empty.

  A toast cannot carry this. It is gone in four seconds, while the wrong empty
  state stays on screen indefinitely and offers no way to retry.

  Rendered above the content rather than instead of it: on a *re*-load failure the
  previously fetched rows are still the best information available, and blanking
  them would lose data the operator was reading.
-->
<template>
  <div class="load-failure" role="alert">
    <div class="row">
      <span class="name">{{ message || t('common.load_failed') }}</span>
      <button v-if="retry" class="tiny" :disabled="busy" @click="retry">
        {{ t('common.retry') }}
      </button>
    </div>
    <!-- The server's own wording, kept verbatim: it names the failing tool and is
         usually the only actionable detail. -->
    <div v-if="detail" class="sub mono load-failure-detail">{{ detail }}</div>
  </div>
</template>

<script setup>
import { injectI18n } from '../i18n'

const { t } = injectI18n()

defineProps({
  /** Headline. Defaults to a generic "could not load" line. */
  message: { type: String, default: '' },
  /** Raw error text from the failed request. */
  detail: { type: String, default: '' },
  /** Omit to render the banner without a retry button. */
  retry: { type: Function, default: null },
  /** Disables the retry button while a load is already running. */
  busy: { type: Boolean, default: false },
})
</script>

<style scoped>
/* Matches the existing danger-tinted callout used by Dashboard and WireGuard:
   card surface, red left rule, sitting in the normal flow. */
.load-failure {
  margin-bottom: var(--sp-6);
  padding: var(--pad-tile, 10px 12px);
  background: var(--card);
  border: 1px solid color-mix(in srgb, var(--down) 25%, var(--line));
  border-left: 3px solid var(--down);
  border-radius: var(--radius);
  box-shadow: var(--card-shadow);
}
.load-failure-detail {
  margin-top: var(--sp-2);
  /* Tool stderr can be one long unbroken line. */
  overflow-wrap: anywhere;
}
</style>
