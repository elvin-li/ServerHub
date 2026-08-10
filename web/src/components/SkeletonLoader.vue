<!--
  Shimmer placeholder for a region whose data has not arrived yet.

  This exists because most list pages rendered their *empty* state during the
  first load: `v-if="!rows.length"` is true both before the request resolves and
  after it returns nothing, so opening Audit or Backups on a slow host showed
  "no records" and then flipped to a full table. That reads as a bug rather than
  as loading, and it is the reason the empty-state copy could not be trusted.

  Variants mirror the layouts the app actually uses (styles.css): a bordered
  `.table-wrap`, a `.grid` of `.card`s, a 12-column `.dash-grid` of `.tile`s, and
  a stacked `.alert-list`. Pick the one matching what will replace it, otherwise
  the page jumps when real content lands.

  Accessibility: the bars are decorative, so they are hidden from the
  accessibility tree and the wrapper carries the announcement instead. Assistive
  tech hears "Loading…" once, not one entry per shimmer bar.
-->
<template>
  <div
    class="sk-wrap"
    role="status"
    aria-busy="true"
    :aria-label="label || t('common.loading')"
  >
    <!-- Bordered table shell: header strip plus evenly divided body rows. -->
    <div v-if="variant === 'table'" class="table-wrap" aria-hidden="true">
      <div class="sk-row sk-head" :style="gridStyle">
        <span v-for="c in cols" :key="c" class="skeleton sk-cell"></span>
      </div>
      <div v-for="r in rows" :key="r" class="sk-row" :style="gridStyle">
        <span v-for="c in cols" :key="c" class="skeleton sk-cell"></span>
      </div>
    </div>

    <!-- Auto-filling card grid, as used by Apps / Bookmarks / Services. -->
    <div v-else-if="variant === 'cards'" class="grid" aria-hidden="true">
      <div v-for="r in rows" :key="r" class="card">
        <div class="skeleton skeleton-title"></div>
        <div class="skeleton skeleton-text" style="width:90%"></div>
        <div class="skeleton skeleton-text" style="width:65%;margin-bottom:0"></div>
      </div>
    </div>

    <!-- Dashboard-style metric tiles on the shared 12-column grid. -->
    <div v-else-if="variant === 'tiles'" class="dash-grid" aria-hidden="true">
      <div v-for="r in rows" :key="r" class="tile" :class="`span-${span}`">
        <div class="skeleton skeleton-title"></div>
        <div class="skeleton skeleton-card" :style="{ height: tileHeight + 'px' }"></div>
      </div>
    </div>

    <!-- Flat stacked rows for log/alert style lists. -->
    <div v-else class="alert-list" aria-hidden="true">
      <div v-for="r in rows" :key="r" class="alert-item">
        <span class="skeleton sk-dot"></span>
        <span class="skeleton sk-cell" style="flex:1"></span>
        <span class="skeleton sk-cell" style="width:72px;flex:none"></span>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { injectI18n } from '../i18n'

const { t } = injectI18n()

const props = defineProps({
  /** Which of the app's existing layouts this placeholder stands in for. */
  variant: {
    type: String,
    default: 'table',
    validator: v => ['table', 'cards', 'tiles', 'list'].includes(v),
  },
  /** Placeholder rows / cards / tiles to draw. */
  rows: { type: Number, default: 5 },
  /** Columns for the `table` variant. Match the real table so widths line up. */
  cols: { type: Number, default: 5 },
  /** Grid span for the `tiles` variant (4 = three across, 6 = two across). */
  span: { type: Number, default: 4 },
  /** Body height for the `tiles` variant. */
  tileHeight: { type: Number, default: 96 },
  /** Overrides the announced text when "Loading…" is too vague. */
  label: { type: String, default: '' },
})

const gridStyle = computed(() => ({
  gridTemplateColumns: `repeat(${props.cols}, minmax(0, 1fr))`,
}))
</script>

<style scoped>
/* The wrapper must not introduce its own box: it replaces content that already
   sits in the page's normal flow, so any extra padding would shift the layout
   at the moment real data swaps in. */
.sk-wrap { display: block; }

.sk-row {
  display: grid;
  gap: var(--sp-3, 10px);
  align-items: center;
  padding: var(--table-pad, 7px 10px);
  border-bottom: 1px solid var(--line);
}
/* Mirrors `table.dense th`: tinted strip, heavier rule under it. */
.sk-head {
  background: var(--table-head);
  border-bottom-width: 2px;
}
.sk-row:last-child { border-bottom: none; }

.sk-cell {
  display: block;
  height: 11px;
  /* .skeleton-text carries a bottom margin for stacked text; inside a row the
     cells are grid items and that margin would offset them from centre. */
  margin: 0;
}
.sk-dot {
  width: 9px;
  height: 9px;
  border-radius: 50%;
  flex: none;
}
</style>
