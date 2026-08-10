<template>
  <div class="stack" :title="title">
    <div class="track">
      <i
        v-for="(seg, i) in segs"
        :key="i"
        :style="{ width: seg.pct + '%', background: seg.color }"
        :title="seg.label + ': ' + seg.value"
      ></i>
    </div>
    <div class="stack-legend" v-if="showLegend">
      <span v-for="(seg, i) in segs" :key="i">
        <i :style="{ background: seg.color }"></i>{{ seg.label }} {{ format(seg.value) }}{{ unit }}
      </span>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  /** [{ label, value, color }] */
  segments: { type: Array, default: () => [] },
  total: { type: Number, default: 100 },
  unit: { type: String, default: '%' },
  showLegend: { type: Boolean, default: true },
  title: { type: String, default: '' },
  decimals: { type: Number, default: 1 },
})

const segs = computed(() => {
  const t = props.total || 100
  return (props.segments || [])
    .filter(s => s && s.value != null && s.value > 0)
    .map(s => ({
      ...s,
      pct: Math.max(0.4, Math.min(100, (s.value / t) * 100)),
    }))
})

function format(v) {
  if (v == null) return '—'
  return Number(v).toFixed(props.decimals)
}
</script>

<style scoped>
.stack { width: 100%; }
.track {
  height: 16px;
  background: var(--bar-track);
  border-radius: var(--radius-sm);
  overflow: hidden;
  display: flex;
  border: 1px solid color-mix(in srgb, var(--line) 60%, transparent);
}
.track i {
  display: block; height: 100%; min-width: 1px;
  transition: width .4s ease;
}
.stack-legend {
  display: flex; flex-wrap: wrap; gap: 6px 12px;
  margin-top: 6px; font-size: 11px; color: var(--sub);
}
.stack-legend i {
  width: 8px; height: 8px; border-radius: 2px;
  display: inline-block; margin-right: 4px;
  box-shadow: 0 0 2px currentColor;
}
</style>
