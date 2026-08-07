<template>
  <div class="lc">
    <div class="lc-plot" :style="{ height: height + 'px' }">
      <!-- HTML Y labels — never stretched -->
      <div class="y-axis">
        <span
          v-for="(g, i) in ticks"
          :key="'yl'+i"
          class="y-lbl"
          :style="{ top: g.pct + '%' }"
        >{{ g.label }}</span>
      </div>

      <div class="plot-body">
        <!-- SVG only for geometry; stretch OK, no text inside -->
        <svg
          class="lc-svg"
          :viewBox="`0 0 ${W} ${H}`"
          preserveAspectRatio="none"
        >
          <g class="grid">
            <line
              v-for="(g, i) in ticks"
              :key="'g'+i"
              :x1="0" :x2="W"
              :y1="g.y" :y2="g.y"
              stroke="currentColor"
              :stroke-opacity="g.value === 0 ? 0.16 : 0.08"
              vector-effect="non-scaling-stroke"
            />
          </g>

          <g v-for="(s, si) in drawn" :key="'s'+si">
            <polyline
              v-if="s.area"
              :points="s.area"
              :fill="s.color"
              opacity="0.1"
              stroke="none"
            />
            <polyline
              :points="s.line"
              fill="none"
              :stroke="s.color"
              stroke-width="2"
              stroke-linejoin="round"
              stroke-linecap="round"
              vector-effect="non-scaling-stroke"
            />
          </g>

          <line
            v-if="refY != null"
            :x1="0" :x2="W"
            :y1="refY" :y2="refY"
            stroke="var(--warn)"
            stroke-dasharray="4 3"
            stroke-opacity="0.7"
            stroke-width="1"
            vector-effect="non-scaling-stroke"
          />
        </svg>

        <!-- reference label in HTML -->
        <span
          v-if="refY != null"
          class="ref-tag"
          :style="{ top: refPct + '%' }"
        >{{ refLabel }}</span>
      </div>
    </div>

    <div class="lc-legend" v-if="legend.length">
      <span v-for="(s, i) in legend" :key="i" class="leg">
        <i :style="{ background: s.color }"></i>
        <span class="leg-name">{{ s.name }}</span>
        <b v-if="s.latest != null">{{ formatLegend(s.latest) }}</b>
      </span>
      <span v-if="unit" class="leg-unit">{{ unitHint }}</span>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { injectI18n } from '../i18n'

// refLabel formats the reference line, which is a localized string.  Without
// this the component threw a ReferenceError the moment any caller passed a
// `reference` prop -- latent only because no current caller does.
const { t } = injectI18n()

const props = defineProps({
  series: { type: Array, default: () => [] },
  height: { type: Number, default: 120 },
  min: { type: Number, default: null },
  max: { type: Number, default: null },
  reference: { type: Number, default: null },
  unit: { type: String, default: '' },
  decimals: { type: Number, default: 1 },
  percent: { type: Boolean, default: false },
})

// Plot coordinate space (lines only — text is HTML)
const W = 400
const H = 100
const PAD = { t: 4, r: 2, b: 4, l: 2 }

const isPercent = computed(() => props.percent || props.unit === '%')

const cleaned = computed(() =>
  (props.series || []).map(s => ({
    ...s,
    values: (s.values || []).map(v => (typeof v === 'number' && !Number.isNaN(v) ? v : null)),
  })).filter(s => s.values.some(v => v != null))
)

function niceNum(range, round) {
  if (range <= 0) return 1
  const exp = Math.floor(Math.log10(range))
  const f = range / 10 ** exp
  let nf
  if (round) {
    if (f < 1.5) nf = 1
    else if (f < 3) nf = 2
    else if (f < 7) nf = 5
    else nf = 10
  } else {
    if (f <= 1) nf = 1
    else if (f <= 2) nf = 2
    else if (f <= 5) nf = 5
    else nf = 10
  }
  return nf * 10 ** exp
}

function niceBounds(dataMin, dataMax, tickCount = 4) {
  let lo = dataMin
  let hi = dataMax
  if (lo === hi) {
    if (lo === 0) hi = 1
    else {
      lo = lo * 0.9
      hi = hi * 1.1
    }
  }
  const range = niceNum(hi - lo, false)
  const step = niceNum(range / Math.max(1, tickCount - 1), true)
  let niceLo = Math.floor(lo / step) * step
  let niceHi = Math.ceil(hi / step) * step
  if (Object.is(niceLo, -0)) niceLo = 0
  if (Object.is(niceHi, -0)) niceHi = 0
  return { lo: niceLo, hi: niceHi, step }
}

const scale = computed(() => {
  const all = []
  for (const s of cleaned.value) {
    for (const v of s.values) if (v != null) all.push(v)
  }
  if (props.reference != null) all.push(props.reference)

  if (isPercent.value) {
    const dataMax = all.length ? Math.max(...all) : 0
    const hi = props.max != null
      ? props.max
      : (dataMax > 100 ? Math.ceil(dataMax / 25) * 25 : 100)
    const lo = props.min != null ? props.min : 0
    const step = hi <= 100 ? 25 : niceNum((hi - lo) / 4, true)
    return { lo, hi: Math.max(hi, lo + step), step }
  }

  if (!all.length) return { lo: 0, hi: 1, step: 0.25 }

  let dataMin = props.min != null ? props.min : Math.min(...all)
  let dataMax = props.max != null ? props.max : Math.max(...all)
  if (props.max == null) dataMax = dataMax * 1.05
  if (props.min === 0 || (props.min == null && dataMin >= 0)) {
    dataMin = Math.min(0, dataMin)
  }
  return niceBounds(dataMin, dataMax, 5)
})

function roundTick(v, step) {
  if (step >= 1) return Math.round(v * 1000) / 1000
  const dec = Math.max(0, -Math.floor(Math.log10(step)) + 1)
  return Number(v.toFixed(dec))
}

function yOf(v) {
  const { lo, hi } = scale.value
  const plotH = H - PAD.t - PAD.b
  const span = hi - lo || 1
  return PAD.t + plotH - ((v - lo) / span) * plotH
}

function yPct(v) {
  // percentage from top of plot for HTML absolute positioning
  return (yOf(v) / H) * 100
}

function xOf(i, n) {
  const plotW = W - PAD.l - PAD.r
  if (n <= 1) return PAD.l
  return PAD.l + (i / (n - 1)) * plotW
}

const ticks = computed(() => {
  const { lo, hi, step } = scale.value
  const out = []
  if (!step || !Number.isFinite(step)) {
    return [{ value: lo, y: yOf(lo), pct: yPct(lo), label: formatTick(lo) }]
  }
  const maxTicks = 12
  let v = lo
  let n = 0
  while (v <= hi + step * 0.001 && n < maxTicks) {
    const val = roundTick(v, step)
    out.push({
      value: val,
      y: yOf(val),
      pct: yPct(val),
      label: formatTick(val),
    })
    v += step
    n++
  }
  if (out.length && Math.abs(out[out.length - 1].value - hi) > step * 0.1) {
    out.push({
      value: hi,
      y: yOf(hi),
      pct: yPct(hi),
      label: formatTick(hi),
    })
  }
  return out
})

const drawn = computed(() => {
  return cleaned.value.map(s => {
    const vals = s.values
    const n = vals.length
    const pts = []
    for (let i = 0; i < n; i++) {
      if (vals[i] == null) continue
      const vv = Math.min(scale.value.hi, Math.max(scale.value.lo, vals[i]))
      pts.push(`${xOf(i, n)},${yOf(vv)}`)
    }
    if (pts.length < 2) return { line: '', area: '', color: s.color }
    const line = pts.join(' ')
    const area = `${pts[0].split(',')[0]},${H - PAD.b} ${line} ${pts[pts.length - 1].split(',')[0]},${H - PAD.b}`
    return { line, area, color: s.color || 'var(--accent)' }
  })
})

const refY = computed(() =>
  props.reference != null ? yOf(props.reference) : null
)
const refPct = computed(() =>
  props.reference != null ? yPct(props.reference) : null
)

const refLabel = computed(() => {
  if (props.reference == null) return ''
  const r = props.reference
  return Number.isInteger(r) ? t('common.cores_n', { n: r }) : r.toFixed(1)
})

const legend = computed(() =>
  cleaned.value.map(s => {
    let latest = null
    for (let i = s.values.length - 1; i >= 0; i--) {
      if (s.values[i] != null) { latest = s.values[i]; break }
    }
    return { name: s.name, color: s.color, latest }
  })
)

const unitHint = computed(() => {
  if (props.unit === '%') return '%'
  return props.unit || ''
})

function formatTick(v) {
  if (v == null || Number.isNaN(v)) return ''
  if (isPercent.value) return String(Math.round(v))
  const abs = Math.abs(v)
  if (abs >= 100) return String(Math.round(v))
  if (abs >= 10) return String(Math.round(v * 10) / 10)
  if (Number.isInteger(v) || Math.abs(v - Math.round(v)) < 1e-9) return String(Math.round(v))
  const d = props.decimals <= 1 ? 1 : props.decimals
  return v.toFixed(d).replace(/\.0+$/, '').replace(/(\.\d*?)0+$/, '$1')
}

function formatLegend(v) {
  if (v == null || Number.isNaN(v)) return '—'
  if (isPercent.value) {
    const rounded = Math.round(v * 10) / 10
    if (Math.abs(rounded - Math.round(rounded)) < 0.05) return `${Math.round(rounded)}%`
    return `${rounded.toFixed(1)}%`
  }
  if (Math.abs(v) >= 100) return String(Math.round(v))
  return Number(v.toFixed(props.decimals)).toString()
}
</script>

<style scoped>
.lc { width: 100%; }

.lc-plot {
  display: flex;
  width: 100%;
  gap: 0;
  min-height: 60px;
  background: color-mix(in srgb, var(--bg) 50%, var(--card));
  border-radius: var(--radius-sm);
  border: 1px solid color-mix(in srgb, var(--line) 60%, transparent);
  padding: 4px 4px 4px 0;
}

/* Y labels in real HTML — fixed aspect, no SVG stretch */
.y-axis {
  position: relative;
  width: 34px;
  flex: none;
  margin-right: 4px;
}
.y-lbl {
  position: absolute;
  right: 0;
  transform: translateY(-50%);
  font-size: 10px;
  line-height: 1;
  color: var(--sub);
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-variant-numeric: tabular-nums;
  font-weight: 500;
  white-space: nowrap;
  user-select: none;
  opacity: .8;
}

.plot-body {
  position: relative;
  flex: 1;
  min-width: 0;
  height: 100%;
  border-left: 1px solid color-mix(in srgb, var(--line) 70%, transparent);
}

.lc-svg {
  position: absolute;
  inset: 0;
  width: 100%;
  height: 100%;
  display: block;
  color: var(--sub);
  overflow: visible;
}

.ref-tag {
  position: absolute;
  right: 4px;
  transform: translateY(-100%);
  font-size: 10px;
  line-height: 1.2;
  color: var(--warn);
  font-family: ui-monospace, Menlo, monospace;
  font-weight: 600;
  background: color-mix(in srgb, var(--card) 88%, transparent);
  padding: 1px 6px;
  border-radius: 3px;
  border: 1px solid color-mix(in srgb, var(--warn) 25%, transparent);
  pointer-events: none;
  white-space: nowrap;
}

.lc-legend {
  display: flex;
  flex-wrap: wrap;
  gap: 6px 10px;
  margin-top: 7px;
  font-size: 11px;
  color: var(--sub);
  align-items: center;
}
.leg {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  background: var(--bg);
  border: 1px solid var(--line);
  border-radius: var(--radius-pill);
  padding: 2px 9px 2px 6px;
  line-height: 1.2;
  transition: border-color .12s;
}
.leg:hover { border-color: var(--accent); }
.leg i {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  display: inline-block;
  flex: none;
  box-shadow: 0 0 3px currentColor;
}
.leg-name {
  font-weight: 600;
  font-size: 11px;
}
.leg b {
  color: var(--txt);
  font-weight: 700;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-variant-numeric: tabular-nums;
  font-size: 11px;
  margin-left: 1px;
}
.leg-unit {
  margin-left: auto;
  font-size: 10px;
  opacity: 0.5;
}
</style>
