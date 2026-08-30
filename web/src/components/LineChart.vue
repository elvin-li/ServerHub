<template>
  <div class="lc" :class="{ quiet: quiet, stacked: stacked, fill: fill }">
    <div v-if="title" class="lc-title">{{ finiteText(title) }}</div>
    <div class="lc-plot">
      <div class="plot-row" :style="plotStyle">
        <!-- HTML Y labels — never stretched -->
        <div v-if="!quiet" class="y-axis">
          <span
            v-for="(g, i) in asArray(ticks)"
            :key="'yl'+i"
            class="y-lbl"
            :style="{ top: asRecord(g).pct + '%' }"
          >{{ finiteText(asRecord(g).label) }}</span>
        </div>

        <div class="plot-body">
          <!-- SVG only for geometry; stretch OK, no text inside -->
          <svg
            class="lc-svg"
            :viewBox="`0 0 ${W} ${H}`"
            preserveAspectRatio="none"
          >
            <g v-if="!quiet" class="grid">
              <line
                v-for="(g, i) in asArray(ticks)"
                :key="'g'+i"
                :x1="0" :x2="W"
                :y1="asRecord(g).y" :y2="asRecord(g).y"
                stroke="currentColor"
                :stroke-opacity="asRecord(g).value === 0 ? 0.16 : 0.08"
                vector-effect="non-scaling-stroke"
              />
            </g>

            <g v-for="(s, si) in asArray(drawn)" :key="'s'+si">
              <polygon
                v-for="(area, ai) in asArray(asRecord(s).polys)"
                :key="'p'+ai"
                :points="area"
                :fill="asRecord(s).color"
                :opacity="asRecord(s).fillOpacity"
                stroke="none"
              />
              <polyline
                v-for="(area, ai) in asArray(asRecord(s).areas)"
                :key="'a'+ai"
                :points="area"
                :fill="asRecord(s).color"
                :opacity="asRecord(s).fillOpacity"
                stroke="none"
              />
              <polyline
                v-for="(line, li) in asArray(asRecord(s).lines)"
                :key="'l'+li"
                :points="line"
                fill="none"
                :stroke="asRecord(s).color"
                :stroke-width="stacked ? 1.25 : 2"
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
          >{{ finiteText(refLabel) }}</span>
        </div>
      </div>
      <!-- HTML X labels — never stretched. Spacer matches the Y column so
           labels sit under the plot, first/last on the time extent ends. -->
      <div v-if="asArray(xTicks).length" class="x-axis-row">
        <div v-if="!quiet" class="x-spacer"></div>
        <div :ref="bindAxis" class="x-axis" :class="{ 'two-line': xAxisTwoLine }">
          <span
            v-for="(g, i) in asArray(xTicks)"
            :key="'xl'+i"
            class="x-lbl"
            :class="{ first: i === 0, last: i === asArray(xTicks).length - 1 }"
            :style="{ left: asRecord(g).pct + '%' }"
          >{{ finiteText(asRecord(g).label) }}</span>
        </div>
      </div>
    </div>

    <div class="lc-legend" v-if="asArray(legend).length && !quiet">
      <span v-for="(s, i) in asArray(legend)" :key="finiteText(asRecord(s).name) + ':' + i" class="leg">
        <i :style="{ background: asRecord(s).color }"></i>
        <span class="leg-name">{{ finiteText(asRecord(s).name) }}</span>
        <b v-if="asRecord(s).latest != null">{{ formatLegend(asRecord(s).latest) }}</b>
      </span>
      <span v-if="unit" class="leg-unit">{{ finiteText(unitHint) }}</span>
    </div>
  </div>
</template>

<script setup>
import { computed, onBeforeUnmount, ref } from 'vue'
import { injectI18n } from '../i18n'
import { asArray, asRecord, finiteN, finiteText } from '../lib/finite'

// refLabel formats the reference line, which is a localized string.  Without
// this the component threw a ReferenceError the moment any caller passed a
// `reference` prop -- latent only because no current caller does.
const { t } = injectI18n()

const props = defineProps({
  series: { type: [Array, Object], default: () => [] },
  // Epoch seconds aligned with series values. When two or more finite
  // timestamps exist, x is (t - tMin) / (tMax - tMin) so a rollup that
  // omitted a window leaves a gap instead of compressing time.
  times: { type: [Array, Object], default: null },
  height: { type: Number, default: 120 },
  min: { type: Number, default: null },
  max: { type: Number, default: null },
  reference: { type: Number, default: null },
  unit: { type: String, default: '' },
  decimals: { type: Number, default: 1 },
  percent: { type: Boolean, default: false },
  /** Stack series bottom→top (Activity Monitor CPU LOAD style). */
  stacked: { type: Boolean, default: false },
  /** Hide grid / soften chrome for Apple-quiet plots. */
  quiet: { type: Boolean, default: false },
  /** Optional centered chart title (e.g. "CPU LOAD"). */
  title: { type: String, default: '' },
  /** Area fill opacity (outline stays opaque). Defaults: stacked 0.72, else 0.1. */
  areaOpacity: { type: Number, default: null },
  /** Stretch the plot to the parent column; `height` is the minimum. */
  fill: { type: Boolean, default: false },
})

const plotStyle = computed(() => (
  props.fill
    ? { minHeight: `${props.height}px`, flex: '1 1 auto' }
    : { height: `${props.height}px` }
))

// Plot coordinate space (lines only — text is HTML)
const W = 400
const H = 100
const PAD = { t: 4, r: 2, b: 4, l: 2 }

const isPercent = computed(() => props.percent || props.unit === '%')

const cleaned = computed(() =>
  asArray(props.series).map(s => {
    const rec = asRecord(s)
    return {
      ...rec,
      values: asArray(rec.values).map(v => (typeof v === 'number' && Number.isFinite(v) ? v : null)),
    }
  }).filter(s => asArray(asRecord(s).values).some(v => v != null))
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
  if (props.stacked) {
    // Stacked totals drive the y-scale.
    const seriesList = asArray(cleaned.value)
    const n = Math.max(0, ...seriesList.map(s => asArray(asRecord(s).values).length))
    for (let i = 0; i < n; i++) {
      let sum = 0
      let any = false
      for (const s of seriesList) {
        const v = asArray(asRecord(s).values)[i]
        if (v != null && Number.isFinite(v)) {
          sum += Math.max(0, v)
          any = true
        }
      }
      if (any) all.push(sum)
    }
  } else {
    for (const s of asArray(cleaned.value)) {
      for (const v of asArray(asRecord(s).values)) if (v != null) all.push(v)
    }
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

const timeExtent = computed(() => {
  const ts = asArray(props.times)
  if (!ts.length) return null
  let lo = Infinity
  let hi = -Infinity
  for (const epoch of ts) {
    if (typeof epoch === 'number' && Number.isFinite(epoch)) {
      if (epoch < lo) lo = epoch
      if (epoch > hi) hi = epoch
    }
  }
  if (!Number.isFinite(lo) || !Number.isFinite(hi) || hi <= lo) return null
  return { lo, hi }
})

function pad2(n) {
  return String(n).padStart(2, '0')
}

function formatTimeTick(epochSec, spanSec) {
  const d = new Date(epochSec * 1000)
  if (!Number.isFinite(d.getTime())) return ''
  const hm = `${pad2(d.getHours())}:${pad2(d.getMinutes())}`
  const md = `${d.getMonth() + 1}/${d.getDate()}`
  if (spanSec <= 36 * 3600) return hm
  // Two lines keep date+time ~half as wide as `M/D HH:MM` in a narrow plot.
  if (spanSec <= 10 * 86400) return `${md}\n${hm}`
  return md
}

// Dense HH:MM ticks fit a narrow plot; `M/D HH:MM` (~36h–10d) needs fewer.
const X_TICK_COUNT_SHORT = 5
const X_TICK_COUNT_LONG = 3

//: Width one label needs before the next may start. Every format the axis
//: emits is at most five monospace characters (`HH:MM`, `12/31`, and the wider
//: line of the two-line `M/D`+`HH:MM`), which is ~30px at the 10px font below;
//: the rest is the smallest gap that still reads as two separate labels.
const X_LABEL_MIN_PX = 38

function xTickCount(spanSec) {
  if (spanSec > 36 * 3600 && spanSec <= 10 * 86400) return X_TICK_COUNT_LONG
  return X_TICK_COUNT_SHORT
}

//: Live width of the label strip, or 0 before/without a ResizeObserver.
const axisWidth = ref(0)
let axisObserver = null
let axisEl = null

/**
 * Track the label strip's width so the tick count can fit it.
 *
 * The dashboard puts two charts side by side inside one card, which leaves each
 * x-axis ~110px: five `HH:MM` labels do not fit and rendered as `11:1711:32`.
 * A template ref rather than onMounted because the row is behind v-if, and a
 * width of 0 (no ResizeObserver, e.g. jsdom) keeps the full tick count.
 */
function bindAxis(el) {
  // Vue re-invokes a template ref on every patch of its element, so without
  // this the observer would be torn down and rebuilt on each metrics tick.
  if (el === axisEl) return
  axisEl = el
  if (axisObserver) {
    axisObserver.disconnect()
    axisObserver = null
  }
  if (!el || typeof ResizeObserver === 'undefined') {
    axisWidth.value = 0
    return
  }
  axisWidth.value = el.getBoundingClientRect().width || 0
  // Safe against resize loops: .x-axis is a flex child whose labels are
  // absolutely positioned, so how many we draw cannot change its width.
  axisObserver = new ResizeObserver((entries) => {
    axisWidth.value = entries[0]?.contentRect?.width || 0
  })
  axisObserver.observe(el)
}

onBeforeUnmount(() => {
  axisObserver?.disconnect()
  axisObserver = null
  axisEl = null
})

const xTicks = computed(() => {
  if (props.quiet) return []
  const ext = timeExtent.value
  if (!ext) return []
  const span = ext.hi - ext.lo
  if (!(span > 0)) return []
  let n = xTickCount(span)
  // A leftover non-finite rect would make the tick count NaN, and the loop
  // below would then emit no labels at all rather than too many.
  const width = axisWidth.value
  if (Number.isFinite(width) && width > 0) {
    n = Math.max(2, Math.min(n, Math.floor(width / X_LABEL_MIN_PX)))
  }
  const out = []
  for (let i = 0; i < n; i++) {
    const frac = i / (n - 1)
    const epoch = ext.lo + span * frac
    out.push({
      pct: frac * 100,
      label: formatTimeTick(epoch, span),
    })
  }
  return out
})

const xAxisTwoLine = computed(() =>
  xTicks.value.some((g) => String(asRecord(g).label).includes('\n'))
)

function xOf(i, n) {
  const plotW = W - PAD.l - PAD.r
  const ext = timeExtent.value
  if (ext) {
    const t = asArray(props.times)[i]
    if (typeof t === 'number' && Number.isFinite(t)) {
      return PAD.l + ((t - ext.lo) / (ext.hi - ext.lo)) * plotW
    }
  }
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

const fillOpacity = computed(() => {
  if (props.areaOpacity != null) return props.areaOpacity
  return props.stacked ? 0.72 : 0.1
})

const drawn = computed(() => {
  const seriesList = asArray(cleaned.value)
  if (!seriesList.length) return []
  const fill = fillOpacity.value

  if (!props.stacked) {
    return seriesList.map(s => {
      const vals = asArray(asRecord(s).values)
      const n = vals.length
      const lines = []
      const areas = []
      let pts = []
      const flush = () => {
        if (pts.length >= 2) {
          const line = pts.join(' ')
          lines.push(line)
          areas.push(`${pts[0].split(',')[0]},${H - PAD.b} ${line} ${pts[pts.length - 1].split(',')[0]},${H - PAD.b}`)
        }
        pts = []
      }
      for (let i = 0; i < n; i++) {
        if (vals[i] == null) {
          flush()
          continue
        }
        const vv = Math.min(scale.value.hi, Math.max(scale.value.lo, vals[i]))
        pts.push(`${xOf(i, n)},${yOf(vv)}`)
      }
      flush()
      return { lines, areas, polys: [], color: asRecord(s).color || 'var(--accent)', fillOpacity: fill }
    })
  }

  // Stacked: bottom→top cumulative bands (Activity Monitor CPU LOAD).
  const n = Math.max(...seriesList.map(s => asArray(asRecord(s).values).length), 0)
  const base = new Array(n).fill(0)
  const out = []
  for (const s of seriesList) {
    const topLine = []
    const polyPts = []
    for (let i = 0; i < n; i++) {
      const raw = asArray(asRecord(s).values)[i]
      const x = xOf(i, n)
      if (raw == null || !Number.isFinite(raw)) {
        // Gap: close any open poly later by splitting — keep continuous for demo simplicity.
        continue
      }
      const lo = base[i]
      const hi = lo + Math.max(0, raw)
      base[i] = hi
      const yTop = yOf(Math.min(scale.value.hi, Math.max(scale.value.lo, hi)))
      const yBot = yOf(Math.min(scale.value.hi, Math.max(scale.value.lo, lo)))
      topLine.push(`${x},${yTop}`)
      polyPts.push({ x, yTop, yBot })
    }
    // Build closed polygon: top L→R then bottom R→L
    const polys = []
    const lines = []
    if (polyPts.length >= 2) {
      const top = polyPts.map(p => `${p.x},${p.yTop}`).join(' ')
      const bot = [...polyPts].reverse().map(p => `${p.x},${p.yBot}`).join(' ')
      polys.push(`${top} ${bot}`)
      lines.push(top)
    }
    out.push({
      lines,
      areas: [],
      polys,
      color: asRecord(s).color || 'var(--accent)',
      fillOpacity: fill,
    })
  }
  return out
})

const refY = computed(() =>
  props.reference != null ? yOf(props.reference) : null
)
const refPct = computed(() =>
  props.reference != null ? yPct(props.reference) : null
)

const refLabel = computed(() => {
  const r = finiteN(props.reference, null)
  if (r == null || !Number.isFinite(Number(props.reference))) return ''
  return Number.isInteger(r) ? t('common.cores_n', { n: r }) : r.toFixed(1)
})

const legend = computed(() =>
  asArray(cleaned.value).map(s => {
    let latest = null
    const vals = asArray(asRecord(s).values)
    for (let i = vals.length - 1; i >= 0; i--) {
      if (vals[i] != null) { latest = vals[i]; break }
    }
    return { name: asRecord(s).name, color: asRecord(s).color, latest }
  })
)

const unitHint = computed(() => {
  if (props.unit === '%') return '%'
  return props.unit || ''
})

function formatTick(v) {
  if (v == null || !Number.isFinite(v)) return ''
  if (isPercent.value) return String(Math.round(v))
  const abs = Math.abs(v)
  if (abs >= 100) return String(Math.round(v))
  if (abs >= 10) return String(Math.round(v * 10) / 10)
  if (Number.isInteger(v) || Math.abs(v - Math.round(v)) < 1e-9) return String(Math.round(v))
  const d = props.decimals <= 1 ? 1 : props.decimals
  return v.toFixed(d).replace(/\.0+$/, '').replace(/(\.\d*?)0+$/, '$1')
}

function formatLegend(v) {
  if (v == null || !Number.isFinite(v)) return '—'
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
.lc.fill {
  display: flex;
  flex-direction: column;
  height: 100%;
  min-height: 0;
}
.lc.fill .lc-plot {
  flex: 1 1 auto;
  min-height: 0;
  display: flex;
  flex-direction: column;
}
.lc.fill .plot-row { flex: 1 1 auto; min-height: 0; }

.lc-title {
  text-align: center;
  font-size: 10px;
  font-weight: 600;
  letter-spacing: .08em;
  text-transform: uppercase;
  color: var(--sub);
  margin: 0 0 4px;
  padding-bottom: 4px;
  border-bottom: 1px solid color-mix(in srgb, var(--line) 70%, transparent);
}
.lc.quiet .lc-title {
  border-bottom: none;
  padding-bottom: 0;
}
:global([data-theme="macos"] .lc-title),
:global([data-theme="macos-dark"] .lc-title) {
  border-bottom: none;
  padding-bottom: 0;
}

.lc-plot {
  display: flex;
  flex-direction: column;
  width: 100%;
  gap: 0;
  min-height: 60px;
  background: color-mix(in srgb, var(--bg) 50%, var(--card));
  border-radius: var(--radius-sm);
  border: 1px solid color-mix(in srgb, var(--line) 60%, transparent);
  padding: 4px 4px 4px 0;
}
.plot-row {
  display: flex;
  width: 100%;
  gap: 0;
  min-height: 0;
  min-width: 0;
}

.lc.quiet .lc-plot {
  background: var(--card);
  border: 1px solid var(--line);
  border-radius: var(--radius);
  padding: 4px;
}
:global([data-theme="macos"] .lc-plot),
:global([data-theme="macos-dark"] .lc-plot) {
  border: none;
  background: transparent;
}
:global([data-theme="macos"] .lc.quiet .lc-plot),
:global([data-theme="macos-dark"] .lc.quiet .lc-plot) {
  background: transparent;
  border: none;
  border-radius: 0;
  padding: 0;
  backdrop-filter: none;
  -webkit-backdrop-filter: none;
}
.lc.quiet .plot-body { border-left: none; }

/* Y labels in real HTML — fixed aspect, no SVG stretch.
   Axis labels take --sub at full strength: they are 10px, and the extra
   opacity: .8 they used to carry pushed the effective colour to #8b8b8f on
   white, i.e. 3.4:1, under the AA floor for text that small. --sub is already
   the muted tone each theme picked, so dimming it twice was the bug. */
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
  /* No extra opacity: --sub is already the muted-text token and clears WCAG AA
     on the card (5.07:1), but multiplying it by .8 blended it back toward the
     surface to 3.39:1 — every axis label on every chart failed AA at 10px. */
}

.plot-body {
  position: relative;
  flex: 1;
  min-width: 0;
  min-height: 0;
  height: 100%;
  border-left: 1px solid color-mix(in srgb, var(--line) 70%, transparent);
}

.x-axis-row {
  display: flex;
  width: 100%;
  flex: none;
  min-width: 0;
  margin-top: 2px;
}
.x-spacer {
  width: 34px;
  flex: none;
  margin-right: 4px;
}
.x-axis {
  position: relative;
  flex: 1;
  min-width: 0;
  height: 16px;
}
.x-axis.two-line { height: 26px; }
.x-lbl {
  position: absolute;
  top: 0;
  transform: translateX(-50%);
  font-size: 10px;
  line-height: 1.15;
  color: var(--sub);
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-variant-numeric: tabular-nums;
  font-weight: 500;
  white-space: pre;
  text-align: center;
  user-select: none;
  /* No extra opacity, for the same reason as .y-lbl above. */
}
.x-lbl.first { transform: none; text-align: left; }
.x-lbl.last { transform: translateX(-100%); text-align: right; }

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
  color: var(--warn-text);
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
