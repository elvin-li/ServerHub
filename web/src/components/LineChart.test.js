/**
 * Axis math for the only chart in the panel.
 *
 * LineChart draws every metric graph on the dashboard, and all of its geometry
 * comes from three pure-ish computed properties -- `scale`, `ticks` and `drawn`.
 * None of them had a single test: `mountAll.test.js` proves the component does
 * not throw, and `a11y.test.js` only reads its source, so a wrong tick step or an
 * inverted y-axis would render a plausible-looking chart with wrong numbers on it.
 * That is the failure mode worth guarding -- a crash is obvious, a silently
 * mis-scaled CPU graph is not.
 *
 * The assertions read the rendered DOM rather than reaching into internals,
 * because the y labels are HTML (deliberately, so SVG stretch cannot distort
 * them) while the lines are SVG: the split between the two is itself part of the
 * contract. Expected values are computed by hand from the component's stated
 * coordinate space (W=400, H=100, PAD t/b=4) so a regression cannot quietly
 * redefine what "correct" means.
 */
import { describe, expect, it, vi } from 'vitest'
import { mount } from '@vue/test-utils'

// The real dictionary is loaded asynchronously by initializeI18n(), which never
// runs in a unit test; injectI18n() would fall back to a locale-dependent
// lookup and make the reference-line label untestable. Substituting the key
// keeps `refLabel` deterministic without weakening what it proves.
vi.mock('../i18n', () => ({
  injectI18n: () => ({
    t: (key, params = {}) => Object.entries(params).reduce(
      (text, [name, value]) => text.replace(`{${name}}`, value),
      String(key),
    ),
    locale: { value: 'en' },
    setLocale: vi.fn(),
  }),
}))

const LineChart = (await import('./LineChart.vue')).default

/** The plot's own coordinate space, restated so the expectations are readable. */
const H = 100
const PAD_T = 4
const PAD_B = 4
const PLOT_H = H - PAD_T - PAD_B // 92
const Y_BOTTOM = PAD_T + PLOT_H // 96
const Y_TOP = PAD_T // 4

function chart(props) {
  return mount(LineChart, { props })
}

/** Rendered y-axis labels, top-to-bottom source order. */
function tickLabels(w) {
  return w.findAll('.y-lbl').map((n) => n.text())
}

/** `points` of each data polyline, area fills excluded. */
function lines(w) {
  return w.findAll('polyline')
    .filter((n) => n.attributes('fill') === 'none')
    .map((n) => n.attributes('points'))
}

function pairs(points) {
  return points.split(' ').map((p) => p.split(',').map(Number))
}

describe('LineChart percent scale', () => {
  it('pins a percent axis to 0-100 in steps of 25 regardless of the data', () => {
    // A CPU chart that peaked at 3% must still show a full 0-100 axis, or the
    // idle machine looks busy.
    const w = chart({ series: [{ name: 'cpu', values: [1, 3, 2] }], unit: '%' })
    expect(tickLabels(w)).toEqual(['0', '25', '50', '75', '100'])
  })

  it('treats percent:true the same as unit:"%"', () => {
    const w = chart({ series: [{ name: 'cpu', values: [1, 3] }], percent: true })
    expect(tickLabels(w)).toEqual(['0', '25', '50', '75', '100'])
  })

  it('grows past 100 in 25s when a percentage legitimately exceeds it', () => {
    // Load average style percentages (multi-core) do exceed 100; clipping them
    // would flatten the line against the top of the plot.
    const w = chart({ series: [{ name: 'cpu', values: [40, 140] }], unit: '%' })
    expect(tickLabels(w)).toEqual(['0', '50', '100', '150'])
  })
})

describe('LineChart linear scale', () => {
  it('chooses whole-number ticks for a small range', () => {
    const w = chart({ series: [{ name: 'gb', values: [0, 3] }], unit: 'GB' })
    expect(tickLabels(w)).toEqual(['0', '1', '2', '3', '4'])
  })

  it('anchors the axis at zero for non-negative data', () => {
    // Starting a memory axis at its minimum exaggerates small fluctuations into
    // dramatic swings.
    const w = chart({ series: [{ name: 'gb', values: [50, 52] }], unit: 'GB' })
    expect(tickLabels(w)[0]).toBe('0')
  })

  it('falls back to a unit axis when there is no data at all', () => {
    const w = chart({ series: [], unit: 'GB' })
    expect(tickLabels(w).length).toBeGreaterThan(0)
    expect(tickLabels(w)[0]).toBe('0')
    expect(tickLabels(w).at(-1)).toBe('1')
  })

  it('never emits a runaway number of gridlines', () => {
    // `ticks` loops until it passes `hi`; a zero or NaN step there would spin.
    const w = chart({ series: [{ name: 'x', values: [0, 987654] }], unit: '' })
    const labels = tickLabels(w)
    expect(labels.length).toBeGreaterThan(1)
    expect(labels.length).toBeLessThanOrEqual(13)
  })
})

describe('LineChart geometry', () => {
  it('maps larger values to smaller y, and spans the full plot height', () => {
    // SVG y grows downward: getting this backwards draws every chart upside down.
    const w = chart({ series: [{ name: 'cpu', values: [0, 100] }], unit: '%' })
    const [[, y0], [, y1]] = pairs(lines(w)[0])
    expect(y0).toBe(Y_BOTTOM)
    expect(y1).toBe(Y_TOP)
    expect(y1).toBeLessThan(y0)
  })

  it('spreads points evenly across the full plot width', () => {
    const w = chart({ series: [{ name: 'cpu', values: [0, 50, 100] }], unit: '%' })
    const xs = pairs(lines(w)[0]).map(([x]) => x)
    expect(xs[0]).toBe(2) // PAD.l
    expect(xs.at(-1)).toBe(398) // W - PAD.r
    expect(xs[1] - xs[0]).toBeCloseTo(xs[2] - xs[1], 6)
  })

  it('clamps out-of-range values onto the axis instead of drawing off-plot', () => {
    const w = chart({
      series: [{ name: 'cpu', values: [150, 0] }],
      unit: '%',
      max: 100,
    })
    const ys = pairs(lines(w)[0]).map(([, y]) => y)
    expect(ys).toEqual([Y_TOP, Y_BOTTOM])
  })

  it('draws nothing for a series with a single point', () => {
    // Two points are needed for a polyline; one would render an invisible stub
    // and an area fill anchored to nothing.
    const w = chart({ series: [{ name: 'cpu', values: [42] }], unit: '%' })
    expect(lines(w)).toEqual([])
  })

  it('breaks the line at gaps so a missing sample is not a slope', () => {
    // The rollup leaves holes as null. Connecting across them drew a straight
    // line through a sleep / outage as if load had been continuous.
    const w = chart({ series: [{ name: 'cpu', values: [10, 20, null, 40, 50] }], unit: '%' })
    const segs = lines(w)
    expect(segs).toHaveLength(2)
    expect(pairs(segs[0])).toHaveLength(2)
    expect(pairs(segs[1])).toHaveLength(2)
  })

  it('does not join two lone samples across a hole', () => {
    const w = chart({ series: [{ name: 'cpu', values: [10, null, 30] }], unit: '%' })
    expect(lines(w)).toEqual([])
  })

  it('discards NaN the same way it discards null', () => {
    // A metric endpoint that returns NaN once must not poison the whole series.
    const w = chart({ series: [{ name: 'cpu', values: [NaN, 10, 30] }], unit: '%' })
    expect(pairs(lines(w)[0])).toHaveLength(2)
  })

  it('drops a series whose every sample is missing', () => {
    const w = chart({ series: [{ name: 'cpu', values: [null, null] }], unit: '%' })
    expect(lines(w)).toEqual([])
  })

  it('plots x by sample time so an omitted window stays a gap', () => {
    // Three samples: t=0, t=10, t=100. Index-based x would put the middle
    // point at 50% of the plot; time-based x puts it at 10%.
    const w = chart({
      series: [{ name: 'cpu', values: [0, 50, 100] }],
      times: [0, 10, 100],
      unit: '%',
    })
    const xs = pairs(lines(w)[0]).map(([x]) => x)
    expect(xs[0]).toBe(2)
    expect(xs.at(-1)).toBe(398)
    expect(xs[1]).toBeCloseTo(2 + (10 / 100) * 396, 6)
    expect(xs[1] - xs[0]).toBeLessThan((xs[2] - xs[1]) / 2)
  })

  it('falls back to even spacing when times are missing or degenerate', () => {
    const w = chart({
      series: [{ name: 'cpu', values: [0, 50, 100] }],
      times: [42, 42, 42],
      unit: '%',
    })
    const xs = pairs(lines(w)[0]).map(([x]) => x)
    expect(xs[1] - xs[0]).toBeCloseTo(xs[2] - xs[1], 6)
  })
})

describe('LineChart legend', () => {
  it('reports the most recent non-null sample, not the last array slot', () => {
    const w = chart({ series: [{ name: 'cpu', values: [10, 30, null] }], unit: '%' })
    expect(w.find('.leg b').text()).toBe('30%')
  })

  it('drops a trailing zero from a percent reading', () => {
    const w = chart({ series: [{ name: 'cpu', values: [1, 42.02] }], unit: '%' })
    expect(w.find('.leg b').text()).toBe('42%')
  })

  it('keeps one decimal when a percent reading needs it', () => {
    const w = chart({ series: [{ name: 'cpu', values: [1, 42.4] }], unit: '%' })
    expect(w.find('.leg b').text()).toBe('42.4%')
  })

  it('renders no legend when there is no series', () => {
    expect(chart({ series: [] }).find('.lc-legend').exists()).toBe(false)
  })
})

describe('LineChart reference line', () => {
  it('is absent unless a reference is given', () => {
    const w = chart({ series: [{ name: 'cpu', values: [1, 2] }], unit: '%' })
    expect(w.find('.ref-tag').exists()).toBe(false)
  })

  it('places the reference line at the reference value', () => {
    const w = chart({ series: [{ name: 'cpu', values: [0, 100] }], unit: '%', reference: 100 })
    expect(w.find('.ref-tag').exists()).toBe(true)
    const dashed = w.findAll('line').filter((n) => n.attributes('stroke-dasharray'))
    expect(dashed).toHaveLength(1)
    expect(Number(dashed[0].attributes('y1'))).toBeCloseTo(Y_TOP, 6)
  })

  it('widens the axis so the reference stays visible above the data', () => {
    // The core-count reference on the load chart sits well above idle load; an
    // axis fitted to the data alone would push it off the top of the plot.
    const w = chart({ series: [{ name: 'load', values: [0.2, 0.4] }], unit: '', reference: 8 })
    const y = Number(
      w.findAll('line').filter((n) => n.attributes('stroke-dasharray'))[0].attributes('y1'),
    )
    expect(y).toBeGreaterThanOrEqual(Y_TOP)
    expect(y).toBeLessThanOrEqual(Y_BOTTOM)
  })

  it('labels a whole-number reference as a core count', () => {
    const w = chart({ series: [{ name: 'load', values: [1, 2] }], reference: 8 })
    expect(w.find('.ref-tag').text()).toContain('cores_n')
  })

  it('labels a fractional reference with its value', () => {
    const w = chart({ series: [{ name: 'load', values: [1, 2] }], reference: 4.5 })
    expect(w.find('.ref-tag').text()).toBe('4.5')
  })
})

describe('LineChart stacked quiet (Activity Monitor CPU LOAD)', () => {
  it('hides the y-axis and grid when quiet', () => {
    const w = chart({
      series: [
        { name: 'sys', values: [10, 20], color: '#FF453A' },
        { name: 'user', values: [30, 40], color: '#5AC8FA' },
      ],
      percent: true,
      stacked: true,
      quiet: true,
      title: 'CPU Load',
    })
    expect(w.find('.lc-title').text()).toBe('CPU Load')
    expect(w.findAll('.y-lbl')).toHaveLength(0)
    expect(w.find('.lc').classes()).toContain('quiet')
    expect(w.findAll('polygon').length).toBeGreaterThan(0)
  })

  it('shows the percent y-axis and grid when stacked without quiet', () => {
    const w = chart({
      series: [
        { name: 'sys', values: [10, 20], color: '#FF453A' },
        { name: 'user', values: [30, 40], color: '#5AC8FA' },
      ],
      percent: true,
      stacked: true,
      fill: true,
      title: 'CPU Load',
    })
    expect(w.find('.lc').classes()).not.toContain('quiet')
    expect(w.find('.lc-title').text()).toBe('CPU Load')
    expect(tickLabels(w)).toEqual(['0', '25', '50', '75', '100'])
    expect(w.find('.grid').exists()).toBe(true)
    expect(w.findAll('polygon').length).toBeGreaterThan(0)
  })

  it('stacks series so the top edge is the sum', () => {
    const w = chart({
      series: [
        { name: 'sys', values: [20, 20], color: '#FF453A' },
        { name: 'user', values: [30, 30], color: '#5AC8FA' },
      ],
      percent: true,
      stacked: true,
      quiet: true,
    })
    const polys = w.findAll('polygon')
    expect(polys).toHaveLength(2)
    // Top of user band at 50% → y = 4 + 92 * 0.5 = 50
    const userPts = pairs(polys[1].attributes('points'))
    const tops = userPts.slice(0, 2).map(([, y]) => y)
    expect(tops[0]).toBeCloseTo(Y_TOP + PLOT_H * 0.5, 5)
  })

  it('uses height as a minimum when fill is set', () => {
    const w = chart({
      series: [{ name: 'cpu', values: [10, 20] }],
      height: 88,
      fill: true,
    })
    expect(w.find('.lc').classes()).toContain('fill')
    expect(w.find('.plot-row').attributes('style')).toContain('min-height: 88px')
  })

  it('paints stacked bands at areaOpacity and keeps strokes opaque', () => {
    const w = chart({
      series: [
        { name: 'sys', values: [20, 20], color: '#FF453A' },
        { name: 'user', values: [30, 30], color: '#5AC8FA' },
      ],
      percent: true,
      stacked: true,
      fill: true,
      areaOpacity: 0.28,
    })
    const polys = w.findAll('polygon')
    expect(polys).toHaveLength(2)
    for (const p of polys) {
      expect(Number(p.attributes('opacity'))).toBeCloseTo(0.28)
    }
    const strokes = w.findAll('polyline').filter((n) => n.attributes('fill') === 'none')
    expect(strokes).toHaveLength(2)
    for (const s of strokes) {
      expect(s.attributes('opacity')).toBeUndefined()
      expect(s.attributes('stroke-width')).toBe('1.25')
    }
  })

  it('keeps non-stacked fill at the soft default', () => {
    const w = chart({
      series: [{ name: 'mem', values: [10, 20], color: '#32D74B' }],
      fill: true,
    })
    const areas = w.findAll('polyline').filter((n) => n.attributes('fill') !== 'none')
    expect(areas.length).toBeGreaterThan(0)
    for (const a of areas) {
      expect(Number(a.attributes('opacity'))).toBeCloseTo(0.1)
    }
  })
})

function xLabels(w) {
  return w.findAll('.x-lbl')
}

describe('LineChart x-axis time labels', () => {
  it('renders HTML time labels when times span a real interval', () => {
    const w = chart({
      series: [{ name: 'cpu', values: [0, 50, 100] }],
      times: [1_700_000_000, 1_700_001_800, 1_700_003_600],
      unit: '%',
    })
    const labels = xLabels(w)
    expect(labels).toHaveLength(5)
    expect(labels[0].attributes('style')).toContain('0%')
    expect(labels.at(-1).attributes('style')).toContain('100%')
    expect(labels[0].classes()).toContain('first')
    expect(labels.at(-1).classes()).toContain('last')
    expect(w.find('.x-axis').classes()).not.toContain('two-line')
    for (const n of labels) {
      expect(n.text()).toMatch(/^\d{2}:\d{2}$/)
    }
  })

  it('thins long month/day time labels on a 48h span', () => {
    const lo = 1_700_000_000
    const hi = lo + 48 * 3600
    const w = chart({
      series: [{ name: 'cpu', values: [0, 50, 100] }],
      times: [lo, lo + 24 * 3600, hi],
      unit: '%',
    })
    const labels = xLabels(w)
    expect(labels).toHaveLength(3)
    expect(labels[0].attributes('style')).toContain('0%')
    expect(labels[1].attributes('style')).toContain('50%')
    expect(labels.at(-1).attributes('style')).toContain('100%')
    expect(labels[0].classes()).toContain('first')
    expect(labels.at(-1).classes()).toContain('last')
    expect(w.find('.x-axis').classes()).toContain('two-line')
    for (const n of labels) {
      expect(n.text()).toMatch(/^\d{1,2}\/\d{1,2}\s+\d{2}:\d{2}$/)
    }
  })

  it('uses month/day labels for a multi-month span', () => {
    const w = chart({
      series: [{ name: 'cpu', values: [0, 50, 100] }],
      times: [1_700_000_000, 1_715_000_000, 1_731_600_000],
      unit: '%',
    })
    const texts = xLabels(w).map((n) => n.text())
    expect(texts).toHaveLength(5)
    for (const text of texts) {
      expect(text).toMatch(/^\d{1,2}\/\d{1,2}$/)
    }
  })

  it('thins the labels to what the strip is actually wide enough for', async () => {
    // The dashboard puts two charts side by side in one card, leaving each
    // x-axis ~110px. Five `HH:MM` labels at ~30px each ran together as
    // `11:1711:32`. jsdom has no ResizeObserver and reports zero-size boxes, so
    // both have to be supplied for the measured path to run at all.
    const observed = []
    const width = 110
    const rect = vi
      .spyOn(Element.prototype, 'getBoundingClientRect')
      .mockReturnValue({ width, height: 16, top: 0, left: 0, right: width, bottom: 16 })
    vi.stubGlobal('ResizeObserver', class {
      constructor(cb) { this.cb = cb }
      observe(el) { observed.push(el) }
      disconnect() {}
    })
    try {
      const w = chart({
        series: [{ name: 'cpu', values: [0, 50, 100] }],
        times: [1_700_000_000, 1_700_001_800, 1_700_003_600],
        unit: '%',
      })
      await w.vm.$nextTick()
      expect(observed).toHaveLength(1)
      // floor(110 / 38) = 2, so only the two extents survive.
      const labels = xLabels(w)
      expect(labels).toHaveLength(2)
      expect(labels[0].attributes('style')).toContain('0%')
      expect(labels[1].attributes('style')).toContain('100%')
    } finally {
      rect.mockRestore()
      vi.unstubAllGlobals()
    }
  })

  it('keeps the full tick count on a strip with room for it', async () => {
    const width = 400
    const rect = vi
      .spyOn(Element.prototype, 'getBoundingClientRect')
      .mockReturnValue({ width, height: 16, top: 0, left: 0, right: width, bottom: 16 })
    vi.stubGlobal('ResizeObserver', class {
      observe() {}
      disconnect() {}
    })
    try {
      const w = chart({
        series: [{ name: 'cpu', values: [0, 50, 100] }],
        times: [1_700_000_000, 1_700_001_800, 1_700_003_600],
        unit: '%',
      })
      await w.vm.$nextTick()
      expect(xLabels(w)).toHaveLength(5)
    } finally {
      rect.mockRestore()
      vi.unstubAllGlobals()
    }
  })

  it('hides the x-axis when times are missing', () => {
    const w = chart({ series: [{ name: 'cpu', values: [0, 50, 100] }], unit: '%' })
    expect(xLabels(w)).toHaveLength(0)
    expect(w.find('.x-axis').exists()).toBe(false)
  })

  it('hides the x-axis when times are degenerate', () => {
    const w = chart({
      series: [{ name: 'cpu', values: [0, 50, 100] }],
      times: [42, 42, 42],
      unit: '%',
    })
    expect(xLabels(w)).toHaveLength(0)
  })

  it('hides the x-axis in quiet mode even when times exist', () => {
    const w = chart({
      series: [{ name: 'cpu', values: [0, 50, 100] }],
      times: [1_700_000_000, 1_700_003_600],
      quiet: true,
      unit: '%',
    })
    expect(xLabels(w)).toHaveLength(0)
    expect(w.findAll('.y-lbl')).toHaveLength(0)
  })
})
