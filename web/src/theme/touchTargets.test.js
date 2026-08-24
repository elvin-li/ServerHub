/**
 * Target size on touch (WCAG 2.5.8, 24x24 CSS px minimum).
 *
 * Measured on a 390px viewport before this rule existed: a native checkbox was
 * 13px square, a checkbox row 15-18px tall, `.btn.tiny` 23px, and the capsule
 * switch 22px.  Every one of those is a miss for a fingertip.
 *
 * jsdom has no layout engine, so these assertions read the stylesheet the same
 * way `contrast.test.js` does: they pin that the `pointer: coarse` block exists
 * and that each rule in it clears 24px.  What they really guard is the split —
 * touch grows, mouse does not — because the obvious "fix" is to widen the
 * desktop metrics too, and that breaks the macOS control sizes the rest of the
 * sheet is built around.
 */
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'

const MINIMUM_PX = 24

const css = readFileSync(resolve(__dirname, '../styles.css'), 'utf8')
const macSwitch = readFileSync(resolve(__dirname, '../components/MacSwitch.vue'), 'utf8')

/** Body of the first `@media (pointer: coarse)` block in *text*, or ''. */
function coarseBlock(text) {
  const start = text.search(/@media\s*\(\s*pointer\s*:\s*coarse\s*\)\s*\{/)
  if (start < 0) return ''
  const open = text.indexOf('{', start)
  let depth = 0
  for (let i = open; i < text.length; i += 1) {
    if (text[i] === '{') depth += 1
    else if (text[i] === '}') {
      depth -= 1
      if (depth === 0) return text.slice(open + 1, i)
    }
  }
  return ''
}

/** [{ selector, body }] for every rule in a block of declarations. */
function rules(block) {
  return [...block.matchAll(/([^{}]+)\{([^{}]*)\}/g)].map((m) => ({
    selector: m[1].replace(/\/\*[\s\S]*?\*\//g, '').trim(),
    body: m[2],
  }))
}

function pixels(body, property) {
  const m = body.match(new RegExp(`(?:^|;|\\s)${property}\\s*:\\s*(-?[\\d.]+)px`))
  return m ? Number(m[1]) : null
}

/** The rule whose selector mentions *needle*, or undefined. */
function ruleFor(block, needle) {
  return rules(block).find((r) => r.selector.includes(needle))
}

describe('touch target sizes', () => {
  const coarse = coarseBlock(css)

  it('the sheet has a coarse-pointer block at all', () => {
    expect(coarse).not.toBe('')
  })

  it('a row-select checkbox is the full minimum on its own', () => {
    // No label wraps it, so nothing else can make up the difference.
    const rule = ruleFor(coarse, '.col-check')
    expect(rule, '.col-check has no coarse-pointer rule').toBeTruthy()
    expect(pixels(rule.body, 'width')).toBeGreaterThanOrEqual(MINIMUM_PX)
    expect(pixels(rule.body, 'height')).toBeGreaterThanOrEqual(MINIMUM_PX)
  })

  it('a labelled checkbox clears the minimum once its label padding counts', () => {
    const box = ruleFor(coarse, 'input[type="checkbox"]')
    const label = ruleFor(coarse, 'label:has(> input[type="checkbox"])')
    expect(box, 'no coarse-pointer size for the box').toBeTruthy()
    expect(label, 'no coarse-pointer padding for the label').toBeTruthy()
    const height = pixels(box.body, 'height')
    const padding = pixels(label.body, 'padding-block')
    // Padding on an inline box grows the hit area top and bottom.
    expect(height + 2 * padding).toBeGreaterThanOrEqual(MINIMUM_PX)
  })

  it('the smallest button variant clears the minimum', () => {
    const rule = ruleFor(coarse, '.btn.tiny')
    expect(rule, '.btn.tiny has no coarse-pointer rule').toBeTruthy()
    expect(pixels(rule.body, 'min-height')).toBeGreaterThanOrEqual(MINIMUM_PX)
  })

  it('the capsule switch grows with the rest', () => {
    const rule = ruleFor(coarseBlock(macSwitch), '.mac-switch')
    expect(rule, 'MacSwitch has no coarse-pointer rule').toBeTruthy()
    expect(pixels(rule.body, 'height')).toBeGreaterThanOrEqual(MINIMUM_PX)
    expect(pixels(rule.body, 'min-height')).toBeGreaterThanOrEqual(MINIMUM_PX)
    expect(pixels(rule.body, 'width')).toBeGreaterThanOrEqual(MINIMUM_PX)
  })

  it('leaves the mouse metrics alone', () => {
    // The base rules must stay at the macOS sizes; only the coarse block grows.
    const outside = css.replace(coarse, '')
    const baseTiny = [...outside.matchAll(/button\.tiny,\s*\.btn\.tiny\s*\{([^}]*)\}/g)]
    expect(baseTiny.length).toBeGreaterThan(0)
    for (const [, body] of baseTiny) {
      expect(pixels(body, 'min-height')).toBeNull()
    }
    const baseSwitch = macSwitch.match(/\.mac-switch\s*\{([^}]*)\}/)
    expect(pixels(baseSwitch[1], 'height')).toBeLessThan(MINIMUM_PX)
  })
})
