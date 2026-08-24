/**
 * Output that lands after the user acts must announce itself.
 *
 * a11y.test.js already requires this of every async-fed <pre>; these four are
 * the same fact in a <p> or a <div>, which that scan deliberately does not
 * reach. Each one is the durable answer to a button press — what the backup
 * produced, where the diagnostics bundle was saved, how much a Docker prune
 * reclaimed — while the toast that accompanies it is gone in four seconds. All
 * are gated with v-if on the same node, so the region holds no idle empty
 * string (the trap error live-region tests pin elsewhere).
 *
 * Source-matched, not mounted: attribute presence on a known element is exactly
 * what a source rule can decide reliably, in the same spirit as a11y.test.js.
 */
import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'

const read = (name) => readFileSync(resolve(__dirname, name), 'utf8')

describe('action results are live regions', () => {
  it('Backups announces what a backup button just did', () => {
    expect(read('Backups.vue')).toMatch(
      /v-if="msg"[^>]*role="status"[^>]*aria-live="polite"/,
    )
  })

  it('Tools announces the diagnostics save result', () => {
    expect(read('Tools.vue')).toMatch(/v-if="diagMsg"[^>]*role="status"/)
  })

  it('Tools announces what a Docker prune reclaimed', () => {
    expect(read('Tools.vue')).toMatch(/v-if="pruneMsg"[^>]*role="status"/)
  })

  it('Settings announces the diagnostics save result', () => {
    expect(read('Settings.vue')).toMatch(/v-if="diagMsg"[^>]*role="status"/)
  })
})
