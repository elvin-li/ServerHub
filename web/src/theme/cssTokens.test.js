/**
 * The stylesheet's custom properties have to survive the CSS parser.
 *
 * `--ok-text` did not.  A prose paragraph was appended to the comment above it
 * without removing the old terminator, so five lines of English sat loose
 * inside `:root`; the parser read them as a malformed declaration, skipping to
 * the next semicolon, which was the end of `--ok-text`.  The token was simply
 * absent, so the fifteen places that ink a healthy value green -- the Health
 * page counters, `.badge.ok`, the dashboard host pills, Pool's "survives"
 * column -- inherited body ink instead, in every theme.  Nothing errored and
 * nothing looked obviously broken; the green was just gone.
 *
 * Both failure modes are cheap to detect from the source text, so they are.
 */
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, relative, resolve } from 'node:path'
import { describe, expect, it } from 'vitest'

const SRC = resolve(__dirname, '..')

function walk(dir) {
  const out = []
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry)
    if (statSync(full).isDirectory()) out.push(...walk(full))
    else if (/\.(css|vue)$/.test(entry)) out.push(full)
  }
  return out
}

/** [{ file, css, lineOffset }] for every stylesheet and every `<style>` block. */
function sheets() {
  const out = []
  for (const file of walk(SRC)) {
    const text = readFileSync(file, 'utf8')
    const name = relative(SRC, file)
    if (file.endsWith('.css')) {
      out.push({ file: name, css: text, lineOffset: 0 })
      continue
    }
    for (const m of text.matchAll(/<style[^>]*>([\s\S]*?)<\/style>/g)) {
      out.push({
        file: name,
        css: m[1],
        lineOffset: text.slice(0, m.index).split('\n').length - 1,
      })
    }
  }
  return out
}

/** Comment delimiters that the parser will not read the way a human does. */
function commentFaults({ file, css, lineOffset }) {
  const faults = []
  const lineAt = (index) => css.slice(0, index).split('\n').length + lineOffset
  let i = 0
  while (i < css.length) {
    if (css.startsWith('/*', i)) {
      const end = css.indexOf('*/', i + 2)
      if (end < 0) {
        faults.push(`${file}:${lineAt(i)} comment is never closed`)
        break
      }
      i = end + 2
    } else if (css.startsWith('*/', i)) {
      faults.push(`${file}:${lineAt(i)} stray */ outside a comment`)
      i += 2
    } else {
      i += 1
    }
  }
  return faults
}

const ALL = sheets()

describe('stylesheet syntax', () => {
  it('reads every stylesheet in the tree', () => {
    expect(ALL.length).toBeGreaterThan(20)
    expect(ALL.some((s) => s.file === 'styles.css')).toBe(true)
  })

  it('has no comment the parser will read as a declaration', () => {
    expect(ALL.flatMap(commentFaults)).toEqual([])
  })

  it('declares the status text tints it tells everyone to use', () => {
    // Split `:root` the way the parser recovers from a bad declaration: on
    // semicolons. A swallowed token is still *present* in the file, so a plain
    // text search would pass; what it is not is the head of its own statement.
    // Comments come out first: the prose in this block contains semicolons of
    // its own, and splitting before stripping would cut them into fragments.
    const css = readFileSync(resolve(SRC, 'styles.css'), 'utf8')
      .replace(/\/\*[\s\S]*?\*\//g, ' ')
    const open = css.indexOf('{', css.indexOf(':root'))
    const body = css.slice(open + 1, css.indexOf('\n}', open))
    const heads = body.split(';').map((part) => part.trim())
    for (const token of ['--ok-text', '--warn-text', '--down-text']) {
      expect(
        heads.some((head) => head.startsWith(`${token}:`)),
        `${token} does not start a declaration — something above it is unterminated`,
      ).toBe(true)
    }
  })
})
