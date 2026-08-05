// TEMPORARY analysis config — safe to delete.
// Builds to a scratch dir and prints per-module rendered bytes for each chunk.
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { resolve } from 'node:path'

const outDir = resolve(__dirname, '../.perf-audit-dist')

function analyze() {
  return {
    name: 'analyze',
    apply: 'build',
    generateBundle(_options, bundle) {
      const rows = []
      for (const [fileName, chunk] of Object.entries(bundle)) {
        if (chunk.type !== 'chunk') continue
        const mods = Object.entries(chunk.modules)
          .map(([id, m]) => ({ id, bytes: m.renderedLength }))
          .sort((a, b) => b.bytes - a.bytes)
        const total = mods.reduce((s, m) => s + m.bytes, 0)
        rows.push({ fileName, isEntry: chunk.isEntry, total, mods })
      }
      rows.sort((a, b) => b.total - a.total)
      const lines = []
      for (const r of rows) {
        lines.push(`\n=== ${r.fileName}${r.isEntry ? '  [ENTRY]' : ''}  total=${r.total}`)
        for (const m of r.mods.slice(0, 30)) {
          const short = m.id.replace(resolve(__dirname, '..') + '/', '')
          lines.push(`  ${String(m.bytes).padStart(8)}  ${short}`)
        }
      }
      console.log(lines.join('\n'))
    },
  }
}

export default defineConfig({
  plugins: [vue(), analyze()],
  base: '/',
  build: {
    outDir,
    emptyOutDir: true,
    cssCodeSplit: true,
    minify: 'esbuild',
    target: 'esnext',
    rollupOptions: { output: { manualChunks: { vendor: ['vue', 'vue-router'] } } },
    chunkSizeWarningLimit: 300,
  },
})
