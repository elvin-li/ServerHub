import { createHash } from 'node:crypto'
import { readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

const CACHE_FINGERPRINT_PLACEHOLDER = '__SERVERHUB_CACHE_FINGERPRINT__'
const PRECACHE_PLACEHOLDER = '__SERVERHUB_PRECACHE_ASSETS__'

// Ratchet the initial application payload. Before locale splitting the entry
// chunk was 258.70 kB; 150 KiB leaves headroom without allowing that regression.
//
// This constant spent some time declared but never referenced, so the build
// enforced nothing while the README advertised the gate. The entry chunk drifted
// to 167 KiB in the meantime; making the two entry routes lazy brought it back to
// ~131 KiB, so the original number is enforceable again as written.
//
// Only ever lower this. A build that needs it raised is a build that should split
// a route or a dependency out of the entry instead.
const ENTRY_CHUNK_BUDGET_BYTES = 150 * 1024

/** Fail the build when the entry chunk grows past the ratchet. */
function enforceEntryChunkBudget() {
  return {
    name: 'serverhub-entry-chunk-budget',
    apply: 'build',
    generateBundle(_options, bundle) {
      const entry = Object.values(bundle).find(
        (chunk) => chunk.type === 'chunk' && chunk.isEntry,
      )
      if (!entry) {
        throw new Error('Entry chunk not found; cannot check the first-paint budget')
      }
      const bytes = Buffer.byteLength(entry.code, 'utf8')
      const asKib = (n) => `${(n / 1024).toFixed(1)} KiB`
      if (bytes > ENTRY_CHUNK_BUDGET_BYTES) {
        throw new Error(
          `Entry chunk ${entry.fileName} is ${asKib(bytes)}, over the `
          + `${asKib(ENTRY_CHUNK_BUDGET_BYTES)} first-paint budget. Split a route or a `
          + 'dependency out of the entry rather than raising the budget.',
        )
      }
    },
  }
}
const outDir = resolve(
  __dirname,
  process.env.SERVERHUB_WEB_OUT_DIR || '../static',
)

function listOutputFiles(directory, relativeDirectory = '') {
  const files = []
  for (const entry of readdirSync(resolve(directory, relativeDirectory)).sort()) {
    const relativePath = relativeDirectory ? `${relativeDirectory}/${entry}` : entry
    const absolutePath = resolve(directory, relativePath)
    if (statSync(absolutePath).isDirectory()) {
      files.push(...listOutputFiles(directory, relativePath))
    } else {
      files.push(relativePath)
    }
  }
  return files
}

function fingerprintServiceWorker() {
  return {
    name: 'serverhub-service-worker-fingerprint',
    apply: 'build',
    closeBundle() {
      const serviceWorkerPath = resolve(outDir, 'sw.js')
      const serviceWorker = readFileSync(serviceWorkerPath, 'utf8')
      if (
        !serviceWorker.includes(CACHE_FINGERPRINT_PLACEHOLDER)
        || !serviceWorker.includes(PRECACHE_PLACEHOLDER)
      ) {
        // Vite may call closeBundle more than once for one build. The first pass
        // has already replaced the placeholders, so accept only our exact final
        // shapes; anything else is still a broken public asset.
        if (
          /const CACHE_NAME = 'serverhub-[a-f0-9]{16}'/.test(serviceWorker)
          && /const PRECACHE_ASSETS = \[/.test(serviceWorker)
        ) return
        throw new Error('Service worker cache fingerprint placeholder is missing')
      }

      const outputFiles = listOutputFiles(outDir)

      // Hash paths and bytes in a fixed order. Excluding sw.js avoids a
      // self-referential hash and makes identical builds produce the same ID.
      const hash = createHash('sha256')
      for (const relativePath of outputFiles.filter((path) => path !== 'sw.js')) {
        hash.update(relativePath)
        hash.update('\0')
        hash.update(readFileSync(resolve(outDir, relativePath)))
        hash.update('\0')
      }
      const fingerprint = hash.digest('hex').slice(0, 16)

      // First-paint assets: entry + vendor chunks, all CSS, and the English
      // dictionary chunk. en.js is code-split out of the entry but the app
      // refuses to mount before it is resident (see src/i18n/index.js), so an
      // install that skipped it would boot into raw key paths when offline.
      // zh-CN/ja stay network-fetched like lazy route chunks so the install
      // cache does not grow with every view or locale in the app.
      const precache = outputFiles
        .filter((path) => {
          if (!path.startsWith('assets/')) return false
          const name = path.slice('assets/'.length)
          return path.endsWith('.css') || /^index-/.test(name) || /^vendor-/.test(name)
            || /^en-/.test(name)
        })
        .map((path) => `/${path}`)

      writeFileSync(
        serviceWorkerPath,
        serviceWorker
          .replaceAll(CACHE_FINGERPRINT_PLACEHOLDER, fingerprint)
          .replaceAll(PRECACHE_PLACEHOLDER, JSON.stringify(precache)),
      )
    },
  }
}

export default defineConfig({
  plugins: [vue(), enforceEntryChunkBudget(), fingerprintServiceWorker()],
  base: '/',
  // Vitest runs the same resolver/plugin chain as the build, so a test that
  // imports a .vue file exercises the real single-file-component pipeline.
  test: {
    environment: 'jsdom',
    include: ['src/**/*.test.js'],
    restoreMocks: true,
    // Node 26 ships an experimental global localStorage that warns on startup
    // unless --localstorage-file is set. jsdom owns the storage the app under
    // test uses, so turn the Node implementation off in the workers that
    // actually run tests. Vitest forwards only profiling flags from the parent
    // process, so the flag has to be declared on the pool itself.
    poolOptions: {
      forks: { execArgv: ['--no-experimental-webstorage'] },
    },
  },

  // Dependency pre-bundling runs esbuild with its own target, which ignores
  // build.target. noVNC 1.7 ships top-level await, so the default es2020 target
  // made `npm run dev` fail to boot at all while `npm run build` was fine.
  optimizeDeps: {
    esbuildOptions: { target: 'esnext' },
  },

  build: {
    outDir,
    emptyOutDir: true,
    // Production optimizations
    cssCodeSplit: true,
    minify: 'esbuild',
    // noVNC 1.7 ships top-level await; preserve it for modern browsers.
    target: 'esnext',
    rollupOptions: {
      output: {
        manualChunks: {
          vendor: ['vue', 'vue-router'],
        },
      },
    },
    // Chunk size warning limit
    chunkSizeWarningLimit: 300,
  },
  server: {
    port: 5173,
    proxy: {
      // The panel refuses a write whose Origin does not exactly equal its Host
      // (hub/app_factory.py, hub/websocket_security.py). Vite's string-shorthand
      // proxy defaults to changeOrigin: true, which rewrote Host to
      // localhost:8086 while the browser still sent Origin: localhost:5173 — so
      // every write from the dev server, sign-in included, came back 403
      // auth.cross_site_denied. Keeping the Host header makes the pair match.
      //
      // ws forwards /api/terminal/ws, which the Terminal view opens against
      // window.location.host and would otherwise 404 in dev.
      '/api': { target: 'http://localhost:8086', changeOrigin: false, ws: true },
    },
  },
})
