import { createHash } from 'node:crypto'
import { readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

const CACHE_FINGERPRINT_PLACEHOLDER = '__SERVERHUB_CACHE_FINGERPRINT__'
// Ratchet the initial application payload. Before locale splitting the entry
// chunk was 258.70 kB; 150 KiB leaves headroom without allowing that regression.
const ENTRY_CHUNK_BUDGET_BYTES = 150 * 1024
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
      if (!serviceWorker.includes(CACHE_FINGERPRINT_PLACEHOLDER)) {
        // Vite may call closeBundle more than once for one build. The first pass
        // has already replaced the placeholder, so accept only our exact final
        // cache-name shape; anything else is still a broken public asset.
        if (/const CACHE_NAME = 'serverhub-[a-f0-9]{16}'/.test(serviceWorker)) return
        throw new Error('Service worker cache fingerprint placeholder is missing')
      }

      // Hash paths and bytes in a fixed order. Excluding sw.js avoids a
      // self-referential hash and makes identical builds produce the same ID.
      const hash = createHash('sha256')
      for (const relativePath of listOutputFiles(outDir).filter((path) => path !== 'sw.js')) {
        hash.update(relativePath)
        hash.update('\0')
        hash.update(readFileSync(resolve(outDir, relativePath)))
        hash.update('\0')
      }
      const fingerprint = hash.digest('hex').slice(0, 16)
      writeFileSync(
        serviceWorkerPath,
        serviceWorker.replaceAll(CACHE_FINGERPRINT_PLACEHOLDER, fingerprint),
      )
    },
  }
}

export default defineConfig({
  plugins: [vue(), fingerprintServiceWorker()],
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
      '/api': 'http://localhost:8086',
    },
  },
})
