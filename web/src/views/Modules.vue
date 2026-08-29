<template>
  <div>
    <div class="page-title">
      <h1>{{ t('modules.title') }}</h1>
      <span class="meta">{{ t('modules.meta') }}</span>
    </div>
    <div class="toolbar">
      <button class="primary" @click="load" :disabled="loading">{{ t('common.refresh') }}</button>
      <!-- role=status: the count is the answer to the Refresh click and it
           changed silently for a screen reader — same treatment as the Tools
           syslog/ports counts (Tools.announcements.test.js). -->
      <span v-if="loaded" class="meta-count" role="status">{{ t('modules.count_n', { n: moduleCount }) }}</span>
    </div>
    <LoadFailure v-if="loadError" :detail="loadError" :retry="load" :busy="loading" />
    <SkeletonLoader v-if="!loaded" variant="cards" :rows="6" />
    <div v-else-if="!Object.keys(asRecord(byCat)).length && !loadError" class="placeholder">{{ t('common.none') }}</div>
    <div v-for="(list, cat) in byCat" :key="cat" style="margin-bottom:14px">
      <h2 class="section-title">{{ catLabel(cat) }}</h2>
      <div class="grid">
        <div v-for="m in list" :key="m.id" class="tile">
          <div class="row">
            <span class="name">{{ finiteText(m.name) }}</span>
            <span class="badge ok" v-if="m.enabled">{{ t('modules.enabled') }}</span>
          </div>
          <div class="detail" style="white-space:normal;min-height:36px">{{ finiteText(m.description) }}</div>
          <div class="sub" style="margin-bottom:6px">
            <span v-for="r in asArray(m.ui_routes)" :key="r" style="margin-right:6px">
              <router-link v-if="typeof r === 'string' && r.startsWith('/')" :to="finiteText(r)" class="btn tiny">{{ finiteText(r) }}</router-link>
            </span>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, inject, onMounted, onUnmounted, ref } from 'vue'
import { asArray, asRecord, finiteText } from '../lib/finite'
import { getModules } from '../api/client'
import { injectI18n } from '../i18n'
import SkeletonLoader from '../components/SkeletonLoader.vue'
import LoadFailure from '../components/LoadFailure.vue'

const toast = inject('toast')
const { t } = injectI18n()
const byCat = ref({})
// The page previously rendered nothing at all until the response arrived, and
// nothing again when the response was empty — indistinguishable from a crash.
const loaded = ref(false)
// Refresh used to stay clickable during a load; each extra click bumped the
// generation and the earlier answers were thrown away — spent requests with
// no feedback. Disabled while in flight, like every other Refresh button.
const loading = ref(false)
const loadError = ref('')
const moduleCount = computed(() =>
  Object.values(asRecord(byCat.value)).reduce(
    (total, list) => total + (Array.isArray(list) ? list.length : 0),
    0,
  ),
)
let pageAlive = true
let loadGeneration = 0
// Category labels come from the backend as stable ids; the visible label is
// looked up so a locale switch relabels them instead of leaving them Chinese.
function catLabel(cat) {
  const key = `modules.cat_${cat}`
  const label = t(key)
  return label === key ? finiteText(cat) : label
}

async function load() {
  const generation = ++loadGeneration
  loading.value = true
  try {
    // Shared client, not a raw fetch: it checks r.ok, so an expired session
    // fires AUTH_LOST_EVENT instead of writing the 401 body into `byCat`.
    const j = await getModules()
    if (generation !== loadGeneration || !pageAlive) return
    byCat.value = asRecord(j.by_category)
    loadError.value = ''
  } catch (e) {
    if (generation !== loadGeneration || !pageAlive) return
    loadError.value = e.message || String(e)
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (generation === loadGeneration && pageAlive) {
      loading.value = false
      loaded.value = true
    }
  }
}
onMounted(() => {
  pageAlive = true
  void load()
})
onUnmounted(() => {
  pageAlive = false
  loadGeneration += 1
})
</script>
