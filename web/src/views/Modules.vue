<template>
  <div>
    <div class="page-title">
      <h1>{{ t('modules.title') }}</h1>
      <span class="meta">{{ t('modules.meta') }}</span>
    </div>
    <div class="toolbar">
      <button class="primary" @click="load">{{ t('common.refresh') }}</button>
    </div>
    <LoadFailure v-if="loadError" :detail="loadError" :retry="load" />
    <SkeletonLoader v-if="!loaded" variant="cards" :rows="6" />
    <div v-else-if="!Object.keys(byCat).length && !loadError" class="placeholder">{{ t('common.none') }}</div>
    <div v-for="(list, cat) in byCat" :key="cat" style="margin-bottom:14px">
      <h2 class="section-title">{{ catLabel(cat) }}</h2>
      <div class="grid">
        <div v-for="m in list" :key="m.id" class="tile">
          <div class="row">
            <span class="name">{{ m.name }}</span>
            <span class="badge ok" v-if="m.enabled">{{ t('modules.enabled') }}</span>
          </div>
          <div class="detail" style="white-space:normal;min-height:36px">{{ m.description }}</div>
          <div class="sub" style="margin-bottom:6px">
            <span v-for="r in m.ui_routes || []" :key="r" style="margin-right:6px">
              <router-link v-if="r.startsWith('/')" :to="r" class="btn tiny">{{ r }}</router-link>
            </span>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { inject, onMounted, ref } from 'vue'
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
const loadError = ref('')
// Category labels come from the backend as stable ids; the visible label is
// looked up so a locale switch relabels them instead of leaving them Chinese.
function catLabel(cat) {
  const key = `modules.cat_${cat}`
  const label = t(key)
  return label === key ? cat : label
}

async function load() {
  try {
    // Shared client, not a raw fetch: it checks r.ok, so an expired session
    // fires AUTH_LOST_EVENT instead of writing the 401 body into `byCat`.
    const j = await getModules()
    byCat.value = j.by_category || {}
    loadError.value = ''
  } catch (e) {
    loadError.value = e.message || String(e)
    toast('❌ ' + e.message)
  } finally {
    loaded.value = true
  }
}
onMounted(load)
</script>
