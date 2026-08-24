<template>
  <div>
    <div class="page-title">
      <h1>{{ t('gateway.title') }}</h1>
      <span class="meta">{{ t('gateway.meta') }}</span>
    </div>
    <div class="toolbar">
      <button class="primary" @click="load" :disabled="busy">{{ t('common.refresh') }}</button>
      <button :disabled="busy" @click="test">{{ t('gateway.test') }}</button>
      <button :disabled="busy" @click="reload">{{ t('gateway.reload') }}</button>
    </div>

    <LoadFailure v-if="loadError" :detail="loadError" :retry="load" :busy="busy" />
    <SkeletonLoader v-if="!loaded" variant="tiles" :rows="2" :span="6" :tile-height="72" />
    <div class="dash-grid" v-else-if="data">
      <div class="tile span-4">
        <h2>{{ t('gateway.status') }}</h2>
        <div class="row">
          <span class="led" :class="data.running ? 'on' : 'err'"></span>
          <strong>{{ data.running ? t('gateway.running') : t('gateway.stopped') }}</strong>
          <span v-if="finiteN(data.pid, null) != null" class="mono" style="color:var(--sub)">pid {{ finiteN(data.pid) }}</span>
        </div>
        <div class="sub" style="margin-top:8px">Label: {{ finiteText(data.label) }}</div>
        <div class="mono sub" style="font-size:11px;margin-top:4px">{{ finiteText(data.conf) }}</div>
      </div>
      <div class="tile span-8">
        <h2>{{ t('gateway.about') }}</h2>
        <p style="font-size:12px;color:var(--sub);line-height:1.55;margin:0">
          {{ t('gateway.about_body') }}
        </p>
      </div>
    </div>

    <h2 class="section-title">{{ t('gateway.sites') }}</h2>
    <SkeletonLoader v-if="!loaded" :cols="4" :rows="4" />
    <div v-else class="table-wrap">
      <table class="dense fit-m">
        <thead>
          <tr>
            <th>{{ t('gateway.conf') }}</th>
            <th class="col-hide-m">{{ t('gateway.listen') }}</th>
            <th class="col-hide-m">server_name</th>
            <th class="col-hide-m">{{ t('gateway.upstream') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="s in data?.sites || []" :key="s.file">
            <td class="mono">
              <strong>{{ finiteText(s.file) }}</strong>
              <div v-if="(s.server_names || []).length" class="show-m sub">{{ (s.server_names || []).map(n => finiteText(n, '')).filter(Boolean).join(', ') }}</div>
              <div v-if="(s.listens || []).length" class="show-m sub">{{ (s.listens || []).map(n => finiteText(n, '')).filter(Boolean).join(', ') }}</div>
              <div v-if="(s.upstreams || []).length" class="show-m sub">{{ (s.upstreams || []).map(n => finiteText(n, '')).filter(Boolean).join(' · ') }}</div>
            </td>
            <td class="mono col-hide-m">{{ (s.listens || []).map(n => finiteText(n, '')).filter(Boolean).join(', ') }}</td>
            <td class="mono col-hide-m">{{ (s.server_names || []).map(n => finiteText(n, '')).filter(Boolean).join(', ') }}</td>
            <td class="mono col-hide-m" style="font-size:11px">{{ (s.upstreams || []).map(n => finiteText(n, '')).filter(Boolean).join(' · ') }}</td>
          </tr>
          <tr v-if="!(data?.sites || []).length && !loadError">
            <td colspan="4" style="color:var(--sub)">{{ t('gateway.empty') }}</td>
          </tr>
        </tbody>
      </table>
    </div>
    <pre v-if="msg" style="margin-top:10px;font-size:11px;white-space:pre-wrap;background:var(--bg);padding:10px;border-radius:4px" role="status" aria-live="polite">{{ finiteText(msg) }}</pre>
  </div>
</template>

<script setup>
import { inject, onMounted, onUnmounted, ref } from 'vue'
import { getNginx, reloadNginx, testNginx } from '../api/client'
import { injectI18n } from '../i18n'
import { finiteN, finiteText } from '../lib/finite'
import SkeletonLoader from '../components/SkeletonLoader.vue'
import LoadFailure from '../components/LoadFailure.vue'

const toast = inject('toast')
const { t } = injectI18n()
const data = ref(null)
const busy = ref(false)
const msg = ref('')
// nginx config parsing walks the sites directory, so the first load is not
// instant; the site table used to claim "no sites configured" until it returned.
const loaded = ref(false)
const loadError = ref('')
let pageAlive = true
let loadSeq = 0

async function load() {
  const seq = ++loadSeq
  try {
    const next = await getNginx()
    if (seq !== loadSeq || !pageAlive) return
    data.value = next
    loadError.value = ''
  } catch (e) {
    if (seq !== loadSeq || !pageAlive) return
    loadError.value = e.message || String(e)
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (seq === loadSeq) loaded.value = true
  }
}

async function test() {
  busy.value = true
  try {
    const j = await testNginx()
    if (!pageAlive) return
    msg.value = finiteText(j.message, '')
    toast(j.ok ? '✅ ' + t('gateway.conf_valid') : '❌ ' + t('gateway.conf_invalid'))
  } catch (e) {
    if (!pageAlive) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (pageAlive) busy.value = false
  }
}

async function reload() {
  if (!confirm(t('gateway.confirm_reload'))) return
  busy.value = true
  try {
    const j = await reloadNginx()
    if (!pageAlive) return
    msg.value = finiteText(j.message, '')
    toast(j.ok ? '✅ ' + t('common.reloaded') : '❌ ' + t('common.reload_failed'))
    void load()
  } catch (e) {
    if (!pageAlive) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (pageAlive) busy.value = false
  }
}

onMounted(() => {
  pageAlive = true
  void load()
})
onUnmounted(() => {
  pageAlive = false
  loadSeq += 1
})
</script>
