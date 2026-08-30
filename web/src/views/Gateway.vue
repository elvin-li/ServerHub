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
          <!-- aria-hidden: the LED only repeats the Running/Stopped text
               beside it in colour (same as the VMs and Network inline LEDs). -->
          <span class="led" :class="asRecord(data).running ? 'on' : 'err'" aria-hidden="true"></span>
          <strong>{{ asRecord(data).running ? t('gateway.running') : t('gateway.stopped') }}</strong>
          <span v-if="finiteN(asRecord(data).pid, null) != null" class="mono" style="color:var(--sub)">pid {{ finiteN(asRecord(data).pid) }}</span>
        </div>
        <div class="sub" style="margin-top:8px">{{ t('gateway.label_is', { label: finiteText(asRecord(data).label) }) }}</div>
        <div class="mono sub" style="font-size:11px;margin-top:4px">{{ finiteText(asRecord(data).conf) }}</div>
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
          <tr v-for="s in asArray(asRecord(data).sites)" :key="finiteText(asRecord(s).file)">
            <td class="mono">
              <strong>{{ finiteText(asRecord(s).file) }}</strong>
              <div v-if="asArray(asRecord(s).server_names).length" class="show-m sub">{{ asArray(asRecord(s).server_names).map(n => finiteText(n, '')).filter(Boolean).join(', ') }}</div>
              <div v-if="asArray(asRecord(s).listens).length" class="show-m sub">{{ asArray(asRecord(s).listens).map(n => finiteText(n, '')).filter(Boolean).join(', ') }}</div>
              <div v-if="asArray(asRecord(s).upstreams).length" class="show-m sub">{{ asArray(asRecord(s).upstreams).map(n => finiteText(n, '')).filter(Boolean).join(' · ') }}</div>
            </td>
            <td class="mono col-hide-m">{{ asArray(asRecord(s).listens).map(n => finiteText(n, '')).filter(Boolean).join(', ') }}</td>
            <td class="mono col-hide-m">{{ asArray(asRecord(s).server_names).map(n => finiteText(n, '')).filter(Boolean).join(', ') }}</td>
            <td class="mono col-hide-m" style="font-size:11px">{{ asArray(asRecord(s).upstreams).map(n => finiteText(n, '')).filter(Boolean).join(' · ') }}</td>
          </tr>
          <tr v-if="!asArray(asRecord(data).sites).length && !loadError">
            <td colspan="4" class="empty-row">{{ t('gateway.empty') }}</td>
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
import { asArray, asRecord, finiteN, finiteText } from '../lib/finite'
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
    const next = asRecord(await getNginx())
    if (seq !== loadSeq || !pageAlive) return
    data.value = {
      ...next,
      sites: asArray(next.sites).map((s) => asRecord(s)),
    }
    loadError.value = ''
  } catch (e) {
    if (seq !== loadSeq || !pageAlive) return
    loadError.value = finiteText(e.message || String(e), '')
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (seq === loadSeq) loaded.value = true
  }
}

async function test() {
  busy.value = true
  try {
    const j = asRecord(await testNginx())
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
    const j = asRecord(await reloadNginx())
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
