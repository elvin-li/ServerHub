<template>
  <div>
    <div class="page-title">
      <h1>{{ t('brew.title') }}</h1>
      <span class="meta">{{ t('brew.meta') }}</span>
    </div>
    <div class="toolbar">
      <button class="primary" @click="refresh" :disabled="busy">{{ t('common.refresh') }}</button>
      <input v-model="q" type="text" :placeholder="t('brew.filter_ph')"  :aria-label="t('brew.filter_ph')"/>
    </div>
    <div class="table-wrap">
      <table class="dense">
        <thead>
          <tr>
            <th></th>
            <th>{{ t('brew.service') }}</th>
            <th>{{ t('common.status') }}</th>
            <th>{{ t('brew.user') }}</th>
            <th>{{ t('common.actions') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="s in filtered" :key="s.id">
            <td><span class="led" :class="s.state==='ok'?'on':(s.state==='warn'?'warn':'err')"></span></td>
            <td>
              <strong>{{ s.name }}</strong>
              <div v-if="s.file" class="mono" style="color:var(--sub);font-size:10px">{{ s.file }}</div>
            </td>
            <td>
              <span class="badge" :class="s.state==='ok'?'ok':(s.state==='warn'?'warn':'')">{{ s.status }}</span>
            </td>
            <td class="mono">{{ s.user || '—' }}</td>
            <td class="ops">
              <button
                v-for="a in s.actions || []"
                :key="a"
                class="tiny"
                :class="{ primary: a==='start', danger: a==='stop' }"
                :disabled="busy"
                @click="act(s, a)"
              >{{ labels[a] || a }}</button>
            </td>
          </tr>
          <tr v-if="!filtered.length">
            <td colspan="5" style="color:var(--sub)">{{ t('brew.empty') }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script setup>
import { computed, inject, onMounted, ref } from 'vue'
import { brewAction, getBrewServices } from '../api/client'
import { injectI18n } from '../i18n'

const toast = inject('toast')
const { t } = injectI18n()
const services = ref([])
const busy = ref(false)
const q = ref('')
const labels = computed(() => ({
  start: t('services.act_start'),
  stop: t('services.act_stop'),
  restart: t('services.act_restart'),
}))

const filtered = computed(() => {
  const qq = q.value.trim().toLowerCase()
  if (!qq) return services.value
  return services.value.filter(s => (s.name || '').toLowerCase().includes(qq))
})

async function refresh() {
  try {
    const j = await getBrewServices()
    services.value = j.services || []
  } catch (e) {
    toast('❌ ' + e.message)
  }
}

async function act(s, action) {
  if (action === 'stop' && !confirm(t('brew.confirm_stop', { name: s.name }))) return
  busy.value = true
  try {
    const j = await brewAction(s.id, action)
    toast(j.ok ? `✅ ${s.name}` : `❌ ${j.message}`)
    setTimeout(refresh, 800)
  } catch (e) {
    toast('❌ ' + e.message)
  }
  busy.value = false
}

onMounted(refresh)
</script>
