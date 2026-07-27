<template>
  <div>
    <div class="page-title">
      <h1>{{ t('shares.title') }}</h1>
      <span class="meta">{{ t('shares.meta') }}</span>
    </div>
    <div class="toolbar">
      <button class="primary" @click="refresh">{{ t('common.refresh') }}</button>
    </div>

    <h2 class="section-title">{{ t('shares.file_services') }}</h2>
    <div class="table-wrap" style="margin-bottom:12px">
      <table class="dense">
        <thead>
          <tr><th></th><th>{{ t('common.name') }}</th><th>{{ t('network.port') }}</th><th>{{ t('common.status') }}</th><th>URL</th><th></th></tr>
        </thead>
        <tbody>
          <tr v-for="s in data?.services || []" :key="s.id">
            <td><span class="led" :class="s.state==='ok'?'on':'err'"></span></td>
            <td><strong>{{ s.name }}</strong></td>
            <td class="mono">{{ s.port }}</td>
            <td><span class="badge" :class="s.state==='ok'?'ok':'down'">{{ s.detail }}</span></td>
            <td class="mono">{{ s.url }}</td>
            <td><a v-if="s.url" class="btn tiny primary" :href="s.url" target="_blank">{{ t('common.open') }}</a></td>
          </tr>
        </tbody>
      </table>
    </div>

    <h2 class="section-title">{{ t('shares.smb') }}</h2>
    <div v-if="!(data?.smb || []).length" class="placeholder">
      {{ t('shares.smb_empty') }}
      <div style="margin-top:8px;font-size:11px">{{ t('shares.smb_example') }}</div>
    </div>
    <div v-else class="table-wrap">
      <table class="dense">
        <thead>
          <tr>
            <th>{{ t('common.name') }}</th>
            <th>{{ t('shares.path') }}</th>
            <th>{{ t('common.size') }}</th>
            <th>{{ t('shares.smb_name') }}</th>
            <th>{{ t('shares.shared') }}</th>
            <th>{{ t('shares.guest') }}</th>
            <th>{{ t('shares.readonly') }}</th>
            <th>{{ t('shares.security_model') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="(s,i) in data.smb" :key="i">
            <td><strong>{{ s.name }}</strong></td>
            <td class="mono">{{ s.path }}</td>
            <td class="mono">{{ s.size_mb != null ? (s.size_mb + ' MB') : '—' }}</td>
            <td>{{ s.smb_name || '—' }}</td>
            <td><span class="badge" :class="s.shared ? 'ok' : ''">{{ yn(s.shared) }}</span></td>
            <td>{{ yn(s.guest) }}</td>
            <td>{{ yn(s.readonly) }}</td>
            <td><span class="badge">{{ s.guest ? 'public' : 'secure' }}</span></td>
          </tr>
        </tbody>
      </table>
    </div>
    <p style="margin-top:10px;color:var(--sub);font-size:11px">{{ data?.hint }}</p>
  </div>
</template>

<script setup>
import { inject, onMounted, ref } from 'vue'
import { getShares } from '../api/client'
import { injectI18n } from '../i18n'

const toast = inject('toast')
const { t } = injectI18n()
const data = ref(null)
const yn = (v) => (v == null ? '—' : (v ? t('common.yes') : t('common.no')))

async function refresh() {
  try { data.value = await getShares() }
  catch (e) { toast('❌ ' + e.message) }
}
onMounted(refresh)
</script>
