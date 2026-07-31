<template>
  <div>
    <div class="page-title">
      <h1>{{ t('pages.users') }}</h1>
      <span class="meta">{{ t('pages.users_meta') }}</span>
    </div>

    <div class="toolbar">
      <button class="primary" @click="load" :disabled="loading">{{ t('common.refresh') }}</button>
      <span class="meta" style="color:var(--sub)" v-if="data">
        {{ data.count }} · {{ data.admins }} {{ t('users.admins') }}
      </span>
    </div>

    <div class="tile" style="margin-bottom:12px;border-left:3px solid var(--accent)">
      <p style="font-size:12px;color:var(--sub);line-height:1.55;margin:0">
        {{ t('users.hint') }}
      </p>
    </div>

    <div class="dash-grid" style="margin-bottom:12px" v-if="data">
      <div class="tile span-4">
        <h3>{{ t('users.total') }}</h3>
        <div class="v">{{ data.count }}</div>
      </div>
      <div class="tile span-4">
        <h3>{{ t('users.admins') }}</h3>
        <div class="v">{{ data.admins }}</div>
        <div class="sub">admin / wheel / root</div>
      </div>
      <div class="tile span-4">
        <h3>{{ t('users.normal') }}</h3>
        <div class="v">{{ (data.count || 0) - (data.admins || 0) }}</div>
      </div>
    </div>

    <div class="table-wrap">
      <table class="dense">
        <thead>
          <tr>
            <th></th>
            <th>{{ t('users.username') }}</th>
            <th>{{ t('users.display') }}</th>
            <th>UID</th>
            <th>{{ t('users.home') }}</th>
            <th>{{ t('users.shell') }}</th>
            <th>{{ t('users.role') }}</th>
            <th>{{ t('users.groups') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="u in data?.users || []" :key="u.uid">
            <td><span class="led" :class="u.admin ? 'on' : 'off'"></span></td>
            <td><strong>{{ u.name }}</strong></td>
            <td>{{ u.gecos || '—' }}</td>
            <td class="mono">{{ u.uid }}</td>
            <td class="mono">{{ u.home }}</td>
            <td class="mono">{{ u.shell }}</td>
            <td>
              <span class="badge" :class="u.admin ? 'ok' : ''">{{ u.admin ? t('common.admin') : t('common.standard') }}</span>
            </td>
            <td class="mono" style="max-width:220px;overflow:hidden;text-overflow:ellipsis;font-size:10px" :title="(u.groups||[]).join(', ')">
              {{ (u.groups || []).slice(0, 6).join(', ') }}{{ (u.groups||[]).length > 6 ? '…' : '' }}
            </td>
          </tr>
          <tr v-if="!(data?.users||[]).length">
            <td colspan="8" style="color:var(--sub)">{{ loading ? t('common.loading') : t('users.empty') }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script setup>
import { inject, onMounted, ref } from 'vue'
import { getUsers } from '../api/client'
import { injectI18n } from '../i18n'

const toast = inject('toast')
const { t } = injectI18n()
const data = ref(null)
const loading = ref(false)

async function load() {
  loading.value = true
  try {
    data.value = await getUsers()
  } catch (e) {
    toast('❌ ' + e.message)
  } finally {
    loading.value = false
  }
}

onMounted(load)
</script>
