<template>
  <div>
    <div class="page-title">
      <h1>{{ t('pages.users') }}</h1>
      <span class="meta">{{ t('pages.users_meta') }}</span>
    </div>

    <div class="toolbar">
      <button class="primary" @click="load" :disabled="loading">{{ t('common.refresh') }}</button>
      <!-- role=status + a name for the first number: "12 · 3 Admins" left the
           total unlabeled, and Refresh updated both counts silently for a
           screen reader. Reuses the summary tiles' keys (Tools ports pattern). -->
      <span class="meta" style="color:var(--sub)" v-if="data" role="status">
        {{ finiteN(recGet(data, 'count')) }} {{ t('users.total') }} · {{ finiteN(recGet(data, 'admins')) }} {{ t('users.admins') }}
      </span>
    </div>

    <div class="tile" style="margin-bottom:12px;border-left:3px solid var(--accent)">
      <p style="font-size:12px;color:var(--sub);line-height:1.55;margin:0">
        {{ t('users.hint') }}
      </p>
    </div>

    <!-- ── panel accounts (ServerHub sign-ins, not macOS users) ─────────── -->
    <div class="tile" style="margin-bottom:12px" v-if="authState.canManage">
      <div class="accounts-head">
        <h2 style="margin:0">{{ t('accounts.title') }}</h2>
        <button class="primary" @click="creating = !creating">
          {{ creating ? t('common.cancel') : t('accounts.add') }}
        </button>
      </div>
      <p class="hint" style="margin-top:4px">{{ t('accounts.hint') }}</p>

      <form v-if="creating" class="accounts-create" @submit.prevent="createAccount">
        <div class="form-grid">
          <label>{{ t('users.username') }}</label>
          <input v-model.trim="createForm.username" maxlength="64" required :aria-label="t('users.username')" />
          <label>{{ t('accounts.initial_password') }}</label>
          <input v-model="createForm.password" type="password" minlength="10" maxlength="256" autocomplete="new-password" required :aria-label="t('accounts.initial_password')" />
          <label>{{ t('accounts.resources') }}</label>
          <!-- tabindex=0: the picker caps at 220px and scrolls; a scrollable
               region a keyboard cannot reach cannot be scrolled by one
               (WCAG 2.1.1). Same treatment as the Tools log boxes. -->
          <div class="resource-picker" tabindex="0" role="region" :aria-label="t('accounts.resources')">
            <label v-for="opt in asArray(serviceOptions)" :key="finiteText(recGet(opt, 'id'))" class="resource-option">
              <input type="checkbox" :value="recGet(opt, 'id')" v-model="createForm.resources" />
              <span>{{ finiteText(recGet(opt, 'name')) }}</span>
              <code class="mono">{{ finiteText(recGet(opt, 'id')) }}</code>
            </label>
            <!-- role=alert: the picker is the only place this failure shows,
                 and without it the empty checkbox list reads like "no
                 services" to an AT user. -->
            <span v-if="serviceOptionsError" class="hint bad" role="alert">{{ finiteText(serviceOptionsError) }}</span>
            <!-- type=button: this retry sits inside the create <form>, and a
                 bare <button> would submit it instead of refetching. -->
            <button v-if="serviceOptionsError" class="tiny" type="button" @click="loadServiceOptions">{{ t('common.retry') }}</button>
            <span v-else-if="serviceOptionsLoaded && !asArray(serviceOptions).length" class="hint">{{ t('accounts.no_services') }}</span>
          </div>
        </div>
        <div class="btns" style="margin-top:10px">
          <button class="primary" :disabled="accountsBusy || !createForm.username || secretLen(createForm.password) < 10">
            {{ t('accounts.create') }}
          </button>
        </div>
      </form>

      <!-- Banner above the rows, not behind them: the empty-row alert below
           only exists while the table is empty, so once accounts were on
           screen a failed *re*-load (after a create/save/delete, or Retry)
           surfaced nowhere — loadAccounts() never toasts. Stale rows still
           render below, which is the LoadFailure contract. -->
      <LoadFailure
        v-if="accountsError && asArray(accounts).length"
        :detail="accountsError"
        :retry="loadAccounts"
        :busy="accountsBusy"
        style="margin-top:10px"
      />
      <div class="table-wrap" style="margin-top:10px">
        <table class="dense fit-m">
          <thead>
            <tr>
              <th>{{ t('users.username') }}</th>
              <th>{{ t('users.role') }}</th>
              <th class="col-hide-m">2FA</th>
              <th class="col-hide-m">{{ t('accounts.resources') }}</th>
              <th><span class="sr-only">{{ t('common.actions') }}</span></th>
            </tr>
          </thead>
          <tbody>
            <template v-for="acct in asArray(accounts)" :key="finiteText(recGet(acct, 'username'))">
              <tr>
                <td>
                  <strong>{{ finiteText(recGet(acct, 'username')) }}</strong>
                  <div class="show-m sub">2FA {{ asRecord(acct).twofa_enabled ? t('common.on') : t('common.off') }}</div>
                  <div class="show-m sub">
                    <template v-if="asRecord(acct).role === 'admin'">{{ t('accounts.all_resources') }}</template>
                    <template v-else-if="asArray(recGet(acct, 'resources')).length">{{ resourceList(recGet(acct, 'resources')) }}</template>
                    <template v-else>{{ t('accounts.no_resources') }}</template>
                  </div>
                </td>
                <td>
                  <span class="badge" :class="asRecord(acct).role === 'admin' ? 'ok' : ''">
                    {{ asRecord(acct).role === 'admin' ? t('common.admin') : t('accounts.member') }}
                  </span>
                </td>
                <td class="col-hide-m">
                  <span class="badge" :class="asRecord(acct).twofa_enabled ? 'ok' : ''">
                    {{ asRecord(acct).twofa_enabled ? t('common.on') : t('common.off') }}
                  </span>
                </td>
                <td class="mono col-hide-m" style="font-size:11px">
                  <template v-if="asRecord(acct).role === 'admin'">{{ t('accounts.all_resources') }}</template>
                  <template v-else-if="asArray(recGet(acct, 'resources')).length">{{ resourceList(recGet(acct, 'resources')) }}</template>
                  <template v-else><span style="color:var(--sub)">{{ t('accounts.no_resources') }}</span></template>
                </td>
                <td style="text-align:right">
                  <button v-if="asRecord(acct).role !== 'admin'" class="tiny" @click="toggleEditor(acct)">
                    {{ editing === recGet(acct, 'username') ? t('common.close') : t('common.manage') }}
                  </button>
                </td>
              </tr>
              <tr v-if="editing === recGet(acct, 'username')">
                <td colspan="5" class="account-editor">
                  <div class="editor-section">
                    <strong>{{ t('accounts.resources') }}</strong>
                    <!-- tabindex=0: same 220px scroll cap as the create form's
                         copy, so the same keyboard reachability fix. -->
                    <div class="resource-picker" tabindex="0" role="region" :aria-label="t('accounts.resources')">
                      <label v-for="opt in asArray(serviceOptions)" :key="finiteText(recGet(opt, 'id'))" class="resource-option">
                        <input type="checkbox" :value="recGet(opt, 'id')" v-model="editResources" />
                        <span>{{ finiteText(recGet(opt, 'name')) }}</span>
                        <code class="mono">{{ finiteText(recGet(opt, 'id')) }}</code>
                      </label>
                      <span v-if="serviceOptionsError" class="hint bad" role="alert">{{ finiteText(serviceOptionsError) }}</span>
                      <button v-if="serviceOptionsError" class="tiny" type="button" @click="loadServiceOptions">{{ t('common.retry') }}</button>
                      <span v-else-if="serviceOptionsLoaded && !asArray(serviceOptions).length" class="hint">{{ t('accounts.no_services') }}</span>
                    </div>
                    <div class="btns" style="margin-top:8px">
                      <button class="primary" :disabled="accountsBusy" @click="saveResources(acct)">
                        {{ t('accounts.save_resources') }}
                      </button>
                    </div>
                  </div>
                  <div class="editor-section">
                    <strong>{{ t('accounts.reset_password') }}</strong>
                    <p class="hint" style="margin:4px 0 6px">{{ t('accounts.reset_password_hint') }}</p>
                    <div class="btns">
                      <!-- Named after the visible "New password" placeholder,
                           not the action: the old aria-label repeated the
                           button beside it, so the input and the button were
                           announced identically. -->
                      <input
                        v-model="resetPassword"
                        type="password"
                        minlength="10"
                        maxlength="256"
                        autocomplete="new-password"
                        :placeholder="t('settings.new_password')"
                        :aria-label="t('settings.new_password')"
                        style="max-width:240px"
                      />
                      <button :disabled="accountsBusy || secretLen(resetPassword) < 10" @click="doResetPassword(acct)">
                        {{ t('accounts.reset_password') }}
                      </button>
                    </div>
                  </div>
                  <div class="editor-section">
                    <strong>{{ t('accounts.danger_zone') }}</strong>
                    <div class="btns" style="margin-top:6px">
                      <button v-if="asRecord(acct).twofa_enabled" :disabled="accountsBusy" @click="resetTwofa(acct)">
                        {{ t('twofa.admin_reset_button') }}
                      </button>
                      <button class="danger" :disabled="accountsBusy" @click="removeAccount(acct)">
                        {{ t('accounts.delete') }}
                      </button>
                    </div>
                  </div>
                </td>
              </tr>
            </template>
            <tr v-if="!asArray(accounts).length">
              <td colspan="5" class="empty-row">
                <!-- The failure text gets its own role=alert span: loadAccounts()
                     does not toast, so this cell is the only place the error
                     surfaces — and the loading/none states must stay out of the
                     live region or they would be announced too. -->
                <span v-if="accountsError" role="alert">{{ finiteText(accountsError) }}</span>
                <!-- Outside the alert span so the announcement stays the error
                     text alone; without this button the only recovery from a
                     failed first fetch was reloading the page. -->
                <button v-if="accountsError" class="tiny" type="button" @click="loadAccounts">{{ t('common.retry') }}</button>
                <template v-else>{{ accountsLoaded ? t('common.none') : t('common.loading') }}</template>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <LoadFailure v-if="loadError" :detail="loadError" :retry="load" :busy="loading" />
    <SkeletonLoader v-if="!loaded" variant="tiles" :rows="3" :span="4" :tile-height="34" style="margin-bottom:12px" />
    <div class="dash-grid" style="margin-bottom:12px" v-else-if="data">
      <div class="tile span-4">
        <h2>{{ t('users.total') }}</h2>
        <div class="v">{{ finiteN(recGet(data, 'count')) }}</div>
      </div>
      <div class="tile span-4">
        <h2>{{ t('users.admins') }}</h2>
        <div class="v">{{ finiteN(recGet(data, 'admins')) }}</div>
        <div class="sub">admin / wheel / root</div>
      </div>
      <div class="tile span-4">
        <h2>{{ t('users.normal') }}</h2>
        <div class="v">{{ finiteDiff(recGet(data, 'count'), recGet(data, 'admins')) }}</div>
      </div>
    </div>

    <SkeletonLoader v-if="!loaded" :cols="8" :rows="6" />
    <div v-else class="table-wrap">
      <table class="dense fit-m">
        <thead>
          <tr>
            <th><span class="sr-only">{{ t('common.status_led') }}</span></th>
            <th>{{ t('users.username') }}</th>
            <th class="col-hide-m">{{ t('users.display') }}</th>
            <th>UID</th>
            <th class="col-hide-m">{{ t('users.home') }}</th>
            <th class="col-hide-m">{{ t('users.shell') }}</th>
            <th>{{ t('users.role') }}</th>
            <th class="col-hide-m">{{ t('users.groups') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="u in asArray(recGet(data, 'users'))" :key="finiteN(recGet(u, 'uid'))">
            <!-- aria-hidden: the LED repeats the Role badge's Admin/Standard
                 text in colour only (same as the Gateway and VMs LEDs). -->
            <td><span class="led" :class="recGet(u, 'admin') ? 'on' : 'off'" aria-hidden="true"></span></td>
            <td>
              <strong>{{ finiteText(recGet(u, 'name')) }}</strong>
              <div v-if="finiteText(recGet(u, 'gecos'), '')" class="show-m sub">{{ finiteText(recGet(u, 'gecos')) }}</div>
              <div class="show-m sub mono">{{ finiteText(recGet(u, 'home')) }} · {{ finiteText(recGet(u, 'shell')) }}</div>
            </td>
            <td class="col-hide-m">{{ finiteText(recGet(u, 'gecos')) }}</td>
            <td class="mono">{{ finiteN(recGet(u, 'uid')) }}</td>
            <td class="mono col-hide-m">{{ finiteText(recGet(u, 'home')) }}</td>
            <td class="mono col-hide-m">{{ finiteText(recGet(u, 'shell')) }}</td>
            <td>
              <span class="badge" :class="recGet(u, 'admin') ? 'ok' : ''">{{ recGet(u, 'admin') ? t('common.admin') : t('common.standard') }}</span>
            </td>
            <td class="mono col-hide-m" style="max-width:220px;overflow:hidden;text-overflow:ellipsis;font-size:10px" :title="asArray(recGet(u, 'groups')).map(g => finiteText(g, '')).filter(Boolean).join(', ')">
              {{ asArray(recGet(u, 'groups')).map(g => finiteText(g, '')).filter(Boolean).slice(0, 6).join(', ') }}{{ asArray(recGet(u, 'groups')).length > 6 ? '…' : '' }}
            </td>
          </tr>
          <tr v-if="!asArray(recGet(data, 'users')).length && !loadError">
            <td colspan="8" class="empty-row">{{ loading ? t('common.loading') : t('users.empty') }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script setup>
import { inject, onMounted, onUnmounted, ref } from 'vue'
import {
  adminDisableTotp, createPanelAccount, deletePanelAccount, getServices,
  getUsers, listPanelAccounts, resetPanelAccountPassword,
  setPanelAccountResources,
} from '../api/client'
import { authState } from '../lib/authState'
import { asArray, asRecord, finiteN, finiteText, recGet } from '../lib/finite'
import { injectI18n } from '../i18n'
import SkeletonLoader from '../components/SkeletonLoader.vue'
import LoadFailure from '../components/LoadFailure.vue'

const toast = inject('toast')
const { t } = injectI18n()
const data = ref(null)

function finiteDiff(a, b) {
  const n = finiteN(a, null)
  const m = finiteN(b, null)
  if (n == null || m == null) return '—'
  return n - m
}

function resourceList(list) {
  return asArray(list).map((r) => finiteText(r, '')).filter(Boolean).join(', ')
}

function accountName(acct) {
  return finiteText(recGet(acct, 'username'), '')
}

function secretLen(value) {
  return typeof value === 'string' ? value.length : 0
}

const loading = ref(false)
// Latched, unlike `loading`: the skeleton stands in for content that has never
// arrived. Keying it off `loading` would blank the populated table every time
// the operator pressed Refresh.
const loaded = ref(false)
const loadError = ref('')
let pageAlive = true
let loadGeneration = 0

async function load() {
  const generation = ++loadGeneration
  loading.value = true
  try {
    const next = asRecord(await getUsers())
    if (generation !== loadGeneration || !pageAlive) return
    data.value = {
      ...next,
      users: asArray(recGet(next, 'users')).map((row) => asRecord(row)),
    }
    loadError.value = ''
  } catch (e) {
    if (generation !== loadGeneration || !pageAlive) return
    loadError.value = finiteText(e.message || String(e), '')
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (generation === loadGeneration) {
      loading.value = false
      loaded.value = true
    }
  }
}

// ── panel accounts (ServerHub sign-ins) ──────────────────────────────────────
const accounts = ref([])
const accountsError = ref('')
// Latched: the empty-row text used to be `accountsError || "loading"`, so a
// successful fetch that returned no members kept saying "loading" forever.
const accountsLoaded = ref(false)
const accountsBusy = ref(false)
const creating = ref(false)
const createForm = ref({ username: '', password: '', resources: [] })
const editing = ref('')        // username whose editor row is open
const editResources = ref([])
const resetPassword = ref('')
// Options for the visibility picker: every manageable service, flattened.
const serviceOptions = ref([])
const serviceOptionsError = ref('')
const serviceOptionsLoaded = ref(false)

async function loadAccounts() {
  const generation = loadGeneration
  try {
    const next = asArray(recGet(asRecord(await listPanelAccounts()), 'accounts')).map((row) => asRecord(row))
    if (generation !== loadGeneration || !pageAlive) return
    accounts.value = next
    accountsError.value = ''
  } catch (e) {
    if (generation !== loadGeneration || !pageAlive) return
    accountsError.value = finiteText(e.message || String(e), '')
  } finally {
    if (generation === loadGeneration) accountsLoaded.value = true
  }
}

async function loadServiceOptions() {
  const generation = loadGeneration
  try {
    const status = asRecord(await getServices())
    if (generation !== loadGeneration || !pageAlive) return
    serviceOptions.value = asArray(recGet(status, 'groups')).flatMap((group) =>
      asArray(recGet(asRecord(group), 'services')).map((svc) => {
        const rec = asRecord(svc)
        return { id: recGet(rec, 'id'), name: finiteText(recGet(rec, 'name'), '') || finiteText(recGet(rec, 'id')) }
      }),
    )
    serviceOptionsError.value = ''
  } catch (e) {
    if (generation !== loadGeneration || !pageAlive) return
    serviceOptionsError.value = finiteText(e.message || String(e), '')
  } finally {
    if (generation === loadGeneration) serviceOptionsLoaded.value = true
  }
}

function toggleEditor(acct) {
  const name = accountName(acct)
  if (editing.value === name) {
    editing.value = ''
    return
  }
  editing.value = name
  editResources.value = [...asArray(recGet(acct, 'resources'))]
  resetPassword.value = ''
}

async function createAccount() {
  const generation = loadGeneration
  accountsBusy.value = true
  try {
    const r = asRecord(await createPanelAccount({
      username: createForm.value.username,
      password: createForm.value.password,
      resources: asArray(createForm.value.resources),
    }))
    if (generation !== loadGeneration || !pageAlive) return
    toast('✅ ' + t('accounts.created', { name: finiteText(createForm.value.username) }))
    createForm.value = { username: '', password: '', resources: [] }
    creating.value = false
    await loadAccounts()
  } catch (e) {
    if (generation !== loadGeneration || !pageAlive) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    // load() bumps loadGeneration and Refresh is not gated on accountsBusy.
    if (pageAlive) accountsBusy.value = false
  }
}

async function saveResources(acct) {
  const generation = loadGeneration
  accountsBusy.value = true
  try {
    const r = asRecord(await setPanelAccountResources(accountName(acct), asArray(editResources.value)))
    if (generation !== loadGeneration || !pageAlive) return
    toast('✅ ' + t('accounts.resources_saved', { name: accountName(acct) }))
    await loadAccounts()
  } catch (e) {
    if (generation !== loadGeneration || !pageAlive) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (pageAlive) accountsBusy.value = false
  }
}

async function doResetPassword(acct) {
  // Resetting revokes every session the member still holds; make that explicit.
  if (!confirm(t('accounts.reset_password_confirm', { name: accountName(acct) }))) return
  const generation = loadGeneration
  accountsBusy.value = true
  try {
    const r = asRecord(await resetPanelAccountPassword(accountName(acct), resetPassword.value))
    if (generation !== loadGeneration || !pageAlive) return
    resetPassword.value = ''
    toast('✅ ' + t('accounts.password_reset_done', { name: accountName(acct) }))
  } catch (e) {
    if (generation !== loadGeneration || !pageAlive) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (pageAlive) accountsBusy.value = false
  }
}

async function resetTwofa(acct) {
  if (!confirm(t('twofa.admin_reset_confirm', { name: accountName(acct) }))) return
  const generation = loadGeneration
  accountsBusy.value = true
  try {
    await adminDisableTotp(accountName(acct))
    if (generation !== loadGeneration || !pageAlive) return
    toast('✅ ' + t('twofa.admin_reset_toast', { name: accountName(acct) }))
    await loadAccounts()
  } catch (e) {
    if (generation !== loadGeneration || !pageAlive) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (pageAlive) accountsBusy.value = false
  }
}

async function removeAccount(acct) {
  if (!confirm(t('accounts.delete_confirm', { name: accountName(acct) }))) return
  const generation = loadGeneration
  accountsBusy.value = true
  try {
    const r = asRecord(await deletePanelAccount(accountName(acct)))
    if (generation !== loadGeneration || !pageAlive) return
    editing.value = ''
    toast('✅ ' + t('accounts.deleted', { name: accountName(acct) }))
    await loadAccounts()
  } catch (e) {
    if (generation !== loadGeneration || !pageAlive) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (pageAlive) accountsBusy.value = false
  }
}

onMounted(() => {
  pageAlive = true
  load()
  if (authState.canManage) {
    loadAccounts()
    loadServiceOptions()
  }
})

onUnmounted(() => {
  pageAlive = false
  loadGeneration += 1
})
</script>

<style scoped>
.accounts-head { display: flex; align-items: center; justify-content: space-between; gap: 10px; flex-wrap: wrap; }
.hint { color: var(--sub); font-size: 12px; line-height: 1.5; }
.accounts-create { margin-top: 10px; padding: 12px; border: 1px dashed var(--line); border-radius: 8px; }
.form-grid { display: grid; grid-template-columns: 150px 1fr; gap: 8px 12px; align-items: start; }
.form-grid > label { color: var(--sub); font-size: 12px; font-weight: 600; padding-top: 8px; }
.resource-picker { display: flex; flex-direction: column; gap: 4px; max-height: 220px; overflow: auto; }
.resource-option { display: flex; align-items: center; gap: 8px; font-size: 12px; cursor: pointer; flex-wrap: wrap; }
.resource-option span, .resource-option code { min-width: 0; overflow-wrap: anywhere; }
.resource-option input { margin: 0; }
.resource-option code { color: var(--sub); font-size: 10px; }
.btns { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
.account-editor { background: color-mix(in srgb, var(--accent) 4%, transparent); }
.editor-section { padding: 8px 4px; }
.editor-section + .editor-section { border-top: 1px dashed var(--line); }
button.tiny { font-size: 11px; padding: 3px 10px; }
@media (max-width: 640px) {
  .form-grid { grid-template-columns: 1fr; }
  .form-grid > label { padding-top: 0; }
}
</style>
