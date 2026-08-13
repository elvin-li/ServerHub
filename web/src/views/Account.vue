<template>
  <div>
    <div class="page-title">
      <h1>{{ t('pages.account') }}</h1>
      <span class="meta">{{ t('account.meta', { name: authState.username }) }}</span>
    </div>

    <div class="account-grid">
      <!-- ── password ─────────────────────────────────────────────────── -->
      <div class="card">
        <h2 class="section-title" style="margin-top:0">{{ t('account.password_title') }}</h2>
        <p class="hint" style="margin-top:0">{{ t('account.password_hint') }}</p>
        <div class="form-grid">
          <label>{{ t('settings.username') }}</label>
          <div class="mono">{{ authState.username }}</div>
          <label>{{ t('settings.current_password') }}</label>
          <input v-model="currentPassword" type="password" autocomplete="current-password" :aria-label="t('settings.current_password')" />
          <label>{{ t('settings.new_password') }}</label>
          <input v-model="newPassword" type="password" autocomplete="new-password" minlength="10" :aria-label="t('settings.new_password')" />
          <label>{{ t('settings.confirm_password') }}</label>
          <input v-model="confirmPassword" type="password" autocomplete="new-password" minlength="10" :aria-label="t('settings.confirm_password')" />
        </div>
        <div class="password-footer">
          <span class="hint" :class="{ bad: !!passwordMessage }">{{ passwordMessage || t('settings.password_rule') }}</span>
          <button class="primary" :disabled="savingPassword || !!passwordValidation" @click="savePassword">
            {{ savingPassword ? t('settings.updating_password') : t('settings.update_password') }}
          </button>
        </div>
      </div>

      <!-- ── two-factor ───────────────────────────────────────────────── -->
      <div class="card">
        <h2 class="section-title" style="margin-top:0">{{ t('twofa.title') }}</h2>
        <p class="hint" style="margin-top:0">{{ t('twofa.hint') }}</p>
        <div v-if="!twofa" class="hint">{{ t('common.loading') }}</div>
        <template v-else>
          <div class="form-grid">
            <label>{{ t('common.status') }}</label>
            <div>
              <span class="badge" :class="twofa.enabled ? 'ok' : 'warn'">
                {{ twofa.enabled ? t('common.on') : t('common.off') }}
              </span>
              <span v-if="twofa.enabled" class="hint" style="margin-left:8px">
                {{ t('twofa.recovery_remaining', { n: twofa.recovery_remaining }) }}
              </span>
            </div>
          </div>

          <!-- Recovery codes exist in plaintext only in the minting response;
               they are rendered once and discarded on navigation. -->
          <div v-if="recoveryCodes.length" class="twofa-recovery">
            <strong>{{ t('twofa.recovery_title') }}</strong>
            <p class="hint" style="margin-top:4px">{{ t('twofa.recovery_hint') }}</p>
            <div class="twofa-recovery-grid">
              <code v-for="code in recoveryCodes" :key="code" class="mono">{{ code }}</code>
            </div>
            <div class="btns" style="margin-top:10px">
              <button @click="copyRecoveryCodes">{{ copiedRecovery ? t('common.copied') : t('twofa.recovery_copy') }}</button>
              <button class="primary" @click="recoveryCodes = []">{{ t('twofa.recovery_done') }}</button>
            </div>
          </div>

          <template v-if="!twofa.enabled">
            <div v-if="!enrollment" class="btns" style="margin-top:10px">
              <button class="primary" :disabled="busy" @click="startEnroll">{{ t('twofa.enable') }}</button>
            </div>
            <div v-else>
              <p class="hint">{{ t('twofa.enroll_hint') }}</p>
              <div class="twofa-qr" v-html="enrollment.qrSvg"></div>
              <div class="form-grid" style="margin-top:8px">
                <label>{{ t('twofa.manual_secret') }}</label>
                <code class="mono" style="user-select:all;word-break:break-all">{{ enrollment.manual_entry }}</code>
                <label>{{ t('twofa.code_label') }}</label>
                <input v-model.trim="pairingCode" inputmode="numeric" autocomplete="one-time-code" maxlength="10" :aria-label="t('twofa.code_label')" />
              </div>
              <div class="btns" style="margin-top:10px">
                <button class="primary" :disabled="busy || !pairingCode" @click="confirmEnroll">{{ t('twofa.confirm') }}</button>
                <button :disabled="busy" @click="cancelEnroll">{{ t('common.cancel') }}</button>
              </div>
            </div>
          </template>
          <template v-else>
            <p class="hint">{{ t('twofa.enabled_hint') }}</p>
            <div class="form-grid">
              <label>{{ t('twofa.code_for_action') }}</label>
              <input v-model.trim="actionCode" autocomplete="one-time-code" maxlength="16" :aria-label="t('twofa.code_for_action')" />
            </div>
            <div class="btns" style="margin-top:10px">
              <button :disabled="busy || !actionCode" @click="regenRecovery">{{ t('twofa.regen') }}</button>
              <button class="danger" :disabled="busy || !actionCode" @click="disable">{{ t('twofa.disable') }}</button>
            </div>
          </template>
        </template>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, inject, onMounted, ref } from 'vue'
import qrcode from 'qrcode-generator'
import {
  changeAuthPassword, confirmTotp, disableTotp, enrollTotp,
  getTotpStatus, regenerateTotpRecovery,
} from '../api/client'
import { authState } from '../lib/authState'
import { injectI18n } from '../i18n'

const toast = inject('toast')
const { t } = injectI18n()

// ── password rotation (always the signed-in account's own) ──────────────────
const currentPassword = ref('')
const newPassword = ref('')
const confirmPassword = ref('')
const savingPassword = ref(false)

const passwordValidation = computed(() => {
  if (!currentPassword.value) return t('settings.current_password_required')
  if (newPassword.value.length < 10) return t('auth.password_length')
  if (newPassword.value !== confirmPassword.value) return t('auth.password_mismatch')
  return ''
})
const passwordMessage = computed(() => {
  if (!currentPassword.value && !newPassword.value && !confirmPassword.value) return ''
  return passwordValidation.value
})

async function savePassword() {
  if (passwordValidation.value) {
    toast('❌ ' + passwordValidation.value)
    return
  }
  // Rotation revokes every other session of this account (epoch/hash change);
  // this browser keeps the fresh cookie set by the response.
  if (!confirm(t('settings.confirm_password_change'))) return
  savingPassword.value = true
  try {
    await changeAuthPassword(authState.username, currentPassword.value, newPassword.value)
    currentPassword.value = ''
    newPassword.value = ''
    confirmPassword.value = ''
    toast('✅ ' + t('settings.password_updated'))
  } catch (e) {
    toast('❌ ' + e.message)
  }
  savingPassword.value = false
}

// ── two-factor self-service (same endpoints the Settings page uses) ─────────
const twofa = ref(null)
const busy = ref(false)
const enrollment = ref(null)
const pairingCode = ref('')
const actionCode = ref('')
const recoveryCodes = ref([])
const copiedRecovery = ref(false)

async function loadTwofa() {
  try {
    twofa.value = await getTotpStatus()
  } catch {
    twofa.value = null
  }
}

function totpQrSvg(text) {
  // qrcode-generator renders encoded modules only; the payload is never
  // interpolated as markup, so binding the result as raw HTML is safe
  // (same argument as Settings.vue, pinned by test_security_regressions).
  try {
    const qr = qrcode(0, 'M')
    qr.addData(text)
    qr.make()
    return qr.createSvgTag({ cellSize: 4, margin: 4, scalable: true })
  } catch {
    return ''
  }
}

async function startEnroll() {
  busy.value = true
  try {
    const r = await enrollTotp()
    enrollment.value = { ...r, qrSvg: totpQrSvg(r.otpauth_uri) }
    pairingCode.value = ''
  } catch (e) {
    toast('❌ ' + e.message)
  }
  busy.value = false
}

function cancelEnroll() {
  enrollment.value = null
  pairingCode.value = ''
}

async function confirmEnroll() {
  busy.value = true
  try {
    const r = await confirmTotp(pairingCode.value)
    recoveryCodes.value = r.recovery_codes || []
    copiedRecovery.value = false
    enrollment.value = null
    pairingCode.value = ''
    toast('✅ ' + t('twofa.enabled_toast'))
    await loadTwofa()
  } catch (e) {
    toast('❌ ' + e.message)
  }
  busy.value = false
}

async function disable() {
  if (!confirm(t('twofa.disable_confirm'))) return
  busy.value = true
  try {
    await disableTotp(actionCode.value)
    actionCode.value = ''
    recoveryCodes.value = []
    toast('✅ ' + t('twofa.disabled_toast'))
    await loadTwofa()
  } catch (e) {
    toast('❌ ' + e.message)
  }
  busy.value = false
}

async function regenRecovery() {
  if (!confirm(t('twofa.regen_confirm'))) return
  busy.value = true
  try {
    const r = await regenerateTotpRecovery(actionCode.value)
    recoveryCodes.value = r.recovery_codes || []
    copiedRecovery.value = false
    actionCode.value = ''
    await loadTwofa()
  } catch (e) {
    toast('❌ ' + e.message)
  }
  busy.value = false
}

function copyRecoveryCodes() {
  navigator.clipboard.writeText(recoveryCodes.value.join('\n')).then(() => {
    copiedRecovery.value = true
    setTimeout(() => { copiedRecovery.value = false }, 2000)
  }).catch(() => toast('❌ ' + t('common.copy_failed')))
}

onMounted(loadTwofa)
</script>

<style scoped>
.account-grid { display: grid; gap: 12px; max-width: 720px; }
.card { border: 1px solid var(--line); border-radius: 10px; background: var(--card); padding: 16px; }
.section-title { font-size: 15px; margin: 18px 0 8px; }
.hint { color: var(--sub); font-size: 12px; line-height: 1.5; }
.hint.bad { color: var(--down); }
.form-grid { display: grid; grid-template-columns: 170px 1fr; gap: 8px 12px; align-items: center; margin-top: 10px; }
.form-grid label { color: var(--sub); font-size: 12px; font-weight: 600; }
.form-grid input { min-height: 36px; }
.password-footer { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-top: 12px; flex-wrap: wrap; }
.btns { display: flex; gap: 8px; flex-wrap: wrap; }
.twofa-qr { margin-top: 10px; max-width: 220px; }
.twofa-qr :deep(svg) { width: 100%; height: auto; border-radius: 6px; background: #fff; }
.twofa-recovery { margin-top: 12px; padding: 12px; border: 1px dashed var(--line); border-radius: 8px; }
.twofa-recovery-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(120px, 1fr)); gap: 6px; margin-top: 8px; }
.twofa-recovery-grid code { padding: 4px 6px; background: var(--bg); border-radius: 5px; font-size: 12px; }
@media (max-width: 560px) {
  .form-grid { grid-template-columns: 1fr; }
}
</style>
