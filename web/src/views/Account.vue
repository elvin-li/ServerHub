<template>
  <div>
    <div class="page-title">
      <h1>{{ t('pages.account') }}</h1>
      <span class="meta">{{ t('account.meta', { name: finiteText(recGet(authState, 'username')) }) }}</span>
    </div>

    <div class="account-grid">
      <!-- ── password ─────────────────────────────────────────────────── -->
      <div class="card">
        <h2 class="section-title" style="margin-top:0">{{ t('account.password_title') }}</h2>
        <p class="hint" style="margin-top:0">{{ t('account.password_hint') }}</p>
        <div class="form-grid">
          <label>{{ t('settings.username') }}</label>
          <div class="mono">{{ finiteText(recGet(authState, 'username')) }}</div>
          <label>{{ t('settings.current_password') }}</label>
          <input v-model="currentPassword" type="password" autocomplete="current-password" :aria-label="t('settings.current_password')" />
          <label>{{ t('settings.new_password') }}</label>
          <input v-model="newPassword" type="password" autocomplete="new-password" minlength="10" :aria-label="t('settings.new_password')" />
          <label>{{ t('settings.confirm_password') }}</label>
          <input v-model="confirmPassword" type="password" autocomplete="new-password" minlength="10" :aria-label="t('settings.confirm_password')" />
        </div>
        <div class="password-footer">
          <!-- role=status: the Update button disables with no spoken reason —
               this hint is where the reason lives, and it changed silently.
               The text only flips at rule boundaries (empty → too short →
               mismatch → rule), not per keystroke, so polite announcements
               stay sparse. -->
          <span class="hint" :class="{ bad: !!passwordMessage }" role="status">{{ finiteText(passwordMessage, '') || t('settings.password_rule') }}</span>
          <button class="primary" :disabled="savingPassword || !!passwordValidation" @click="savePassword">
            {{ savingPassword ? t('settings.updating_password') : t('settings.update_password') }}
          </button>
        </div>
      </div>

      <!-- ── two-factor ───────────────────────────────────────────────── -->
      <div class="card">
        <h2 class="section-title" style="margin-top:0">{{ t('twofa.title') }}</h2>
        <p class="hint" style="margin-top:0">{{ t('twofa.hint') }}</p>
        <div v-if="twofaError" class="hint bad" role="alert">
          {{ finiteText(twofaError) }}
          <button class="tiny" type="button" :disabled="busy" @click="loadTwofa">{{ t('common.retry') }}</button>
        </div>
        <div v-else-if="!twofa" class="hint" role="status">{{ t('common.loading') }}</div>
        <template v-else>
          <div class="form-grid">
            <label>{{ t('common.status') }}</label>
            <div class="twofa-status">
              <span class="badge" :class="twofa.enabled ? 'ok' : 'warn'">
                {{ twofa.enabled ? t('common.on') : t('common.off') }}
              </span>
              <span v-if="twofa.enabled" class="hint">
                {{ t('twofa.recovery_remaining', { n: finiteN(twofa.recovery_remaining) }) }}
              </span>
            </div>
          </div>

          <!-- Recovery codes exist in plaintext only in the minting response;
               they are rendered once and discarded on navigation. -->
          <div v-if="asArray(recoveryCodes).length" class="twofa-recovery">
            <strong>{{ t('twofa.recovery_title') }}</strong>
            <p class="hint" style="margin-top:4px">{{ t('twofa.recovery_hint') }}</p>
            <div class="twofa-recovery-grid">
              <code v-for="code in asArray(recoveryCodes)" :key="finiteText(code)" class="mono">{{ finiteText(code) }}</code>
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
              <!-- aria-hidden: the QR encodes exactly the secret shown as
                   "Manual entry secret" below, so for a screen reader it is a
                   duplicate with no name, announced as an anonymous graphic
                   (same as the WireGuard peer QR). -->
              <div class="twofa-qr" aria-hidden="true" v-html="enrollment.qrSvg"></div>
              <div class="form-grid" style="margin-top:8px">
                <label>{{ t('twofa.manual_secret') }}</label>
                <code class="mono" style="user-select:all;word-break:break-all">{{ finiteText(enrollment.manual_entry) }}</code>
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
import { computed, inject, onMounted, onUnmounted, ref } from 'vue'
import qrcode from 'qrcode-generator'
import {
  changeAuthPassword, confirmTotp, disableTotp, enrollTotp,
  getTotpStatus, regenerateTotpRecovery,
} from '../api/client'
import { authState } from '../lib/authState'
import { copyToClipboard } from '../lib/clipboard'
import { asArray, asRecord, finiteN, finiteText, recGet } from '../lib/finite'
import { injectI18n } from '../i18n'

const toast = inject('toast')
const { t } = injectI18n()

// ── password rotation (always the signed-in account's own) ──────────────────
const currentPassword = ref('')
const newPassword = ref('')
const confirmPassword = ref('')
const savingPassword = ref(false)

function secretLen(value) {
  return typeof value === 'string' ? value.length : 0
}

const passwordValidation = computed(() => {
  if (!currentPassword.value) return t('settings.current_password_required')
  if (secretLen(newPassword.value) < 10) return t('auth.password_length')
  if (newPassword.value !== confirmPassword.value) return t('auth.password_mismatch')
  return ''
})
const passwordMessage = computed(() => {
  if (!currentPassword.value && !newPassword.value && !confirmPassword.value) return ''
  return passwordValidation.value
})

async function savePassword() {
  if (passwordValidation.value) {
    toast('❌ ' + finiteText(passwordValidation.value))
    return
  }
  // Rotation revokes every other session of this account (epoch/hash change);
  // this browser keeps the fresh cookie set by the response.
  if (!confirm(t('settings.confirm_password_change'))) return
  const generation = loadGeneration
  savingPassword.value = true
  try {
    await changeAuthPassword(recGet(authState, 'username'), currentPassword.value, newPassword.value)
    if (generation !== loadGeneration || !pageAlive) return
    currentPassword.value = ''
    newPassword.value = ''
    confirmPassword.value = ''
    toast('✅ ' + t('settings.password_updated'))
  } catch (e) {
    if (generation !== loadGeneration || !pageAlive) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    // loadTwofa() (Retry) bumps loadGeneration, so a generation match
    // would leave Update stuck after a 2FA reload during save.
    if (pageAlive) savingPassword.value = false
  }
}

// ── two-factor self-service (same endpoints the Settings page uses) ─────────
const twofa = ref(null)
const busy = ref(false)
const enrollment = ref(null)
const pairingCode = ref('')
const actionCode = ref('')
const recoveryCodes = ref([])
const copiedRecovery = ref(false)
const twofaError = ref('')
let copyTimer = 0
let pageAlive = true
let loadGeneration = 0

async function loadTwofa() {
  const generation = ++loadGeneration
  try {
    const next = asRecord(await getTotpStatus())
    if (generation !== loadGeneration || !pageAlive) return
    twofa.value = next
    twofaError.value = ''
  } catch (e) {
    if (generation !== loadGeneration || !pageAlive) return
    twofa.value = null
    twofaError.value = finiteText(e.message || String(e), '')
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
  const generation = loadGeneration
  busy.value = true
  try {
    const r = asRecord(await enrollTotp())
    if (generation !== loadGeneration || !pageAlive) return
    enrollment.value = { ...r, qrSvg: totpQrSvg(r.otpauth_uri) }
    pairingCode.value = ''
  } catch (e) {
    if (generation !== loadGeneration || !pageAlive) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (pageAlive) busy.value = false
  }
}

function cancelEnroll() {
  enrollment.value = null
  pairingCode.value = ''
}

async function confirmEnroll() {
  const generation = loadGeneration
  busy.value = true
  try {
    const r = asRecord(await confirmTotp(pairingCode.value))
    if (generation !== loadGeneration || !pageAlive) return
    recoveryCodes.value = asArray(r.recovery_codes)
    copiedRecovery.value = false
    enrollment.value = null
    pairingCode.value = ''
    toast('✅ ' + t('twofa.enabled_toast'))
    await loadTwofa()
  } catch (e) {
    if (generation !== loadGeneration || !pageAlive) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    // loadTwofa() bumps loadGeneration, so a generation match would leave
    // Confirm stuck disabled after a successful enroll.
    if (pageAlive) busy.value = false
  }
}

async function disable() {
  if (!confirm(t('twofa.disable_confirm'))) return
  const generation = loadGeneration
  busy.value = true
  try {
    await disableTotp(actionCode.value)
    if (generation !== loadGeneration || !pageAlive) return
    actionCode.value = ''
    recoveryCodes.value = []
    toast('✅ ' + t('twofa.disabled_toast'))
    await loadTwofa()
  } catch (e) {
    if (generation !== loadGeneration || !pageAlive) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    // loadTwofa() bumps loadGeneration, so a generation match would leave
    // Disable stuck after a successful write.
    if (pageAlive) busy.value = false
  }
}

async function regenRecovery() {
  if (!confirm(t('twofa.regen_confirm'))) return
  const generation = loadGeneration
  busy.value = true
  try {
    const r = asRecord(await regenerateTotpRecovery(actionCode.value))
    if (generation !== loadGeneration || !pageAlive) return
    recoveryCodes.value = asArray(r.recovery_codes)
    copiedRecovery.value = false
    actionCode.value = ''
    // Enable and disable both toast; regeneration was the one 2FA write whose
    // only feedback was a silent DOM swap below the button.
    toast('✅ ' + t('twofa.regen_toast'))
    await loadTwofa()
  } catch (e) {
    if (generation !== loadGeneration || !pageAlive) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    // loadTwofa() bumps loadGeneration, so a generation match would leave
    // Regen stuck after a successful write.
    if (pageAlive) busy.value = false
  }
}

async function copyRecoveryCodes() {
  const ok = await copyToClipboard(asArray(recoveryCodes.value).map((c) => finiteText(c, '')).filter(Boolean).join('\n'))
  if (!pageAlive) return
  if (!ok) {
    toast('❌ ' + t('common.copy_failed'))
    return
  }
  copiedRecovery.value = true
  clearTimeout(copyTimer)
  copyTimer = setTimeout(() => { if (!pageAlive) return; copiedRecovery.value = false }, 2000)
}

onMounted(() => { pageAlive = true; loadTwofa() })
onUnmounted(() => {
  pageAlive = false
  loadGeneration += 1
  clearTimeout(copyTimer)
})
</script>

<style scoped>
.account-grid { display: grid; gap: 12px; max-width: 720px; }
.card { border: 1px solid var(--line); border-radius: 10px; background: var(--card); padding: 16px; }
.section-title { font-size: 15px; margin: 18px 0 8px; }
.hint { color: var(--sub); font-size: 12px; line-height: 1.5; }
.hint.bad { color: var(--down-text); }
.form-grid { display: grid; grid-template-columns: 170px 1fr; gap: 8px 12px; align-items: center; margin-top: 10px; }
.form-grid label { color: var(--sub); font-size: 12px; font-weight: 600; }
.form-grid input { min-height: 36px; }
.password-footer { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-top: 12px; flex-wrap: wrap; }
.btns { display: flex; gap: 8px; flex-wrap: wrap; }
.twofa-status { display: flex; flex-wrap: wrap; align-items: center; gap: 6px; }
.twofa-qr {
  width: 190px; max-width: 100%; aspect-ratio: 1; margin: 10px 0;
  padding: 8px; background: #fff; border-radius: 8px; border: 1px solid var(--line);
}
.twofa-qr :deep(svg) { display: block; width: 100%; height: 100%; }
.twofa-recovery { margin-top: 12px; padding: 12px; border: 1px dashed var(--line); border-radius: 8px; }
.twofa-recovery-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(120px, 1fr)); gap: 6px; margin-top: 8px; }
.twofa-recovery-grid code { padding: 4px 6px; background: var(--bg); border-radius: 5px; font-size: 12px; overflow-wrap: anywhere; }
@media (max-width: 640px) {
  .form-grid { grid-template-columns: 1fr; }
  .form-grid label { margin-bottom: -4px; }
  .password-footer { flex-direction: column; align-items: stretch; }
  .password-footer button { width: 100%; }
  .twofa-recovery-grid { grid-template-columns: repeat(2, 1fr); }
}
</style>
