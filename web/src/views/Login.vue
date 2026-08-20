<template>
  <main class="login-page">
    <section class="login-card">
      <div class="login-brand">
        <img src="/logo.svg" width="42" height="42" alt="" />
        <div><h1>ServerHub</h1><p>{{ setupMode ? t('auth.first_setup') : t('auth.welcome_back') }}</p></div>
      </div>

      <div v-if="loading" class="login-loading">{{ t('common.loading') }}</div>

      <!-- Second sign-in step: the password was accepted but the account
           requires a TOTP code. No session cookie exists yet — only the
           short-lived pending token held in memory here. -->
      <form v-else-if="totpStep" @submit.prevent="submitTotp">
        <div class="setup-note">
          <strong>{{ t('auth.totp_title') }}</strong>
          <span>{{ t('auth.totp_hint') }}</span>
        </div>
        <label>
          <span>{{ t('auth.totp_code') }}</span>
          <input
            v-model.trim="totpCode"
            class="totp-input"
            autocomplete="one-time-code"
            inputmode="numeric"
            maxlength="64"
            required
            autofocus
            :placeholder="t('auth.totp_placeholder')"
          />
          <small>{{ t('auth.totp_recovery_hint') }}</small>
        </label>
        <div class="login-error-live" role="alert" aria-live="assertive"><p v-if="error" class="login-error">{{ finiteText(error) }}</p></div>
        <button class="primary login-submit" :disabled="busy || !totpCode">
          {{ busy ? t('auth.processing') : t('auth.totp_submit') }}
        </button>
        <button type="button" class="totp-back" @click="leaveTotpStep">
          {{ t('auth.totp_back') }}
        </button>
      </form>

      <form v-else @submit.prevent="submit">
        <div v-if="setupMode" class="setup-note">
          <strong>{{ t('auth.secure_panel') }}</strong>
          <span>{{ t('auth.setup_hint') }}</span>
        </div>
        <!-- Only shown when this claim actually needs a token. Setting up on the
             machine itself does not: the server hands the token to any loopback
             client on request, so asking the operator to copy it from one box into
             another excludes nobody. -->
        <div v-if="setupMode && tokenNeeded && autoToken" class="token-card">
          <span class="token-label">{{ t('auth.your_token') }}</span>
          <code class="token-value">{{ finiteText(autoToken) }}</code>
          <button type="button" class="token-copy" @click="copyToken" :title="t('common.copy')">
            {{ copied ? t('common.copied') : t('common.copy') }}
          </button>
        </div>
        <div v-if="setupMode && tokenNeeded && tokenError" class="token-error" role="alert">
          {{ t('auth.token_fetch_failed') }}
        </div>
        <label>
          <span>{{ t('auth.username') }}</span>
          <input v-model.trim="username" autocomplete="username" maxlength="64" required autofocus />
        </label>
        <label v-if="setupMode && tokenNeeded">
          <span>{{ t('auth.setup_token') }}</span>
          <input v-model.trim="setupToken" type="password" autocomplete="one-time-code" minlength="32" maxlength="128" required />
          <small>{{ t('auth.setup_token_hint') }}</small>
        </label>
        <label>
          <span>{{ setupMode ? t('auth.create_password') : t('auth.password') }}</span>
          <input v-model="password" type="password" :autocomplete="setupMode ? 'new-password' : 'current-password'" minlength="10" maxlength="256" required />
        </label>
        <label v-if="setupMode">
          <span>{{ t('auth.confirm_password') }}</span>
          <input v-model="confirmPassword" type="password" autocomplete="new-password" minlength="10" maxlength="256" required />
        </label>
        <!-- The live region is rendered unconditionally and only its text
             changes. Putting role="alert" on a v-if element instead means the
             node does not exist when the region is first read, and whether an
             alert that appears with the node is announced varies by screen
             reader -- a failed login would then be silent for the one user who
             cannot see the red box. -->
        <div class="login-error-live" role="alert" aria-live="assertive"><p v-if="error" class="login-error">{{ finiteText(error) }}</p></div>
        <button class="primary login-submit" :disabled="busy">
          {{ busy ? t('auth.processing') : (setupMode ? t('auth.create_admin') : t('auth.login')) }}
        </button>
      </form>
      <p class="login-foot">{{ t('auth.local_only') }}</p>
      <div class="login-locale">
        <select :value="locale" @change="onLocale" :title="t('appearance.language')" :aria-label="t('appearance.language')">
          <option v-for="l in locales" :key="l.id" :value="l.id">{{ finiteText(l.native) }}</option>
        </select>
      </div>
    </section>
  </main>
</template>

<script setup>
import { onMounted, onUnmounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { getAuthStatus, getSetupToken, loginAuth, resetAuthLost, setupAuth, verifyTotpLogin } from '../api/client'
import { applyAuthStatus } from '../lib/authState'
import { injectI18n } from '../i18n'
import { copyToClipboard } from '../lib/clipboard'
import { finiteText } from '../lib/finite'

const { t, locale, locales, setLocale } = injectI18n()
const route = useRoute()
const router = useRouter()
const loading = ref(true)
const busy = ref(false)
const setupMode = ref(false)
const username = ref('admin')
const setupToken = ref('')
const password = ref('')
const confirmPassword = ref('')
const autoToken = ref('')
const copied = ref(false)
let copyTimer = 0
const tokenError = ref(false)
// The server decides, because only it knows where the request came from and what
// mode is configured. Defaults to true so a status call that fails cannot drop the
// token field and make the form look easier than it is.
const tokenNeeded = ref(true)
const error = ref('')
// Second-factor step state. `totpPending` is the signed short-lived token from
// the login response; it lives only in this component and is sent back exactly
// once per verification attempt.
const totpStep = ref(false)
const totpPending = ref('')
const totpCode = ref('')

let pageAlive = true
let loginGeneration = 0

onMounted(async () => {
  pageAlive = true
  try {
    const state = await getAuthStatus()
    if (!pageAlive) return
    setupMode.value = !!state.setup_required
    username.value = finiteText(state.username, '') || 'admin'
    // Absent on an older backend, where a token was always required.
    tokenNeeded.value = state.setup_token_required !== false
    if (setupMode.value && tokenNeeded.value) {
      try {
        const tokenResp = await getSetupToken()
        if (!pageAlive) return
        autoToken.value = finiteText(tokenResp.setup_token, '')
        if (autoToken.value) setupToken.value = autoToken.value
      } catch {
        if (!pageAlive) return
        tokenError.value = true
      }
    }
  } catch (e) {
    if (!pageAlive) return
    error.value = finiteText(e.message, '')
  }
  if (pageAlive) loading.value = false
})

onUnmounted(() => {
  pageAlive = false
  loginGeneration += 1
  clearTimeout(copyTimer)
})

function onLocale(e) { setLocale(e.target.value) }

async function copyToken() {
  if (!await copyToClipboard(autoToken.value)) return
  if (!pageAlive) return
  copied.value = true
  clearTimeout(copyTimer)
  copyTimer = setTimeout(() => {
    if (!pageAlive) return
    copied.value = false
  }, 2000)
}

function rememberSession(result) {
  if (!result || typeof result !== 'object') return
  applyAuthStatus({
    authenticated: true,
    username: finiteText(result.username, '') || finiteText(username.value),
    role: result.role,
    can_manage: result.can_manage,
    resources: result.resources,
  })
}

async function finishLogin() {
  if (!pageAlive) return
  // Re-arm the session-lost redirect for the new session.
  resetAuthLost()
  // Only same-origin relative paths, so ?next= cannot be used to bounce a
  // freshly authenticated user to another site.
  const raw = typeof route.query.next === 'string' ? route.query.next : ''
  const next = raw.startsWith('/') && !raw.startsWith('//') ? raw : '/'
  await router.replace(next)
}

async function submit() {
  if (busy.value) return
  error.value = ''
  if (setupMode.value && password.value !== confirmPassword.value) {
    error.value = t('auth.password_mismatch')
    return
  }
  if (password.value.length < 10) {
    error.value = t('auth.password_length')
    return
  }
  const generation = loginGeneration
  busy.value = true
  try {
    if (setupMode.value) {
      const result = await setupAuth(username.value, password.value, setupToken.value)
      if (!pageAlive) return
      if (generation !== loginGeneration) return
      rememberSession(result)
    } else {
      const result = await loginAuth(username.value, password.value)
      if (!pageAlive) return
      if (generation !== loginGeneration) return
      if (result && result.totp_required) {
        // Password accepted; the account demands a code before any session
        // exists. Keep the pending token in memory and swap the form.
        totpPending.value = finiteText(result.pending, '')
        totpCode.value = ''
        password.value = ''
        totpStep.value = true
        if (pageAlive) busy.value = false
        return
      }
      rememberSession(result)
    }
    await finishLogin()
  } catch (e) {
    if (!pageAlive) return
    if (generation !== loginGeneration) return
    error.value = finiteText(e.message, '')
  } finally {
    // leaveTotpStep / unmount bump loginGeneration so a late reply must
    // not re-enable (or keep stuck) the password form after leave.
    if (pageAlive && generation === loginGeneration) busy.value = false
  }
}

async function submitTotp() {
  if (busy.value) return
  error.value = ''
  const generation = loginGeneration
  busy.value = true
  try {
    const result = await verifyTotpLogin(totpPending.value, totpCode.value)
    if (!pageAlive) return
    if (generation !== loginGeneration) return
    rememberSession(result)
    await finishLogin()
  } catch (e) {
    if (!pageAlive) return
    if (generation !== loginGeneration) return
    error.value = finiteText(e.message, '')
    // An expired pending window can only be fixed by re-entering the
    // password; bounce back so the retry starts at the right step.
    if (e.code === 'auth.totp_pending_invalid') {
      totpStep.value = false
      totpPending.value = ''
      totpCode.value = ''
    }
  } finally {
    if (pageAlive && generation === loginGeneration) busy.value = false
  }
}

function leaveTotpStep() {
  loginGeneration += 1
  totpStep.value = false
  totpPending.value = ''
  totpCode.value = ''
  error.value = ''
  busy.value = false
}
</script>

<style scoped>
.login-page {
  min-height: 100vh; min-height: 100dvh; display: grid; place-items: center;
  padding: 20px;
  padding-top: max(20px, env(safe-area-inset-top));
  padding-bottom: max(20px, env(safe-area-inset-bottom));
  background:
    radial-gradient(900px 500px at 15% -10%, color-mix(in srgb, var(--accent) 20%, transparent), transparent 60%),
    var(--bg);
}
.login-card {
  width: min(410px, 100%); padding: 26px;
  border: 1px solid var(--line); border-radius: 12px; background: var(--card);
  box-shadow: 0 18px 50px rgba(0,0,0,.16);
  animation: loginIn .35s ease-out;
}
@keyframes loginIn {
  from { opacity: 0; transform: translateY(12px) scale(.98); }
  to { opacity: 1; transform: translateY(0) scale(1); }
}
.login-brand { display: flex; gap: 12px; align-items: center; margin-bottom: 24px; }
.login-brand img { border-radius: var(--radius-lg); }
.login-brand h1 { font-size: 22px; margin: 0; }
.login-brand p { color: var(--sub); font-size: 12px; margin-top: 2px; }
form { display: flex; flex-direction: column; gap: 14px; }
label { display: flex; flex-direction: column; gap: 5px; color: var(--sub); font-size: 12px; font-weight: 600; }
label input { width: 100%; min-height: 44px; font-size: 16px; border-radius: 8px; }
.setup-note { display: flex; flex-direction: column; gap: 3px; padding: 10px 12px; border-radius: 6px; background: color-mix(in srgb, var(--accent) 10%, var(--bg)); border-left: 3px solid var(--accent); }
.setup-note span { color: var(--sub); font-size: 12px; line-height: 1.45; }
.login-submit { min-height: 48px; margin-top: 2px; font-size: 15px; font-weight: 700; border-radius: 8px; }
/* The live-region wrappers are in the DOM from first paint so a screen reader is
   already watching them when the error lands.  While empty they must still cost
   nothing: taking them out of flow keeps the form from spending one of its 14px
   gaps on an invisible box.  Deliberately not display:none or visibility:hidden
   -- either one drops the element out of the accessibility tree, so the error
   would once again arrive as a *new* live region rather than as content added to
   one already being watched, which is the announcement browsers miss. */
.login-error-live:empty {
  position: absolute;
  width: 0;
  height: 0;
  overflow: hidden;
}
.login-error { color: var(--down); font-size: 12px; padding: 8px 10px; background: color-mix(in srgb, var(--down) 8%, transparent); border-radius: 5px; animation: shake .3s ease; }
@keyframes shake {
  0%, 100% { transform: translateX(0); }
  25% { transform: translateX(-4px); }
  75% { transform: translateX(4px); }
}
.totp-input { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; letter-spacing: 2px; }
.totp-back {
  min-height: 40px; font-size: 13px; border-radius: 8px;
  border: 1px solid var(--line); background: var(--card); color: var(--sub); cursor: pointer;
}
.totp-back:hover { background: var(--hover); }
.login-foot { color: var(--sub); font-size: 11px; text-align: center; margin-top: 18px; }
.login-loading { color: var(--sub); text-align: center; padding: 35px 0; }
.token-card { display: flex; align-items: center; gap: 8px; padding: 10px 12px; border-radius: 8px; background: color-mix(in srgb, var(--up) 8%, var(--bg)); border: 1px solid color-mix(in srgb, var(--up) 20%, transparent); }
.token-label { font-size: 11px; color: var(--sub); font-weight: 600; white-space: nowrap; }
.token-value { flex: 1; min-width: 0; font-size: 13px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; background: transparent; border: none; padding: 0; color: var(--fg); word-break: break-all; user-select: all; }
.token-copy { font-size: 11px; padding: 4px 10px; border-radius: 5px; border: 1px solid var(--line); background: var(--card); color: var(--fg); cursor: pointer; white-space: nowrap; }
.token-copy:hover { background: var(--hover); }
.token-error { font-size: 12px; color: var(--down); padding: 8px 10px; background: color-mix(in srgb, var(--down) 8%, transparent); border-radius: 5px; }
.login-locale { margin-top: 12px; text-align: center; }
.login-locale select { font-size: 12px; padding: 4px 8px; border-radius: 5px; border: 1px solid var(--line); background: var(--card); color: var(--sub); cursor: pointer; }
.login-locale select:focus { outline: 2px solid var(--accent); outline-offset: 1px; }

@media (max-width: 640px) {
  .login-card { padding: 20px 16px; border-radius: 16px; }
  .login-brand h1 { font-size: 20px; }
  form { gap: 16px; }
  label input { min-height: 48px; font-size: 16px; }
  .login-submit { min-height: 50px; }
  .token-card { flex-wrap: wrap; }
  .token-copy { margin-left: auto; }
  .login-locale select { font-size: 16px; padding: 9px 12px; }
}
</style>
