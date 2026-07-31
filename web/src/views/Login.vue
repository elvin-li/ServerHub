<template>
  <main class="login-page">
    <section class="login-card">
      <div class="login-brand">
        <img src="/logo.svg" width="42" height="42" alt="" />
        <div><h1>ServerHub</h1><p>{{ setupMode ? t('auth.first_setup') : t('auth.welcome_back') }}</p></div>
      </div>

      <div v-if="loading" class="login-loading">{{ t('common.loading') }}</div>
      <form v-else @submit.prevent="submit">
        <div v-if="setupMode" class="setup-note">
          <strong>{{ t('auth.secure_panel') }}</strong>
          <span>{{ t('auth.setup_hint') }}</span>
        </div>
        <label>
          <span>{{ t('auth.username') }}</span>
          <input v-model.trim="username" autocomplete="username" maxlength="64" required autofocus />
        </label>
        <label v-if="setupMode">
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
        <p v-if="error" class="login-error">{{ error }}</p>
        <button class="primary login-submit" :disabled="busy">
          {{ busy ? t('auth.processing') : (setupMode ? t('auth.create_admin') : t('auth.login')) }}
        </button>
      </form>
      <p class="login-foot">{{ t('auth.local_only') }}</p>
    </section>
  </main>
</template>

<script setup>
import { onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { getAuthStatus, loginAuth, resetAuthLost, setupAuth } from '../api/client'
import { injectI18n } from '../i18n'

const { t } = injectI18n()
const route = useRoute()
const router = useRouter()
const loading = ref(true)
const busy = ref(false)
const setupMode = ref(false)
const username = ref('admin')
const setupToken = ref('')
const password = ref('')
const confirmPassword = ref('')
const error = ref('')

onMounted(async () => {
  try {
    const state = await getAuthStatus()
    setupMode.value = !!state.setup_required
    username.value = state.username || 'admin'
  } catch (e) {
    error.value = e.message
  }
  loading.value = false
})

async function submit() {
  error.value = ''
  if (setupMode.value && password.value !== confirmPassword.value) {
    error.value = t('auth.password_mismatch')
    return
  }
  if (password.value.length < 10) {
    error.value = t('auth.password_length')
    return
  }
  busy.value = true
  try {
    if (setupMode.value) await setupAuth(username.value, password.value, setupToken.value)
    else await loginAuth(username.value, password.value)
    // Re-arm the session-lost redirect for the new session.
    resetAuthLost()
    // Only same-origin relative paths, so ?next= cannot be used to bounce a
    // freshly authenticated user to another site.
    const raw = typeof route.query.next === 'string' ? route.query.next : ''
    const next = raw.startsWith('/') && !raw.startsWith('//') ? raw : '/'
    await router.replace(next)
  } catch (e) {
    error.value = e.message
  }
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
.login-brand img { border-radius: 10px; }
.login-brand h1 { font-size: 22px; margin: 0; }
.login-brand p { color: var(--sub); font-size: 12px; margin-top: 2px; }
form { display: flex; flex-direction: column; gap: 14px; }
label { display: flex; flex-direction: column; gap: 5px; color: var(--sub); font-size: 12px; font-weight: 600; }
label input { width: 100%; min-height: 44px; font-size: 16px; border-radius: 8px; }
.setup-note { display: flex; flex-direction: column; gap: 3px; padding: 10px 12px; border-radius: 6px; background: color-mix(in srgb, var(--accent) 10%, var(--bg)); border-left: 3px solid var(--accent); }
.setup-note span { color: var(--sub); font-size: 12px; line-height: 1.45; }
.login-submit { min-height: 48px; margin-top: 2px; font-size: 15px; font-weight: 700; border-radius: 8px; }
.login-error { color: var(--down); font-size: 12px; padding: 8px 10px; background: color-mix(in srgb, var(--down) 8%, transparent); border-radius: 5px; animation: shake .3s ease; }
@keyframes shake {
  0%, 100% { transform: translateX(0); }
  25% { transform: translateX(-4px); }
  75% { transform: translateX(4px); }
}
.login-foot { color: var(--sub); font-size: 11px; text-align: center; margin-top: 18px; }
.login-loading { color: var(--sub); text-align: center; padding: 35px 0; }

@media (max-width: 480px) {
  .login-card { padding: 20px 16px; border-radius: 16px; }
  .login-brand h1 { font-size: 20px; }
  form { gap: 16px; }
  label input { min-height: 48px; font-size: 16px; }
  .login-submit { min-height: 50px; }
}
</style>
