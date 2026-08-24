<template>
  <div v-if="open" class="modal-bg" @click.self="cancel" role="presentation">
    <div ref="panel" class="modal admin-prompt" role="dialog" aria-modal="true" :aria-label="t('adminPrompt.title')">
      <h3>{{ t('adminPrompt.title') }}</h3>
      <p class="hint">{{ t('adminPrompt.hint') }}</p>
      <div class="admin-error-live" role="alert" aria-live="assertive"><p v-if="incorrect" class="warn">{{ t('adminPrompt.incorrect') }}</p></div>
      <form @submit.prevent="confirm">
        <input
          v-model="password"
          type="password"
          autocomplete="current-password"
          :aria-label="t('adminPrompt.password')"
        />
        <div class="actions">
          <button type="button" @click="cancel">{{ t('adminPrompt.cancel') }}</button>
          <button type="submit" class="primary" :disabled="!password">{{ t('adminPrompt.confirm') }}</button>
        </div>
      </form>
    </div>
  </div>
</template>

<script setup>
import { onMounted, onUnmounted, ref } from 'vue'
import { injectI18n } from '../i18n'
import { useDismissable } from '../composables/useDismissable'
import { registerAdminPromptHandler, unregisterAdminPromptHandler } from '../lib/adminPassword'

const { t } = injectI18n()

const open = ref(false)
const incorrect = ref(false)
const password = ref('')
const panel = ref(null)

// Several concurrent requests can hit admin.password_required at once (page
// polls); they must share one dialog instead of stacking. Keep the pending
// promise and hand the same one to every caller until it settles.
let pending = null
let resolveFn = null

function handler(wasIncorrect) {
  if (pending) {
    incorrect.value = incorrect.value || wasIncorrect
    return pending
  }
  incorrect.value = !!wasIncorrect
  password.value = ''
  open.value = true
  pending = new Promise((resolve) => { resolveFn = resolve })
  return pending
}

function settle(value) {
  open.value = false
  password.value = ''
  const resolve = resolveFn
  pending = null
  resolveFn = null
  resolve?.(value)
}

function confirm() {
  if (!password.value) return
  settle(password.value)
}

function cancel() {
  settle(null)
}

// Escape closes, focus moves into the password field and stays trapped inside.
useDismissable(open, cancel, panel)

onMounted(() => registerAdminPromptHandler(handler))
onUnmounted(() => {
  unregisterAdminPromptHandler(handler)
  settle(null)
})
</script>

<style scoped>
.admin-prompt { width: min(400px, 100%); max-height: none; gap: 10px; }
.admin-prompt h3 { margin: 0; font-size: 15px; }
.admin-prompt .hint { margin: 0; font-size: 12px; color: var(--sub); line-height: 1.5; }
.admin-error-live:empty { position: absolute; width: 0; height: 0; overflow: hidden; }
.admin-prompt .warn { margin: 0; font-size: 12px; color: var(--down-text); }
.admin-prompt input {
  width: 100%; box-sizing: border-box; padding: 9px 10px; font-size: 16px;
  border: 1px solid var(--line); border-radius: 8px; background: var(--bg);
  color: var(--txt);
}
.admin-prompt .actions { display: flex; justify-content: flex-end; gap: 8px; margin-top: 4px; }
@media (max-width: 640px) {
  .admin-prompt .actions { flex-wrap: wrap; }
  .admin-prompt .actions button { flex: 1 1 120px; min-height: 44px; }
}
</style>
