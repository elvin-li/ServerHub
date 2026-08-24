<template>
  <div>
    <!-- Appearance & Language -->
    <div v-if="tab==='appearance'">
      <div class="card" style="margin-bottom:12px">
        <h2 class="section-title" style="margin-top:0">{{ t('appearance.language') }}</h2>
        <p class="hint" style="margin-top:0">{{ t('appearance.language_hint') }}</p>
        <div class="lang-row">
          <button
            v-for="l in locales"
            :key="l.id"
            :class="{ active: locale === l.id }"
            @click="pickLocale(l.id)"
          >{{ finiteText(l.native) }}</button>
        </div>
      </div>

      <div class="card" style="margin-bottom:12px">
        <h2 class="section-title" style="margin-top:0">{{ t('theme.title') }}</h2>
        <p class="hint" style="margin-top:0">{{ t('appearance.theme_hint') }}</p>
        <label class="follow-system-row" style="display:flex;align-items:center;gap:8px;margin:0 0 12px;cursor:pointer">
          <input
            type="checkbox"
            data-test="follow-system"
            :checked="followSystemOn"
            @change="pickFollowSystem($event.target.checked)"
          >
          {{ t('theme.system') }}
        </label>
        <div class="theme-grid">
          <button
            v-for="th in themes"
            :key="th.id"
            type="button"
            class="theme-card"
            :class="{ active: (appliedTheme ?? theme) === th.id }"
            :aria-pressed="(appliedTheme ?? theme) === th.id"
            @click="pickTheme(th.id)"
          >
            <div class="swatches">
              <i v-for="(c, i) in th.swatches" :key="i" :style="{ background: c }"></i>
            </div>
            <div class="t-name">{{ t(th.labelKey) }}</div>
          </button>
        </div>
      </div>

      <div class="card">
        <h2 class="section-title" style="margin-top:0">{{ t('theme.density') }}</h2>
        <div class="density-row">
          <button
            v-for="d in densities"
            :key="d.id"
            type="button"
            :class="{ active: density === d.id }"
            :aria-pressed="density === d.id"
            @click="pickDensity(d.id)"
          >{{ t(d.labelKey) }}</button>
        </div>
        <div class="btns" style="margin-top:14px">
          <button class="primary" :disabled="saving" @click="syncUiToServer">{{ t('appearance.save_server') }}</button>
        </div>
      </div>
    </div>

    <!-- Identity -->
    <div v-else-if="tab==='identity'" class="two-col">
      <div class="card">
        <h2 class="section-title" style="margin-top:0">{{ t('settings.identity') }}</h2>
        <p class="hint" style="margin-top:0">{{ t('settings.identity_hint') }}</p>
        <div class="form-grid">
          <label>{{ t('settings.computer_name') }}</label>
          <input v-model="identityForm.computer_name" type="text" placeholder="ComputerName" :aria-label="t('settings.computer_name')" />
          <label>{{ t('settings.hostname') }}</label>
          <div class="mono">{{ finiteText(identity?.hostname) }}</div>
          <label>LocalHostName</label>
          <div class="mono">{{ finiteText(identity?.local_hostname) }}</div>
          <label>{{ t('settings.model') }}</label>
          <div class="mono" style="font-size:12px">{{ finiteText(identity?.model) }}</div>
          <label>{{ t('settings.timezone') }}</label>
          <div class="mono">{{ finiteText(identity?.timezone) }}</div>
          <label>{{ t('settings.platform') }}</label>
          <div class="mono" style="font-size:11px">{{ finiteText(identity?.platform) }}</div>
          <label>{{ t('settings.host_ip') }}</label>
          <input v-model="identityForm.host_ip" type="text" placeholder="auto" :aria-label="t('settings.host_ip')" />
          <label>{{ t('settings.probe_current') }}</label>
          <div class="mono">{{ finiteText(identity?.host_ip) }}</div>
          <label>{{ t('settings.comment') }}</label>
          <input v-model="identityForm.comment" type="text" :aria-label="t('settings.comment')" />
        </div>
        <!-- The fields above are blank until loadIdentity() succeeds, and Save
             sends them unconditionally, so a failed load must disable Save
             rather than let it write empty strings over the stored values. -->
        <div
          v-if="identityError"
          class="tile"
          style="margin-top:10px;border-left:3px solid var(--down)"
          role="alert"
        >
          <div>{{ t('settings.identity_load_failed') }}</div>
          <div class="sub mono" style="margin-top:4px">{{ finiteText(identityError) }}</div>
        </div>
        <div class="btns" style="margin-top:12px">
          <button class="primary" :disabled="saving || !identityLoaded" @click="saveIdentity">{{ t('settings.save_identity') }}</button>
          <button :disabled="saving" @click="loadIdentity">{{ t('common.reload') }}</button>
        </div>
      </div>
      <div class="card">
        <h2 class="section-title" style="margin-top:0">{{ t('settings.shortcuts') }}</h2>
        <div class="btns" style="flex-direction:column;align-items:stretch">
          <router-link class="btn" to="/users">{{ t('nav.users') }}</router-link>
          <router-link class="btn" to="/scheduler">{{ t('nav.scheduler') }}</router-link>
          <router-link class="btn" to="/health">{{ t('nav.health') }}</router-link>
          <router-link class="btn" to="/gateway">{{ t('nav.gateway') }}</router-link>
          <router-link class="btn" to="/containers">{{ t('nav.docker') }}</router-link>
        </div>
      </div>
    </div>

    <div v-else-if="tab==='panel' && form" class="two-col">
      <div
        class="card launcher-card"
        role="region"
        aria-labelledby="launcher-title"
        :aria-busy="launcherBusy || launcherLoading"
      >
        <div class="launcher-header">
          <div>
            <h2 id="launcher-title" class="section-title launcher-title">{{ t('settings.launcher_title') }}</h2>
            <p class="hint launcher-hint">{{ t('settings.launcher_hint') }}</p>
          </div>
          <span v-if="launcher" class="launcher-overall" :class="launcher.app_running && launcher.panel_running ? 'is-ready' : 'is-idle'" aria-hidden="true">
            <span class="launcher-overall-dot"></span>
            {{ launcher.app_running && launcher.panel_running ? t('common.running') : t('common.off') }}
          </span>
        </div>
        <p v-if="launcher" class="sr-only" role="status" aria-live="polite" aria-atomic="true">
          {{ t('settings.launcher_app') }}: {{ launcher.app_installed ? t('settings.launcher_installed') : t('settings.launcher_not_installed') }};
          {{ t('settings.launcher_menu_bar') }}: {{ launcher.app_running ? t('common.running') : t('common.off') }};
          {{ t('settings.launcher_panel_service') }}: {{ launcher.panel_running ? t('common.running') : t('common.stopped') }};
          {{ t('settings.launcher_login') }}: {{ launcher.login_enabled ? t('common.on') : t('common.off') }}
        </p>
        <div v-if="launcher" class="launcher-content">
          <dl class="launcher-status-grid">
            <div class="launcher-status-item">
              <dt>{{ t('settings.launcher_app') }}</dt>
              <dd><span class="badge" :class="launcher.app_installed ? 'ok' : 'down'">{{ launcher.app_installed ? t('settings.launcher_installed') : t('settings.launcher_not_installed') }}</span></dd>
            </div>
            <div class="launcher-status-item">
              <dt>{{ t('settings.launcher_menu_bar') }}</dt>
              <dd><span class="badge" :class="launcher.app_running ? 'ok' : 'warn'">{{ launcher.app_running ? t('common.running') : t('common.off') }}</span></dd>
            </div>
            <div class="launcher-status-item">
              <dt>{{ t('settings.launcher_panel_service') }}</dt>
              <dd><span class="badge" :class="launcher.panel_running ? 'ok' : 'down'">{{ launcher.panel_running ? t('common.running') : t('common.stopped') }}</span></dd>
            </div>
            <div class="launcher-status-item">
              <dt>{{ t('settings.launcher_login') }}</dt>
              <dd><span class="badge" :class="launcher.login_enabled ? 'ok' : 'warn'">{{ launcher.login_enabled ? t('common.on') : t('common.off') }}</span></dd>
            </div>
          </dl>
          <div class="launcher-path">
            <span class="launcher-path-label">{{ t('settings.launcher_path') }}</span>
            <code class="launcher-path-value">{{ finiteText(launcher.app_path) }}</code>
          </div>
        </div>
        <LoadFailure v-else-if="launcherError" :detail="launcherError" :retry="loadLauncher" :busy="launcherLoading" />
        <div v-else-if="launcherLoading" class="placeholder launcher-placeholder" role="status" aria-live="polite">{{ t('common.loading') }}</div>
        <div v-else class="placeholder launcher-placeholder launcher-unavailable" role="status" aria-live="polite">
          {{ t('settings.launcher_unavailable') }}
        </div>
        <div class="launcher-actions" role="group" :aria-label="t('settings.launcher_actions')">
          <button class="primary" :disabled="launcherBusy || launcherLoading || !launcher?.app_installed" @click="runLauncher('open')">{{ t('settings.launcher_open') }}</button>
          <button :disabled="launcherBusy || launcherLoading || !launcher?.app_installed" @click="runLauncher('login')">
            {{ launcher?.login_enabled ? t('settings.launcher_disable_login') : t('settings.launcher_enable_login') }}
          </button>
          <button :disabled="launcherBusy || launcherLoading || !launcher?.panel_registered" @click="runLauncher('restart')">{{ t('settings.launcher_restart') }}</button>
          <button :disabled="launcherBusy || launcherLoading || !launcher?.panel_running" @click="runLauncher('stop')">{{ t('settings.launcher_stop') }}</button>
          <button :disabled="launcherBusy || launcherLoading" @click="loadLauncher">{{ t('common.refresh') }}</button>
        </div>
      </div>

      <div class="card">
        <h2 class="section-title" style="margin-top:0">{{ t('settings.host_paths') }}</h2>
        <div class="form-grid">
          <label>{{ t('settings.host_ip') }}</label>
          <input v-model="form.host_ip" type="text" placeholder="auto" :aria-label="t('settings.host_ip')" />
          <label>{{ t('settings.probe_current') }}</label>
          <div class="mono">{{ finiteText(host?.lan_ip, '') || finiteText(host?.host_ip) }}</div>
          <label>{{ t('settings.hostname') }}</label>
          <div class="mono">{{ finiteText(host?.hostname) }}</div>
          <label>{{ t('settings.platform') }}</label>
          <div class="mono" style="font-size:12px">{{ finiteText(host?.platform) }}</div>
          <label>docker / orb</label>
          <div class="mono" style="font-size:12px">{{ finiteText(form.paths?.docker) }} · {{ finiteText(form.paths?.orb) }}</div>
        </div>
      </div>

      <div class="card">
        <h2 class="section-title" style="margin-top:0">{{ t('settings.auth') }}</h2>
        <div class="form-grid">
          <label>{{ t('settings.auth_enable') }}</label>
          <div>{{ t('common.on') }}</div>
          <label>{{ t('settings.auth_localhost') }}</label>
          <div>{{ t('common.off') }}</div>
          <label>{{ t('settings.current_account') }}</label>
          <div class="mono">{{ finiteText(form.auth.username) }}</div>
        </div>
        <p class="hint">{{ t('settings.auth_hint') }}</p>
      </div>

      <div class="card password-card">
        <h2 class="section-title" style="margin-top:0">{{ t('settings.password_management') }}</h2>
        <p class="hint" style="margin-top:0">{{ t('settings.password_management_hint') }}</p>
        <div class="form-grid">
          <label>{{ t('settings.username') }}</label>
          <input v-model.trim="accountForm.username" type="text" autocomplete="username" maxlength="64" :aria-label="t('settings.username')" />
          <label>{{ t('settings.current_password') }}</label>
          <input v-model="accountForm.currentPassword" type="password" autocomplete="current-password" :aria-label="t('settings.current_password')" />
          <label>{{ t('settings.new_password') }}</label>
          <input v-model="accountForm.newPassword" type="password" autocomplete="new-password" minlength="10" :aria-label="t('settings.new_password')" />
          <label>{{ t('settings.confirm_password') }}</label>
          <input v-model="accountForm.confirmPassword" type="password" autocomplete="new-password" minlength="10" :aria-label="t('settings.confirm_password')" />
        </div>
        <div class="password-footer">
          <span class="hint password-state" :class="{ bad: !!passwordMessage() }">{{ finiteText(passwordMessage(), '') || t('settings.password_rule') }}</span>
          <button class="primary" :disabled="savingPassword || !!passwordValidation()" @click="savePassword">
            {{ savingPassword ? t('settings.updating_password') : t('settings.update_password') }}
          </button>
        </div>
      </div>

      <div class="card">
        <h2 class="section-title" style="margin-top:0">{{ t('twofa.title') }}</h2>
        <p class="hint" style="margin-top:0">{{ t('twofa.hint') }}</p>
        <div v-if="twofaError" class="hint bad">
          {{ finiteText(twofaError) }}
          <button class="tiny" type="button" :disabled="twofaBusy" @click="loadTwofa">{{ t('common.retry') }}</button>
        </div>
        <div v-else-if="!twofa" class="hint">{{ t('common.loading') }}</div>
        <template v-else>
          <div class="form-grid">
            <label>{{ t('common.status') }}</label>
            <div>
              <span class="badge" :class="twofa.enabled ? 'ok' : 'warn'">
                {{ twofa.enabled ? t('common.on') : t('common.off') }}
              </span>
              <span v-if="twofa.enabled" class="hint" style="margin-left:8px">
                {{ t('twofa.recovery_remaining', { n: finiteN(twofa.recovery_remaining) }) }}
              </span>
            </div>
          </div>

          <!-- Recovery codes: rendered exactly once, straight from the response
               that minted them. Navigating away discards them forever. -->
          <div v-if="recoveryCodes.length" class="twofa-recovery">
            <strong>{{ t('twofa.recovery_title') }}</strong>
            <p class="hint" style="margin-top:4px">{{ t('twofa.recovery_hint') }}</p>
            <div class="twofa-recovery-grid">
              <code v-for="code in recoveryCodes" :key="finiteText(code)" class="mono">{{ finiteText(code) }}</code>
            </div>
            <div class="btns" style="margin-top:10px">
              <button @click="copyRecoveryCodes">{{ copiedRecovery ? t('common.copied') : t('twofa.recovery_copy') }}</button>
              <button class="primary" @click="recoveryCodes = []">{{ t('twofa.recovery_done') }}</button>
            </div>
          </div>

          <template v-if="!twofa.enabled">
            <div v-if="!twofaEnroll" class="btns" style="margin-top:10px">
              <button class="primary" :disabled="twofaBusy" @click="startTwofaEnroll">{{ t('twofa.enable') }}</button>
            </div>
            <div v-else>
              <p class="hint">{{ t('twofa.enroll_hint') }}</p>
              <div class="twofa-qr" v-html="twofaEnroll.qrSvg"></div>
              <div class="form-grid" style="margin-top:8px">
                <label>{{ t('twofa.manual_secret') }}</label>
                <code class="mono" style="user-select:all;word-break:break-all">{{ finiteText(twofaEnroll.manual_entry) }}</code>
                <label>{{ t('twofa.code_label') }}</label>
                <input v-model.trim="twofaCode" inputmode="numeric" autocomplete="one-time-code" maxlength="10" :aria-label="t('twofa.code_label')" />
              </div>
              <div class="btns" style="margin-top:10px">
                <button class="primary" :disabled="twofaBusy || !twofaCode" @click="confirmTwofaEnroll">{{ t('twofa.confirm') }}</button>
                <button :disabled="twofaBusy" @click="cancelTwofaEnroll">{{ t('common.cancel') }}</button>
              </div>
            </div>
          </template>
          <template v-else>
            <p class="hint">{{ t('twofa.enabled_hint') }}</p>
            <div class="form-grid">
              <label>{{ t('twofa.code_for_action') }}</label>
              <input v-model.trim="twofaActionCode" autocomplete="one-time-code" maxlength="16" :aria-label="t('twofa.code_for_action')" />
            </div>
            <div class="btns" style="margin-top:10px">
              <button :disabled="twofaBusy || !twofaActionCode" @click="regenTwofaRecovery">{{ t('twofa.regen') }}</button>
              <button class="danger" :disabled="twofaBusy || !twofaActionCode" @click="disableTwofa">{{ t('twofa.disable') }}</button>
            </div>
          </template>

          <h2 class="section-title">{{ t('twofa.admin_reset') }}</h2>
          <p class="hint" style="margin-top:0">{{ t('twofa.admin_reset_hint') }}</p>
          <div class="form-grid">
            <label>{{ t('settings.username') }}</label>
            <input v-model.trim="twofaResetUser" maxlength="64" :aria-label="t('twofa.admin_reset')" />
          </div>
          <div class="btns" style="margin-top:10px">
            <button class="danger" :disabled="twofaBusy || !twofaResetUser" @click="adminResetTwofa">{{ t('twofa.admin_reset_button') }}</button>
          </div>
        </template>
      </div>

      <div class="card">
        <h2 class="section-title" style="margin-top:0">{{ t('apikeys.title') }}</h2>
        <p class="hint" style="margin-top:0">{{ t('apikeys.hint') }}</p>

        <!-- The plaintext key exists only in this response; it is shown once
             with a copy button and never listed again. -->
        <div v-if="createdKey" class="apikey-created">
          <strong>{{ t('apikeys.created_title') }}</strong>
          <p class="hint" style="margin-top:4px">{{ t('apikeys.created_hint') }}</p>
          <div class="apikey-value-row">
            <code class="mono" style="user-select:all;word-break:break-all">{{ finiteText(createdKey.key) }}</code>
            <button @click="copyCreatedKey">{{ copiedKey ? t('common.copied') : t('common.copy') }}</button>
          </div>
          <div class="btns" style="margin-top:10px">
            <button class="primary" @click="createdKey = null">{{ t('common.close') }}</button>
          </div>
        </div>

        <div class="table-wrap" v-if="(apiKeys || []).length" style="margin-bottom:12px">
        <table class="dense fit-m">
          <thead>
            <tr>
              <th>{{ t('common.name') }}</th>
              <th>{{ t('apikeys.role') }}</th>
              <th class="col-hide-m">{{ t('apikeys.created') }}</th>
              <th class="col-hide-m">{{ t('apikeys.last_used') }}</th>
              <th class="col-hide-m">{{ t('apikeys.expires') }}</th>
              <th class="ops"></th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="key in apiKeys" :key="key.id">
              <td>
                {{ finiteText(key.name) }}
                <div class="show-m sub">{{ fmtEpoch(key.created) }} · {{ key.last_used ? fmtEpoch(key.last_used) : t('apikeys.never_used') }}</div>
                <div class="show-m sub">{{ key.expires ? fmtEpoch(key.expires) : t('apikeys.no_expiry') }}</div>
              </td>
              <td><span class="badge" :class="key.role === 'admin' ? 'warn' : 'ok'">{{ key.role === 'admin' ? t('apikeys.role_admin') : t('apikeys.role_member') }}</span></td>
              <td class="mono col-hide-m">{{ fmtEpoch(key.created) }}</td>
              <td class="mono col-hide-m">{{ key.last_used ? fmtEpoch(key.last_used) : t('apikeys.never_used') }}</td>
              <td class="mono col-hide-m">{{ key.expires ? fmtEpoch(key.expires) : t('apikeys.no_expiry') }}</td>
              <td class="ops">
                <button class="danger" :disabled="apiKeyBusy" @click="revokeKey(key)">{{ t('apikeys.revoke') }}</button>
              </td>
            </tr>
          </tbody>
        </table>
        </div>
        <p v-else-if="apiKeysError" class="hint" style="color:var(--down-text)">{{ finiteText(apiKeysError) }}</p>
        <p v-else-if="apiKeys" class="hint">{{ t('apikeys.empty') }}</p>
        <p v-else class="hint">{{ t('common.loading') }}</p>

        <div class="form-grid">
          <label>{{ t('common.name') }}</label>
          <input v-model.trim="newKey.name" maxlength="64" :placeholder="t('apikeys.name_ph')" :aria-label="t('common.name')" />
          <label>{{ t('apikeys.role') }}</label>
          <select v-model="newKey.role" :aria-label="t('apikeys.role')">
            <option value="member">{{ t('apikeys.role_member') }}</option>
            <option value="admin">{{ t('apikeys.role_admin') }}</option>
          </select>
          <label>{{ t('apikeys.expires_days') }}</label>
          <input v-model.number="newKey.expiresDays" type="number" min="1" max="3650" :placeholder="t('apikeys.no_expiry')" :aria-label="t('apikeys.expires_days')" />
        </div>
        <p class="hint" v-if="newKey.role === 'admin'">{{ t('apikeys.admin_warning') }}</p>
        <div class="btns" style="margin-top:10px">
          <button class="primary" :disabled="apiKeyBusy || !newKey.name" @click="createKey">{{ t('apikeys.create') }}</button>
        </div>
      </div>

      <div class="card">
        <h2 class="section-title" style="margin-top:0">{{ t('settings.intervals') }}</h2>
        <div class="form-grid">
          <label>{{ t('settings.resource_mode') }}</label>
          <select v-model="form.resource_mode" :aria-label="t('settings.resource_mode')">
            <option value="low">{{ t('settings.resource_mode_low') }}</option>
            <option value="high">{{ t('settings.resource_mode_high') }}</option>
          </select>
          <label>{{ t('settings.metrics_interval') }}</label>
          <input v-model.number="form.metrics_interval" type="number" min="15" max="600" :aria-label="t('settings.metrics_interval')" />
          <label>{{ t('settings.alert_interval') }}</label>
          <input v-model.number="form.alert_interval" type="number" min="15" max="600" :aria-label="t('settings.alert_interval')" />
        </div>
        <p class="hint">{{ t('settings.resource_mode_hint') }}</p>
        <p class="hint">{{ t('settings.intervals_hint') }}</p>
      </div>
    </div>

    <div v-else-if="tab==='notify' && form" class="two-col">
      <NotifyChannels />
      <div class="card">
        <h2 class="section-title" style="margin-top:0">{{ t('settings.notify') }}</h2>
        <p class="hint" style="margin-top:0">{{ t('settings.notify_legacy_hint') }}</p>
        <div class="form-grid">
          <label>{{ t('settings.notify_enable') }}</label>
          <input type="checkbox" v-model="form.notify.enabled" />
          <label>{{ t('settings.include_warn') }}</label>
          <input type="checkbox" v-model="form.notify.include_warn" />
          <label>{{ t('settings.notify_resolve') }}</label>
          <input type="checkbox" v-model="form.notify.notify_resolve" />
          <label>{{ t('notifych.f_ha_url') }}</label>
          <input v-model="form.notify.ha_url" type="text" :aria-label="t('notifych.f_ha_url')" />
          <label>{{ t('notifych.f_ha_service') }}</label>
          <input v-model="form.notify.ha_service" type="text" placeholder="notify.notify" :aria-label="t('notifych.f_ha_service')" />
          <label>{{ t('notifych.f_ha_token') }}</label>
          <input v-model="form.notify.ha_token" type="password" :aria-label="t('notifych.f_ha_token')" />
          <label>{{ t('notifych.f_ha_webhook_url') }}</label>
          <input v-model="form.notify.ha_webhook_url" type="text" :aria-label="t('notifych.f_ha_webhook_url')" />
        </div>
        <div class="btns" style="margin-top:10px">
          <button @click="testNotify" :disabled="saving">{{ t('settings.test_notify') }}</button>
          <button @click="forceCheck" :disabled="saving">{{ t('settings.force_check') }}</button>
        </div>
      </div>
      <div class="card">
        <h2 class="section-title" style="margin-top:0">{{ t('settings.thresholds') }}</h2>
        <p class="hint" style="margin-top:0">{{ t('settings.thresholds_hint') }}</p>
        <div class="form-grid">
          <label>{{ t('settings.th_enable') }}</label>
          <input type="checkbox" v-model="form.thresholds.enabled" />
          <label>{{ t('settings.th_cpu') }}</label>
          <input v-model.number="form.thresholds.cpu_pct" type="number" min="50" max="100" :aria-label="t('settings.th_cpu')" />
          <label>{{ t('settings.th_mem') }}</label>
          <input v-model.number="form.thresholds.mem_pct" type="number" min="50" max="100" :aria-label="t('settings.th_mem')" />
          <label>{{ t('settings.th_disk') }}</label>
          <input v-model.number="form.thresholds.disk_pct" type="number" min="50" max="100" :aria-label="t('settings.th_disk')" />
          <label>{{ t('settings.th_cooldown') }}</label>
          <input v-model.number="form.thresholds.cooldown_sec" type="number" min="60" max="86400" :aria-label="t('settings.th_cooldown')" />
        </div>
        <p class="hint">{{ t('settings.th_cooldown_hint') }}</p>

        <!-- Own switch, not gated on th_enable: usage alerts and "this disk is
             dying" have very different signal-to-noise, and an operator who muted
             the chatty one must not lose the one that matters.  min/max mirror the
             server's ThresholdsPatch, which rejects anything outside them. -->
        <h2 class="section-title">{{ t('settings.th_smart') }}</h2>
        <p class="hint" style="margin-top:0">{{ t('settings.th_smart_hint') }}</p>
        <div class="form-grid">
          <label>{{ t('settings.th_smart_enable') }}</label>
          <input type="checkbox" v-model="form.thresholds.smart_enabled" :aria-label="t('settings.th_smart_enable')" />
          <label>{{ t('settings.th_smart_temp') }}</label>
          <input v-model.number="form.thresholds.smart_temp_c" type="number" min="30" max="95" :aria-label="t('settings.th_smart_temp')" />
          <label>{{ t('settings.th_smart_wear') }}</label>
          <input v-model.number="form.thresholds.smart_wear_pct" type="number" min="50" max="100" :aria-label="t('settings.th_smart_wear')" />
          <label>{{ t('settings.th_smart_spare') }}</label>
          <input v-model.number="form.thresholds.smart_spare_pct" type="number" min="1" max="50" :aria-label="t('settings.th_smart_spare')" />
        </div>
        <!-- Available Spare counts down, so this one is a floor.  Without saying so
             the field reads like every other limit on this page and gets set to 90,
             which alerts on every healthy disk. -->
        <p class="hint">{{ t('settings.th_smart_spare_hint') }}</p>
      </div>

      <div class="card">
        <h2 class="section-title" style="margin-top:0">{{ t('settings.ups_alerts') }}</h2>
        <p class="hint" style="margin-top:0">{{ t('settings.ups_alerts_hint') }}</p>
        <LoadFailure v-if="upsError && !upsInfo" :detail="upsError" :retry="loadUps" />
        <div class="form-grid" v-else-if="upsInfo">
          <label>{{ t('settings.power_source') }}</label>
          <div>
            <span v-if="upsInfo.present" class="badge" :class="upsInfo.on_battery ? 'warn' : 'ok'">
              {{ upsInfo.on_battery ? t('dashboard.ups_on_battery') : t('dashboard.ups_on_ac') }}
            </span>
            <span v-else class="sub">{{ t('settings.ups_none') }}</span>
            <span v-if="finiteN(upsInfo.battery_percent, null) != null" class="mono" style="margin-left:8px">
              {{ withUnit(upsInfo.battery_percent, '%') }}
            </span>
            <span v-if="upsPhase !== 'idle'" class="badge down" style="margin-left:8px">
              {{ upsPhase === 'engaged' ? t('settings.ups_phase_engaged') : t('settings.ups_phase_restoring') }}
            </span>
          </div>
          <label>{{ t('settings.ups_alerts_enable') }}</label>
          <input type="checkbox" v-model="upsForm.alerts_enabled" :aria-label="t('settings.ups_alerts_enable')" />
          <label>{{ t('settings.ups_low_pct') }}</label>
          <input v-model.number="upsForm.low_battery_pct" type="number" min="5" max="95" :aria-label="t('settings.ups_low_pct')" />
        </div>
        <div v-else class="sub">{{ t('common.loading') }}</div>

        <template v-if="upsInfo">
          <h2 class="section-title">{{ t('settings.ups_shutdown_title') }}</h2>
          <p class="hint" style="margin-top:0">{{ t('settings.ups_shutdown_hint') }}</p>
          <div class="form-grid">
            <label>{{ t('settings.ups_shutdown_enable') }}</label>
            <input type="checkbox" v-model="upsForm.shutdown.enabled" :aria-label="t('settings.ups_shutdown_enable')" />
            <label>{{ t('settings.ups_shutdown_pct') }}</label>
            <input v-model="upsForm.shutdown.trigger_pct" type="number" min="5" max="95"
                   :placeholder="t('settings.ups_shutdown_empty_off')"
                   :aria-label="t('settings.ups_shutdown_pct')" />
            <label>{{ t('settings.ups_shutdown_remaining') }}</label>
            <input v-model="upsForm.shutdown.trigger_remaining_min" type="number" min="1" max="720"
                   :placeholder="t('settings.ups_shutdown_empty_off')"
                   :aria-label="t('settings.ups_shutdown_remaining')" />
            <label>{{ t('settings.ups_shutdown_mode') }}</label>
            <select v-model="upsForm.shutdown.require_both" :aria-label="t('settings.ups_shutdown_mode')">
              <option :value="false">{{ t('settings.ups_shutdown_mode_any') }}</option>
              <option :value="true">{{ t('settings.ups_shutdown_mode_both') }}</option>
            </select>
            <label>{{ t('settings.ups_shutdown_stacks') }}</label>
            <div>
              <select v-model="upsForm.shutdown.stacksMode" :aria-label="t('settings.ups_shutdown_stacks')">
                <option value="all">{{ t('settings.ups_shutdown_stacks_all') }}</option>
                <option value="custom">{{ t('settings.ups_shutdown_stacks_custom') }}</option>
              </select>
              <div v-if="upsForm.shutdown.stacksMode === 'custom'" style="margin-top:6px">
                <div v-for="(row, i) in upsStackRows" :key="row.id" class="ups-pick-row">
                  <input type="checkbox" v-model="row.selected" :aria-label="finiteText(row.id)" />
                  <span class="mono">
                    {{ finiteText(row.name) }}
                    <span class="sub" v-if="row.missing">· {{ t('settings.ups_shutdown_stack_missing') }}</span>
                  </span>
                  <button class="btn" :disabled="i === 0" :aria-label="t('settings.ups_move_up')"
                          @click="moveStackRow(i, -1)">↑</button>
                  <button class="btn" :disabled="i === upsStackRows.length - 1" :aria-label="t('settings.ups_move_down')"
                          @click="moveStackRow(i, 1)">↓</button>
                </div>
                <p class="hint" style="margin:4px 0 0">{{ t('settings.ups_shutdown_order_hint') }}</p>
              </div>
            </div>
            <label v-if="upsScriptChoices.length">{{ t('settings.ups_shutdown_scripts') }}</label>
            <div v-if="upsScriptChoices.length">
              <div v-for="s in upsScriptChoices" :key="s.id" class="ups-pick-row">
                <input type="checkbox" :value="s.id" v-model="upsForm.shutdown.stop_scripts" :aria-label="finiteText(s.id)" />
                <span class="mono">{{ finiteText(s.name) }}</span>
              </div>
            </div>
          </div>

          <div class="btns" style="margin-top:10px">
            <button class="primary" :disabled="saving" @click="saveUps">{{ t('common.save') }}</button>
            <button class="btn" :disabled="saving || drillBusy" @click="runDrill">
              {{ t('settings.ups_shutdown_drill') }}
            </button>
          </div>

          <div v-if="upsDrill" style="margin-top:10px" data-test="drill-result">
            <p class="hint" style="margin:0 0 6px">
              <template v-if="upsDrill.would_trigger_now">
                {{ t('settings.ups_would_trigger', { reason: upsDrill.reason }) }}
              </template>
              <template v-else>{{ t('settings.ups_would_not_trigger') }}</template>
            </p>
            <div v-for="s in upsDrill.steps" :key="s.kind + ':' + s.id"
                 style="display:flex;align-items:center;gap:8px;padding:2px 0">
              <span class="badge" :class="s.running ? 'warn' : ''">
                {{ s.running ? t('settings.ups_step_stop') : t('settings.ups_step_skip') }}
              </span>
              <span class="mono">{{ finiteText(s.name, '') || finiteText(s.id) }}</span>
              <span class="sub">{{ s.kind === 'stack' ? 'compose' : 'service' }}</span>
            </div>
          </div>

          <p class="hint" v-if="upsLast" style="margin-top:10px" data-test="last-run">
            {{ t('settings.ups_last_trigger', { time: fmtUpsTs(upsLast.engaged_at), reason: finiteText(upsLast.reason) }) }}
            <template v-if="upsLast.restored_at">
              · {{ t('settings.ups_last_restored', { time: fmtUpsTs(upsLast.restored_at), n: (upsLast.restarted || []).length }) }}
            </template>
            <template v-if="(upsLast.failed || []).length">
              · {{ t('settings.ups_last_failed', { ids: (upsLast.failed || []).map(n => finiteText(n, '')).filter(Boolean).join(', ') }) }}
            </template>
          </p>

          <h2 class="section-title">{{ t('settings.ups_halt_title') }}</h2>
          <p class="hint" style="margin-top:0">{{ t('settings.ups_halt_hint') }}</p>
          <div class="form-grid">
            <label>{{ t('settings.ups_halt_current') }}</label>
            <div class="mono">
              <template v-if="upsInfo.halt_levels">
                <span v-if="finiteN(upsInfo.halt_levels.haltlevel, null) != null">haltlevel {{ withUnit(upsInfo.halt_levels.haltlevel, '%') }}</span>
                <span v-if="finiteN(upsInfo.halt_levels.haltafter, null) != null" style="margin-left:8px">haltafter {{ withUnit(upsInfo.halt_levels.haltafter, ' min') }}</span>
                <span v-if="finiteN(upsInfo.halt_levels.haltremain, null) != null" style="margin-left:8px">haltremain {{ withUnit(upsInfo.halt_levels.haltremain, ' min') }}</span>
              </template>
              <span v-else class="sub">{{ t('settings.ups_halt_none') }}</span>
            </div>
            <label>{{ t('settings.ups_halt_level') }}</label>
            <div>
              <input v-model.number="haltLevel" type="number" min="-1" max="95" style="width:90px"
                     :aria-label="t('settings.ups_halt_level')" />
              <button class="btn" style="margin-left:8px" :disabled="saving || haltLevel === null || haltLevel === ''"
                      @click="saveHalt">{{ t('settings.ups_halt_set') }}</button>
            </div>
          </div>
        </template>
      </div>
    </div>

    <div v-else-if="tab==='docker'">
      <LoadFailure v-if="dockerError" :detail="dockerError" :retry="loadDockerInfo" />
      <div class="card" v-if="dockerInfo">
        <h2 class="section-title" style="margin-top:0">{{ t('settings.docker_engine') }}</h2>
        <p class="hint" style="margin-top:0">{{ t('settings.docker_hint') }}</p>
        <div class="form-grid" v-if="dockerInfo.engine_up">
          <label>{{ t('common.engine') }}</label>
          <div><span class="badge ok">{{ t('common.running') }}</span> {{ finiteText(dockerInfo.info?.Name, '') }}</div>
          <label>Version</label>
          <div class="mono">{{ finiteText(dockerInfo.info?.ServerVersion) }}</div>
          <label>OrbStack</label>
          <div class="mono">{{ finiteText(dockerInfo.orb_version) }}</div>
          <label>OS / Arch</label>
          <div class="mono">{{ finiteText(dockerInfo.info?.OperatingSystem) }} · {{ finiteText(dockerInfo.info?.Architecture) }}</div>
          <label>CPU / RAM</label>
          <div>{{ finiteN(dockerInfo.info?.NCPU) }} · {{ memGb(dockerInfo.info?.MemTotal) }} GB</div>
          <label>Driver</label>
          <div class="mono">{{ finiteText(dockerInfo.info?.Driver) }} · {{ finiteText(dockerInfo.info?.DockerRootDir) }}</div>
          <label>Containers</label>
          <div>
            {{ t('common.running') }} {{ finiteN(dockerInfo.info?.ContainersRunning, 0) }}
            · {{ t('common.stopped') }} {{ finiteN(dockerInfo.info?.ContainersStopped, 0) }}
            · images {{ finiteN(dockerInfo.info?.Images, 0) }}
          </div>
        </div>
        <div v-else class="placeholder">{{ finiteText(dockerInfo.message, '') || t('common.off') }}</div>
        <div class="btns" style="margin-top:12px">
          <router-link class="btn primary" to="/containers">{{ t('nav.docker') }}</router-link>
          <button @click="loadDockerInfo">{{ t('common.refresh') }}</button>
        </div>
      </div>
      <div v-else-if="!dockerError" class="placeholder">{{ t('common.loading') }}</div>
    </div>

    <!-- VMs -->
    <div v-else-if="tab==='vms'" class="two-col">
      <div class="card">
        <h2 class="section-title" style="margin-top:0">{{ t('settings.vm_manager') }}</h2>
        <p class="hint" style="margin-top:0">{{ t('settings.vm_hint') }}</p>
        <div class="form-grid" v-if="sysBundle?.vms">
          <label>UTM</label>
          <div>
            <span class="badge" :class="sysBundle.vms.utm_available ? 'ok' : 'warn'">
              {{ sysBundle.vms.utm_available ? t('common.ok') : '—' }}
            </span>
          </div>
          <label>OrbStack</label>
          <div>
            <span class="badge" :class="sysBundle.vms.orb_available ? 'ok' : 'warn'">
              {{ sysBundle.vms.orb_available ? t('common.ok') : '—' }}
            </span>
          </div>
          <label>{{ t('settings.vm_total') }}</label>
          <div>{{ finiteN(sysBundle.vms.total, 0) }} · {{ t('common.running') }} {{ finiteN(sysBundle.vms.running, 0) }}</div>
        </div>
        <div class="btns" style="margin-top:12px">
          <router-link class="btn primary" to="/vms">{{ t('nav.vms') }}</router-link>
          <button @click="loadSysBundle">{{ t('common.refresh') }}</button>
        </div>
      </div>
      <div class="card">
        <h2 class="section-title" style="margin-top:0">{{ t('settings.vm_list') }}</h2>
        <div v-if="sysBundleError && !sysBundle" class="sub" style="color:var(--down-text)">{{ finiteText(sysBundleError) }}</div>
        <div v-else-if="!sysBundle" class="sub">{{ t('common.loading') }}</div>
        <div class="table-wrap" v-else-if="(sysBundle.vms?.items||[]).length">
        <table class="dense fit-m">
          <thead><tr><th>{{ t('common.name') }}</th><th>{{ t('common.status') }}</th><th>Backend</th></tr></thead>
          <tbody>
            <tr v-for="v in sysBundle.vms.items" :key="v.id">
              <td>{{ finiteText(v.name) }}</td>
              <td><span class="badge">{{ finiteText(v.state) }}</span></td>
              <td class="mono">{{ finiteText(v.backend) }}</td>
            </tr>
          </tbody>
        </table>
        </div>
        <div v-else class="sub">{{ t('settings.vm_empty') }}</div>
      </div>
    </div>

    <!-- Date & Time -->
    <div v-else-if="tab==='datetime'" class="two-col">
      <div class="card">
        <h2 class="section-title" style="margin-top:0">{{ t('settings.datetime') }}</h2>
        <p class="hint" style="margin-top:0">{{ t('settings.datetime_hint') }}</p>
        <div class="form-grid" v-if="sysBundle?.datetime">
          <label>{{ t('settings.now') }}</label>
          <div class="mono">{{ finiteText(sysBundle.datetime.now) }}</div>
          <label>{{ t('settings.timezone') }}</label>
          <div class="mono">{{ finiteText(sysBundle.datetime.timezone) }}</div>
          <label>NTP</label>
          <div>
            <span class="badge" :class="sysBundle.datetime.ntp_enabled ? 'ok' : 'warn'">
              {{ sysBundle.datetime.ntp_enabled == null ? '—' : (sysBundle.datetime.ntp_enabled ? t('common.on') : t('common.off')) }}
            </span>
            <span class="mono" style="margin-left:8px">{{ finiteText(sysBundle.datetime.ntp_server, '') }}</span>
          </div>
          <label>Unix</label>
          <div class="mono">{{ finiteN(sysBundle.datetime.unix) }}</div>
        </div>
        <p class="hint">{{ finiteText(sysBundle?.datetime?.hint) }}</p>
        <div class="btns" style="margin-top:10px">
          <button class="primary" @click="loadSysBundle">{{ t('common.refresh') }}</button>
        </div>
      </div>
      <div class="card">
        <h2 class="section-title" style="margin-top:0">{{ t('settings.shortcuts') }}</h2>
        <div class="btns" style="flex-direction:column;align-items:stretch">
          <router-link class="btn" to="/scheduler">{{ t('nav.scheduler') }}</router-link>
          <router-link class="btn" to="/maintenance">{{ t('nav.maintenance') }}</router-link>
        </div>
      </div>
    </div>

    <!-- Power + UPS -->
    <div v-else-if="tab==='power'" class="two-col">
      <div class="card">
        <h2 class="section-title" style="margin-top:0">{{ t('settings.power') }}</h2>
        <p class="hint" style="margin-top:0">{{ t('settings.power_hint') }}</p>
        <div class="form-grid" v-if="sysBundle?.power">
          <label>{{ t('settings.sleep') }}</label>
          <div class="row" style="gap:8px">
            <input v-model.number="powerForm.sleep" type="number" min="0" max="180" style="width:80px" :aria-label="t('settings.sleep')" />
            <span class="meta">{{ t('settings.minutes') }} · 0={{ t('settings.never') }}</span>
            <button class="tiny" :disabled="saving" @click="applyPower('sleep')">{{ t('common.apply') }}</button>
          </div>
          <label>{{ t('settings.displaysleep') }}</label>
          <div class="row" style="gap:8px">
            <input v-model.number="powerForm.displaysleep" type="number" min="0" max="180" style="width:80px" :aria-label="t('settings.displaysleep')" />
            <span class="meta">{{ t('settings.minutes') }}</span>
            <button class="tiny" :disabled="saving" @click="applyPower('displaysleep')">{{ t('common.apply') }}</button>
          </div>
          <label>{{ t('settings.disksleep') }}</label>
          <div class="row" style="gap:8px">
            <input v-model.number="powerForm.disksleep" type="number" min="0" max="180" style="width:80px" :aria-label="t('settings.disksleep')" />
            <span class="meta">{{ t('settings.minutes') }}</span>
            <button class="tiny" :disabled="saving" @click="applyPower('disksleep')">{{ t('common.apply') }}</button>
          </div>
          <label>WoL</label>
          <div class="row" style="gap:8px">
            <select v-model.number="powerForm.womp" style="width:100px">
              <option :value="1">{{ t('common.on') }}</option>
              <option :value="0">{{ t('common.off') }}</option>
            </select>
            <button class="tiny" :disabled="saving" @click="applyPower('womp')">{{ t('common.apply') }}</button>
          </div>
        </div>
        <p class="hint">{{ finiteText(sysBundle?.power?.hint) }}</p>
      </div>
      <div class="card">
        <h2 class="section-title" style="margin-top:0">{{ t('settings.ups') }}</h2>
        <div class="form-grid" v-if="sysBundle?.power?.ups">
          <label>{{ t('settings.power_source') }}</label>
          <div>
            <span class="badge" :class="sysBundle.power.ups.on_ac ? 'ok' : 'warn'">
              {{ sysBundle.power.ups.source === 'ac' ? 'AC' : finiteText(sysBundle.power.ups.source) }}
            </span>
          </div>
          <label>{{ t('settings.battery') }}</label>
          <div>
            <span v-if="finiteN(sysBundle.power.ups.battery_percent, null) != null">
              {{ withUnit(sysBundle.power.ups.battery_percent, '%') }}
              <span class="meta" v-if="sysBundle.power.ups.charging">· {{ t('settings.charging') }}</span>
            </span>
            <span v-else>—</span>
          </div>
        </div>
        <p class="hint">{{ finiteText(sysBundle?.power?.ups?.hint) }}</p>
        <h2 class="section-title">{{ t('settings.assertions') }}</h2>
        <div v-if="sysBundleError && !sysBundle" class="sub" style="color:var(--down-text)">{{ finiteText(sysBundleError) }}</div>
        <div v-else-if="!sysBundle" class="sub">{{ t('common.loading') }}</div>
        <div v-else-if="(sysBundle.power?.assertions||[]).length" class="mono" style="font-size:11px;max-height:180px;overflow:auto">
          <div v-for="(a,i) in sysBundle.power.assertions" :key="i" style="margin-bottom:6px">{{ finiteText(a) }}</div>
        </div>
        <div v-else class="sub">{{ t('settings.no_assertions') }}</div>
        <p v-if="hiddenAssertions" class="hint">
          {{ t('settings.assertions_truncated', {
            shown: (sysBundle?.power?.assertions || []).length,
            total: finiteN(sysBundle?.power?.assertion_count),
          }) }}
        </p>
        <div class="btns" style="margin-top:10px">
          <button @click="loadSysBundle">{{ t('common.refresh') }}</button>
          <router-link class="btn" to="/maintenance">{{ t('nav.maintenance') }}</router-link>
        </div>
      </div>
    </div>

    <!-- Disk -->
    <div v-else-if="tab==='disk'" class="two-col">
      <div class="card">
        <h2 class="section-title" style="margin-top:0">{{ t('settings.disk') }}</h2>
        <p class="hint" style="margin-top:0">{{ t('settings.disk_hint') }}</p>
        <div class="form-grid" v-if="sysBundle?.disk">
          <label>disksleep</label>
          <div>{{ finiteN(sysBundle.disk.disksleep_minutes) }} {{ t('settings.minutes') }}</div>
          <label>{{ t('settings.disk_count') }}</label>
          <div>{{ finiteN(sysBundle.disk.disk_count, 0) }}</div>
        </div>
        <p class="hint">{{ finiteText(sysBundle?.disk?.hint) }}</p>
        <div class="btns" style="margin-top:10px">
          <router-link class="btn primary" to="/main">{{ t('nav.main') }}</router-link>
        </div>
      </div>
      <div class="card">
        <h2 class="section-title" style="margin-top:0">{{ t('settings.disk_power') }}</h2>
        <div v-if="sysBundleError && !sysBundle" class="sub" style="color:var(--down-text)">{{ finiteText(sysBundleError) }}</div>
        <div v-else-if="!sysBundle" class="sub">{{ t('common.loading') }}</div>
        <div class="table-wrap" v-else-if="(sysBundle.disk?.power_disks||[]).length">
        <table class="dense fit-m">
          <thead><tr><th>{{ t('settings.disk') }}</th><th>{{ t('common.status') }}</th><th>{{ t('common.size') }}</th></tr></thead>
          <tbody>
            <tr v-for="d in sysBundle.disk.power_disks" :key="d.id">
              <td>{{ finiteText(d.name) }}</td>
              <td><span class="badge">{{ finiteText(d.power_state) }}</span></td>
              <td class="mono">{{ sizeGb(d.size_gb) }}</td>
            </tr>
          </tbody>
        </table>
        </div>
        <div v-else class="sub">{{ t('settings.disk_power_empty') }}</div>
      </div>
    </div>

    <!-- Network -->
    <div v-else-if="tab==='network'" class="two-col">
      <div class="card">
        <h2 class="section-title" style="margin-top:0">{{ t('settings.network') }}</h2>
        <p class="hint" style="margin-top:0">{{ t('settings.network_hint') }}</p>
        <div class="form-grid" v-if="sysBundle?.alias_auto">
          <label>{{ t('settings.auto_bind') }}</label>
          <div>
            <span class="badge" :class="sysBundle.alias_auto.config?.auto_bind ? 'ok' : 'warn'">
              {{ sysBundle.alias_auto.config?.auto_bind ? t('common.on') : t('common.off') }}
            </span>
          </div>
          <label>{{ t('settings.preferred_nic') }}</label>
          <div class="mono" v-if="sysBundle.alias_auto.preferred">
            {{ finiteText(sysBundle.alias_auto.preferred.device) }} · {{ finiteText(sysBundle.alias_auto.preferred.service) }}
            · {{ finiteText(sysBundle.alias_auto.preferred.primary_ip) }}
          </div>
          <div v-else style="color:var(--down-text)">—</div>
          <label>{{ t('settings.managed_ips') }}</label>
          <div>
            <span v-for="ip in (sysBundle.alias_auto.config?.ips||[])" :key="ip" class="badge ok" style="margin-right:4px">{{ finiteText(ip) }}</span>
          </div>
        </div>
        <div class="btns" style="margin-top:12px">
          <router-link class="btn primary" to="/network">{{ t('nav.network') }}</router-link>
          <button @click="runAliasAlign" :disabled="saving">{{ t('settings.align_alias') }}</button>
          <button @click="loadSysBundle">{{ t('common.refresh') }}</button>
        </div>
      </div>
      <div class="card">
        <h2 class="section-title" style="margin-top:0">{{ t('settings.shortcuts') }}</h2>
        <div class="btns" style="flex-direction:column;align-items:stretch">
          <router-link class="btn" to="/network">{{ t('nav.network') }}</router-link>
          <router-link class="btn" to="/gateway">{{ t('nav.gateway') }}</router-link>
          <router-link class="btn" to="/wireguard">{{ t('nav.wireguard') }}</router-link>
          <router-link class="btn" to="/bookmarks">{{ t('nav.bookmarks') }}</router-link>
        </div>
      </div>
    </div>

    <!-- Shares -->
    <div v-else-if="tab==='shares'" class="two-col">
      <div class="card">
        <h2 class="section-title" style="margin-top:0">{{ t('settings.shares') }}</h2>
        <p class="hint" style="margin-top:0">{{ t('settings.shares_hint') }}</p>
        <div class="form-grid" v-if="sysBundle?.shares">
          <label>smbd</label>
          <div>
            <span class="badge" :class="sysBundle.shares.smb_running ? 'ok' : 'down'">
              {{ sysBundle.shares.smb_running ? t('common.running') : t('common.off') }}
            </span>
          </div>
          <label>{{ t('settings.share_count') }}</label>
          <div>{{ finiteN(sysBundle.shares.share_count, 0) }}</div>
        </div>
        <p class="hint">{{ finiteText(sysBundle?.shares?.hint) }}</p>
        <div class="btns" style="margin-top:10px">
          <router-link class="btn primary" to="/shares">{{ t('nav.shares') }}</router-link>
          <router-link class="btn" to="/users">{{ t('nav.users') }}</router-link>
        </div>
      </div>
    </div>

    <!-- Scheduler -->
    <div v-else-if="tab==='scheduler'" class="two-col">
      <div class="card">
        <h2 class="section-title" style="margin-top:0">{{ t('settings.scheduler') }}</h2>
        <p class="hint" style="margin-top:0">{{ t('settings.scheduler_hint') }}</p>
        <div class="form-grid" v-if="sysBundle?.scheduler">
          <label>{{ t('settings.timer_count') }}</label>
          <div>{{ finiteN(sysBundle.scheduler.count, 0) }}</div>
        </div>
        <div class="table-wrap" style="margin-top:10px" v-if="(sysBundle?.scheduler?.timers||[]).length">
        <table class="dense fit-m">
          <thead><tr><th>{{ t('common.name') }}</th><th>Interval</th></tr></thead>
          <tbody>
            <tr v-for="(tm, i) in sysBundle.scheduler.timers.slice(0, 15)" :key="i">
              <td class="mono" style="font-size:11px">{{ finiteText(tm.label) }}</td>
              <td class="mono">{{ finiteN(tm.interval, null) != null ? withUnit(tm.interval, 's') : (tm.calendar ? 'cal' : '—') }}</td>
            </tr>
          </tbody>
        </table>
        </div>
        <div class="btns" style="margin-top:12px">
          <router-link class="btn primary" to="/scheduler">{{ t('nav.scheduler') }}</router-link>
          <router-link class="btn" to="/maintenance">{{ t('nav.maintenance') }}</router-link>
          <button @click="loadSysBundle">{{ t('common.refresh') }}</button>
        </div>
      </div>
    </div>

    <!-- Management Access -->
    <div v-else-if="tab==='access'" class="two-col">
      <div class="card">
        <h2 class="section-title" style="margin-top:0">{{ t('settings.access') }}</h2>
        <p class="hint" style="margin-top:0">{{ t('settings.access_hint') }}</p>
        <div class="form-grid" v-if="sysBundle?.management">
          <label>{{ t('settings.panel_port') }}</label>
          <div class="mono">{{ finiteN(sysBundle.management.panel_port) }}</div>
          <label>{{ t('settings.auth') }}</label>
          <div>
            <span class="badge" :class="sysBundle.management.auth_enabled ? 'ok' : 'warn'">
              {{ sysBundle.management.auth_enabled ? t('common.on') : t('common.off') }}
            </span>
            · {{ finiteText(sysBundle.management.username) }}
          </div>
          <label>{{ t('settings.auth_localhost') }}</label>
          <div>{{ sysBundle.management.allow_localhost ? t('common.yes') : t('common.no') }}</div>
          <label>Host IP</label>
          <div class="mono">{{ finiteText(sysBundle.management.host_ip) }}</div>
          <label>Nginx HTTPS</label>
          <div class="mono">{{ finiteText(sysBundle.management.nginx_https) }}</div>
          <label>{{ t('settings.version') }}</label>
          <div>
            ServerHub {{ finiteText(sysBundle.management.version) }}
            <template v-if="sysBundle.management.panel_update?.update_available">
              · {{ t('settings.update_available', { v: finiteText(sysBundle.management.panel_update.latest) }) }}
              <router-link class="btn tiny primary" to="/tools?tab=updates">{{ t('dashboard.open_updates') }}</router-link>
            </template>
          </div>
        </div>
        <div class="btns" style="margin-top:12px">
          <button class="primary" @click="switchTab('panel')">{{ t('settings.edit_panel') }}</button>
          <a class="btn" href="/api/export/services-yaml" download="services.yaml">{{ t('settings.export_yaml') }}</a>
        </div>
      </div>
      <div class="card">
        <h2 class="section-title" style="margin-top:0">{{ t('settings.paths') }}</h2>
        <div class="mono" style="font-size:11px;line-height:1.6" v-if="sysBundle?.management?.paths">
          <div>BASE: {{ finiteText(sysBundle.management.paths.base) }}</div>
          <div>YAML: {{ finiteText(sysBundle.management.paths.services_yaml) }}</div>
          <div v-if="sysBundle.management.paths.data">DATA: {{ finiteText(sysBundle.management.paths.data) }}</div>
        </div>
        <div class="btns" style="margin-top:12px;flex-direction:column;align-items:stretch">
          <router-link class="btn" to="/modules">{{ t('nav.modules') }}</router-link>
          <router-link class="btn" to="/health">{{ t('nav.health') }}</router-link>
          <router-link class="btn" to="/backups">{{ t('nav.backups') }}</router-link>
        </div>
      </div>
    </div>

    <!-- Advanced / Other -->
    <div v-else-if="tab==='advanced' && form">
    <div class="two-col">
      <div class="card">
        <h2 class="section-title" style="margin-top:0">{{ t('settings.advanced') }}</h2>
        <p class="hint" style="margin-top:0">{{ t('settings.advanced_hint') }}</p>
        <div class="form-grid">
          <label>{{ t('settings.adaptive') }}</label>
          <input type="checkbox" v-model="form.adaptive" />
          <label>{{ t('settings.alias_auto') }}</label>
          <input type="checkbox" v-model="form.ip_aliases.auto_bind" />
          <label>{{ t('settings.prefer_wired') }}</label>
          <input type="checkbox" v-model="form.ip_aliases.prefer_wired" />
          <label>{{ t('settings.alias_interval') }}</label>
          <!-- Backend is IpAliasesPatch.interval = Field(ge=30, le=600); a lower
               bound of 15 here made the whole Advanced save 422 silently. -->
          <input v-model.number="form.ip_aliases.interval" type="number" min="30" max="600" :aria-label="t('settings.alias_interval')" />
          <label>{{ t('settings.resource_mode') }}</label>
          <select v-model="form.resource_mode" :aria-label="t('settings.resource_mode')">
            <option value="low">{{ t('settings.resource_mode_low') }}</option>
            <option value="high">{{ t('settings.resource_mode_high') }}</option>
          </select>
          <label>{{ t('settings.metrics_interval') }}</label>
          <input v-model.number="form.metrics_interval" type="number" min="15" max="600" :aria-label="t('settings.metrics_interval')" />
          <label>{{ t('settings.alert_interval') }}</label>
          <input v-model.number="form.alert_interval" type="number" min="15" max="600" :aria-label="t('settings.alert_interval')" />
        </div>
        <p class="hint">{{ t('settings.resource_mode_hint') }}</p>
        <p class="hint">{{ t('settings.adaptive_hint') }}</p>
        <div class="btns" style="margin-top:12px">
          <button class="primary" :disabled="saving" @click="saveAdvanced">{{ t('settings.save_settings') }}</button>
        </div>
      </div>
      <div class="card">
        <h2 class="section-title" style="margin-top:0">{{ t('settings.terminal_title') }}</h2>
        <p class="hint" style="margin-top:0">{{ t('settings.terminal_hint') }}</p>
        <div class="form-grid">
          <label>{{ t('settings.terminal_host_enabled') }}</label>
          <input type="checkbox" v-model="form.terminal.host_enabled" />
        </div>
        <p class="hint danger-hint">⚠ {{ t('settings.terminal_warning') }}</p>
        <div class="btns" style="margin-top:12px">
          <button class="primary" :disabled="saving" @click="saveTerminal">{{ t('settings.save_settings') }}</button>
        </div>
      </div>
      <div class="card" data-test="settings-ollama">
        <h2 class="section-title" style="margin-top:0">{{ t('settings.ollama_title') }}</h2>
        <p class="hint" style="margin-top:0">{{ t('settings.ollama_hint') }}</p>
        <div class="form-grid">
          <label>{{ t('settings.ollama_url') }}</label>
          <input v-model="form.ollama.url" type="text" :aria-label="t('settings.ollama_url')" />
          <label>{{ t('settings.ollama_label') }}</label>
          <input
            v-model="form.ollama.label"
            type="text"
            :placeholder="t('settings.ollama_label_ph')"
            :aria-label="t('settings.ollama_label')"
          />
        </div>
        <div class="btns" style="margin-top:12px">
          <button class="primary" :disabled="saving" @click="saveOllama">{{ t('settings.save_settings') }}</button>
          <router-link class="btn" to="/ollama">{{ t('nav.ollama') }}</router-link>
        </div>
      </div>
      <div class="card">
        <h2 class="section-title" style="margin-top:0">{{ t('settings.ssd_friendly') }}</h2>
        <p class="hint" style="margin-top:0">{{ finiteText(sysBundle?.other?.ssd_friendly?.hint, '') || t('settings.ssd_hint') }}</p>
        <ul class="hint" style="margin:0;padding-left:18px;line-height:1.7">
          <li>{{ t('settings.ssd_item_metrics') }}</li>
          <li>{{ t('settings.ssd_item_alerts') }}</li>
          <li>{{ t('settings.ssd_item_bak') }}</li>
          <li>{{ t('settings.ssd_item_interval') }}</li>
        </ul>
      </div>
    </div>
    <ServiceSignatures />
    <GroupRules />
    </div>

    <!-- Diagnostics -->
    <div v-else-if="tab==='diagnostics'" class="two-col">
      <div class="card">
        <h2 class="section-title" style="margin-top:0">{{ t('settings.diagnostics') }}</h2>
        <p class="hint" style="margin-top:0">{{ t('settings.diagnostics_hint') }}</p>
        <div class="btns" style="flex-direction:column;align-items:stretch">
          <button class="primary" :disabled="saving" @click="runDiagnostics">{{ t('settings.gen_diagnostics') }}</button>
          <a class="btn" href="/api/diagnostics/download">{{ t('settings.download_diagnostics') }}</a>
          <a class="btn" href="/api/export/services-yaml" download="services.yaml">{{ t('settings.export_yaml') }}</a>
          <router-link class="btn" to="/health">{{ t('nav.health') }}</router-link>
          <router-link class="btn" to="/logs">{{ t('nav.logs') }}</router-link>
        </div>
        <p class="hint" v-if="diagMsg" style="margin-top:12px">{{ finiteText(diagMsg) }}</p>
      </div>
      <div class="card" v-if="diagPreview">
        <h2 class="section-title" style="margin-top:0">{{ t('settings.diag_preview') }}</h2>
        <pre class="mono" style="font-size:11px;max-height:360px;overflow:auto;margin:0;white-space:pre-wrap" role="status" aria-live="polite">{{ finiteText(diagPreview) }}</pre>
      </div>
    </div>

    <div class="toolbar" style="margin-top:16px" v-if="form && (tab==='panel' || tab==='notify')">
      <button class="primary" :disabled="saving" @click="save">{{ t('settings.save_settings') }}</button>
      <button :disabled="saving" @click="load">{{ t('common.reload') }}</button>
      <a class="btn" href="/api/export/services-yaml" download="services.yaml">{{ t('settings.export_yaml') }}</a>
    </div>
    <LoadFailure
      v-else-if="formError && !form && !['identity','docker','appearance','datetime','power','disk','network','shares','access','vms','scheduler','diagnostics'].includes(tab)"
      :detail="formError"
      :retry="load"
    />
    <div
      v-else-if="!form && !formError && !['identity','docker','appearance','datetime','power','disk','network','shares','access','vms','scheduler','diagnostics'].includes(tab)"
      class="placeholder"
    >{{ t('common.loading') }}</div>
  </div>
</template>

<script setup>
import { computed, inject, onMounted, onUnmounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import qrcode from 'qrcode-generator'
import { finiteN, finiteText, fmtTs, withUnit } from '../lib/finite'
import {
  changeAuthPassword, controlPanelService, forceAlertCheck, generateDiagnostics, getDockerInfo,
  getHost, getIdentity, getLauncherStatus, getSettings, getSystemSettings, getUps,
  getUpsShutdownPlan, openLauncherApp, putIdentity, putSettings, putUpsHalt, putUpsSettings,
  runAliasAutoBind, runUpsShutdownDrill, setLauncherLogin, setPowerSetting,
  testNotify as apiTest,
} from '../api/client'
import {
  adminDisableTotp, confirmTotp, createApiKey, disableTotp, enrollTotp,
  getTotpStatus, listApiKeys, regenerateTotpRecovery, revokeApiKey,
} from '../api/client'
import { injectI18n } from '../i18n'
import { copyToClipboard } from '../lib/clipboard'
import { injectTheme } from '../theme'
import LoadFailure from '../components/LoadFailure.vue'
import NotifyChannels from '../components/NotifyChannels.vue'
import ServiceSignatures from '../components/ServiceSignatures.vue'
import GroupRules from '../components/GroupRules.vue'

const toast = inject('toast')
const route = useRoute()
const router = useRouter()
const { t, locale, locales, setLocale } = injectI18n()
const {
  theme, appliedTheme, density, themes, densities, followSystem,
  setTheme, setFollowSystem, setDensity,
} = injectTheme()
const followSystemOn = computed(() => {
  const v = followSystem
  if (v && typeof v === 'object' && 'value' in v) return !!v.value
  return !!v
})

const tab = ref('appearance')
const form = ref(null)
const formError = ref('')
const host = ref(null)
const identity = ref(null)
const identityForm = ref({ computer_name: '', comment: '', host_ip: '' })
// Whether identityForm holds the server's real values. Save is blocked until it
// does: the form starts blank, saveIdentity() sends comment and host_ip
// unconditionally, and the Identity tab renders with an enabled Save button
// regardless of whether loadIdentity() succeeded. Saving after a failed load
// therefore wrote empty strings over the stored comment and over host_ip -- the
// value that resolves every app's link across the whole panel.
const identityLoaded = ref(false)
const identityError = ref('')
const dockerInfo = ref(null)
const dockerError = ref('')
const sysBundle = ref(null)
const sysBundleError = ref('')
//: How many sleep assertions the backend found but did not send.  A panel that
//: predates `assertion_count` sends none, so fall back to the row count and keep
//: the note hidden rather than claiming the list is short.
const hiddenAssertions = computed(() => {
  const power = sysBundle.value?.power
  if (!power) return 0
  const shown = (power.assertions || []).length
  const total = finiteN(power.assertion_count, shown)
  return Math.max(0, total - shown)
})
const launcher = ref(null)
const launcherBusy = ref(false)
const launcherLoading = ref(false)
const launcherError = ref('')
let launcherLoadRequest = 0
let pageAlive = true
let loadGeneration = 0
let saveGeneration = 0
let twofaBusyGeneration = 0
let apiKeyBusyGeneration = 0
let launcherBusyGeneration = 0
let drillBusyGeneration = 0
let savingPasswordGeneration = 0

function beginSaving() {
  const generation = ++saveGeneration
  saving.value = true
  return generation
}
function endSaving(generation) {
  if (generation === saveGeneration && pageAlive) saving.value = false
}
function beginTwofaBusy() {
  const generation = ++twofaBusyGeneration
  twofaBusy.value = true
  return generation
}
function endTwofaBusy(generation) {
  if (generation === twofaBusyGeneration && pageAlive) twofaBusy.value = false
}
function beginApiKeyBusy() {
  const generation = ++apiKeyBusyGeneration
  apiKeyBusy.value = true
  return generation
}
function endApiKeyBusy(generation) {
  if (generation === apiKeyBusyGeneration && pageAlive) apiKeyBusy.value = false
}
function beginLauncherBusy() {
  const generation = ++launcherBusyGeneration
  launcherBusy.value = true
  return generation
}
function endLauncherBusy(generation) {
  if (generation === launcherBusyGeneration && pageAlive) launcherBusy.value = false
}
function beginDrillBusy() {
  const generation = ++drillBusyGeneration
  drillBusy.value = true
  return generation
}
function endDrillBusy(generation) {
  if (generation === drillBusyGeneration && pageAlive) drillBusy.value = false
}
const powerForm = ref({ sleep: 0, displaysleep: 10, disksleep: 0, womp: 1 })
const saving = ref(false)
const diagMsg = ref('')
const diagPreview = ref('')
const savingPassword = ref(false)
const accountForm = ref({ username: '', currentPassword: '', newPassword: '', confirmPassword: '' })
const upsInfo = ref(null)
const upsError = ref('')
// shutdown.trigger_* hold '' for "condition off" (the inputs are cleared, not
// zeroed); the empty string becomes an explicit null on save.
const upsForm = ref({
  alerts_enabled: true,
  low_battery_pct: 20,
  shutdown: {
    enabled: false,
    trigger_pct: 25,
    trigger_remaining_min: '',
    require_both: false,
    stacksMode: 'all',
    stop_scripts: [],
  },
})
// Full stack menu in stop order: configured entries first (their saved order),
// then the rest of the catalog unticked. Rows move with the ↑/↓ buttons.
const upsStackRows = ref([])
const upsPlan = ref(null)   // catalog + resolved plan from /api/ups/shutdown/plan
const upsDrill = ref(null)  // last drill result shown under the button
const drillBusy = ref(false)
const haltLevel = ref(null)

const upsPhase = computed(() => upsInfo.value?.shutdown_state?.phase || 'idle')
const upsLast = computed(() => upsInfo.value?.shutdown_state?.last || null)
const upsScriptChoices = computed(() => upsPlan.value?.catalog?.scripts || [])

function fmtUpsTs(ts) {
  return fmtTs(ts)
}

function moveStackRow(i, delta) {
  const rows = upsStackRows.value
  const j = i + delta
  if (j < 0 || j >= rows.length) return
  ;[rows[i], rows[j]] = [rows[j], rows[i]]
}

function buildStackRows() {
  const catalog = upsPlan.value?.catalog?.stacks || []
  const saved = upsInfo.value?.settings?.shutdown?.stacks
  const custom = Array.isArray(saved)
  const rows = []
  if (custom) {
    for (const id of saved) {
      const hit = catalog.find((s) => s.id === id)
      rows.push({ id, name: finiteText(hit?.name, '') || id, selected: true, missing: !hit })
    }
  }
  for (const s of catalog) {
    if (!rows.some((r) => r.id === s.id)) {
      rows.push({ id: s.id, name: finiteText(s.name, '') || s.id, selected: !custom, missing: false })
    }
  }
  upsStackRows.value = rows
}

// ── two-factor (TOTP) card state ─────────────────────────────────────────────
const twofa = ref(null)          // status from the server, null while unknown
const twofaError = ref('')
const twofaBusy = ref(false)
const twofaEnroll = ref(null)    // {secret, otpauth_uri, manual_entry, qrSvg}
const twofaCode = ref('')        // pairing confirmation input
const twofaActionCode = ref('')  // disable / regenerate input
const twofaResetUser = ref('')   // admin rescue target
const recoveryCodes = ref([])    // plaintext codes, shown exactly once
const copiedRecovery = ref(false)
let copyRecoveryTimer = 0

// ── API keys card state ──────────────────────────────────────────────────────
const apiKeys = ref(null)        // list from the server, null while unknown
const apiKeysError = ref('')
const apiKeyBusy = ref(false)
const newKey = ref({ name: '', role: 'member', expiresDays: null })
const createdKey = ref(null)     // {key, record}: plaintext lives only here
const copiedKey = ref(false)
let copyKeyTimer = 0

const tabs = [
  { id: 'appearance', labelKey: 'settings.tab_appearance' },
  { id: 'identity', labelKey: 'settings.tab_identity' },
  { id: 'datetime', labelKey: 'settings.tab_datetime' },
  { id: 'network', labelKey: 'settings.tab_network' },
  { id: 'disk', labelKey: 'settings.tab_disk' },
  { id: 'power', labelKey: 'settings.tab_power' },
  { id: 'docker', labelKey: 'settings.tab_docker' },
  { id: 'vms', labelKey: 'settings.tab_vms' },
  { id: 'notify', labelKey: 'settings.tab_notify' },
  { id: 'shares', labelKey: 'settings.tab_shares' },
  { id: 'scheduler', labelKey: 'settings.tab_scheduler' },
  { id: 'access', labelKey: 'settings.tab_access' },
  { id: 'advanced', labelKey: 'settings.tab_advanced' },
  { id: 'diagnostics', labelKey: 'settings.tab_diagnostics' },
  { id: 'panel', labelKey: 'settings.tab_panel' },
]

function memGb(bytes) {
  const n = Number(bytes)
  if (!Number.isFinite(n) || n <= 0) return '—'
  return (n / 2 ** 30).toFixed(1)
}

function sizeGb(value) {
  const n = Number(value)
  return Number.isFinite(n) ? `${n} GB` : '—'
}

function normalizeTab(id) {
  return tabs.some((tb) => tb.id === id) ? id : 'appearance'
}

function queryTab() {
  const q = route.query?.tab
  const raw = Array.isArray(q) ? q[0] : q
  return typeof raw === 'string' ? raw : ''
}

function applyTab(id) {
  const next = normalizeTab(id)
  if (next === tab.value) return
  tab.value = next
  if (next === 'docker') loadDockerInfo()
  if (next === 'panel') {
    loadLauncher()
    loadTwofa()
    loadApiKeys()
  }
  if (next === 'notify') loadUps()
  if (['datetime', 'power', 'disk', 'network', 'shares', 'access', 'vms', 'scheduler', 'advanced', 'diagnostics'].includes(next)) {
    loadSysBundle()
  }
}

function switchTab(id) {
  const next = normalizeTab(id)
  if (next !== normalizeTab(queryTab())) {
    router.replace({ query: { ...route.query, tab: next } })
  }
  applyTab(next)
}

async function loadSysBundle() {
  const generation = loadGeneration
  try {
    const next = await getSystemSettings()
    if (generation !== loadGeneration || !pageAlive) return
    sysBundle.value = next
    sysBundleError.value = ''
    const p = sysBundle.value?.power?.settings || {}
    powerForm.value = {
      sleep: p.sleep ?? sysBundle.value?.power?.sleep ?? 0,
      displaysleep: p.displaysleep ?? sysBundle.value?.power?.displaysleep ?? 10,
      disksleep: p.disksleep ?? sysBundle.value?.power?.disksleep ?? 0,
      womp: p.womp ?? sysBundle.value?.power?.womp ?? 1,
    }
  } catch (e) {
    if (generation !== loadGeneration || !pageAlive) return
    sysBundleError.value = finiteText(e.message || String(e), '')
    toast('❌ ' + finiteText(e.message))
  }
}

function softText(j, fallbackKey = 'common.fail') {
  if (j?.code) {
    const key = `err.${j.code}`
    const translated = t(key, j.params || {})
    if (translated !== key) return translated
  }
  return finiteText(j?.message, '') || t(fallbackKey)
}

async function applyPower(key) {
  const generation = beginSaving()
  try {
    const value = powerForm.value[key]
    const result = await setPowerSetting(key, value)
    if (!pageAlive) return
    toast(result.ok ? `✅ ${finiteText(key)}=${finiteText(value)}` : `❌ ${softText(result)}`)
    await loadSysBundle()
  } catch (e) {
    if (!pageAlive) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    endSaving(generation)
  }
}

async function runAliasAlign() {
  if (!confirm(t('network.confirm_autobind'))) return
  const generation = beginSaving()
  try {
    const result = await runAliasAutoBind()
    if (!pageAlive) return
    toast(result.ok ? `✅ ${finiteText(result.message, '') || t('common.ok')}` : `❌ ${finiteText(result.message, '') || t('common.fail')}`)
    await loadSysBundle()
  } catch (e) {
    if (!pageAlive) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    endSaving(generation)
  }
}

async function runDiagnostics() {
  const generation = beginSaving()
  diagMsg.value = ''
  try {
    const result = await generateDiagnostics()
    if (!pageAlive) return
    const saved = Boolean(result.saved_path)
    diagMsg.value = saved
      ? `${t('settings.diag_saved')}: ${result.saved_path}`
      : t('settings.diag_save_failed', { error: finiteText(result.save_error, '') || t('common.failed') })
    try {
      diagPreview.value = JSON.stringify({
        generated_at: result.generated_at,
        hostname: result.hostname,
        platform: result.platform,
        docker: result.docker,
        management: result.management,
        other: result.other,
        vms: result.vms,
        metrics_latest: result.metrics_latest,
        health_summary: Array.isArray(result.health?.checks)
          ? result.health.checks.slice(0, 8)
          : result.health,
      }, null, 2)
    } catch {
      diagPreview.value = ''
    }
    toast(saved ? '✅ ' + t('settings.diag_done') : '❌ ' + finiteText(diagMsg.value))
  } catch (e) {
    if (!pageAlive) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    endSaving(generation)
  }
}

// The pick* handlers apply the choice locally and then persist it. The persist
// used to be fire-and-forget with an empty .catch, so a server-side failure was
// invisible: the setting appeared to stick and then silently reverted on the next
// getSettings(). Report the failure instead -- the local change is still applied,
// so the message says it was not saved rather than that it did not work.
function persistUi(patch) {
  const generation = loadGeneration
  putSettings({ ui: patch }).catch(e => {
    if (generation !== loadGeneration || !pageAlive) return
    toast('❌ ' + t('appearance.save_server_failed', { error: finiteText(e.message || e) }))
  })
}

function uiThemeId() {
  return followSystem?.value ? 'system' : (theme?.value ?? theme)
}

async function pickLocale(id) {
  if (await setLocale(id)) {
    if (!pageAlive) return
    toast('✅ ' + t('appearance.saved_local'))
    persistUi({ locale: id, theme: uiThemeId(), density: density.value })
  }
}

function pickTheme(id) {
  setTheme(id)
  toast('✅ ' + t('theme.applied'))
  persistUi({ locale: locale.value, theme: uiThemeId(), density: density.value })
}

function pickFollowSystem(on) {
  setFollowSystem(on)
  toast('✅ ' + t('appearance.saved_local'))
  persistUi({ locale: locale.value, theme: on ? 'system' : theme.value, density: density.value })
}

function pickDensity(id) {
  setDensity(id)
  toast('✅ ' + t('appearance.saved_local'))
  persistUi({ locale: locale.value, theme: uiThemeId(), density: id })
}

async function syncUiToServer() {
  const generation = beginSaving()
  try {
    await putSettings({
      ui: { locale: locale.value, theme: uiThemeId(), density: density.value },
    })
    if (!pageAlive) return
    toast('✅ ' + t('appearance.saved_server'))
  } catch (e) {
    if (!pageAlive) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    endSaving(generation)
  }
}

async function loadIdentity() {
  const generation = loadGeneration
  try {
    const next = await getIdentity()
    if (generation !== loadGeneration || !pageAlive) return
    identity.value = next
    identityForm.value = {
      computer_name: identity.value.computer_name || '',
      comment: identity.value.comment || '',
      host_ip: identity.value.host_ip_config || 'auto',
    }
    identityLoaded.value = true
    identityError.value = ''
  } catch (e) {
    if (generation !== loadGeneration || !pageAlive) return
    identityLoaded.value = false
    identityError.value = finiteText(e.message || String(e), '')
    toast('❌ ' + finiteText(e.message))
  }
}

async function saveIdentity() {
  // Refuse to write a form that was never populated from the server.
  if (!identityLoaded.value) {
    toast('❌ ' + t('settings.identity_load_failed'))
    return
  }
  const generation = beginSaving()
  try {
    const r = await putIdentity({
      computer_name: identityForm.value.computer_name || null,
      comment: identityForm.value.comment,
      host_ip: identityForm.value.host_ip,
    })
    if (!pageAlive) return
    toast('✅ ' + (finiteText(r.message, '') || t('common.save')))
    await loadIdentity()
    if (!pageAlive) return
    if (form.value && identityForm.value.host_ip) form.value.host_ip = identityForm.value.host_ip
  } catch (e) {
    if (!pageAlive) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    endSaving(generation)
  }
}

async function loadDockerInfo() {
  const generation = loadGeneration
  try {
    const next = await getDockerInfo()
    if (generation !== loadGeneration || !pageAlive) return
    dockerInfo.value = next
    dockerError.value = ''
  } catch (e) {
    if (generation !== loadGeneration || !pageAlive) return
    // The tab's fallback branch renders "Loading…" whenever dockerInfo is null,
    // so swallowing this left the panel claiming it was still loading forever —
    // and the Refresh button lives inside the loaded branch, so there was no way
    // to retry from the page.
    dockerError.value = finiteText(e.message || String(e), '')
    toast('❌ ' + finiteText(e.message))
  }
}

async function loadLauncher() {
  if (!pageAlive) return
  const request = ++launcherLoadRequest
  launcherLoading.value = true
  launcherError.value = ''
  try {
    const status = await getLauncherStatus()
    if (request !== launcherLoadRequest || !pageAlive) return
    launcher.value = status
    launcherError.value = ''
  } catch (e) {
    if (request !== launcherLoadRequest || !pageAlive) return
    launcherError.value = finiteText(e.message || String(e), '')
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (request === launcherLoadRequest && pageAlive) launcherLoading.value = false
  }
}

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms))

/** Wait for the panel to answer again after it restarts itself.
 *
 * A cold start measured 8.5s on an idle host and can pass a minute when the
 * machine is loaded, so the fixed 1.4s wait this replaces always read the
 * status of a socket that was not listening yet: the restart succeeded and the
 * UI reported it as a failure every single time.
 */
let launcherPageAlive = true
async function waitForPanelRestart() {
  // The API deliberately keeps answering for ~0.6s so its response reaches the
  // browser before launchd replaces the job, and the old worker drains its
  // connections after that.  Polling before it has actually gone would read
  // the process being torn down and call the restart finished.
  await sleep(3000)
  if (!launcherPageAlive) return null
  const deadline = Date.now() + 150000
  while (launcherPageAlive && Date.now() < deadline) {
    try {
      const status = await getLauncherStatus()
      if (status?.panel_running) return status
    } catch {
      // Expected for as long as nothing is listening.
    }
    await sleep(1500)
  }
  return null
}

async function runLauncher(action) {
  if (['restart', 'stop'].includes(action) && !confirm(t(`settings.launcher_${action}_confirm`))) return
  const generation = beginLauncherBusy()
  try {
    let result
    if (action === 'open') result = await openLauncherApp()
    else if (action === 'login') result = await setLauncherLogin(!launcher.value?.login_enabled)
    else result = await controlPanelService(action)
    if (!pageAlive) return
    if (!result?.ok) throw new Error(softText(result))
    toast('✅ ' + (finiteText(result.message, '') || t('common.ok')))
    if (action === 'stop') {
      // The API intentionally disappears after accepting this command, so do
      // not leave the last green status visible or try to poll a stopped panel.
      launcher.value = {
        ...launcher.value,
        panel_running: false,
        panel_job_state: 'stopping',
      }
    } else if (action === 'restart') {
      launcher.value = {
        ...launcher.value,
        panel_running: false,
        panel_job_state: 'restarting',
      }
      const status = await waitForPanelRestart()
      if (!launcherPageAlive) return
      if (status) {
        launcher.value = status
        toast('✅ ' + t('settings.launcher_restart_done'))
      } else {
        // Still not answering. The panel watchdog restarts a job that stays
        // unreachable, so say that rather than reporting a hard failure.
        toast('⚠️ ' + t('settings.launcher_restart_slow'))
        await loadLauncher()
      }
    } else {
      await sleep(300)
      if (!pageAlive) return
      await loadLauncher()
    }
  } catch (e) {
    if (!pageAlive) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    endLauncherBusy(generation)
  }
}

async function load() {
  const generation = ++loadGeneration
  try {
    // The host summary is only used for the hostname line; it does not feed the
    // settings form, so waiting for /api/settings before asking for it added a
    // whole round trip to every load of this page for no ordering reason.
    const [s, hostInfo] = await Promise.all([
      getSettings(),
      getHost().catch(() => null),
    ])
    if (generation !== loadGeneration || !pageAlive) return
    host.value = hostInfo
    form.value = {
      ...s,
      host_ip: s.host_ip_config || 'auto',
      auth: {
        enabled: !!s.auth?.enabled,
        allow_localhost: s.auth?.allow_localhost !== false,
        username: s.auth?.username || 'admin',
        has_password: s.auth?.has_password,
      },
      notify: {
        enabled: !!s.notify?.enabled,
        include_warn: !!s.notify?.include_warn,
        notify_resolve: s.notify?.notify_resolve !== false,
        ha_url: s.notify?.ha_url || 'http://localhost:8123',
        ha_service: s.notify?.ha_service || 'notify.notify',
        ha_token: '',
        ha_webhook_url: '',
        has_token: s.notify?.has_token,
        has_webhook: s.notify?.has_webhook,
      },
      thresholds: {
        enabled: s.thresholds?.enabled !== false,
        cpu_pct: s.thresholds?.cpu_pct ?? 90,
        mem_pct: s.thresholds?.mem_pct ?? 90,
        disk_pct: s.thresholds?.disk_pct ?? 90,
        cooldown_sec: s.thresholds?.cooldown_sec ?? 1800,
        // Defaults match _public_settings(); `!== false` so a server that omits the
        // key cannot read as "SMART alerts off".
        smart_enabled: s.thresholds?.smart_enabled !== false,
        smart_temp_c: s.thresholds?.smart_temp_c ?? 60,
        smart_wear_pct: s.thresholds?.smart_wear_pct ?? 90,
        smart_spare_pct: s.thresholds?.smart_spare_pct ?? 10,
      },
      adaptive: s.adaptive !== false,
      ip_aliases: {
        auto_bind: s.ip_aliases?.auto_bind !== false,
        prefer_wired: s.ip_aliases?.prefer_wired !== false,
        interval: s.ip_aliases?.interval ?? 60,
        ips: s.ip_aliases?.ips || [],
        netmask: s.ip_aliases?.netmask || '255.255.255.255',
      },
      metrics_interval: s.metrics_interval || 90,
      alert_interval: s.alert_interval || 90,
      resource_mode: s.resource_mode === 'high' ? 'high' : 'low',
      // Host shell is opt-in: default to OFF whenever the server does not
      // explicitly say it is on, so a missing field can never read as enabled.
      terminal: {
        host_enabled: s.terminal?.host_enabled === true,
        shell: s.terminal?.shell || '',
        cwd: s.terminal?.cwd || '',
      },
      ollama: {
        url: s.ollama?.url || 'http://127.0.0.1:11434',
        label: s.ollama?.label || '',
      },
    }
    accountForm.value.username = form.value.auth.username
    formError.value = ''
  } catch (e) {
    if (generation !== loadGeneration || !pageAlive) return
    formError.value = finiteText(e.message || String(e), '')
    toast('❌ ' + finiteText(e.message))
  }
}

async function save() {
  const generation = beginSaving()
  try {
    const body = {
      host_ip: form.value.host_ip,
      metrics_interval: form.value.metrics_interval,
      alert_interval: form.value.alert_interval,
      resource_mode: form.value.resource_mode,
      auth: {
        enabled: form.value.auth.enabled,
        allow_localhost: form.value.auth.allow_localhost,
      },
      notify: {
        enabled: form.value.notify.enabled,
        include_warn: form.value.notify.include_warn,
        notify_resolve: form.value.notify.notify_resolve,
        ha_url: form.value.notify.ha_url,
        ha_service: form.value.notify.ha_service,
      },
      thresholds: {
        enabled: form.value.thresholds.enabled,
        cpu_pct: form.value.thresholds.cpu_pct,
        mem_pct: form.value.thresholds.mem_pct,
        disk_pct: form.value.thresholds.disk_pct,
        cooldown_sec: form.value.thresholds.cooldown_sec,
        smart_enabled: form.value.thresholds.smart_enabled,
        smart_temp_c: form.value.thresholds.smart_temp_c,
        smart_wear_pct: form.value.thresholds.smart_wear_pct,
        smart_spare_pct: form.value.thresholds.smart_spare_pct,
      },
      ui: {
        locale: locale.value,
        theme: uiThemeId(),
        density: density.value,
      },
    }
    if (form.value.notify.ha_token) body.notify.ha_token = form.value.notify.ha_token
    if (form.value.notify.ha_webhook_url) body.notify.ha_webhook_url = form.value.notify.ha_webhook_url
    await putSettings(body)
    if (!pageAlive) return
    toast('✅ ' + t('common.save'))
    await load()
  } catch (e) {
    if (!pageAlive) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    endSaving(generation)
  }
}

function passwordValidation() {
  const f = accountForm.value
  if (!f.username.trim()) return t('settings.username_required')
  if (!f.currentPassword) return t('settings.current_password_required')
  if (f.newPassword.length < 10) return t('auth.password_length')
  if (f.newPassword !== f.confirmPassword) return t('auth.password_mismatch')
  return ''
}

function passwordMessage() {
  const f = accountForm.value
  if (!f.currentPassword && !f.newPassword && !f.confirmPassword) return ''
  return passwordValidation()
}

async function savePassword() {
  const error = passwordValidation()
  if (error) {
    toast('❌ ' + finiteText(error))
    return
  }
  // Rotating the password bumps the session version, which signs out every other
  // browser session. Worth confirming: the current-password field proves intent to
  // change *a* password, not that the operator expected to be logged out elsewhere.
  if (!confirm(t('settings.confirm_password_change'))) return
  const passwordGeneration = ++savingPasswordGeneration
  savingPassword.value = true
  try {
    const r = await changeAuthPassword(
      accountForm.value.username.trim(),
      accountForm.value.currentPassword,
      accountForm.value.newPassword,
    )
    if (!pageAlive) return
    form.value.auth.username = r.username
    accountForm.value = {
      username: r.username,
      currentPassword: '',
      newPassword: '',
      confirmPassword: '',
    }
    toast('✅ ' + (finiteText(r.message, '') || t('settings.password_updated')))
  } catch (e) {
    if (!pageAlive) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (passwordGeneration === savingPasswordGeneration && pageAlive) savingPassword.value = false
  }
}

// ── two-factor (TOTP) ────────────────────────────────────────────────────────

async function loadTwofa() {
  const generation = loadGeneration
  try {
    const next = await getTotpStatus()
    if (generation !== loadGeneration || !pageAlive) return
    twofa.value = next
    twofaError.value = ''
  } catch (e) {
    if (generation !== loadGeneration || !pageAlive) return
    twofa.value = null
    twofaError.value = finiteText(e.message || String(e), '')
  }
}

/** Same rendering path as the WireGuard peer QR: qrcode-generator builds the
 *  SVG from encoded modules only (never interpolating the payload as markup),
 *  and the wrapper constrains it so the whole symbol stays visible. */
function totpQrSvg(text) {
  try {
    const qr = qrcode(0, 'M')
    qr.addData(text)
    qr.make()
    return qr.createSvgTag({ cellSize: 4, margin: 4, scalable: true })
  } catch {
    return ''
  }
}

async function startTwofaEnroll() {
  const generation = beginTwofaBusy()
  try {
    const r = await enrollTotp()
    if (!pageAlive) return
    twofaEnroll.value = { ...r, qrSvg: totpQrSvg(r.otpauth_uri) }
    twofaCode.value = ''
  } catch (e) {
    if (!pageAlive) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    endTwofaBusy(generation)
  }
}

function cancelTwofaEnroll() {
  twofaEnroll.value = null
  twofaCode.value = ''
}

async function confirmTwofaEnroll() {
  const generation = beginTwofaBusy()
  try {
    const r = await confirmTotp(twofaCode.value)
    if (!pageAlive) return
    recoveryCodes.value = r.recovery_codes || []
    copiedRecovery.value = false
    twofaEnroll.value = null
    twofaCode.value = ''
    toast('✅ ' + t('twofa.enabled_toast'))
    await loadTwofa()
  } catch (e) {
    if (!pageAlive) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    endTwofaBusy(generation)
  }
}

async function disableTwofa() {
  if (!confirm(t('twofa.disable_confirm'))) return
  const generation = beginTwofaBusy()
  try {
    await disableTotp(twofaActionCode.value)
    if (!pageAlive) return
    twofaActionCode.value = ''
    recoveryCodes.value = []
    toast('✅ ' + t('twofa.disabled_toast'))
    await loadTwofa()
  } catch (e) {
    if (!pageAlive) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    endTwofaBusy(generation)
  }
}

async function regenTwofaRecovery() {
  if (!confirm(t('twofa.regen_confirm'))) return
  const generation = beginTwofaBusy()
  try {
    const r = await regenerateTotpRecovery(twofaActionCode.value)
    if (!pageAlive) return
    recoveryCodes.value = r.recovery_codes || []
    copiedRecovery.value = false
    twofaActionCode.value = ''
    await loadTwofa()
  } catch (e) {
    if (!pageAlive) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    endTwofaBusy(generation)
  }
}

async function adminResetTwofa() {
  if (!confirm(t('twofa.admin_reset_confirm', { name: finiteText(twofaResetUser.value) }))) return
  const generation = beginTwofaBusy()
  try {
    await adminDisableTotp(twofaResetUser.value)
    if (!pageAlive) return
    toast('✅ ' + t('twofa.admin_reset_toast', { name: finiteText(twofaResetUser.value) }))
    twofaResetUser.value = ''
    await loadTwofa()
  } catch (e) {
    if (!pageAlive) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    endTwofaBusy(generation)
  }
}

async function copyRecoveryCodes() {
  const ok = await copyToClipboard(recoveryCodes.value.join('\n'))
  if (!pageAlive) return
  if (!ok) {
    toast('❌ ' + t('common.copy_failed'))
    return
  }
  copiedRecovery.value = true
  clearTimeout(copyRecoveryTimer)
  copyRecoveryTimer = setTimeout(() => {
    if (!pageAlive) return
    copiedRecovery.value = false
  }, 2000)
}

// ── API keys ─────────────────────────────────────────────────────────────────

async function loadApiKeys() {
  const generation = loadGeneration
  try {
    const next = await listApiKeys()
    if (generation !== loadGeneration || !pageAlive) return
    apiKeys.value = next.keys || []
    apiKeysError.value = ''
  } catch (e) {
    if (generation !== loadGeneration || !pageAlive) return
    apiKeysError.value = finiteText(e.message || String(e), '')
  }
}

function fmtEpoch(value) {
  return fmtTs(value)
}

async function createKey() {
  const generation = beginApiKeyBusy()
  try {
    const r = await createApiKey({
      name: newKey.value.name,
      role: newKey.value.role,
      expiresDays: newKey.value.expiresDays || null,
    })
    if (!pageAlive) return
    createdKey.value = r
    copiedKey.value = false
    newKey.value = { name: '', role: 'member', expiresDays: null }
    await loadApiKeys()
  } catch (e) {
    if (!pageAlive) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    endApiKeyBusy(generation)
  }
}

async function copyCreatedKey() {
  const ok = await copyToClipboard(createdKey.value?.key)
  if (!pageAlive) return
  if (!ok) {
    toast('❌ ' + t('common.copy_failed'))
    return
  }
  copiedKey.value = true
  clearTimeout(copyKeyTimer)
  copyKeyTimer = setTimeout(() => {
    if (!pageAlive) return
    copiedKey.value = false
  }, 2000)
}

async function revokeKey(key) {
  if (!confirm(t('apikeys.revoke_confirm', { name: finiteText(key.name) }))) return
  const generation = beginApiKeyBusy()
  try {
    await revokeApiKey(key.id)
    if (!pageAlive) return
    toast('✅ ' + t('apikeys.revoked_toast', { name: finiteText(key.name) }))
    await loadApiKeys()
  } catch (e) {
    if (!pageAlive) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    endApiKeyBusy(generation)
  }
}

async function saveAdvanced() {
  const generation = beginSaving()
  try {
    await putSettings({
      adaptive: form.value.adaptive,
      metrics_interval: form.value.metrics_interval,
      alert_interval: form.value.alert_interval,
      resource_mode: form.value.resource_mode,
      ip_aliases: {
        auto_bind: form.value.ip_aliases.auto_bind,
        prefer_wired: form.value.ip_aliases.prefer_wired,
        interval: form.value.ip_aliases.interval,
      },
    })
    if (!pageAlive) return
    toast('✅ ' + t('common.save'))
    // Disjoint targets: load() rewrites `form`/`host`, loadSysBundle() rewrites
    // `sysBundle`/`powerForm`. Neither reads what the other writes.
    await Promise.all([load(), loadSysBundle()])
  } catch (e) {
    if (!pageAlive) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    endSaving(generation)
  }
}

async function saveOllama() {
  const generation = beginSaving()
  try {
    await putSettings({
      ollama: {
        url: form.value.ollama.url.trim(),
        label: form.value.ollama.label.trim(),
      },
    })
    if (!pageAlive) return
    toast('✅ ' + t('common.save'))
    await load()
  } catch (e) {
    if (!pageAlive) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    endSaving(generation)
  }
}

async function saveTerminal() {
  // Turning this ON is the one settings change that grants remote code
  // execution on this Mac, so make the operator acknowledge it explicitly
  // rather than letting a stray click arm it.
  if (form.value.terminal.host_enabled && !confirm(t('settings.terminal_confirm'))) {
    return
  }
  const generation = beginSaving()
  try {
    await putSettings({
      terminal: {
        host_enabled: form.value.terminal.host_enabled,
        cwd: form.value.terminal.cwd || undefined,
      },
    })
    if (!pageAlive) return
    toast('✅ ' + t('common.save'))
    await load()
  } catch (e) {
    if (!pageAlive) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    endSaving(generation)
  }
}

async function loadUps() {
  const generation = loadGeneration
  try {
    const next = await getUps()
    if (generation !== loadGeneration || !pageAlive) return
    upsInfo.value = next
    upsError.value = ''
    const sd = upsInfo.value.settings?.shutdown || {}
    upsForm.value = {
      alerts_enabled: upsInfo.value.settings?.alerts_enabled !== false,
      low_battery_pct: upsInfo.value.settings?.low_battery_pct ?? 20,
      shutdown: {
        enabled: sd.enabled === true,
        trigger_pct: sd.trigger_pct ?? '',
        trigger_remaining_min: sd.trigger_remaining_min ?? '',
        require_both: sd.require_both === true,
        stacksMode: Array.isArray(sd.stacks) ? 'custom' : 'all',
        stop_scripts: Array.isArray(sd.stop_scripts) ? [...sd.stop_scripts] : [],
      },
    }
  } catch (e) {
    if (generation !== loadGeneration || !pageAlive) return
    upsError.value = finiteText(e.message || String(e), '')
    toast('❌ ' + finiteText(e.message))
    return
  }
  // Catalog for the stack/script pickers; enumeration is a docker round-trip,
  // so a failure degrades to "no pickers" rather than blocking the card.
  try {
    const plan = await getUpsShutdownPlan()
    if (generation !== loadGeneration || !pageAlive) return
    upsPlan.value = plan
  } catch {
    if (generation !== loadGeneration || !pageAlive) return
    upsPlan.value = null
  }
  if (generation !== loadGeneration || !pageAlive) return
  buildStackRows()
}

// '' (cleared input) → explicit null, meaning "this condition is off".
function numOrNull(v) {
  return v === '' || v === null || v === undefined ? null : Number(v)
}

async function saveUps() {
  const f = upsForm.value
  const shutdown = {
    enabled: f.shutdown.enabled,
    trigger_pct: numOrNull(f.shutdown.trigger_pct),
    trigger_remaining_min: numOrNull(f.shutdown.trigger_remaining_min),
    require_both: f.shutdown.require_both,
    stacks: f.shutdown.stacksMode === 'all'
      ? 'all'
      : upsStackRows.value.filter((r) => r.selected).map((r) => r.id),
    stop_scripts: [...f.shutdown.stop_scripts],
  }
  // Same rule the server enforces (ups.policy_no_condition), said upfront.
  if (shutdown.enabled && shutdown.trigger_pct === null && shutdown.trigger_remaining_min === null) {
    toast('❌ ' + t('settings.ups_shutdown_need_condition'))
    return
  }
  const generation = beginSaving()
  try {
    const r = await putUpsSettings({
      alerts_enabled: f.alerts_enabled,
      low_battery_pct: f.low_battery_pct,
      shutdown,
    })
    if (!pageAlive) return
    if (r.ups) upsInfo.value = r.ups
    buildStackRows()
    toast('✅ ' + t('common.save'))
  } catch (e) {
    if (!pageAlive) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    endSaving(generation)
  }
}

async function runDrill() {
  const generation = beginDrillBusy()
  try {
    const next = await runUpsShutdownDrill()
    if (!pageAlive) return
    upsDrill.value = next
  } catch (e) {
    if (!pageAlive) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    endDrillBusy(generation)
  }
}

async function saveHalt() {
  if (!confirm(t('settings.ups_halt_confirm', { n: finiteN(haltLevel.value) }))) return
  const generation = beginSaving()
  try {
    const r = await putUpsHalt({ haltlevel: Number(haltLevel.value) })
    if (!pageAlive) return
    if (r.ups) upsInfo.value = r.ups
    toast('✅ ' + t('settings.ups_halt_set'))
  } catch (e) {
    if (!pageAlive) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    endSaving(generation)
  }
}

async function testNotify() {
  if (saving.value) return
  const generation = beginSaving()
  try {
    const r = await apiTest()
    if (!pageAlive) return
    toast(r.ok ? '✅ ' + t('common.ok') : '❌ ' + (finiteText(r.message, '') || t('common.fail')))
  } catch (e) {
    if (!pageAlive) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    endSaving(generation)
  }
}

async function forceCheck() {
  if (saving.value) return
  const generation = beginSaving()
  try {
    const r = await forceAlertCheck()
    if (!pageAlive) return
    toast(`${t('settings.force_check')} · ${r.emitted?.length || 0}`)
  } catch (e) {
    if (!pageAlive) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    endSaving(generation)
  }
}

watch(() => route.query.tab, (q) => {
  const raw = Array.isArray(q) ? q[0] : q
  applyTab(typeof raw === 'string' ? raw : '')
})

onMounted(() => {
  pageAlive = true
  launcherPageAlive = true
  load()
  loadIdentity()
  applyTab(queryTab())
  // Don't load full system bundle until a tab needs it (saves ~1.5s shell storm)
})
onUnmounted(() => {
  pageAlive = false
  loadGeneration += 1
  saveGeneration += 1
  twofaBusyGeneration += 1
  apiKeyBusyGeneration += 1
  launcherBusyGeneration += 1
  drillBusyGeneration += 1
  savingPasswordGeneration += 1
  launcherPageAlive = false
  launcherLoadRequest += 1
  clearTimeout(copyRecoveryTimer)
  clearTimeout(copyKeyTimer)
})
</script>

<style scoped>
.form-grid {
  display: grid;
  grid-template-columns: 130px 1fr;
  gap: 10px 14px;
  align-items: center;
  font-size: 13px;
}
.form-grid label { color: var(--sub); font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: .3px; }
.form-grid input[type=text],
.form-grid input[type=password],
.form-grid input[type=number] { width: 100%; }
.hint { margin-top: 12px; color: var(--sub); font-size: 12px; line-height: 1.55; }
.password-card, .launcher-card { grid-column: 1 / -1; }
.launcher-card {
  position: relative;
  overflow: hidden;
  background:
    linear-gradient(135deg, color-mix(in srgb, var(--accent) 7%, transparent), transparent 42%),
    var(--card);
}
.launcher-card::before {
  content: '';
  position: absolute;
  inset: 0 0 auto;
  height: 3px;
  background: var(--logo-grad);
}
.launcher-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 20px;
}
.launcher-title { margin: 0; }
.launcher-hint { max-width: 680px; margin: 4px 0 0; }
.launcher-overall {
  display: inline-flex;
  flex: 0 0 auto;
  align-items: center;
  gap: 7px;
  min-height: 28px;
  padding: 5px 10px;
  border: 1px solid currentColor;
  border-radius: var(--radius-pill);
  font-size: 11px;
  font-weight: 700;
  letter-spacing: .2px;
  white-space: nowrap;
}
.launcher-overall.is-ready {
  color: var(--ok-text);
  background: color-mix(in srgb, var(--ok) 10%, transparent);
}
.launcher-overall.is-idle {
  color: var(--warn-text);
  background: color-mix(in srgb, var(--warn) 10%, transparent);
}
.launcher-overall-dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: currentColor;
  box-shadow: 0 0 0 3px color-mix(in srgb, currentColor 16%, transparent);
}
.launcher-content { margin-top: 16px; }
.launcher-status-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 8px;
  margin: 0;
}
.launcher-status-item {
  min-width: 0;
  padding: 11px 12px;
  border: 1px solid var(--line);
  border-radius: max(4px, var(--radius));
  background: color-mix(in srgb, var(--bg) 62%, var(--card));
}
.launcher-status-item dt,
.launcher-path-label {
  color: var(--sub);
  font-size: 10px;
  font-weight: 700;
  letter-spacing: .45px;
  text-transform: uppercase;
}
.launcher-status-item dd { margin: 8px 0 0; }
.launcher-path {
  display: grid;
  grid-template-columns: 110px minmax(0, 1fr);
  align-items: center;
  gap: 12px;
  margin-top: 8px;
  padding: 9px 12px;
  border: 1px solid var(--line);
  border-radius: max(4px, var(--radius));
  background: color-mix(in srgb, var(--bg) 62%, var(--card));
}
.launcher-path-value {
  min-width: 0;
  overflow: hidden;
  color: var(--txt);
  font-size: 11px;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.launcher-placeholder { min-height: 112px; }
.launcher-actions {
  display: grid;
  grid-template-columns: repeat(5, minmax(0, 1fr));
  gap: 8px;
  margin-top: 12px;
  padding-top: 12px;
  border-top: 1px solid var(--line);
}
.launcher-actions button { width: 100%; min-width: 0; min-height: 36px; }
.password-footer { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-top: 14px; }
.password-state { margin: 0; }
.password-state.bad { color: var(--down-text); }
/* Same constraint story as WireGuard's .wg-qr: the scalable SVG has no
   intrinsic size, so the wrapper fixes one and keeps a light quiet zone. */
.twofa-qr {
  width: 190px; max-width: 100%; aspect-ratio: 1; margin: 10px 0;
  padding: 8px; background: #fff; border-radius: 8px; border: 1px solid var(--line);
}
.twofa-qr :deep(svg) { display: block; width: 100%; height: 100%; }
.twofa-recovery, .apikey-created {
  margin: 12px 0; padding: 12px; border-radius: 8px;
  background: color-mix(in srgb, var(--up) 8%, var(--bg));
  border: 1px solid color-mix(in srgb, var(--up) 25%, transparent);
}
.twofa-recovery-grid {
  display: grid; grid-template-columns: repeat(auto-fill, minmax(120px, 1fr));
  gap: 6px; margin-top: 8px;
}
.twofa-recovery-grid code { padding: 4px 8px; background: var(--card); border-radius: 5px; border: 1px solid var(--line); user-select: all; }
.apikey-value-row { display: flex; align-items: center; gap: 8px; margin-top: 8px; }
.apikey-value-row code { flex: 1; min-width: 0; padding: 6px 10px; background: var(--card); border-radius: 6px; border: 1px solid var(--line); overflow-wrap: anywhere; }
.ups-pick-row { display: flex; align-items: center; gap: 6px; padding: 2px 0; flex-wrap: wrap; }
.ups-pick-row .mono { flex: 1; min-width: 0; overflow-wrap: anywhere; }
@media (max-width: 900px) {
  .launcher-status-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .launcher-actions { grid-template-columns: repeat(3, minmax(0, 1fr)); }
}
@media (max-width: 640px) {
  .form-grid { grid-template-columns: 1fr; gap: 5px; }
  .form-grid label { margin-top: 5px; }
  .launcher-header { flex-wrap: wrap; align-items: center; gap: 12px; }
  .launcher-status-grid { grid-template-columns: 1fr; }
  .launcher-path { grid-template-columns: 1fr; gap: 5px; }
  .launcher-path-value { overflow: visible; text-overflow: clip; white-space: normal; word-break: break-all; }
  .launcher-actions { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .launcher-actions button:last-child { grid-column: 1 / -1; }
  .password-footer { flex-direction: column; align-items: stretch; }
  .password-footer button { width: 100%; }
  .apikey-value-row { flex-direction: column; align-items: stretch; }
}
</style>
