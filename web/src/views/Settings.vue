<template>
  <div>
    <div class="page-title">
      <h1>{{ t('settings.title') }}</h1>
      <span class="meta">{{ t('settings.meta') }} · v{{ form?.version || sysBundle?.management?.version || '—' }}</span>
    </div>

    <div class="tabs">
      <button v-for="tb in tabs" :key="tb.id" :class="{ active: tab===tb.id }" :aria-pressed="tab === tb.id" @click="switchTab(tb.id)">
        {{ t(tb.labelKey) }}
      </button>
    </div>

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
          >{{ l.native }}</button>
        </div>
      </div>

      <div class="card" style="margin-bottom:12px">
        <h2 class="section-title" style="margin-top:0">{{ t('theme.title') }}</h2>
        <p class="hint" style="margin-top:0">{{ t('appearance.theme_hint') }}</p>
        <div class="theme-grid">
          <button
            v-for="th in themes"
            :key="th.id"
            type="button"
            class="theme-card"
            :class="{ active: theme === th.id }"
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
            :class="{ active: density === d.id }"
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
          <div class="mono">{{ identity?.hostname || '—' }}</div>
          <label>LocalHostName</label>
          <div class="mono">{{ identity?.local_hostname || '—' }}</div>
          <label>{{ t('settings.model') }}</label>
          <div class="mono" style="font-size:12px">{{ identity?.model || '—' }}</div>
          <label>{{ t('settings.timezone') }}</label>
          <div class="mono">{{ identity?.timezone || '—' }}</div>
          <label>{{ t('settings.platform') }}</label>
          <div class="mono" style="font-size:11px">{{ identity?.platform || '—' }}</div>
          <label>{{ t('settings.host_ip') }}</label>
          <input v-model="identityForm.host_ip" type="text" placeholder="auto" :aria-label="t('settings.host_ip')" />
          <label>{{ t('settings.probe_current') }}</label>
          <div class="mono">{{ identity?.host_ip || '—' }}</div>
          <label>{{ t('settings.comment') }}</label>
          <input v-model="identityForm.comment" type="text" :aria-label="t('settings.comment')" />
        </div>
        <div class="btns" style="margin-top:12px">
          <button class="primary" :disabled="saving" @click="saveIdentity">{{ t('settings.save_identity') }}</button>
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
            <code class="launcher-path-value">{{ launcher.app_path || '—' }}</code>
          </div>
        </div>
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
          <div class="mono">{{ host?.lan_ip || host?.host_ip || '—' }}</div>
          <label>{{ t('settings.hostname') }}</label>
          <div class="mono">{{ host?.hostname || '—' }}</div>
          <label>{{ t('settings.platform') }}</label>
          <div class="mono" style="font-size:12px">{{ host?.platform || '—' }}</div>
          <label>docker / orb</label>
          <div class="mono" style="font-size:12px">{{ form.paths?.docker }} · {{ form.paths?.orb }}</div>
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
          <div class="mono">{{ form.auth.username }}</div>
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
          <span class="hint password-state" :class="{ bad: !!passwordMessage() }">{{ passwordMessage() || t('settings.password_rule') }}</span>
          <button class="primary" :disabled="savingPassword || !!passwordValidation()" @click="savePassword">
            {{ savingPassword ? t('settings.updating_password') : t('settings.update_password') }}
          </button>
        </div>
      </div>

      <div class="card">
        <h2 class="section-title" style="margin-top:0">{{ t('settings.intervals') }}</h2>
        <div class="form-grid">
          <label>{{ t('settings.metrics_interval') }}</label>
          <input v-model.number="form.metrics_interval" type="number" min="15" max="600" :aria-label="t('settings.metrics_interval')" />
          <label>{{ t('settings.alert_interval') }}</label>
          <input v-model.number="form.alert_interval" type="number" min="15" max="600" :aria-label="t('settings.alert_interval')" />
        </div>
        <p class="hint">{{ t('settings.intervals_hint') }}</p>
      </div>
    </div>

    <div v-else-if="tab==='notify' && form" class="two-col">
      <div class="card">
        <h2 class="section-title" style="margin-top:0">{{ t('settings.notify') }}</h2>
        <div class="form-grid">
          <label>{{ t('settings.notify_enable') }}</label>
          <input type="checkbox" v-model="form.notify.enabled" />
          <label>{{ t('settings.include_warn') }}</label>
          <input type="checkbox" v-model="form.notify.include_warn" />
          <label>{{ t('settings.notify_resolve') }}</label>
          <input type="checkbox" v-model="form.notify.notify_resolve" />
          <label>HA URL</label>
          <input v-model="form.notify.ha_url" type="text" aria-label="HA URL" />
          <label>HA Service</label>
          <input v-model="form.notify.ha_service" type="text" placeholder="notify.notify" aria-label="HA Service" />
          <label>HA Token</label>
          <input v-model="form.notify.ha_token" type="password" />
          <label>Webhook URL</label>
          <input v-model="form.notify.ha_webhook_url" type="text" />
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
      </div>
    </div>

    <div v-else-if="tab==='docker'">
      <div class="card" v-if="dockerInfo">
        <h2 class="section-title" style="margin-top:0">{{ t('settings.docker_engine') }}</h2>
        <p class="hint" style="margin-top:0">{{ t('settings.docker_hint') }}</p>
        <div class="form-grid" v-if="dockerInfo.engine_up">
          <label>{{ t('common.engine') }}</label>
          <div><span class="badge ok">{{ t('common.running') }}</span> {{ dockerInfo.info?.Name || '' }}</div>
          <label>Version</label>
          <div class="mono">{{ dockerInfo.info?.ServerVersion }}</div>
          <label>OrbStack</label>
          <div class="mono">{{ dockerInfo.orb_version || '—' }}</div>
          <label>OS / Arch</label>
          <div class="mono">{{ dockerInfo.info?.OperatingSystem }} · {{ dockerInfo.info?.Architecture }}</div>
          <label>CPU / RAM</label>
          <div>{{ dockerInfo.info?.NCPU }} · {{ memGb(dockerInfo.info?.MemTotal) }} GB</div>
          <label>Driver</label>
          <div class="mono">{{ dockerInfo.info?.Driver }} · {{ dockerInfo.info?.DockerRootDir }}</div>
          <label>Containers</label>
          <div>
            {{ t('common.running') }} {{ dockerInfo.info?.ContainersRunning ?? 0 }}
            · {{ t('common.stopped') }} {{ dockerInfo.info?.ContainersStopped ?? 0 }}
            · images {{ dockerInfo.info?.Images ?? 0 }}
          </div>
        </div>
        <div v-else class="placeholder">{{ dockerInfo.message || t('common.off') }}</div>
        <div class="btns" style="margin-top:12px">
          <router-link class="btn primary" to="/containers">{{ t('nav.docker') }}</router-link>
          <button @click="loadDockerInfo">{{ t('common.refresh') }}</button>
        </div>
      </div>
      <div v-else class="placeholder">{{ t('common.loading') }}</div>
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
          <div>{{ sysBundle.vms.total ?? 0 }} · {{ t('common.running') }} {{ sysBundle.vms.running ?? 0 }}</div>
        </div>
        <div class="btns" style="margin-top:12px">
          <router-link class="btn primary" to="/vms">{{ t('nav.vms') }}</router-link>
          <button @click="loadSysBundle">{{ t('common.refresh') }}</button>
        </div>
      </div>
      <div class="card">
        <h2 class="section-title" style="margin-top:0">{{ t('settings.vm_list') }}</h2>
        <table class="dense" v-if="(sysBundle?.vms?.items||[]).length">
          <thead><tr><th>{{ t('common.name') }}</th><th>{{ t('common.status') }}</th><th>Backend</th></tr></thead>
          <tbody>
            <tr v-for="v in sysBundle.vms.items" :key="v.id">
              <td>{{ v.name }}</td>
              <td><span class="badge">{{ v.state }}</span></td>
              <td class="mono">{{ v.backend }}</td>
            </tr>
          </tbody>
        </table>
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
          <div class="mono">{{ sysBundle.datetime.now }}</div>
          <label>{{ t('settings.timezone') }}</label>
          <div class="mono">{{ sysBundle.datetime.timezone || '—' }}</div>
          <label>NTP</label>
          <div>
            <span class="badge" :class="sysBundle.datetime.ntp_enabled ? 'ok' : 'warn'">
              {{ sysBundle.datetime.ntp_enabled == null ? '—' : (sysBundle.datetime.ntp_enabled ? t('common.on') : t('common.off')) }}
            </span>
            <span class="mono" style="margin-left:8px">{{ sysBundle.datetime.ntp_server || '' }}</span>
          </div>
          <label>Unix</label>
          <div class="mono">{{ sysBundle.datetime.unix }}</div>
        </div>
        <p class="hint">{{ sysBundle?.datetime?.hint }}</p>
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
        <p class="hint">{{ sysBundle?.power?.hint }}</p>
      </div>
      <div class="card">
        <h2 class="section-title" style="margin-top:0">{{ t('settings.ups') }}</h2>
        <div class="form-grid" v-if="sysBundle?.power?.ups">
          <label>{{ t('settings.power_source') }}</label>
          <div>
            <span class="badge" :class="sysBundle.power.ups.on_ac ? 'ok' : 'warn'">
              {{ sysBundle.power.ups.source === 'ac' ? 'AC' : (sysBundle.power.ups.source || '—') }}
            </span>
          </div>
          <label>{{ t('settings.battery') }}</label>
          <div>
            <span v-if="sysBundle.power.ups.battery_percent != null">
              {{ sysBundle.power.ups.battery_percent }}%
              <span class="meta" v-if="sysBundle.power.ups.charging">· {{ t('settings.charging') }}</span>
            </span>
            <span v-else>—</span>
          </div>
        </div>
        <p class="hint">{{ sysBundle?.power?.ups?.hint }}</p>
        <h2 class="section-title">{{ t('settings.assertions') }}</h2>
        <div v-if="(sysBundle?.power?.assertions||[]).length" class="mono" style="font-size:11px;max-height:180px;overflow:auto">
          <div v-for="(a,i) in sysBundle.power.assertions" :key="i" style="margin-bottom:6px">{{ a }}</div>
        </div>
        <div v-else class="sub">{{ t('settings.no_assertions') }}</div>
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
          <div>{{ sysBundle.disk.disksleep_minutes ?? '—' }} {{ t('settings.minutes') }}</div>
          <label>{{ t('settings.disk_count') }}</label>
          <div>{{ sysBundle.disk.disk_count ?? 0 }}</div>
        </div>
        <p class="hint">{{ sysBundle?.disk?.hint }}</p>
        <div class="btns" style="margin-top:10px">
          <router-link class="btn primary" to="/main">{{ t('nav.main') }}</router-link>
        </div>
      </div>
      <div class="card">
        <h2 class="section-title" style="margin-top:0">{{ t('settings.disk_power') }}</h2>
        <table class="dense" v-if="(sysBundle?.disk?.power_disks||[]).length">
          <thead><tr><th>{{ t('settings.disk') }}</th><th>{{ t('common.status') }}</th><th>{{ t('common.size') }}</th></tr></thead>
          <tbody>
            <tr v-for="d in sysBundle.disk.power_disks" :key="d.id">
              <td>{{ d.name }}</td>
              <td><span class="badge">{{ d.power_state || '—' }}</span></td>
              <td class="mono">{{ d.size_gb != null ? d.size_gb + ' GB' : '—' }}</td>
            </tr>
          </tbody>
        </table>
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
            {{ sysBundle.alias_auto.preferred.device }} · {{ sysBundle.alias_auto.preferred.service }}
            · {{ sysBundle.alias_auto.preferred.primary_ip }}
          </div>
          <div v-else style="color:var(--down)">—</div>
          <label>{{ t('settings.managed_ips') }}</label>
          <div>
            <span v-for="ip in (sysBundle.alias_auto.config?.ips||[])" :key="ip" class="badge ok" style="margin-right:4px">{{ ip }}</span>
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
          <div>{{ sysBundle.shares.share_count ?? 0 }}</div>
        </div>
        <p class="hint">{{ sysBundle?.shares?.hint }}</p>
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
          <div>{{ sysBundle.scheduler.count ?? 0 }}</div>
        </div>
        <table class="dense" style="margin-top:10px" v-if="(sysBundle?.scheduler?.timers||[]).length">
          <thead><tr><th>{{ t('common.name') }}</th><th>Interval</th></tr></thead>
          <tbody>
            <tr v-for="(tm, i) in sysBundle.scheduler.timers.slice(0, 15)" :key="i">
              <td class="mono" style="font-size:11px">{{ tm.label }}</td>
              <td class="mono">{{ tm.interval || tm.calendar || '—' }}</td>
            </tr>
          </tbody>
        </table>
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
          <div class="mono">{{ sysBundle.management.panel_port }}</div>
          <label>{{ t('settings.auth') }}</label>
          <div>
            <span class="badge" :class="sysBundle.management.auth_enabled ? 'ok' : 'warn'">
              {{ sysBundle.management.auth_enabled ? t('common.on') : t('common.off') }}
            </span>
            · {{ sysBundle.management.username }}
          </div>
          <label>{{ t('settings.auth_localhost') }}</label>
          <div>{{ sysBundle.management.allow_localhost ? t('common.yes') : t('common.no') }}</div>
          <label>Host IP</label>
          <div class="mono">{{ sysBundle.management.host_ip || '—' }}</div>
          <label>Nginx HTTPS</label>
          <div class="mono">{{ sysBundle.management.nginx_https }}</div>
          <label>{{ t('settings.version') }}</label>
          <div>ServerHub {{ sysBundle.management.version }}</div>
        </div>
        <div class="btns" style="margin-top:12px">
          <button class="primary" @click="tab='panel'">{{ t('settings.edit_panel') }}</button>
          <a class="btn" href="/api/export/services-yaml" download="services.yaml">{{ t('settings.export_yaml') }}</a>
        </div>
      </div>
      <div class="card">
        <h2 class="section-title" style="margin-top:0">{{ t('settings.paths') }}</h2>
        <div class="mono" style="font-size:11px;line-height:1.6" v-if="sysBundle?.management?.paths">
          <div>BASE: {{ sysBundle.management.paths.base }}</div>
          <div>YAML: {{ sysBundle.management.paths.services_yaml }}</div>
          <div v-if="sysBundle.management.paths.data">DATA: {{ sysBundle.management.paths.data }}</div>
        </div>
        <div class="btns" style="margin-top:12px;flex-direction:column;align-items:stretch">
          <router-link class="btn" to="/modules">{{ t('nav.modules') }}</router-link>
          <router-link class="btn" to="/health">{{ t('nav.health') }}</router-link>
          <router-link class="btn" to="/backups">{{ t('nav.backups') }}</router-link>
        </div>
      </div>
    </div>

    <!-- Advanced / Other -->
    <div v-else-if="tab==='advanced' && form" class="two-col">
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
          <label>{{ t('settings.metrics_interval') }}</label>
          <input v-model.number="form.metrics_interval" type="number" min="15" max="600" :aria-label="t('settings.metrics_interval')" />
          <label>{{ t('settings.alert_interval') }}</label>
          <input v-model.number="form.alert_interval" type="number" min="15" max="600" :aria-label="t('settings.alert_interval')" />
        </div>
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
      <div class="card">
        <h2 class="section-title" style="margin-top:0">{{ t('settings.ssd_friendly') }}</h2>
        <p class="hint" style="margin-top:0">{{ sysBundle?.other?.ssd_friendly?.hint || t('settings.ssd_hint') }}</p>
        <ul class="hint" style="margin:0;padding-left:18px;line-height:1.7">
          <li>metrics batch flush</li>
          <li>alert state write-if-changed</li>
          <li>services.yaml bak keep ≤ 5</li>
          <li>default metrics/alert interval 90s</li>
        </ul>
      </div>
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
        <p class="hint" v-if="diagMsg" style="margin-top:12px">{{ diagMsg }}</p>
      </div>
      <div class="card" v-if="diagPreview">
        <h2 class="section-title" style="margin-top:0">{{ t('settings.diag_preview') }}</h2>
        <pre class="mono" style="font-size:11px;max-height:360px;overflow:auto;margin:0;white-space:pre-wrap" role="status" aria-live="polite">{{ diagPreview }}</pre>
      </div>
    </div>

    <div class="toolbar" style="margin-top:16px" v-if="form && (tab==='panel' || tab==='notify')">
      <button class="primary" :disabled="saving" @click="save">{{ t('settings.save_settings') }}</button>
      <button :disabled="saving" @click="load">{{ t('common.reload') }}</button>
      <a class="btn" href="/api/export/services-yaml" download="services.yaml">{{ t('settings.export_yaml') }}</a>
    </div>
    <div
      v-else-if="!form && !['identity','docker','appearance','datetime','power','disk','network','shares','access','vms','scheduler','diagnostics'].includes(tab)"
      class="placeholder"
    >{{ t('common.loading') }}</div>
  </div>
</template>

<script setup>
import { inject, onMounted, ref } from 'vue'
import {
  changeAuthPassword, controlPanelService, forceAlertCheck, generateDiagnostics, getDockerInfo,
  getHost, getIdentity, getLauncherStatus, getSettings, getSystemSettings, openLauncherApp,
  putIdentity, putSettings, runAliasAutoBind, setLauncherLogin, setPowerSetting,
  testNotify as apiTest,
} from '../api/client'
import { injectI18n } from '../i18n'
import { injectTheme } from '../theme'

const toast = inject('toast')
const { t, locale, locales, setLocale } = injectI18n()
const { theme, density, themes, densities, setTheme, setDensity } = injectTheme()

const tab = ref('appearance')
const form = ref(null)
const host = ref(null)
const identity = ref(null)
const identityForm = ref({ computer_name: '', comment: '', host_ip: '' })
const dockerInfo = ref(null)
const sysBundle = ref(null)
const launcher = ref(null)
const launcherBusy = ref(false)
const launcherLoading = ref(false)
let launcherLoadRequest = 0
const powerForm = ref({ sleep: 0, displaysleep: 10, disksleep: 0, womp: 1 })
const saving = ref(false)
const diagMsg = ref('')
const diagPreview = ref('')
const savingPassword = ref(false)
const accountForm = ref({ username: '', currentPassword: '', newPassword: '', confirmPassword: '' })

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
  if (!bytes) return '—'
  return (bytes / 2 ** 30).toFixed(1)
}

function switchTab(id) {
  if (id === tab.value) return
  tab.value = id
  if (id === 'docker') loadDockerInfo()
  if (id === 'panel') loadLauncher()
  if (['datetime', 'power', 'disk', 'network', 'shares', 'access', 'vms', 'scheduler', 'advanced', 'diagnostics'].includes(id)) {
    loadSysBundle()
  }
}

async function loadSysBundle() {
  try {
    sysBundle.value = await getSystemSettings()
    const p = sysBundle.value?.power?.settings || {}
    powerForm.value = {
      sleep: p.sleep ?? sysBundle.value?.power?.sleep ?? 0,
      displaysleep: p.displaysleep ?? sysBundle.value?.power?.displaysleep ?? 10,
      disksleep: p.disksleep ?? sysBundle.value?.power?.disksleep ?? 0,
      womp: p.womp ?? sysBundle.value?.power?.womp ?? 1,
    }
  } catch (e) {
    toast('❌ ' + e.message)
  }
}

async function applyPower(key) {
  saving.value = true
  try {
    const value = powerForm.value[key]
    const result = await setPowerSetting(key, value)
    toast(result.ok ? `✅ ${key}=${value}` : `❌ ${result.message}`)
    await loadSysBundle()
  } catch (e) {
    toast('❌ ' + e.message)
  } finally {
    saving.value = false
  }
}

async function runAliasAlign() {
  saving.value = true
  try {
    const result = await runAliasAutoBind()
    toast(result.ok ? `✅ ${result.message || 'ok'}` : `❌ ${result.message || 'fail'}`)
    await loadSysBundle()
  } catch (e) {
    toast('❌ ' + e.message)
  } finally {
    saving.value = false
  }
}

async function runDiagnostics() {
  saving.value = true
  diagMsg.value = ''
  try {
    const result = await generateDiagnostics()
    const saved = Boolean(result.saved_path)
    diagMsg.value = saved
      ? `${t('settings.diag_saved')}: ${result.saved_path}`
      : t('settings.diag_save_failed', { error: result.save_error || t('common.failed') })
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
    toast(saved ? '✅ ' + t('settings.diag_done') : '❌ ' + diagMsg.value)
  } catch (e) {
    toast('❌ ' + e.message)
  } finally {
    saving.value = false
  }
}

async function pickLocale(id) {
  if (await setLocale(id)) {
    toast('✅ ' + t('appearance.saved_local'))
    putSettings({ ui: { locale: id, theme: theme.value, density: density.value } }).catch(() => {})
  }
}

function pickTheme(id) {
  setTheme(id)
  toast('✅ ' + t('theme.applied'))
  putSettings({ ui: { locale: locale.value, theme: id, density: density.value } }).catch(() => {})
}

function pickDensity(id) {
  setDensity(id)
  toast('✅ ' + t('appearance.saved_local'))
  putSettings({ ui: { locale: locale.value, theme: theme.value, density: id } }).catch(() => {})
}

async function syncUiToServer() {
  saving.value = true
  try {
    await putSettings({
      ui: { locale: locale.value, theme: theme.value, density: density.value },
    })
    toast('✅ ' + t('appearance.saved_server'))
  } catch (e) {
    toast('❌ ' + e.message)
  }
  saving.value = false
}

async function loadIdentity() {
  try {
    identity.value = await getIdentity()
    identityForm.value = {
      computer_name: identity.value.computer_name || '',
      comment: identity.value.comment || '',
      host_ip: identity.value.host_ip_config || 'auto',
    }
  } catch (e) {
    toast('❌ ' + e.message)
  }
}

async function saveIdentity() {
  saving.value = true
  try {
    const r = await putIdentity({
      computer_name: identityForm.value.computer_name || null,
      comment: identityForm.value.comment,
      host_ip: identityForm.value.host_ip,
    })
    toast('✅ ' + (r.message || t('common.save')))
    await loadIdentity()
    if (form.value && identityForm.value.host_ip) form.value.host_ip = identityForm.value.host_ip
  } catch (e) {
    toast('❌ ' + e.message)
  }
  saving.value = false
}

async function loadDockerInfo() {
  try { dockerInfo.value = await getDockerInfo() }
  catch (e) { toast('❌ ' + e.message) }
}

async function loadLauncher() {
  const request = ++launcherLoadRequest
  launcherLoading.value = true
  try {
    const status = await getLauncherStatus()
    if (request === launcherLoadRequest) launcher.value = status
  } catch (e) {
    if (request === launcherLoadRequest) toast('❌ ' + e.message)
  } finally {
    if (request === launcherLoadRequest) launcherLoading.value = false
  }
}

async function runLauncher(action) {
  if (['restart', 'stop'].includes(action) && !confirm(t(`settings.launcher_${action}_confirm`))) return
  launcherBusy.value = true
  try {
    let result
    if (action === 'open') result = await openLauncherApp()
    else if (action === 'login') result = await setLauncherLogin(!launcher.value?.login_enabled)
    else result = await controlPanelService(action)
    if (!result?.ok) throw new Error(result?.message || t('common.fail'))
    toast('✅ ' + (result.message || t('common.ok')))
    if (action === 'stop') {
      // The API intentionally disappears after accepting this command, so do
      // not leave the last green status visible or try to poll a stopped panel.
      launcher.value = {
        ...launcher.value,
        panel_running: false,
        panel_job_state: 'stopping',
      }
    } else {
      await new Promise(resolve => setTimeout(resolve, action === 'restart' ? 1400 : 300))
      await loadLauncher()
    }
  } catch (e) {
    toast('❌ ' + e.message)
  }
  launcherBusy.value = false
}

async function load() {
  try {
    const s = await getSettings()
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
      // Host shell is opt-in: default to OFF whenever the server does not
      // explicitly say it is on, so a missing field can never read as enabled.
      terminal: {
        host_enabled: s.terminal?.host_enabled === true,
        shell: s.terminal?.shell || '',
        cwd: s.terminal?.cwd || '',
      },
    }
    host.value = await getHost().catch(() => null)
    accountForm.value.username = form.value.auth.username
  } catch (e) {
    toast('❌ ' + e.message)
  }
}

async function save() {
  saving.value = true
  try {
    const body = {
      host_ip: form.value.host_ip,
      metrics_interval: form.value.metrics_interval,
      alert_interval: form.value.alert_interval,
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
      },
      ui: {
        locale: locale.value,
        theme: theme.value,
        density: density.value,
      },
    }
    if (form.value.notify.ha_token) body.notify.ha_token = form.value.notify.ha_token
    if (form.value.notify.ha_webhook_url) body.notify.ha_webhook_url = form.value.notify.ha_webhook_url
    await putSettings(body)
    toast('✅ ' + t('common.save'))
    await load()
  } catch (e) {
    toast('❌ ' + e.message)
  }
  saving.value = false
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
    toast('❌ ' + error)
    return
  }
  savingPassword.value = true
  try {
    const r = await changeAuthPassword(
      accountForm.value.username.trim(),
      accountForm.value.currentPassword,
      accountForm.value.newPassword,
    )
    form.value.auth.username = r.username
    accountForm.value = {
      username: r.username,
      currentPassword: '',
      newPassword: '',
      confirmPassword: '',
    }
    toast('✅ ' + (r.message || t('settings.password_updated')))
  } catch (e) {
    toast('❌ ' + e.message)
  }
  savingPassword.value = false
}

async function saveAdvanced() {
  saving.value = true
  try {
    await putSettings({
      adaptive: form.value.adaptive,
      metrics_interval: form.value.metrics_interval,
      alert_interval: form.value.alert_interval,
      ip_aliases: {
        auto_bind: form.value.ip_aliases.auto_bind,
        prefer_wired: form.value.ip_aliases.prefer_wired,
        interval: form.value.ip_aliases.interval,
      },
    })
    toast('✅ ' + t('common.save'))
    await load()
    await loadSysBundle()
  } catch (e) {
    toast('❌ ' + e.message)
  }
  saving.value = false
}

async function saveTerminal() {
  // Turning this ON is the one settings change that grants remote code
  // execution on this Mac, so make the operator acknowledge it explicitly
  // rather than letting a stray click arm it.
  if (form.value.terminal.host_enabled && !confirm(t('settings.terminal_confirm'))) {
    return
  }
  saving.value = true
  try {
    await putSettings({
      terminal: {
        host_enabled: form.value.terminal.host_enabled,
        cwd: form.value.terminal.cwd || undefined,
      },
    })
    toast('✅ ' + t('common.save'))
    await load()
  } catch (e) {
    toast('❌ ' + e.message)
  }
  saving.value = false
}

async function testNotify() {
  if (saving.value) return
  saving.value = true
  try {
    const r = await apiTest()
    toast(r.ok ? '✅ ' + t('common.ok') : '❌ ' + (r.message || t('common.fail')))
  } catch (e) {
    toast('❌ ' + e.message)
  } finally {
    saving.value = false
  }
}

async function forceCheck() {
  if (saving.value) return
  saving.value = true
  try {
    const r = await forceAlertCheck()
    toast(`${t('settings.force_check')} · ${r.emitted?.length || 0}`)
  } catch (e) {
    toast('❌ ' + e.message)
  } finally {
    saving.value = false
  }
}

onMounted(() => {
  load()
  loadIdentity()
  // Don't load full system bundle until a tab needs it (saves ~1.5s shell storm)
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
.sr-only {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
  border: 0;
}
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
  border-radius: 999px;
  font-size: 11px;
  font-weight: 700;
  letter-spacing: .2px;
  white-space: nowrap;
}
.launcher-overall.is-ready {
  color: var(--ok);
  background: color-mix(in srgb, var(--ok) 10%, transparent);
}
.launcher-overall.is-idle {
  color: var(--warn);
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
.password-state.bad { color: var(--down); }
.tabs {
  display: flex;
  flex-wrap: wrap;
  gap: 0;
  margin-bottom: 4px;
}
.tabs button {
  font-size: 12px;
  padding: 8px 12px;
}
@media (max-width: 900px) {
  .launcher-status-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .launcher-actions { grid-template-columns: repeat(3, minmax(0, 1fr)); }
}
@media (max-width: 640px) {
  .form-grid { grid-template-columns: 1fr; gap: 5px; }
  .form-grid label { margin-top: 5px; }
  .launcher-header { align-items: center; gap: 12px; }
  .launcher-status-grid { grid-template-columns: 1fr; }
  .launcher-path { grid-template-columns: 1fr; gap: 5px; }
  .launcher-path-value { overflow: visible; text-overflow: clip; white-space: normal; word-break: break-all; }
  .launcher-actions { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .launcher-actions button:last-child { grid-column: 1 / -1; }
  .password-footer { flex-direction: column; align-items: stretch; }
  .password-footer button { width: 100%; }
}
</style>
