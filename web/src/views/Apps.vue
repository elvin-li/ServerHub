<template>
  <div class="apps-page">
    <div class="page-title">
      <h1>{{ t('apps.title') }}</h1>
      <span class="meta">
        {{ t('apps.meta') }}
        · {{ overview.total ?? catalog.length }} {{ t('apps.templates') }}
        · {{ overview.installed ?? 0 }} {{ t('apps.installed_n') }}
      </span>
    </div>

    <div class="tabs">
      <button :class="{ active: tab === 'managed' }" :aria-pressed="tab === 'managed'" @click="tab = 'managed'; loadManaged()">{{ t('apps.tab_managed') }}</button>
      <button :class="{ active: tab === 'autostart' }" :aria-pressed="tab === 'autostart'" @click="tab = 'autostart'; loadAutostart()">{{ t('apps.tab_autostart') }}</button>
      <button :class="{ active: tab === 'catalog' }" :aria-pressed="tab === 'catalog'" @click="tab = 'catalog'; loadCatalog()">{{ t('apps.tab_catalog') }}</button>
    </div>
    <!-- Catalog / App Store -->
    <template v-if="tab === 'catalog'">
      <div class="toolbar apps-toolbar">
        <input v-model="q" type="text" class="search" :placeholder="t('apps.search_ph')"  :aria-label="t('apps.search_ph')"/>
        <select v-model="cat" class="cat-select">
          <option v-for="c in categories" :key="c.id" :value="c.id">
            {{ catLabel(c.id) }}{{ countLabel(c.id) }}
          </option>
        </select>
        <label class="chk"><input type="checkbox" v-model="onlyFeatured" /> {{ t('apps.featured_only') }}</label>
        <label class="chk"><input type="checkbox" v-model="hideInstalled" /> {{ t('apps.hide_installed') }}</label>
        <button type="button" @click="loadCatalog">{{ t('common.refresh') }}</button>
        <router-link class="btn" to="/compose">{{ t('apps.compose_editor') }}</router-link>
        <router-link class="btn" to="/containers">{{ t('nav.docker') }}</router-link>
      </div>

      <div class="cat-pills">
        <button
          v-for="c in quickCats"
          :key="c.id"
          type="button"
          class="cat-pill"
          :class="{ active: cat === c.id }"
          @click="cat = c.id"
        >{{ catLabel(c.id) }}{{ countLabel(c.id) }}</button>
      </div>

      <div class="app-grid">
        <article
          v-for="tpl in filtered"
          :key="tpl.id"
          class="app-card"
          :class="{
            featured: tpl.featured,
            installed: tpl.installed,
            native: tpl.kind === 'native',
          }"
        >
          <header class="app-head">
            <h3 class="app-title" :title="tpl.name">{{ tpl.name }}</h3>
            <div class="app-badges">
              <span class="chip" :class="tpl.kind === 'native' ? 'chip-native' : 'chip-docker'">
                {{ tpl.kind === 'native' ? t('apps.kind_native') : t('apps.kind_docker') }}
              </span>
              <span v-if="tpl.featured" class="chip chip-feat">{{ t('apps.featured') }}</span>
              <span v-if="tpl.installed" class="chip chip-ok">{{ t('apps.installed') }}</span>
              <span v-if="tpl.running" class="chip chip-ok">{{ t('common.running') }}</span>
            </div>
          </header>

          <div class="app-meta">
            <span class="cat-tag">{{ catLabel(tpl.category) }}</span>
            <span v-for="tg in (tpl.tags || []).slice(0, 3)" :key="tg" class="tag">{{ tg }}</span>
          </div>

          <p class="app-desc">{{ tpl.desc || '—' }}</p>

          <div v-if="(tpl.ports || []).length" class="app-ports mono">
            ports: {{ (tpl.ports || []).join(', ') }}
          </div>
          <div v-if="(tpl.images || []).length" class="app-images mono" :title="(tpl.images || []).join(', ')">
            {{ (tpl.images || []).slice(0, 2).join(', ') }}{{ (tpl.images || []).length > 2 ? '…' : '' }}
          </div>
          <div v-if="tpl.package" class="app-ports mono">brew: {{ tpl.package }}</div>
          <div v-if="catalogOpenUrl(tpl)" class="app-ports mono">{{ catalogOpenUrl(tpl) }}</div>

          <footer class="app-actions">
            <button
              v-if="!tpl.installed"
              type="button"
              class="primary"
              :disabled="busy"
              @click="openInstall(tpl)"
            >
              {{ tpl.kind === 'native' ? t('apps.deploy_native') : t('apps.deploy') }}
            </button>
            <template v-else>
              <button
                type="button"
                class="danger"
                :disabled="busy"
                @click="doUninstall(tpl)"
              >{{ t('apps.uninstall') }}</button>
              <button
                v-if="tpl.kind === 'docker' || (tpl.kind === 'native' && tpl.running != null)"
                type="button"
                :disabled="busy"
                @click="goManage(tpl)"
              >{{ t('apps.manage') }}</button>
              <button
                v-if="tpl.path && tpl.kind !== 'native'"
                type="button"
                @click="openPath(tpl)"
              >{{ t('apps.open_stack') }}</button>
              <button
                v-if="catalogOpenUrl(tpl)"
                type="button"
                class="btn primary"
                :disabled="busy"
                @click="launchOpen(tpl)"
              >{{ t('apps.open_url') }}</button>
            </template>
          </footer>
        </article>
      </div>
      <LoadFailure v-if="catalogError" :detail="catalogError" :retry="loadCatalog" :busy="busy" />
      <div v-else-if="!catalogLoaded" class="placeholder">{{ t('common.loading') }}</div>
      <div v-else-if="!filtered.length" class="placeholder">{{ t('apps.empty') }}</div>
    </template>

    <!-- Managed inventory: native + docker + vm -->
    <template v-else-if="tab === 'managed'">
      <div class="toolbar apps-toolbar">
        <input v-model="mq" type="text" class="search" :placeholder="t('apps.managed_search')"  :aria-label="t('apps.managed_search')"/>
        <select v-model="mkind" class="cat-select">
          <option value="all">{{ t('apps.cat_all') }}</option>
          <option value="native">{{ t('apps.kind_native') }}</option>
          <option value="docker">{{ t('apps.kind_docker') }}</option>
          <option value="vm">{{ t('apps.kind_vm') }}</option>
        </select>
        <button type="button" class="primary" @click="loadManaged(true)" :disabled="loading">{{ t('common.refresh') }}</button>
        <button type="button" @click="tab = 'catalog'">{{ t('apps.browse_catalog') }}</button>
        <span class="meta-count" v-if="managed.counts">
          {{ managed.counts.total }} ·
          {{ t('apps.kind_native') }} {{ managed.counts.native }} ·
          Docker {{ managed.counts.docker }} ·
          VM {{ managed.counts.vm }} ·
          {{ t('common.running') }} {{ managed.counts.running }}
        </span>
      </div>

      <!-- This is the tab the page opens on, and the inventory walks launchd,
           docker and the VM list before answering. Without this the landing view
           stated "no managed apps" for the whole first request. -->
      <LoadFailure
        v-if="managedError"
        :detail="managedError"
        :retry="() => loadManaged(true)"
        :busy="loading"
      />
      <SkeletonLoader v-if="!managedLoaded" :cols="7" :rows="8" />
      <div v-else class="managed-table-wrap">
        <table class="managed-table">
          <thead>
            <tr>
              <th>{{ t('common.name') }}</th>
              <th>{{ t('apps.col_kind') }}</th>
              <th>{{ t('common.status') }}</th>
              <th>{{ t('apps.col_ports') }}</th>
              <th>{{ t('apps.col_autostart') }}</th>
              <th>{{ t('apps.col_path') }}</th>
              <th>{{ t('common.actions') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="it in filteredManaged" :key="it.id" @click="openDetail(it)" tabindex="0" role="button" @keydown.enter.prevent="openDetail(it)" @keydown.space.prevent="openDetail(it)">
              <td>
                <strong>{{ it.name }}</strong>
                <div class="sub-line" v-if="it.status_text">{{ it.status_text }}</div>
              </td>
              <td>
                <span class="chip" :class="kindChip(it.kind)">{{ kindLabel(it.kind) }}</span>
              </td>
              <td>
                <span class="chip" :class="it.state === 'ok' ? 'chip-ok' : (it.state === 'warn' ? 'chip-feat' : 'chip-muted')">
                  {{ stateLabel(it.state) }}
                </span>
              </td>
              <td class="mono ports-cell">{{ it.ports_summary || (it.ips || []).join(', ') || '—' }}</td>
              <td @click.stop>
                <label v-if="it.autostart != null || it.kind === 'docker' || it.autostart_id" class="auto-toggle" :title="it.autostart_detail || ''">
                  <input
                    type="checkbox"
                    :checked="!!it.autostart"
                    :disabled="busy || it.kind === 'vm'"
                    @change="toggleManagedAutostart(it, $event.target.checked)"
                  />
                  <span>{{ it.autostart ? t('apps.auto_on') : t('apps.auto_off') }}</span>
                </label>
                <span v-else class="sub-line">—</span>
              </td>
              <td class="mono path-cell" :title="it.path || it.package || ''">{{ it.path || it.package || it.backend || '—' }}</td>
              <td class="actions-cell" @click.stop>
                <div class="act-row">
                  <button type="button" class="act-btn" @click="openDetail(it)" tabindex="0" role="button" @keydown.enter.prevent="openDetail(it)" @keydown.space.prevent="openDetail(it)">{{ t('apps.detail') }}</button>
                  <button v-if="canAct(it, 'start')" type="button" class="act-btn primary" :disabled="busy" @click="doManagedAction(it, 'start')">{{ t('apps.act_start') }}</button>
                  <button v-if="canAct(it, 'stop')" type="button" class="act-btn" :disabled="busy" @click="doManagedAction(it, 'stop')">{{ t('apps.act_stop') }}</button>
                  <button v-if="canAct(it, 'restart')" type="button" class="act-btn" :disabled="busy" @click="doManagedAction(it, 'restart')">{{ t('apps.act_restart') }}</button>
                  <button v-if="canAct(it, 'logs') || it.kind === 'docker' || it.kind === 'native'" type="button" class="act-btn" @click="openManagedLogs(it)">{{ t('apps.logs') }}</button>
                  <button
                    v-if="openUrl(it)"
                    type="button"
                    class="act-btn primary"
                    :disabled="busy"
                    @click="launchOpen(it)"
                  >{{ t('apps.open_url') }}</button>
                  <button type="button" class="act-btn danger" :disabled="busy" @click="doManagedUninstall(it)">{{ t('apps.uninstall') }}</button>
                </div>
              </td>
            </tr>
            <tr v-if="!filteredManaged.length && !managedError">
              <td colspan="7" class="empty-row">{{ t('apps.managed_empty') }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </template>

    <!-- Autostart console -->
    <template v-else-if="tab === 'autostart'">
      <div class="toolbar apps-toolbar">
        <button type="button" class="primary" @click="loadAutostart(true)" :disabled="loading">{{ t('common.refresh') }}</button>
        <button type="button" :disabled="busy" @click="runAutostartNow">{{ t('apps.run_autostart_now') }}</button>
        <span class="meta-count" v-if="autostart.counts">
          {{ t('apps.auto_on') }} {{ autostart.counts.autostart_on }} ·
          {{ t('apps.auto_off') }} {{ autostart.counts.autostart_off }} ·
          brew {{ autostart.counts.brew }} ·
          Docker {{ autostart.counts.docker }} ·
          LaunchAgent {{ autostart.counts.launchd }}
        </span>
      </div>
      <p class="hint-line">{{ t('apps.autostart_hint') }}</p>

      <div v-for="grp in autostartGroups" :key="grp" class="auto-group">
        <h2 class="section-title">{{ grp }}</h2>
        <div class="managed-table-wrap" style="margin-bottom:14px">
          <table class="managed-table">
            <thead>
              <tr>
                <th>{{ t('common.name') }}</th>
                <th>{{ t('common.status') }}</th>
                <th>{{ t('apps.col_autostart') }}</th>
                <th>{{ t('apps.col_detail') }}</th>
                <th>{{ t('common.actions') }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="it in (autostartByGroup[grp] || [])" :key="it.id">
                <td>
                  <strong>{{ it.name }}</strong>
                  <div class="sub-line mono" v-if="it.program">{{ it.program }}</div>
                </td>
                <td>
                  <span class="chip" :class="it.running ? 'chip-ok' : 'chip-muted'">
                    {{ it.running ? t('common.running') : t('common.stopped') }}
                  </span>
                  <span v-if="it.policy" class="sub-line mono"> {{ it.policy }}</span>
                </td>
                <td>
                  <label class="auto-toggle">
                    <input
                      type="checkbox"
                      :checked="!!it.autostart"
                      :disabled="busy"
                      @change="setAutostartItem(it, $event.target.checked)"
                    />
                    <span>{{ it.autostart ? t('apps.auto_on') : t('apps.auto_off') }}</span>
                  </label>
                </td>
                <td class="mono path-cell" :title="it.detail || it.plist || ''">{{ it.detail || it.plist || '—' }}</td>
                <td class="actions-cell">
                  <div class="act-row" v-if="it.kind === 'docker'">
                    <select
                      class="policy-select"
                      :value="it.policy || 'no'"
                      :disabled="busy"
                      @change="setDockerPolicy(it, $event.target.value)"
                    >
                      <option value="no">no</option>
                      <option value="unless-stopped">unless-stopped</option>
                      <option value="always">always</option>
                      <option value="on-failure">on-failure</option>
                    </select>
                  </div>
                  <span v-else class="sub-line">{{ it.kind }}</span>
                </td>
              </tr>
              <tr v-if="!(autostartByGroup[grp] || []).length">
                <td colspan="5" class="empty-row">—</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </template>

    <!-- Detail drawer -->
    <div v-if="detail" class="drawer-bg" @click.self="closeDetail" role="presentation">
      <aside ref="detailPanel" class="drawer" role="dialog" aria-modal="true" aria-labelledby="apps-detail-title" tabindex="-1">
        <div class="drawer-head">
          <div>
            <h2 id="apps-detail-title" class="drawer-title">{{ detail.name }}</h2>
            <div class="app-badges" style="margin-top:6px">
              <span class="chip" :class="kindChip(detail.kind)">{{ kindLabel(detail.kind) }}</span>
              <span class="chip" :class="detail.state === 'ok' ? 'chip-ok' : 'chip-muted'">{{ stateLabel(detail.state) }}</span>
            </div>
          </div>
          <button type="button" @click="closeDetail">{{ t('common.close') }}</button>
        </div>

        <div class="drawer-actions">
          <button v-if="canAct(detail, 'start')" type="button" class="primary" :disabled="busy" @click="doManagedAction(detail, 'start')">{{ t('apps.act_start') }}</button>
          <button v-if="canAct(detail, 'stop')" type="button" :disabled="busy" @click="doManagedAction(detail, 'stop')">{{ t('apps.act_stop') }}</button>
          <button v-if="canAct(detail, 'restart')" type="button" :disabled="busy" @click="doManagedAction(detail, 'restart')">{{ t('apps.act_restart') }}</button>
          <button v-if="canAct(detail, 'update')" type="button" :disabled="busy" @click="doManagedAction(detail, 'update')">{{ t('apps.act_update') }}</button>
          <button type="button" @click="openManagedLogs(detail)">{{ t('apps.logs') }}</button>
          <button v-if="openUrl(detail)" type="button" class="primary" :disabled="busy" @click="launchOpen(detail)">{{ t('apps.open_url') }}</button>
          <button type="button" class="danger" :disabled="busy" @click="doManagedUninstall(detail)">{{ t('apps.uninstall') }}</button>
        </div>

        <section class="drawer-sec credential-sec">
          <div class="credential-title">
            <h3>{{ t('apps.credentials') }}</h3>
            <span v-if="credential?.has_password" class="chip chip-ok">{{ t('apps.credential_saved') }}</span>
            <span v-else class="chip chip-muted">{{ t('apps.credential_not_saved') }}</span>
          </div>
          <p class="sub-line credential-hint">
            {{ credential?.can_apply ? t('apps.credential_apply_hint') : t('apps.credential_store_hint') }}
          </p>
          <div class="credential-grid">
            <label>{{ t('settings.username') }}</label>
            <input v-model.trim="credentialForm.username" type="text" autocomplete="username" maxlength="128" :aria-label="t('settings.username')" />
            <label>{{ t('settings.new_password') }}</label>
            <div class="credential-password-input">
              <input v-model="credentialForm.password" :type="showCredentialPassword ? 'text' : 'password'" autocomplete="new-password" minlength="8" :aria-label="t('settings.new_password')" />
              <button type="button" @click="generateCredentialPassword">{{ t('apps.credential_generate') }}</button>
              <button type="button" @click="showCredentialPassword = !showCredentialPassword">
                {{ showCredentialPassword ? t('apps.credential_hide') : t('apps.credential_show') }}
              </button>
            </div>
            <label>{{ t('settings.confirm_password') }}</label>
            <input v-model="credentialForm.confirm" :type="showCredentialPassword ? 'text' : 'password'" autocomplete="new-password" minlength="8" :aria-label="t('settings.confirm_password')" />
            <label>URL</label>
            <input v-model.trim="credentialForm.url" type="text" autocomplete="url" aria-label="URL" />
            <label>{{ t('apps.credential_notes') }}</label>
            <textarea v-model="credentialForm.notes" rows="2" maxlength="1000" :aria-label="t('apps.credential_notes')"></textarea>
          </div>
          <p class="sub-line credential-security">{{ t('apps.credential_security') }}</p>
          <!-- The form falls back to a hardcoded username and empty notes, so a
               failed read must disable Save rather than let it overwrite the
               stored record with those defaults. -->
          <div v-if="!credentialLoaded" class="placeholder" role="alert" style="margin-bottom:8px">
            <div>{{ t('apps.credential_load_failed') }}</div>
            <div v-if="credentialError" class="sub mono" style="margin-top:4px">{{ credentialError }}</div>
          </div>
          <div class="credential-actions">
            <button
              v-if="credential?.can_apply"
              type="button"
              class="primary"
              :disabled="credentialBusy || !credentialLoaded"
              @click="saveCredential(true)"
            >{{ t('apps.credential_apply_save') }}</button>
            <button type="button" :disabled="credentialBusy || !credentialLoaded" @click="saveCredential(false)">
              {{ t('apps.credential_save_only') }}
            </button>
            <button
              v-if="credential?.has_password"
              type="button"
              class="danger"
              :disabled="credentialBusy"
              @click="deleteCredential"
            >{{ t('apps.credential_delete') }}</button>
          </div>
        </section>

        <!-- Cloudflare Tunnel panel -->
        <section class="drawer-sec" v-if="detail.source_id === 'native-cloudflared' || detail.cloudflared">
          <h3>{{ t('apps.cf_title') }}</h3>
          <p class="sub-line" style="margin-bottom:10px">
            {{ t('apps.cf_hint') }}
            <a href="https://one.dash.cloudflare.com/" target="_blank" rel="noopener">{{ t('apps.cf_zero_trust') }}</a>
            {{ t('apps.cf_hint_tail') }}
          </p>
          <div class="app-badges" style="margin-bottom:10px">
            <span class="chip" :class="cfStatus.logged_in ? 'chip-ok' : 'chip-muted'">
              {{ cfStatus.logged_in ? t('apps.cf_signed_in') : t('apps.cf_signed_out') }}
            </span>
            <span class="chip" :class="cfStatus.running ? 'chip-ok' : 'chip-muted'">
              {{ cfStatus.running ? t('apps.cf_tunnel_running') : t('apps.cf_tunnel_stopped') }}
            </span>
            <span v-if="cfStatus.active_tunnel" class="chip chip-muted mono">{{ cfStatus.active_tunnel }}</span>
          </div>

          <div class="credential-actions" style="margin-bottom:12px;flex-wrap:wrap;gap:8px">
            <button type="button" :disabled="busy || cfBusy" @click="cfLogin">{{ t('apps.cf_login') }}</button>
            <button type="button" :disabled="busy || cfBusy" @click="cfRefresh">{{ t('apps.cf_refresh') }}</button>
            <button type="button" class="primary" :disabled="busy || cfBusy || !cfSelectedTunnel" @click="cfStartSelected">
              {{ t('apps.cf_start_selected') }}
            </button>
            <button type="button" :disabled="busy || cfBusy || !cfStatus.running" @click="cfStop">{{ t('apps.act_stop') }}</button>
            <button type="button" :disabled="busy || cfBusy" @click="cfRestart">{{ t('apps.act_restart') }}</button>
            <button type="button" :disabled="busy || cfBusy" @click="openManagedLogs(detail)">{{ t('apps.logs') }}</button>
          </div>

          <div v-if="cfStatus.login_url" class="notes" style="margin-bottom:10px;word-break:break-all">
            {{ t('apps.cf_open_link') }}
            <a :href="cfStatus.login_url" target="_blank" rel="noopener">{{ cfStatus.login_url }}</a>
            <div class="sub-line" style="margin-top:6px">{{ t('apps.cf_after_auth') }}</div>
          </div>

          <div class="form-grid" style="margin-bottom:10px">
            <label class="form-label">{{ t('apps.cf_existing_tunnel') }}</label>
            <div class="form-field">
              <select v-model="cfSelectedTunnel" :disabled="cfBusy" style="width:100%;padding:8px;border-radius:8px" :aria-label="t('apps.cf_existing_tunnel')">
                <option value="">{{ t('apps.cf_select_ph') }}</option>
                <option v-for="tn in (cfStatus.tunnels || [])" :key="tn.id" :value="tn.name">
                  {{ tn.name }} ({{ tn.id.slice(0, 8) }}…){{ tn.active ? ` · ${t('apps.cf_connected')}` : '' }}
                </option>
              </select>
              <div class="field-help" v-if="!(cfStatus.tunnels || []).length">
                {{ cfStatus.logged_in ? t('apps.cf_no_tunnels') : t('apps.cf_login_to_list') }}
              </div>
            </div>
            <label class="form-label">{{ t('apps.cf_new_tunnel') }}</label>
            <div class="form-field" style="display:flex;gap:8px">
              <input v-model.trim="cfNewName" type="text" :placeholder="t('apps.cf_new_name_ph')" maxlength="64" style="flex:1"  :aria-label="t('apps.cf_new_name_ph')"/>
              <button type="button" :disabled="cfBusy || !cfNewName" @click="cfCreate">{{ t('apps.cf_create') }}</button>
            </div>
            <label class="form-label">{{ t('apps.cf_paste_token') }}</label>
            <div class="form-field">
              <input v-model.trim="cfToken" type="password" placeholder="Zero Trust → Tunnels → Install token" :aria-label="t('apps.cf_paste_token')" />
              <div class="field-help">{{ t('apps.cf_token_help') }}</div>
            </div>
          </div>
          <div class="credential-actions" style="margin-bottom:10px">
            <button type="button" class="primary" :disabled="cfBusy || !cfToken" @click="cfStartToken">{{ t('apps.cf_start_token') }}</button>
          </div>

          <div class="form-grid">
            <label class="form-label">{{ t('apps.cf_dns_route') }}</label>
            <div class="form-field" style="display:flex;gap:8px;flex-wrap:wrap">
              <input v-model.trim="cfDnsHost" type="text" placeholder="ha.example.com" style="flex:1;min-width:160px" :aria-label="t('apps.cf_dns_route')" />
              <button type="button" :disabled="cfBusy || !cfSelectedTunnel || !cfDnsHost" @click="cfRouteDns">{{ t('apps.cf_bind_dns') }}</button>
            </div>
            <div class="field-help">{{ t('apps.cf_dns_help') }}</div>
          </div>
          <pre v-if="cfMsg" class="install-log" style="margin-top:12px;max-height:180px" role="log" aria-live="polite">{{ cfMsg }}</pre>
        </section>

        <section class="drawer-sec" v-if="detail.kind !== 'vm'">
          <h3>{{ t('apps.col_autostart') }}</h3>
          <label class="auto-toggle">
            <input
              type="checkbox"
              :checked="!!detail.autostart"
              :disabled="busy"
              @change="toggleManagedAutostart({ id: detail.id, kind: detail.kind, autostart_id: detail.autostart_id, source_id: detail.source_id }, $event.target.checked)"
            />
            <span>{{ detail.autostart ? t('apps.auto_on') : t('apps.auto_off') }} · {{ t('apps.autostart_help') }}</span>
          </label>
        </section>

        <section class="drawer-sec" v-if="detail.path || detail.compose_file || detail.package || detail.plist_hint">
          <h3>{{ t('apps.sec_paths') }}</h3>
          <div class="kv-list mono">
            <div v-if="detail.path"><span class="k">path</span>{{ detail.path }}</div>
            <div v-if="detail.compose_file"><span class="k">compose</span>{{ detail.compose_file }}</div>
            <div v-if="detail.package"><span class="k">package</span>{{ detail.package }}</div>
            <div v-if="detail.plist_hint"><span class="k">plist</span>{{ detail.plist_hint }}</div>
            <div v-if="detail.backend"><span class="k">backend</span>{{ detail.backend }}</div>
            <div v-if="detail.uuid"><span class="k">uuid</span>{{ detail.uuid }}</div>
          </div>
        </section>

        <section class="drawer-sec" v-if="(detail.data_paths||[]).length">
          <h3>{{ t('apps.sec_data') }}</h3>
          <ul class="plain-list mono">
            <li v-for="(p,i) in detail.data_paths" :key="i">{{ p }}</li>
          </ul>
        </section>

        <section class="drawer-sec" v-if="(detail.databases||[]).length">
          <h3>{{ t('apps.sec_db') }}</h3>
          <ul class="plain-list mono">
            <li v-for="(d,i) in detail.databases" :key="i">{{ d.type }} · {{ d.path }} <span v-if="d.mount">→ {{ d.mount }}</span></li>
          </ul>
        </section>

        <section class="drawer-sec" v-if="(detail.ports||[]).length || (detail.listening||[]).length">
          <h3>{{ t('apps.sec_ports') }}</h3>
          <table class="mini-table" v-if="(detail.ports||[]).length">
            <thead><tr><th>{{ t('apps.col_ports') }}</th><th>target</th><th>ctr</th></tr></thead>
            <tbody>
              <tr v-for="(p,i) in detail.ports" :key="i">
                <td class="mono">{{ p.published || '—' }}</td>
                <td class="mono">{{ p.target }}</td>
                <td class="mono">{{ p.container || '' }}</td>
              </tr>
            </tbody>
          </table>
          <div v-if="(detail.listening||[]).length" class="sub-line" style="margin-top:8px">
            {{ t('apps.listening') }}:
            <span v-for="(l,i) in detail.listening" :key="i" class="mono"> {{ l.name }} </span>
          </div>
        </section>

        <section class="drawer-sec" v-if="(detail.networks||[]).length">
          <h3>{{ t('apps.sec_network') }}</h3>
          <table class="mini-table">
            <thead><tr><th>network</th><th>IP</th><th>gw / ctr</th></tr></thead>
            <tbody>
              <tr v-for="(n,i) in detail.networks" :key="i">
                <td class="mono">{{ n.network }}</td>
                <td class="mono">{{ n.ip || '—' }}</td>
                <td class="mono">{{ n.gateway || n.container || '' }}</td>
              </tr>
            </tbody>
          </table>
        </section>

        <section class="drawer-sec" v-if="(detail.mounts||[]).length">
          <h3>{{ t('apps.sec_mounts') }}</h3>
          <table class="mini-table">
            <thead><tr><th>src</th><th>dst</th><th>type</th></tr></thead>
            <tbody>
              <tr v-for="(m,i) in detail.mounts" :key="i">
                <td class="mono path-cell" :title="m.source">{{ m.source }}</td>
                <td class="mono">{{ m.destination }}</td>
                <td>{{ m.type }}</td>
              </tr>
            </tbody>
          </table>
        </section>

        <section class="drawer-sec" v-if="(detail.containers||[]).length">
          <h3>{{ t('apps.sec_containers') }}</h3>
          <table class="mini-table">
            <thead><tr><th>name</th><th>image</th><th>state</th><th>ports</th></tr></thead>
            <tbody>
              <tr v-for="(c,i) in detail.containers" :key="i">
                <td class="mono">{{ c.name }}</td>
                <td class="mono path-cell">{{ c.image }}</td>
                <td>{{ c.state }}</td>
                <td class="mono path-cell">{{ c.ports }}</td>
              </tr>
            </tbody>
          </table>
        </section>

        <section class="drawer-sec" v-if="(detail.ips||[]).length">
          <h3>VM IP</h3>
          <div class="mono">{{ (detail.ips || []).join(', ') }}</div>
        </section>

        <section class="drawer-sec" v-if="(detail.env_sample||[]).length">
          <h3>Env</h3>
          <pre class="env-pre">{{ (detail.env_sample || []).join('\n') }}</pre>
        </section>

        <section class="drawer-sec" v-if="detail.notes">
          <h3>{{ t('apps.sec_notes') }}</h3>
          <p class="notes">{{ detail.notes }}</p>
        </section>

        <p class="sub-line" v-if="detail.host_ip">Host IP: {{ detail.host_ip }}</p>
      </aside>
    </div>

    <!-- install modal -->
    <div ref="installPanel" v-if="installTpl" class="modal-bg" @click.self="installTpl = null" role="presentation">
      <div class="modal install-modal" role="dialog" aria-modal="true" aria-labelledby="apps-install-title">
        <div class="modal-head">
          <h3 id="apps-install-title" class="modal-title">{{ t('apps.deploy') }} · {{ installTpl.name }}</h3>
          <button type="button" @click="installTpl = null">{{ t('common.close') }}</button>
        </div>
        <p class="modal-desc">{{ installTpl.desc }}</p>
        <p v-if="installTpl.notes" class="notes">{{ installTpl.notes }}</p>
        <p v-if="installTpl.kind === 'native'" class="path-line mono">
          → {{ t('apps.native_install') }} · {{ installTpl.method || 'system' }}{{ installTpl.package ? ` · ${installTpl.package}` : '' }}
        </p>
        <p v-else class="path-line mono">→ ~/Services/{{ installTpl.id }}/docker-compose.yml</p>

        <div v-if="(installTpl.vars || []).length" class="form-grid">
          <template v-for="v in installTpl.vars" :key="v.name">
            <label class="form-label">{{ v.label || v.name }}</label>
            <div class="form-field">
              <input
                v-model="installVars[v.name]"
                :type="v.secret ? 'password' : 'text'"
                :placeholder="v.default === '' && v.secret ? t('apps.auto_password') : (v.required === false ? t('apps.optional') : '')"
              />
              <div v-if="v.help" class="field-help">{{ v.help }}</div>
            </div>
          </template>
        </div>
        <p v-else class="modal-desc">{{ t('apps.no_vars') }}</p>

        <div class="app-actions" style="margin-top:14px">
          <button type="button" class="primary" :disabled="busy" @click="doInstall">{{ t('apps.confirm_deploy') }}</button>
          <button type="button" @click="installTpl = null">{{ t('common.cancel') }}</button>
        </div>
        <pre v-if="installLog" class="install-log" role="log" aria-live="polite">{{ installLog }}</pre>
        <a
          v-if="installUrl"
          class="btn primary open-url"
          :href="installUrl"
          target="_blank"
          rel="noopener"
        >{{ t('apps.open_url') }} · {{ installUrl }}</a>
      </div>
    </div>

    <!-- closeJobLog, not `logOpen = false`: the job log polls every 1.5s and the
         interval was only cleared when a poll happened to observe running:false,
         so closing the modal left it running against the server indefinitely. -->
    <div ref="logPanel" v-if="logOpen" class="modal-bg" @click.self="closeJobLog" role="presentation">
      <div class="modal install-modal" role="dialog" aria-modal="true" aria-labelledby="apps-log-title">
        <div class="modal-head">
          <h3 id="apps-log-title" class="modal-title">📋 {{ logTitle }}</h3>
          <button type="button" @click="closeJobLog">{{ t('common.close') }}</button>
        </div>
        <pre class="install-log">{{ logText }}</pre>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, inject, onMounted, onUnmounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import {
  createCloudflareTunnel,
  deleteAppCredential,
  getAppCredential,
  getAutostartApps,
  getCatalog,
  getCloudflareStatus,
  getManagedAppDetail,
  getManagedAppLogs,
  getManagedApps,
  getStackJob,
  getStacks,
  installCatalog,
  manageApp,
  pollCloudflareLogin,
  restartCloudflare,
  routeCloudflareDns,
  runAppAutostartNow,
  runStack,
  saveAppCredential,
  setAppAutostart,
  setDockerAutostartPolicy,
  startCloudflareLogin,
  startCloudflareToken,
  startCloudflareTunnel,
  stopCloudflare,
  uninstallCatalog,
} from '../api/client'
import { injectI18n } from '../i18n'
import { useDismissable } from '../composables/useDismissable'
import SkeletonLoader from '../components/SkeletonLoader.vue'
import LoadFailure from '../components/LoadFailure.vue'
import { startVisibleInterval } from '../lib/poll'

const toast = inject('toast')
const { t } = injectI18n()

const tab = ref('managed')
const stacks = ref([])
const jobs = ref([])
const catalog = ref([])
const overview = ref({})
const categories = ref([{ id: 'all', label: t('common.all') }])
const router = useRouter()
const managed = ref({ items: [], counts: null })
const autostart = ref({ items: [], counts: null, groups: [] })
const detail = ref(null)
const detailPanel = ref(null)
const mq = ref('')
const mkind = ref('all')
const loading = ref(false)
// Latched per data source, not derived from `loading`: the two tabs load
// independently, and reusing `loading` would blank a populated table whenever the
// other source refreshed.
const managedLoaded = ref(false)
const catalogLoaded = ref(false)
const managedError = ref('')
const catalogError = ref('')
const busy = ref(false)
const logOpen = ref(false)
const logPanel = ref(null)
const logTitle = ref('')
const logText = ref('')
const curJob = ref(null)
const installTpl = ref(null)
const installPanel = ref(null)
const installVars = ref({})
const installLog = ref('')
const installUrl = ref('')
const credential = ref(null)
const credentialBusy = ref(false)
const credentialForm = ref({ username: '', password: '', confirm: '', url: '', notes: '' })
// Whether credentialForm reflects the stored record; gates Save. See loadCredential().
const credentialLoaded = ref(false)
const credentialError = ref('')
const showCredentialPassword = ref(false)
const q = ref('')
const cat = ref('all')
const onlyFeatured = ref(false)
const hideInstalled = ref(false)
// Cloudflare Tunnel panel state
const cfStatus = ref({ logged_in: false, running: false, tunnels: [] })
const cfSelectedTunnel = ref('')
const cfNewName = ref('')
const cfToken = ref('')
const cfDnsHost = ref('')
const cfMsg = ref('')
const cfBusy = ref(false)
let timer = null
let logTimer = null
let cfPollTimer = null
let cfPollGeneration = 0

const CAT_I18N = {
  all: 'apps.cat_all',
  featured: 'apps.cat_featured',
  native: 'apps.cat_native',
  docker: 'apps.cat_docker',
  network: 'apps.cat_network',
  remote: 'apps.cat_remote',
  media: 'apps.cat_media',
  download: 'apps.cat_download',
  files: 'apps.cat_files',
  security: 'apps.cat_security',
  dashboard: 'apps.cat_dashboard',
  monitor: 'apps.cat_monitor',
  ops: 'apps.cat_ops',
  dev: 'apps.cat_dev',
  data: 'apps.cat_data',
  iot: 'apps.cat_iot',
  productivity: 'apps.cat_productivity',
  notify: 'apps.cat_notify',
  backup: 'apps.cat_backup',
  other: 'apps.cat_other',
}

const jobMap = computed(() => {
  const m = {}
  for (const j of jobs.value) if (j.stack_id) m[j.stack_id] = j.job_id
  return m
})

const filteredManaged = computed(() => {
  let list = managed.value.items || []
  if (mkind.value !== 'all') list = list.filter(x => x.kind === mkind.value)
  const s = mq.value.trim().toLowerCase()
  if (s) {
    list = list.filter(x =>
      (x.name || '').toLowerCase().includes(s)
      || (x.id || '').toLowerCase().includes(s)
      || (x.path || '').toLowerCase().includes(s)
      || (x.package || '').toLowerCase().includes(s)
      || (x.ports_summary || '').toLowerCase().includes(s)
    )
  }
  return list
})

const autostartGroups = computed(() => {
  const g = autostart.value.groups || []
  if (g.length) return g
  const set = new Set((autostart.value.items || []).map(i => i.group || t('common.other')))
  return [...set]
})

const autostartByGroup = computed(() => {
  const m = {}
  for (const it of autostart.value.items || []) {
    const g = it.group || t('common.other')
    ;(m[g] || (m[g] = [])).push(it)
  }
  return m
})

/**
 * The headline of a possibly multi-line backend message, for a toast.
 *
 * Install and uninstall failures can be several lines long -- a pkg-based cask
 * explains that Homebrew cannot be run as root and prints the command to run on
 * the Mac instead. That belongs in the install log, which is a <pre>; a toast
 * carrying it covers the page.
 */
function firstLine(message) {
  const text = String(message ?? '').trim()
  if (!text) return t('common.fail')
  return text.split('\n')[0]
}

function kindLabel(k) {
  if (k === 'native') return t('apps.kind_native')
  if (k === 'docker') return t('apps.kind_docker')
  if (k === 'vm') return t('apps.kind_vm')
  return k
}
function kindChip(k) {
  if (k === 'native') return 'chip-native'
  if (k === 'docker') return 'chip-docker'
  return 'chip-feat'
}
function stateLabel(s) {
  if (s === 'ok') return t('common.running')
  if (s === 'stopped' || s === 'down') return t('common.stopped')
  if (s === 'warn') return t('common.warn')
  return s || '—'
}
/** Always allow common ops; never hide uninstall behind missing action flags */
function canAct(it, act) {
  if (!it) return false
  if (act === 'uninstall') return true
  const acts = it.actions || []
  if (acts.includes(act)) return true
  // fallbacks when backend omits flags
  if (act === 'logs' && (it.kind === 'docker' || it.kind === 'native')) return true
  if (act === 'start' && (it.state === 'down' || it.state === 'stopped')) return true
  if (act === 'stop' && it.state === 'ok' && it.kind !== 'native') return true
  if (act === 'restart' && it.state === 'ok') return true
  return false
}

function isScreenSharing(it) {
  if (!it) return false
  const id = `${it.id || ''} ${it.source_id || ''}`
  const name = (it.name || '').toLowerCase()
  return id.includes('screen-sharing')
    || name.includes('屏幕共享')
    || name.includes('screen sharing')
    || (it.url || '').startsWith('vnc://')
    || (it.url_hint || '').startsWith('vnc://')
    || it.open_protocol === 'vnc'
}

/** Prefer url field; fall back to first host port in ports_summary */
function openUrl(it) {
  if (!it) return ''
  // VNC / Screen Sharing: connect to the host you're browsing (panel host)
  if (isScreenSharing(it)) {
    const host = window.location.hostname
      || (managed.value && managed.value.host_ip)
      || 'localhost'
    return `vnc://${host}`
  }
  const rawUrl = it.url || it.url_hint || ''
  if (rawUrl) {
    const host = window.location.hostname
      || (managed.value && managed.value.host_ip)
      || 'localhost'
    return rawUrl.replaceAll('{{HOST}}', host).replaceAll('{{HOST_IP}}', host)
  }
  const ps = it.ports_summary || ''
  const m = ps.match(/(?:0\.0\.0\.0|127\.0\.0\.1|\[::\]):(\d+)->/) || ps.match(/^(\d{2,5})$/)
  if (m) {
    const host = (managed.value && managed.value.host_ip) || window.location.hostname || 'localhost'
    return `http://${host}:${m[1]}`
  }
  // native ports list like "8125"
  if (it.ports_summary && /^\d{2,5}/.test(it.ports_summary.trim())) {
    const port = it.ports_summary.trim().split(/[,\s]/)[0]
    if (!['1883', '5432', '6379', '3306', '5900', '9100'].includes(port)) {
      const host = (managed.value && managed.value.host_ip) || window.location.hostname || 'localhost'
      return `http://${host}:${port}`
    }
  }
  return ''
}

/** Catalog/store open link: url_hint (resolved) or url_template with defaults */
function catalogOpenUrl(tpl) {
  if (!tpl) return ''
  if (isScreenSharing(tpl)) {
    const host = window.location.hostname || 'localhost'
    return `vnc://${host}`
  }
  if (tpl.url_hint) return tpl.url_hint
  if (tpl.url) return tpl.url
  const ut = tpl.url_template || ''
  if (!ut) {
    // ports-only fallback for web-ish services
    const ports = tpl.ports || []
    for (const p of ports) {
      const ps = String(p).split('/')[0]
      if (/^\d+$/.test(ps) && !['1883', '5432', '6379', '3306', '5900', '9100', '22000', '53'].includes(ps)) {
        const host = window.location.hostname || 'localhost'
        return `http://${host}:${ps}`
      }
    }
    return ''
  }
  const host = window.location.hostname || 'localhost'
  let out = ut.replaceAll('{{HOST_IP}}', host).replaceAll('{{HOST}}', host)
  const vars = tpl.vars || []
  for (const v of vars) {
    if (v && v.name && v.default != null && v.default !== '') {
      out = out.replaceAll(`{{${v.name}}}`, String(v.default))
    }
  }
  // leftover placeholders → not a usable URL
  if (out.includes('{{')) return ''
  return out
}

/**
 * Open WebUI or native client.
 * vnc:// must NOT use target=_blank — that often blocks Screen Sharing activation.
 * For screen-sharing also hit backend open (launches client on the hub Mac).
 */
async function launchOpen(it) {
  const u = openUrl(it) || catalogOpenUrl(it)
  if (!u) return
  // The trigger buttons are bound to `busy` but this never set it, so repeat
  // clicks fired concurrent manageApp(..., 'open') calls at the host.
  if (busy.value) return
  busy.value = true
  try {
    await launchOpenInner(it, u)
  } finally {
    busy.value = false
  }
}

async function launchOpenInner(it, u) {
  const isProto = /^(vnc|ssh|rdp|smb|afp|vnc):\/\//i.test(u)

  if (isScreenSharing(it) || isProto) {
    // 1) Activate client on the machine running the browser
    try {
      const a = document.createElement('a')
      a.href = u
      // no target=_blank — required for custom URL schemes on macOS
      document.body.appendChild(a)
      a.click()
      a.remove()
    } catch {
      try { window.location.href = u } catch {}
    }
    // 2) Also ask hub Mac to open Screen Sharing (local panel / menubar)
    if (isScreenSharing(it)) {
      try {
        const id = (it.id && String(it.id).includes(':'))
          ? it.id
          : `native:${it.source_id || it.id || 'native-screen-sharing'}`
        const result = await manageApp(id, 'open')
        if (result.ok) {
          toast(`✅ ${t('apps.open_url')} · ${result.url || u}`)
          return
        }
      } catch {}
    }
    toast(`→ ${u}`)
    return
  }
  window.open(u, '_blank', 'noopener')
}
function goManage(tpl) {
  tab.value = 'managed'
  loadManaged(true)
  // try open detail after load
  setTimeout(() => {
    const id = tpl.kind === 'native'
      ? `native:${tpl.id}`
      : `docker:${tpl.id}`
    const hit = (managed.value.items || []).find(x => x.id === id || x.source_id === tpl.id)
    if (hit) openDetail(hit)
  }, 400)
}

async function loadManaged(force = false) {
  loading.value = true
  try {
    managed.value = await getManagedApps(force)
    managedError.value = ''
  } catch (e) {
    managedError.value = e.message || String(e)
    toast('❌ ' + e.message)
  } finally {
    loading.value = false
    managedLoaded.value = true
  }
}

async function loadAutostart(force = false) {
  loading.value = true
  try {
    autostart.value = await getAutostartApps(force)
  } catch (e) {
    toast('❌ ' + e.message)
  } finally {
    loading.value = false
  }
}

async function setAutostartItem(it, enabled) {
  busy.value = true
  try {
    const result = await setAppAutostart(it.id, enabled)
    toast(result.ok !== false ? `✅ ${enabled ? t('apps.auto_on') : t('apps.auto_off')} · ${it.name}` : '❌ ' + (result.message || ''))
    // Disjoint state (`autostart` vs `managed`) re-read after the same write.
    await Promise.all([loadAutostart(true), loadManaged(true)])
  } catch (e) {
    toast('❌ ' + e.message)
  } finally {
    busy.value = false
  }
}

async function setDockerPolicy(it, policy) {
  const name = (it.id || '').replace(/^docker-ctr:/, '').replace(/^docker:/, '')
  busy.value = true
  try {
    const result = await setDockerAutostartPolicy(name, policy)
    toast(result.ok ? `✅ restart=${policy}` : '❌ ' + (result.message || ''))
    // Disjoint state (`autostart` vs `managed`) re-read after the same write.
    await Promise.all([loadAutostart(true), loadManaged(true)])
  } catch (e) {
    toast('❌ ' + e.message)
  } finally {
    busy.value = false
  }
}

async function runAutostartNow() {
  if (!confirm(t('apps.confirm_run_autostart'))) return
  busy.value = true
  try {
    const result = await runAppAutostartNow()
    toast(result.ok ? '✅ ' + (result.message || 'ok') : '❌ ' + (result.message || 'fail'))
    // This starts every autostart-enabled app, so the table it was launched from
    // is immediately out of date. Nothing reloaded it before: the 15s poll only
    // covers the Managed tab, so the Autostart rows kept their pre-run "stopped"
    // chips until the user switched tabs and back.
    await loadAutostart()
  } catch (e) {
    toast('❌ ' + e.message)
  } finally {
    busy.value = false
  }
}

async function toggleManagedAutostart(it, enabled) {
  busy.value = true
  try {
    // Prefer dedicated autostart_id (brew:xxx) when present
    if (it.autostart_id) {
      await setAutostartItem({ id: it.autostart_id, name: it.name }, enabled)
      return
    }
    const result = await manageApp(it.id, enabled ? 'autostart_on' : 'autostart_off')
    toast(result.ok !== false ? `✅ ${enabled ? t('apps.auto_on') : t('apps.auto_off')}` : '❌ ' + (result.message || ''))
    await loadManaged(true)
    if (detail.value?.id === it.id) {
      detail.value = { ...detail.value, autostart: enabled }
    }
  } catch (e) {
    toast('❌ ' + e.message)
  } finally {
    busy.value = false
  }
}

async function openDetail(it) {
  busy.value = true
  try {
    const d = await getManagedAppDetail(it.id)
    // merge list-level autostart flags
    d.autostart = it.autostart
    d.autostart_id = it.autostart_id
    detail.value = d
    await loadCredential(d)
    if (d.source_id === 'native-cloudflared' || d.cloudflared) {
      await cfRefresh()
    }
  } catch (e) {
    toast('❌ ' + e.message)
  } finally {
    busy.value = false
  }
}

function stopCfLoginPolling() {
  // Invalidating the generation also neutralizes a request that is already in
  // flight: its late response cannot update a closed drawer or schedule again.
  cfPollGeneration += 1
  if (cfPollTimer) clearTimeout(cfPollTimer)
  cfPollTimer = null
}

function closeDetail() {
  detail.value = null
  credential.value = null
  credentialForm.value = { username: '', password: '', confirm: '', url: '', notes: '' }
  showCredentialPassword.value = false
  cfMsg.value = ''
  stopCfLoginPolling()
}

async function cfRefresh() {
  cfBusy.value = true
  try {
    const status = await getCloudflareStatus()
    cfStatus.value = status
    if (status.active_tunnel && !cfSelectedTunnel.value) {
      cfSelectedTunnel.value = status.active_tunnel
    }
    if (detail.value?.source_id === 'native-cloudflared') {
      detail.value = {
        ...detail.value,
        state: status.running ? 'ok' : 'down',
        cloudflared: status,
        autostart: !!status.plist,
      }
    }
  } catch (e) {
    cfMsg.value = '❌ ' + e.message
  } finally {
    cfBusy.value = false
  }
}

function startCfLoginPolling() {
  stopCfLoginPolling()
  const generation = cfPollGeneration

  const poll = async () => {
    cfPollTimer = null
    try {
      const pollResult = await pollCloudflareLogin()
      if (generation !== cfPollGeneration) return
      if (pollResult.logged_in) {
        stopCfLoginPolling()
        toast('✅ ' + t('apps.cf_logged_in'))
        await cfRefresh()
        return
      }
    } catch (_) { /* Poll errors are intentionally nonfatal. */ }

    // setTimeout after await keeps at most one request in flight.
    if (generation === cfPollGeneration) {
      cfPollTimer = setTimeout(poll, 2500)
    }
  }

  cfPollTimer = setTimeout(poll, 2500)
}

async function cfLogin() {
  cfBusy.value = true
  cfMsg.value = ''
  try {
    const result = await startCloudflareLogin()
    cfMsg.value = (result.ok ? '✅ ' : '❌ ') + (result.message || '')
    if (result.login_url) {
      cfStatus.value = { ...cfStatus.value, login_url: result.login_url, login_pending: true }
      startCfLoginPolling()
    } else if (result.logged_in || result.already) {
      stopCfLoginPolling()
      await cfRefresh()
    }
  } catch (e) {
    cfMsg.value = '❌ ' + e.message
    toast('❌ ' + e.message)
  } finally {
    cfBusy.value = false
  }
}

async function cfStartSelected() {
  if (!cfSelectedTunnel.value) return
  cfBusy.value = true
  cfMsg.value = ''
  try {
    const result = await startCloudflareTunnel(cfSelectedTunnel.value)
    cfMsg.value = (result.ok ? '✅ ' : '❌ ') + (result.message || '')
    toast(result.ok ? '✅ ' + t('apps.tunnel_started', { name: cfSelectedTunnel.value }) : '❌ ' + (result.message || ''))
    // cfRefresh() writes `cfStatus`, loadManaged() writes `managed`; the tunnel
    // action above already committed, so neither read depends on the other.
    await Promise.all([cfRefresh(), loadManaged(true)])
  } catch (e) {
    cfMsg.value = '❌ ' + e.message
    toast('❌ ' + e.message)
  } finally {
    cfBusy.value = false
  }
}

async function cfStartToken() {
  if (!cfToken.value) return
  cfBusy.value = true
  cfMsg.value = ''
  try {
    const result = await startCloudflareToken(cfToken.value, cfSelectedTunnel.value || 'token')
    cfMsg.value = (result.ok ? '✅ ' : '❌ ') + (result.message || '')
    toast(result.ok ? '✅ ' + t('apps.token_tunnel_started') : '❌ ' + (result.message || ''))
    cfToken.value = ''
    // cfRefresh() writes `cfStatus`, loadManaged() writes `managed`; the tunnel
    // action above already committed, so neither read depends on the other.
    await Promise.all([cfRefresh(), loadManaged(true)])
  } catch (e) {
    cfMsg.value = '❌ ' + e.message
    toast('❌ ' + e.message)
  } finally {
    cfBusy.value = false
  }
}

async function cfStop() {
  // Stopping the tunnel drops every externally published hostname. The panel's
  // own service stop is confirmed (Settings.vue), so this is too.
  if (!confirm(t('apps.cf_confirm_stop'))) return
  cfBusy.value = true
  try {
    const result = await stopCloudflare()
    cfMsg.value = (result.ok ? '✅ ' : '❌ ') + (result.message || '')
    toast(result.ok ? '✅ ' + t('apps.stopped') : '❌ ' + (result.message || ''))
    // cfRefresh() writes `cfStatus`, loadManaged() writes `managed`; the tunnel
    // action above already committed, so neither read depends on the other.
    await Promise.all([cfRefresh(), loadManaged(true)])
  } catch (e) {
    toast('❌ ' + e.message)
  } finally {
    cfBusy.value = false
  }
}

async function cfRestart() {
  cfBusy.value = true
  try {
    const result = await restartCloudflare()
    cfMsg.value = (result.ok ? '✅ ' : '❌ ') + (result.message || '')
    toast(result.ok ? '✅ ' + t('apps.restarted') : '❌ ' + (result.message || ''))
    // cfRefresh() writes `cfStatus`, loadManaged() writes `managed`; the tunnel
    // action above already committed, so neither read depends on the other.
    await Promise.all([cfRefresh(), loadManaged(true)])
  } catch (e) {
    toast('❌ ' + e.message)
  } finally {
    cfBusy.value = false
  }
}

async function cfCreate() {
  if (!cfNewName.value) return
  cfBusy.value = true
  try {
    const result = await createCloudflareTunnel(cfNewName.value)
    cfMsg.value = (result.ok ? '✅ ' : '❌ ') + (result.message || '')
    if (result.ok) {
      cfSelectedTunnel.value = cfNewName.value
      cfNewName.value = ''
    }
    await cfRefresh()
  } catch (e) {
    cfMsg.value = '❌ ' + e.message
    toast('❌ ' + e.message)
  } finally {
    cfBusy.value = false
  }
}

async function cfRouteDns() {
  if (!cfSelectedTunnel.value || !cfDnsHost.value) return
  cfBusy.value = true
  try {
    const result = await routeCloudflareDns(cfSelectedTunnel.value, cfDnsHost.value)
    cfMsg.value = (result.ok ? '✅ ' : '❌ ') + (result.message || '')
    toast(result.ok ? '✅ ' + t('apps.dns_bound') : '❌ ' + (result.message || ''))
  } catch (e) {
    cfMsg.value = '❌ ' + e.message
    toast('❌ ' + e.message)
  } finally {
    cfBusy.value = false
  }
}

function generateCredentialPassword() {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%_-'
  const bytes = new Uint8Array(20)
  crypto.getRandomValues(bytes)
  const value = Array.from(bytes, b => alphabet[b % alphabet.length]).join('')
  credentialForm.value.password = value
  credentialForm.value.confirm = value
  showCredentialPassword.value = true
}

function credentialDefaultUsername(app) {
  const id = `${app?.id || ''} ${app?.source_id || ''}`.toLowerCase()
  if (id.includes('filebrowser')) return 'admin'
  if (id.includes('teslamate')) return 'teslamate'
  return ''
}

async function loadCredential(app) {
  credential.value = null
  credentialForm.value = {
    username: credentialDefaultUsername(app),
    password: '',
    confirm: '',
    url: openUrl(app) || '',
    notes: '',
  }
  try {
    const result = await getAppCredential(app.id)
    credential.value = result
    credentialForm.value = {
      username: result.username || credentialDefaultUsername(app),
      password: '',
      confirm: '',
      url: result.url || openUrl(app) || '',
      notes: result.notes || '',
    }
    credentialLoaded.value = true
    credentialError.value = ''
  } catch (e) {
    // Latch the failure and block Save. The form is pre-seeded with a hardcoded
    // default username and empty notes, and saveCredential sends both, so saving
    // on top of a failed read replaced the stored username and wiped the notes.
    // A missing credential is not this case: the API returns 200 with an empty
    // record for an app that has none, so a rejection here is a real failure.
    credentialLoaded.value = false
    credentialError.value = e.message || String(e)
    toast('❌ ' + e.message)
  }
}

async function saveCredential(applyToService) {
  if (!credentialLoaded.value) {
    toast('❌ ' + t('apps.credential_load_failed'))
    return
  }
  const f = credentialForm.value
  if (!f.username) {
    toast('❌ ' + t('settings.username_required'))
    return
  }
  if (f.password.length < 8) {
    toast('❌ ' + t('apps.credential_password_length'))
    return
  }
  if (f.password !== f.confirm) {
    toast('❌ ' + t('auth.password_mismatch'))
    return
  }
  credentialBusy.value = true
  try {
    const result = await saveAppCredential({
      service_id: detail.value.id,
      display_name: detail.value.name || detail.value.id,
      username: f.username,
      password: f.password,
      url: f.url,
      notes: f.notes,
      apply_to_service: !!applyToService,
    })
    credential.value = result.credential
    credentialForm.value.password = ''
    credentialForm.value.confirm = ''
    showCredentialPassword.value = false
    toast('✅ ' + (result.message || t('apps.credential_saved')))
  } catch (e) {
    toast('❌ ' + e.message)
  } finally {
    credentialBusy.value = false
  }
}

async function deleteCredential() {
  if (!confirm(t('apps.credential_delete_confirm'))) return
  credentialBusy.value = true
  try {
    await deleteAppCredential(detail.value.id)
    await loadCredential(detail.value)
    toast('✅ ' + t('apps.credential_deleted'))
  } catch (e) {
    toast('❌ ' + e.message)
  } finally {
    credentialBusy.value = false
  }
}

// Generation counter so overlapping opens cannot interleave. None of the three
// triggers were disabled and this had no in-flight guard, so two clicks resolved
// into the shared logText in whatever order the responses arrived -- leaving the
// modal titled for one app and showing another's log.
let managedLogGeneration = 0

async function openManagedLogs(it) {
  const generation = ++managedLogGeneration
  logOpen.value = true
  logTitle.value = (it.name || it.id) + ' · logs'
  logText.value = t('common.loading')
  try {
    const result = await getManagedAppLogs(it.id, 150)
    if (generation !== managedLogGeneration) return
    logText.value = result.log || result.message || '—'
  } catch (e) {
    if (generation !== managedLogGeneration) return
    logText.value = e.message
  }
}

async function doManagedAction(it, action) {
  if (!it?.id) return
  busy.value = true
  try {
    const result = await manageApp(it.id, action)
    toast(result.ok !== false ? `✅ ${action}` : '❌ ' + (result.message || ''))
    await loadManaged(true)
    if (detail.value?.id === it.id) await openDetail(it)
  } catch (e) {
    toast('❌ ' + e.message)
  } finally {
    busy.value = false
  }
}

async function doManagedUninstall(it) {
  if (!it?.id) return
  if (!confirm(t('apps.confirm_uninstall_managed', { name: it.name || it.id }))) return
  const removeData = it.kind === 'docker' ? confirm(t('apps.confirm_remove_data')) : false
  busy.value = true
  try {
    const result = await manageApp(it.id, 'uninstall', removeData)
    toast(result.ok !== false ? `✅ ${t('apps.uninstalled')}` : '❌ ' + (result.message || ''))
    detail.value = null
    await Promise.all([loadManaged(true), loadCatalog()])
  } catch (e) {
    toast('❌ ' + e.message)
  } finally {
    busy.value = false
  }
}

const quickCats = computed(() => {
  const prefer = ['all', 'native', 'docker', 'featured', 'network', 'remote', 'media', 'files', 'ops', 'monitor']
  const map = Object.fromEntries((categories.value || []).map(c => [c.id, c]))
  return prefer.map(id => map[id] || { id, label: id }).filter(Boolean)
})

const filtered = computed(() => {
  let list = catalog.value || []
  if (cat.value === 'featured') list = list.filter(x => x.featured)
  else if (cat.value === 'native') list = list.filter(x => x.kind === 'native')
  else if (cat.value === 'docker') list = list.filter(x => (x.kind || 'docker') === 'docker')
  else if (cat.value && cat.value !== 'all') list = list.filter(x => x.category === cat.value)
  if (onlyFeatured.value) list = list.filter(x => x.featured)
  if (hideInstalled.value) list = list.filter(x => !x.installed)
  const s = q.value.trim().toLowerCase()
  if (s) {
    list = list.filter(x =>
      (x.name || '').toLowerCase().includes(s)
      || (x.desc || '').toLowerCase().includes(s)
      || (x.id || '').toLowerCase().includes(s)
      || (x.package || '').toLowerCase().includes(s)
      || (x.tags || []).some(tg => String(tg).toLowerCase().includes(s))
      || (x.category || '').toLowerCase().includes(s)
      || (x.kind || '').toLowerCase().includes(s)
    )
  }
  return list
})

function catLabel(id) {
  const key = CAT_I18N[id]
  if (key) {
    const tr = t(key)
    if (tr && tr !== key) return tr
  }
  const c = (categories.value || []).find(x => x.id === id)
  return c?.label || id || 'other'
}

function countLabel(id) {
  if (id === 'all') return overview.value.total != null ? ` (${overview.value.total})` : ''
  if (id === 'featured') {
    const n = (catalog.value || []).filter(x => x.featured).length
    return n ? ` (${n})` : ''
  }
  if (id === 'native' && overview.value.native_count != null) return ` (${overview.value.native_count})`
  if (id === 'docker' && overview.value.docker_count != null) return ` (${overview.value.docker_count})`
  const n = (overview.value.counts || {})[id]
  return n ? ` (${n})` : ''
}

async function refresh() {
  loading.value = true
  try {
    const d = await getStacks()
    stacks.value = d.stacks || []
    jobs.value = d.jobs || []
  } catch (e) {
    toast('❌ ' + e.message)
  }
  loading.value = false
}

async function loadCatalog() {
  try {
    const d = await getCatalog()
    catalog.value = d.templates || []
    overview.value = d
    if (d.categories?.length) categories.value = d.categories
    catalogError.value = ''
  } catch (e) {
    catalogError.value = e.message || String(e)
    toast('❌ ' + e.message)
  } finally {
    catalogLoaded.value = true
  }
}

function openInstall(tpl) {
  installTpl.value = tpl
  installLog.value = ''
  installUrl.value = ''
  const vars = {}
  for (const v of tpl.vars || []) vars[v.name] = v.default || ''
  installVars.value = vars
}

// "Open stack" sends the operator to the Compose page, which is this app's
// dedicated stack view. It used to set tab.value = 'stacks', but the template
// only branches on catalog / managed / autostart, so the button rendered a blank
// page. It deliberately does not reuse goManage(): the adjacent "Manage" button
// already does that, and the two are offered as distinct actions.
function openPath() {
  router.push('/compose')
}

async function doInstall() {
  if (!installTpl.value) return
  // The confirm button is bound to `busy`, but a disabled attribute is not a
  // lock: the dialog stays open for the whole install, and Enter on a focused
  // button still fires. Two concurrent installs of the same package now get a
  // 409 from the server rather than colliding inside Homebrew's own lock, and
  // this keeps the panel from asking for that in the first place.
  if (busy.value) return
  const isNative = installTpl.value.kind === 'native'
  const msg = isNative
    ? t('apps.confirm_native', { name: installTpl.value.name })
    : t('apps.confirm_msg', { name: installTpl.value.name, id: installTpl.value.id })
  if (!confirm(msg)) return
  busy.value = true
  installLog.value = isNative ? t('apps.deploying_native') : t('apps.deploying')
  installUrl.value = ''
  try {
    const r = await installCatalog(installTpl.value.id, installVars.value)
    installLog.value = (r.ok ? '✅ ' : '❌ ') + (r.message || '') + (r.path ? `\n→ ${r.path}` : '')
    if (r.notes) installLog.value += `\n\n${r.notes}`
    if (r.url || r.url_hint) installUrl.value = r.url || r.url_hint
    // First line only in the toast. A failure message can be several lines --
    // a pkg-based cask, for instance, explains that brew cannot be elevated and
    // prints the command to run on the Mac instead. The full text is right there
    // in installLog; a five-line toast just hides the rest of the page.
    toast(r.ok ? `✅ ${installTpl.value.name}` : '❌ ' + firstLine(r.message))
    if (r.ok) {
      // Three independent re-reads after a successful install: catalog, managed
      // list and stacks. refresh() was already fire-and-forget here.
      await Promise.all([loadCatalog(), loadManaged(true), refresh()])
    }
  } catch (e) {
    installLog.value = '❌ ' + e.message
    toast('❌ ' + e.message)
  }
  busy.value = false
}

async function doUninstall(tpl) {
  if (!tpl?.id) return
  if (busy.value) return
  const isNative = tpl.kind === 'native'
  if (!confirm(
    isNative
      ? t('apps.confirm_uninstall_native', { name: tpl.name })
      : t('apps.confirm_uninstall', { name: tpl.name, id: tpl.id })
  )) return

  // Docker: optional keep compose dir (default remove)
  let removeData = true
  if (!isNative) {
    removeData = confirm(t('apps.confirm_remove_data'))
  } else if (tpl.id === 'native-filebrowser') {
    removeData = confirm(t('apps.confirm_remove_data'))
  }

  busy.value = true
  try {
    const r = await uninstallCatalog(tpl.id, { remove_data: removeData })
    toast(r.ok ? `✅ ${t('apps.uninstalled')} ${tpl.name}` : '❌ ' + firstLine(r.message))
    if (r.message && !r.ok) {
      // show detail in console-friendly toast only; full msg may be long
    }
    // loadManaged too: uninstalling from the catalog left the app still listed
    // under Managed until something else happened to refresh it, so the two
    // uninstall paths disagreed -- doManagedUninstall() already reloads it.
    await Promise.all([loadCatalog(), refresh(), loadManaged(true)])
  } catch (e) {
    toast('❌ ' + e.message)
  }
  busy.value = false
}

async function run(s, action) {
  if (action === 'down' && !confirm(t('apps.confirm_down', { name: s.name }))) return
  if (action === 'update' && !confirm(t('apps.confirm_update', { name: s.name }))) return
  busy.value = true
  try {
    const r = await runStack(s.id, action)
    toast('🚀 ' + (r.message || 'ok'))
    if (r.job_id) openJob(r.job_id, s.name)
    refresh()
  } catch (e) {
    toast('❌ ' + e.message)
  }
  busy.value = false
}

function openJob(jobId, title) {
  curJob.value = jobId
  logTitle.value = title || jobId
  logOpen.value = true
  logText.value = t('common.loading')
  poll()
  if (logTimer) clearInterval(logTimer)
  logTimer = setInterval(poll, 1500)
}

// Tear the poll down with the modal. Clearing curJob as well makes poll() a no-op
// even if one call was already in flight when the modal closed.
function closeJobLog() {
  logOpen.value = false
  curJob.value = null
  if (logTimer) clearInterval(logTimer)
  logTimer = null
}

async function poll() {
  if (!curJob.value) return
  try {
    const j = await getStackJob(curJob.value)
    logText.value = j.log + (j.running ? '\n⏳…' : '')
    if (!j.running) {
      clearInterval(logTimer)
      logTimer = null
      refresh()
    }
  } catch (e) {
    // Append rather than swallow: a failing poll used to leave the modal on
    // "Loading…" forever with no indication that the job status was unreadable.
    logText.value = `${logText.value === t('common.loading') ? '' : logText.value || ''}\n⚠ ${e.message || e}`.trim()
  }
}

onMounted(() => {
  loadManaged()
  loadCatalog()
  refresh()
  // startVisibleInterval also refreshes the moment the tab becomes visible
  // again, so returning to the page does not show up-to-15s-stale data.
  timer = startVisibleInterval(() => {
    if (tab.value === 'managed') return loadManaged(false)
  }, 15000)
})
onUnmounted(() => {
  if (timer) timer()
  if (logTimer) clearInterval(logTimer)
  // Stop the scheduled poll and invalidate any request already in flight so a
  // late response cannot update this unmounted page or schedule another poll.
  stopCfLoginPolling()
})


// Escape dismisses each dialog, focus returns to whatever opened it, and Tab
// cannot wander to the page behind the overlay.
useDismissable(installTpl, () => { installTpl.value = null }, installPanel)
useDismissable(logOpen, () => { logOpen.value = false }, logPanel)

useDismissable(detail, () => { closeDetail() }, detailPanel)
</script>

<style scoped>
.apps-page {
  color: var(--txt);
}

.hint-line {
  margin: 0 0 12px;
  color: var(--sub);
  font-size: 12px;
  line-height: 1.55;
}

.apps-toolbar {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  align-items: center;
  margin-bottom: 10px;
}

.apps-toolbar .search {
  min-width: 200px;
  flex: 1 1 200px;
  max-width: 320px;
}

.cat-select {
  min-width: 140px;
}

.chk {
  font-size: 12px;
  color: var(--sub);
  display: inline-flex;
  align-items: center;
  gap: 5px;
  white-space: nowrap;
  cursor: pointer;
  user-select: none;
}

.cat-pills {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin: 0 0 14px;
}

/* Do NOT use global .pill (header status chips — light text on dark chrome) */
.cat-pill {
  font-size: 12px;
  padding: 6px 12px;
  border-radius: var(--radius-pill);
  border: 1px solid var(--line);
  background: var(--btn);
  color: var(--txt) !important;
  cursor: pointer;
  line-height: 1.3;
  white-space: nowrap;
  font-weight: 500;
  transition: border-color .12s, background .12s, box-shadow .12s;
}

.cat-pill:hover {
  border-color: var(--accent);
  filter: none;
  background: color-mix(in srgb, var(--accent) 10%, var(--btn));
  color: var(--txt) !important;
}

.cat-pill.active {
  border-color: var(--accent);
  background: color-mix(in srgb, var(--accent) 18%, var(--card));
  color: var(--txt) !important;
  font-weight: 700;
  box-shadow: inset 0 0 0 1px color-mix(in srgb, var(--accent) 35%, transparent);
}

.app-card.native {
  border-color: color-mix(in srgb, var(--ok) 35%, var(--line));
}

/* Own grid — avoid global 220px clamp + nowrap .detail/.name */
.app-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(min(100%, 300px), 1fr));
  gap: 12px;
  align-items: stretch;
}

.app-card {
  display: flex;
  flex-direction: column;
  gap: 0;
  background: var(--card);
  color: var(--txt);
  border: 1px solid var(--line);
  border-radius: var(--radius, 8px);
  padding: 14px 14px 12px;
  min-width: 0;
  max-width: 100%;
  box-shadow: var(--card-shadow, none);
  overflow: hidden;
  transition: border-color .15s, box-shadow .15s, transform .1s;
}

.app-card:hover {
  border-color: color-mix(in srgb, var(--accent) 40%, var(--line));
  transform: translateY(-1px);
}

.app-card.featured {
  border-color: color-mix(in srgb, var(--accent) 45%, var(--line));
  box-shadow: 0 0 0 1px color-mix(in srgb, var(--accent) 18%, transparent);
}

.app-card.installed {
  opacity: 1;
}

.app-head {
  /* Stack title over badges so the name always gets the full card width.
     (Side-by-side let a 3–4 chip badge cluster squeeze long names into an
      ellipsis, e.g. "FileBrows er（原生…".) */
  display: flex;
  flex-direction: column;
  align-items: stretch;
  gap: 6px;
  margin-bottom: 8px;
}

.app-title {
  margin: 0;
  font-size: 15px;
  font-weight: 700;
  line-height: 1.35;
  color: var(--txt);
  min-width: 0;
  padding-top: 1px;
  /* Full width now → most names fit on one line; still clamp to 2 as a guard */
  white-space: normal;
  overflow-wrap: anywhere;
  word-break: break-word;
  display: -webkit-box;
  -webkit-box-orient: vertical;
  -webkit-line-clamp: 2;
  line-clamp: 2;
  overflow: hidden;
}

/* Uniform chips — same height/padding/radius for 原生/推荐/已装 */
.app-badges {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
  flex: 0 0 auto;
  justify-content: flex-start;
  align-items: center;
}

.chip {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  box-sizing: border-box;
  height: 20px;
  min-width: 2.2em;
  padding: 0 7px;
  border-radius: var(--radius-sm);
  font-size: 11px;
  font-weight: 600;
  line-height: 1;
  white-space: nowrap;
  border: 1px solid var(--line);
  background: var(--btn);
  color: var(--txt);
}

.chip-native {
  background: color-mix(in srgb, var(--ok) 16%, var(--card));
  border-color: color-mix(in srgb, var(--ok) 40%, var(--line));
  color: var(--ok);
}

.chip-docker {
  background: color-mix(in srgb, #2496ed 12%, var(--card));
  border-color: color-mix(in srgb, #2496ed 35%, var(--line));
  color: #1a6fb0;
}

.chip-feat {
  background: color-mix(in srgb, var(--accent) 14%, var(--card));
  border-color: color-mix(in srgb, var(--accent) 40%, var(--line));
  color: var(--accent-hover, var(--accent));
}

.chip-ok {
  background: color-mix(in srgb, var(--ok) 16%, var(--card));
  border-color: color-mix(in srgb, var(--ok) 40%, var(--line));
  color: var(--ok);
}

.chip-muted {
  background: var(--btn);
  border-color: var(--line);
  color: var(--sub);
}

[data-theme="nord"] .chip-docker,
[data-theme="glass"] .chip-docker,
[data-theme="unraid-dark"] .chip-docker,
[data-theme="system"] .chip-docker,
[data-theme="mono"] .chip-docker {
  color: #7ec8ff;
}

.app-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 5px;
  margin-bottom: 8px;
}

.cat-tag {
  font-size: 11px;
  padding: 2px 7px;
  border-radius: var(--radius-sm);
  background: color-mix(in srgb, var(--accent) 16%, var(--card));
  color: var(--txt);
  border: 1px solid color-mix(in srgb, var(--accent) 30%, var(--line));
  font-weight: 600;
  line-height: 1.4;
}

.tag {
  font-size: 11px;
  padding: 2px 7px;
  border-radius: var(--radius-sm);
  background: var(--btn);
  color: var(--sub);
  border: 1px solid var(--line);
  line-height: 1.4;
}

.app-desc {
  margin: 0 0 8px;
  font-size: 13px;
  line-height: 1.5;
  color: var(--txt);
  opacity: 0.88;
  flex: 1 1 auto;
  min-height: 3.9em;
  max-height: 5.1em;
  white-space: normal;
  overflow-wrap: anywhere;
  word-break: break-word;
  display: -webkit-box;
  -webkit-box-orient: vertical;
  -webkit-line-clamp: 3;
  line-clamp: 3;
  overflow: hidden;
}

.app-ports,
.app-images {
  font-size: 11px;
  line-height: 1.4;
  color: var(--sub);
  margin: 0 0 4px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  max-width: 100%;
}

.app-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin-top: auto;
  padding-top: 10px;
  border-top: 1px solid var(--line);
  align-items: center;
}

.app-actions button,
.app-actions .btn {
  font-size: 12px;
  white-space: nowrap;
  flex: 0 0 auto;
}

.chip-inline {
  height: 28px;
  padding: 0 10px;
  font-size: 12px;
}

/* Modal */
.install-modal {
  max-height: 85vh;
  max-width: min(560px, 94vw);
  overflow: auto;
  color: var(--txt);
  background: var(--card);
}

.modal-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  margin-bottom: 10px;
}

.modal-title {
  margin: 0;
  font-size: 16px;
  font-weight: 700;
  color: var(--txt);
  line-height: 1.35;
  white-space: normal;
  word-break: break-word;
}

.modal-desc {
  margin: 0 0 10px;
  font-size: 13px;
  line-height: 1.5;
  color: var(--sub);
  white-space: normal;
}

.path-line {
  font-size: 11px;
  color: var(--sub);
  margin: 0 0 12px;
  word-break: break-all;
}

.form-grid {
  display: grid;
  grid-template-columns: minmax(100px, 130px) 1fr;
  gap: 10px 12px;
  align-items: start;
  font-size: 13px;
}

.form-label {
  color: var(--sub);
  padding-top: 8px;
  line-height: 1.35;
  word-break: break-word;
}

.form-field input {
  width: 100%;
  box-sizing: border-box;
}

.field-help {
  font-size: 11px;
  color: var(--sub);
  margin-top: 3px;
  line-height: 1.4;
}

.notes {
  font-size: 12px;
  color: var(--txt);
  background: color-mix(in srgb, var(--warn) 12%, var(--card));
  border-left: 3px solid var(--warn);
  padding: 8px 10px;
  margin: 0 0 10px;
  white-space: pre-wrap;
  line-height: 1.5;
  word-break: break-word;
}

.install-log {
  margin-top: 12px;
  max-height: 220px;
  overflow: auto;
  font-size: 12px;
  line-height: 1.45;
  white-space: pre-wrap;
  word-break: break-word;
  color: var(--txt);
  background: var(--bg);
  border: 1px solid var(--line);
  border-radius: 6px;
  padding: 10px;
}

.open-url {
  margin-top: 10px;
  display: inline-block;
  word-break: break-all;
}

/* Size and colour come from the global .meta-count. */
.meta-count { white-space: nowrap; }

.managed-table-wrap {
  overflow: auto;
  border: 1px solid var(--line);
  border-radius: var(--radius, 8px);
  background: var(--card);
}

.managed-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
}

.managed-table th {
  text-align: left;
  padding: 10px 12px;
  background: var(--table-head);
  color: var(--sub);
  font-size: 11px;
  font-weight: 700;
  border-bottom: 1px solid var(--line);
  white-space: nowrap;
}

.managed-table td {
  padding: 10px 12px;
  border-bottom: 1px solid var(--line);
  vertical-align: top;
  color: var(--txt);
}

.managed-table tbody tr {
  cursor: pointer;
}

.managed-table tbody tr:hover {
  background: var(--table-hover);
}

.sub-line {
  font-size: 11px;
  color: var(--sub);
  margin-top: 2px;
  line-height: 1.35;
}

.ports-cell, .path-cell {
  max-width: 200px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-size: 11px;
}

.actions-cell {
  min-width: 220px;
  max-width: 340px;
}

.act-row {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
  align-items: center;
}

.act-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  height: 26px;
  padding: 0 9px;
  font-size: 12px;
  font-weight: 600;
  border-radius: var(--radius-sm);
  border: 1px solid var(--btn-border);
  background: var(--btn);
  color: var(--txt);
  cursor: pointer;
  white-space: nowrap;
  text-decoration: none;
  line-height: 1;
}

.act-btn:hover {
  border-color: var(--accent);
}

.act-btn.primary {
  background: var(--accent);
  border-color: var(--accent);
  color: #fff;
}

.act-btn.danger {
  background: color-mix(in srgb, var(--down) 12%, var(--card));
  border-color: color-mix(in srgb, var(--down) 45%, var(--line));
  color: var(--down);
  font-weight: 700;
}

.act-btn.link {
  color: var(--accent-hover, var(--accent));
}

.act-btn:disabled {
  opacity: 0.4;
  cursor: not-allowed;
}

.auto-toggle {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
  color: var(--txt);
  cursor: pointer;
  user-select: none;
  white-space: nowrap;
}

.auto-toggle input {
  width: 15px;
  height: 15px;
  accent-color: var(--ok);
}

.auto-group .section-title {
  margin: 8px 0 8px;
  font-size: 14px;
}

.policy-select {
  font-size: 11px;
  max-width: 140px;
}

.hint-line {
  margin: 0 0 12px;
  color: var(--sub);
  font-size: 12px;
  line-height: 1.5;
}

.empty-row {
  text-align: center;
  color: var(--sub);
  padding: 24px !important;
}

/* Detail drawer */
.drawer-bg {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.4);
  z-index: 80;
  display: flex;
  justify-content: flex-end;
}

.drawer {
  width: min(480px, 100vw);
  max-width: 100%;
  height: 100%;
  background: var(--card);
  color: var(--txt);
  border-left: 1px solid var(--line);
  overflow: auto;
  padding: 16px 18px 40px;
  box-sizing: border-box;
}

.drawer-head {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 12px;
  margin-bottom: 12px;
}

.drawer-title {
  margin: 0;
  font-size: 18px;
  font-weight: 700;
  line-height: 1.3;
  word-break: break-word;
}

.drawer-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin-bottom: 16px;
  padding-bottom: 12px;
  border-bottom: 1px solid var(--line);
}

.drawer-sec {
  margin-bottom: 16px;
}

.drawer-sec h3 {
  margin: 0 0 8px;
  font-size: 13px;
  font-weight: 700;
  color: var(--sub);
}

.credential-sec {
  padding: 10px;
  border: 1px solid var(--line);
  border-radius: 6px;
  background: var(--bg);
}
.credential-title { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
.credential-title h3 { margin: 0; }
.credential-hint { margin: 5px 0 9px; line-height: 1.45; }
.credential-grid { display: grid; grid-template-columns: 92px minmax(0, 1fr); gap: 7px 9px; align-items: center; }
.credential-grid label { color: var(--sub); font-size: 11px; }
.credential-grid input, .credential-grid textarea { width: 100%; box-sizing: border-box; }
.credential-grid textarea { resize: vertical; min-height: 48px; }
.credential-password-input { display: grid; grid-template-columns: minmax(0, 1fr) auto auto; gap: 4px; }
.credential-password-input button { padding: 4px 7px; font-size: 10px; }
.credential-security { margin: 8px 0; line-height: 1.4; }
.credential-actions { display: flex; flex-wrap: wrap; gap: 6px; }

.kv-list .k {
  display: inline-block;
  min-width: 72px;
  color: var(--sub);
  margin-right: 8px;
}

.kv-list div {
  margin-bottom: 4px;
  font-size: 12px;
  word-break: break-all;
  line-height: 1.4;
}

.plain-list {
  margin: 0;
  padding-left: 18px;
  font-size: 12px;
  line-height: 1.5;
  word-break: break-all;
}

.mini-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 11px;
}

.mini-table th,
.mini-table td {
  text-align: left;
  padding: 5px 6px;
  border-bottom: 1px solid var(--line);
  word-break: break-all;
}

.env-pre {
  font-size: 11px;
  max-height: 160px;
  overflow: auto;
  background: var(--bg);
  border: 1px solid var(--line);
  border-radius: 6px;
  padding: 8px;
  white-space: pre-wrap;
  word-break: break-all;
  margin: 0;
}

@media (max-width: 520px) {
  .app-grid {
    grid-template-columns: 1fr;
  }
  .form-grid {
    grid-template-columns: 1fr;
  }
  .form-label {
    padding-top: 0;
  }
  .drawer {
    width: 100%;
  }
  .credential-grid { grid-template-columns: 1fr; gap: 4px; }
  .credential-grid label { margin-top: 4px; }
  .credential-password-input { grid-template-columns: 1fr 1fr; }
  .credential-password-input input { grid-column: 1 / -1; }
}
</style>
