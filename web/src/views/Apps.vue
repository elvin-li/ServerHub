<template>
  <div class="apps-page">
    <div class="page-title">
      <h1>{{ t('apps.title') }}</h1>
      <span class="meta">
        {{ t('apps.meta') }}
        · {{ finiteN(asRecord(overview).total, asArray(catalog).length) }} {{ t('apps.templates') }}
        · {{ finiteN(asRecord(overview).installed, 0) }} {{ t('apps.installed_n') }}
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
        <!-- role=status: the count is the only feedback the search box, category
             select and toggles give, and it changed silently for a screen
             reader. Same pattern as the Services filter count. -->
        <span class="meta-count" role="status">{{ finiteN(asArray(filtered).length) }} / {{ finiteN(asArray(catalog).length) }}</span>
        <select v-model="cat" class="cat-select" :aria-label="t('apps.filter_category')">
          <option v-for="c in asArray(categories)" :key="finiteText(asRecord(c).id)" :value="asRecord(c).id">
            {{ catLabel(asRecord(c).id) }}{{ countLabel(asRecord(c).id) }}
          </option>
        </select>
        <label class="chk"><input type="checkbox" v-model="onlyFeatured" /> {{ t('apps.featured_only') }}</label>
        <label class="chk"><input type="checkbox" v-model="hideInstalled" /> {{ t('apps.hide_installed') }}</label>
        <button type="button" @click="loadCatalog">{{ t('common.refresh') }}</button>
        <button type="button" @click="openRemoteModal">{{ t('catalog_remote.title') }}</button>
        <button type="button" :disabled="remoteBusy" @click="checkRemoteUpdates">
          {{ remoteBusy ? t('catalog_remote.checking') : t('catalog_remote.check_updates') }}
        </button>
        <router-link class="btn" to="/compose">{{ t('apps.compose_editor') }}</router-link>
        <router-link class="btn" to="/containers">{{ t('nav.docker') }}</router-link>
      </div>

      <div class="cat-pills">
        <button
          v-for="c in asArray(quickCats)"
          :key="finiteText(asRecord(c).id)"
          type="button"
          class="cat-pill"
          :class="{ active: cat === asRecord(c).id }"
          :aria-pressed="cat === asRecord(c).id"
          @click="cat = asRecord(c).id"
        >{{ catLabel(asRecord(c).id) }}{{ countLabel(asRecord(c).id) }}</button>
      </div>

      <!-- Above the grid: on a failed refresh the cards below are the *stale*
           listing, and the failure banner used to render underneath them —
           off-screen on any populated catalog, so the page looked healthy
           while showing old data. Same placement the Managed tab uses.
           role=status on the placeholders: the empty/no-match split is the
           grid's only answer to a filter change and it changed silently for
           a screen reader (the same treatment the filter count carries). -->
      <LoadFailure v-if="catalogError" :detail="catalogError" :retry="loadCatalog" :busy="busy" />
      <div v-else-if="!catalogLoaded" class="placeholder" role="status">{{ t('common.loading') }}</div>
      <div v-else-if="!asArray(filtered).length" class="placeholder" role="status">
        {{ asArray(catalog).length ? t('common.no_match') : t('apps.empty') }}
      </div>
      <div class="app-grid">
        <article
          v-for="tpl in asArray(filtered)"
          :key="finiteText(asRecord(tpl).id)"
          class="app-card"
          :class="{
            featured: asRecord(tpl).featured,
            installed: asRecord(tpl).installed,
            native: asRecord(tpl).kind === 'native',
          }"
        >
          <header class="app-head">
            <h3 class="app-title" :title="finiteText(asRecord(tpl).name)">{{ finiteText(asRecord(tpl).name) }}</h3>
            <div class="app-badges">
              <span class="chip" :class="asRecord(tpl).kind === 'native' ? 'chip-native' : 'chip-docker'">
                {{ asRecord(tpl).kind === 'native' ? t('apps.kind_native') : t('apps.kind_docker') }}
              </span>
              <span
                v-if="asRecord(tpl).source === 'remote'"
                class="chip chip-remote"
                :title="t('catalog_remote.badge_title')"
              >{{ t('catalog_remote.badge') }}{{ finiteText(asRecord(tpl).remote_version, '') ? ` ${finiteText(asRecord(tpl).remote_version)}` : '' }}</span>
              <span v-if="asRecord(tpl).featured" class="chip chip-feat">{{ t('apps.featured') }}</span>
              <span v-if="asRecord(tpl).installed" class="chip chip-ok">{{ t('apps.installed') }}</span>
              <span v-if="asRecord(tpl).running" class="chip chip-ok">{{ t('common.running') }}</span>
            </div>
          </header>

          <div class="app-meta">
            <span class="cat-tag">{{ catLabel(asRecord(tpl).category) }}</span>
            <span v-for="tg in asArray(asRecord(tpl).tags).slice(0, 3)" :key="finiteText(tg)" class="tag">{{ finiteText(tg) }}</span>
          </div>

          <p class="app-desc">{{ finiteText(asRecord(tpl).desc) }}</p>

          <div v-if="asArray(asRecord(tpl).ports).length" class="app-ports mono">
            ports: {{ asArray(asRecord(tpl).ports).map(p => finiteText(p, '')).filter(Boolean).join(', ') }}
          </div>
          <div v-if="asArray(asRecord(tpl).images).length" class="app-images mono" :title="asArray(asRecord(tpl).images).map(im => finiteText(im, '')).filter(Boolean).join(', ')">
            {{ asArray(asRecord(tpl).images).map(im => finiteText(im, '')).filter(Boolean).slice(0, 2).join(', ') }}{{ asArray(asRecord(tpl).images).length > 2 ? '…' : '' }}
          </div>
          <div v-if="asRecord(tpl).package" class="app-ports mono">brew: {{ finiteText(asRecord(tpl).package) }}</div>
          <div v-if="catalogOpenUrl(tpl)" class="app-ports mono">{{ catalogOpenUrl(tpl) }}</div>

          <footer class="app-actions">
            <button
              v-if="!asRecord(tpl).installed"
              type="button"
              class="primary"
              :disabled="busy"
              @click="openInstall(tpl)"
            >
              {{ asRecord(tpl).kind === 'native' ? t('apps.deploy_native') : t('apps.deploy') }}
            </button>
            <template v-else>
              <button
                type="button"
                class="danger"
                :disabled="busy"
                @click="doUninstall(tpl)"
              >{{ t('apps.uninstall') }}</button>
              <button
                v-if="asRecord(tpl).kind === 'docker' || (asRecord(tpl).kind === 'native' && asRecord(tpl).running != null)"
                type="button"
                :disabled="busy"
                @click="goManage(tpl)"
              >{{ t('apps.manage') }}</button>
              <button
                v-if="asRecord(tpl).path && asRecord(tpl).kind !== 'native'"
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
            <button
              v-if="asRecord(tpl).source === 'remote'"
              type="button"
              :disabled="busy || remoteBusy"
              @click="restoreBuiltin(tpl)"
            >{{ t('catalog_remote.restore_builtin') }}</button>
          </footer>
        </article>
      </div>
    </template>

    <!-- Managed inventory: native + docker + launchd + vm -->
    <template v-else-if="tab === 'managed'">
      <div class="toolbar apps-toolbar">
        <input v-model="mq" type="text" class="search" :placeholder="t('apps.managed_search')"  :aria-label="t('apps.managed_search')"/>
        <!-- role=status: the count is the only feedback the search box and kind
             select give, and it changed silently for a screen reader. Same
             pattern as the Services filter count. -->
        <span class="meta-count" role="status">{{ finiteN(asArray(filteredManaged).length) }} / {{ finiteN(asArray(asRecord(managed).items).length) }}</span>
        <select v-model="mkind" class="cat-select" :aria-label="t('apps.filter_kind')">
          <option value="all">{{ t('apps.cat_all') }}</option>
          <option value="native">{{ t('apps.kind_native') }}</option>
          <option value="docker">{{ t('apps.kind_docker') }}</option>
          <option value="launchd">{{ t('apps.kind_launchd') }}</option>
          <option value="vm">{{ t('apps.kind_vm') }}</option>
        </select>
        <button type="button" class="primary" @click="loadManaged(true)" :disabled="loading">{{ t('common.refresh') }}</button>
        <button type="button" @click="tab = 'catalog'">{{ t('apps.browse_catalog') }}</button>
        <!-- role=status: the breakdown is Refresh's only answer and it changed
             silently for a screen reader — the same treatment the filter count
             beside it (and every sibling .meta-count) already carries. -->
        <span class="meta-count" role="status" v-if="asRecord(managed).counts">
          {{ finiteN(asRecord(asRecord(managed).counts).total) }} ·
          {{ t('apps.kind_native') }} {{ finiteN(asRecord(asRecord(managed).counts).native) }} ·
          Docker {{ finiteN(asRecord(asRecord(managed).counts).docker) }} ·
          {{ t('apps.kind_launchd') }} {{ finiteN(asRecord(asRecord(managed).counts).launchd, 0) }} ·
          VM {{ finiteN(asRecord(asRecord(managed).counts).vm) }} ·
          {{ t('common.running') }} {{ finiteN(asRecord(asRecord(managed).counts).running) }}
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
              <th class="col-hide-m">{{ t('apps.col_kind') }}</th>
              <th>{{ t('common.status') }}</th>
              <th class="col-hide-m">{{ t('apps.col_ports') }}</th>
              <th class="col-hide-m">{{ t('apps.col_autostart') }}</th>
              <th class="col-hide-m">{{ t('apps.col_path') }}</th>
              <th>{{ t('common.actions') }}</th>
            </tr>
          </thead>
          <tbody>
            <!-- The row keeps its click shortcut, but not role="button"/tabindex:
                 it holds the autostart switch and the whole action button row, and
                 a control may not contain other controls (ARIA nested-interactive).
                 It also duplicated the tab stop the "Detail" button in the actions
                 cell already provides, which is the keyboard path to the same
                 openDetail(it). -->
            <tr v-for="it in asArray(filteredManaged)" :key="finiteText(asRecord(it).id)" @click="openDetail(it)">
              <td>
                <strong>{{ finiteText(asRecord(it).name) }}</strong>
                <div class="sub-line" v-if="asRecord(it).status_text">{{ finiteText(asRecord(it).status_text) }}</div>
                <div class="show-m sub-line">{{ kindLabel(asRecord(it).kind) }}</div>
                <div v-if="finiteText(asRecord(it).ports_summary, '') || asArray(asRecord(it).ips).map(n => finiteText(n, '')).filter(Boolean).join(', ')" class="show-m sub-line mono">{{ finiteText(asRecord(it).ports_summary, '') || asArray(asRecord(it).ips).map(n => finiteText(n, '')).filter(Boolean).join(', ') }}</div>
                <div class="show-m sub-line mono">{{ finiteText(asRecord(it).path, '') || finiteText(asRecord(it).package, '') || finiteText(asRecord(it).backend, '') }}</div>
                <div class="show-m" @click.stop>
                  <!-- Named after the app: a column of switches all announced as
                       "Autostart" cannot be told apart in a form-controls
                       listing — same fix as the Scheduler enable toggles. -->
                  <MacSwitch
                    v-if="asRecord(it).autostart != null || asRecord(it).kind === 'docker' || asRecord(it).autostart_id"
                    :checked="!!asRecord(it).autostart"
                    :disabled="busy || asRecord(it).kind === 'vm'"
                    :aria-label="t('apps.autostart_name', { name: finiteText(asRecord(it).name, '') || finiteText(asRecord(it).id) })"
                    :title="finiteText(asRecord(it).autostart_detail, '')"
                    @click.stop
                    @change="toggleManagedAutostart(it, $event)"
                  />
                </div>
              </td>
              <td class="col-hide-m">
                <span class="chip" :class="kindChip(asRecord(it).kind)">{{ kindLabel(asRecord(it).kind) }}</span>
              </td>
              <td>
                <span class="chip" :class="asRecord(it).state === 'ok' ? 'chip-ok' : (asRecord(it).state === 'warn' ? 'chip-feat' : 'chip-muted')">
                  {{ stateLabel(asRecord(it).state) }}
                </span>
              </td>
              <td class="mono ports-cell col-hide-m">{{ finiteText(asRecord(it).ports_summary, '') || asArray(asRecord(it).ips).map(n => finiteText(n, '')).filter(Boolean).join(', ') }}</td>
              <td class="col-hide-m" @click.stop>
                <MacSwitch
                  v-if="asRecord(it).autostart != null || asRecord(it).kind === 'docker' || asRecord(it).autostart_id"
                  :checked="!!asRecord(it).autostart"
                  :disabled="busy || asRecord(it).kind === 'vm'"
                  :aria-label="t('apps.autostart_name', { name: finiteText(asRecord(it).name, '') || finiteText(asRecord(it).id) })"
                  :title="finiteText(asRecord(it).autostart_detail, '')"
                  @click.stop
                  @change="toggleManagedAutostart(it, $event)"
                />
                <span v-else class="sub-line">—</span>
              </td>
              <td class="mono path-cell col-hide-m" :title="finiteText(asRecord(it).path, '') || finiteText(asRecord(it).package, '')">{{ finiteText(asRecord(it).path, '') || finiteText(asRecord(it).package, '') || finiteText(asRecord(it).backend) }}</td>
              <td class="actions-cell" @click.stop>
                <div class="act-row">
                  <!-- A native <button> activates on Enter/Space and sits in the
                       tab order by itself; the copied role/tabindex/keydown set
                       belongs on the non-button hotspots (Services problem chips),
                       not here, where it double-declared what the element is. -->
                  <button type="button" class="act-btn" @click="openDetail(it)">{{ t('apps.detail') }}</button>
                  <button v-if="canAct(it, 'start')" type="button" class="act-btn primary" :disabled="busy" @click="doManagedAction(it, 'start')">{{ t('apps.act_start') }}</button>
                  <button v-if="canAct(it, 'stop')" type="button" class="act-btn" :disabled="busy" @click="doManagedAction(it, 'stop')">{{ t('apps.act_stop') }}</button>
                  <button v-if="canAct(it, 'restart')" type="button" class="act-btn hide-m" :disabled="busy" @click="doManagedAction(it, 'restart')">{{ t('apps.act_restart') }}</button>
                  <button v-if="canAct(it, 'logs') || asRecord(it).kind === 'docker' || asRecord(it).kind === 'native' || asRecord(it).kind === 'launchd'" type="button" class="act-btn" @click="openManagedLogs(it)">{{ t('apps.logs') }}</button>
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
            <!-- Same split: a kind/search filter that matches nothing must not
                 claim the host has no managed apps. -->
            <tr v-if="!asArray(filteredManaged).length && !managedError">
              <td colspan="7" class="empty-row">{{ asArray(asRecord(managed).items).length ? t('common.no_match') : t('apps.managed_empty') }}</td>
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
        <!-- role=status: these counts are Refresh's and Run-now's only answer
             and changed silently for a screen reader — same treatment as the
             managed-tab breakdown and every sibling .meta-count. -->
        <span class="meta-count" role="status" v-if="autostart.counts">
          {{ t('apps.auto_on') }} {{ finiteN(autostart.counts.autostart_on) }} ·
          {{ t('apps.auto_off') }} {{ finiteN(autostart.counts.autostart_off) }} ·
          brew {{ finiteN(autostart.counts.brew) }} ·
          Docker {{ finiteN(autostart.counts.docker) }} ·
          LaunchAgent {{ finiteN(autostart.counts.launchd) }}
        </span>
      </div>
      <p class="hint-line">{{ t('apps.autostart_hint') }}</p>
      <LoadFailure v-if="autostartError" :detail="autostartError" :retry="() => loadAutostart(true)" :busy="loading" />
      <div v-else-if="!autostartLoaded" class="hint-line">{{ t('common.loading') }}</div>
      <template v-else>
      <div v-for="grp in asArray(autostartGroups)" :key="finiteText(grp)" class="auto-group">
        <h2 class="section-title">{{ finiteText(grp) }}</h2>
        <div class="managed-table-wrap" style="margin-bottom:14px">
          <table class="managed-table">
            <thead>
              <tr>
                <th>{{ t('common.name') }}</th>
                <th>{{ t('common.status') }}</th>
                <th>{{ t('apps.col_autostart') }}</th>
                <th class="col-hide-m">{{ t('apps.col_detail') }}</th>
                <th>{{ t('common.actions') }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="it in asArray(autostartByGroup[grp])" :key="finiteText(asRecord(it).id)">
                <td>
                  <strong>{{ finiteText(asRecord(it).name) }}</strong>
                  <div class="sub-line mono" v-if="asRecord(it).program">{{ finiteText(asRecord(it).program) }}</div>
                  <div class="show-m sub-line mono">{{ finiteText(asRecord(it).detail, '') || finiteText(asRecord(it).plist, '') }}</div>
                  <div class="show-m sub-line">
                    {{ asRecord(it).running ? t('common.running') : t('common.stopped') }}{{ finiteText(asRecord(it).policy, '') ? ' · ' + finiteText(asRecord(it).policy) : '' }}
                  </div>
                </td>
                <td class="col-hide-m">
                  <span class="chip" :class="asRecord(it).running ? 'chip-ok' : 'chip-muted'">
                    {{ asRecord(it).running ? t('common.running') : t('common.stopped') }}
                  </span>
                  <span v-if="finiteText(asRecord(it).policy, '')" class="sub-line mono"> {{ finiteText(asRecord(it).policy) }}</span>
                </td>
                <td>
                  <MacSwitch
                    :checked="!!asRecord(it).autostart"
                    :disabled="busy"
                    :aria-label="t('apps.autostart_name', { name: finiteText(asRecord(it).name, '') || finiteText(asRecord(it).id) })"
                    @change="setAutostartItem(it, $event)"
                  />
                </td>
                <td class="mono path-cell col-hide-m" :title="finiteText(asRecord(it).detail, '') || finiteText(asRecord(it).plist)">{{ finiteText(asRecord(it).detail, '') || finiteText(asRecord(it).plist) }}</td>
                <td class="actions-cell">
                  <div class="act-row" v-if="asRecord(it).kind === 'docker'">
                    <select
                      class="policy-select"
                      :value="finiteText(asRecord(it).policy, '') || 'no'"
                      :disabled="busy"
                      :aria-label="t('apps.policy_name', { name: finiteText(asRecord(it).name, '') || finiteText(asRecord(it).id) })"
                      @change="setDockerPolicy(it, $event.target.value)"
                    >
                      <option value="no">no</option>
                      <option value="unless-stopped">unless-stopped</option>
                      <option value="always">always</option>
                      <option value="on-failure">on-failure</option>
                    </select>
                  </div>
                  <span v-else class="sub-line">{{ finiteText(asRecord(it).kind) }}</span>
                </td>
              </tr>
              <tr v-if="!asArray(autostartByGroup[grp]).length">
                <td colspan="5" class="empty-row">—</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
      </template>
    </template>

    <!-- Detail drawer -->
    <div v-if="detail" class="drawer-bg" @click.self="closeDetail" role="presentation">
      <aside ref="detailPanel" class="drawer" role="dialog" aria-modal="true" aria-labelledby="apps-detail-title" tabindex="-1">
        <div class="drawer-head">
          <div>
            <h2 id="apps-detail-title" class="drawer-title">{{ finiteText(asRecord(detail).name) }}</h2>
            <div class="app-badges" style="margin-top:6px">
              <span class="chip" :class="kindChip(asRecord(detail).kind)">{{ kindLabel(asRecord(detail).kind) }}</span>
              <span class="chip" :class="asRecord(detail).state === 'ok' ? 'chip-ok' : 'chip-muted'">{{ stateLabel(asRecord(detail).state) }}</span>
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
            {{ asRecord(credential).can_apply ? t('apps.credential_apply_hint') : t('apps.credential_store_hint') }}
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
          <div v-if="credentialError" class="placeholder" role="alert" style="margin-bottom:8px">
            <div>{{ t('apps.credential_load_failed') }}</div>
            <div class="sub mono" style="margin-top:4px">{{ finiteText(credentialError) }}</div>
          </div>
          <div class="credential-actions">
            <button
              v-if="asRecord(credential).can_apply"
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
        <section class="drawer-sec" v-if="asRecord(detail).source_id === 'native-cloudflared' || asRecord(detail).cloudflared">
          <h3>{{ t('apps.cf_title') }}</h3>
          <p class="sub-line" style="margin-bottom:10px">
            {{ t('apps.cf_hint') }}
            <a href="https://one.dash.cloudflare.com/" target="_blank" rel="noopener">{{ t('apps.cf_zero_trust') }}</a>
            {{ t('apps.cf_hint_tail') }}
          </p>
          <div class="app-badges" style="margin-bottom:10px">
            <span class="chip" :class="asRecord(cfStatus).logged_in ? 'chip-ok' : 'chip-muted'">
              {{ asRecord(cfStatus).logged_in ? t('apps.cf_signed_in') : t('apps.cf_signed_out') }}
            </span>
            <span class="chip" :class="asRecord(cfStatus).running ? 'chip-ok' : 'chip-muted'">
              {{ asRecord(cfStatus).running ? t('apps.cf_tunnel_running') : t('apps.cf_tunnel_stopped') }}
            </span>
            <span v-if="asRecord(cfStatus).has_token && asRecord(cfStatus).token_ok === false" class="chip chip-warn">
              {{ t('apps.cf_token_invalid') }}
            </span>
            <span v-else-if="!asRecord(cfStatus).running && asRecord(cfStatus).crash_loop" class="chip chip-warn">
              {{ t('apps.cf_crash_loop') }}
            </span>
            <span v-if="asRecord(cfStatus).active_tunnel" class="chip chip-muted mono">{{ finiteText(asRecord(cfStatus).active_tunnel) }}</span>
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

          <div v-if="asRecord(cfStatus).login_url" class="notes" role="status" style="margin-bottom:10px;word-break:break-all">
            {{ t('apps.cf_open_link') }}
            <a :href="finiteText(asRecord(cfStatus).login_url, '')" target="_blank" rel="noopener">{{ finiteText(asRecord(cfStatus).login_url) }}</a>
            <div class="sub-line" style="margin-top:6px">{{ t('apps.cf_after_auth') }}</div>
          </div>

          <div class="form-grid" style="margin-bottom:10px">
            <label class="form-label">{{ t('apps.cf_existing_tunnel') }}</label>
            <div class="form-field">
              <select v-model="cfSelectedTunnel" :disabled="cfBusy" style="width:100%;padding:8px;border-radius:8px" :aria-label="t('apps.cf_existing_tunnel')">
                <option value="">{{ t('apps.cf_select_ph') }}</option>
                <option v-for="tn in asArray(asRecord(cfStatus).tunnels)" :key="finiteText(asRecord(tn).id)" :value="asRecord(tn).name">
                  {{ finiteText(asRecord(tn).name) }} ({{ String(finiteText(asRecord(tn).id)).slice(0, 8) }}…){{ asRecord(tn).active ? ` · ${t('apps.cf_connected')}` : '' }}
                </option>
              </select>
              <!-- Error vs empty: a failed tunnel-list fetch used to render as
                   "No tunnels found", silently hiding the failure. -->
              <div class="field-help" v-if="!asArray(asRecord(cfStatus).tunnels).length" role="status">
                <template v-if="asRecord(cfStatus).logged_in && finiteText(asRecord(cfStatus).tunnels_error, '')">{{ t('apps.cf_tunnels_failed') }} {{ finiteText(asRecord(cfStatus).tunnels_error, '') }}</template>
                <template v-else>{{ asRecord(cfStatus).logged_in ? t('apps.cf_no_tunnels') : t('apps.cf_login_to_list') }}</template>
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
          <pre v-if="cfMsg" class="install-log" style="margin-top:12px;max-height:180px" role="log" aria-live="polite">{{ finiteText(cfMsg) }}</pre>
        </section>

        <section class="drawer-sec" v-if="asRecord(detail).kind !== 'vm'">
          <h3>{{ t('apps.col_autostart') }}</h3>
          <div class="auto-toggle">
            <MacSwitch
              :checked="!!asRecord(detail).autostart"
              :disabled="busy"
              :aria-label="t('apps.col_autostart')"
              @change="toggleManagedAutostart({ id: asRecord(detail).id, kind: asRecord(detail).kind, autostart_id: asRecord(detail).autostart_id, source_id: asRecord(detail).source_id }, $event)"
            />
            <span>{{ t('apps.autostart_help') }}</span>
          </div>
        </section>

        <section class="drawer-sec" v-if="asRecord(detail).path || asRecord(detail).compose_file || asRecord(detail).package || asRecord(detail).plist_hint">
          <h3>{{ t('apps.sec_paths') }}</h3>
          <div class="kv-list mono">
            <div v-if="finiteText(asRecord(detail).path, '')"><span class="k">path</span>{{ finiteText(asRecord(detail).path) }}</div>
            <div v-if="finiteText(asRecord(detail).compose_file, '')"><span class="k">compose</span>{{ finiteText(asRecord(detail).compose_file) }}</div>
            <div v-if="finiteText(asRecord(detail).package, '')"><span class="k">package</span>{{ finiteText(asRecord(detail).package) }}</div>
            <div v-if="finiteText(asRecord(detail).plist_hint, '')"><span class="k">plist</span>{{ finiteText(asRecord(detail).plist_hint) }}</div>
            <div v-if="finiteText(asRecord(detail).backend, '')"><span class="k">backend</span>{{ finiteText(asRecord(detail).backend) }}</div>
            <div v-if="finiteText(asRecord(detail).uuid, '')"><span class="k">uuid</span>{{ finiteText(asRecord(detail).uuid) }}</div>
          </div>
        </section>

        <section class="drawer-sec" v-if="asArray(asRecord(detail).data_paths).length">
          <h3>{{ t('apps.sec_data') }}</h3>
          <ul class="plain-list mono">
            <li v-for="(p,i) in asArray(asRecord(detail).data_paths)" :key="finiteText(p) + ':' + i">{{ finiteText(p) }}</li>
          </ul>
        </section>

        <section class="drawer-sec" v-if="asArray(asRecord(detail).databases).length">
          <h3>{{ t('apps.sec_db') }}</h3>
          <ul class="plain-list mono">
            <li v-for="(d,i) in asArray(asRecord(detail).databases)" :key="finiteText(asRecord(d).path) + ':' + i">{{ finiteText(asRecord(d).type) }} · {{ finiteText(asRecord(d).path) }} <span v-if="asRecord(d).mount">→ {{ finiteText(asRecord(d).mount) }}</span></li>
          </ul>
        </section>

        <section class="drawer-sec" v-if="asArray(asRecord(detail).ports).length || asArray(asRecord(detail).listening).length">
          <h3>{{ t('apps.sec_ports') }}</h3>
          <table class="mini-table" v-if="asArray(asRecord(detail).ports).length">
            <thead><tr><th>{{ t('apps.col_ports') }}</th><th>target</th><th>ctr</th></tr></thead>
            <tbody>
              <tr v-for="(p,i) in asArray(asRecord(detail).ports)" :key="finiteText(asRecord(p).published) + ':' + finiteText(asRecord(p).target) + ':' + i">
                <td class="mono">{{ finiteText(asRecord(p).published) }}</td>
                <td class="mono">{{ finiteText(asRecord(p).target) }}</td>
                <td class="mono">{{ finiteText(asRecord(p).container, '') }}</td>
              </tr>
            </tbody>
          </table>
          <div v-if="asArray(asRecord(detail).listening).length" class="sub-line" style="margin-top:8px">
            {{ t('apps.listening') }}:
            <span v-for="(l,i) in asArray(asRecord(detail).listening)" :key="finiteText(asRecord(l).name) + ':' + i" class="mono"> {{ finiteText(asRecord(l).name) }} </span>
          </div>
        </section>

        <section class="drawer-sec" v-if="asArray(asRecord(detail).networks).length">
          <h3>{{ t('apps.sec_network') }}</h3>
          <table class="mini-table">
            <thead><tr><th>network</th><th>IP</th><th>gw / ctr</th></tr></thead>
            <tbody>
              <tr v-for="(n,i) in asArray(asRecord(detail).networks)" :key="finiteText(asRecord(n).network) + ':' + finiteText(asRecord(n).ip) + ':' + i">
                <td class="mono">{{ finiteText(asRecord(n).network) }}</td>
                <td class="mono">{{ finiteText(asRecord(n).ip) }}</td>
                <td class="mono">{{ finiteText(asRecord(n).gateway, '') || finiteText(asRecord(n).container, '') }}</td>
              </tr>
            </tbody>
          </table>
        </section>

        <section class="drawer-sec" v-if="asArray(asRecord(detail).mounts).length">
          <h3>{{ t('apps.sec_mounts') }}</h3>
          <table class="mini-table">
            <thead><tr><th>src</th><th>dst</th><th>type</th></tr></thead>
            <tbody>
              <tr v-for="(m,i) in asArray(asRecord(detail).mounts)" :key="finiteText(asRecord(m).source) + ':' + finiteText(asRecord(m).destination) + ':' + i">
                <td class="mono path-cell" :title="finiteText(asRecord(m).source)">{{ finiteText(asRecord(m).source) }}</td>
                <td class="mono">{{ finiteText(asRecord(m).destination) }}</td>
                <td>{{ finiteText(asRecord(m).type) }}</td>
              </tr>
            </tbody>
          </table>
        </section>

        <section class="drawer-sec" v-if="asArray(asRecord(detail).containers).length">
          <h3>{{ t('apps.sec_containers') }}</h3>
          <table class="mini-table">
            <thead><tr><th>name</th><th>image</th><th>state</th><th>ports</th></tr></thead>
            <tbody>
              <tr v-for="(c,i) in asArray(asRecord(detail).containers)" :key="finiteText(asRecord(c).name) + ':' + i">
                <td class="mono">{{ finiteText(asRecord(c).name) }}</td>
                <td class="mono path-cell">{{ finiteText(asRecord(c).image) }}</td>
                <td>{{ finiteText(asRecord(c).state) }}</td>
                <td class="mono path-cell">{{ finiteText(asRecord(c).ports) }}</td>
              </tr>
            </tbody>
          </table>
        </section>

        <section class="drawer-sec" v-if="asArray(asRecord(detail).ips).length">
          <h3>VM IP</h3>
          <div class="mono">{{ asArray(asRecord(detail).ips).map(ip => finiteText(ip, '')).filter(Boolean).join(', ') }}</div>
        </section>

        <section class="drawer-sec" v-if="asArray(asRecord(detail).env_sample).length">
          <h3>Env</h3>
          <pre class="env-pre">{{ asArray(asRecord(detail).env_sample).map(n => finiteText(n, '')).filter(Boolean).join('\n') }}</pre>
        </section>

        <section class="drawer-sec" v-if="asRecord(detail).notes">
          <h3>{{ t('apps.sec_notes') }}</h3>
          <p class="notes">{{ finiteText(asRecord(detail).notes) }}</p>
        </section>

        <p class="sub-line" v-if="asRecord(detail).host_ip">Host IP: {{ finiteText(asRecord(detail).host_ip) }}</p>
      </aside>
    </div>

    <!-- install modal -->
    <div ref="installPanel" v-if="installTpl" class="modal-bg" @click.self="installTpl = null" role="presentation">
      <div class="modal install-modal" role="dialog" aria-modal="true" aria-labelledby="apps-install-title">
        <div class="modal-head">
          <h3 id="apps-install-title" class="modal-title">{{ t('apps.deploy') }} · {{ finiteText(asRecord(installTpl).name) }}</h3>
          <button type="button" @click="installTpl = null">{{ t('common.close') }}</button>
        </div>
        <p class="modal-desc">{{ finiteText(asRecord(installTpl).desc) }}</p>
        <p v-if="finiteText(asRecord(installTpl).notes, '')" class="notes">{{ finiteText(asRecord(installTpl).notes) }}</p>
        <!-- Elevated-access compose directives found when the remote template
             was synced: accepted (the admin's source choice is the trust
             root), but never silently. -->
        <div v-if="asArray(asRecord(installTpl).compose_warnings).length" class="tpl-danger" role="alert">
          <strong>{{ t('catalog_remote.warn_title') }}</strong>
          {{ asArray(asRecord(installTpl).compose_warnings).map((w) => finiteText(w, '')).filter(Boolean).map((w) => t(`catalog_remote.warn_${w}`)).join(' · ') }}
        </div>
        <p v-if="asRecord(installTpl).source === 'remote' && asRecord(installTpl).builtin_available" class="tpl-danger" role="alert">
          {{ t('catalog_remote.overrides_builtin_note') }}
        </p>
        <p v-if="asRecord(installTpl).kind === 'native'" class="path-line mono">
          → {{ t('apps.native_install') }} · {{ finiteText(asRecord(installTpl).method, '') || 'system' }}{{ finiteText(asRecord(installTpl).package, '') ? ` · ${finiteText(asRecord(installTpl).package)}` : '' }}
        </p>
        <p v-else class="path-line mono">→ ~/Services/{{ finiteText(asRecord(installTpl).id) }}/docker-compose.yml</p>

        <div v-if="asArray(asRecord(installTpl).vars).length" class="form-grid">
          <template v-for="v in asArray(asRecord(installTpl).vars)" :key="finiteText(asRecord(v).name)">
            <label class="form-label">{{ finiteText(asRecord(v).label, '') || finiteText(asRecord(v).name) }}</label>
            <div class="form-field">
<!-- The form-label beside this grid cell is not associated (no for/id), so
                   the input had no accessible name; mirror the label's text. -->
              <input
                v-model="installVars[asRecord(v).name]"
                :type="asRecord(v).secret ? 'password' : 'text'"
                :aria-label="finiteText(asRecord(v).label, '') || finiteText(asRecord(v).name)"
                :placeholder="asRecord(v).default === '' && asRecord(v).secret ? t('apps.auto_password') : (asRecord(v).required === false ? t('apps.optional') : '')"
              />
              <div v-if="finiteText(asRecord(v).help, '')" class="field-help">{{ finiteText(asRecord(v).help) }}</div>
            </div>
          </template>
        </div>
        <p v-else class="modal-desc">{{ t('apps.no_vars') }}</p>

        <div class="app-actions" style="margin-top:14px">
          <button type="button" class="primary" :disabled="busy" @click="doInstall">{{ t('apps.confirm_deploy') }}</button>
          <button type="button" @click="installTpl = null">{{ t('common.cancel') }}</button>
        </div>
        <pre v-if="installLog" class="install-log" role="log" aria-live="polite">{{ finiteText(installLog) }}</pre>
        <!-- Fixed upstream first-run login (cannot be preset via env): shown on
             the success panel so nobody has to dig it out of the notes, with a
             change-it-now reminder. -->
        <div v-if="installCreds" class="tpl-danger first-run-creds" role="alert">
          <strong>{{ t('apps.first_run_creds_title') }}</strong>
          <span class="mono">{{ finiteText(installCreds) }}</span>
          <span>{{ t('apps.first_run_creds_hint') }}</span>
        </div>
        <a
          v-if="installUrl"
          class="btn primary open-url"
          :href="finiteText(installUrl, '')"
          target="_blank"
          rel="noopener"
        >{{ t('apps.open_url') }} · {{ finiteText(installUrl) }}</a>
      </div>
    </div>

    <!-- remote catalog source config + update check -->
    <div v-if="remoteModal" class="modal-bg" @click.self="remoteModal = false" role="presentation">
      <div ref="remotePanel" class="modal install-modal" role="dialog" aria-modal="true" aria-labelledby="apps-remote-title">
        <div class="modal-head">
          <h3 id="apps-remote-title" class="modal-title">{{ t('catalog_remote.title') }}</h3>
          <button type="button" @click="remoteModal = false">{{ t('common.close') }}</button>
        </div>
        <p class="modal-desc">{{ t('catalog_remote.source_help') }}</p>
        <div class="form-grid">
          <label class="form-label">{{ t('catalog_remote.source_url') }}</label>
          <div class="form-field" style="display:flex;gap:8px">
            <input
              v-model.trim="remoteUrl"
              type="text"
              :placeholder="t('catalog_remote.source_ph')"
              style="flex:1"
              :aria-label="t('catalog_remote.source_url')"
            />
            <button type="button" :disabled="remoteBusy" @click="saveRemoteSource">{{ t('catalog_remote.save') }}</button>
          </div>
        </div>
        <p class="sub-line" style="margin-top:8px">{{ t('catalog_remote.security_note') }}</p>
        <div class="app-actions" style="margin:10px 0">
          <button type="button" class="primary" :disabled="remoteBusy" @click="checkRemoteUpdates">
            {{ remoteBusy ? t('catalog_remote.checking') : t('catalog_remote.check_updates') }}
          </button>
        </div>
        <!-- role=alert: the source config loads after the modal already holds
             focus, and a failure used to leave it silently blank — neither the
             "not configured" line nor the overrides list rendered, so a dead
             read looked like a fresh install. -->
        <div v-if="remoteError" class="tpl-danger" role="alert">
          <div>{{ t('catalog_remote.load_failed') }}</div>
          <div class="sub mono" style="margin-top:4px">{{ finiteText(remoteError) }}</div>
        </div>
        <p v-if="remoteInfo && !asRecord(remoteInfo).configured && !remoteUrl" class="sub-line">
          {{ t('catalog_remote.not_configured') }}
        </p>
        <p v-if="finiteText(asRecord(remoteInfo)?.last_check, '')" class="sub-line">
          {{ t('catalog_remote.last_check') }}: {{ finiteText(asRecord(remoteInfo).last_check) }}
          <template v-if="asRecord(remoteInfo).last_result">
            · {{ summaryLine(asRecord(remoteInfo).last_result) }}
          </template>
        </p>
        <div v-if="remoteResult" class="notes" role="status" style="margin-bottom:10px">
          {{ summaryLine(remoteResult) }}
          <ul v-if="asArray(asRecord(remoteResult).rejected).length" class="plain-list mono" style="margin-top:6px">
            <li v-for="r in asArray(asRecord(remoteResult).rejected)" :key="finiteText(asRecord(r).id)">
              {{ finiteText(asRecord(r).id) }} — {{ t(`catalog_remote.reject_${asRecord(r).reason}`) }}
            </li>
          </ul>
        </div>
        <section v-if="asArray(asRecord(remoteInfo)?.overrides).length">
          <h4 class="modal-title" style="font-size:14px;margin:8px 0">{{ t('catalog_remote.overrides_title') }}</h4>
          <table class="mini-table">
            <thead><tr><th>id</th><th>{{ t('catalog_remote.col_version') }}</th><th><span class="sr-only">{{ t('common.actions') }}</span></th></tr></thead>
            <tbody>
              <tr v-for="o in asArray(asRecord(remoteInfo).overrides)" :key="finiteText(asRecord(o).id)">
                <td class="mono">{{ finiteText(asRecord(o).id) }}</td>
                <td class="mono">{{ finiteText(asRecord(o).version) }}</td>
                <td>
                  <button type="button" class="act-btn" :disabled="remoteBusy" @click="restoreBuiltin(o)">
                    {{ t('catalog_remote.restore_builtin') }}
                  </button>
                </td>
              </tr>
            </tbody>
          </table>
        </section>
        <p v-else-if="remoteInfo" class="sub-line">{{ t('catalog_remote.no_overrides') }}</p>
      </div>
    </div>

    <!-- closeJobLog, not `logOpen = false`: the job log polls every 1.5s and the
         interval was only cleared when a poll happened to observe running:false,
         so closing the modal left it running against the server indefinitely. -->
    <div ref="logPanel" v-if="logOpen" class="modal-bg" @click.self="closeJobLog" role="presentation">
      <div class="modal install-modal" role="dialog" aria-modal="true" aria-labelledby="apps-log-title">
        <div class="modal-head">
          <h3 id="apps-log-title" class="modal-title">📋 {{ finiteText(logTitle) }}</h3>
          <button type="button" @click="closeJobLog">{{ t('common.close') }}</button>
        </div>
        <pre class="install-log">{{ finiteText(logText) }}</pre>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, inject, onMounted, onUnmounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import {
  checkCatalogRemoteUpdates,
  createCloudflareTunnel,
  deleteAppCredential,
  getAppCredential,
  getAutostartApps,
  getCatalog,
  getCatalogRemote,
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
  restoreCatalogBuiltin,
  routeCloudflareDns,
  runAppAutostartNow,
  runStack,
  saveAppCredential,
  setAppAutostart,
  setCatalogRemoteSource,
  setDockerAutostartPolicy,
  startCloudflareLogin,
  startCloudflareToken,
  startCloudflareTunnel,
  stopCloudflare,
  uninstallCatalog,
} from '../api/client'
import { injectI18n } from '../i18n'
import { finiteN, finiteText, asArray, asRecord, asTrimmed, jsonText } from '../lib/finite'
import { useDismissable } from '../composables/useDismissable'
import SkeletonLoader from '../components/SkeletonLoader.vue'
import LoadFailure from '../components/LoadFailure.vue'
import MacSwitch from '../components/MacSwitch.vue'
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
const autostartLoaded = ref(false)
const autostartError = ref('')
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
//: Upstream first-run credentials of the just-installed template, if any.
const installCreds = ref('')
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
// Remote template catalog source (admin: configure URL, pull updates, restore)
const remoteModal = ref(false)
const remotePanel = ref(null)
const remoteInfo = ref(null)
const remoteError = ref('')
const remoteUrl = ref('')
const remoteBusy = ref(false)
const remoteResult = ref(null)
// Cloudflare Tunnel panel state
const cfStatus = ref({ logged_in: false, running: false, tunnels: [] })
const cfSelectedTunnel = ref('')
const cfNewName = ref('')
const cfToken = ref('')
const cfDnsHost = ref('')
const cfMsg = ref('')
const cfBusy = ref(false)
let timer = null
let jobTimer = null
let jobPollGeneration = 0
const refreshTimers = new Set()

function later(fn, ms) {
  const generation = appsDataGeneration
  const id = setTimeout(() => {
    refreshTimers.delete(id)
    if (generation !== appsDataGeneration) return
    fn()
  }, ms)
  refreshTimers.add(id)
}

function stopJobPolling() {
  jobPollGeneration += 1
  if (jobTimer) clearTimeout(jobTimer)
  jobTimer = null
}
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
  for (const j of asArray(jobs.value)) if (j.stack_id) m[j.stack_id] = j.job_id
  return m
})

function fieldText(value) {
  const text = finiteText(value, '')
  return typeof text === 'string' ? text : ''
}

const filteredManaged = computed(() => {
  let list = asArray(asRecord(managed.value).items)
  if (mkind.value !== 'all') list = list.filter(x => asRecord(x).kind === mkind.value)
  const rawQ = mq.value
  const s = asTrimmed(rawQ).toLowerCase()
  if (s) {
    list = list.filter(x => {
      const rec = asRecord(x)
      return fieldText(rec.name).toLowerCase().includes(s)
        || fieldText(rec.id).toLowerCase().includes(s)
        || fieldText(rec.path).toLowerCase().includes(s)
        || fieldText(rec.package).toLowerCase().includes(s)
        || fieldText(rec.ports_summary).toLowerCase().includes(s)
    })
  }
  return list
})

const autostartGroups = computed(() => {
  const bag = asRecord(autostart.value)
  const g = asArray(bag.groups)
  if (g.length) return g
  const set = new Set(asArray(bag.items).map(i => asRecord(i).group || t('common.other')))
  return [...set]
})

const autostartByGroup = computed(() => {
  const m = {}
  for (const it of asArray(asRecord(autostart.value).items)) {
    const g = asRecord(it).group || t('common.other')
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
  const text = asTrimmed(finiteText(message, ''))
  if (!text) return t('common.fail')
  return text.split('\n')[0]
}

function kindLabel(k) {
  if (k === 'native') return t('apps.kind_native')
  if (k === 'docker') return t('apps.kind_docker')
  if (k === 'launchd') return t('apps.kind_launchd')
  if (k === 'vm') return t('apps.kind_vm')
  return finiteText(k)
}
function kindChip(k) {
  if (k === 'native') return 'chip-native'
  if (k === 'docker') return 'chip-docker'
  if (k === 'launchd') return 'chip-launchd'
  return 'chip-feat'
}
function stateLabel(s) {
  if (s === 'ok') return t('common.running')
  if (s === 'stopped' || s === 'down') return t('common.stopped')
  if (s === 'warn') return t('common.warn')
  return finiteText(s)
}
/** Always allow common ops; never hide uninstall behind missing action flags */
function canAct(it, act) {
  if (!it) return false
  if (act === 'uninstall') return true
  const acts = asArray(it.actions)
  if (acts.includes(act)) return true
  // fallbacks when backend omits flags
  if (act === 'logs' && (it.kind === 'docker' || it.kind === 'native' || it.kind === 'launchd')) return true
  if (act === 'start' && (it.state === 'down' || it.state === 'stopped')) return true
  if (act === 'stop' && it.state === 'ok' && it.kind !== 'native') return true
  if (act === 'restart' && it.state === 'ok') return true
  return false
}

function isScreenSharing(it) {
  if (!it) return false
  const rec = asRecord(it)
  const id = `${fieldText(rec.id)} ${fieldText(rec.source_id)}`
  const name = fieldText(rec.name).toLowerCase()
  return id.includes('screen-sharing')
    || name.includes('屏幕共享') // cjk-input: matches the service name macOS reports in a zh locale
    || name.includes('screen sharing')
    || fieldText(rec.url).startsWith('vnc://')
    || fieldText(rec.url_hint).startsWith('vnc://')
    || rec.open_protocol === 'vnc'
}

function browseHost() {
  return finiteText(window.location.hostname, '')
    || finiteText(asRecord(managed.value).host_ip, '')
    || 'localhost'
}

/** Prefer url field; fall back to first host port in ports_summary */
function openUrl(it) {
  if (!it) return ''
  // VNC / Screen Sharing: connect to the host you're browsing (panel host)
  if (isScreenSharing(it)) {
    return `vnc://${browseHost()}`
  }
  const rec = asRecord(it)
  const rawUrl = fieldText(rec.url) || fieldText(rec.url_hint)
  if (rawUrl) {
    const host = browseHost()
    return rawUrl.replaceAll('{{HOST}}', host).replaceAll('{{HOST_IP}}', host)
  }
  const ps = fieldText(rec.ports_summary)
  const m = ps.match(/(?:0\.0\.0\.0|127\.0\.0\.1|\[::\]):(\d+)->/) || ps.match(/^(\d{2,5})$/)
  if (m) {
    return `http://${browseHost()}:${m[1]}`
  }
  // native ports list like "8125"
  if (ps && /^\d{2,5}/.test(asTrimmed(ps))) {
    const port = asTrimmed(ps).split(/[,\s]/)[0]
    if (!['1883', '5432', '6379', '3306', '5900', '9100'].includes(port)) {
      return `http://${browseHost()}:${port}`
    }
  }
  return ''
}

/** Catalog/store open link: url_hint (resolved) or url_template with defaults */
function catalogOpenUrl(tpl) {
  if (!tpl) return ''
  if (isScreenSharing(tpl)) {
    const host = finiteText(window.location.hostname, '') || 'localhost'
    return `vnc://${host}`
  }
  const hinted = finiteText(tpl.url_hint, '') || finiteText(tpl.url, '')
  if (hinted) return hinted
  const ut = finiteText(tpl.url_template, '')
  if (!ut) {
    // ports-only fallback for web-ish services
    const ports = asArray(asRecord(tpl).ports)
    for (const p of ports) {
      const ps = fieldText(p).split('/')[0]
      if (/^\d+$/.test(ps) && !['1883', '5432', '6379', '3306', '5900', '9100', '22000', '53'].includes(ps)) {
        const host = finiteText(window.location.hostname, '') || 'localhost'
        return `http://${host}:${ps}`
      }
    }
    return ''
  }
  const host = finiteText(window.location.hostname, '') || 'localhost'
  let out = ut.replaceAll('{{HOST_IP}}', host).replaceAll('{{HOST}}', host)
  const vars = asArray(tpl.vars)
  for (const v of vars) {
    if (v && v.name && v.default != null && v.default !== '') {
      out = out.replaceAll(`{{${finiteText(v.name, '')}}}`, String(finiteText(v.default, '')))
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
  const generation = appsDataGeneration
  busy.value = true
  try {
    await launchOpenInner(it, u)
  } finally {
    if (stillOnApps(generation)) busy.value = false
  }
}

async function launchOpenInner(it, u) {
  const generation = appsDataGeneration
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
        const result = asRecord(await manageApp(id, 'open'))
        if (!stillOnApps(generation)) return
        if (result.ok) {
          toast(`✅ ${t('apps.open_url')} · ${result.url || u}`)
          return
        }
      } catch {
        if (!stillOnApps(generation)) return
      }
    }
    if (!stillOnApps(generation)) return
    toast(`→ ${u}`)
    return
  }
  if (!stillOnApps(generation)) return
  window.open(u, '_blank', 'noopener')
}
function goManage(tpl) {
  tab.value = 'managed'
  loadManaged(true)
  later(() => {
    const id = tpl.kind === 'native'
      ? `native:${tpl.id}`
      : `docker:${tpl.id}`
    const hit = asArray(asRecord(managed.value).items).find(x => asRecord(x).id === id || asRecord(x).source_id === tpl.id)
    if (hit) openDetail(hit)
  }, 400)
}

let managedGeneration = 0

async function loadManaged(force = false) {
  const generation = ++managedGeneration
  loading.value = true
  try {
    const payload = asRecord(await getManagedApps(force))
    if (generation !== managedGeneration) return
    managed.value = {
      ...payload,
      items: asArray(payload.items),
      counts: payload.counts == null ? null : asRecord(payload.counts),
    }
    managedError.value = ''
  } catch (e) {
    if (generation !== managedGeneration) return false
    managedError.value = finiteText(e.message || String(e), '')
    // The 15s tick passes force=false, so background failures stay silent —
    // LoadFailure already marks the state on screen, and a toast per interval
    // while the panel is down is pure noise. Manual paths pass force=true.
    if (force) toast('❌ ' + finiteText(e.message))
    // The 15s tick returns this promise, so a dead server engages the
    // lib/poll.js failure backoff instead of being polled at full rate.
    return false
  } finally {
    if (generation === managedGeneration) {
      loading.value = false
      managedLoaded.value = true
    }
  }
}

function softText(j, fallbackKey = 'common.fail') {
  const rec = asRecord(j)
  if (rec.code) {
    const key = `err.${rec.code}`
    const translated = t(key, asRecord(rec.params))
    if (translated !== key) return translated
  }
  return finiteText(rec.message, '') || t(fallbackKey)
}

let appsDataGeneration = 0
let pageAlive = true

function stillOnApps(generation) {
  return pageAlive && generation === appsDataGeneration
}

async function loadAutostart(force = false) {
  const generation = appsDataGeneration
  loading.value = true
  try {
    const payload = asRecord(await getAutostartApps(force))
    if (generation !== appsDataGeneration) return
    autostart.value = {
      ...payload,
      items: asArray(payload.items),
      groups: asArray(payload.groups),
      counts: payload.counts == null ? null : asRecord(payload.counts),
    }
    autostartError.value = ''
  } catch (e) {
    if (generation !== appsDataGeneration) return
    autostartError.value = finiteText(e.message || String(e), '')
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (generation === appsDataGeneration) {
      loading.value = false
      autostartLoaded.value = true
    }
  }
}

async function setAutostartItem(it, enabled) {
  const key = enabled ? 'apps.confirm_autostart_on' : 'apps.confirm_autostart_off'
  if (!confirm(t(key, { name: finiteText(asRecord(it).name) }))) return
  const generation = appsDataGeneration
  busy.value = true
  try {
    const result = asRecord(await setAppAutostart(it.id, enabled))
    if (!stillOnApps(generation)) return
    toast(result.ok !== false ? `✅ ${enabled ? t('apps.auto_on') : t('apps.auto_off')} · ${finiteText(asRecord(it).name)}` : '❌ ' + softText(result))
    // Disjoint state (`autostart` vs `managed`) re-read after the same write.
    await Promise.all([loadAutostart(true), loadManaged(true)])
  } catch (e) {
    if (!stillOnApps(generation)) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (stillOnApps(generation)) busy.value = false
  }
}

async function setDockerPolicy(it, policy) {
  if (!confirm(t('apps.confirm_docker_policy', { name: finiteText(asRecord(it).name, '') || finiteText(asRecord(it).id), policy: finiteText(policy) }))) return
  const name = fieldText(it.id).replace(/^docker-ctr:/, '').replace(/^docker:/, '')
  const generation = appsDataGeneration
  busy.value = true
  try {
    const result = asRecord(await setDockerAutostartPolicy(name, policy))
    if (!stillOnApps(generation)) return
    toast(result.ok ? `✅ restart=${finiteText(policy)}` : '❌ ' + softText(result))
    // Disjoint state (`autostart` vs `managed`) re-read after the same write.
    await Promise.all([loadAutostart(true), loadManaged(true)])
  } catch (e) {
    if (!stillOnApps(generation)) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (stillOnApps(generation)) busy.value = false
  }
}

async function runAutostartNow() {
  if (!confirm(t('apps.confirm_run_autostart'))) return
  const generation = appsDataGeneration
  busy.value = true
  try {
    const result = asRecord(await runAppAutostartNow())
    if (!stillOnApps(generation)) return
    toast(result.ok ? '✅ ' + (finiteText(result.message, '') || t('common.ok')) : '❌ ' + softText(result))
    // This starts every autostart-enabled app, so the table it was launched from
    // is immediately out of date. Nothing reloaded it before: the 15s poll only
    // covers the Managed tab, so the Autostart rows kept their pre-run "stopped"
    // chips until the user switched tabs and back.
    await loadAutostart()
  } catch (e) {
    if (!stillOnApps(generation)) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (stillOnApps(generation)) busy.value = false
  }
}

async function toggleManagedAutostart(it, enabled) {
  if (!it.autostart_id) {
    const key = enabled ? 'apps.confirm_autostart_on' : 'apps.confirm_autostart_off'
    if (!confirm(t(key, { name: finiteText(asRecord(it).name) }))) return
  }
  const generation = appsDataGeneration
  busy.value = true
  try {
    // Prefer dedicated autostart_id (brew:xxx) when present
    if (it.autostart_id) {
      const r = asRecord(await setAutostartItem({ id: it.autostart_id, name: it.name }, enabled))
      return
    }
    const result = asRecord(await manageApp(it.id, enabled ? 'autostart_on' : 'autostart_off'))
    if (!stillOnApps(generation)) return
    toast(result.ok !== false ? `✅ ${enabled ? t('apps.auto_on') : t('apps.auto_off')}` : '❌ ' + softText(result))
    await loadManaged(true)
    if (!stillOnApps(generation)) return
    if (detail.value?.id === it.id) {
      detail.value = { ...detail.value, autostart: enabled }
    }
  } catch (e) {
    if (!stillOnApps(generation)) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (stillOnApps(generation)) busy.value = false
  }
}

let detailGeneration = 0
async function openDetail(it) {
  const generation = ++detailGeneration
  busy.value = true
  try {
    const d = asRecord(await getManagedAppDetail(it.id))
    if (generation !== detailGeneration) return
    // merge list-level autostart flags
    d.autostart = it.autostart
    d.autostart_id = it.autostart_id
    detail.value = d
    await loadCredential(d, generation)
    if (generation !== detailGeneration) return
    if (d.source_id === 'native-cloudflared' || d.cloudflared) {
      await cfRefresh()
    }
  } catch (e) {
    if (generation !== detailGeneration) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    // closeDetail() bumps detailGeneration; a generation match would leave
    // the page stuck busy after the user closed the drawer mid-load.
    if (pageAlive) busy.value = false
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
  detailGeneration += 1
  detail.value = null
  credential.value = null
  credentialForm.value = { username: '', password: '', confirm: '', url: '', notes: '' }
  showCredentialPassword.value = false
  cfMsg.value = ''
  stopCfLoginPolling()
}

async function cfRefresh() {
  const generation = appsDataGeneration
  cfBusy.value = true
  try {
    const status = asRecord(await getCloudflareStatus())
    if (!stillOnApps(generation)) return
    cfStatus.value = { ...status, tunnels: asArray(status.tunnels) }
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
    if (!stillOnApps(generation)) return
    cfMsg.value = '❌ ' + finiteText(e.message)
  } finally {
    if (stillOnApps(generation)) cfBusy.value = false
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
  const generation = appsDataGeneration
  cfBusy.value = true
  cfMsg.value = ''
  try {
    const result = await startCloudflareLogin()
    if (!stillOnApps(generation)) return
    cfMsg.value = result.ok ? '✅ ' + (finiteText(result.message, '') || '') : '❌ ' + softText(result)
    if (result.login_url) {
      cfStatus.value = { ...cfStatus.value, login_url: result.login_url, login_pending: true }
      startCfLoginPolling()
    } else if (result.logged_in || result.already) {
      stopCfLoginPolling()
      await cfRefresh()
    }
  } catch (e) {
    if (!stillOnApps(generation)) return
    cfMsg.value = '❌ ' + finiteText(e.message)
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (stillOnApps(generation)) cfBusy.value = false
  }
}

async function cfStartSelected() {
  if (!cfSelectedTunnel.value) return
  const generation = appsDataGeneration
  cfBusy.value = true
  cfMsg.value = ''
  try {
    const result = await startCloudflareTunnel(cfSelectedTunnel.value)
    if (!stillOnApps(generation)) return
    cfMsg.value = result.ok ? '✅ ' + (finiteText(result.message, '') || '') : '❌ ' + softText(result)
    toast(result.ok ? '✅ ' + t('apps.tunnel_started', { name: finiteText(cfSelectedTunnel.value) }) : '❌ ' + softText(result))
    // cfRefresh() writes `cfStatus`, loadManaged() writes `managed`; the tunnel
    // action above already committed, so neither read depends on the other.
    await Promise.all([cfRefresh(), loadManaged(true)])
  } catch (e) {
    if (!stillOnApps(generation)) return
    cfMsg.value = '❌ ' + finiteText(e.message)
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (stillOnApps(generation)) cfBusy.value = false
  }
}

async function cfStartToken() {
  if (!cfToken.value) return
  const generation = appsDataGeneration
  cfBusy.value = true
  cfMsg.value = ''
  try {
    const result = await startCloudflareToken(cfToken.value, cfSelectedTunnel.value || 'token')
    if (!stillOnApps(generation)) return
    cfMsg.value = result.ok ? '✅ ' + (finiteText(result.message, '') || '') : '❌ ' + softText(result)
    toast(result.ok ? '✅ ' + t('apps.token_tunnel_started') : '❌ ' + softText(result))
    cfToken.value = ''
    // cfRefresh() writes `cfStatus`, loadManaged() writes `managed`; the tunnel
    // action above already committed, so neither read depends on the other.
    await Promise.all([cfRefresh(), loadManaged(true)])
  } catch (e) {
    if (!stillOnApps(generation)) return
    cfMsg.value = '❌ ' + finiteText(e.message)
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (stillOnApps(generation)) cfBusy.value = false
  }
}

async function cfStop() {
  // Stopping the tunnel drops every externally published hostname. The panel's
  // own service stop is confirmed (Settings.vue), so this is too.
  if (!confirm(t('apps.cf_confirm_stop'))) return
  const generation = appsDataGeneration
  cfBusy.value = true
  try {
    const result = await stopCloudflare()
    if (!stillOnApps(generation)) return
    cfMsg.value = result.ok ? '✅ ' + (finiteText(result.message, '') || '') : '❌ ' + softText(result)
    toast(result.ok ? '✅ ' + t('apps.stopped') : '❌ ' + softText(result))
    // cfRefresh() writes `cfStatus`, loadManaged() writes `managed`; the tunnel
    // action above already committed, so neither read depends on the other.
    await Promise.all([cfRefresh(), loadManaged(true)])
  } catch (e) {
    if (!stillOnApps(generation)) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (stillOnApps(generation)) cfBusy.value = false
  }
}

async function cfRestart() {
  const generation = appsDataGeneration
  cfBusy.value = true
  try {
    const result = await restartCloudflare()
    if (!stillOnApps(generation)) return
    cfMsg.value = result.ok ? '✅ ' + (finiteText(result.message, '') || '') : '❌ ' + softText(result)
    toast(result.ok ? '✅ ' + t('apps.restarted') : '❌ ' + softText(result))
    // cfRefresh() writes `cfStatus`, loadManaged() writes `managed`; the tunnel
    // action above already committed, so neither read depends on the other.
    await Promise.all([cfRefresh(), loadManaged(true)])
  } catch (e) {
    if (!stillOnApps(generation)) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (stillOnApps(generation)) cfBusy.value = false
  }
}

async function cfCreate() {
  if (!cfNewName.value) return
  const generation = appsDataGeneration
  cfBusy.value = true
  try {
    const result = await createCloudflareTunnel(cfNewName.value)
    if (!stillOnApps(generation)) return
    cfMsg.value = result.ok ? '✅ ' + (finiteText(result.message, '') || '') : '❌ ' + softText(result)
    if (result.ok) {
      cfSelectedTunnel.value = cfNewName.value
      cfNewName.value = ''
    }
    await cfRefresh()
  } catch (e) {
    if (!stillOnApps(generation)) return
    cfMsg.value = '❌ ' + finiteText(e.message)
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (stillOnApps(generation)) cfBusy.value = false
  }
}

async function cfRouteDns() {
  if (!cfSelectedTunnel.value || !cfDnsHost.value) return
  const generation = appsDataGeneration
  cfBusy.value = true
  try {
    const result = await routeCloudflareDns(cfSelectedTunnel.value, cfDnsHost.value)
    if (!stillOnApps(generation)) return
    cfMsg.value = result.ok ? '✅ ' + (finiteText(result.message, '') || '') : '❌ ' + softText(result)
    toast(result.ok ? '✅ ' + t('apps.dns_bound') : '❌ ' + softText(result))
  } catch (e) {
    if (!stillOnApps(generation)) return
    cfMsg.value = '❌ ' + finiteText(e.message)
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (stillOnApps(generation)) cfBusy.value = false
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

async function loadCredential(app, generation = detailGeneration) {
  credentialLoaded.value = false
  credential.value = null
  credentialForm.value = {
    username: credentialDefaultUsername(app),
    password: '',
    confirm: '',
    url: openUrl(app) || '',
    notes: '',
  }
  try {
    const result = asRecord(await getAppCredential(app.id))
    if (generation !== detailGeneration) return
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
    if (generation !== detailGeneration) return
    // Latch the failure and block Save. The form is pre-seeded with a hardcoded
    // default username and empty notes, and saveCredential sends both, so saving
    // on top of a failed read replaced the stored username and wiped the notes.
    // A missing credential is not this case: the API returns 200 with an empty
    // record for an app that has none, so a rejection here is a real failure.
    credentialLoaded.value = false
    credentialError.value = finiteText(e.message || String(e), '')
    toast('❌ ' + finiteText(e.message))
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
  const generation = detailGeneration
  credentialBusy.value = true
  try {
    const result = asRecord(await saveAppCredential({
      service_id: detail.value.id,
      display_name: finiteText(detail.value.name, '') || finiteText(detail.value.id),
      username: f.username,
      password: f.password,
      url: f.url,
      notes: f.notes,
      apply_to_service: !!applyToService,
    }))
    if (generation !== detailGeneration || !pageAlive) return
    credential.value = asRecord(result.credential)
    credentialForm.value.password = ''
    credentialForm.value.confirm = ''
    showCredentialPassword.value = false
    toast('✅ ' + (finiteText(result.message, '') || t('apps.credential_saved')))
  } catch (e) {
    if (generation !== detailGeneration || !pageAlive) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    // openDetail() / closeDetail() bump detailGeneration; a generation
    // match would leave Save stuck after switching the drawer.
    if (pageAlive) credentialBusy.value = false
  }
}

async function deleteCredential() {
  if (!confirm(t('apps.credential_delete_confirm'))) return
  const generation = detailGeneration
  credentialBusy.value = true
  try {
    const r = asRecord(await deleteAppCredential(detail.value.id))
    if (generation !== detailGeneration || !pageAlive) return
    await loadCredential(detail.value)
    if (generation !== detailGeneration || !pageAlive) return
    toast('✅ ' + t('apps.credential_deleted'))
  } catch (e) {
    if (generation !== detailGeneration || !pageAlive) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (pageAlive) credentialBusy.value = false
  }
}

// Generation counter so overlapping opens cannot interleave. None of the three
// triggers were disabled and this had no in-flight guard, so two clicks resolved
// into the shared logText in whatever order the responses arrived -- leaving the
// modal titled for one app and showing another's log.
let managedLogGeneration = 0

async function openManagedLogs(it) {
  stopJobPolling()
  curJob.value = null
  const generation = ++managedLogGeneration
  logOpen.value = true
  logTitle.value = (finiteText(asRecord(it).name, '') || finiteText(asRecord(it).id)) + ' · logs'
  logText.value = t('common.loading')
  try {
    const result = asRecord(await getManagedAppLogs(it.id, 150))
    if (generation !== managedLogGeneration) return
    const logBody = typeof result.log === 'string' || typeof result.log === 'number'
      ? finiteText(result.log, '')
      : jsonText(result.log, '')
    logText.value = logBody || finiteText(result.message)
  } catch (e) {
    if (generation !== managedLogGeneration) return
    logText.value = finiteText(e.message, '')
  }
}

async function doManagedAction(it, action) {
  if (!it?.id) return
  if (['stop', 'restart', 'update'].includes(action)
    && !confirm(t('services.confirm_action', { name: finiteText(asRecord(it).name, '') || finiteText(asRecord(it).id), action: finiteText(action) }))) return
  const generation = appsDataGeneration
  busy.value = true
  try {
    const result = asRecord(await manageApp(it.id, action))
    if (!stillOnApps(generation)) return
    toast(result.ok !== false ? `✅ ${finiteText(action)}` : '❌ ' + softText(result))
    await loadManaged(true)
    if (!stillOnApps(generation)) return
    if (detail.value?.id === it.id) await openDetail(it)
  } catch (e) {
    if (!stillOnApps(generation)) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (stillOnApps(generation)) busy.value = false
  }
}

async function doManagedUninstall(it) {
  if (!it?.id) return
  const confirmKey = it.kind === 'launchd'
    ? 'apps.confirm_uninstall_launchd'
    : 'apps.confirm_uninstall_managed'
  if (!confirm(t(confirmKey, { name: finiteText(asRecord(it).name, '') || finiteText(asRecord(it).id) }))) return
  const removeData = it.kind === 'docker'
    ? confirm(t('apps.confirm_remove_data'))
    : it.kind === 'launchd'
      ? confirm(t('apps.confirm_remove_launchd_data'))
      : false
  const generation = appsDataGeneration
  busy.value = true
  try {
    const result = asRecord(await manageApp(it.id, 'uninstall', removeData))
    if (!stillOnApps(generation)) return
    toast(result.ok !== false ? `✅ ${t('apps.uninstalled')}` : '❌ ' + softText(result))
    detail.value = null
    await Promise.all([loadManaged(true), loadCatalog()])
  } catch (e) {
    if (!stillOnApps(generation)) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (stillOnApps(generation)) busy.value = false
  }
}

const quickCats = computed(() => {
  const prefer = ['all', 'native', 'docker', 'featured', 'network', 'remote', 'media', 'files', 'ops', 'monitor']
  const map = Object.fromEntries(asArray(categories.value).map((c) => {
    const rec = asRecord(c)
    return [rec.id, rec]
  }))
  return prefer.map(id => map[id] || { id, label: id }).filter(Boolean)
})

const filtered = computed(() => {
  let list = asArray(catalog.value)
  if (cat.value === 'featured') list = list.filter(x => asRecord(x).featured)
  else if (cat.value === 'native') list = list.filter(x => asRecord(x).kind === 'native')
  else if (cat.value === 'docker') list = list.filter(x => (asRecord(x).kind || 'docker') === 'docker')
  else if (cat.value && cat.value !== 'all') list = list.filter(x => asRecord(x).category === cat.value)
  if (onlyFeatured.value) list = list.filter(x => asRecord(x).featured)
  if (hideInstalled.value) list = list.filter(x => !asRecord(x).installed)
  const rawQ = q.value
  const s = asTrimmed(rawQ).toLowerCase()
  if (s) {
    list = list.filter(x => {
      const rec = asRecord(x)
      return fieldText(rec.name).toLowerCase().includes(s)
        || fieldText(rec.desc).toLowerCase().includes(s)
        || fieldText(rec.id).toLowerCase().includes(s)
        || fieldText(rec.package).toLowerCase().includes(s)
        || asArray(rec.tags).some(tg => fieldText(tg).toLowerCase().includes(s))
        || fieldText(rec.category).toLowerCase().includes(s)
        || fieldText(rec.kind).toLowerCase().includes(s)
    })
  }
  return list
})

function catLabel(id) {
  const key = CAT_I18N[id]
  if (key) {
    const tr = t(key)
    if (tr && tr !== key) return tr
  }
  const c = asArray(categories.value).find(x => x.id === id)
  return finiteText(c?.label, '') || finiteText(id, '') || 'other'
}

function countLabel(id) {
  if (id === 'all') {
    const n = finiteN(overview.value.total, null)
    return n != null ? ` (${n})` : ''
  }
  if (id === 'featured') {
    const n = asArray(catalog.value).filter(x => x.featured).length
    return n ? ` (${n})` : ''
  }
  if (id === 'native') {
    const n = finiteN(overview.value.native_count, null)
    return n != null ? ` (${n})` : ''
  }
  if (id === 'docker') {
    const n = finiteN(overview.value.docker_count, null)
    return n != null ? ` (${n})` : ''
  }
  const n = finiteN(asRecord(overview.value.counts)[id], null)
  return n ? ` (${n})` : ''
}

async function refresh(manual = false) {
  const generation = appsDataGeneration
  loading.value = true
  try {
    const d = asRecord(await getStacks())
    if (generation !== appsDataGeneration) return
    stacks.value = asArray(d.stacks)
    jobs.value = asArray(d.jobs)
  } catch (e) {
    if (generation !== appsDataGeneration) return
    // The job-completion poll calls this in the background (the server, not
    // the user, decides when a stack job ends); a failure there must not
    // toast over whatever the operator is doing. User-initiated reloads pass
    // `manual` and keep their feedback.
    if (manual) toast('❌ ' + finiteText(e.message))
  }
  if (generation === appsDataGeneration) loading.value = false
}

async function loadCatalog() {
  const generation = appsDataGeneration
  try {
    const d = asRecord(await getCatalog())
    if (generation !== appsDataGeneration) return
    catalog.value = asArray(d.templates)
    overview.value = d
    const cats = asArray(d.categories)
    if (cats.length) categories.value = cats
    catalogError.value = ''
  } catch (e) {
    if (generation !== appsDataGeneration) return
    catalogError.value = finiteText(e.message || String(e), '')
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (generation === appsDataGeneration) catalogLoaded.value = true
  }
}

function openInstall(tpl) {
  installTpl.value = tpl
  installLog.value = ''
  installUrl.value = ''
  installCreds.value = ''
  const vars = {}
  for (const v of asArray(asRecord(tpl).vars)) {
    const rec = asRecord(v)
    if (rec.name) vars[rec.name] = rec.default || ''
  }
  installVars.value = vars
}

// ── remote catalog source ────────────────────────────────────────────────────

function summaryLine(r) {
  return t('catalog_remote.result_summary', {
    added: finiteN(Array.isArray(r.added) ? r.added.length : r.added, 0),
    updated: finiteN(Array.isArray(r.updated) ? r.updated.length : r.updated, 0),
    unchanged: finiteN(r.unchanged, 0),
    rejected: finiteN(Array.isArray(r.rejected) ? r.rejected.length : r.rejected, 0),
  })
}

async function loadRemote() {
  const generation = appsDataGeneration
  try {
    const next = asRecord(await getCatalogRemote())
    if (generation !== appsDataGeneration) return
    remoteInfo.value = next
    remoteError.value = ''
    remoteUrl.value = next?.url || ''
  } catch (e) {
    if (generation !== appsDataGeneration) return
    // Latched, not just toasted: with remoteInfo null the modal renders neither
    // the "not configured" line nor the overrides table, so after the toast
    // faded the failure was indistinguishable from an unconfigured source.
    remoteError.value = finiteText(e.message || String(e), '')
    toast('❌ ' + finiteText(e.message))
  }
}

function openRemoteModal() {
  remoteModal.value = true
  loadRemote()
}

async function saveRemoteSource() {
  const generation = appsDataGeneration
  remoteBusy.value = true
  try {
    const r = asRecord(await setCatalogRemoteSource(asTrimmed(remoteUrl.value)))
    if (!stillOnApps(generation)) return
    toast('✅ ' + t('catalog_remote.saved'))
    await loadRemote()
  } catch (e) {
    if (!stillOnApps(generation)) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (stillOnApps(generation)) remoteBusy.value = false
  }
}

async function checkRemoteUpdates() {
  const generation = appsDataGeneration
  // Nothing configured yet: open the config dialog instead of a guaranteed 400.
  if (!remoteInfo.value) await loadRemote()
  if (!stillOnApps(generation)) return
  if (!remoteInfo.value?.configured) {
    openRemoteModal()
    return
  }
  remoteBusy.value = true
  try {
    const result = asRecord(await checkCatalogRemoteUpdates())
    if (!stillOnApps(generation)) return
    remoteResult.value = result
    toast('✅ ' + summaryLine(result))
    // The listing changed server-side; both the store grid and the override
    // table must reflect it.
    await Promise.all([loadCatalog(), loadRemote()])
  } catch (e) {
    if (!stillOnApps(generation)) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (stillOnApps(generation)) remoteBusy.value = false
  }
}

async function restoreBuiltin(item) {
  if (!confirm(t('catalog_remote.restore_confirm', { id: finiteText(asRecord(item).id) }))) return
  const generation = appsDataGeneration
  remoteBusy.value = true
  try {
    await restoreCatalogBuiltin(item.id)
    if (!stillOnApps(generation)) return
    toast('✅ ' + t('catalog_remote.restored'))
    await Promise.all([loadCatalog(), loadRemote()])
  } catch (e) {
    if (!stillOnApps(generation)) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (stillOnApps(generation)) remoteBusy.value = false
  }
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
  const isNative = installTpl.value.kind === 'native'
  const msg = isNative
    ? t('apps.confirm_native', { name: finiteText(asRecord(installTpl.value).name) })
    : t('apps.confirm_msg', { name: finiteText(asRecord(installTpl.value).name), id: finiteText(asRecord(installTpl.value).id) })
  if (!confirm(msg)) return
  const generation = appsDataGeneration
  busy.value = true
  installLog.value = isNative ? t('apps.deploying_native') : t('apps.deploying')
  installUrl.value = ''
  installCreds.value = ''
  try {
    const r = asRecord(await installCatalog(installTpl.value.id, installVars.value))
    if (!stillOnApps(generation)) return
    installLog.value = (r.ok ? '✅ ' : '❌ ') + (finiteText(r.message, '') || '') + (finiteText(r.path, '') ? `\n→ ${finiteText(r.path)}` : '')
    if (finiteText(r.notes, '')) installLog.value += `\n\n${finiteText(r.notes)}`
    const url = finiteText(r.url, '') || finiteText(r.url_hint, '')
    if (url) installUrl.value = url
    // Surface the upstream default login only once something actually
    // deployed; the field also rides the listing, so fall back to it for
    // installs whose backend predates the response field.
    if (r.ok) {
      installCreds.value = finiteText(r.first_run_credentials, '') || finiteText(installTpl.value.first_run_credentials, '')
    }
    // First line only in the toast. A failure message can be several lines --
    // a pkg-based cask, for instance, explains that brew cannot be elevated and
    // prints the command to run on the Mac instead. The full text is right there
    // in installLog; a five-line toast just hides the rest of the page.
    toast(r.ok ? `✅ ${finiteText(asRecord(installTpl.value).name)}` : '❌ ' + firstLine(r.message))
    if (r.ok) {
      // Three independent re-reads after a successful install: catalog, managed
      // list and stacks. refresh() was already fire-and-forget here.
      await Promise.all([loadCatalog(), loadManaged(true), refresh(true)])
    }
  } catch (e) {
    if (!stillOnApps(generation)) return
    installLog.value = '❌ ' + e.message
    toast('❌ ' + finiteText(e.message))
  }
  if (stillOnApps(generation)) busy.value = false
}

async function doUninstall(tpl) {
  if (!tpl?.id) return
  const isNative = tpl.kind === 'native'
  if (!confirm(
    isNative
      ? t('apps.confirm_uninstall_native', { name: finiteText(asRecord(tpl).name) })
      : t('apps.confirm_uninstall', { name: finiteText(asRecord(tpl).name), id: finiteText(asRecord(tpl).id) })
  )) return

  // Docker: optional keep compose dir (default remove)
  let removeData = true
  if (!isNative) {
    removeData = confirm(t('apps.confirm_remove_data'))
  } else if (tpl.id === 'native-filebrowser') {
    removeData = confirm(t('apps.confirm_remove_data'))
  }

  const generation = appsDataGeneration
  busy.value = true
  try {
    const r = asRecord(await uninstallCatalog(tpl.id, { remove_data: removeData }))
    if (!stillOnApps(generation)) return
    toast(r.ok ? `✅ ${t('apps.uninstalled')} ${finiteText(asRecord(tpl).name)}` : '❌ ' + firstLine(r.message))
    if (r.message && !r.ok) {
      // show detail in console-friendly toast only; full msg may be long
    }
    // loadManaged too: uninstalling from the catalog left the app still listed
    // under Managed until something else happened to refresh it, so the two
    // uninstall paths disagreed -- doManagedUninstall() already reloads it.
    await Promise.all([loadCatalog(), refresh(true), loadManaged(true)])
  } catch (e) {
    if (!stillOnApps(generation)) return
    toast('❌ ' + finiteText(e.message))
  }
  if (stillOnApps(generation)) busy.value = false
}

async function run(s, action) {
  if (action === 'down' && !confirm(t('apps.confirm_down', { name: finiteText(asRecord(s).name) }))) return
  if (action === 'update' && !confirm(t('apps.confirm_update', { name: finiteText(asRecord(s).name) }))) return
  const generation = appsDataGeneration
  busy.value = true
  try {
    const r = asRecord(await runStack(s.id, action))
    if (!stillOnApps(generation)) return
    toast('🚀 ' + (finiteText(r.message, '') || t('common.ok')))
    if (r.job_id) openJob(r.job_id, s.name)
    refresh(true)
  } catch (e) {
    if (!stillOnApps(generation)) return
    toast('❌ ' + finiteText(e.message))
  }
  if (stillOnApps(generation)) busy.value = false
}

function openJob(jobId, title) {
  stopJobPolling()
  managedLogGeneration += 1
  curJob.value = jobId
  logTitle.value = finiteText(title, '') || finiteText(jobId)
  logOpen.value = true
  logText.value = t('common.loading')
  const generation = jobPollGeneration
  const poll = async () => {
    jobTimer = null
    if (!curJob.value) return
    if (typeof document !== 'undefined' && document.hidden) {
      if (generation === jobPollGeneration) jobTimer = setTimeout(poll, 1500)
      return
    }
    try {
      const j = asRecord(await getStackJob(curJob.value))
      if (generation !== jobPollGeneration) return
      logText.value = finiteText(j.log, '') + (j.running ? '\n⏳…' : '')
      if (!j.running) {
        stopJobPolling()
        refresh()
        return
      }
    } catch (e) {
      if (generation !== jobPollGeneration) return
      logText.value = `${logText.value === t('common.loading') ? '' : logText.value || ''}\n⚠ ${finiteText(e.message || e)}`.trim()
    }
    if (generation === jobPollGeneration) jobTimer = setTimeout(poll, 1500)
  }
  void poll()
}

function closeJobLog() {
  logOpen.value = false
  curJob.value = null
  managedLogGeneration += 1
  stopJobPolling()
}

onMounted(() => {
  pageAlive = true
  loadManaged()
  loadCatalog()
  // The first load counts as user-initiated: with no stacks fetched yet there
  // is no stale-but-usable list on screen, so the failure must say something.
  refresh(true)
  // startVisibleInterval also refreshes the moment the tab becomes visible
  // again, so returning to the page does not show up-to-15s-stale data.
  timer = startVisibleInterval(() => {
    if (tab.value === 'managed') return loadManaged(false)
  }, 15000)
})
onUnmounted(() => {
  pageAlive = false
  managedGeneration += 1
  appsDataGeneration += 1
  // closeDetail / closeJobLog bump their own generations.  Leave used to
  // invalidate only the list/catalog counters, so a late getManagedAppDetail
  // / saveAppCredential / getManagedAppLogs still wrote into the unmounted
  // drawer and log modal.
  closeDetail()
  closeJobLog()
  if (timer) timer()
  stopJobPolling()
  for (const id of refreshTimers) clearTimeout(id)
  refreshTimers.clear()
  // Stop the scheduled poll and invalidate any request already in flight so a
  // late response cannot update this unmounted page or schedule another poll.
  stopCfLoginPolling()
})


// Escape dismisses each dialog, focus returns to whatever opened it, and Tab
// cannot wander to the page behind the overlay.
useDismissable(installTpl, () => { installTpl.value = null }, installPanel)
useDismissable(logOpen, closeJobLog, logPanel)
useDismissable(remoteModal, () => { remoteModal.value = false }, remotePanel)

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
      ellipsis, e.g. "FileBrows er (nat…".) */
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

/* Uniform chips — same height/padding/radius for native/recommended/installed */
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

/* Mixed toward --txt like the branded chips below:
   the raw --ok on its own 16% tint is ~2:1 for this 10px text. */
.chip-native {
  background: color-mix(in srgb, var(--ok) 16%, var(--card));
  border-color: color-mix(in srgb, var(--ok) 40%, var(--line));
  /* var(--ok) on its own 16% tint is 1.9:1 — the least legible text in the
     panel. --ok-text keeps the green reading as "native" on both palettes
     while clearing WCAG AA. */
  color: var(--ok-text);
}

/* Brand-hue inks mixed toward --txt, like the --*-text tokens in styles.css:
   the literal inks these shipped with (#1a6fb0 / #b45309 / #7c4fe0) were
   darkened for light cards only — on the dark themes they measured 1.7-3.0:1,
   and the per-theme #7ec8ff override that patched .chip-docker also applied
   in *light* system mode (1.7:1 on white). The percentages are the largest
   that clear 4.5:1 on the chip's own tint in every theme
   (theme/contrast.test.js measures them). */
.chip-docker {
  background: color-mix(in srgb, #2496ed 12%, var(--card));
  border-color: color-mix(in srgb, #2496ed 35%, var(--line));
  color: color-mix(in srgb, #2496ed 50%, var(--txt));
}

.chip-launchd {
  background: color-mix(in srgb, #d97706 12%, var(--card));
  border-color: color-mix(in srgb, #d97706 35%, var(--line));
  color: color-mix(in srgb, #d97706 50%, var(--txt));
}

.chip-feat {
  background: color-mix(in srgb, var(--accent) 14%, var(--card));
  border-color: color-mix(in srgb, var(--accent) 40%, var(--line));
  /* The ink sized for a 14% accent wash; raw --accent-hover is 2.8-4.2:1 on
     this tint in eight of the eleven palettes. */
  color: var(--on-accent-wash);
}

.chip-remote {
  background: color-mix(in srgb, #8b5cf6 14%, var(--card));
  border-color: color-mix(in srgb, #8b5cf6 40%, var(--line));
  color: color-mix(in srgb, #8b5cf6 45%, var(--txt));
}

.chip-ok {
  background: color-mix(in srgb, var(--ok) 16%, var(--card));
  border-color: color-mix(in srgb, var(--ok) 40%, var(--line));
  color: var(--ok-text);
}

.chip-muted {
  background: var(--btn);
  border-color: var(--line);
  color: var(--sub);
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
  max-width: min(560px, 100%);
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

/* Red, not amber: elevated-access directives in a remote template deserve a
   louder tone than ordinary install notes. */
.tpl-danger {
  font-size: 12px;
  color: var(--down-text);
  background: color-mix(in srgb, var(--down) 10%, var(--card));
  border-left: 3px solid var(--down);
  padding: 8px 10px;
  margin: 0 0 10px;
  line-height: 1.5;
  word-break: break-word;
}

.tpl-danger strong {
  display: block;
  margin-bottom: 2px;
}

.first-run-creds {
  margin-top: 10px;
}

.first-run-creds .mono {
  display: block;
  font-size: 14px;
  font-weight: 700;
  margin: 2px 0;
  user-select: all;
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
  background: var(--accent-fill);
  border-color: var(--accent-fill);
  color: var(--on-accent);
}

.act-btn.danger {
  background: color-mix(in srgb, var(--down) 12%, var(--card));
  border-color: color-mix(in srgb, var(--down) 45%, var(--line));
  color: var(--down-text);
  font-weight: 700;
}

.act-btn.link {
  /* --accent-text, not the raw hover hue: as ink on --card the hover step is
     still 2.7-4.2:1 in most themes (styles.css sizes the tint per palette). */
  color: var(--accent-text);
}

.act-btn:disabled {
  opacity: 0.4;
  cursor: not-allowed;
}

.auto-toggle {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  font-size: 12px;
  color: var(--txt);
  user-select: none;
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
  width: min(480px, 100%);
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

@media (max-width: 640px) {
  .act-row { flex-wrap: wrap; }
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
  .apps-toolbar .search { min-width: 0; flex: 1 1 140px; max-width: none; }
  .cat-select { min-width: 0; }
  .actions-cell { min-width: 0; max-width: none; }
  .managed-table th, .managed-table td { white-space: normal; overflow-wrap: anywhere; }
  .install-modal { max-width: 100%; }
  .credential-grid { grid-template-columns: 1fr; gap: 4px; }
  .credential-grid label { margin-top: 4px; }
  .credential-password-input { grid-template-columns: 1fr 1fr; }
  .credential-password-input input { grid-column: 1 / -1; }
}
</style>
