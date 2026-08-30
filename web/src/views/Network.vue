<template>
  <div>
    <!-- No visible page title on this layout; see Dashboard.vue. -->
    <h1 class="sr-only">{{ t('network.title') }}</h1>
    <div class="tabs">
      <button :class="{ active: tab==='switch' }" :aria-pressed="tab === 'switch'" @click="tab='switch'">{{ t('network.tab_switch') }}</button>
      <button :class="{ active: tab==='ifaces' }" :aria-pressed="tab === 'ifaces'" @click="tab='ifaces'">{{ t('network.tab_ifaces') }}</button>
      <button :class="{ active: tab==='ip' }" :aria-pressed="tab === 'ip'" @click="tab='ip'">{{ t('network.tab_ip') }}</button>
      <button :class="{ active: tab==='dns' }" :aria-pressed="tab === 'dns'" @click="tab='dns'">{{ t('network.tab_dns') }}</button>
      <button :class="{ active: tab==='ports' }" :aria-pressed="tab === 'ports'" @click="tab='ports'">{{ t('network.tab_ports') }}</button>
      <button :class="{ active: tab==='routes' }" :aria-pressed="tab === 'routes'" @click="tab='routes'">{{ t('network.tab_routes') }}</button>
      <button :class="{ active: tab==='docker' }" :aria-pressed="tab === 'docker'" @click="tab='docker'">{{ t('network.tab_docker') }}</button>
    </div>

    <div class="toolbar">
      <button class="primary" @click="refresh(true)" :disabled="loading">{{ t('common.refresh') }}</button>
      <span class="meta" style="color:var(--sub)" v-if="data?.default_route">
        {{ t('network.default_gw', { gw: finiteText(data.default_route.gateway), iface: finiteText(data.default_route.interface) }) }}
      </span>
    </div>

    <!-- /api/system/network runs `networksetup` per configured service and a
         `docker network inspect` per network, so the first response is one of the
         slowest in the app. Every tab below reads the same `data` object, so all
         seven were simultaneously asserting "no addresses" / "no services" /
         "no published ports" for the whole wait. One latch covers them all. -->
    <LoadFailure v-if="loadError" :detail="loadError" :retry="refresh" :busy="loading" />
    <SkeletonLoader v-if="!loaded" :cols="6" :rows="7" />

    <template v-else>
    <!-- Mobile-friendly network status summary -->
    <div class="net-summary" v-if="data">
      <div class="net-summary-item">
        <span class="net-summary-label">{{ t('network.sum_egress') }}</span>
        <span class="net-summary-value">{{ finiteText(data.default_route?.interface) }}</span>
      </div>
      <div class="net-summary-item">
        <span class="net-summary-label">{{ t('network.sum_gateway') }}</span>
        <span class="net-summary-value mono">{{ finiteText(data.default_route?.gateway) }}</span>
      </div>
      <div class="net-summary-item">
        <span class="net-summary-label">{{ t('network.sum_services') }}</span>
        <span class="net-summary-value">{{ t('network.sum_active_n', { n: asServiceList(data.services).filter(s => !s.disabled).length }) }}</span>
      </div>
      <div class="net-summary-item">
        <span class="net-summary-label">{{ t('network.sum_listening') }}</span>
        <span class="net-summary-value">{{ t('network.sum_ports_n', { n: asArray(data.listening).length }) }}</span>
      </div>
    </div>

    <pre v-if="msg" class="msg-box" role="status" aria-live="polite">{{ finiteText(msg) }}</pre>

    <!-- Switch profile + multi-IP bindings -->
    <template v-if="tab==='switch'">
      <div class="tile" style="margin-bottom:12px;border-left:3px solid var(--accent)">
        <h2 style="margin:0 0 6px">{{ t('network.switch_title') }}</h2>
        <p style="margin:0;font-size:12px;color:var(--sub);line-height:1.55">
          {{ t('network.wifi_switch_hint1') }}
          <code>networksetup</code> {{ t('network.wifi_switch_hint2') }}
        </p>
        <div class="btns" style="margin-top:10px">
          <button class="primary" :disabled="busy" @click="applyProfile('ethernet')">{{ t('network.prefer_ethernet') }}</button>
          <button :disabled="busy" @click="applyProfile('wifi')">{{ t('network.prefer_wifi') }}</button>
          <button :disabled="busy" @click="applyProfile('ethernet_only')">{{ t('network.ethernet_only') }}</button>
          <button :disabled="busy" @click="applyProfile('wifi_only')">{{ t('network.wifi_only') }}</button>
        </div>
        <div class="sub" style="margin-top:8px" v-if="data?.default_route">
          {{ t('network.current_egress', { iface: finiteText(data.default_route.interface) }) }}
          · {{ t('network.gateway_is', { gw: finiteText(data.default_route.gateway) }) }}
        </div>
      </div>

      <div class="tile" style="margin-bottom:12px;border-left:3px solid var(--ok)">
        <div class="row" style="margin-bottom:8px;align-items:center;gap:10px;flex-wrap:wrap">
          <h2 style="margin:0;flex:1">{{ t('network.failover_title') }}</h2>
          <span class="badge" :class="data?.network_failover?.state?.mode === 'wired' ? 'ok' : 'warn'">
            {{ failoverModeLabel }}
          </span>
          <button class="tiny primary" :disabled="busy" @click="runFailover">{{ t('network.check_now') }}</button>
        </div>
        <p style="margin:0 0 8px;font-size:12px;color:var(--sub);line-height:1.5">
          {{ t('network.failover_hint1') }}
          {{ t('network.failover_hint2') }}
        </p>
        <div style="font-size:12px;line-height:1.6" v-if="data?.network_failover">
          <span>{{ t('network.policy_is', { state: data.network_failover.config?.enabled ? t('network.enabled_state') : t('network.disabled_state') }) }}</span>
          <span> · {{ t('network.wifi_is', { state: failoverWifiLabel }) }}</span>
          <span v-if="finiteText(data.network_failover.state?.last_check_at, '')"> · {{ t('network.last_check', { at: finiteText(data.network_failover.state.last_check_at) }) }}</span>
          <span v-if="finiteText(data.network_failover.state?.last_action, '')"> · {{ t('network.last_action', { action: finiteText(data.network_failover.state.last_action) }) }}</span>
        </div>
      </div>

      <div
        class="tile"
        style="margin-bottom:12px;border-left:3px solid var(--accent)"
        v-if="data?.wstunnel?.configured || data?.wstunnel?.running"
      >
        <div class="row" style="margin-bottom:8px;align-items:center;gap:10px;flex-wrap:wrap">
          <h2 style="margin:0;flex:1">{{ t('network.wstunnel_title') }}</h2>
          <span class="badge" :class="data.wstunnel.running ? 'ok' : 'warn'">
            {{ data.wstunnel.running ? t('common.running') : t('common.off') }}
          </span>
          <span v-if="data.wstunnel.stale_restrict" class="badge warn">{{ t('wg.wstunnel_stale') }}</span>
          <span v-else-if="data.wstunnel.stable_restrict === false" class="badge warn">{{ t('wg.wstunnel_unstable') }}</span>
          <span v-else-if="data.wstunnel.aligned === false" class="badge warn">{{ t('wg.wstunnel_mismatch') }}</span>
          <router-link class="tiny primary" to="/wireguard">{{ t('network.wstunnel_open') }}</router-link>
        </div>
        <p style="margin:0 0 8px;font-size:12px;color:var(--sub);line-height:1.5">
          {{ t('network.wstunnel_hint') }}
        </p>
        <div style="font-size:12px;line-height:1.6">
          <div>
            {{ t('network.wstunnel_listen') }}
            <code>{{ finiteText(data.wstunnel.listen) }}</code>
          </div>
          <div>
            {{ t('network.wstunnel_public') }}
            <code>{{ finiteText(data.wstunnel.public) }}</code>
          </div>
          <div>
            {{ t('network.wstunnel_restrict') }}
            <code>{{ finiteText(data.wstunnel.restrict_to) }}</code>
          </div>
          <div v-if="data.wstunnel.client_command" class="mono" style="margin-top:6px;font-size:11px;word-break:break-all">
            {{ finiteText(data.wstunnel.client_command) }}
          </div>
        </div>
      </div>

      <h2 class="section-title">{{ t('network.prio_title') }}</h2>
      <div class="table-wrap" style="margin-bottom:14px">
        <table class="dense fit-m">
          <thead>
            <tr><th class="col-hide-m">#</th><th>{{ t('network.th_service') }}</th><th class="col-hide-m">{{ t('network.th_device') }}</th><th class="col-hide-m">{{ t('network.th_status') }}</th><th class="col-hide-m">{{ t('network.th_mode_ip') }}</th><th>{{ t('network.th_ops') }}</th></tr>
          </thead>
          <tbody>
            <tr v-for="(s, idx) in asArray(orderList)" :key="s.name">
              <td class="mono col-hide-m">{{ idx + 1 }}</td>
              <td>
                <strong>{{ finiteText(s.name) }}</strong>
                <span v-if="s.disabled" class="badge down">{{ t('network.act_disable') }}</span>
                <span v-if="isWifi(s)" class="badge accent">{{ t('network.badge_wifi') }}</span>
                <span v-else-if="looksEthernet(s)" class="badge ok">{{ t('network.badge_wired') }}</span>
                <div class="show-m sub mono">{{ finiteText(s.device) }} · {{ t(priorityStatusKey(s)) }}</div>
                <div class="show-m sub mono">{{ finiteText(s.mode) }} {{ finiteText(s.ip, '') }}</div>
              </td>
              <td class="mono col-hide-m">{{ finiteText(s.device) }}</td>
              <td class="col-hide-m">{{ t(priorityStatusKey(s)) }}</td>
              <td class="mono col-hide-m" style="font-size:11px">{{ finiteText(s.mode) }} {{ finiteText(s.ip, '') }}</td>
              <td class="ops">
                <button class="tiny" :disabled="busy || idx===0" @click="moveService(idx, -1)" :aria-label="t('network.move_up')">↑</button>
                <button class="tiny" :disabled="busy || idx===asArray(orderList).length-1" @click="moveService(idx, 1)" :aria-label="t('network.move_down')">↓</button>
                <button class="tiny" :disabled="busy" @click="toggleService(s)">{{ s.disabled ? t('network.act_enable') : t('network.act_disable') }}</button>
                <template v-if="isWifi(s)">
                  <button class="tiny" :disabled="busy" @click="wifi('on')">{{ t('network.wifi_on') }}</button>
                  <button class="tiny danger" :disabled="busy" @click="wifi('off')">{{ t('network.wifi_off') }}</button>
                </template>
              </td>
            </tr>
            <tr v-if="!asArray(orderList).length && !loadError">
              <td colspan="6" class="empty-row">{{ finiteText(data?.services_error, '') || t('network.empty_services') }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <div class="toolbar">
        <button class="primary" :disabled="busy" @click="saveOrder">{{ t('network.save_order') }}</button>
        <button :disabled="busy" @click="resetOrderFromData">{{ t('network.reset_unsaved') }}</button>
      </div>

      <h2 class="section-title">{{ t('network.bind_title') }}</h2>
      <div class="tile" style="margin-bottom:10px;border-left:3px solid var(--warn)">
        <p style="margin:0;font-size:12px;color:var(--sub);line-height:1.5">
          <code>&lt;alias-ip&gt;/32</code> {{ t('network.alias_hint1') }}
          {{ t('network.alias_hint2') }}
        </p>
      </div>

      <!-- Auto-bind aliases to preferred active NIC -->
      <div class="tile" style="margin-bottom:12px;border-left:3px solid var(--accent)">
        <div class="row" style="margin-bottom:8px;align-items:center;gap:10px;flex-wrap:wrap">
          <h3 style="margin:0;flex:1">{{ t('network.autobind_title') }}</h3>
          <label style="font-size:12px;color:var(--sub);display:flex;align-items:center;gap:6px">
            <input type="checkbox" v-model="autoBindOn" :disabled="busy" @change="saveAutoBind" /> {{ t('network.autobind_on') }}
          </label>
          <button class="tiny primary" :disabled="busy" @click="runAutoBind">{{ t('network.align_now') }}</button>
        </div>
        <p style="margin:0 0 8px;font-size:12px;color:var(--sub);line-height:1.5">
          {{ t('network.autobind_hint1') }}
          {{ t('network.autobind_hint2') }}
        </p>
        <div v-if="data?.alias_auto" style="font-size:12px;line-height:1.6">
          <div>
            {{ t('network.preferred_iface') }}
            <strong class="mono" v-if="data.alias_auto.preferred">
              {{ finiteText(data.alias_auto.preferred.device) }}
            </strong>
            <span v-else style="color:var(--down-text)">{{ t('network.no_network') }}</span>
            <span v-if="data.alias_auto.preferred" style="color:var(--sub)">
              · {{ finiteText(data.alias_auto.preferred.service) }}
              · {{ t('network.primary_ip_is', { ip: finiteText(data.alias_auto.preferred.primary_ip) }) }}
            </span>
          </div>
          <div style="margin-top:6px">
            {{ t('network.managed_aliases') }}
            <span v-for="(ip, i) in asArray(data.alias_auto.config?.ips)" :key="ip" class="badge" style="margin-right:4px"
              :class="asArray(data.alias_auto.ips).find(x=>x.ip===ip)?.on_preferred ? 'ok' : 'warn'"
            >{{ finiteText(ip) }}</span>
            <span v-if="!asArray(data.alias_auto.config?.ips).length" style="color:var(--sub)">{{ t('network.not_configured') }}</span>
          </div>
          <div class="field-grid" style="margin-top:10px">
            <label>{{ t('network.alias_list') }}</label>
            <input v-model="autoIpsText" type="text" :placeholder="t('network.alias_list_ph')" style="width:100%"  :aria-label="t('network.alias_list_ph')"/>
          </div>
          <div class="btns" style="margin-top:8px">
            <button class="tiny" :disabled="busy" @click="saveAutoIps">{{ t('network.save_list') }}</button>
          </div>
          <pre v-if="autoBindLog" class="log-pre" style="margin-top:8px;max-height:100px" role="status" aria-live="polite">{{ finiteText(autoBindLog) }}</pre>
        </div>
      </div>
      <div class="table-wrap" style="margin-bottom:12px">
        <table class="dense fit-m">
          <thead>
            <tr><th>{{ t('network.th_nic') }}</th><th>{{ t('network.th_status') }}</th><th>IP</th><th class="col-hide-m">{{ t('network.th_mask') }}</th><th class="col-hide-m">{{ t('network.th_type') }}</th><th>{{ t('network.th_ops') }}</th></tr>
          </thead>
          <tbody>
            <template v-for="iface in asArray(data?.interface_addresses)" :key="iface.device">
              <tr v-for="(a, ai) in asArray(iface.addresses)" :key="iface.device + a.ip + ai">
                <td class="mono" v-if="ai===0" :rowspan="Math.max(1, asArray(iface.addresses).length)">
                  <strong>{{ finiteText(iface.device) }}</strong>
                </td>
                <td v-if="ai===0" :rowspan="Math.max(1, asArray(iface.addresses).length)">
                  <!-- The LED is the whole status column here (the interfaces tab
                       pairs its LED with a textual badge); colour alone says
                       nothing to a screen reader, so spell the state. -->
                  <span class="led" :class="iface.up ? 'on' : 'off'" aria-hidden="true"></span>
                  <span class="sr-only">{{ iface.up ? t('network.on') : t('network.off') }}</span>
                </td>
                <td class="mono">
                  <strong>{{ finiteText(a.ip) }}</strong>
                  <div class="show-m sub">{{ finiteText(a.netmask) }} · {{ a.alias ? t('network.badge_alias') : t('network.badge_primary') }}</div>
                </td>
                <td class="mono col-hide-m">{{ finiteText(a.netmask) }}</td>
                <td class="col-hide-m">
                  <span class="badge" :class="a.alias ? 'warn' : 'ok'">{{ a.alias ? t('network.badge_alias') : t('network.badge_primary') }}</span>
                </td>
                <td class="ops">
                  <button
                    v-if="a.alias"
                    class="tiny danger"
                    :disabled="busy"
                    @click="removeAlias(iface.device, a.ip)"
                  >{{ t('network.del_alias') }}</button>
                  <button
                    v-else
                    class="tiny"
                    :disabled="busy"
                    @click="openPrimaryEdit(iface.device, a)"
                  >{{ t('network.edit_primary') }}</button>
                </td>
              </tr>
              <tr v-if="!asArray(iface.addresses).length" :key="iface.device+'-empty'">
                <td class="mono"><strong>{{ finiteText(iface.device) }}</strong></td>
                <td>
                  <span class="led" :class="iface.up ? 'on' : 'off'" aria-hidden="true"></span>
                  <span class="sr-only">{{ iface.up ? t('network.on') : t('network.off') }}</span>
                </td>
                <td colspan="3" class="empty-row">{{ t('network.no_ipv4') }}</td>
                <td></td>
              </tr>
            </template>
            <tr v-if="!asArray(data?.interface_addresses).length && !loadError">
              <td colspan="6" class="empty-row">{{ t('network.no_bindings') }}</td>
            </tr>
          </tbody>
        </table>
      </div>

      <div class="tile">
        <h3 style="margin-top:0">{{ t('network.add_alias_title') }}</h3>
        <div class="field-grid">
          <label>{{ t('network.th_nic') }}</label>
          <select v-model="aliasForm.device" :aria-label="t('network.th_nic')">
            <option v-for="i in asArray(deviceOptions)" :key="i" :value="i">{{ finiteText(i) }}</option>
          </select>
          <label>IP</label>
          <input v-model="aliasForm.ip" type="text" :placeholder="t('network.alias_ip_ph')"  :aria-label="t('network.alias_ip_ph')"/>
          <label>{{ t('network.mask') }}</label>
          <input v-model="aliasForm.netmask" type="text" placeholder="255.255.255.255" :aria-label="t('network.mask')" />
        </div>
        <p style="font-size:11px;color:var(--sub);margin:8px 0">
          {{ t('network.alias_mask_hint') }}
          <code>sudo ifconfig &lt;{{ t('network.alias_mask_cmd_nic') }}&gt; alias &lt;IP&gt; netmask 255.255.255.255</code>
        </p>
        <div class="btns">
          <button class="primary" :disabled="busy || !aliasForm.ip.trim()" @click="addAlias">{{ t('network.add_binding') }}</button>
        </div>
      </div>
    </template>

    <!-- Interfaces -->
    <template v-else-if="tab==='ifaces'">
      <div class="table-wrap">
        <table class="dense fit-m">
          <thead>
            <tr>
              <th><span class="sr-only">{{ t('common.status_led') }}</span></th><th>{{ t('network.iface') }}</th><th>{{ t('common.status') }}</th><th>IPv4</th><th class="col-hide-m">{{ t('network.mask') }}</th><th class="col-hide-m">IPv6</th><th class="col-hide-m">MAC</th><th class="col-hide-m">MTU</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="i in asArray(data?.interfaces)" :key="i.name">
              <!-- The Status column next to it spells the state in text, so
                   the LED is decoration here; without aria-hidden a screen
                   reader met a column named "status LED" whose cells said
                   nothing (the bindings table pairs its LED with sr-only text
                   because there the LED is the whole status column). -->
              <td><span class="led" :class="i.up ? 'on' : 'off'" aria-hidden="true"></span></td>
              <td>
                <strong>{{ finiteText(i.name) }}</strong>
                <div class="show-m sub mono">{{ finiteText(i.mac) }}{{ finiteN(i.mtu, null) != null ? ' · MTU ' + finiteN(i.mtu) : '' }}</div>
                <div v-if="asArray(i.ipv6).length" class="show-m sub mono">{{ asArray(i.ipv6).slice(0,2).map(n => finiteText(n, '')).filter(Boolean).join(', ') }}</div>
              </td>
              <td><span class="badge" :class="i.up ? 'ok' : ''">{{ finiteText(i.status, '') || (i.up ? 'up' : 'down') }}</span></td>
              <td class="mono">
                <div v-for="(a,idx) in asArray(i.ipv4)" :key="idx">{{ finiteText(a.ip) }}</div>
                <span v-if="!asArray(i.ipv4).length">—</span>
              </td>
              <td class="mono col-hide-m">
                <div v-for="(a,idx) in asArray(i.ipv4)" :key="'m'+idx">{{ finiteText(a.netmask) }}</div>
              </td>
              <td class="mono col-hide-m" style="font-size:10px">{{ asArray(i.ipv6).slice(0,2).map(n => finiteText(n, '')).filter(Boolean).join(', ') }}</td>
              <td class="mono col-hide-m">{{ finiteText(i.mac) }}</td>
              <td class="mono col-hide-m">{{ finiteN(i.mtu) }}</td>
            </tr>
            <tr v-if="!asArray(data?.interfaces).length && !loadError">
              <td colspan="8" class="empty-row">{{ t('network.no_interfaces') }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </template>

    <!-- IP / networksetup services -->
    <template v-else-if="tab==='ip'">
      <div class="tile" style="margin-bottom:10px;border-left:3px solid var(--accent)">
        <p style="margin:0;font-size:12px;color:var(--sub);line-height:1.5">
          {{ t('network.ip_hint') }}
        </p>
      </div>
      <div class="table-wrap">
        <table class="dense fit-m">
          <thead>
            <tr>
              <th>{{ t('network.service') }}</th><th class="col-hide-m">{{ t('network.device') }}</th><th class="col-hide-m">{{ t('network.mode') }}</th><th>IP</th><th class="col-hide-m">{{ t('network.mask') }}</th><th class="col-hide-m">{{ t('network.gateway') }}</th><th class="col-hide-m">DNS</th><th>{{ t('network.ops') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="s in asServiceList(data?.services)" :key="s.name">
              <td>
                <strong>{{ finiteText(s.name) }}</strong>
                <span v-if="s.disabled" class="badge down">{{ t('network.disabled') }}</span>
                <div class="show-m sub">{{ finiteText(s.mode) }}{{ finiteText(s.device, '') ? ' · ' + finiteText(s.device) : '' }}{{ finiteText(s.router, '') ? ' · ' + finiteText(s.router) : '' }}</div>
                <div v-if="asArray(s.dns).length" class="show-m sub mono">{{ asArray(s.dns).map(n => finiteText(n, '')).filter(Boolean).join(', ') }}</div>
              </td>
              <td class="mono col-hide-m">{{ finiteText(s.device) }}</td>
              <td class="col-hide-m"><span class="badge" :class="s.mode==='manual'?'warn':(s.mode==='dhcp'?'ok':'')">{{ finiteText(s.mode) }}</span></td>
              <td class="mono">{{ finiteText(s.ip) }}</td>
              <td class="mono col-hide-m">{{ finiteText(s.subnet) }}</td>
              <td class="mono col-hide-m">{{ finiteText(s.router) }}</td>
              <td class="mono col-hide-m" style="font-size:11px">{{ asArray(s.dns).map(n => finiteText(n, '')).filter(Boolean).join(', ') }}</td>
              <td class="ops">
                <button class="tiny" :disabled="busy || s.disabled" @click="openManual(s)">{{ t('network.edit_ip') }}</button>
                <button class="tiny" :disabled="busy || s.disabled" @click="setDhcp(s)">{{ t('network.act_dhcp') }}</button>
                <button class="tiny" :disabled="busy || s.disabled" @click="openDns(s)">{{ t('network.tab_dns') }}</button>
                <template v-if="isWifi(s)">
                  <button class="tiny" :disabled="busy" @click="wifi('on')">{{ t('network.wifi_on') }}</button>
                  <button class="tiny danger" :disabled="busy" @click="wifi('off')">{{ t('network.wifi_off') }}</button>
                </template>
              </td>
            </tr>
            <tr v-if="!asServiceList(data?.services).length && !loadError">
              <td colspan="8" class="empty-row">{{ finiteText(data?.services_error, '') || t('network.empty_services') }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </template>

    <!-- DNS lookup -->
    <template v-else-if="tab==='dns'">
      <div class="toolbar">
        <input v-model="lookupHost" type="text" :placeholder="t('network.host_ph')" style="min-width:200px" @keyup.enter="doLookup"  :aria-label="t('network.host_ph')"/>
        <button class="primary" :disabled="busy || !lookupHost.trim()" @click="doLookup">{{ t('network.resolve') }}</button>
      </div>
      <div class="tile" v-if="lookupResult">
        <div><strong>{{ finiteText(lookupResult.host) }}</strong>
          <span class="badge" :class="lookupResult.ok?'ok':'down'">{{ lookupResult.ok ? t('common.ok') : t('common.fail') }}</span>
        </div>
        <div class="mono" style="margin-top:8px" v-for="(a,i) in asArray(lookupResult.answers)" :key="i">{{ finiteText(a) }}</div>
        <pre v-if="!asArray(lookupResult.answers).length && lookupResult.message" class="msg-box" style="margin-top:8px" role="status" aria-live="polite">{{ finiteText(lookupResult.message) }}</pre>
      </div>
      <h2 class="section-title">{{ t('network.dns_per_svc') }}</h2>
      <div class="table-wrap">
        <table class="dense fit-m">
          <thead><tr><th>{{ t('network.service') }}</th><th>{{ t('network.dns_servers') }}</th><th class="col-hide-m">{{ t('network.search_domains') }}</th><th><span class="sr-only">{{ t('common.actions') }}</span></th></tr></thead>
          <tbody>
            <tr v-for="s in asServiceList(data?.services)" :key="s.name">
              <td>
                <strong>{{ finiteText(s.name) }}</strong>
                <div v-if="asArray(s.search_domains).length" class="show-m sub mono">{{ asArray(s.search_domains).map(n => finiteText(n, '')).filter(Boolean).join(', ') }}</div>
              </td>
              <td class="mono">{{ asArray(s.dns).map(n => finiteText(n, '')).filter(Boolean).join(', ') || t('network.system_default') }}</td>
              <td class="mono col-hide-m">{{ asArray(s.search_domains).map(n => finiteText(n, '')).filter(Boolean).join(', ') }}</td>
              <td><button class="tiny" @click="openDns(s)">{{ t('network.edit') }}</button></td>
            </tr>
            <tr v-if="!asServiceList(data?.services).length && !loadError">
              <td colspan="4" class="empty-row">{{ finiteText(data?.services_error, '') || t('network.empty_services') }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </template>

    <!-- Listening -->
    <template v-else-if="tab==='ports'">
      <div class="toolbar">
        <input v-model="portQ" type="text" :placeholder="t('network.filter_port')" style="min-width:160px"  :aria-label="t('network.filter_port')"/>
        <!-- role=status: the count is the only feedback the filter box gives,
             and it changed silently for a screen reader. Same pattern as the
             Services filter count. -->
        <span class="meta-count" role="status">{{ asArray(filteredListen).length }} / {{ asArray(data?.listening).length }}</span>
      </div>
      <div class="table-wrap">
        <table class="dense fit-m">
          <thead><tr><th>{{ t('network.process') }}</th><th class="col-hide-m">PID</th><th class="col-hide-m">{{ t('tools.user') }}</th><th class="col-hide-m">{{ t('network.address') }}</th><th>{{ t('network.port') }}</th></tr></thead>
          <tbody>
            <tr v-for="(p,i) in asArray(filteredListen)" :key="i">
              <td>
                <strong>{{ finiteText(p.process) }}</strong>
                <div class="show-m sub">{{ finiteText(p.user) }} · {{ finiteN(p.pid) }} · {{ finiteText(p.address) }}</div>
              </td>
              <td class="mono col-hide-m">{{ finiteN(p.pid) }}</td>
              <td class="col-hide-m">{{ finiteText(p.user) }}</td>
              <td class="mono col-hide-m">{{ finiteText(p.address) }}</td>
              <td class="mono">{{ finiteN(p.port) }}</td>
            </tr>
            <tr v-if="!asArray(filteredListen).length && !loadError">
              <td colspan="5" class="empty-row">{{ portQ.trim() ? t('common.no_match') : t('network.no_listening') }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </template>

    <!-- Routes -->
    <template v-else-if="tab==='routes'">
      <div class="table-wrap">
        <table class="dense fit-m">
          <thead><tr><th>{{ t('network.destination') }}</th><th>{{ t('network.gateway') }}</th><th class="col-hide-m">Flags</th><th>{{ t('network.iface') }}</th></tr></thead>
          <tbody>
            <tr v-for="(r,i) in asArray(data?.routes)" :key="i">
              <td class="mono">
                {{ finiteText(r.destination) }}
                <div v-if="r.flags" class="show-m sub">{{ finiteText(r.flags) }}</div>
              </td>
              <td class="mono">{{ finiteText(r.gateway) }}</td>
              <td class="mono col-hide-m">{{ finiteText(r.flags) }}</td>
              <td>{{ finiteText(r.netif) }}</td>
            </tr>
            <tr v-if="!asArray(data?.routes).length && !loadError">
              <td colspan="4" class="empty-row">{{ t('network.no_routes') }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </template>

    <!-- Docker network -->
    <template v-else-if="tab==='docker'">
      <div v-if="data && data.engine_up === false" class="placeholder">{{ t('network.engine_off') }}</div>
      <template v-else-if="data && data.engine_up">
        <h2 class="section-title">{{ t('network.port_maps') }}</h2>
        <div class="toolbar">
          <input v-model="dockerPortQ" type="text" :placeholder="t('network.filter_ctr')" style="min-width:160px"  :aria-label="t('network.filter_ctr')"/>
          <!-- role=status: the count is the only feedback the filter box gives,
               and it changed silently for a screen reader. Same pattern as the
               Services filter count. -->
          <span class="meta-count" role="status">{{ asArray(filteredDockerPorts).length }} / {{ asArray(data?.docker_ports).length }}</span>
          <button @click="openPortEdit()" :disabled="busy">{{ t('network.edit_map') }}</button>
        </div>
        <div class="table-wrap" style="margin-bottom:14px">
          <table class="dense fit-m">
            <thead>
              <tr><th>{{ t('network.container') }}</th><th class="col-hide-m">{{ t('common.status') }}</th><th>{{ t('network.host') }}</th><th class="col-hide-m">→</th><th>{{ t('network.cport') }}</th><th class="col-hide-m">{{ t('network.proto') }}</th><th><span class="sr-only">{{ t('common.actions') }}</span></th></tr>
            </thead>
            <tbody>
              <tr v-for="(p,i) in asArray(filteredDockerPorts)" :key="i">
                <td>
                  <strong>{{ finiteText(p.container) }}</strong>
                  <div class="show-m sub">{{ finiteText(p.status) }} · {{ finiteText(p.protocol) }}</div>
                </td>
                <td class="col-hide-m" style="font-size:11px">{{ finiteText(p.status) }}</td>
                <td class="mono">{{ finiteText(p.host_ip) }}:{{ finiteN(p.host_port) }}</td>
                <td class="col-hide-m">→</td>
                <td class="mono">{{ finiteN(p.container_port) }}</td>
                <td class="col-hide-m">{{ finiteText(p.protocol) }}</td>
                <td class="ops">
                  <button class="tiny" :disabled="busy" @click="openPortEdit(p.container)">{{ t('network.change_port') }}</button>
                </td>
              </tr>
              <tr v-if="!asArray(filteredDockerPorts).length && !loadError">
                <!-- A filter miss and a host with no published ports are
                     different states; the listening tab already tells them
                     apart the same way. -->
                <td colspan="7" class="empty-row">{{ dockerPortQ.trim() ? t('common.no_match') : t('network.no_published') }}</td>
              </tr>
            </tbody>
          </table>
        </div>

        <h2 class="section-title">{{ t('network.docker_nets') }}</h2>
        <div class="table-wrap" style="margin-bottom:14px">
          <table class="dense fit-m">
            <thead>
              <tr><th>{{ t('common.name') }}</th><th class="col-hide-m">{{ t('docker.driver') }}</th><th>{{ t('network.subnet') }}</th><th class="col-hide-m">{{ t('network.gateway') }}</th><th class="col-hide-m">{{ t('network.container') }}</th><th>{{ t('network.ops') }}</th></tr>
            </thead>
            <tbody>
              <tr v-for="n in asArray(data?.docker_networks)" :key="n.id">
                <td>
                  <strong>{{ finiteText(n.name) }}</strong>
                  <div class="show-m sub">{{ finiteText(n.driver) }}{{ finiteText(n.gateway, '') ? ' · ' + finiteText(n.gateway) : '' }}</div>
                  <span v-if="n.builtin" class="badge">{{ t('network.builtin') }}</span>
                </td>
                <td class="col-hide-m">{{ finiteText(n.driver) }}</td>
                <td class="mono">{{ finiteText(n.subnet) }}</td>
                <td class="mono col-hide-m">{{ finiteText(n.gateway) }}</td>
                <td class="col-hide-m" style="font-size:11px">
                  <div v-for="c in asArray(n.containers).slice(0,6)" :key="c.id">
                    {{ finiteText(c.name, '') || finiteText(c.id) }} <span class="mono" style="color:var(--sub)">{{ finiteText(c.ipv4, '') }}</span>
                  </div>
                  <span v-if="!asArray(n.containers).length" style="color:var(--sub)">—</span>
                </td>
                <td class="ops">
                  <button class="tiny" :disabled="busy || n.builtin" @click="openConnect(n)">{{ t('network.connect') }}</button>
                  <button class="tiny" :disabled="busy || n.builtin" @click="openDisconnect(n)">{{ t('network.disconnect') }}</button>
                </td>
              </tr>
              <tr v-if="!asArray(data?.docker_networks).length && !loadError">
                <td colspan="6" class="empty-row">{{ t('network.empty_docker_nets') }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </template>
    </template>
    </template>

    <!-- Manual IP modal -->
    <div ref="manualPanel" v-if="manualSvc" class="modal-bg" @click.self="manualSvc=null" role="presentation">
      <div class="modal" style="max-width:440px" role="dialog" aria-modal="true" aria-labelledby="net-manual-title">
        <div class="row" style="margin-bottom:12px">
          <span id="net-manual-title" class="name">{{ t('network.static_ip') }} · {{ finiteText(manualSvc.name) }}</span>
          <button class="tiny" @click="manualSvc=null">{{ t('common.close') }}</button>
        </div>
        <div class="field-grid">
          <label>{{ t('network.ip_addr') }}</label>
          <input v-model="manualForm.ip" type="text" :placeholder="t('network.static_ip_ph')"  :aria-label="t('network.static_ip_ph')"/>
          <label>{{ t('network.subnet_mask') }}</label>
          <input v-model="manualForm.subnet" type="text" placeholder="255.255.255.0" :aria-label="t('network.subnet_mask')" />
          <label>{{ t('network.gateway') }}</label>
          <input v-model="manualForm.router" type="text" :placeholder="t('network.gateway_ph')"  :aria-label="t('network.gateway_ph')"/>
        </div>
        <p style="font-size:11px;color:var(--sub);margin:10px 0">{{ t('network.manual_hint') }}</p>
        <div class="btns">
          <button class="primary" :disabled="busy" @click="applyManual">{{ t('network.apply') }}</button>
          <button @click="manualSvc=null">{{ t('common.cancel') }}</button>
        </div>
      </div>
    </div>

    <!-- DNS modal -->
    <div ref="dnsPanel" v-if="dnsSvc" class="modal-bg" @click.self="dnsSvc=null" role="presentation">
      <div class="modal" style="max-width:440px" role="dialog" aria-modal="true" aria-labelledby="net-dns-title">
        <div class="row" style="margin-bottom:12px">
          <span id="net-dns-title" class="name">DNS · {{ finiteText(dnsSvc.name) }}</span>
          <button class="tiny" @click="dnsSvc=null">{{ t('common.close') }}</button>
        </div>
        <label style="font-size:12px;color:var(--sub)">{{ t('network.dns_ph') }}</label>
        <textarea v-model="dnsServers" rows="4" style="width:100%;margin:8px 0 12px;font-family:ui-monospace,Menlo,monospace;font-size:12px" :aria-label="t('network.dns_ph')"></textarea>
        <div class="btns">
          <button class="primary" :disabled="busy" @click="applyDns">{{ t('common.save') }}</button>
          <button @click="dnsSvc=null">{{ t('common.cancel') }}</button>
        </div>
      </div>
    </div>

    <!-- Docker port edit -->
    <div ref="portPanel" v-if="portEdit" class="modal-bg" @click.self="portEdit=null" role="presentation">
      <div class="modal" style="max-width:480px" role="dialog" aria-modal="true" aria-labelledby="net-port-title">
        <div class="row" style="margin-bottom:12px">
          <span id="net-port-title" class="name">{{ t('network.port_map') }} · {{ finiteText(portEdit) }}</span>
          <button class="tiny" @click="portEdit=null">{{ t('common.close') }}</button>
        </div>
        <p style="font-size:12px;color:var(--down-text);line-height:1.45;margin-bottom:8px">
          {{ t('network.recreate_hint') }}
        </p>
        <label style="font-size:12px;color:var(--sub)">{{ t('network.map_list') }}</label>
        <textarea v-model="portEditText" rows="5" style="width:100%;margin:8px 0 12px;font-family:ui-monospace,Menlo,monospace;font-size:12px" placeholder="4000:4000&#10;8080:80" :aria-label="t('network.map_list')"></textarea>
        <div class="btns">
          <button class="primary" :disabled="busy" @click="applyPorts">{{ t('network.recreate_apply') }}</button>
          <button @click="portEdit=null">{{ t('common.cancel') }}</button>
        </div>
      </div>
    </div>

    <!-- Connect / disconnect -->
    <div ref="connectPanel" v-if="connectNet" class="modal-bg" @click.self="connectNet=null" role="presentation">
      <div class="modal" style="max-width:400px" role="dialog" aria-modal="true" aria-labelledby="net-connect-title">
        <div class="row" style="margin-bottom:12px">
          <span id="net-connect-title" class="name">{{ connectMode==='connect'?t('network.connect_to'):t('network.disconnect_from') }} · {{ finiteText(connectNet.name) }}</span>
          <button class="tiny" @click="connectNet=null">{{ t('common.close') }}</button>
        </div>
        <label style="font-size:12px;color:var(--sub)">{{ t('network.ctr_name') }}</label>
        <input v-model="connectContainer" type="text" list="ctr-list" style="width:100%;margin:8px 0 12px" :placeholder="t('network.ctr_name')"  :aria-label="t('network.ctr_name')"/>
        <datalist id="ctr-list">
          <option v-for="c in asArray(containerNames)" :key="c" :value="c" />
        </datalist>
        <div class="btns">
          <button class="primary" :disabled="busy || !connectContainer.trim()" @click="applyConnect">{{ t('common.confirm') }}</button>
          <button @click="connectNet=null">{{ t('common.cancel') }}</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, inject, onMounted, onUnmounted, ref } from 'vue'
import {
  addNetworkAlias,
  connectContainerNetwork,
  getSystemNetwork,
  lookupNetworkDns,
  removeNetworkAlias,
  runAliasAutoBind,
  runNetworkFailover,
  setContainerPorts,
  setNetworkDhcp,
  setNetworkDns,
  setNetworkManual,
  setNetworkServiceEnabled,
  setNetworkServiceOrder,
  setWifiPower,
  switchNetworkProfile,
  updateAliasAuto,
} from '../api/client'
import { injectI18n } from '../i18n'
import { asArray, asRecord, finiteN, finiteText, jsonDump, jsonLoad, jsonText } from '../lib/finite'
import { useDismissable } from '../composables/useDismissable'
import SkeletonLoader from '../components/SkeletonLoader.vue'
import LoadFailure from '../components/LoadFailure.vue'

const toast = inject('toast')
const { t } = injectI18n()
const data = ref(null)
const loading = ref(false)
const loaded = ref(false)
const loadError = ref('')
const busy = ref(false)
const msg = ref('')
const tab = ref('switch')
const portQ = ref('')
const dockerPortQ = ref('')
const lookupHost = ref('')
const lookupResult = ref(null)
const orderList = ref([])

const manualSvc = ref(null)
const manualPanel = ref(null)
const manualForm = ref({ ip: '', subnet: '255.255.255.0', router: '' })
const dnsSvc = ref(null)
const dnsPanel = ref(null)
const dnsServers = ref('')
const portEdit = ref(null)
const portPanel = ref(null)
const portEditText = ref('')
const connectNet = ref(null)
const connectPanel = ref(null)
const connectMode = ref('connect')
const connectContainer = ref('')
const aliasForm = ref({ device: '', ip: '', netmask: '255.255.255.255' })
const autoBindOn = ref(true)
const autoIpsText = ref('')
const autoBindLog = ref('')
const refreshTimers = new Set()
let pageAlive = true

function scheduleRefresh(delay) {
  const generation = loadGeneration
  const id = setTimeout(() => {
    refreshTimers.delete(id)
    if (generation !== loadGeneration || !pageAlive) return
    void refresh(true)
  }, delay)
  refreshTimers.add(id)
}

function stillOnNetwork(generation) {
  return pageAlive && generation === loadGeneration
}

function mapNetwork(raw) {
  const row = asRecord(raw)
  const failover = asRecord(row.network_failover)
  const foState = asRecord(failover.state)
  const foResult = asRecord(foState.last_result)
  const alias = asRecord(row.alias_auto)
  const aliasCfg = asRecord(alias.config)
  return {
    ...row,
    listening: asArray(row.listening).map((p) => asRecord(p)),
    docker_ports: asArray(row.docker_ports).map((p) => asRecord(p)),
    docker_networks: asArray(row.docker_networks).map((n) => {
      const net = asRecord(n)
      return { ...net, containers: asArray(net.containers).map((c) => asRecord(c)) }
    }),
    interface_addresses: asArray(row.interface_addresses).map((iface) => {
      const rec = asRecord(iface)
      return { ...rec, addresses: asArray(rec.addresses).map((a) => asRecord(a)) }
    }),
    interfaces: asArray(row.interfaces).map((i) => {
      const rec = asRecord(i)
      return { ...rec, ipv4: asArray(rec.ipv4).map((a) => asRecord(a)) }
    }),
    services: asArray(row.services).map((s) => asRecord(s)),
    routes: asArray(row.routes).map((r) => asRecord(r)),
    default_route: asRecord(row.default_route),
    network_failover: {
      ...failover,
      state: {
        ...foState,
        last_result: { ...foResult, wifi: asRecord(foResult.wifi) },
      },
    },
    alias_auto: { ...alias, config: aliasCfg },
    wstunnel: asRecord(row.wstunnel),
    wifi_power: asRecord(row.wifi_power),
  }
}

const filteredListen = computed(() => {
  const q = portQ.value.trim().toLowerCase()
  const list = asArray(asRecord(data.value).listening).map((p) => asRecord(p))
  if (!q) return list
  return list.filter(p =>
    (p.process || '').toLowerCase().includes(q)
    || String(p.port).includes(q)
    || (p.address || '').toLowerCase().includes(q)
  )
})

const filteredDockerPorts = computed(() => {
  const q = dockerPortQ.value.trim().toLowerCase()
  const list = asArray(asRecord(data.value).docker_ports).map((p) => asRecord(p))
  if (!q) return list
  return list.filter(p =>
    (p.container || '').toLowerCase().includes(q)
    || String(p.host_port).includes(q)
    || String(p.container_port).includes(q)
  )
})

const containerNames = computed(() => {
  const s = new Set()
  for (const p of asArray(asRecord(data.value).docker_ports).map((p) => asRecord(p))) {
    if (p.container) s.add(p.container)
  }
  for (const n of asArray(asRecord(data.value).docker_networks).map((n) => asRecord(n))) {
    for (const c of asArray(n.containers).map((c) => asRecord(c))) {
      if (c.name) s.add(c.name)
    }
  }
  return [...s].sort()
})

const deviceOptions = computed(() => {
  return asArray(asRecord(data.value).interface_addresses).map((i) => asRecord(i).device)
})

const failoverModeLabel = computed(() => {
  const mode = asRecord(asRecord(asRecord(data.value).network_failover).state).mode
  return ({ wired: t('network.mode_wired'), wifi_backup: t('network.mode_wifi_backup'), waiting_for_failover: t('network.mode_waiting'), starting: t('network.mode_starting'), disabled: t('network.disabled_state') })[mode] || t('network.mode_pending')
})

const failoverWifiLabel = computed(() => {
  const result = asRecord(asRecord(asRecord(data.value).network_failover).state).last_result
  const on = asRecord(asRecord(result).wifi).on
  return on === true ? t('network.on') : (on === false ? t('network.off') : t('network.unknown'))
})

function isWifi(s) {
  const row = asRecord(s)
  return /wi-?fi|airport|无线/i.test((row.name || '') + (row.hardware_port || '')) // cjk-input: networksetup port names are localized
}
function looksEthernet(s) {
  if (isWifi(s)) return false
  const row = asRecord(s)
  const n = (row.name || '') + (row.hardware_port || '')
  const d = row.device || ''
  return /ethernet|lan|usb.*lan|有线/i.test(n) || (d.startsWith('en') && d !== 'en0') // cjk-input: networksetup port names are localized
}

function serviceHasIpv4(s) {
  const ip = String(asRecord(s).ip || '').trim()
  return Boolean(ip) && ip.toLowerCase() !== 'none'
}

function priorityStatusKey(s) {
  const row = asRecord(s)
  if (row.disabled) return 'network.off'
  if (isWifi(row)) {
    // Live radio from overview, not the last failover tick.
    if (asRecord(asRecord(data.value).wifi_power).on === false) return 'network.off'
    if (!serviceHasIpv4(row)) return 'network.no_ipv4'
  }
  return 'network.on'
}

function asServiceList(raw) {
  return asArray(raw).map((s) => asRecord(s))
}

function cloneServiceOrder(raw) {
  const list = asArray(raw).map((s) => asRecord(s))
  if (!list.length) return []
  try {
    const cloned = jsonLoad(jsonDump(list) || 'null')
    return asArray(cloned).map((s) => asRecord(s))
  } catch {
    return []
  }
}

function syncOrderFromData() {
  orderList.value = cloneServiceOrder(data.value?.services)
}
function resetOrderFromData() {
  syncOrderFromData()
  toast(t('network.reset_done'))
}
function moveService(idx, dir) {
  const j = idx + dir
  if (j < 0 || j >= asArray(orderList.value).length) return
  const arr = asArray(orderList.value).slice()
  const tmp = arr[idx]
  arr[idx] = arr[j]
  arr[j] = tmp
  orderList.value = arr
}

let loadGeneration = 0

async function refresh(force = false) {
  const generation = ++loadGeneration
  loading.value = true
  try {
    const next = asRecord(await getSystemNetwork(force))
    if (generation !== loadGeneration) return
    data.value = mapNetwork(next)
    loadError.value = ''
    syncOrderFromData()
    if (asArray(deviceOptions.value).length && !asArray(deviceOptions.value).includes(aliasForm.value.device)) {
      aliasForm.value.device = deviceOptions.value[0]
    }
    const aa = data.value?.alias_auto
    if (aa?.config) {
      autoBindOn.value = !!aa.config.auto_bind
      autoIpsText.value = asArray(aa.config.ips).map((n) => finiteText(n, '')).filter(Boolean).join(', ')
    }
  } catch (e) {
    if (generation !== loadGeneration) return
    loadError.value = finiteText(e.message || String(e), '')
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (generation === loadGeneration) {
      loading.value = false
      loaded.value = true
    }
  }
}

async function runAutoBind() {
  const generation = loadGeneration
  busy.value = true
  autoBindLog.value = t('network.running')
  try {
    const j = asRecord(await runAliasAutoBind())
    if (!stillOnNetwork(generation)) return
    autoBindLog.value = jsonText(j.actions || j, finiteText(j.message, '') || t('network.failed'))
    toast(j.ok ? `✅ ${finiteText(j.message, '') || t('network.aligned')}` : `❌ ${finiteText(j.message, '') || t('network.failed')}`)
    await refresh(true)
  } catch (e) {
    if (!stillOnNetwork(generation)) return
    toast('❌ ' + finiteText(e.message))
    autoBindLog.value = e.message
  } finally {
    if (pageAlive) busy.value = false
  }
}

async function runFailover() {
  if (!confirm(t('network.confirm_failover'))) return
  const generation = loadGeneration
  busy.value = true
  try {
    const j = asRecord(await runNetworkFailover())
    if (!stillOnNetwork(generation)) return
    toast(j.ok ? `✅ ${j.mode === 'wired' ? t('network.wired_ok') : t('network.wifi_engaged')}` : `❌ ${t('network.switch_failed')}`)
    await refresh(true)
  } catch (e) {
    if (!stillOnNetwork(generation)) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (pageAlive) busy.value = false
  }
}

async function saveAutoBind() {
  const generation = loadGeneration
  busy.value = true
  try {
    const j = asRecord(await updateAliasAuto({ auto_bind: autoBindOn.value }))
    if (!stillOnNetwork(generation)) return
    toast(`✅ ${autoBindOn.value ? t('network.autobind_enabled') : t('network.autobind_disabled')}`)
    data.value = { ...data.value, alias_auto: j }
  } catch (e) {
    if (!stillOnNetwork(generation)) return
    toast('❌ ' + finiteText(e.message))
    // Put the checkbox back. It is bound with v-model, so on failure it kept the
    // flipped position while the server state was unchanged -- the one control on
    // this page that showed a setting it had not actually applied.
    autoBindOn.value = !autoBindOn.value
  } finally {
    if (pageAlive) busy.value = false
  }
}

async function saveAutoIps() {
  if (!confirm(t('network.confirm_autobind'))) return
  const generation = loadGeneration
  busy.value = true
  try {
    const ips = autoIpsText.value.split(/[,\s]+/).map(s => s.trim()).filter(Boolean)
    const j = asRecord(await updateAliasAuto({ ips }))
    if (!stillOnNetwork(generation)) return
    toast(`✅ ${t('network.alias_list_saved')}`)
    data.value = { ...data.value, alias_auto: j }
    await runAutoBind()
  } catch (e) {
    if (!stillOnNetwork(generation)) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (pageAlive) busy.value = false
  }
}

async function applyProfile(profile) {
  if (!confirm(t('network.confirm_profile', { profile: finiteText(profile) }))) return
  const generation = loadGeneration
  busy.value = true
  msg.value = t('network.switching')
  try {
    const j = asRecord(await switchNetworkProfile(profile))
    if (!stillOnNetwork(generation)) return
    toast(j.ok ? `✅ ${t('network.switched')}` : `❌ ${finiteText(j.message)}`)
    msg.value = finiteText(j.message, '')
    if (j.ok) scheduleRefresh(2000)
  } catch (e) {
    if (!stillOnNetwork(generation)) return
    toast('❌ ' + finiteText(e.message))
    msg.value = finiteText(e.message, '')
  } finally {
    // refresh() bumps loadGeneration; Refresh is bound to `loading`, not `busy`.
    if (pageAlive) busy.value = false
  }
}

async function saveOrder() {
  // Service order decides which interface is primary egress, so this can move
  // the machine onto a different network path -- the same class of change as the
  // confirmed actions elsewhere on this page.
  if (!confirm(t('network.confirm_order'))) return
  const generation = loadGeneration
  busy.value = true
  try {
    const j = asRecord(await setNetworkServiceOrder(asArray(orderList.value).map(s => s.name)))
    if (!stillOnNetwork(generation)) return
    toast(j.ok ? `✅ ${t('network.order_saved')}` : `❌ ${finiteText(j.message)}`)
    msg.value = finiteText(j.message, '')
    if (j.ok) scheduleRefresh(1500)
  } catch (e) {
    if (!stillOnNetwork(generation)) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (pageAlive) busy.value = false
  }
}

async function toggleService(s) {
  const en = !!s.disabled
  if (!confirm(t('network.confirm_toggle', { action: en ? t('network.act_enable') : t('network.act_disable'), name: finiteText(s.name) }))) return
  const generation = loadGeneration
  busy.value = true
  try {
    const j = asRecord(await setNetworkServiceEnabled(s.name, en))
    if (!stillOnNetwork(generation)) return
    toast(j.ok ? '✅ ' + t('common.ok') : `❌ ${finiteText(j.message)}`)
    if (j.ok) scheduleRefresh(1200)
  } catch (e) {
    if (!stillOnNetwork(generation)) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (pageAlive) busy.value = false
  }
}

async function addAlias() {
  if (!confirm(t('network.confirm_add_alias', {
    device: finiteText(aliasForm.value.device),
    ip: finiteText(aliasForm.value.ip),
  }))) return
  const generation = loadGeneration
  busy.value = true
  try {
    const j = asRecord(await addNetworkAlias(aliasForm.value))
    if (!stillOnNetwork(generation)) return
    toast(j.ok ? `✅ ${t('network.ip_added')}` : `❌ ${finiteText(j.message)}`)
    msg.value = finiteText(j.message, '')
    if (j.ok) scheduleRefresh(800)
  } catch (e) {
    if (!stillOnNetwork(generation)) return
    toast('❌ ' + finiteText(e.message))
    msg.value = finiteText(e.message, '')
  } finally {
    if (pageAlive) busy.value = false
  }
}

async function removeAlias(device, ip) {
  if (!confirm(t('network.confirm_del_alias', { device: finiteText(device), ip: finiteText(ip) }))) return
  const generation = loadGeneration
  busy.value = true
  try {
    const j = asRecord(await removeNetworkAlias({ device, ip, netmask: '255.255.255.255' }))
    if (!stillOnNetwork(generation)) return
    toast(j.ok ? `✅ ${t('network.alias_deleted')}` : `❌ ${finiteText(j.message)}`)
    msg.value = finiteText(j.message, '')
    if (j.ok) scheduleRefresh(800)
  } catch (e) {
    if (!stillOnNetwork(generation)) return
    toast('❌ ' + finiteText(e.message))
    msg.value = finiteText(e.message, '')
  } finally {
    if (pageAlive) busy.value = false
  }
}

function openPrimaryEdit(device, addr) {
  // open manual editor for matching service
  const svc = asServiceList(data.value?.services).find(s => s.device === device)
  if (svc) {
    openManual({
      ...svc,
      ip: addr.ip,
      subnet: addr.netmask === '255.255.255.255' ? '255.255.255.0' : (addr.netmask || '255.255.255.0'),
    })
    tab.value = 'ip'
  } else {
    toast(t('network.no_service_for_nic'))
    tab.value = 'ip'
  }
}

async function setDhcp(s) {
  if (!confirm(t('network.confirm_dhcp', { name: finiteText(s.name) }))) return
  const generation = loadGeneration
  busy.value = true
  try {
    const j = asRecord(await setNetworkDhcp(s.name))
    if (!stillOnNetwork(generation)) return
    toast(j.ok ? '✅ ' + t('network.dhcp_applied') : `❌ ${finiteText(j.message)}`)
    msg.value = finiteText(j.message, '')
    if (j.ok) scheduleRefresh(1500)
  } catch (e) {
    if (!stillOnNetwork(generation)) return
    toast('❌ ' + finiteText(e.message))
    msg.value = finiteText(e.message, '')
  } finally {
    if (pageAlive) busy.value = false
  }
}

function openManual(s) {
  manualSvc.value = s
  manualForm.value = {
    ip: s.ip || '',
    subnet: s.subnet || '255.255.255.0',
    router: s.router || '',
  }
}

async function applyManual() {
  if (!manualSvc.value) return
  if (!confirm(t('network.confirm_manual', { name: finiteText(manualSvc.value.name) }))) return
  const generation = loadGeneration
  busy.value = true
  try {
    const j = asRecord(await setNetworkManual(manualSvc.value.name, manualForm.value))
    if (!stillOnNetwork(generation)) return
    toast(j.ok ? `✅ ${t('network.static_applied')}` : `❌ ${finiteText(j.message)}`)
    msg.value = finiteText(j.message, '')
    if (j.ok) {
      manualSvc.value = null
      scheduleRefresh(2000)
    }
  } catch (e) {
    if (!stillOnNetwork(generation)) return
    toast('❌ ' + finiteText(e.message))
    msg.value = finiteText(e.message, '')
  } finally {
    if (pageAlive) busy.value = false
  }
}

function openDns(s) {
  dnsSvc.value = s
  dnsServers.value = asArray(s.dns).map((n) => finiteText(n, '')).filter(Boolean).join('\n')
}

async function applyDns() {
  if (!dnsSvc.value) return
  const servers = dnsServers.value.split(/[\n,;]+/).map(x => x.trim()).filter(Boolean)
  // Rewriting a service's resolvers can break name resolution for the very
  // session viewing this page. Every sibling connectivity action here already
  // confirms (applyProfile, toggleService, setDhcp, applyManual, wifi); this one
  // was the exception.
  if (!confirm(t('network.confirm_dns', { name: finiteText(dnsSvc.value.name) }))) return
  const generation = loadGeneration
  busy.value = true
  try {
    const j = asRecord(await setNetworkDns(dnsSvc.value.name, servers))
    if (!stillOnNetwork(generation)) return
    toast(j.ok ? `✅ ${t('network.dns_updated')}` : `❌ ${finiteText(j.message)}`)
    msg.value = finiteText(j.message, '')
    if (j.ok) {
      dnsSvc.value = null
      scheduleRefresh(1000)
    }
  } catch (e) {
    if (!stillOnNetwork(generation)) return
    toast('❌ ' + finiteText(e.message))
    msg.value = finiteText(e.message, '')
  } finally {
    if (pageAlive) busy.value = false
  }
}

async function wifi(state) {
  const label = state === 'on' ? t('network.on') : t('network.off')
  if (!confirm(t('network.confirm_wifi', { state: label }))) return
  const generation = loadGeneration
  busy.value = true
  try {
    const j = asRecord(await setWifiPower(state))
    if (!stillOnNetwork(generation)) return
    toast(j.ok ? '✅ ' + t('network.wifi_set', { state: label }) : `❌ ${finiteText(j.message)}`)
    if (j.ok) scheduleRefresh(1500)
  } catch (e) {
    if (!stillOnNetwork(generation)) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (pageAlive) busy.value = false
  }
}

async function doLookup() {
  const generation = loadGeneration
  busy.value = true
  try {
    const next = asRecord(await lookupNetworkDns(lookupHost.value.trim()))
    if (!stillOnNetwork(generation)) return
    lookupResult.value = next
  } catch (e) {
    if (!stillOnNetwork(generation)) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (pageAlive) busy.value = false
  }
}

function openPortEdit(container) {
  portEdit.value = container || ''
  if (container) {
    const maps = asArray(data.value?.docker_ports)
      .filter(p => p.container === container && finiteN(p.host_port, null) != null)
      .map(p => `${finiteN(p.host_port)}:${finiteN(p.container_port)}`)
    portEditText.value = [...new Set(maps)].join('\n')
  } else {
    portEditText.value = ''
    // pick first container with ports
    const c = data.value?.docker_ports?.[0]?.container
    if (c) openPortEdit(c)
  }
}

async function applyPorts() {
  if (!portEdit.value) {
    toast('❌ ' + t('network.ctr_name'))
    return
  }
  if (!confirm(t('network.confirm_recreate_ports', { name: finiteText(portEdit.value) }))) return
  const ports = portEditText.value.split(/[\n,;]+/).map(x => x.trim()).filter(Boolean)
  const generation = loadGeneration
  busy.value = true
  msg.value = '…'
  try {
    const j = asRecord(await setContainerPorts(portEdit.value, ports))
    if (!stillOnNetwork(generation)) return
    toast(j.ok ? `✅ ${t('network.port_updated')}` : `❌ ${finiteText(j.message)}`)
    msg.value = finiteText(j.message, '')
    if (j.ok) {
      portEdit.value = null
      scheduleRefresh(1200)
    }
  } catch (e) {
    if (!stillOnNetwork(generation)) return
    toast('❌ ' + finiteText(e.message))
    msg.value = finiteText(e.message, '')
  } finally {
    if (pageAlive) busy.value = false
  }
}

function openConnect(n) {
  connectNet.value = n
  connectMode.value = 'connect'
  connectContainer.value = ''
}
function openDisconnect(n) {
  connectNet.value = n
  connectMode.value = 'disconnect'
  connectContainer.value = asArray(n.containers)[0]?.name || ''
}

async function applyConnect() {
  if (!connectNet.value || !connectContainer.value.trim()) return
  const container = connectContainer.value.trim()
  const confirmKey = connectMode.value === 'disconnect'
    ? 'network.confirm_disconnect'
    : 'network.confirm_connect'
  if (!confirm(t(confirmKey, {
    container: finiteText(container),
    network: finiteText(connectNet.value.name),
  }))) return
  const generation = loadGeneration
  busy.value = true
  try {
    const j = asRecord(await connectContainerNetwork(connectMode.value, connectNet.value.name, container))
    if (!stillOnNetwork(generation)) return
    toast(j.ok ? `✅ ${t('network.done')}` : `❌ ${finiteText(j.message)}`)
    msg.value = finiteText(j.message, '')
    if (j.ok) {
      connectNet.value = null
      scheduleRefresh(800)
    }
  } catch (e) {
    if (!stillOnNetwork(generation)) return
    toast('❌ ' + finiteText(e.message))
    msg.value = finiteText(e.message, '')
  } finally {
    if (pageAlive) busy.value = false
  }
}

onMounted(() => {
  pageAlive = true
  refresh(false)
})
onUnmounted(() => {
  pageAlive = false
  loadGeneration += 1
  for (const id of refreshTimers) clearTimeout(id)
  refreshTimers.clear()
})


// Escape dismisses each dialog, focus returns to whatever opened it, and Tab
// cannot wander to the page behind the overlay.
useDismissable(manualSvc, () => { manualSvc.value = null }, manualPanel)
useDismissable(dnsSvc, () => { dnsSvc.value = null }, dnsPanel)
useDismissable(portEdit, () => { portEdit.value = null }, portPanel)
useDismissable(connectNet, () => { connectNet.value = null }, connectPanel)
</script>

<style scoped>
.net-summary {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 8px;
  margin-bottom: 12px;
}
.net-summary-item {
  background: var(--card);
  border: 1px solid var(--line);
  border-radius: var(--radius);
  padding: 8px 10px;
  text-align: center;
}
.net-summary-label {
  display: block;
  font-size: 9px;
  color: var(--sub);
  text-transform: uppercase;
  letter-spacing: .3px;
  margin-bottom: 3px;
}
.net-summary-value {
  display: block;
  font-size: 13px;
  font-weight: 700;
}
.msg-box {
  font-size: 11px; white-space: pre-wrap; max-height: 100px; overflow: auto;
  background: var(--bg); border: 1px solid var(--line); border-radius: var(--radius-sm);
  padding: 8px 10px; margin-bottom: 12px; font-family: ui-monospace, Menlo, monospace;
}
/* Layout comes from the global .field-grid; 100px is that grid's default, so
   this page needs no knob. Note this also makes the selects in these forms
   full-width, matching every other form in the app — the local copy of this rule
   only ever set `input`, which is why Network's dropdowns were the odd ones out. */
.log-pre {
  font-size: 11px; white-space: pre-wrap; overflow: auto;
  font-family: ui-monospace, Menlo, monospace;
  background: var(--bg); border: 1px solid var(--line);
  border-radius: var(--radius-sm); padding: 8px;
}
@media (max-width: 640px) {
  .net-summary { grid-template-columns: repeat(2, 1fr); gap: 6px; }
  .net-summary-item { padding: 6px 8px; }
  .net-summary-value { font-size: 12px; overflow-wrap: anywhere; }
  .msg-box { font-size: 10px; max-height: 80px; }
}
</style>
