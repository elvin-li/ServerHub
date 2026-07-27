<template>
  <div>
    <div class="page-title">
      <h1>{{ t('network.title') }}</h1>
      <span class="meta">
        {{ t('network.meta') }}
        <span v-if="data?.ts"> · {{ data.ts }}</span>
      </span>
    </div>

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
        {{ t('network.default_gw', { gw: data.default_route.gateway || '—', iface: data.default_route.interface || '—' }) }}
      </span>
    </div>

    <!-- Mobile-friendly network status summary -->
    <div class="net-summary" v-if="data">
      <div class="net-summary-item">
        <span class="net-summary-label">{{ t('network.sum_egress') }}</span>
        <span class="net-summary-value">{{ data.default_route?.interface || '—' }}</span>
      </div>
      <div class="net-summary-item">
        <span class="net-summary-label">{{ t('network.sum_gateway') }}</span>
        <span class="net-summary-value mono">{{ data.default_route?.gateway || '—' }}</span>
      </div>
      <div class="net-summary-item">
        <span class="net-summary-label">{{ t('network.sum_services') }}</span>
        <span class="net-summary-value">{{ t('network.sum_active_n', { n: (data.services || []).filter(s => !s.disabled).length }) }}</span>
      </div>
      <div class="net-summary-item">
        <span class="net-summary-label">{{ t('network.sum_listening') }}</span>
        <span class="net-summary-value">{{ t('network.sum_ports_n', { n: (data.listening || []).length }) }}</span>
      </div>
    </div>

    <pre v-if="msg" class="msg-box" role="status" aria-live="polite">{{ msg }}</pre>

    <!-- Switch profile + multi-IP bindings -->
    <template v-if="tab==='switch'">
      <div class="tile" style="margin-bottom:12px;border-left:3px solid var(--accent)">
        <h3 style="margin:0 0 6px">{{ t('network.switch_title') }}</h3>
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
          {{ t('network.current_egress', { iface: data.default_route.interface || '—' }) }}
          · {{ t('network.gateway_is', { gw: data.default_route.gateway || '—' }) }}
        </div>
      </div>

      <div class="tile" style="margin-bottom:12px;border-left:3px solid var(--ok)">
        <div class="row" style="margin-bottom:8px;align-items:center;gap:10px;flex-wrap:wrap">
          <h3 style="margin:0;flex:1">{{ t('network.failover_title') }}</h3>
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
          <span> · Wi‑Fi：{{ failoverWifiLabel }}</span>
          <span v-if="data.network_failover.state?.last_check_at"> · {{ t('network.last_check', { at: data.network_failover.state.last_check_at }) }}</span>
          <span v-if="data.network_failover.state?.last_action"> · {{ t('network.last_action', { action: data.network_failover.state.last_action }) }}</span>
        </div>
      </div>

      <h2 class="section-title">{{ t('network.prio_title') }}</h2>
      <div class="table-wrap" style="margin-bottom:14px">
        <table class="dense">
          <thead>
            <tr><th>#</th><th>{{ t('network.th_service') }}</th><th>{{ t('network.th_device') }}</th><th>{{ t('network.th_status') }}</th><th>{{ t('network.th_mode_ip') }}</th><th>{{ t('network.th_ops') }}</th></tr>
          </thead>
          <tbody>
            <tr v-for="(s, idx) in orderList" :key="s.name">
              <td class="mono">{{ idx + 1 }}</td>
              <td>
                <strong>{{ s.name }}</strong>
                <span v-if="s.disabled" class="badge down">{{ t('network.act_disable') }}</span>
                <span v-if="isWifi(s)" class="badge accent">Wi‑Fi</span>
                <span v-else-if="looksEthernet(s)" class="badge ok">{{ t('network.badge_wired') }}</span>
              </td>
              <td class="mono">{{ s.device || '—' }}</td>
              <td>{{ s.disabled ? 'off' : 'on' }}</td>
              <td class="mono" style="font-size:11px">{{ s.mode }} {{ s.ip || '' }}</td>
              <td class="ops">
                <button class="tiny" :disabled="busy || idx===0" @click="moveService(idx, -1)">↑</button>
                <button class="tiny" :disabled="busy || idx===orderList.length-1" @click="moveService(idx, 1)">↓</button>
                <button class="tiny" :disabled="busy" @click="toggleService(s)">{{ s.disabled ? t('network.act_enable') : t('network.act_disable') }}</button>
              </td>
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
            <input type="checkbox" v-model="autoBindOn" @change="saveAutoBind" /> {{ t('network.autobind_on') }}
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
              {{ data.alias_auto.preferred.device }}
            </strong>
            <span v-else style="color:var(--down)">{{ t('network.no_network') }}</span>
            <span v-if="data.alias_auto.preferred" style="color:var(--sub)">
              · {{ data.alias_auto.preferred.service }}
              · {{ t('network.primary_ip_is', { ip: data.alias_auto.preferred.primary_ip || '—' }) }}
            </span>
          </div>
          <div style="margin-top:6px">
            {{ t('network.managed_aliases') }}
            <span v-for="(ip, i) in (data.alias_auto.config?.ips || [])" :key="ip" class="badge" style="margin-right:4px"
              :class="(data.alias_auto.ips||[]).find(x=>x.ip===ip)?.on_preferred ? 'ok' : 'warn'"
            >{{ ip }}</span>
            <span v-if="!(data.alias_auto.config?.ips||[]).length" style="color:var(--sub)">{{ t('network.not_configured') }}</span>
          </div>
          <div class="form-n" style="margin-top:10px">
            <label>{{ t('network.alias_list') }}</label>
            <input v-model="autoIpsText" type="text" :placeholder="t('network.alias_list_ph')" style="width:100%"  :aria-label="t('network.alias_list_ph')"/>
          </div>
          <div class="btns" style="margin-top:8px">
            <button class="tiny" :disabled="busy" @click="saveAutoIps">{{ t('network.save_list') }}</button>
          </div>
          <pre v-if="autoBindLog" class="log-pre" style="margin-top:8px;max-height:100px" role="status" aria-live="polite">{{ autoBindLog }}</pre>
        </div>
      </div>
      <div class="table-wrap" style="margin-bottom:12px">
        <table class="dense">
          <thead>
            <tr><th>{{ t('network.th_nic') }}</th><th>{{ t('network.th_status') }}</th><th>IP</th><th>{{ t('network.th_mask') }}</th><th>{{ t('network.th_type') }}</th><th>{{ t('network.th_ops') }}</th></tr>
          </thead>
          <tbody>
            <template v-for="iface in (data?.interface_addresses || [])" :key="iface.device">
              <tr v-for="(a, ai) in (iface.addresses || [])" :key="iface.device + a.ip + ai">
                <td class="mono" v-if="ai===0" :rowspan="Math.max(1, (iface.addresses||[]).length)">
                  <strong>{{ iface.device }}</strong>
                </td>
                <td v-if="ai===0" :rowspan="Math.max(1, (iface.addresses||[]).length)">
                  <span class="led" :class="iface.up ? 'on' : 'off'"></span>
                </td>
                <td class="mono"><strong>{{ a.ip }}</strong></td>
                <td class="mono">{{ a.netmask }}</td>
                <td>
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
              <tr v-if="!(iface.addresses||[]).length" :key="iface.device+'-empty'">
                <td class="mono"><strong>{{ iface.device }}</strong></td>
                <td><span class="led" :class="iface.up ? 'on' : 'off'"></span></td>
                <td colspan="3" style="color:var(--sub)">{{ t('network.no_ipv4') }}</td>
                <td></td>
              </tr>
            </template>
          </tbody>
        </table>
      </div>

      <div class="tile">
        <h3 style="margin-top:0">{{ t('network.add_alias_title') }}</h3>
        <div class="form-n">
          <label>{{ t('network.th_nic') }}</label>
          <select v-model="aliasForm.device" :aria-label="t('network.th_nic')">
            <option v-for="i in deviceOptions" :key="i" :value="i">{{ i }}</option>
          </select>
          <label>IP</label>
          <input v-model="aliasForm.ip" type="text" :placeholder="t('network.alias_ip_ph')"  :aria-label="t('network.alias_ip_ph')"/>
          <label>{{ t('network.mask') }}</label>
          <input v-model="aliasForm.netmask" type="text" placeholder="255.255.255.255"  aria-label="255.255.255.255"/>
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
        <table class="dense">
          <thead>
            <tr>
              <th></th><th>{{ t('network.iface') }}</th><th>{{ t('common.status') }}</th><th>IPv4</th><th>{{ t('network.mask') }}</th><th>IPv6</th><th>MAC</th><th>MTU</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="i in data?.interfaces || []" :key="i.name">
              <td><span class="led" :class="i.up ? 'on' : 'off'"></span></td>
              <td><strong>{{ i.name }}</strong></td>
              <td><span class="badge" :class="i.up ? 'ok' : ''">{{ i.status || (i.up ? 'up' : 'down') }}</span></td>
              <td class="mono">
                <div v-for="(a,idx) in i.ipv4 || []" :key="idx">{{ a.ip }}</div>
                <span v-if="!(i.ipv4||[]).length">—</span>
              </td>
              <td class="mono">
                <div v-for="(a,idx) in i.ipv4 || []" :key="'m'+idx">{{ a.netmask || '—' }}</div>
              </td>
              <td class="mono" style="font-size:10px">{{ (i.ipv6 || []).slice(0,2).join(', ') || '—' }}</td>
              <td class="mono">{{ i.mac || '—' }}</td>
              <td class="mono">{{ i.mtu || '—' }}</td>
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
        <table class="dense">
          <thead>
            <tr>
              <th>{{ t('network.service') }}</th><th>{{ t('network.device') }}</th><th>{{ t('network.mode') }}</th><th>IP</th><th>{{ t('network.mask') }}</th><th>{{ t('network.gateway') }}</th><th>DNS</th><th>{{ t('network.ops') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="s in data?.services || []" :key="s.name">
              <td>
                <strong>{{ s.name }}</strong>
                <span v-if="s.disabled" class="badge down">{{ t('network.disabled') }}</span>
              </td>
              <td class="mono">{{ s.device || '—' }}</td>
              <td><span class="badge" :class="s.mode==='manual'?'warn':(s.mode==='dhcp'?'ok':'')">{{ s.mode }}</span></td>
              <td class="mono">{{ s.ip || '—' }}</td>
              <td class="mono">{{ s.subnet || '—' }}</td>
              <td class="mono">{{ s.router || '—' }}</td>
              <td class="mono" style="font-size:11px">{{ (s.dns||[]).join(', ') || '—' }}</td>
              <td class="ops">
                <button class="tiny" :disabled="busy || s.disabled" @click="openManual(s)">{{ t('network.edit_ip') }}</button>
                <button class="tiny" :disabled="busy || s.disabled" @click="setDhcp(s)">DHCP</button>
                <button class="tiny" :disabled="busy || s.disabled" @click="openDns(s)">{{ t('network.tab_dns') }}</button>
                <template v-if="isWifi(s)">
                  <button class="tiny" :disabled="busy" @click="wifi('on')">Wi‑Fi On</button>
                  <button class="tiny danger" :disabled="busy" @click="wifi('off')">Off</button>
                </template>
              </td>
            </tr>
            <tr v-if="!(data?.services||[]).length">
              <td colspan="8" style="color:var(--sub)">{{ data?.services_error || t('network.no_services') }}</td>
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
        <div><strong>{{ lookupResult.host }}</strong>
          <span class="badge" :class="lookupResult.ok?'ok':'down'">{{ lookupResult.ok?'OK':'FAIL' }}</span>
        </div>
        <div class="mono" style="margin-top:8px" v-for="(a,i) in lookupResult.answers||[]" :key="i">{{ a }}</div>
        <pre v-if="!lookupResult.answers?.length" class="msg-box" style="margin-top:8px" role="status" aria-live="polite">{{ lookupResult.message }}</pre>
      </div>
      <h2 class="section-title">{{ t('network.dns_per_svc') }}</h2>
      <div class="table-wrap">
        <table class="dense">
          <thead><tr><th>{{ t('network.service') }}</th><th>{{ t('network.dns_servers') }}</th><th>{{ t('network.search_domains') }}</th><th></th></tr></thead>
          <tbody>
            <tr v-for="s in data?.services || []" :key="s.name">
              <td><strong>{{ s.name }}</strong></td>
              <td class="mono">{{ (s.dns||[]).join(', ') || t('network.system_default') }}</td>
              <td class="mono">{{ (s.search_domains||[]).join(', ') || '—' }}</td>
              <td><button class="tiny" @click="openDns(s)">{{ t('network.edit') }}</button></td>
            </tr>
          </tbody>
        </table>
      </div>
    </template>

    <!-- Listening -->
    <template v-else-if="tab==='ports'">
      <div class="toolbar">
        <input v-model="portQ" type="text" :placeholder="t('network.filter_port')" style="min-width:160px"  :aria-label="t('network.filter_port')"/>
      </div>
      <div class="table-wrap">
        <table class="dense">
          <thead><tr><th>{{ t('network.process') }}</th><th>PID</th><th>{{ t('tools.user') }}</th><th>{{ t('network.address') }}</th><th>{{ t('network.port') }}</th></tr></thead>
          <tbody>
            <tr v-for="(p,i) in filteredListen" :key="i">
              <td><strong>{{ p.process }}</strong></td>
              <td class="mono">{{ p.pid }}</td>
              <td>{{ p.user }}</td>
              <td class="mono">{{ p.address }}</td>
              <td class="mono">{{ p.port }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </template>

    <!-- Routes -->
    <template v-else-if="tab==='routes'">
      <div class="table-wrap">
        <table class="dense">
          <thead><tr><th>{{ t('network.destination') }}</th><th>{{ t('network.gateway') }}</th><th>Flags</th><th>{{ t('network.iface') }}</th></tr></thead>
          <tbody>
            <tr v-for="(r,i) in data?.routes || []" :key="i">
              <td class="mono">{{ r.destination }}</td>
              <td class="mono">{{ r.gateway }}</td>
              <td class="mono">{{ r.flags }}</td>
              <td>{{ r.netif }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </template>

    <!-- Docker network -->
    <template v-else-if="tab==='docker'">
      <div v-if="!data?.engine_up" class="placeholder">{{ t('network.engine_off') }}</div>
      <template v-else>
        <h2 class="section-title">{{ t('network.port_maps') }}</h2>
        <div class="toolbar">
          <input v-model="dockerPortQ" type="text" :placeholder="t('network.filter_ctr')" style="min-width:160px"  :aria-label="t('network.filter_ctr')"/>
          <button @click="openPortEdit()" :disabled="busy">{{ t('network.edit_map') }}</button>
        </div>
        <div class="table-wrap" style="margin-bottom:14px">
          <table class="dense">
            <thead>
              <tr><th>{{ t('network.container') }}</th><th>{{ t('common.status') }}</th><th>{{ t('network.host') }}</th><th>→</th><th>{{ t('network.cport') }}</th><th>{{ t('network.proto') }}</th><th></th></tr>
            </thead>
            <tbody>
              <tr v-for="(p,i) in filteredDockerPorts" :key="i">
                <td><strong>{{ p.container }}</strong></td>
                <td style="font-size:11px">{{ p.status }}</td>
                <td class="mono">{{ p.host_ip }}:{{ p.host_port || '—' }}</td>
                <td>→</td>
                <td class="mono">{{ p.container_port || '—' }}</td>
                <td>{{ p.protocol || '—' }}</td>
                <td class="ops">
                  <button class="tiny" :disabled="busy" @click="openPortEdit(p.container)">{{ t('network.change_port') }}</button>
                </td>
              </tr>
              <tr v-if="!filteredDockerPorts.length">
                <td colspan="7" style="color:var(--sub)">{{ t('network.no_published') }}</td>
              </tr>
            </tbody>
          </table>
        </div>

        <h2 class="section-title">{{ t('network.docker_nets') }}</h2>
        <div class="table-wrap" style="margin-bottom:14px">
          <table class="dense">
            <thead>
              <tr><th>{{ t('common.name') }}</th><th>{{ t('docker.driver') }}</th><th>{{ t('network.subnet') }}</th><th>{{ t('network.gateway') }}</th><th>{{ t('network.container') }}</th><th>{{ t('network.ops') }}</th></tr>
            </thead>
            <tbody>
              <tr v-for="n in data?.docker_networks || []" :key="n.id">
                <td>
                  <strong>{{ n.name }}</strong>
                  <span v-if="n.builtin" class="badge">{{ t('network.builtin') }}</span>
                </td>
                <td>{{ n.driver }}</td>
                <td class="mono">{{ n.subnet || '—' }}</td>
                <td class="mono">{{ n.gateway || '—' }}</td>
                <td style="font-size:11px">
                  <div v-for="c in (n.containers||[]).slice(0,6)" :key="c.id">
                    {{ c.name || c.id }} <span class="mono" style="color:var(--sub)">{{ c.ipv4 }}</span>
                  </div>
                  <span v-if="!(n.containers||[]).length" style="color:var(--sub)">—</span>
                </td>
                <td class="ops">
                  <button class="tiny" :disabled="busy || n.builtin" @click="openConnect(n)">{{ t('network.connect') }}</button>
                  <button class="tiny" :disabled="busy || n.builtin" @click="openDisconnect(n)">{{ t('network.disconnect') }}</button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </template>
    </template>

    <!-- Manual IP modal -->
    <div ref="manualPanel" v-if="manualSvc" class="modal-bg" @click.self="manualSvc=null" role="presentation">
      <div class="modal" style="max-width:440px" role="dialog" aria-modal="true" aria-labelledby="net-manual-title">
        <div class="row" style="margin-bottom:12px">
          <span id="net-manual-title" class="name">{{ t('network.static_ip') }} · {{ manualSvc.name }}</span>
          <button class="tiny" @click="manualSvc=null">{{ t('common.close') }}</button>
        </div>
        <div class="form-n">
          <label>{{ t('network.ip_addr') }}</label>
          <input v-model="manualForm.ip" type="text" :placeholder="t('network.static_ip_ph')"  :aria-label="t('network.static_ip_ph')"/>
          <label>{{ t('network.subnet_mask') }}</label>
          <input v-model="manualForm.subnet" type="text" placeholder="255.255.255.0"  aria-label="255.255.255.0"/>
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
          <span id="net-dns-title" class="name">DNS · {{ dnsSvc.name }}</span>
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
          <span id="net-port-title" class="name">{{ t('network.port_map') }} · {{ portEdit }}</span>
          <button class="tiny" @click="portEdit=null">{{ t('common.close') }}</button>
        </div>
        <p style="font-size:12px;color:var(--down);line-height:1.45;margin-bottom:8px">
          {{ t('network.recreate_hint') }}
        </p>
        <label style="font-size:12px;color:var(--sub)">{{ t('network.map_list') }}</label>
        <textarea v-model="portEditText" rows="5" style="width:100%;margin:8px 0 12px;font-family:ui-monospace,Menlo,monospace;font-size:12px" placeholder="4000:4000&#10;8080:80" aria-label="4000:4000&#10;8080:80"></textarea>
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
          <span id="net-connect-title" class="name">{{ connectMode==='connect'?t('network.connect_to'):t('network.disconnect_from') }} · {{ connectNet.name }}</span>
          <button class="tiny" @click="connectNet=null">{{ t('common.close') }}</button>
        </div>
        <label style="font-size:12px;color:var(--sub)">{{ t('network.ctr_name') }}</label>
        <input v-model="connectContainer" type="text" list="ctr-list" style="width:100%;margin:8px 0 12px" :placeholder="t('network.ctr_name')"  :aria-label="t('network.ctr_name')"/>
        <datalist id="ctr-list">
          <option v-for="c in containerNames" :key="c" :value="c" />
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
import { computed, inject, onMounted, ref } from 'vue'
import { injectI18n } from '../i18n'
import { useDismissable } from '../composables/useDismissable'

const toast = inject('toast')
const { t } = injectI18n()
const data = ref(null)
const loading = ref(false)
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

const filteredListen = computed(() => {
  const q = portQ.value.trim().toLowerCase()
  const list = data.value?.listening || []
  if (!q) return list
  return list.filter(p =>
    (p.process || '').toLowerCase().includes(q)
    || String(p.port).includes(q)
    || (p.address || '').toLowerCase().includes(q)
  )
})

const filteredDockerPorts = computed(() => {
  const q = dockerPortQ.value.trim().toLowerCase()
  const list = data.value?.docker_ports || []
  if (!q) return list
  return list.filter(p =>
    (p.container || '').toLowerCase().includes(q)
    || String(p.host_port).includes(q)
    || String(p.container_port).includes(q)
  )
})

const containerNames = computed(() => {
  const s = new Set()
  for (const p of data.value?.docker_ports || []) {
    if (p.container) s.add(p.container)
  }
  for (const n of data.value?.docker_networks || []) {
    for (const c of n.containers || []) {
      if (c.name) s.add(c.name)
    }
  }
  return [...s].sort()
})

const deviceOptions = computed(() => {
  return (data.value?.interface_addresses || []).map(i => i.device)
})

const failoverModeLabel = computed(() => {
  const mode = data.value?.network_failover?.state?.mode
  return ({ wired: t('network.mode_wired'), wifi_backup: t('network.mode_wifi_backup'), waiting_for_failover: t('network.mode_waiting'), starting: t('network.mode_starting'), disabled: t('network.disabled_state') })[mode] || t('network.mode_pending')
})

const failoverWifiLabel = computed(() => {
  const result = data.value?.network_failover?.state?.last_result
  const on = result?.wifi?.on
  return on === true ? t('network.on') : (on === false ? t('network.off') : t('network.unknown'))
})

function isWifi(s) {
  return /wi-?fi|airport|无线/i.test((s.name || '') + (s.hardware_port || ''))
}
function looksEthernet(s) {
  if (isWifi(s)) return false
  const n = (s.name || '') + (s.hardware_port || '')
  const d = s.device || ''
  return /ethernet|lan|usb.*lan|有线/i.test(n) || (d.startsWith('en') && d !== 'en0')
}

function syncOrderFromData() {
  orderList.value = JSON.parse(JSON.stringify(data.value?.services || []))
}
function resetOrderFromData() {
  syncOrderFromData()
  toast(t('network.reset_done'))
}
function moveService(idx, dir) {
  const j = idx + dir
  if (j < 0 || j >= orderList.value.length) return
  const arr = orderList.value.slice()
  const tmp = arr[idx]
  arr[idx] = arr[j]
  arr[j] = tmp
  orderList.value = arr
}

async function refresh(force = false) {
  loading.value = true
  try {
    const r = await fetch('/api/system/network?force=' + (force ? 'true' : 'false'))
    data.value = await r.json()
    syncOrderFromData()
    if (deviceOptions.value.length && !deviceOptions.value.includes(aliasForm.value.device)) {
      aliasForm.value.device = deviceOptions.value[0]
    }
    const aa = data.value?.alias_auto
    if (aa?.config) {
      autoBindOn.value = !!aa.config.auto_bind
      autoIpsText.value = (aa.config.ips || []).join(', ')
    }
  } catch (e) {
    toast('❌ ' + e.message)
  }
  loading.value = false
}

async function runAutoBind() {
  busy.value = true
  autoBindLog.value = t('network.running')
  try {
    const r = await fetch('/api/system/network/alias/auto/run', { method: 'POST' })
    const j = await r.json()
    autoBindLog.value = JSON.stringify(j.actions || j, null, 2)
    toast(j.ok ? `✅ ${j.message || t('network.aligned')}` : `❌ ${j.message || t('network.failed')}`)
    await refresh(true)
  } catch (e) {
    toast('❌ ' + e.message)
    autoBindLog.value = e.message
  }
  busy.value = false
}

async function runFailover() {
  busy.value = true
  try {
    const r = await fetch('/api/system/network/failover/run', { method: 'POST' })
    const j = await r.json().catch(() => ({}))
    if (!r.ok) throw new Error(typeof j.detail === 'string' ? j.detail : (j.message || t('network.check_failed')))
    toast(j.ok ? `✅ ${j.mode === 'wired' ? t('network.wired_ok') : t('network.wifi_engaged')}` : `❌ ${t('network.switch_failed')}`)
    await refresh(true)
  } catch (e) {
    toast('❌ ' + e.message)
  }
  busy.value = false
}

async function saveAutoBind() {
  busy.value = true
  try {
    const r = await fetch('/api/system/network/alias/auto', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ auto_bind: autoBindOn.value }),
    })
    const j = await r.json()
    toast(`✅ ${autoBindOn.value ? t('network.autobind_enabled') : t('network.autobind_disabled')}`)
    data.value = { ...data.value, alias_auto: j }
  } catch (e) {
    toast('❌ ' + e.message)
  }
  busy.value = false
}

async function saveAutoIps() {
  busy.value = true
  try {
    const ips = autoIpsText.value.split(/[,\s]+/).map(s => s.trim()).filter(Boolean)
    const r = await fetch('/api/system/network/alias/auto', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ips }),
    })
    const j = await r.json()
    toast(`✅ ${t('network.alias_list_saved')}`)
    data.value = { ...data.value, alias_auto: j }
    await runAutoBind()
  } catch (e) {
    toast('❌ ' + e.message)
  }
  busy.value = false
}

async function applyProfile(profile) {
  if (!confirm(t('network.confirm_profile', { profile }))) return
  busy.value = true
  msg.value = t('network.switching')
  try {
    const r = await fetch('/api/system/network/profile', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ profile }),
    })
    const j = await r.json().catch(() => ({}))
    if (!r.ok) throw new Error(typeof j.detail === 'string' ? j.detail : (j.message || t('network.failed')))
    toast(j.ok ? `✅ ${t('network.switched')}` : `❌ ${j.message}`)
    msg.value = j.message || ''
    setTimeout(() => refresh(true), 2000)
  } catch (e) {
    toast('❌ ' + e.message)
    msg.value = e.message
  }
  busy.value = false
}

async function saveOrder() {
  busy.value = true
  try {
    const r = await fetch('/api/system/network/order', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ services: orderList.value.map(s => s.name) }),
    })
    const j = await r.json().catch(() => ({}))
    if (!r.ok) throw new Error(typeof j.detail === 'string' ? j.detail : (j.message || t('network.failed')))
    toast(j.ok ? `✅ ${t('network.order_saved')}` : `❌ ${j.message}`)
    msg.value = j.message || ''
    setTimeout(() => refresh(true), 1500)
  } catch (e) {
    toast('❌ ' + e.message)
  }
  busy.value = false
}

async function toggleService(s) {
  const en = !!s.disabled
  if (!confirm(t('network.confirm_toggle', { action: en ? t('network.act_enable') : t('network.act_disable'), name: s.name }))) return
  busy.value = true
  try {
    const r = await fetch(`/api/system/network/services/${encodeURIComponent(s.name)}/enabled`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled: en }),
    })
    const j = await r.json().catch(() => ({}))
    if (!r.ok) throw new Error(typeof j.detail === 'string' ? j.detail : (j.message || t('network.failed')))
    toast(j.ok ? '✅' : `❌ ${j.message}`)
    setTimeout(() => refresh(true), 1200)
  } catch (e) {
    toast('❌ ' + e.message)
  }
  busy.value = false
}

async function addAlias() {
  busy.value = true
  try {
    const r = await fetch('/api/system/network/alias/add', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(aliasForm.value),
    })
    const j = await r.json().catch(() => ({}))
    if (!r.ok) throw new Error(typeof j.detail === 'string' ? j.detail : (j.message || t('network.failed')))
    toast(j.ok ? `✅ ${t('network.ip_added')}` : `❌ ${j.message}`)
    msg.value = j.message || ''
    setTimeout(() => refresh(true), 800)
  } catch (e) {
    toast('❌ ' + e.message)
    msg.value = e.message
  }
  busy.value = false
}

async function removeAlias(device, ip) {
  if (!confirm(t('network.confirm_del_alias', { device, ip }))) return
  busy.value = true
  try {
    const r = await fetch('/api/system/network/alias/remove', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ device, ip, netmask: '255.255.255.255' }),
    })
    const j = await r.json().catch(() => ({}))
    if (!r.ok) throw new Error(typeof j.detail === 'string' ? j.detail : (j.message || t('network.failed')))
    toast(j.ok ? `✅ ${t('network.alias_deleted')}` : `❌ ${j.message}`)
    msg.value = j.message || ''
    setTimeout(() => refresh(true), 800)
  } catch (e) {
    toast('❌ ' + e.message)
    msg.value = e.message
  }
  busy.value = false
}

function openPrimaryEdit(device, addr) {
  // open manual editor for matching service
  const svc = (data.value?.services || []).find(s => s.device === device)
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
  if (!confirm(t('network.confirm_dhcp', { name: s.name }))) return
  busy.value = true
  try {
    const r = await fetch(`/api/system/network/services/${encodeURIComponent(s.name)}/dhcp`, { method: 'POST' })
    const j = await r.json().catch(() => ({}))
    if (!r.ok) throw new Error(typeof j.detail === 'string' ? j.detail : (j.message || t('network.failed')))
    toast(j.ok ? '✅ DHCP' : `❌ ${j.message}`)
    msg.value = j.message || ''
    setTimeout(() => refresh(true), 1500)
  } catch (e) {
    toast('❌ ' + e.message)
    msg.value = e.message
  }
  busy.value = false
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
  busy.value = true
  try {
    const r = await fetch(`/api/system/network/services/${encodeURIComponent(manualSvc.value.name)}/manual`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(manualForm.value),
    })
    const j = await r.json().catch(() => ({}))
    if (!r.ok) throw new Error(typeof j.detail === 'string' ? j.detail : (j.message || t('network.failed')))
    toast(j.ok ? `✅ ${t('network.static_applied')}` : `❌ ${j.message}`)
    msg.value = j.message || ''
    manualSvc.value = null
    setTimeout(() => refresh(true), 2000)
  } catch (e) {
    toast('❌ ' + e.message)
    msg.value = e.message
  }
  busy.value = false
}

function openDns(s) {
  dnsSvc.value = s
  dnsServers.value = (s.dns || []).join('\n')
}

async function applyDns() {
  if (!dnsSvc.value) return
  const servers = dnsServers.value.split(/[\n,;]+/).map(x => x.trim()).filter(Boolean)
  busy.value = true
  try {
    const r = await fetch(`/api/system/network/services/${encodeURIComponent(dnsSvc.value.name)}/dns`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ servers }),
    })
    const j = await r.json().catch(() => ({}))
    if (!r.ok) throw new Error(typeof j.detail === 'string' ? j.detail : (j.message || t('network.failed')))
    toast(j.ok ? `✅ ${t('network.dns_updated')}` : `❌ ${j.message}`)
    msg.value = j.message || ''
    dnsSvc.value = null
    setTimeout(() => refresh(true), 1000)
  } catch (e) {
    toast('❌ ' + e.message)
  }
  busy.value = false
}

async function wifi(state) {
  if (!confirm(`Wi‑Fi ${state}？`)) return
  busy.value = true
  try {
    const r = await fetch(`/api/system/network/wifi/${state}`, { method: 'POST' })
    const j = await r.json().catch(() => ({}))
    if (!r.ok) throw new Error(typeof j.detail === 'string' ? j.detail : (j.message || t('network.failed')))
    toast(j.ok ? `✅ Wi‑Fi ${state}` : `❌ ${j.message}`)
    setTimeout(() => refresh(true), 1500)
  } catch (e) {
    toast('❌ ' + e.message)
  }
  busy.value = false
}

async function doLookup() {
  busy.value = true
  try {
    const r = await fetch('/api/system/network/dns-lookup?host=' + encodeURIComponent(lookupHost.value.trim()))
    lookupResult.value = await r.json()
  } catch (e) {
    toast('❌ ' + e.message)
  }
  busy.value = false
}

function openPortEdit(container) {
  portEdit.value = container || ''
  if (container) {
    const maps = (data.value?.docker_ports || [])
      .filter(p => p.container === container && p.host_port)
      .map(p => `${p.host_port}:${p.container_port}`)
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
  if (!confirm(portEdit.value + ' recreate ports?')) return
  const ports = portEditText.value.split(/[\n,;]+/).map(x => x.trim()).filter(Boolean)
  busy.value = true
  msg.value = '…'
  try {
    const r = await fetch(`/api/system/network/docker/ports/${encodeURIComponent(portEdit.value)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ports }),
    })
    const j = await r.json().catch(() => ({}))
    if (!r.ok) throw new Error(typeof j.detail === 'string' ? j.detail : (j.message || t('network.failed')))
    toast(j.ok ? `✅ ${t('network.port_updated')}` : `❌ ${j.message}`)
    msg.value = j.message || ''
    portEdit.value = null
    setTimeout(() => refresh(true), 1200)
  } catch (e) {
    toast('❌ ' + e.message)
    msg.value = e.message
  }
  busy.value = false
}

function openConnect(n) {
  connectNet.value = n
  connectMode.value = 'connect'
  connectContainer.value = ''
}
function openDisconnect(n) {
  connectNet.value = n
  connectMode.value = 'disconnect'
  connectContainer.value = (n.containers || [])[0]?.name || ''
}

async function applyConnect() {
  if (!connectNet.value || !connectContainer.value.trim()) return
  busy.value = true
  try {
    const path = connectMode.value === 'connect' ? 'connect' : 'disconnect'
    const r = await fetch(`/api/system/network/docker/${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        network: connectNet.value.name,
        container: connectContainer.value.trim(),
        force: true,
      }),
    })
    const j = await r.json().catch(() => ({}))
    if (!r.ok) throw new Error(typeof j.detail === 'string' ? j.detail : (j.message || t('network.failed')))
    toast(j.ok ? `✅ ${t('network.done')}` : `❌ ${j.message}`)
    msg.value = j.message || ''
    connectNet.value = null
    setTimeout(() => refresh(true), 800)
  } catch (e) {
    toast('❌ ' + e.message)
  }
  busy.value = false
}

onMounted(() => refresh(false))


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
  background: var(--bg); border: 1px solid var(--line); border-radius: 4px;
  padding: 8px 10px; margin-bottom: 12px; font-family: ui-monospace, Menlo, monospace;
}
.form-n {
  display: grid;
  grid-template-columns: 100px 1fr;
  gap: 8px 12px;
  align-items: center;
  font-size: 13px;
}
.form-n label { color: var(--sub); font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: .3px; }
.form-n input { width: 100%; }
.log-pre {
  font-size: 11px; white-space: pre-wrap; overflow: auto;
  font-family: ui-monospace, Menlo, monospace;
  background: var(--bg); border: 1px solid var(--line);
  border-radius: 4px; padding: 8px;
}
@media (max-width: 640px) {
  .net-summary { grid-template-columns: repeat(2, 1fr); gap: 6px; }
  .net-summary-item { padding: 6px 8px; }
  .net-summary-value { font-size: 12px; }
  .form-n { grid-template-columns: 1fr; }
  .form-n label { margin-bottom: -4px; }
  .msg-box { font-size: 10px; max-height: 80px; }
}
</style>
