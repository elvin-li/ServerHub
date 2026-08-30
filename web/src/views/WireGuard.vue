<template>
  <div>
    <div class="page-title">
      <h1>{{ t('pages.wireguard') }}</h1>
      <span class="meta">{{ t('pages.wireguard_meta') }} · {{ finiteText(data?.ts, '…') }}</span>
    </div>

    <!-- Running status card -->
    <div v-if="data" class="wg-status-bar" :class="{ running: asRecord(data).running }">
      <span class="wg-status-led"></span>
      <span class="wg-status-text">{{ asRecord(data).running ? t('wg.tunnel_running') : t('wg.tunnel_stopped') }}</span>
      <span v-if="asRecord(data).running" class="wg-status-meta">
        {{ finiteText(asRecord(data).interface) }} · {{ t('wg.listen_port') }} {{ finiteN(asRecord(data).listen_port) }}
        <template v-if="asRecord(asRecord(data).wstunnel).running || asRecord(asRecord(data).wstunnel).enabled">
          · {{ t('wg.wstunnel_short') }} {{ finiteText(asRecord(asRecord(data).wstunnel).port, '') || finiteText(asRecord(asRecord(data).wstunnel).listen) }}
        </template>
        · {{ finiteN(asRecord(data).active_count) }}/{{ finiteN(asRecord(data).peer_count) }} {{ t('wg.peers_online') }}
      </span>
    </div>

    <div class="toolbar">
      <button
        v-if="data && !asRecord(data).running"
        class="primary wg-start"
        @click="control('up')"
        :disabled="busy"
      >&#9654; {{ t('wg.start') }}</button>
      <button
        v-else-if="asRecord(data).running"
        class="danger wg-stop"
        @click="control('down')"
        :disabled="busy"
      >&#9632; {{ t('wg.stop') }}</button>
      <button @click="control('restart')" :disabled="busy" class="wg-restart">&#8635; {{ t('wg.restart') }}</button>
      <span class="toolbar-sep"></span>
      <button @click="sync" :disabled="busy || !data?.running">{{ t('wg.sync') }}</button>
      <button @click="openConf" :disabled="busy">{{ t('wg.view_conf') }}</button>
      <button @click="ping" :disabled="busy || !data?.running">{{ t('wg.ping') }}</button>
      <span class="toolbar-grow"></span>
      <!-- Neutral, not a dimmed `.primary`: Start/Stop is this toolbar's one
           primary action, and the 65% opacity that used to hold Refresh back
           took its label down to 2.5:1. -->
      <button @click="load" :disabled="loading">{{ t('common.refresh') }}</button>
    </div>

    <!-- Above the content, not instead of it: the `&& !data` gate this used to
         carry hid every *re*-load failure, so a 20s poll that started failing
         left stale peer rows and a stale Running badge on screen with nothing
         marking them as stale. LoadFailure is role="alert", so the failure is
         also announced to assistive tech when it appears. -->
    <LoadFailure v-if="loadError" :detail="loadError" :retry="load" :busy="loading" />
    <SkeletonLoader v-if="!loaded && !loadError" variant="tiles" :rows="4" :span="3" :tile-height="52" />
    <!-- Not installed: nothing else on this page can work, so say only that. -->
    <div v-else-if="data && !data.installed" class="tile" style="border-left:3px solid var(--down)">
      <h2>{{ t('wg.not_installed_title') }}</h2>
      <p style="font-size:12px;color:var(--sub);line-height:1.6;margin:6px 0 0">
        {{ t('wg.not_installed_hint') }}
      </p>
      <pre class="mono" style="margin-top:8px;font-size:11px">brew install wireguard-tools wireguard-go</pre>
    </div>

    <template v-else-if="data">
      <!-- Readiness: a running tunnel that carries no traffic is the normal
           failure on macOS, so blocking gaps are stated before the status tiles. -->
      <div
        v-if="readiness && !readiness.ready"
        class="tile"
        style="margin-bottom:12px;border-left:3px solid var(--down)"
      >
        <h2>{{ t('wg.not_ready') }}</h2>
        <p style="font-size:12px;color:var(--sub);line-height:1.6;margin:6px 0 8px">
          {{ t('wg.not_ready_hint') }}
        </p>
        <div class="table-wrap">
        <table class="dense fit-m">
          <tbody>
            <tr v-for="c in asArray(blockingChecks)" :key="finiteText(asRecord(c).id)">
              <td style="width:28px"><span class="led err"></span></td>
              <td>
                <strong>{{ checkLabel(asRecord(c).id) }}</strong>
                <div class="show-m sub">{{ checkFix(asRecord(c).id) }}</div>
                <div v-if="finiteText(asRecord(c).detail, '')" class="show-m sub mono">{{ finiteText(asRecord(c).detail) }}</div>
              </td>
              <td class="col-hide-m" style="font-size:11px;color:var(--sub)">{{ checkFix(asRecord(c).id) }}</td>
              <td class="mono col-hide-m" style="font-size:10px;max-width:200px;overflow:hidden;text-overflow:ellipsis">{{ finiteText(asRecord(c).detail) }}</td>
              <td style="text-align:right">
                <button
                  v-if="asRecord(c).id === 'forwarding'"
                  class="tiny primary"
                  @click="fixForwarding"
                  :disabled="busy"
                >{{ t('wg.enable') }}</button>
                <!-- Same action for both: installing the NAT rule rewrites
                     /etc/pf.conf in the order pf requires, which is exactly what
                     repairs a file pf is currently refusing. -->
                <button
                  v-else-if="asRecord(c).id === 'nat' || asRecord(c).id === 'pf_conf'"
                  class="tiny primary"
                  @click="fixNat"
                  :disabled="busy"
                >{{ t('wg.install') }}</button>
                <button
                  v-else-if="asRecord(c).id === 'endpoint'"
                  class="tiny"
                  @click="settingsOpen = true"
                  :disabled="busy"
                >{{ t('wg.configure') }}</button>
              </td>
            </tr>
          </tbody>
        </table>
        </div>
      </div>

      <!-- Non-blocking gaps. The traffic flows without these, so they must not
           look like failures, but they were previously computed by the server and
           then rendered nowhere at all: `boot` in particular reports whether the
           tunnel comes back after a reboot, and the action that fixes it existed
           in the API with nothing on the page able to call it. -->
      <div
        v-if="asArray(warningChecks).length"
        class="tile"
        style="margin-bottom:12px;border-left:3px solid var(--warn)"
      >
        <h2>{{ t('wg.warnings') }}</h2>
        <p style="font-size:12px;color:var(--sub);line-height:1.6;margin:6px 0 8px">
          {{ t('wg.warnings_hint') }}
        </p>
        <div class="table-wrap">
        <table class="dense fit-m">
          <tbody>
            <tr v-for="c in asArray(warningChecks)" :key="finiteText(asRecord(c).id)">
              <td style="width:28px"><span class="led warn"></span></td>
              <td>
                <strong>{{ checkLabel(asRecord(c).id) }}</strong>
                <div class="show-m sub">{{ checkFix(asRecord(c).id) }}</div>
                <div v-if="finiteText(asRecord(c).detail, '')" class="show-m sub mono">{{ finiteText(asRecord(c).detail) }}</div>
              </td>
              <td class="col-hide-m" style="font-size:11px;color:var(--sub)">{{ checkFix(asRecord(c).id) }}</td>
              <td class="mono col-hide-m" style="font-size:10px;max-width:200px;overflow:hidden;text-overflow:ellipsis">{{ finiteText(asRecord(c).detail) }}</td>
              <td style="text-align:right">
                <button
                  v-if="asRecord(c).id === 'boot'"
                  class="tiny primary wg-fix-boot"
                  @click="fixDaemon"
                  :disabled="busy"
                >{{ t('wg.install') }}</button>
                <!-- Installing the NAT rule ends with `pfctl -E`, which is what
                     turns pf on, so this is the same action as for the NAT row. -->
                <button
                  v-else-if="asRecord(c).id === 'pf'"
                  class="tiny primary"
                  @click="fixNat"
                  :disabled="busy"
                >{{ t('wg.enable') }}</button>
                <button
                  v-else-if="asRecord(c).id === 'wstunnel' || asRecord(c).id === 'wstunnel_align'"
                  class="tiny primary wg-fix-wstunnel"
                  @click="fixWstunnel"
                  :disabled="busy"
                >{{ t('wg.wstunnel_apply') }}</button>
                <button
                  v-else-if="c.id === 'wstunnel_restrict'"
                  class="tiny primary wg-fix-wstunnel-restrict"
                  @click="stabilizeWstunnel"
                  :disabled="busy"
                >{{ t('wg.wstunnel_stabilize') }}</button>
              </td>
            </tr>
          </tbody>
        </table>
        </div>
      </div>

      <!-- Peers copied from another server can never handshake here. This is a
           config-shape problem, not a runtime one, so it gets its own callout. -->
      <div
        v-if="readiness?.peer_origin?.conflict"
        class="tile"
        style="margin-bottom:12px;border-left:3px solid var(--warn)"
      >
        <h2>{{ t('wg.foreign_peers_title') }}</h2>
        <p style="font-size:12px;color:var(--sub);line-height:1.6;margin:6px 0 0">
          {{ t('wg.foreign_peers_hint', { n: finiteN(readiness.peer_origin.foreign), total: finiteN(readiness.peer_origin.total) }) }}
        </p>
      </div>

      <div class="dash-grid" style="margin-bottom:12px" v-if="data">
        <div class="tile span-3">
          <h2>{{ t('wg.listen_port') }}</h2>
          <div class="v">{{ finiteN(data.listen_port) }}</div>
          <div class="sub">{{ finiteText(data.interface) }}</div>
        </div>
        <div class="tile span-3">
          <h2>{{ t('wg.subnet') }}</h2>
          <div class="v" style="font-size:15px">{{ finiteText(data.address, '') || finiteText(data.subnet) }}</div>
          <div class="sub">MTU {{ finiteN(data.mtu) }}</div>
        </div>
        <div class="tile span-3">
          <h2>{{ t('wg.active_peers') }}</h2>
          <div class="v">{{ finiteN(data.active_count) }}/{{ finiteN(data.peer_count) }}</div>
          <div class="sub" v-if="data.stale_count">{{ t('wg.stale', { n: finiteN(data.stale_count, 0) }) }}</div>
        </div>
        <div class="tile span-3">
          <h2>{{ t('wg.keepalive_missing') }}</h2>
          <!-- -text tints, not the raw hues: --warn / --ok are fill colours
               and fail AA as ink (contrast.test.js pins the binding shape). -->
          <div class="v" :style="{ color: data.keepalive_missing ? 'var(--warn-text)' : 'var(--ok-text)' }">
            {{ finiteN(data.keepalive_missing) }}
          </div>
        </div>
      </div>

      <div class="tile" style="margin-bottom:12px" v-if="data">
        <h2>{{ t('wg.server_key') }}</h2>
        <div class="mono" style="font-size:11px;word-break:break-all">{{ finiteText(data.public_key) }}</div>
        <div class="sub" style="margin-top:6px">
          {{ t('wg.endpoint') }}:
          <code>{{ finiteText(data.endpoint, '') || t('wg.endpoint_unset') }}</code>
          <button class="tiny" style="margin-left:8px" @click="settingsOpen = true">{{ t('common.edit') }}</button>
        </div>
      </div>

      <div
        class="tile"
        style="margin-bottom:12px;border-left:3px solid var(--accent)"
        v-if="asRecord(asRecord(data).wstunnel).configured || asRecord(asRecord(data).wstunnel).running || asRecord(asRecord(data).wstunnel).enabled"
      >
        <div class="row" style="margin-bottom:6px;align-items:center;gap:10px;flex-wrap:wrap">
          <h2 style="margin:0;flex:1">{{ t('wg.wstunnel_title') }}</h2>
          <span class="badge" :class="asRecord(asRecord(data).wstunnel).running ? 'ok' : 'warn'">
            {{ asRecord(asRecord(data).wstunnel).running ? t('common.running') : t('common.off') }}
          </span>
          <span v-if="asRecord(asRecord(data).wstunnel).stale_restrict" class="badge warn">{{ t('wg.wstunnel_stale') }}</span>
          <span v-else-if="asRecord(asRecord(data).wstunnel).stable_restrict === false" class="badge warn">{{ t('wg.wstunnel_unstable') }}</span>
          <span v-else-if="asRecord(asRecord(data).wstunnel).aligned === false" class="badge warn">{{ t('wg.wstunnel_mismatch') }}</span>
          <button class="tiny" @click="settingsOpen = true">{{ t('common.edit') }}</button>
        </div>
        <p style="margin:0 0 8px;font-size:12px;color:var(--sub);line-height:1.5">
          {{ t('wg.wstunnel_hint') }}
        </p>
        <div style="font-size:12px;line-height:1.6">
          <div>{{ t('wg.wstunnel_listen') }} <code>{{ finiteText(asRecord(asRecord(data).wstunnel).listen) }}</code></div>
          <div>{{ t('wg.wstunnel_public') }} <code>{{ finiteText(asRecord(asRecord(data).wstunnel).public) }}</code></div>
          <div>{{ t('wg.wstunnel_restrict') }} <code>{{ finiteText(asRecord(asRecord(data).wstunnel).restrict_to) }}</code></div>
          <div
            v-if="!asRecord(asRecord(data).wstunnel).aligned && asRecord(asRecord(data).wstunnel).desired_restrict_to"
            class="sub"
          >
            {{ t('wg.wstunnel_desired') }}
            <code>{{ finiteText(asRecord(asRecord(data).wstunnel).desired_listen) }} → {{ finiteText(asRecord(asRecord(data).wstunnel).desired_restrict_to) }}</code>
          </div>
          <div
            v-if="asRecord(asRecord(data).wstunnel).client_command"
            class="mono"
            style="margin:8px 0 0;font-size:11px;word-break:break-all"
          >{{ finiteText(asRecord(asRecord(data).wstunnel).client_command) }}</div>
        </div>
        <div class="row" style="margin-top:10px;gap:8px;flex-wrap:wrap">
          <button
            v-if="data.wstunnel.client_command"
            class="tiny"
            @click="copyWstunnelCommand"
          >{{ t('common.copy') }}</button>
          <button
            v-if="data.wstunnel.needs_stabilize"
            class="tiny primary wg-stabilize-wstunnel"
            @click="stabilizeWstunnel"
            :disabled="busy"
          >{{ t('wg.wstunnel_stabilize') }}</button>
          <button
            v-else-if="data.wstunnel.needs_apply"
            class="tiny primary wg-apply-wstunnel"
            @click="fixWstunnel"
            :disabled="busy"
          >{{ t('wg.wstunnel_apply') }}</button>
          <button
            v-if="data.wstunnel.running"
            class="tiny"
            @click="removeWstunnel"
            :disabled="busy"
          >{{ t('wg.wstunnel_remove') }}</button>
        </div>
      </div>

      <!-- Peers -->
      <h2 class="section-title">{{ t('wg.peers') }} ({{ finiteN(data?.peer_count, 0) }})</h2>
      <div class="table-wrap">
        <table class="dense fit-m">
          <thead>
            <tr>
              <th style="width:28px"><span class="sr-only">{{ t('common.status_led') }}</span></th>
              <th>{{ t('wg.peer_name') }}</th>
              <th>{{ t('wg.address') }}</th>
              <th class="col-hide-m">{{ t('wg.remote_endpoint') }}</th>
              <th class="col-hide-m">{{ t('wg.handshake') }}</th>
              <th class="col-hide-m">{{ t('wg.keepalive') }}</th>
              <th class="col-hide-m">{{ t('wg.traffic') }}</th>
              <th class="actions">{{ t('common.actions') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="p in asArray(asRecord(data).peers)" :key="finiteText(asRecord(p).pubkey)">
              <td><span class="led" :class="asRecord(p).active ? 'on' : (asRecord(p).stale ? 'warn' : 'off')"></span></td>
              <td>
                <strong>{{ finiteText(asRecord(p).name, '') || t('wg.unnamed') }}</strong>
                <span v-if="asRecord(p).psk" class="badge ok" style="margin-left:4px">PSK</span>
                <span v-if="!asRecord(p).reissuable" class="badge" style="margin-left:4px" :title="t('wg.no_stored_key')">
                  {{ t('wg.key_not_stored') }}
                </span>
                <div class="mono" style="font-size:9px;color:var(--sub)" :title="finiteText(asRecord(p).pubkey)">
                  {{ finiteText(asRecord(p).pubkey, '').slice(0, 16) }}{{ finiteText(asRecord(p).pubkey, '') ? '…' : '' }}
                </div>
                <div v-if="asRecord(p).endpoint" class="show-m sub mono">{{ finiteText(asRecord(p).endpoint) }}</div>
                <div class="show-m sub mono">↑{{ finiteText(asRecord(p).tx_human) }} ↓{{ finiteText(asRecord(p).rx_human) }}</div>
                <div class="show-m sub">
                  <span v-if="asRecord(p).active">{{ t('wg.connected') }} · {{ relativeAge(asRecord(p).handshake_age) }}</span>
                  <span v-else-if="asRecord(p).stale">{{ t('wg.disconnected') }} · {{ relativeAge(asRecord(p).handshake_age) }}</span>
                  <span v-else-if="asRecord(p).last_handshake">{{ relativeAge(asRecord(p).handshake_age) }}</span>
                </div>
              </td>
              <td class="mono">{{ finiteText(asRecord(p).allowed_ips) }}</td>
              <td class="mono col-hide-m" style="font-size:10px">{{ finiteText(asRecord(p).endpoint) }}</td>
              <td class="col-hide-m" style="font-size:11px">
                <span v-if="asRecord(p).active" class="badge ok">{{ t('wg.connected') }} · {{ relativeAge(asRecord(p).handshake_age) }}</span>
                <span v-else-if="asRecord(p).stale" class="badge warn">{{ t('wg.disconnected') }} · {{ relativeAge(asRecord(p).handshake_age) }}</span>
                <span v-else-if="asRecord(p).last_handshake" class="badge">{{ relativeAge(asRecord(p).handshake_age) }}</span>
                <span v-else style="color:var(--sub)">{{ t('wg.never') }}</span>
              </td>
              <td class="col-hide-m">
                <span class="badge" :class="asRecord(p).keepalive && asRecord(p).keepalive !== 'off' && asRecord(p).keepalive !== '0' ? 'ok' : 'warn'">
                  {{ finiteText(asRecord(p).keepalive, 'off') }}
                </span>
              </td>
              <td class="mono col-hide-m" style="font-size:10px">↑{{ finiteText(asRecord(p).tx_human) }} ↓{{ finiteText(asRecord(p).rx_human) }}</td>
              <td class="actions">
                <button class="tiny primary" @click="showPeer(p)" :disabled="busy || !asRecord(p).reissuable">
                  {{ t('wg.config') }}
                </button>
                <button class="tiny hide-m" @click="togglePsk(p)" :disabled="busy">
                  {{ asRecord(p).psk ? t('wg.psk_remove') : t('wg.psk_add') }}
                </button>
                <button class="tiny danger" @click="removePeer(p)" :disabled="busy">{{ t('common.delete') }}</button>
              </td>
            </tr>
            <tr v-if="!asArray(asRecord(data).peers).length">
              <td colspan="8" class="empty-row">{{ loading ? t('common.loading') : t('wg.no_peers') }}</td>
            </tr>
          </tbody>
        </table>
      </div>

      <!-- Add peer -->
      <h2 class="section-title">{{ t('wg.add_peer') }}</h2>
      <div class="tile">
        <div class="form-row">
          <label>
            {{ t('wg.peer_name') }}
            <input v-model="form.name" type="text" :placeholder="t('wg.peer_name_ph')" />
          </label>
          <label>
            {{ t('wg.address') }}
            <input v-model="form.ip" type="text" :placeholder="nextIp || t('wg.address_auto')" />
          </label>
        </div>
        <div class="tabs" style="margin:8px 0">
          <button :class="{ active: form.mode === 'split' }" :aria-pressed="form.mode === 'split'" @click="form.mode = 'split'">
            {{ t('wg.mode_split') }}
          </button>
          <button :class="{ active: form.mode === 'full' }" :aria-pressed="form.mode === 'full'" @click="form.mode = 'full'">
            {{ t('wg.mode_full') }}
          </button>
        </div>
        <p style="font-size:11px;color:var(--sub);line-height:1.55;margin:0 0 8px">
          {{ form.mode === 'full' ? t('wg.mode_full_hint') : t('wg.mode_split_hint') }}
        </p>
        <label class="inline">
          <input type="checkbox" v-model="form.psk" /> {{ t('wg.use_psk') }}
        </label>
        <label class="inline">
          <input type="checkbox" v-model="form.keep_key" /> {{ t('wg.keep_key') }}
        </label>
        <p style="font-size:11px;color:var(--sub);line-height:1.55;margin:6px 0 8px">
          {{ form.keep_key ? t('wg.keep_key_hint') : t('wg.keep_key_off_hint') }}
        </p>
        <button class="primary" @click="createPeer" :disabled="busy || !form.name">{{ t('wg.create') }}</button>
      </div>

      <!-- Batch + import -->
      <div class="dash-grid" style="margin-top:12px">
        <div class="tile span-6">
          <h2>{{ t('wg.batch_add') }}</h2>
          <div class="form-row">
            <label>
              {{ t('wg.batch_count') }}
              <input v-model.number="batch.count" type="number" min="1" max="50" />
            </label>
            <label>
              {{ t('wg.batch_prefix') }}
              <input v-model="batch.prefix" type="text" placeholder="peer" />
            </label>
          </div>
          <button style="margin-top:8px" @click="createBatch" :disabled="busy || !batch.count">
            {{ t('wg.create') }}
          </button>
        </div>
        <div class="tile span-6">
          <h2>{{ t('wg.import_peer') }}</h2>
          <div class="form-row">
            <label>
              {{ t('wg.public_key') }}
              <input v-model="imp.pubkey" type="text" placeholder="base64=" />
            </label>
            <label>
              {{ t('wg.address') }}
              <input v-model="imp.ip" type="text" placeholder="10.10.0.9/32" />
            </label>
          </div>
          <label>
            {{ t('wg.peer_name') }}
            <input v-model="imp.name" type="text" />
          </label>
          <p style="font-size:11px;color:var(--sub);line-height:1.55;margin:6px 0 8px">
            {{ t('wg.import_hint') }}
          </p>
          <button style="margin-top:4px" @click="doImport" :disabled="busy || !imp.pubkey || !imp.ip">
            {{ t('wg.import') }}
          </button>
        </div>
      </div>

      <div v-if="pingResult" class="tile" style="margin-top:12px">
        <h2>{{ t('wg.ping_result', { ok: finiteN(asRecord(pingResult).reachable), total: finiteN(asRecord(pingResult).total) }) }}</h2>
        <div class="table-wrap">
        <table class="dense fit-m">
          <tbody>
            <tr v-for="r in asArray(asRecord(pingResult).results)" :key="finiteText(asRecord(r).pubkey)">
              <!-- Spell the per-row outcome, not just the LED colour: unlike
                   the peers table there is no textual badge here, so a screen
                   reader heard name and IP with nothing saying whether the
                   ping came back (same fix as the Network binding table). -->
              <td style="width:28px">
                <span class="led" :class="asRecord(r).reachable ? 'on' : 'err'"></span>
                <span class="sr-only">{{ asRecord(r).reachable ? t('wg.reachable') : t('wg.unreachable') }}</span>
              </td>
              <td>{{ finiteText(asRecord(r).name, '') || t('wg.unnamed') }}</td>
              <td class="mono">{{ finiteText(asRecord(r).ip) }}</td>
              <td class="mono">{{ withUnit(asRecord(r).latency_ms, ' ms') }}</td>
            </tr>
          </tbody>
        </table>
        </div>
      </div>
    </template>

    <!-- Peer config dialog: formats + QR -->
    <div v-if="peerDialog" class="modal-bg" @click.self="peerDialog = null" role="presentation">
      <div class="modal" role="dialog" aria-modal="true" aria-labelledby="wg-peer-title" ref="peerPanel" tabindex="-1">
        <h3 id="wg-peer-title">{{ t('wg.config_for', { name: finiteText(peerDialog.name) }) }}</h3>
        <div class="tabs" style="margin:8px 0">
          <button
            v-for="f in asArray(formats)"
            :key="finiteText(f)"
            :class="{ active: peerFormat === f }"
            :aria-pressed="peerFormat === f"
            @click="selectFormat(f)"
          >{{ formatLabel(f) }}</button>
        </div>
        <p v-if="peerFormat === 'wst'" style="font-size:11px;color:var(--sub);line-height:1.5;margin:0 0 8px">
          {{ t('wg.wstunnel_client_hint') }}
        </p>
        <p v-else-if="!peerDialog.endpoint_configured" style="font-size:11px;color:var(--warn-text);line-height:1.5;margin:0 0 8px">
          {{ t('wg.endpoint_missing_warn') }}
        </p>
        <pre class="mono" style="max-height:180px;overflow:auto;font-size:11px">{{ finiteText(peerContent) }}</pre>
        <!-- The QR must never be the thing that gets clipped: give it its own
             bounded, centred box with a white quiet zone so a phone camera can
             actually resolve it against a dark theme. -->
        <!-- aria-hidden: the QR encodes exactly the config shown in the <pre>
             above and offered by Copy/Download, so for a screen reader it is
             a duplicate with no name, announced as an anonymous graphic. -->
        <div v-if="qrSvg" class="wg-qr" aria-hidden="true" v-html="qrSvg"></div>
        <p v-else-if="qrTooLong" style="font-size:11px;color:var(--sub);margin-top:8px">
          {{ t('wg.qr_too_long') }}
        </p>
        <div class="modal-actions">
          <button @click="copyPeer">{{ t('common.copy') }}</button>
          <a class="btn" :href="finiteText(downloadUrl, '')" :download="finiteText(peerFilename, '')">{{ t('common.download') }}</a>
          <button class="primary" @click="peerDialog = null">{{ t('common.close') }}</button>
        </div>
      </div>
    </div>

    <!-- Raw server config -->
    <div v-if="confDialog" class="modal-bg" @click.self="confDialog = null" role="presentation">
      <div class="modal" role="dialog" aria-modal="true" aria-labelledby="wg-conf-title" ref="confPanel" tabindex="-1">
        <h3 id="wg-conf-title">{{ t('wg.view_conf') }}</h3>
        <p style="font-size:11px;color:var(--sub);margin:4px 0 8px">
          {{ confDialog.redacted ? t('wg.conf_redacted') : t('wg.conf_revealed') }}
        </p>
        <pre class="mono" style="max-height:340px;overflow:auto;font-size:11px">{{ finiteText(confDialog.conf) }}</pre>
        <div class="modal-actions">
          <button v-if="confDialog.redacted" class="danger" @click="openConf(true)">{{ t('wg.reveal_key') }}</button>
          <button class="primary" @click="confDialog = null">{{ t('common.close') }}</button>
        </div>
      </div>
    </div>

    <!-- Settings -->
    <div v-if="settingsOpen" class="modal-bg" @click.self="settingsOpen = false" role="presentation">
      <div class="modal" role="dialog" aria-modal="true" aria-labelledby="wg-settings-title" ref="settingsPanel" tabindex="-1">
        <h3 id="wg-settings-title">{{ t('wg.settings') }}</h3>
        <!-- The fields below fall back to literal defaults, so saving without a
             successful read would overwrite the live port/MTU. Say so and offer
             a retry instead of presenting an editable form that cannot be saved
             for no visible reason. -->
        <div
          v-if="!settingsLoaded"
          class="tile"
          style="margin-bottom:10px;border-left:3px solid var(--down)"
          role="alert"
        >
          <div>{{ t('wg.settings_load_failed') }}</div>
          <div v-if="settingsError" class="sub mono" style="margin-top:4px">{{ finiteText(settingsError) }}</div>
          <button class="tiny" style="margin-top:6px" :disabled="busy" @click="loadSettings">
            {{ t('common.retry') }}
          </button>
        </div>
        <label>
          {{ t('wg.endpoint') }}
          <input v-model="cfgForm.endpoint" type="text" placeholder="vpn.example.com:51820" />
        </label>
        <p style="font-size:11px;color:var(--sub);line-height:1.5;margin:4px 0 8px">
          {{ t('wg.endpoint_hint') }}
        </p>
        <div class="form-row">
          <label>
            {{ t('wg.subnet') }}
            <input v-model="cfgForm.subnet" type="text" placeholder="10.10.0.0/24" />
          </label>
          <label>
            {{ t('wg.listen_port') }}
            <input v-model.number="cfgForm.listen_port" type="number" min="1" max="65535" />
          </label>
        </div>
        <div class="form-row">
          <label>
            {{ t('wg.lan_cidr') }}
            <input v-model="cfgForm.lan_cidr" type="text" placeholder="192.168.1.0/24" />
          </label>
          <label>
            {{ t('wg.wan_interface') }}
            <input v-model="cfgForm.wan_interface" type="text" :placeholder="finiteText(readiness?.wan_interface, '') || 'en0'" />
          </label>
        </div>
        <div class="form-row">
          <label>
            DNS
            <input v-model="cfgForm.dns" type="text" placeholder="1.1.1.1, 8.8.8.8" />
          </label>
          <label>
            MTU
            <input v-model.number="cfgForm.mtu" type="number" min="576" max="1500" />
          </label>
        </div>
        <label style="display:flex;align-items:center;gap:8px;margin:10px 0 8px">
          <input type="checkbox" v-model="cfgForm.wstunnel_enabled" />
          {{ t('wg.wstunnel_enable') }}
        </label>
        <p style="font-size:11px;color:var(--sub);line-height:1.5;margin:0 0 8px">
          {{ t('wg.wstunnel_hint') }}
        </p>
        <div class="form-row">
          <label>
            {{ t('wg.wstunnel_listen') }}
            <input v-model="cfgForm.wstunnel_listen" type="text" placeholder="ws://0.0.0.0:8444" />
          </label>
          <label>
            {{ t('wg.wstunnel_public') }}
            <input v-model="cfgForm.wstunnel_public" type="text" placeholder="ws://vpn.example.com:8444" />
          </label>
        </div>
        <label>
          {{ t('wg.wstunnel_restrict') }}
          <input v-model="cfgForm.wstunnel_restrict_to" type="text" placeholder="127.0.0.1:51821" />
        </label>
        <p style="font-size:11px;color:var(--sub);line-height:1.5;margin:4px 0 8px">
          {{ t('wg.wstunnel_restrict_hint') }}
        </p>
        <div class="modal-actions">
          <button @click="settingsOpen = false">{{ t('common.cancel') }}</button>
          <button class="primary" @click="saveSettings" :disabled="busy || !settingsLoaded">{{ t('common.save') }}</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, inject, onMounted, onUnmounted, ref } from 'vue'
import qrcode from 'qrcode-generator'
import {
  addWireguardPeer, batchAddWireguardPeers, controlWireguardInterface,
  deleteWireguardPeer, getWireguard, getWireguardConf, getWireguardNextIp,
  getWireguardPeerConfig, getWireguardReadiness, getWireguardSettings,
  importWireguardPeer, pingWireguardPeers, putWireguardSettings,
  remediateWireguard, setWireguardForwarding, setWireguardPsk, syncWireguard,
  wireguardPeerDownloadUrl,
} from '../api/client'
import { useDismissable } from '../composables/useDismissable'
import { injectI18n } from '../i18n'
import { copyToClipboard } from '../lib/clipboard'
import { asArray, asRecord, finiteN, finiteText, withUnit } from '../lib/finite'
import { startVisibleInterval } from '../lib/poll'
import LoadFailure from '../components/LoadFailure.vue'
import SkeletonLoader from '../components/SkeletonLoader.vue'

const toast = inject('toast')
const { t } = injectI18n()

const data = ref(null)
const readiness = ref(null)
const nextIp = ref('')
const loading = ref(false)
const loaded = ref(false)
const loadError = ref('')
const busy = ref(false)
const pingResult = ref(null)

const peerDialog = ref(null)
const peerFormat = ref('wg')
const peerContent = ref('')
const qrSvg = ref('')
const qrTooLong = ref(false)
const confDialog = ref(null)
const settingsOpen = ref(false)

const peerPanel = ref(null)
const confPanel = ref(null)
const settingsPanel = ref(null)

useDismissable(() => !!peerDialog.value, () => { peerDialog.value = null }, peerPanel)
useDismissable(() => !!confDialog.value, () => { confDialog.value = null }, confPanel)
useDismissable(() => settingsOpen.value, () => { settingsOpen.value = false }, settingsPanel)

// Clash-full and Shadowrocket are generated from the same peer, so the format
// list is fixed rather than server-driven.
const formats = computed(() => {
  const base = ['wg', 'clash', 'clashfull', 'sr']
  const wst = asRecord(asRecord(data.value).wstunnel)
  if (wst.enabled || wst.running) {
    return [...base, 'wst']
  }
  return base
})

// Readiness ids and export formats are looked up through explicit maps rather
// than by concatenating an id onto a key prefix at the call site.  A concatenated
// key is invisible to the i18n contract test, which scans for literal translation
// arguments: it would treat the bare prefix as the key, fail to resolve it, and at
// the same time never verify that the nine real keys exist in all three locales.
const CHECK_LABELS = {
  installed: 'wg.check_installed',
  conf: 'wg.check_conf',
  running: 'wg.check_running',
  endpoint: 'wg.check_endpoint',
  endpoint_resolves: 'wg.check_endpoint_resolves',
  forwarding: 'wg.check_forwarding',
  nat: 'wg.check_nat',
  pf_conf: 'wg.check_pf_conf',
  pf: 'wg.check_pf',
  boot: 'wg.check_boot',
  peer_origin: 'wg.check_peer_origin',
  stale_runtime: 'wg.check_stale_runtime',
  wstunnel: 'wg.check_wstunnel',
  wstunnel_align: 'wg.check_wstunnel_align',
  wstunnel_restrict: 'wg.check_wstunnel_restrict',
}
const CHECK_FIXES = {
  installed: 'wg.fix_installed',
  conf: 'wg.fix_conf',
  running: 'wg.fix_running',
  endpoint: 'wg.fix_endpoint',
  endpoint_resolves: 'wg.fix_endpoint_resolves',
  forwarding: 'wg.fix_forwarding',
  nat: 'wg.fix_nat',
  pf_conf: 'wg.fix_pf_conf',
  pf: 'wg.fix_pf',
  boot: 'wg.fix_boot',
  peer_origin: 'wg.fix_peer_origin',
  stale_runtime: 'wg.fix_stale_runtime',
  wstunnel: 'wg.fix_wstunnel',
  wstunnel_align: 'wg.fix_wstunnel_align',
  wstunnel_restrict: 'wg.fix_wstunnel_restrict',
}
const FORMAT_LABELS = {
  wg: 'wg.fmt_wg',
  clash: 'wg.fmt_clash',
  clashfull: 'wg.fmt_clashfull',
  sr: 'wg.fmt_sr',
  wst: 'wg.fmt_wst',
}

const checkLabel = (id) => (CHECK_LABELS[id] ? t(CHECK_LABELS[id]) : finiteText(id))
const checkFix = (id) => (CHECK_FIXES[id] ? t(CHECK_FIXES[id]) : '')
const formatLabel = (fmt) => (FORMAT_LABELS[fmt] ? t(FORMAT_LABELS[fmt]) : finiteText(fmt))

const form = ref({ name: '', ip: '', mode: 'split', psk: false, keep_key: true })
const batch = ref({ count: 3, prefix: 'peer' })
const imp = ref({ pubkey: '', ip: '', name: '' })
const cfgForm = ref({
  endpoint: '', subnet: '', listen_port: 51820, lan_cidr: '',
  wan_interface: '', dns: '', mtu: 1280,
  wstunnel_enabled: false, wstunnel_listen: 'ws://0.0.0.0:8444',
  wstunnel_public: '', wstunnel_restrict_to: '',
})

// Peers copied from another server get their own callout below, which explains
// the situation properly and names the keys. Leaving the check in this table as
// well put the same finding on screen twice, once with room to explain it and
// once without.
const SELF_EXPLAINING = new Set(['peer_origin'])
const blockingChecks = computed(
  () => asArray(asRecord(readiness.value).checks).map((row) => asRecord(row)).filter(
    (c) => !c.ok && c.level === 'error' && !SELF_EXPLAINING.has(c.id),
  ),
)
// `running` is already the status bar at the top of the page and the Start button
// next to it, so repeating it as a warning row would be the third statement of the
// same fact.
const ALREADY_SHOWN = new Set([...SELF_EXPLAINING, 'running'])
const warningChecks = computed(
  () => asArray(asRecord(readiness.value).checks).map((row) => asRecord(row)).filter(
    (c) => !c.ok && c.level === 'warn' && !ALREADY_SHOWN.has(c.id),
  ),
)
const downloadUrl = computed(
  () => (peerDialog.value ? wireguardPeerDownloadUrl(finiteText(peerDialog.value.pubkey, ''), peerFormat.value) : '#'),
)
const peerFilename = computed(() => {
  const safe = finiteText(peerDialog.value?.name, 'peer').replace(/[^A-Za-z0-9_-]/g, '-')
  const ext = { wg: '.conf', clash: '-clash.yaml', clashfull: '-clash-full.yaml', sr: '-shadowrocket.txt', wst: '-wstunnel.conf' }
  return finiteText(safe, 'peer') + (ext[peerFormat.value] || '.conf')
})

function relativeAge(seconds) {
  const s = Number(seconds)
  if (!Number.isFinite(s) || s < 0) return '—'
  if (s < 60) return t('wg.age_seconds', { n: s })
  if (s < 3600) return t('wg.age_minutes', { n: Math.floor(s / 60) })
  if (s < 86400) return t('wg.age_hours', { n: Math.floor(s / 3600) })
  return t('wg.age_days', { n: Math.floor(s / 86400) })
}

/** Render *text* as an inline QR SVG, or flag it as too long to encode.
 *
 *  Only the WireGuard config and the Shadowrocket URL are short enough to scan
 *  reliably; a full Clash config is kilobytes and would produce a QR no camera
 *  can resolve, so those formats deliberately get no code. */
function renderQr(text, fmt) {
  qrSvg.value = ''
  qrTooLong.value = false
  if (fmt !== 'wg' && fmt !== 'sr') return
  try {
    const qr = qrcode(0, 'M')
    qr.addData(text)
    qr.make()
    // `scalable: true` emits an SVG with a viewBox and no width/height, so the
    // browser gives it no intrinsic size: inside a flex/auto-height dialog it
    // either collapsed to nothing or overflowed and got clipped, which is why the
    // code rendered only partially. The wrapper below constrains it instead, so
    // the whole symbol is always visible and stays square.
    qrSvg.value = qr.createSvgTag({ cellSize: 4, margin: 4, scalable: true })
  } catch {
    // qrcode-generator throws once the payload exceeds the largest version.
    qrTooLong.value = true
  }
}

let poll = null
// Guards against a slow response from a previous refresh landing after a newer
// one and overwriting fresher state.
let loadGeneration = 0

async function load(manual = false) {
  const generation = ++loadGeneration
  loading.value = true
  try {
    const [status, ready] = await Promise.all([
      getWireguard(),
      getWireguardReadiness().catch(() => readiness.value),
    ])
    if (generation !== loadGeneration) return
    data.value = {
      ...asRecord(status),
      peers: asArray(asRecord(status).peers).map((row) => asRecord(row)),
      wstunnel: asRecord(asRecord(status).wstunnel),
    }
    readiness.value = {
      ...asRecord(ready),
      checks: asArray(asRecord(ready).checks).map((row) => asRecord(row)),
      peer_origin: asRecord(asRecord(ready).peer_origin),
    }
    loadError.value = ''
    if (asRecord(status).installed) {
      // Clear it on failure rather than leaving a stale suggestion: the address
      // field uses this as its placeholder, and an IP that was free minutes ago
      // may now be taken. An empty placeholder is honest; a wrong one is not.
      getWireguardNextIp()
        .then((r) => { if (generation === loadGeneration) nextIp.value = asRecord(r).next_ip })
        .catch(() => { if (generation === loadGeneration) nextIp.value = '' })
    }
  } catch (e) {
    if (generation !== loadGeneration) return
    loadError.value = finiteText(e.message || String(e), '')
    // Background 20s ticks stay silent: LoadFailure already marks the state on
    // screen, and re-toasting every interval while the panel is down is noise.
    // The Refresh/retry buttons pass their click event as `manual`.
    if (manual) toast('❌ ' + finiteText(e.message))
    // Failed tick → lib/poll.js backoff while the server stays unreachable.
    // A superseded request (generation moved on) stays neutral: the newer
    // request will report its own outcome.
    return false
  } finally {
    if (generation === loadGeneration) {
      loading.value = false
      loaded.value = true
    }
  }
}

async function withBusy(fn, okKey) {
  if (busy.value) return null
  const generation = loadGeneration
  busy.value = true
  try {
    const result = asRecord(await fn())
    if (generation !== loadGeneration || !pageAlive) return null
    if (okKey) toast('✅ ' + t(okKey))
    await load()
    return result
  } catch (e) {
    if (generation !== loadGeneration || !pageAlive) return null
    toast('❌ ' + finiteText(e.message))
    return null
  } finally {
    // load() bumps loadGeneration, so a generation match would leave every
    // successful action stuck in the busy state.
    if (pageAlive) busy.value = false
  }
}

const sync = () => withBusy(syncWireguard, 'wg.synced')
const ping = () => withBusy(async () => {
  const generation = loadGeneration
  const result = asRecord(await pingWireguardPeers())
  if (generation !== loadGeneration || !pageAlive) return result
  pingResult.value = {
    ...asRecord(result),
    results: asArray(asRecord(result).results).map((row) => asRecord(row)),
  }
  return result
})

function control(action) {
  const key = { up: 'wg.confirm_up', down: 'wg.confirm_down', restart: 'wg.confirm_restart' }[action]
  if (key && !confirm(t(key))) return
  return withBusy(() => controlWireguardInterface(action), 'wg.interface_done')
}

const fixForwarding = () => {
  if (!confirm(t('wg.confirm_forwarding'))) return
  return withBusy(() => setWireguardForwarding(true), 'wg.forwarding_enabled')
}
const fixNat = () => {
  if (!confirm(t('wg.confirm_nat'))) return
  return withBusy(() => remediateWireguard('nat', true), 'wg.nat_installed')
}
// Boot persistence. The service and the endpoint for this both existed; nothing on
// the page called them, so an operator whose LaunchDaemon was missing (or was some
// other build's) had no way to install the one the panel manages.
const fixDaemon = () => {
  if (!confirm(t('wg.confirm_daemon'))) return
  return withBusy(() => remediateWireguard('daemon', true), 'wg.boot_installed')
}
const fixWstunnel = () => {
  if (!confirm(t('wg.confirm_wstunnel_apply'))) return
  return withBusy(() => remediateWireguard('wstunnel', true), 'wg.wstunnel_applied')
}
const stabilizeWstunnel = () => {
  if (!confirm(t('wg.confirm_wstunnel_stabilize'))) return
  return withBusy(
    () => remediateWireguard('wstunnel_stabilize', true),
    'wg.wstunnel_stabilized',
  )
}
const removeWstunnel = () => {
  if (!confirm(t('wg.wstunnel_remove_confirm'))) return
  return withBusy(() => remediateWireguard('wstunnel', false), 'wg.wstunnel_removed')
}

async function copyWstunnelCommand() {
  const command = finiteText(asRecord(asRecord(data.value).wstunnel).client_command, '')
  if (!command) return
  const ok = await copyToClipboard(command)
  if (!pageAlive) return
  toast(ok ? '✅ ' + t('common.copied') : '❌ ' + t('common.copy_failed'))
}

async function createPeer() {
  const created = await withBusy(
    () => addWireguardPeer({ ...form.value, ip: form.value.ip || '' }),
    'wg.peer_created',
  )
  if (!created || !pageAlive) return
  form.value = { name: '', ip: '', mode: form.value.mode, psk: false, keep_key: form.value.keep_key }
  // Show the config immediately: with keep_key off this is the only time the
  // private key is ever available.
  peerDialog.value = {
    pubkey: created.pub,
    name: created.name,
    endpoint_configured: created.endpoint_configured,
  }
  peerFormat.value = 'wg'
  peerContent.value = finiteText(created.client_conf, '')
  renderQr(created.client_conf, 'wg')
}

async function createBatch() {
  const result = await withBusy(
    () => batchAddWireguardPeers({ ...batch.value, mode: form.value.mode, keep_key: true }),
    null,
  )
  if (result && pageAlive) toast('✅ ' + t('wg.batch_created', { n: finiteN(result.created) }))
}

async function doImport() {
  const result = await withBusy(() => importWireguardPeer({ ...imp.value }), 'wg.peer_imported')
  if (result && pageAlive) imp.value = { pubkey: '', ip: '', name: '' }
}

function removePeer(peer) {
  const row = asRecord(peer)
  if (!confirm(t('wg.confirm_delete', { name: finiteText(row.name, '') || String(finiteText(row.pubkey, '')).slice(0, 16) }))) return
  return withBusy(() => deleteWireguardPeer(row.pubkey), 'wg.peer_deleted')
}

function togglePsk(peer) {
  const row = asRecord(peer)
  const op = row.psk ? 'remove' : 'add'
  if (!confirm(t(op === 'add' ? 'wg.confirm_psk_add' : 'wg.confirm_psk_remove'))) return
  return withBusy(() => setWireguardPsk(row.pubkey, op), 'wg.psk_changed')
}

async function showPeer(peer) {
  const row = asRecord(peer)
  const generation = loadGeneration
  try {
    const result = asRecord(await getWireguardPeerConfig(row.pubkey, 'wg'))
    if (generation !== loadGeneration || !pageAlive) return
    peerDialog.value = {
      pubkey: row.pubkey,
      name: result.name,
      endpoint_configured: Boolean(asRecord(data.value).endpoint),
    }
    peerFormat.value = 'wg'
    peerContent.value = finiteText(result.content, '')
    renderQr(peerContent.value, 'wg')
  } catch (e) {
    if (generation !== loadGeneration || !pageAlive) return
    toast('❌ ' + finiteText(e.message))
  }
}

async function selectFormat(fmt) {
  if (!peerDialog.value) return
  const generation = loadGeneration
  peerFormat.value = fmt
  try {
    const result = asRecord(await getWireguardPeerConfig(peerDialog.value.pubkey, fmt))
    if (generation !== loadGeneration || !pageAlive) return
    peerContent.value = finiteText(result.content, '')
    renderQr(peerContent.value, fmt)
  } catch (e) {
    if (generation !== loadGeneration || !pageAlive) return
    toast('❌ ' + finiteText(e.message))
  }
}

async function copyPeer() {
  const ok = await copyToClipboard(peerContent.value)
  if (!pageAlive) return
  toast(ok ? '✅ ' + t('common.copied') : '❌ ' + t('common.copy_failed'))
}

async function openConf(reveal = false) {
  if (reveal && !confirm(t('wg.confirm_reveal'))) return
  const generation = loadGeneration
  try {
    const next = asRecord(await getWireguardConf(reveal))
    if (generation !== loadGeneration || !pageAlive) return
    confDialog.value = next
  } catch (e) {
    if (generation !== loadGeneration || !pageAlive) return
    toast('❌ ' + finiteText(e.message))
  }
}

async function saveSettings() {
  // Refuse to write when the current settings were never read back: the patch
  // below would consist of this form's hardcoded defaults.
  if (!settingsLoaded.value) {
    toast('❌ ' + t('wg.settings_load_failed'))
    return
  }
  const patch = {}
  for (const [key, value] of Object.entries(asRecord(cfgForm.value))) {
    if (key === 'wstunnel_enabled') {
      patch[key] = Boolean(value)
      continue
    }
    if (value !== '' && value != null) patch[key] = value
  }
  const result = await withBusy(() => putWireguardSettings(patch), 'wg.settings_saved')
  if (result && pageAlive) settingsOpen.value = false
}

// Whether cfgForm reflects the server's real settings. Save is blocked until it
// does: cfgForm is seeded with literal defaults (listen_port 51820, mtu 1280),
// and saveSettings sends every non-empty field, so saving on top of a failed
// load silently rewrote a working tunnel's port and MTU to those defaults --
// with a success toast, and with the peers' configs left pointing at the old
// port. The failure is latched rather than merely toasted because the toast is
// gone by the time the user opens the dialog and presses Save.
const settingsLoaded = ref(false)
const settingsError = ref('')

async function loadSettings() {
  const generation = loadGeneration
  try {
    const current = asRecord(await getWireguardSettings())
    if (generation !== loadGeneration || !pageAlive) return
    cfgForm.value = { ...cfgForm.value, ...asRecord(current.settings) }
    settingsLoaded.value = true
    settingsError.value = ''
  } catch (e) {
    if (generation !== loadGeneration || !pageAlive) return
    settingsLoaded.value = false
    settingsError.value = finiteText(e.message || String(e), '')
  }
}

let pageAlive = true
onMounted(async () => {
  pageAlive = true
  // Independent reads: load() fills the status/readiness/peers view, loadSettings()
  // only seeds cfgForm. Awaiting them in sequence made the page wait for two
  // round trips of privileged shell-outs before anything rendered, for no
  // ordering reason. Both swallow their own errors, so neither can reject here.
  await Promise.all([load(), loadSettings()])
  if (!pageAlive) return
  // Peer handshake ages only matter at ~minute resolution; 20s keeps the table
  // live without hammering `wg show` (which is a privileged call per poll).
  poll = startVisibleInterval(load, 20000)
})

onUnmounted(() => {
  pageAlive = false
  if (typeof poll === 'function') poll()
  poll = null
  loadGeneration += 1
})
</script>

<style scoped>
/* ── Status bar ─────────────────────────────────────────────────────────── */
.wg-status-bar {
  display: flex; align-items: center; gap: 10px;
  padding: 10px 14px; border-radius: 8px; margin-bottom: 12px;
  border: 1px solid var(--line); background: var(--card);
}
.wg-status-bar.running {
  border-color: color-mix(in srgb, var(--ok) 25%, transparent);
  background: color-mix(in srgb, var(--ok) 6%, var(--card));
}
.wg-status-bar:not(.running) {
  border-color: color-mix(in srgb, var(--down) 25%, transparent);
  background: color-mix(in srgb, var(--down) 6%, var(--card));
}
.wg-status-led {
  width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0;
  background: var(--down); box-shadow: 0 0 6px var(--down);
}
.wg-status-bar.running .wg-status-led {
  background: var(--ok); box-shadow: 0 0 6px var(--ok);
}
.wg-status-text { font-weight: 700; font-size: 14px; }
.wg-status-meta { font-size: 11px; color: var(--sub); margin-left: auto; }
@media (max-width: 640px) {
  .wg-status-bar { flex-wrap: wrap; }
  .wg-status-meta { margin-left: 0; width: 100%; }
  .toolbar-grow, .toolbar-sep { display: none; }
}

/* ── Toolbar refinements ────────────────────────────────────────────────── */
.toolbar-sep { width: 1px; height: 20px; background: var(--line); margin: 0 4px; }
.toolbar-grow { flex: 1; }
.wg-start { min-width: 80px; }
.wg-stop { min-width: 80px; }
.wg-stop.danger { background: color-mix(in srgb, var(--down) 85%, #000); border-color: var(--down); color: #fff; }
.wg-stop.danger:hover { background: var(--down); }
.wg-restart { min-width: 80px; }

/* A QR code is only useful if the whole symbol is visible and has a light quiet
   zone. The generated SVG is scalable (viewBox, no width/height), so it needs an
   explicitly sized box; without one it inherited no dimensions and was clipped. */
.wg-qr {
  margin: 12px auto 0;
  width: 100%;
  max-width: 300px;
  padding: 12px;
  background: #fff;
  border-radius: 8px;
  box-sizing: border-box;
}
.wg-qr :deep(svg) {
  display: block;
  width: 100%;
  height: auto;
  /* Keep the modules crisp rather than smoothed when the box scales the symbol. */
  image-rendering: pixelated;
  shape-rendering: crispEdges;
}
</style>
