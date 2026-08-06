<template>
  <div>
    <div class="page-title">
      <h1>{{ t('pages.wireguard') }}</h1>
      <span class="meta">{{ t('pages.wireguard_meta') }} · {{ data?.ts || '…' }}</span>
    </div>

    <div class="toolbar">
      <button class="primary" @click="load" :disabled="loading">{{ t('common.refresh') }}</button>
      <button @click="sync" :disabled="busy || !data?.running">{{ t('wg.sync') }}</button>
      <button @click="control('restart')" :disabled="busy">{{ t('wg.restart') }}</button>
      <button @click="control(data?.running ? 'down' : 'up')" :disabled="busy">
        {{ data?.running ? t('wg.stop') : t('wg.start') }}
      </button>
      <button @click="openConf" :disabled="busy">{{ t('wg.view_conf') }}</button>
      <button @click="ping" :disabled="busy || !data?.running">{{ t('wg.ping') }}</button>
      <span v-if="data" class="badge" :class="data.running ? 'ok' : 'down'">
        {{ data.running ? t('common.on') : t('common.off') }}
      </span>
    </div>

    <!-- Not installed: nothing else on this page can work, so say only that. -->
    <div v-if="data && !data.installed" class="tile" style="border-left:3px solid var(--down)">
      <h3>{{ t('wg.not_installed_title') }}</h3>
      <p style="font-size:12px;color:var(--sub);line-height:1.6;margin:6px 0 0">
        {{ t('wg.not_installed_hint') }}
      </p>
      <pre class="mono" style="margin-top:8px;font-size:11px">brew install wireguard-tools wireguard-go</pre>
    </div>

    <template v-else>
      <!-- Readiness: a running tunnel that carries no traffic is the normal
           failure on macOS, so blocking gaps are stated before the status tiles. -->
      <div
        v-if="readiness && !readiness.ready"
        class="tile"
        style="margin-bottom:12px;border-left:3px solid var(--down)"
      >
        <h3>{{ t('wg.not_ready') }}</h3>
        <p style="font-size:12px;color:var(--sub);line-height:1.6;margin:6px 0 8px">
          {{ t('wg.not_ready_hint') }}
        </p>
        <table class="dense">
          <tbody>
            <tr v-for="c in blockingChecks" :key="c.id">
              <td style="width:28px"><span class="led err"></span></td>
              <td><strong>{{ checkLabel(c.id) }}</strong></td>
              <td style="font-size:11px;color:var(--sub)">{{ checkFix(c.id) }}</td>
              <td class="mono" style="font-size:10px;max-width:200px;overflow:hidden;text-overflow:ellipsis">{{ c.detail }}</td>
              <td style="text-align:right">
                <button
                  v-if="c.id === 'forwarding'"
                  class="tiny primary"
                  @click="fixForwarding"
                  :disabled="busy"
                >{{ t('wg.enable') }}</button>
                <button
                  v-else-if="c.id === 'nat'"
                  class="tiny primary"
                  @click="fixNat"
                  :disabled="busy"
                >{{ t('wg.install') }}</button>
                <button
                  v-else-if="c.id === 'endpoint'"
                  class="tiny"
                  @click="settingsOpen = true"
                  :disabled="busy"
                >{{ t('wg.configure') }}</button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <!-- Peers copied from another server can never handshake here. This is a
           config-shape problem, not a runtime one, so it gets its own callout. -->
      <div
        v-if="readiness?.peer_origin?.conflict"
        class="tile"
        style="margin-bottom:12px;border-left:3px solid var(--warn)"
      >
        <h3>{{ t('wg.foreign_peers_title') }}</h3>
        <p style="font-size:12px;color:var(--sub);line-height:1.6;margin:6px 0 0">
          {{ t('wg.foreign_peers_hint', { n: readiness.peer_origin.foreign, total: readiness.peer_origin.total }) }}
        </p>
      </div>

      <div class="dash-grid" style="margin-bottom:12px" v-if="data">
        <div class="tile span-3">
          <h3>{{ t('wg.listen_port') }}</h3>
          <div class="v">{{ data.listen_port || '—' }}</div>
          <div class="sub">{{ data.interface }}</div>
        </div>
        <div class="tile span-3">
          <h3>{{ t('wg.subnet') }}</h3>
          <div class="v" style="font-size:15px">{{ data.address || data.subnet }}</div>
          <div class="sub">MTU {{ data.mtu }}</div>
        </div>
        <div class="tile span-3">
          <h3>{{ t('wg.active_peers') }}</h3>
          <div class="v">{{ data.active_count }}/{{ data.peer_count }}</div>
          <div class="sub" v-if="data.stale_count">{{ t('wg.stale', { n: data.stale_count }) }}</div>
        </div>
        <div class="tile span-3">
          <h3>{{ t('wg.keepalive_missing') }}</h3>
          <div class="v" :style="{ color: data.keepalive_missing ? 'var(--warn)' : 'var(--ok)' }">
            {{ data.keepalive_missing }}
          </div>
        </div>
      </div>

      <div class="tile" style="margin-bottom:12px" v-if="data">
        <h3>{{ t('wg.server_key') }}</h3>
        <div class="mono" style="font-size:11px;word-break:break-all">{{ data.public_key || '—' }}</div>
        <div class="sub" style="margin-top:6px">
          {{ t('wg.endpoint') }}:
          <code>{{ data.endpoint || t('wg.endpoint_unset') }}</code>
          <button class="tiny" style="margin-left:8px" @click="settingsOpen = true">{{ t('common.edit') }}</button>
        </div>
      </div>

      <!-- Peers -->
      <h2 class="section-title">{{ t('wg.peers') }} ({{ data?.peer_count || 0 }})</h2>
      <div class="table-wrap">
        <table class="dense">
          <thead>
            <tr>
              <th style="width:28px"></th>
              <th>{{ t('wg.peer_name') }}</th>
              <th>{{ t('wg.address') }}</th>
              <th>{{ t('wg.remote_endpoint') }}</th>
              <th>{{ t('wg.handshake') }}</th>
              <th>{{ t('wg.keepalive') }}</th>
              <th>{{ t('wg.traffic') }}</th>
              <th class="actions">{{ t('common.actions') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="p in data?.peers || []" :key="p.pubkey">
              <td><span class="led" :class="p.active ? 'on' : (p.stale ? 'warn' : 'off')"></span></td>
              <td>
                <strong>{{ p.name || t('wg.unnamed') }}</strong>
                <span v-if="p.psk" class="badge ok" style="margin-left:4px">PSK</span>
                <span v-if="!p.reissuable" class="badge" style="margin-left:4px" :title="t('wg.no_stored_key')">
                  {{ t('wg.key_not_stored') }}
                </span>
                <div class="mono" style="font-size:9px;color:var(--sub)" :title="p.pubkey">
                  {{ p.pubkey.slice(0, 16) }}…
                </div>
              </td>
              <td class="mono">{{ p.allowed_ips }}</td>
              <td class="mono" style="font-size:10px">{{ p.endpoint || '—' }}</td>
              <td style="font-size:11px">
                <span v-if="p.last_handshake" :class="p.active ? 'badge ok' : (p.stale ? 'badge warn' : 'badge')">
                  {{ relativeAge(p.handshake_age) }}
                </span>
                <span v-else style="color:var(--sub)">{{ t('wg.never') }}</span>
              </td>
              <td>
                <span class="badge" :class="p.keepalive && p.keepalive !== 'off' && p.keepalive !== '0' ? 'ok' : 'warn'">
                  {{ p.keepalive || 'off' }}
                </span>
              </td>
              <td class="mono" style="font-size:10px">↑{{ p.tx_human }} ↓{{ p.rx_human }}</td>
              <td class="actions">
                <button class="tiny primary" @click="showPeer(p)" :disabled="busy || !p.reissuable">
                  {{ t('wg.config') }}
                </button>
                <button class="tiny" @click="togglePsk(p)" :disabled="busy">
                  {{ p.psk ? t('wg.psk_remove') : t('wg.psk_add') }}
                </button>
                <button class="tiny danger" @click="removePeer(p)" :disabled="busy">{{ t('common.delete') }}</button>
              </td>
            </tr>
            <tr v-if="!(data?.peers || []).length">
              <td colspan="8" style="color:var(--sub)">{{ loading ? t('common.loading') : t('wg.no_peers') }}</td>
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
          <h3>{{ t('wg.batch_add') }}</h3>
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
          <h3>{{ t('wg.import_peer') }}</h3>
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
        <h3>{{ t('wg.ping_result', { ok: pingResult.reachable, total: pingResult.total }) }}</h3>
        <table class="dense">
          <tbody>
            <tr v-for="r in pingResult.results" :key="r.pubkey">
              <td style="width:28px"><span class="led" :class="r.reachable ? 'on' : 'err'"></span></td>
              <td>{{ r.name || t('wg.unnamed') }}</td>
              <td class="mono">{{ r.ip }}</td>
              <td class="mono">{{ r.latency_ms != null ? r.latency_ms + ' ms' : '—' }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </template>

    <!-- Peer config dialog: formats + QR -->
    <div v-if="peerDialog" class="modal-bg" @click.self="peerDialog = null">
      <div class="modal" role="dialog" aria-labelledby="wg-peer-title" ref="peerPanel" tabindex="-1">
        <h3 id="wg-peer-title">{{ t('wg.config_for', { name: peerDialog.name }) }}</h3>
        <div class="tabs" style="margin:8px 0">
          <button
            v-for="f in formats"
            :key="f"
            :class="{ active: peerFormat === f }"
            :aria-pressed="peerFormat === f"
            @click="selectFormat(f)"
          >{{ formatLabel(f) }}</button>
        </div>
        <p v-if="!peerDialog.endpoint_configured" style="font-size:11px;color:var(--warn);line-height:1.5;margin:0 0 8px">
          {{ t('wg.endpoint_missing_warn') }}
        </p>
        <pre class="mono" style="max-height:180px;overflow:auto;font-size:11px">{{ peerContent }}</pre>
        <!-- The QR must never be the thing that gets clipped: give it its own
             bounded, centred box with a white quiet zone so a phone camera can
             actually resolve it against a dark theme. -->
        <div v-if="qrSvg" class="wg-qr" v-html="qrSvg"></div>
        <p v-else-if="qrTooLong" style="font-size:11px;color:var(--sub);margin-top:8px">
          {{ t('wg.qr_too_long') }}
        </p>
        <div class="modal-actions">
          <button @click="copyPeer">{{ t('common.copy') }}</button>
          <a class="btn" :href="downloadUrl" :download="peerFilename">{{ t('common.download') }}</a>
          <button class="primary" @click="peerDialog = null">{{ t('common.close') }}</button>
        </div>
      </div>
    </div>

    <!-- Raw server config -->
    <div v-if="confDialog" class="modal-bg" @click.self="confDialog = null">
      <div class="modal" role="dialog" aria-labelledby="wg-conf-title" ref="confPanel" tabindex="-1">
        <h3 id="wg-conf-title">{{ t('wg.view_conf') }}</h3>
        <p style="font-size:11px;color:var(--sub);margin:4px 0 8px">
          {{ confDialog.redacted ? t('wg.conf_redacted') : t('wg.conf_revealed') }}
        </p>
        <pre class="mono" style="max-height:340px;overflow:auto;font-size:11px">{{ confDialog.conf }}</pre>
        <div class="modal-actions">
          <button v-if="confDialog.redacted" class="danger" @click="openConf(true)">{{ t('wg.reveal_key') }}</button>
          <button class="primary" @click="confDialog = null">{{ t('common.close') }}</button>
        </div>
      </div>
    </div>

    <!-- Settings -->
    <div v-if="settingsOpen" class="modal-bg" @click.self="settingsOpen = false">
      <div class="modal" role="dialog" aria-labelledby="wg-settings-title" ref="settingsPanel" tabindex="-1">
        <h3 id="wg-settings-title">{{ t('wg.settings') }}</h3>
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
            <input v-model="cfgForm.wan_interface" type="text" :placeholder="readiness?.wan_interface || 'en0'" />
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
        <div class="modal-actions">
          <button @click="settingsOpen = false">{{ t('common.cancel') }}</button>
          <button class="primary" @click="saveSettings" :disabled="busy">{{ t('common.save') }}</button>
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
import { startVisibleInterval } from '../lib/poll'

const toast = inject('toast')
const { t } = injectI18n()

const data = ref(null)
const readiness = ref(null)
const nextIp = ref('')
const loading = ref(false)
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
const formats = ['wg', 'clash', 'clashfull', 'sr']

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
  forwarding: 'wg.check_forwarding',
  nat: 'wg.check_nat',
  pf: 'wg.check_pf',
  boot: 'wg.check_boot',
  peer_origin: 'wg.check_peer_origin',
  stale_runtime: 'wg.check_stale_runtime',
}
const CHECK_FIXES = {
  installed: 'wg.fix_installed',
  conf: 'wg.fix_conf',
  running: 'wg.fix_running',
  endpoint: 'wg.fix_endpoint',
  forwarding: 'wg.fix_forwarding',
  nat: 'wg.fix_nat',
  pf: 'wg.fix_pf',
  boot: 'wg.fix_boot',
  peer_origin: 'wg.fix_peer_origin',
  stale_runtime: 'wg.fix_stale_runtime',
}
const FORMAT_LABELS = {
  wg: 'wg.fmt_wg',
  clash: 'wg.fmt_clash',
  clashfull: 'wg.fmt_clashfull',
  sr: 'wg.fmt_sr',
}

const checkLabel = (id) => (CHECK_LABELS[id] ? t(CHECK_LABELS[id]) : id)
const checkFix = (id) => (CHECK_FIXES[id] ? t(CHECK_FIXES[id]) : '')
const formatLabel = (fmt) => (FORMAT_LABELS[fmt] ? t(FORMAT_LABELS[fmt]) : fmt)

const form = ref({ name: '', ip: '', mode: 'split', psk: false, keep_key: true })
const batch = ref({ count: 3, prefix: 'peer' })
const imp = ref({ pubkey: '', ip: '', name: '' })
const cfgForm = ref({
  endpoint: '', subnet: '', listen_port: 51820, lan_cidr: '',
  wan_interface: '', dns: '', mtu: 1280,
})

const blockingChecks = computed(
  () => (readiness.value?.checks || []).filter((c) => !c.ok && c.level === 'error'),
)
const downloadUrl = computed(
  () => (peerDialog.value ? wireguardPeerDownloadUrl(peerDialog.value.pubkey, peerFormat.value) : '#'),
)
const peerFilename = computed(() => {
  const safe = String(peerDialog.value?.name || 'peer').replace(/[^A-Za-z0-9_-]/g, '-')
  const ext = { wg: '.conf', clash: '-clash.yaml', clashfull: '-clash-full.yaml', sr: '-shadowrocket.txt' }
  return safe + (ext[peerFormat.value] || '.conf')
})

function relativeAge(seconds) {
  const s = Number(seconds || 0)
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

async function load() {
  const generation = ++loadGeneration
  loading.value = true
  try {
    const [status, ready] = await Promise.all([
      getWireguard(),
      getWireguardReadiness().catch(() => null),
    ])
    if (generation !== loadGeneration) return
    data.value = status
    readiness.value = ready
    if (status.installed) {
      getWireguardNextIp()
        .then((r) => { if (generation === loadGeneration) nextIp.value = r.next_ip })
        .catch(() => {})
    }
  } catch (e) {
    if (generation === loadGeneration) toast('❌ ' + e.message)
  } finally {
    if (generation === loadGeneration) loading.value = false
  }
}

async function withBusy(fn, okKey) {
  if (busy.value) return null
  busy.value = true
  try {
    const result = await fn()
    if (okKey) toast('✅ ' + t(okKey))
    await load()
    return result
  } catch (e) {
    toast('❌ ' + e.message)
    return null
  } finally {
    busy.value = false
  }
}

const sync = () => withBusy(syncWireguard, 'wg.synced')
const ping = () => withBusy(async () => { pingResult.value = await pingWireguardPeers() })

function control(action) {
  const key = { up: 'wg.confirm_up', down: 'wg.confirm_down', restart: 'wg.confirm_restart' }[action]
  if (key && !confirm(t(key))) return
  return withBusy(() => controlWireguardInterface(action), 'wg.interface_done')
}

const fixForwarding = () => withBusy(() => setWireguardForwarding(true), 'wg.forwarding_enabled')
const fixNat = () => withBusy(() => remediateWireguard('nat', true), 'wg.nat_installed')

async function createPeer() {
  const created = await withBusy(
    () => addWireguardPeer({ ...form.value, ip: form.value.ip || '' }),
    'wg.peer_created',
  )
  if (!created) return
  form.value = { name: '', ip: '', mode: form.value.mode, psk: false, keep_key: form.value.keep_key }
  // Show the config immediately: with keep_key off this is the only time the
  // private key is ever available.
  peerDialog.value = {
    pubkey: created.pub,
    name: created.name,
    endpoint_configured: created.endpoint_configured,
  }
  peerFormat.value = 'wg'
  peerContent.value = created.client_conf
  renderQr(created.client_conf, 'wg')
}

async function createBatch() {
  const result = await withBusy(
    () => batchAddWireguardPeers({ ...batch.value, mode: form.value.mode, keep_key: true }),
    null,
  )
  if (result) toast('✅ ' + t('wg.batch_created', { n: result.created }))
}

async function doImport() {
  const result = await withBusy(() => importWireguardPeer({ ...imp.value }), 'wg.peer_imported')
  if (result) imp.value = { pubkey: '', ip: '', name: '' }
}

function removePeer(peer) {
  if (!confirm(t('wg.confirm_delete', { name: peer.name || peer.pubkey.slice(0, 16) }))) return
  return withBusy(() => deleteWireguardPeer(peer.pubkey), 'wg.peer_deleted')
}

function togglePsk(peer) {
  const op = peer.psk ? 'remove' : 'add'
  if (!confirm(t(op === 'add' ? 'wg.confirm_psk_add' : 'wg.confirm_psk_remove'))) return
  return withBusy(() => setWireguardPsk(peer.pubkey, op), 'wg.psk_changed')
}

async function showPeer(peer) {
  try {
    const result = await getWireguardPeerConfig(peer.pubkey, 'wg')
    peerDialog.value = {
      pubkey: peer.pubkey,
      name: result.name,
      endpoint_configured: Boolean(data.value?.endpoint),
    }
    peerFormat.value = 'wg'
    peerContent.value = result.content
    renderQr(result.content, 'wg')
  } catch (e) {
    toast('❌ ' + e.message)
  }
}

async function selectFormat(fmt) {
  if (!peerDialog.value) return
  peerFormat.value = fmt
  try {
    const result = await getWireguardPeerConfig(peerDialog.value.pubkey, fmt)
    peerContent.value = result.content
    renderQr(result.content, fmt)
  } catch (e) {
    toast('❌ ' + e.message)
  }
}

async function copyPeer() {
  try {
    await navigator.clipboard.writeText(peerContent.value)
    toast('✅ ' + t('common.copied'))
  } catch {
    toast('❌ ' + t('common.copy_failed'))
  }
}

async function openConf(reveal = false) {
  if (reveal && !confirm(t('wg.confirm_reveal'))) return
  try {
    confDialog.value = await getWireguardConf(reveal)
  } catch (e) {
    toast('❌ ' + e.message)
  }
}

async function saveSettings() {
  const patch = {}
  for (const [key, value] of Object.entries(cfgForm.value)) {
    if (value !== '' && value != null) patch[key] = value
  }
  const result = await withBusy(() => putWireguardSettings(patch), 'wg.settings_saved')
  if (result) settingsOpen.value = false
}

onMounted(async () => {
  await load()
  try {
    const current = await getWireguardSettings()
    cfgForm.value = { ...cfgForm.value, ...current.settings }
  } catch {}
  // Peer handshake ages only matter at ~minute resolution; 20s keeps the table
  // live without hammering `wg show` (which is a privileged call per poll).
  poll = startVisibleInterval(load, 20000)
})

onUnmounted(() => {
  if (typeof poll === 'function') poll()
  poll = null
  loadGeneration += 1
})
</script>

<style scoped>
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
