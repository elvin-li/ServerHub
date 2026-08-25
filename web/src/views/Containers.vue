<template>
  <div>
    <div class="page-title">
      <h1>{{ t('pages.docker') }}</h1>
      <span class="meta">
        {{ t('pages.docker_meta') }} ·
        <template v-if="data">
          {{ t('common.engine') }} {{ data.engine_up ? t('common.running') : t('common.stopped') }} · {{ containers.length }}
          <span v-if="finiteText(data.update_checked_at, '')"> · {{ finiteText(data.update_checked_at) }}</span>
        </template>
      </span>
    </div>

    <div class="tabs">
      <button :class="{ active: tab==='containers' }" :aria-pressed="tab === 'containers'" @click="tab='containers'">{{ t('docker.containers') }}</button>
      <button :class="{ active: tab==='images' }" :aria-pressed="tab === 'images'" @click="tab='images'; loadImages()">{{ t('docker.images') }}</button>
      <button :class="{ active: tab==='volumes' }" :aria-pressed="tab === 'volumes'" @click="tab='volumes'; loadVolumes()">{{ t('docker.volumes') }}</button>
      <button :class="{ active: tab==='networks' }" :aria-pressed="tab === 'networks'" @click="tab='networks'; loadNetworks()">{{ t('docker.networks') }}</button>
      <button :class="{ active: tab==='engine' }" :aria-pressed="tab === 'engine'" @click="tab='engine'; loadEngine()">{{ t('docker.engine_settings') }}</button>
    </div>

    <!-- Unraid-style bulk actions -->
    <div class="toolbar" v-if="tab==='containers'">
      <button class="primary" @click="refresh" :disabled="busy">{{ t('common.refresh') }}</button>
      <button class="primary" :disabled="busy" @click="showRun=true">{{ t('docker.create') }}</button>
      <input v-model="q" type="text" :placeholder="t('docker.filter_ph')" style="min-width:140px"  :aria-label="t('docker.filter_ph')"/>
      <!-- role=status: the count is the only feedback the filter box and the
           hide-system toggle give, and it changed silently for a screen
           reader. Same pattern as the Services filter count. -->
      <span class="meta-count" role="status">{{ filteredContainers.length }} / {{ containers.length }}</span>
      <button :disabled="busy" @click="doAll('start')">{{ t('docker.start_all') }}</button>
      <button :disabled="busy" @click="doAll('stop')">{{ t('docker.stop_all') }}</button>
      <button :disabled="busy" @click="doAll('pause')">{{ t('docker.pause_all') }}</button>
      <button :disabled="busy" @click="doAll('unpause')">{{ t('docker.unpause_all') }}</button>
      <button :disabled="busy" @click="checkUpdates">{{ t('docker.check_updates') }}</button>
      <button :disabled="busy || !selected.length" @click="batchSel('start')">{{ t('docker.start_sel') }}</button>
      <button :disabled="busy || !selected.length" @click="batchSel('stop')">{{ t('docker.stop_sel') }}</button>
      <button :disabled="busy || !selected.length" @click="batchSel('restart')">{{ t('docker.restart_sel') }}</button>
      <button class="danger" :disabled="busy || !selected.length" @click="batchSel('remove')">{{ t('docker.remove_sel') }}</button>
      <button class="danger" :disabled="busy" @click="doPrune('system')">{{ t('docker.prune') }}</button>
      <button class="danger" :disabled="busy" @click="doPrune('containers')">{{ t('docker.prune_exited') }}</button>
      <label style="font-size:11px;color:var(--sub);display:flex;align-items:center;gap:4px;margin-left:6px">
        <input type="checkbox" v-model="groupByProject" /> {{ t('docker.group_project') }}
      </label>
      <label style="font-size:11px;color:var(--sub);display:flex;align-items:center;gap:4px">
        <input type="checkbox" v-model="advanced" /> {{ t('docker.advanced') }}
      </label>
      <label
        v-if="systemCount"
        style="font-size:11px;color:var(--sub);display:flex;align-items:center;gap:4px"
        :title="t('docker.hide_system_hint')"
      >
        <input type="checkbox" v-model="hideSystem" /> {{ t('docker.hide_system') }} ({{ systemCount }})
      </label>
    </div>

    <div v-if="jobLog" class="tile" style="margin-bottom:8px">
      <div class="row">
        <strong style="font-size:12px">{{ t('docker.job_log') }}</strong>
        <button class="tiny" @click="closeJobLog">{{ t('common.close') }}</button>
      </div>
      <pre v-if="jobLog" class="log" style="max-height:160px;margin-top:6px" role="log" aria-live="polite">{{ finiteText(jobLog) }}</pre>
    </div>

    <!-- The banner is not part of the chain below: when a 20s re-poll fails
         the rows the operator was reading stay on screen under it instead of
         being replaced wholesale (the LoadFailure contract — same as Alerts
         and the Users accounts table). Only a failed *first* load, with
         nothing fetched yet, renders the banner alone. -->
    <LoadFailure v-if="listError" :detail="listError" :retry="refresh" :busy="busy" />
    <SkeletonLoader v-if="!data && !listError" :cols="7" :rows="6" />
    <!-- Only claim the engine is down once a reply actually said so. -->
    <div v-else-if="data && !data.engine_up" class="placeholder">{{ t('docker.engine_off') }}</div>

    <template v-else-if="data && tab==='containers'">
      <!-- An empty engine and a filter that misses are different answers
           (Tools/Scheduler pattern): before this the tab rendered nothing at
           all — no table, no message — for either state. -->
      <div v-if="!containers.length" class="placeholder">{{ t('docker.no_containers') }}</div>
      <div v-else-if="!filteredContainers.length" class="placeholder">{{ t('common.no_match') }}</div>
      <template v-for="grp in displayGroups" :key="grp.name">
        <h2 v-if="groupByProject" class="section-title">
          {{ finiteText(grp.name) }}
          <span class="badge">{{ grp.items.length }}</span>
        </h2>
        <div class="table-wrap" :style="groupByProject ? 'margin-bottom:10px' : ''">
          <table class="dense fit-m">
            <thead>
              <tr>
                <th style="width:28px"><input type="checkbox" :checked="allSelected(grp.items)" :aria-label="t('common.select_all')" @change="toggleAll(grp.items, $event)" /></th>
                <th><span class="sr-only">{{ t('common.status_led') }}</span></th>
                <th>{{ t('docker.app') }}</th>
                <th class="col-hide-m">{{ t('docker.version_update') }}</th>
                <th class="col-hide-m">{{ t('docker.network') }}</th>
                <th v-if="advanced" class="col-hide-m">{{ t('docker.container_ip') }}</th>
                <th class="col-hide-m">{{ t('docker.ports') }}</th>
                <th class="col-hide-m">{{ t('docker.mounts') }}</th>
                <th class="col-hide-m">{{ t('docker.cpu_mem') }}</th>
                <th v-if="advanced" class="col-hide-m">Net I/O</th>
                <th class="col-hide-m">{{ t('docker.autostart') }}</th>
                <th class="col-hide-m">{{ t('docker.uptime') }}</th>
                <th>{{ t('common.actions') }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="c in grp.items" :key="c.id">
<!-- Named after the container (Files/Services row-checkbox pattern):
                     anonymous checkboxes cannot be told apart in a form-controls list. -->
                <td><input type="checkbox" :value="c.id" v-model="selected" :aria-label="t('common.select_row_name', { name: finiteText(c.name, '') || finiteText(c.id) })" /></td>
                <!-- The LED is the row's whole status signal on mobile (the
                     uptime column is col-hide-m); colour alone says nothing to
                     a screen reader, so hide the paint and spell the state —
                     same treatment as the Network binding and Dashboard rows. -->
                <td>
                  <span class="led" :class="ledClass(c)" aria-hidden="true"></span>
                  <span class="sr-only">{{ ledText(c) }}</span>
                </td>
                <td style="max-width:260px">
                  <strong>{{ finiteText(c.name) }}</strong>
                  <span v-if="c.sandbox" class="badge" style="background:var(--bar-track);color:var(--sub)">pause</span>
                  <span v-else-if="c.system" class="badge" style="background:color-mix(in srgb, #6366f1 20%, transparent);color:color-mix(in srgb, #6366f1 40%, var(--txt))">k8s</span>
                  <div
                    class="mono"
                    style="color:var(--sub);font-size:10px;max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"
                    :title="finiteText(c.raw_name, '') || finiteText(c.id)"
                  >{{ finiteText(c.subtitle, '') || finiteText(c.id) }}</div>
                  <span v-if="finiteText(c.project, '')" class="badge accent">{{ finiteText(c.project) }}</span>
                  <div v-if="finiteText(c.network, '') || finiteText(c.ports, '')" class="show-m sub mono">{{ [finiteText(c.network, ''), finiteText(c.ports, '')].filter(Boolean).join(' · ') }}</div>
                  <div class="show-m sub mono">{{ shortImage(c.image) }}</div>
                  <span v-if="c.update === true" class="show-m badge warn">{{ t('docker.updateable') }}</span>
                  <span v-else-if="c.update === false" class="show-m badge ok">{{ t('docker.latest') }}</span>
                  <div class="show-m" @click.stop>
                    <button
                      class="tiny"
                      :class="c.autostart ? 'primary' : ''"
                      :disabled="busy"
                      :title="t('docker.current_policy', { p: finiteText(c.restart_policy, '') || 'no' })"
                      @click="toggleAutostart(c)"
                    >{{ t('docker.autostart') }} {{ c.autostart ? t('common.yes') : t('common.no') }}</button>
                  </div>
                </td>
                <td class="col-hide-m">
                  <div class="mono" :title="finiteText(c.image)">{{ shortImage(c.image) }}</div>
                  <span v-if="c.update === true" class="badge warn">{{ t('docker.updateable') }}</span>
                  <span v-else-if="c.update === false" class="badge ok">{{ t('docker.latest') }}</span>
                </td>
                <td class="mono col-hide-m">{{ finiteText(c.network) }}</td>
                <td v-if="advanced" class="mono col-hide-m">{{ finiteText(c.ip) }}</td>
                <td class="mono col-hide-m" style="max-width:120px;overflow:hidden;text-overflow:ellipsis" :title="finiteText(c.ports)">{{ finiteText(c.ports) }}</td>
                <td class="mono col-hide-m" style="max-width:140px" :title="mountTitle(c)">
                  <template v-if="(c.mounts||[]).length">
                    <div v-for="(m,i) in c.mounts.slice(0,2)" :key="i" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
                      {{ shortPath(m.src) }} → {{ finiteText(m.dst) }}
                    </div>
                    <span v-if="c.mounts.length>2" style="color:var(--sub)">+{{ c.mounts.length-2 }}</span>
                  </template>
                  <template v-else>—</template>
                </td>
                <td class="mono col-hide-m">
                  <div>
                    {{ finiteText(stats[c.id]?.cpu) }}
                    <span v-if="cpuNum(stats[c.id]?.cpu)!=null" class="mini-bar">
                      <i :style="{ width: Math.min(100, cpuNum(stats[c.id]?.cpu)) + '%' }"></i>
                    </span>
                  </div>
                  <div style="color:var(--sub)">{{ finiteText(stats[c.id]?.mem_pct, '') || finiteText(stats[c.id]?.mem) }}</div>
                </td>
                <td v-if="advanced" class="mono col-hide-m" style="font-size:10px">{{ finiteText(stats[c.id]?.net) }}</td>
                <td class="col-hide-m">
                  <button
                    class="tiny"
                    :class="c.autostart ? 'primary' : ''"
                    :disabled="busy"
                    :title="t('docker.current_policy', { p: finiteText(c.restart_policy, '') || 'no' })"
                    @click="toggleAutostart(c)"
                  >{{ c.autostart ? t('common.yes') : t('common.no') }}</button>
                  <div class="mono" style="color:var(--sub)">{{ finiteText(c.restart_policy) }}</div>
                </td>
                <td class="col-hide-m">{{ finiteText(c.status) }}</td>
                <td class="ops">
                  <a v-if="c.url" class="btn tiny primary" :href="finiteText(c.url, '')" target="_blank">WebUI</a>
                  <button v-if="c.raw_state==='running'" class="tiny" :disabled="busy" @click="act(c,'restart')">{{ t('dashboard.act_restart') }}</button>
                  <button v-if="c.raw_state==='running'" class="tiny hide-m" :disabled="busy" @click="act(c,'pause')">{{ t('docker.pause') }}</button>
                  <button v-if="c.raw_state==='paused'" class="tiny primary hide-m" :disabled="busy" @click="act(c,'unpause')">{{ t('docker.unpause') }}</button>
                  <button v-if="c.raw_state==='running'||c.raw_state==='paused'" class="tiny danger" :disabled="busy" @click="act(c,'stop')">{{ t('dashboard.act_stop') }}</button>
                  <button v-if="c.raw_state!=='running'&&c.raw_state!=='paused'" class="tiny primary" :disabled="busy" @click="act(c,'start')">{{ t('dashboard.act_start') }}</button>
                  <button class="tiny" :disabled="busy" @click="openLogs(c)">{{ t('docker.logs') }}</button>
                  <button class="tiny hide-m" :disabled="busy" @click="openExec(c)">{{ t('docker.console') }}</button>
                  <button class="tiny" :disabled="busy" @click="openInspect(c)">{{ t('common.details') }}</button>
                  <button v-if="c.update" class="tiny primary hide-m" :disabled="busy" @click="doUpdate(c)">{{ t('docker.update') }}</button>
                  <button v-if="c.raw_state!=='running'&&c.raw_state!=='paused'" class="tiny danger" :disabled="busy" @click="act(c,'remove')">{{ t('docker.remove') }}</button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </template>
    </template>

    <template v-else-if="data && tab==='images'">
      <div class="toolbar">
        <input v-model="pullImage" type="text" :placeholder="t('docker.pull_ph')" style="min-width:200px"  :aria-label="t('docker.pull_ph')"/>
        <button class="primary" :disabled="busy || !pullImage.trim()" @click="doPull">{{ t('docker.pull') }}</button>
        <button class="danger" :disabled="busy" @click="doPrune('images')">{{ t('docker.prune_images') }}</button>
        <button @click="loadImages" :disabled="busy">{{ t('common.refresh') }}</button>
      </div>
      <LoadFailure v-if="subError.images" :detail="subError.images" :retry="loadImages" :busy="busy" />
      <SkeletonLoader v-if="!subLoaded.images" :cols="6" :rows="6" />
      <div v-else class="table-wrap">
        <table class="dense fit-m">
          <thead><tr><th>{{ t('docker.repo') }}</th><th>Tag</th><th class="col-hide-m">ID</th><th>{{ t('docker.size') }}</th><th class="col-hide-m">{{ t('docker.created') }}</th><th>{{ t('common.actions') }}</th></tr></thead>
          <tbody>
            <tr v-for="(im,i) in images" :key="i">
              <td class="mono">
                {{ finiteText(im.Repository) }}
                <div class="show-m sub">{{ String(finiteText(im.ID, '')).replace('sha256:','').slice(0,12) }} · {{ finiteText(im.CreatedSince, '') || finiteText(im.CreatedAt) }}</div>
              </td>
              <td>{{ finiteText(im.Tag) }}</td>
              <td class="mono col-hide-m">{{ String(finiteText(im.ID, '')).replace('sha256:','').slice(0,12) }}</td>
              <td>{{ finiteText(im.Size) }}</td>
              <td class="col-hide-m">{{ finiteText(im.CreatedSince, '') || finiteText(im.CreatedAt) }}</td>
              <td class="ops">
                <button class="tiny danger" :disabled="busy" @click="rmi(im)">{{ t('docker.remove') }}</button>
              </td>
            </tr>
            <tr v-if="!images.length && !subError.images"><td colspan="6" class="empty-row">{{ t('docker.no_images') }}</td></tr>
          </tbody>
        </table>
      </div>
    </template>

    <template v-else-if="data && tab==='volumes'">
      <div class="toolbar">
        <input v-model="newVol" type="text" :placeholder="t('docker.new_vol_ph')" style="min-width:160px"  :aria-label="t('docker.new_vol_ph')"/>
        <button class="primary" :disabled="busy || !newVol.trim()" @click="createVol">{{ t('docker.create_vol') }}</button>
        <button class="danger" :disabled="busy" @click="doPrune('volumes')">{{ t('docker.prune_volumes') }}</button>
        <button @click="loadVolumes" :disabled="busy">{{ t('common.refresh') }}</button>
      </div>
      <LoadFailure v-if="subError.volumes" :detail="subError.volumes" :retry="loadVolumes" :busy="busy" />
      <SkeletonLoader v-if="!subLoaded.volumes" :cols="4" :rows="5" />
      <div v-else class="table-wrap">
        <table class="dense fit-m">
          <thead><tr><th>{{ t('common.name') }}</th><th class="col-hide-m">{{ t('docker.driver') }}</th><th>{{ t('docker.mountpoint') }}</th><th>{{ t('common.actions') }}</th></tr></thead>
          <tbody>
            <tr v-for="v in volumes" :key="v.Name">
              <td class="mono">
                {{ finiteText(v.Name) }}
                <div class="show-m sub">{{ finiteText(v.Driver) }}</div>
              </td>
              <td class="col-hide-m">{{ finiteText(v.Driver) }}</td>
              <td class="mono" style="font-size:11px">{{ finiteText(v.Mountpoint) }}</td>
              <td class="ops">
                <button class="tiny danger" :disabled="busy" @click="rmVol(v)">{{ t('docker.remove') }}</button>
              </td>
            </tr>
            <tr v-if="!volumes.length && !subError.volumes"><td colspan="4" class="empty-row">{{ t('docker.no_volumes') }}</td></tr>
          </tbody>
        </table>
      </div>
    </template>

    <template v-else-if="data && tab==='networks'">
      <div class="toolbar">
        <input v-model="newNet" type="text" :placeholder="t('docker.new_net_ph')" style="min-width:160px"  :aria-label="t('docker.new_net_ph')"/>
        <button class="primary" :disabled="busy || !newNet.trim()" @click="createNet">{{ t('docker.create_net') }}</button>
        <button class="danger" :disabled="busy" @click="doPrune('networks')">{{ t('docker.prune_networks') }}</button>
        <button @click="loadNetworks" :disabled="busy">{{ t('common.refresh') }}</button>
      </div>
      <LoadFailure v-if="subError.networks" :detail="subError.networks" :retry="loadNetworks" :busy="busy" />
      <SkeletonLoader v-if="!subLoaded.networks" :cols="5" :rows="4" />
      <div v-else class="table-wrap">
        <table class="dense fit-m">
          <thead><tr><th>{{ t('common.name') }}</th><th>{{ t('docker.driver') }}</th><th class="col-hide-m">Scope</th><th class="col-hide-m">ID</th><th>{{ t('common.actions') }}</th></tr></thead>
          <tbody>
            <tr v-for="n in networks" :key="n.Id">
              <td>
                {{ finiteText(n.Name) }}
                <div class="show-m sub mono">{{ finiteText(n.Scope) }} · {{ finiteText(n.Id) }}</div>
              </td>
              <td>{{ finiteText(n.Driver) }}</td>
              <td class="col-hide-m">{{ finiteText(n.Scope) }}</td>
              <td class="mono col-hide-m">{{ finiteText(n.Id) }}</td>
              <td class="ops">
                <button
                  v-if="!['bridge','host','none'].includes(n.Name)"
                  class="tiny danger"
                  :disabled="busy"
                  @click="rmNet(n)"
                >{{ t('docker.remove') }}</button>
                <span v-else class="sub">{{ t('docker.builtin') }}</span>
              </td>
            </tr>
            <tr v-if="!networks.length && !subError.networks"><td colspan="5" class="empty-row">{{ t('docker.no_networks') }}</td></tr>
          </tbody>
        </table>
      </div>
    </template>

    <template v-else-if="data && tab==='engine'">
      <div class="tile" style="margin-bottom:12px;border-left:3px solid var(--accent)">
        <p style="font-size:12px;color:var(--sub);line-height:1.55;margin:0">
          {{ t('docker.engine_hint') }}
        </p>
      </div>
      <LoadFailure v-if="subError.engine" :detail="subError.engine" :retry="loadEngine" :busy="busy" />
      <SkeletonLoader v-if="!subLoaded.engine" variant="tiles" :rows="2" :span="6" :tile-height="260" />
      <div v-else-if="engineInfo?.engine_up" class="two-col">
        <div class="card">
          <h2 class="section-title" style="margin-top:0">{{ t('docker.engine_info') }}</h2>
          <div class="kv">
            <div class="k">{{ t('common.name') }}</div><div class="mono">{{ finiteText(engineInfo.info?.Name) }}</div>
            <div class="k">{{ t('docker.version') }}</div><div class="mono">{{ finiteText(engineInfo.info?.ServerVersion) }}</div>
            <div class="k">OrbStack</div><div class="mono">{{ finiteText(engineInfo.orb_version) }}</div>
            <div class="k">OS</div><div class="mono">{{ finiteText(engineInfo.info?.OperatingSystem) }}</div>
            <div class="k">Arch</div><div>{{ finiteText(engineInfo.info?.Architecture) }}</div>
            <div class="k">CPU</div><div>{{ finiteN(engineInfo.info?.NCPU) }}</div>
            <div class="k">{{ t('docker.mem') }}</div><div>{{ engineMem }} GB</div>
            <div class="k">Root</div><div class="mono">{{ finiteText(engineInfo.info?.DockerRootDir) }}</div>
            <div class="k">{{ t('docker.driver') }}</div><div class="mono">{{ finiteText(engineInfo.info?.Driver) }}</div>
            <div class="k">{{ t('docker.log_driver') }}</div><div class="mono">{{ finiteText(engineInfo.info?.LoggingDriver) }}</div>
            <div class="k">Cgroup</div><div class="mono">{{ finiteText(engineInfo.info?.CgroupDriver) }}</div>
          </div>
        </div>
        <div class="card">
          <h2 class="section-title" style="margin-top:0">{{ t('docker.resources') }}</h2>
          <div class="kv">
            <div class="k">{{ t('docker.total_containers') }}</div><div>{{ finiteN(engineInfo.info?.Containers) }}</div>
            <div class="k">{{ t('common.running') }}</div><div><span class="badge ok">{{ finiteN(engineInfo.info?.ContainersRunning, 0) }}</span></div>
            <div class="k">{{ t('docker.paused') }}</div><div>{{ finiteN(engineInfo.info?.ContainersPaused, 0) }}</div>
            <div class="k">{{ t('common.stopped') }}</div><div>{{ finiteN(engineInfo.info?.ContainersStopped, 0) }}</div>
            <div class="k">{{ t('docker.images') }}</div><div>{{ finiteN(engineInfo.info?.Images, 0) }}</div>
            <div class="k">docker CLI</div><div class="mono" style="font-size:10px">{{ finiteText(engineInfo.docker_cli) }}</div>
            <div class="k">orb CLI</div><div class="mono" style="font-size:10px">{{ finiteText(engineInfo.orb_cli) }}</div>
          </div>
          <div class="btns" style="margin-top:12px">
            <button class="tiny" @click="loadEngine">{{ t('common.refresh') }}</button>
            <router-link class="btn tiny" to="/settings">{{ t('docker.settings_link') }}</router-link>
          </div>
        </div>
      </div>
      <!-- Reached only after the probe returned, so this states the engine is
           down rather than hedging between "off" and "still loading". -->
      <div v-else-if="!subError.engine" class="placeholder">{{ finiteText(engineInfo?.message, '') || t('docker.engine_off') }}</div>
    </template>

    <!-- logs drawer -->
    <div v-if="logDrawer" class="drawer-bg" @click.self="closeLogs" role="presentation">
      <div ref="logPanel" class="drawer" role="dialog" aria-modal="true" aria-labelledby="ctr-log-drawer-title" tabindex="-1">
        <div class="row" style="margin-bottom:10px">
          <span id="ctr-log-drawer-title" class="name">{{ t('docker.logs') }} · {{ finiteText(logName) }}</span>
          <button class="tiny" @click="closeLogs">{{ t('common.close') }}</button>
        </div>
        <pre class="log" ref="logEl">{{ finiteText(logText) }}</pre>
      </div>
    </div>

    <!-- exec console -->
    <div ref="execPanel" v-if="execC" class="modal-bg" @click.self="execC=null" role="presentation">
      <div class="modal" role="dialog" aria-modal="true" aria-labelledby="ctr-exec-title">
        <div class="row" style="margin-bottom:10px">
          <span id="ctr-exec-title" class="name">{{ t('docker.console') }} · {{ finiteText(execC.name) }}</span>
          <button class="tiny" @click="execC=null">{{ t('common.close') }}</button>
        </div>
        <p style="color:var(--sub);font-size:11px;margin-bottom:8px">
          {{ t('docker.exec_hint') }}
        </p>
        <div class="row" style="gap:6px;margin-bottom:8px">
          <input v-model="execCmd" type="text" style="flex:1" :placeholder="t('docker.exec_ph')" :disabled="busy" @keyup.enter="runExec"  :aria-label="t('docker.exec_ph')"/>
          <button class="primary tiny" :disabled="busy" @click="runExec">{{ t('docker.exec_run') }}</button>
        </div>
        <pre class="log" style="min-height:200px">{{ finiteText(execOut, '') || t('docker.exec_output_ph') }}</pre>
      </div>
    </div>

    <!-- Create / run container -->
    <div ref="runPanel" v-if="showRun" class="modal-bg" @click.self="showRun=false" role="presentation">
      <div class="modal" style="max-width:520px;max-height:90vh;overflow:auto" role="dialog" aria-modal="true" aria-labelledby="ctr-run-title">
        <div class="row" style="margin-bottom:12px">
          <span id="ctr-run-title" class="name">{{ t('docker.create_run') }}</span>
          <button class="tiny" @click="showRun=false">{{ t('common.close') }}</button>
        </div>
        <div class="field-grid">
          <label>{{ t('docker.image') }} *</label>
          <input v-model="runForm.image" type="text" placeholder="nginx:alpine" :aria-label="t('docker.image')" />
          <label>{{ t('common.name') }}</label>
          <input v-model="runForm.name" type="text" placeholder="my-nginx" :aria-label="t('common.name')" />
          <label>{{ t('docker.restart_policy') }}</label>
          <select v-model="runForm.restart" :aria-label="t('docker.restart_policy')">
            <option value="no">no</option>
            <option value="unless-stopped">unless-stopped</option>
            <option value="always">always</option>
            <option value="on-failure">on-failure</option>
          </select>
          <label>{{ t('docker.ports') }}</label>
          <input v-model="runForm.ports" type="text" placeholder="8080:80, 443:443" :aria-label="t('docker.ports')" />
          <label>{{ t('docker.volumes') }}</label>
          <input v-model="runForm.volumes" type="text" placeholder="/host/path:/container" :aria-label="t('docker.volumes')" />
          <label>{{ t('docker.env') }}</label>
          <input v-model="runForm.env" type="text" placeholder="KEY=val, FOO=bar" :aria-label="t('docker.env')" />
          <label>{{ t('docker.network') }}</label>
          <input v-model="runForm.network" type="text" :placeholder="t('docker.network_ph')"  :aria-label="t('docker.network_ph')"/>
          <label>{{ t('docker.command') }}</label>
          <input v-model="runForm.command" type="text" :placeholder="t('docker.optional_ph')"  :aria-label="t('docker.optional_ph')"/>
          <label>{{ t('docker.privileged') }}</label>
          <input type="checkbox" v-model="runForm.privileged" :aria-label="t('docker.privileged')" />
        </div>
        <div class="btns" style="margin-top:14px">
          <button class="primary" :disabled="busy || !runForm.image.trim()" @click="doRun">{{ t('docker.create_start') }}</button>
          <button @click="showRun=false">{{ t('common.cancel') }}</button>
        </div>
      </div>
    </div>

    <!-- inspect -->
    <div v-if="inspectData" class="drawer-bg" @click.self="inspectData=null" role="presentation">
      <div ref="inspectPanel" class="drawer" style="overflow:auto" role="dialog" aria-modal="true" aria-labelledby="ctr-inspect-title" tabindex="-1">
        <div class="row" style="margin-bottom:10px">
          <span id="ctr-inspect-title" class="name">{{ t('common.details') }} · {{ finiteText(inspectData.Name) }}</span>
          <button class="tiny" @click="inspectData=null">{{ t('common.close') }}</button>
        </div>
        <div class="kv">
          <div class="k">{{ t('docker.image') }}</div><div class="mono">{{ finiteText(inspectData.Image) }}</div>
          <div class="k">{{ t('common.status') }}</div><div>{{ finiteText(inspectData.State?.Status) }} · {{ finiteText(inspectData.State?.Health) }}</div>
          <div class="k">{{ t('docker.network') }}</div><div>{{ (inspectData.Networks||[]).map(n => finiteText(n, '')).filter(Boolean).join(', ') }}</div>
          <div class="k">{{ t('docker.restart_policy') }}</div><div>{{ finiteText(inspectData.RestartPolicy?.Name) }}</div>
        </div>
        <h2 class="section-title">{{ t('docker.mounts') }}</h2>
        <div v-for="(m,i) in inspectData.Mounts||[]" :key="i" class="mono" style="margin-bottom:3px">
          {{ finiteText(m.Source) }} → {{ finiteText(m.Destination) }}
        </div>
        <h2 class="section-title">{{ t('docker.env_masked') }}</h2>
        <pre class="log" style="max-height:180px">{{ (inspectData.Env||[]).map(e => finiteText(e, '')).filter(Boolean).join('\n') }}</pre>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, inject, nextTick, onMounted, onUnmounted, ref } from 'vue'
import { startVisibleInterval } from '../lib/poll'
import {
  batchContainers, containerAction, checkContainerUpdates, containersAll, createNetwork,
  createVolume, execContainer, getContainers, getDockerInfo, getImages, getNetworks,
  getStackJob, getVolumes, inspectContainer, openContainerLogs, prune, pullImageApi,
  removeImage, removeNetwork, removeVolume, runContainer, setRestartPolicy, updateContainer,
} from '../api/client'
import { injectI18n } from '../i18n'
import { finiteN, finiteText } from '../lib/finite'
import { useDismissable } from '../composables/useDismissable'
import SkeletonLoader from '../components/SkeletonLoader.vue'
import LoadFailure from '../components/LoadFailure.vue'

const toast = inject('toast')
const { t } = injectI18n()
const tab = ref('containers')
const data = ref(null)
const busy = ref(false)
const selected = ref([])
const groupByProject = ref(true)
const advanced = ref(false)
const hideSystem = ref(true)
const q = ref('')
const images = ref([])
const volumes = ref([])
const networks = ref([])
const engineInfo = ref(null)
// Per-tab first-load latch. The sub-tabs load lazily on click, so each one had a
// window where its table asserted "no images" / "no volumes" and the engine tab
// showed a message that hedged between "off" and "loading" because it genuinely
// could not tell. Latched rather than derived from `busy`, so pressing Refresh
// on a populated tab does not blank it back to shimmer bars.
const subLoaded = ref({ images: false, volumes: false, networks: false, engine: false })
// Per-tab failure text, keyed the same way. Kept separate from `subLoaded` so a
// failed tab does not hold the skeleton up forever, and so switching tabs does not
// carry one tab's error onto another.
const subError = ref({ images: '', volumes: '', networks: '', engine: '' })
const listError = ref('')
const showRun = ref(false)
const runPanel = ref(null)
const pullImage = ref('')
const newVol = ref('')
const newNet = ref('')
const runForm = ref({
  image: '', name: '', restart: 'unless-stopped',
  ports: '', volumes: '', env: '', network: '', command: '', privileged: false,
})
const logDrawer = ref(false)
const logPanel = ref(null)
const logName = ref('')
const logText = ref('')
let logScrollQueued = false
const logEl = ref(null)
const inspectData = ref(null)
const inspectPanel = ref(null)
const execC = ref(null)
const execPanel = ref(null)
const execCmd = ref('ls -la')
const execOut = ref('')
const jobLog = ref('')
const jobId = ref(null)
let es = null
let timer = null
let jobTimer = null
let jobPollGeneration = 0
const refreshTimers = new Set()

function stopJobPolling() {
  jobPollGeneration += 1
  if (jobTimer) clearTimeout(jobTimer)
  jobTimer = null
}

function closeJobLog() {
  stopJobPolling()
  jobLog.value = ''
  jobId.value = ''
}

let pageAlive = true

function stillOnList(generation) {
  return pageAlive && generation === listGeneration
}

function scheduleRefresh(delay) {
  const generation = listGeneration
  const id = setTimeout(() => {
    refreshTimers.delete(id)
    if (generation !== listGeneration || !pageAlive) return
    void refresh()
  }, delay)
  refreshTimers.add(id)
}

const containers = computed(() => data.value?.containers || [])
const stats = computed(() => data.value?.stats || {})
const engineMem = computed(() => {
  const n = Number(engineInfo.value?.info?.MemTotal)
  if (!Number.isFinite(n) || n <= 0) return '—'
  return (n / 2 ** 30).toFixed(1)
})

const systemCount = computed(() => containers.value.filter(c => c.system).length)

const filteredContainers = computed(() => {
  let list = containers.value
  if (hideSystem.value) list = list.filter(c => !c.system)
  const qq = q.value.trim().toLowerCase()
  if (!qq) return list
  return list.filter(c =>
    (c.name || '').toLowerCase().includes(qq)
    || (c.id || '').toLowerCase().includes(qq)
    || (c.subtitle || '').toLowerCase().includes(qq)
    || (c.image || '').toLowerCase().includes(qq)
    || (c.project || '').toLowerCase().includes(qq)
  )
})

const displayGroups = computed(() => {
  const list = filteredContainers.value
  // The empty and filter-miss placeholders own the no-rows case; an empty
  // "All" table with only headers under them would just restate it.
  if (!list.length) return []
  if (!groupByProject.value) return [{ name: t('common.all'), items: list }]
  const map = {}
  for (const c of list) {
    const k = c.project || t('docker.other_group')
    map[k] = map[k] || []
    map[k].push(c)
  }
  return Object.keys(map).sort().map(k => ({ name: k, items: map[k] }))
})

function ledClass(c) {
  if (c.raw_state === 'paused') return 'warn'
  if (c.state === 'ok') return 'on'
  if (c.state === 'warn') return 'warn'
  if (c.state === 'stopped') return 'off'
  return 'err'
}
// The sr-only twin of ledClass, in words. Existing keys only: the engine tab
// already says Paused, and the page header already says Running/Stopped.
function ledText(c) {
  if (c.raw_state === 'paused') return t('docker.paused')
  if (c.state === 'ok') return t('common.running')
  if (c.state === 'warn') return t('common.warn')
  if (c.state === 'stopped') return t('common.stopped')
  return t('common.error')
}
function shortImage(img) {
  const s = String(finiteText(img, ''))
  if (!s) return '—'
  const leaf = s.split('/').pop()
  return leaf.length > 40 ? leaf.slice(0, 38) + '…' : leaf
}
function shortPath(p) {
  const s = String(finiteText(p, ''))
  if (!s) return ''
  const parts = s.split('/')
  return parts.length > 3 ? '…/' + parts.slice(-2).join('/') : s
}
function mountTitle(c) {
  return (c.mounts || []).map(m => `${finiteText(m.src)} → ${finiteText(m.dst)}`).join('\n')
}
function cpuNum(s) {
  if (!s) return null
  const n = parseFloat(String(s).replace('%', ''))
  return Number.isFinite(n) ? n : null
}
function allSelected(items) {
  return items.length && items.every(c => selected.value.includes(c.id))
}
function toggleAll(items, ev) {
  const ids = items.map(c => c.id)
  if (ev.target.checked) {
    selected.value = Array.from(new Set([...selected.value, ...ids]))
  } else {
    selected.value = selected.value.filter(id => !ids.includes(id))
  }
}

let listGeneration = 0

async function refresh(manual = false) {
  const generation = ++listGeneration
  try {
    const next = await getContainers(true)
    if (generation !== listGeneration) return
    data.value = next
    listError.value = ''
  } catch (e) {
    if (generation !== listGeneration) return false
    // Without this, a failed list read left `data` null and the page rendered
    // "engine is not running" — blaming Docker for what was an API failure.
    listError.value = finiteText(e.message || String(e), '')
    // Background 20s ticks stay silent: LoadFailure already marks the state on
    // screen, and re-toasting every interval while the panel is down is noise.
    // Button and retry clicks pass their event as `manual`, so those still toast.
    if (manual) toast('❌ ' + finiteText(e.message))
    // Failed tick → lib/poll.js backoff while the server stays unreachable.
    return false
  }
}

function batchToast(j) {
  const text = t('docker.done_count', { done: finiteN(j.done, 0), total: finiteN(j.total, 0) })
  toast(j.ok === false ? `⚠ ${text}` : `✅ ${text}`)
}

async function act(c, action) {
  if (action === 'stop' && !confirm(t('docker.confirm_stop', { name: finiteText(c.name) }))) return
  if (action === 'remove' && !confirm(t('docker.confirm_remove', { name: finiteText(c.name) }))) return
  // restart and pause also take a running service offline, so they get the same
  // confirmation as stop. Previously only stop/remove were guarded, and the
  // restart/pause buttons sit immediately next to them in the row.
  if (action === 'restart' && !confirm(t('docker.confirm_restart', { name: finiteText(c.name) }))) return
  if (action === 'pause' && !confirm(t('docker.confirm_pause', { name: finiteText(c.name) }))) return
  const generation = listGeneration
  busy.value = true
  try {
    const r = await containerAction(c.id, action)
    if (!stillOnList(generation)) return
    if (action === 'update' && r.job_id) {
      toast('🚀 ' + t('docker.update_job_started'))
      watchJob(r.job_id)
    } else {
      toast(r.ok ? `✅ ${finiteText(c.name)}` : `❌ ${finiteText(r.message)}`)
      if (r.ok) scheduleRefresh(800)
    }
  } catch (e) {
    if (!stillOnList(generation)) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    // The 20s poll's refresh() bumps listGeneration while an action is in flight.
    if (pageAlive) busy.value = false
  }
}

async function doUpdate(c) {
  if (!confirm(t('docker.confirm_update', { name: finiteText(c.name) }))) return
  const generation = listGeneration
  busy.value = true
  try {
    const j = await updateContainer(c.id)
    if (!stillOnList(generation)) return
    toast('🚀 ' + (finiteText(j.message, '') || t('docker.updating')))
    if (j.job_id) watchJob(j.job_id)
  } catch (e) {
    if (!stillOnList(generation)) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (pageAlive) busy.value = false
  }
}

async function doAll(action) {
  const labels = {
    start: t('docker.start_all'),
    stop: t('docker.stop_all'),
    pause: t('docker.pause_all'),
    unpause: t('docker.unpause_all'),
  }
  if (!confirm(t('docker.confirm_action', { action: finiteText(labels[action], '') || finiteText(action) }))) return
  const generation = listGeneration
  busy.value = true
  try {
    const j = await containersAll(action)
    if (!stillOnList(generation)) return
    batchToast(j)
    scheduleRefresh(1000)
  } catch (e) {
    if (!stillOnList(generation)) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (pageAlive) busy.value = false
  }
}

async function batchSel(action) {
  if (!selected.value.length) return
  if (!confirm(t('docker.confirm_batch', { action: finiteText(action), n: finiteN(selected.value.length, 0) }))) return
  const generation = listGeneration
  busy.value = true
  try {
    const j = await batchContainers(action, selected.value)
    if (!stillOnList(generation)) return
    batchToast(j)
    scheduleRefresh(1000)
  } catch (e) {
    if (!stillOnList(generation)) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (pageAlive) busy.value = false
  }
}

async function checkUpdates() {
  if (!confirm(t('docker.confirm_check_updates'))) return
  const generation = listGeneration
  busy.value = true
  try {
    const j = await checkContainerUpdates()
    if (!stillOnList(generation)) return
    toast('🚀 ' + finiteText(j.message))
    if (j.job_id) watchJob(j.job_id)
  } catch (e) {
    if (!stillOnList(generation)) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (pageAlive) busy.value = false
  }
}

function watchJob(id) {
  stopJobPolling()
  jobId.value = id
  jobLog.value = t('common.loading')
  const generation = jobPollGeneration

  const poll = async () => {
    jobTimer = null
    // Skip the fetch while the tab is hidden, but keep re-arming. The job keeps
    // running server-side and the log is re-read as soon as the tab is visible
    // again, so nothing is lost -- this only stops a background tab from asking
    // the host for job status every 1.5s indefinitely. The page's main refresh
    // already uses the visibility-aware helper in lib/poll.js; this hand-rolled
    // loop needs its own check because it cannot use a fixed interval.
    if (typeof document !== 'undefined' && document.hidden) {
      if (generation === jobPollGeneration) jobTimer = setTimeout(poll, 1500)
      return
    }
    try {
      const j = await getStackJob(id)
      if (generation !== jobPollGeneration) return
      jobLog.value = j.log || ''
      if (!j.running) {
        stopJobPolling()
        void refresh()
        return
      }
    } catch (e) {
      if (generation !== jobPollGeneration) return
      // Say so instead of leaving the log frozen at its last content. The loop
      // still re-arms (a transient failure should recover), but the operator can
      // now see that the job status is not being read.
      jobLog.value = `${jobLog.value || ''}\n⚠ ${finiteText(e.message || e)}`.trim()
    }
    if (generation === jobPollGeneration) jobTimer = setTimeout(poll, 1500)
  }

  void poll()
}

//: A chatty container emits faster than anyone can read.  Without a ceiling the
//: string grows without bound and every message replaces the whole <pre> text
//: node, so the drawer eventually stalls the tab.
const LOG_MAX_LINES = 2000

function appendLog(chunk) {
  let next = logText.value + finiteText(chunk, '')
  const lines = next.split('\n')
  if (lines.length > LOG_MAX_LINES) next = lines.slice(-LOG_MAX_LINES).join('\n')
  logText.value = next
}

function scrollLogToEnd() {
  // Coalesce into one frame: assigning scrollTop per message forces a synchronous
  // layout on every line, which is what actually janks the drawer.
  if (logScrollQueued) return
  logScrollQueued = true
  const generation = listGeneration
  requestAnimationFrame(() => {
    logScrollQueued = false
    if (generation !== listGeneration) return
    if (logEl.value) logEl.value.scrollTop = logEl.value.scrollHeight
  })
}

function openLogs(c) {
  closeLogs()
  logName.value = finiteText(c.name)
  logText.value = t('docker.log_connecting') + '\n'
  logDrawer.value = true
  es = openContainerLogs(c.id, { tail: 300, follow: true })
  es.onmessage = (ev) => {
    appendLog(ev.data + '\n')
    if (ev.data?.includes('configured logging driver does not support reading')) {
      appendLog('\n' + t('docker.log_driver_none') + '\n')
      es?.close(); es = null
    }
    scrollLogToEnd()
  }
  es.onerror = () => { if (es) { appendLog(`\n—— ${t('docker.log_ended')} ——\n`); es.close(); es = null } }
}
function closeLogs() { es?.close(); es = null; logDrawer.value = false }

function openExec(c) {
  execC.value = c
  execCmd.value = 'ls -la'
  execOut.value = ''
}
async function runExec() {
  if (!execC.value) return
  // Re-entry guard. The Run button is bound to `busy`, but the command input
  // fires this on Enter and was not, and busy was only set *after* entry -- so
  // holding Enter issued concurrent `docker exec` calls into a live container.
  if (busy.value) return
  const generation = listGeneration
  busy.value = true
  try {
    const j = await execContainer(execC.value.id, execCmd.value)
    if (!stillOnList(generation)) return
    execOut.value = finiteText(j.output, '') || finiteText(j.message, '') || JSON.stringify(j)
  } catch (e) {
    if (!stillOnList(generation)) return
    execOut.value = finiteText(e.message, '')
  } finally {
    if (pageAlive) busy.value = false
  }
}

async function openInspect(c) {
  const generation = listGeneration
  busy.value = true
  try {
    const next = await inspectContainer(c.id)
    if (generation !== listGeneration) return
    inspectData.value = next
  } catch (e) {
    if (generation !== listGeneration) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (pageAlive) busy.value = false
  }
}

async function loadImages() {
  const generation = listGeneration
  try {
    const next = (await getImages()).images || []
    if (generation !== listGeneration) return
    images.value = next
    subError.value.images = ''
  } catch (e) {
    if (generation !== listGeneration) return
    subError.value.images = finiteText(e.message || String(e), '')
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (generation === listGeneration) subLoaded.value.images = true
  }
}
async function loadVolumes() {
  const generation = listGeneration
  try {
    const next = (await getVolumes()).volumes || []
    if (generation !== listGeneration) return
    volumes.value = next
    subError.value.volumes = ''
  } catch (e) {
    if (generation !== listGeneration) return
    subError.value.volumes = finiteText(e.message || String(e), '')
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (generation === listGeneration) subLoaded.value.volumes = true
  }
}
async function loadNetworks() {
  const generation = listGeneration
  try {
    const next = (await getNetworks()).networks || []
    if (generation !== listGeneration) return
    networks.value = next
    subError.value.networks = ''
  } catch (e) {
    if (generation !== listGeneration) return
    subError.value.networks = finiteText(e.message || String(e), '')
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (generation === listGeneration) subLoaded.value.networks = true
  }
}
async function loadEngine() {
  const generation = listGeneration
  try {
    const next = await getDockerInfo()
    if (generation !== listGeneration) return
    engineInfo.value = next
    subError.value.engine = ''
  } catch (e) {
    if (generation !== listGeneration) return
    subError.value.engine = finiteText(e.message || String(e), '')
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (generation === listGeneration) subLoaded.value.engine = true
  }
}
async function doPrune(kind) {
  const tips = {
    system: t('docker.confirm_prune_system'),
    images: t('docker.confirm_prune_images'),
    volumes: t('docker.confirm_prune_volumes'),
    networks: t('docker.confirm_prune_networks'),
    containers: t('docker.confirm_prune_containers'),
  }
  if (!confirm(tips[kind] || t('docker.confirm_prune'))) return
  const generation = listGeneration
  busy.value = true
  try {
    const r = await prune(kind)
    if (!stillOnList(generation)) return
    toast(r.ok ? '✅ ' + t('docker.done') : '❌ ' + finiteText(r.message))
    refresh()
    if (tab.value === 'images') loadImages()
    if (tab.value === 'volumes') loadVolumes()
    if (tab.value === 'networks') loadNetworks()
  } catch (e) {
    if (!stillOnList(generation)) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    // refresh() bumps listGeneration, so a generation match would leave
    // prune stuck in the busy state.
    if (pageAlive) busy.value = false
  }
}

function splitCsv(s) {
  return (s || '').split(/[,;\n]/).map(x => x.trim()).filter(Boolean)
}

async function doRun() {
  const generation = listGeneration
  busy.value = true
  try {
    const body = {
      image: runForm.value.image.trim(),
      name: runForm.value.name.trim() || null,
      restart: runForm.value.restart,
      ports: splitCsv(runForm.value.ports),
      volumes: splitCsv(runForm.value.volumes),
      env: splitCsv(runForm.value.env),
      network: runForm.value.network.trim() || null,
      command: runForm.value.command.trim() || null,
      privileged: !!runForm.value.privileged,
    }
    const j = await runContainer(body)
    if (!stillOnList(generation)) return
    toast(j.ok ? '✅ ' + t('docker.container_created') : `❌ ${finiteText(j.message)}`)
    if (j.ok) {
      showRun.value = false
      scheduleRefresh(800)
    }
  } catch (e) {
    if (!stillOnList(generation)) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (pageAlive) busy.value = false
  }
}

async function doPull() {
  if (!pullImage.value.trim()) return
  const generation = listGeneration
  busy.value = true
  try {
    const j = await pullImageApi(pullImage.value.trim())
    if (!stillOnList(generation)) return
    toast(j.ok ? '✅ ' + t('docker.pull_done') : `❌ ${finiteText(j.message)}`)
    stopJobPolling()
    jobLog.value = finiteText(j.message, '')
    loadImages()
  } catch (e) {
    if (!stillOnList(generation)) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (pageAlive) busy.value = false
  }
}

async function rmi(im) {
  const repo = finiteText(im.Repository, '')
  const tag = finiteText(im.Tag, '')
  const ref = (repo && tag && repo !== '<none>')
    ? `${repo}:${tag}`
    : finiteText(String(im.ID || '').replace('sha256:', '').slice(0, 12), '')
  if (!ref || !confirm(t('docker.confirm_remove_image', { image: finiteText(ref) }))) return
  const generation = listGeneration
  busy.value = true
  try {
    const j = await removeImage(ref, true)
    if (!stillOnList(generation)) return
    toast(j.ok ? '✅ ' + t('docker.removed') : `❌ ${finiteText(j.message)}`)
    loadImages()
  } catch (e) {
    if (!stillOnList(generation)) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (pageAlive) busy.value = false
  }
}

async function createVol() {
  const generation = listGeneration
  busy.value = true
  try {
    const j = await createVolume(newVol.value.trim())
    if (!stillOnList(generation)) return
    toast(j.ok ? '✅ ' + t('docker.volume_created') : `❌ ${finiteText(j.message)}`)
    newVol.value = ''
    loadVolumes()
  } catch (e) {
    if (!stillOnList(generation)) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (pageAlive) busy.value = false
  }
}

async function rmVol(v) {
  if (!confirm(t('docker.confirm_remove_volume', { name: finiteText(v.Name) }))) return
  const generation = listGeneration
  busy.value = true
  try {
    const j = await removeVolume(v.Name, true)
    if (!stillOnList(generation)) return
    toast(j.ok ? '✅ ' + t('docker.removed') : `❌ ${finiteText(j.message)}`)
    loadVolumes()
  } catch (e) {
    if (!stillOnList(generation)) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (pageAlive) busy.value = false
  }
}

async function createNet() {
  const generation = listGeneration
  busy.value = true
  try {
    const j = await createNetwork(newNet.value.trim())
    if (!stillOnList(generation)) return
    toast(j.ok ? '✅ ' + t('docker.network_created') : `❌ ${finiteText(j.message)}`)
    newNet.value = ''
    loadNetworks()
  } catch (e) {
    if (!stillOnList(generation)) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (pageAlive) busy.value = false
  }
}

async function rmNet(n) {
  if (!confirm(t('docker.confirm_remove_network', { name: finiteText(n.Name) }))) return
  const generation = listGeneration
  busy.value = true
  try {
    const j = await removeNetwork(n.Name)
    if (!stillOnList(generation)) return
    toast(j.ok ? '✅ ' + t('docker.removed') : `❌ ${finiteText(j.message)}`)
    loadNetworks()
  } catch (e) {
    if (!stillOnList(generation)) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (pageAlive) busy.value = false
  }
}

async function toggleAutostart(c) {
  const next = c.autostart ? 'no' : 'unless-stopped'
  const key = c.autostart ? 'docker.confirm_autostart_off' : 'docker.confirm_autostart_on'
  if (!confirm(t(key, { name: finiteText(c.name) }))) return
  const generation = listGeneration
  busy.value = true
  try {
    const j = await setRestartPolicy(c.id, next)
    if (!stillOnList(generation)) return
    toast(j.ok ? `✅ ${t('docker.autostart')} → ${next}` : `❌ ${finiteText(j.message)}`)
    refresh()
  } catch (e) {
    if (!stillOnList(generation)) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    // refresh() bumps listGeneration, so a generation match would leave
    // autostart stuck in the busy state.
    if (pageAlive) busy.value = false
  }
}

onMounted(() => { pageAlive = true; refresh(); timer = startVisibleInterval(refresh, 20000) })
onUnmounted(() => {
  pageAlive = false
  listGeneration += 1
  if (typeof timer === 'function') timer()
  timer = null
  stopJobPolling()
  for (const id of refreshTimers) clearTimeout(id)
  refreshTimers.clear()
  closeLogs()
})


// Escape dismisses each dialog, focus returns to whatever opened it, and Tab
// cannot wander to the page behind the overlay.
useDismissable(execC, () => { execC.value = null }, execPanel)
useDismissable(showRun, () => { showRun.value = false }, runPanel)

useDismissable(logDrawer, () => { closeLogs() }, logPanel)

useDismissable(inspectData, () => { inspectData.value = null }, inspectPanel)
</script>
