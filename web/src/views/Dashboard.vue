<template>
  <div class="dash">
    <!-- The page has no visible title -- the host card is the heading the eye
         uses -- but a document with no h1 leaves a screen reader without the
         one landmark that names where it landed. -->
    <h1 class="sr-only">{{ t('nav.dashboard') }}</h1>
    <!-- A failed load must not read as "still loading". The banner stays up while
         the failure persists and clears on the next successful poll, so stale
         tiles below it are never presented as current. -->
    <div
      v-if="loadError"
      class="tile"
      style="margin-bottom:12px;border-left:3px solid var(--down)"
      role="alert"
    >
      <div class="row">
        <span class="name">{{ t('dashboard.load_failed') }}</span>
        <button class="tiny" :disabled="loading" @click="retryLoad">
          {{ t('common.retry') }}
        </button>
      </div>
      <div class="sub mono" style="margin-top:4px">{{ finiteText(loadError) }}</div>
    </div>

    <!-- ===== Member view: only the services assigned to this account. The
         host metrics, containers, power and sensor tiles all read admin
         endpoints the member surface deliberately refuses, so none of them
         are rendered (or fetched) for a member session. ===== -->
    <template v-if="isMemberView">
      <div class="host-strip">
        <div class="host-main">
          <div class="host-name">{{ t('dashboard.member_title') }}</div>
          <div class="host-meta">
            <!-- role=status: this count is the poll's (and Refresh's) only
                 summary of the member's services and changed silently for a
                 screen reader — the Scheduler/VMs/Users toolbar-count rule. -->
            <span role="status">{{ t('dashboard.services_count', { total: finiteN(status?.service_total, '—'), ok: finiteN(status?.counts?.ok, 0) }) }}</span>
            <span class="dot">·</span>
            <span>{{ finiteText(status?.ts, '…') }}</span>
          </div>
        </div>
        <div class="host-pills">
          <button class="tiny" @click="refresh" :disabled="loading">{{ t('common.refresh') }}</button>
        </div>
      </div>
      <template v-for="g in status?.groups || []" :key="g.group">
        <h2 class="member-group">{{ finiteText(g.group) }}</h2>
        <div class="dash-grid">
          <div v-for="s in g.services || []" :key="s.id" class="tile span-4 member-svc">
            <div class="row">
              <!-- The LED is colour alone, and the sub line below prefers the
                   free-text detail over the state word, so a screen reader
                   heard "Plex · port 32400 responding" with nothing saying
                   whether that is up or down. Same treatment as the WireGuard
                   ping rows: hide the paint, spell the state. -->
              <span class="led" :class="led(s.state)" aria-hidden="true"></span>
              <span class="sr-only">{{ ledText(s.state) }}</span>
              <span class="name">{{ finiteText(s.name) }}</span>
            </div>
            <div class="sub" style="margin-top:4px">{{ finiteText(s.detail, '') || finiteText(s.state) }}</div>
            <div class="row" style="margin-top:8px;gap:6px">
              <a v-if="s.url" class="btn tiny primary" :href="finiteText(s.url, '')" target="_blank" rel="noopener">{{ t('services.open') }}</a>
              <router-link class="btn tiny" to="/services">{{ t('services.more') }}</router-link>
            </div>
          </div>
        </div>
      </template>
      <div v-if="!status && !loadError" class="tile sub" role="status">
        {{ t('common.loading') }}
      </div>
      <div v-else-if="!(status?.groups || []).length && !loadError" class="tile sub">
        {{ t('dashboard.member_empty') }}
      </div>
    </template>

    <!-- Skeleton loading state. Gated on loadError too: without that, a failed
         first load left this placeholder on screen permanently, presented
         above the failure banner as if data were still on the way. -->
    <template v-else-if="!host && !sensors && !loadError">
      <div class="host-strip">
        <div class="host-main">
          <div class="skeleton skeleton-title" style="width:140px"></div>
          <div class="skeleton skeleton-text" style="width:280px"></div>
        </div>
      </div>
      <div class="dash-grid">
        <div class="tile span-4" v-for="i in 3" :key="i">
          <div class="skeleton skeleton-title"></div>
          <div class="skeleton skeleton-card"></div>
        </div>
        <div class="tile span-6" v-for="i in 2" :key="'b'+i">
          <div class="skeleton skeleton-title"></div>
          <div class="skeleton skeleton-card" style="height:80px"></div>
        </div>
      </div>
    </template>

    <template v-else>
    <div
      v-if="authState.canManage && status?.panel_update?.update_available"
      class="tile"
      style="margin-bottom:12px;border-left:3px solid var(--ok)"
      role="status"
    >
      <div class="row">
        <span class="name">{{ t('dashboard.update_available', { v: finiteText(status.panel_update.latest) }) }}</span>
        <router-link class="tiny primary" to="/tools?tab=updates">{{ t('dashboard.open_updates') }}</router-link>
      </div>
    </div>
    <!-- Host strip — Unraid / Glances header -->
    <div class="host-strip">
      <div class="host-main">
        <div class="host-name">
          <span>{{ finiteText(host?.hostname) }}</span>
          <!-- UPS / battery chip. The old full-width tile was mostly empty
               space, so the details it carried (name, runtime, threshold,
               policy switch) moved into this chip's tooltip. On AC it stays a
               quiet icon+percent; it only turns amber/red and grows a state
               word when the box is on battery, engaged, or restoring. -->
          <span
            v-if="ups?.present"
            class="host-ups"
            :class="upsChipClass"
            :title="upsTooltip"
            data-test="ups-indicator"
          >
            <component :is="upsIcon" :size="13" />
            <span v-if="finiteN(ups.battery_percent, null) != null" class="ups-pct">{{ withUnit(ups.battery_percent, '%') }}</span>
            <span v-if="upsStateLabel">{{ upsStateLabel }}</span>
          </span>
          <router-link
            v-if="ollamaChipVisible"
            class="host-ups host-ollama"
            :class="ollamaChipClass"
            :title="ollamaTooltip"
            data-test="ollama-indicator"
            to="/ollama"
          >
            <Bot :size="13" />
            <span class="ups-pct">{{ ollamaChipLabel }}</span>
          </router-link>
          <button
            v-if="authState.canManage"
            class="host-ups host-assist"
            type="button"
            data-test="assistant-brief-dash"
            :title="t('assistant.brief')"
            @click="openAssistBrief"
          >
            <Sparkles :size="13" />
            <span class="ups-pct">{{ t('assistant.short') }}</span>
          </button>
        </div>
        <div class="host-meta">
          <span>{{ finiteText(host?.cpu, 'CPU') }}</span>
          <span class="dot">·</span>
          <span>{{ t('dashboard.cores', { n: ncpu }) }}</span>
          <span class="dot">·</span>
          <span>{{ fmtGb(memTotal) }} RAM</span>
          <span class="dot">·</span>
          <span>{{ finiteText(host?.lan_ip, '') || finiteText(host?.host_ip) }}</span>
          <span class="dot">·</span>
          <span>{{ t('dashboard.uptime', { t: uptimeText }) }}</span>
        </div>
      </div>
      <div class="host-pills">
        <span class="pill" :class="engineUp ? 'ok' : 'down'">
          OrbStack {{ engineUp ? t('common.on') : t('common.off') }}
        </span>
        <span class="pill" :class="healthOk ? 'ok' : 'down'">
          {{ healthSummary }}
        </span>
        <span class="pill">{{ finiteText(sensors?.ts, '') || finiteText(status?.ts, '…') }}</span>
       <button class="tiny" @click="refreshAll" :disabled="loading">{{ t('common.refresh') }}</button>
      <span id="remote" class="pwr-group">
         <!-- Screen Sharing is off => no href, and an <a> without href has no
              implicit role, which makes aria-label a prohibited attribute that
              assistive tech drops. This control is icon-only, so dropping the
              label left it announced as nothing at all. State the role and
              carry the off state in aria-disabled instead. -->
         <a class="tiny primary"
           role="link"
           :class="{ disabled: !ss.running }"
           :href="ss.running ? finiteText(ss.vnc_url, '') : undefined"
           :tabindex="ss.running ? undefined : -1"
           :aria-disabled="ss.running ? undefined : 'true'"
           :title="ss.running ? t('power.connect') : t('power.off')"
           :aria-label="ss.running ? t('power.connect') : t('power.off')"
         ><Monitor :size="14" /></a>
         <!-- Both toggles require a successful power read. Without that gate a
              failed probe left powerData empty, so !ss.running was true and the
              Enable button appeared even when Screen Sharing was already on. -->
         <button v-if="powerLoaded && !ss.running" class="tiny primary" :disabled="ssBusy || loading" @click="enableSS" :title="t('power.enable_ss')" :aria-label="t('power.enable_ss')"><Play :size="13" /></button>
         <button v-else-if="powerLoaded" class="tiny danger" :disabled="ssBusy" @click="disableSS" :title="t('power.disable_ss')" :aria-label="t('power.disable_ss')"><Square :size="13" /></button>
         <button v-else class="tiny" disabled :title="t('power.state_unknown')" :aria-label="t('power.state_unknown')"><Play :size="13" /></button>
         <button class="tiny hide-m" :disabled="!ss.vnc_url" @click="copyVnc" :title="t('power.copy')" :aria-label="t('power.copy')"><Copy :size="13" /></button>
      </span>
      <span class="pwr-group">
          <button class="tiny" @click="doPower('sleep')" :disabled="pwrBusy" :title="t('power.sleep')" :aria-label="t('power.sleep')"><Moon :size="13" /></button>
          <button class="tiny" @click="doPower('restart')" :disabled="pwrBusy" :title="t('power.restart')" :aria-label="t('power.restart')"><RefreshCw :size="13" /></button>
          <button class="tiny danger" @click="doPower('shutdown')" :disabled="pwrBusy" :title="t('power.shutdown')" :aria-label="t('power.shutdown')"><Power :size="13" /></button>
      </span>
      </div>
    </div>

    <div class="dash-grid">
      <div class="span-12 monitor-toolbar">
        <span class="range-btns">
          <!-- The chosen range is signalled by the primary tint alone, which
               reaches a sighted reader and nobody else — same gap the `active`
               chips had (the a11y sweep only matched that class name). -->
          <button
            v-for="r in METRIC_RANGES"
            :key="r"
            class="tiny"
            :class="metricRange===r?'primary':''"
            :aria-pressed="metricRange === r"
            @click="setMetricRange(r)"
          >{{ r }}</button>
        </span>
        <!-- Aggregate tiers only start filling from the day this feature is
             enabled; charts render whatever exists and this line says why the
             window looks short instead of leaving it blank. -->
        <div v-if="metricsSwitching || historyHint" class="sub monitor-toolbar-hint">
          {{ metricsSwitching ? t('common.loading') : historyHint }}
        </div>
      </div>
      <!-- ===== CPU + Load ===== -->
      <div class="tile span-4 res-card" :class="{ 'am-surface': isMacSurface }">
        <h2>
          {{ t('dashboard.cpu') }}
          <span class="tile-tools">
            <span class="badge" data-test="cpu-badge" :class="cpuBadge">{{ cpuBadgeText }}</span>
            <span
              v-if="gpuUtilPct != null || gpuMemLabel"
              class="badge"
              data-test="gpu-badge"
              :class="gpuBadge"
            >
              <template v-if="gpuUtilPct != null">{{ t('dashboard.gpu_pct', { p: fmtN(gpuUtilPct) }) }}</template>
              <template v-if="gpuUtilPct != null && gpuMemLabel"> · </template>
              <span v-if="gpuMemLabel" data-test="gpu-mem">{{ gpuMemLabel }}</span>
            </span>
          </span>
        </h2>
        <!-- CPU left, GPU right — taller twin plots than Memory/Disk. -->
        <div v-if="isMacSurface" class="cpu-charts am-cpu">
          <LineChart
            class="am-chart"
            data-test="cpu-chart"
            :height="PROC_CHART_HEIGHT"
            fill
            :min="0"
            :max="100"
            percent
            stacked
            :areaOpacity="0.28"
            :title="t('dashboard.cpu_load')"
            :times="metricTimes"
            :series="cpuAppleChartSeries"
            unit="%"
          />
          <LineChart
            class="am-chart"
            data-test="gpu-chart"
            :height="PROC_CHART_HEIGHT"
            fill
            :min="0"
            :max="100"
            percent
            :areaOpacity="0.28"
            :title="gpuChartTitle"
            :times="metricTimes"
            :series="gpuChartSeries"
            unit="%"
          />
        </div>
        <div v-else class="cpu-charts">
          <LineChart
            data-test="cpu-chart"
            :height="PROC_CHART_HEIGHT"
            :min="0"
            :max="100"
            percent
            :title="t('dashboard.cpu_load')"
            :times="metricTimes"
            :series="cpuChartSeries"
            unit="%"
          />
          <LineChart
            data-test="gpu-chart"
            :height="PROC_CHART_HEIGHT"
            :min="0"
            :max="100"
            percent
            :title="gpuChartTitle"
            :times="metricTimes"
            :series="gpuChartSeries"
            unit="%"
          />
        </div>
        <div class="sub cpu-loadline">
          Load {{ fmtN(load1) }} / {{ fmtN(load5) }} / {{ fmtN(load15) }}
          ·
          {{ t('dashboard.load_capacity', { p: finiteN(loadPct) }) }}
          <span data-test="cpu-thermal">
            · {{ t('dashboard.thermal_status') }}
            <span :class="thermal.pressure === 'warning' ? 'temp-warn' : ''">{{ thermalStatus }}</span>
            <template v-if="cpuTempC != null"> · {{ fmtN(cpuTempC) }}°C</template>
          </span>
          <span class="badge" style="margin-left:4px">{{ t('dashboard.cores', { n: ncpu }) }}</span>
        </div>
      </div>

      <!-- ===== Memory ===== -->
      <div class="tile span-4 res-card" :class="{ 'am-surface': isMacSurface }">
        <h2>
          {{ t('dashboard.memory') }}
          <span class="tile-tools">
            <span class="badge" :class="memBadge">{{ t('dashboard.pressure_pct', { p: finiteN(memUsedPct) }) }}</span>
          </span>
        </h2>
        <!-- chart-first keeps non-mac stacked order (chart then stats); mac
             surface CSS still places stats left / chart right. -->
        <div class="am-monitor am-mem chart-first">
          <div class="am-monitor-stats">
            <div class="res-head">
              <div class="big">{{ memAvailGb }}<small> {{ t('dashboard.gb_available') }}</small></div>
              <div class="res-side">
                <div class="kv-mini">
                  <span>{{ t('dashboard.pressure') }}</span><b>{{ withUnit(memUsedPct, '%') }}</b>
                  <span>{{ t('dashboard.free_rate') }}</span><b>{{ withUnit(memFreePct, '%') }}</b>
                  <span>{{ t('dashboard.total') }}</span><b>{{ fmtGb(memTotal) }}</b>
                </div>
              </div>
            </div>
            <div class="pct-bar thick" :class="memBarClass">
              <i :style="{ width: barPct(memUsedPct) + '%' }"></i>
            </div>
            <div class="mem-break">
              <div class="mb">
                <span class="k">{{ t('dashboard.wired') }}</span>
                <span class="v">{{ fmtN(mem.wired_gb) }} GB</span>
              </div>
              <div class="mb">
                <span class="k">{{ t('dashboard.compressed') }}</span>
                <span class="v">{{ fmtN(mem.compressor_gb) }} GB</span>
              </div>
              <div class="mb">
                <span class="k">{{ t('dashboard.cache_approx') }}</span>
                <span class="v">{{ fmtN(mem.cache_gb) }} GB</span>
              </div>
            </div>
          </div>
          <div class="am-monitor-chart">
            <LineChart
              class="am-chart"
              :height="isMacSurface ? AM_CHART_HEIGHT : 72"
              :fill="isMacSurface"
              :min="0"
              :max="100"
              percent
              :times="metricTimes"
              :series="memChartSeries"
              unit="%"
            />
          </div>
        </div>
        <div class="sub mem-footnote" :title="memFootnote">{{ memFootnote }}</div>
      </div>

      <!-- ===== Disk + SMART ===== -->
      <div class="tile span-4 res-card" :class="{ 'am-surface': isMacSurface }">
        <h2>
          {{ t('dashboard.disk_smart') }}
          <span class="tile-tools">
            <span class="badge" :class="barClass(diskPct) || ''">{{ withUnit(diskPct, '%') }}</span>
            <span class="badge" :class="smartSummaryClass" :title="smartSummaryTitle" :aria-label="smartSummaryTitle">{{ smartSummary }}</span>
          </span>
        </h2>
        <div class="am-monitor am-disk">
          <div class="am-monitor-stats">
            <div class="res-head disk-head">
              <div class="big">{{ formatCapacityGb(diskUsed) }}<small> / {{ formatCapacityGb(diskTotal) }}</small></div>
              <div class="sub">{{ t('dashboard.disk_free_short', { free: formatCapacityGb(diskFree) }) }}</div>
            </div>
            <div class="pct-bar thick" :class="barClass(diskPct)">
              <i :style="{ width: barPct(diskPct) + '%' }"></i>
            </div>
            <div class="disk-list">
              <div v-for="d in smartDisks" :key="d.id" class="disk-item">
                <div class="disk-primary">
                  <strong :title="finiteText(d.smart?.model, '') || finiteText(d.name, '') || finiteText(d.id)">{{ finiteText(d.name, '') || finiteText(d.smart?.model, '') || finiteText(d.id) }}</strong>
                  <span class="disk-primary-meta">
                    <span v-if="formatDiskSize(d)" class="disk-capacity">{{ formatDiskSize(d) }}</span>
                    <span
                      class="badge"
                      :class="smartBadgeClass(d)"
                      :title="smartHealthTitle(d)"
                      :aria-label="smartHealthTitle(d)"
                    >{{ smartHealthLabel(d) }}</span>
                  </span>
                </div>
                <div v-if="d.smart" class="disk-facts">
                  <span class="disk-temp" :title="formatSmartTemp(d.smart.temp)">{{ formatSmartTemp(d.smart.temp) }}</span>
                  <span>{{ t('dashboard.wear') }} <b>{{ finiteText(d.smart.wear) }}</b></span>
                  <span>{{ t('dashboard.written') }} <b>{{ finiteText(d.smart.written) }}</b></span>
                  <span v-if="finiteN(d.smart.media_errors, null) != null">{{ t('dashboard.media_errors') }} <b>{{ finiteN(d.smart.media_errors) }}</b></span>
                </div>
                <div v-else class="disk-unavailable" :title="finiteText(d.error, '')">{{ t('dashboard.smart_unavailable_short') }}</div>
              </div>
              <div v-if="!storage" class="disk-empty">{{ loadError ? t('common.load_failed') : t('common.loading') }}</div>
              <div v-else-if="!smartDisks.length" class="disk-empty">{{ t('dashboard.no_smart_disks') }}</div>
            </div>
          </div>
          <div class="am-monitor-chart">
            <LineChart
              class="am-chart"
              :height="isMacSurface ? AM_CHART_HEIGHT : 52"
              :fill="isMacSurface"
              :min="0"
              :max="100"
              percent
              :times="metricTimes"
              :series="diskChartSeries"
              unit="%"
            />
          </div>
        </div>
      </div>

      <!-- ===== Network + processes ===== -->
      <div class="tile span-4">
        <h2>{{ t('dashboard.net_proc') }}</h2>
        <div class="net-stats">
          <div class="ns">
            <div class="k">↓ RX</div>
            <div class="v2">{{ formatBps(net.rx_bps) }}</div>
          </div>
          <div class="ns">
            <div class="k">↑ TX</div>
            <div class="v2">{{ formatBps(net.tx_bps) }}</div>
          </div>
          <div class="ns">
            <div class="k">{{ t('dashboard.process') }}</div>
            <div class="v2">{{ finiteN(cpu.proc_total) }} <small class="sub">run {{ finiteN(cpu.proc_running) }}</small></div>
          </div>
        </div>
        <h3 class="section-title top-cpu-head">
          <span>{{ t('dashboard.top_cpu') }}</span>
          <span class="ollama-api-wrap">
            <router-link
              class="ollama-api"
              to="/ollama"
              data-test="ollama-api"
              :title="ollamaApiTitle"
            >
              <Bot :size="12" />
              <span>{{ t('dashboard.ollama_api') }}</span>
              <span class="mono">{{ ollamaApiHost }}</span>
            </router-link>
            <button
              class="tiny"
              type="button"
              data-test="ollama-api-copy"
              :title="t('common.copy')"
              :aria-label="t('common.copy')"
              @click="copyOllamaApi"
            ><Copy :size="12" /></button>
          </span>
        </h3>
        <div class="table-wrap">
          <table class="dense top-cpu fit-m">
            <colgroup>
              <col class="col-proc">
              <col class="col-cpu">
              <col class="col-mem">
              <col class="col-rss col-hide-m">
            </colgroup>
            <thead>
              <tr>
                <th>{{ t('dashboard.col_process') }}</th>
                <th class="num">CPU%</th>
                <th class="num">MEM%</th>
                <th class="num col-hide-m">RSS</th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="p in topProcs"
                :key="p.pid"
                :class="{ dim: finiteN(p.cpu, 0) < 0.5 }"
              >
                <td class="proc" :title="'pid '+finiteN(p.pid)">
                  <strong>{{ finiteText(p.name) }}</strong>
                  <div class="show-m sub">{{ withUnit(p.rss_mb, 'M') }}</div>
                </td>
                <td class="num cpu-cell">
                  <span class="cpu-n">{{ finiteN(p.cpu) }}</span>
                  <span class="mini-bar"><i :style="{ width: barPct(p.cpu) + '%' }"></i></span>
                </td>
                <td class="num">{{ finiteN(p.mem) }}</td>
                <td class="num col-hide-m">{{ withUnit(p.rss_mb, 'M') }}</td>
              </tr>
              <tr v-if="!topProcs.length">
                <td colspan="4" class="empty-row">{{ sensors ? t('common.none') : (loadError ? t('common.load_failed') : t('common.loading')) }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- ===== Storage array ===== -->
      <div class="tile span-4">
        <h3>
          {{ t('dashboard.array') }}
          <router-link class="btn tiny" to="/main">{{ t('common.open') }}</router-link>
        </h3>
        <div class="table-wrap">
        <table class="dense fit-m">
          <thead>
            <tr>
              <th>{{ t('dashboard.col_mount') }}</th>
              <th class="col-hide-m">{{ t('dashboard.col_type') }}</th>
              <th class="col-hide-m">{{ t('dashboard.col_capacity') }}</th>
              <th class="col-hide-m">{{ t('dashboard.col_used') }}</th>
              <th class="col-hide-m">{{ t('dashboard.col_free') }}</th>
              <th>{{ t('main_extra.th_pct') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="v in (storage?.volumes || []).slice(0, 8)" :key="v.mount">
              <td class="mono">
                {{ shortMount(v) }}
                <div class="show-m sub">{{ finiteText(v.kind) }} · {{ fmtGb(v.used_gb) }} / {{ fmtGb(v.avail_gb) }}</div>
              </td>
              <td class="col-hide-m"><span class="badge accent">{{ finiteText(v.kind) }}</span></td>
              <td class="col-hide-m">{{ fmtGb(v.total_gb) }}</td>
              <td class="col-hide-m">{{ fmtGb(v.used_gb) }}</td>
              <td class="col-hide-m">{{ fmtGb(v.avail_gb) }}</td>
              <td style="min-width:100px">
                <!-- -text tints, not the raw hues: --down / --warn are fill
                     colours and measure 2.0-4.1:1 as ink on most cards
                     (contrast.test.js pins the binding shape too). -->
                <strong :style="{ color: v.pct >= 90 ? 'var(--down-text)' : (v.pct >= 75 ? 'var(--warn-text)' : 'inherit') }">{{ withUnit(v.pct, '%') }}</strong>
                <div class="pct-bar" :class="barClass(v.pct)" style="margin-top:3px">
                  <i :style="{ width: barPct(v.pct) + '%' }"></i>
                </div>
              </td>
            </tr>
            <!-- Column headings above nothing read as "still loading"; say
                 which of the two states this actually is. -->
            <tr v-if="!(storage?.volumes || []).length">
              <td colspan="6" class="empty-row">{{ storage ? t('main_extra.empty_volumes') : (loadError ? t('common.load_failed') : t('common.loading')) }}</td>
            </tr>
          </tbody>
        </table>
        </div>
      </div>

      <!-- ===== Docker ===== -->
      <div class="tile span-4">
        <h3>
          Docker
          <span class="badge">{{ containers ? containers.length : '—' }}</span>
          <span v-if="cstatsStale" class="badge warn" :title="t('dashboard.stats_stale_hint')">
            {{ t('dashboard.stats_stale') }}
          </span>
          <router-link class="btn tiny" to="/containers">{{ t('common.manage') }}</router-link>
        </h3>
        <div class="table-wrap">
        <table class="dense fit-m">
          <thead>
            <tr>
              <th><span class="sr-only">{{ t('common.status_led') }}</span></th>
              <th>{{ t('dashboard.col_name') }}</th>
              <th class="col-hide-m">{{ t('dashboard.col_status') }}</th>
              <th class="num">{{ t('dashboard.col_cpu') }}</th>
              <th class="num">{{ t('dashboard.col_mem') }}</th>
              <th><span class="sr-only">{{ t('common.actions') }}</span></th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="c in (containers || []).slice(0, 10)" :key="c.id">
              <!-- The visible Status column is col-hide-m, so on a phone this
                   LED is the row's only state and colour alone says nothing
                   to a screen reader: hide the paint, spell the state — same
                   treatment as the Containers page rows. -->
              <td>
                <span class="led" :class="led(c.state)" aria-hidden="true"></span>
                <span class="sr-only">{{ ledText(c.state) }}</span>
              </td>
              <td>
                <strong>{{ finiteText(c.name) }}</strong>
                <div class="mono" style="color:var(--sub);font-size:10px">{{ shortImage(c.image) }}</div>
                <div v-if="c.status" class="show-m sub">{{ finiteText(c.status) }}</div>
              </td>
              <td class="col-hide-m" style="font-size:11px">{{ finiteText(c.status) }}</td>
              <td class="mono num">
                {{ finiteText(cstats[c.id]?.cpu) }}
                <span v-if="cpuNum(cstats[c.id]?.cpu)!=null" class="mini-bar">
                  <i :style="{ width: Math.min(100, cpuNum(cstats[c.id]?.cpu)) + '%' }"></i>
                </span>
              </td>
              <td class="mono num">{{ finiteText(cstats[c.id]?.mem_pct, '') || finiteText(cstats[c.id]?.mem) }}</td>
              <td>
                <a v-if="c.url" class="btn tiny primary" :href="finiteText(c.url, '')" target="_blank">WebUI</a>
              </td>
            </tr>
            <tr v-if="containers && !containers.length">
              <td colspan="6" class="empty-row">{{ t('dashboard.no_containers') }}</td>
            </tr>
            <tr v-else-if="!containers">
              <td colspan="6" class="empty-row">{{ loadError ? t('common.load_failed') : t('common.loading') }}</td>
            </tr>
          </tbody>
        </table>
        </div>
      </div>

      <!-- ===== Attention ===== -->
      <div class="tile span-4">
        <h3>
          {{ t('dashboard.attention') }}
          <!-- role=status: both counts update silently on every status poll,
               and together they are the tile's whole summary (how many need
               attention, out of how many ok) — same rule as the member
               header count. One region so a poll that moves both reads as
               one announcement, not two. -->
          <span role="status">
            <span class="badge" :class="attention.length ? 'down' : 'ok'">{{ attention.length }}</span>
            <span class="sub" style="font-weight:500;text-transform:none;letter-spacing:0">
              {{ t('dashboard.services_count', { total: finiteN(status?.service_total, '—'), ok: finiteN(status?.counts?.ok, 0) }) }}
            </span>
          </span>
        </h3>
        <!-- Before status resolves, attention is [] because nothing was read,
             not because everything is healthy: the old status-gated ok branch
             fell through to an empty list that said nothing at all. -->
        <div v-if="!status" class="sub">{{ loadError ? t('common.load_failed') : t('common.loading') }}</div>
        <div v-else-if="!attention.length" class="sub ok-msg">{{ t('dashboard.all_ok') }}</div>
        <div v-else class="alert-list">
          <div v-for="s in attention.slice(0, 10)" :key="s.id" class="alert-item">
            <!-- warn vs down was carried by the LED colour alone. -->
            <span class="led" :class="led(s.state)" aria-hidden="true"></span>
            <span class="sr-only">{{ ledText(s.state) }}</span>
            <div style="flex:1;min-width:0">
              <div class="name">{{ finiteText(s.name) }}</div>
              <div class="detail" style="margin:0">{{ finiteText(s.group) }} · {{ finiteText(s.detail) }}</div>
            </div>
            <button
              v-for="a in (s.actions || []).filter(x => ['start','restart'].includes(x)).slice(0,1)"
              :key="a"
              class="tiny primary"
              :disabled="busy"
              @click="act(s, a)"
            >{{ finiteText(labels[a], '') || finiteText(a) }}</button>
          </div>
        </div>
        <h3 style="margin-top:12px">{{ t('dashboard.recent_alerts') }}</h3>
        <div v-if="!alerts" class="sub">{{ loadError ? t('common.load_failed') : t('common.loading') }}</div>
        <div v-else-if="!alerts.length" class="sub">{{ t('common.none') }}</div>
        <div v-for="(a,i) in (alerts || []).slice(0,5)" :key="i" class="alert-item">
          <!-- The alert's severity was its LED colour alone; the message text
               does not necessarily repeat it. -->
          <span class="led" :class="a.level === 'ok' ? 'on' : (a.level === 'warn' ? 'warn' : 'err')" aria-hidden="true"></span>
          <span class="sr-only">{{ a.level === 'ok' ? t('common.ok') : (a.level === 'warn' ? t('common.warn') : t('common.error')) }}</span>
          <div style="flex:1">
            <div class="name">{{ finiteText(a.name) }}</div>
            <div class="detail" style="margin:0">{{ fmt(a.t) }} · {{ finiteText(a.message) }}</div>
          </div>
        </div>
      </div>

      <!-- ===== Ports ===== -->
      <div class="tile span-4">
        <h3>
          {{ t('dashboard.ports') }}
          <router-link class="btn tiny" to="/network">{{ t('nav.network') }}</router-link>
        </h3>
        <div class="table-wrap">
        <table class="dense fit-m">
          <thead><tr><th>{{ t('dashboard.col_process') }}</th><th>{{ t('dashboard.col_port') }}</th><th class="col-hide-m">{{ t('dashboard.col_addr') }}</th></tr></thead>
          <tbody>
            <tr v-for="(p,i) in (ports || []).slice(0, 12)" :key="i">
              <td>
                {{ finiteText(p.process) }}
                <div v-if="finiteText(p.address, '')" class="show-m sub mono">{{ finiteText(p.address) }}</div>
              </td>
              <td class="mono">{{ finiteN(p.port) }}</td>
              <td class="mono col-hide-m" style="font-size:10px">{{ finiteText(p.address) }}</td>
            </tr>
            <tr v-if="!ports"><td colspan="3" class="empty-row">{{ loadError ? t('common.load_failed') : t('common.loading') }}</td></tr>
            <tr v-else-if="!ports.length"><td colspan="3" class="empty-row">{{ t('common.none') }}</td></tr>
          </tbody>
        </table>
        </div>
      </div>

      <!-- ===== Health + Bookmarks ===== -->
      <div class="tile span-4">
        <h3>
          {{ t('dashboard.health') }}
          <router-link class="btn tiny" to="/health">{{ t('dashboard.scan') }}</router-link>
          <router-link class="btn tiny" to="/bookmarks">{{ t('common.all') }}</router-link>
        </h3>
        <div class="health-grid" v-if="health?.summary">
          <div class="hg ok"><div class="n">{{ finiteN(health.summary.ok) }}</div><div class="l">{{ t('health.passed') }}</div></div>
          <div class="hg warn"><div class="n">{{ finiteN(health.summary.warn) }}</div><div class="l">{{ t('health.warnings') }}</div></div>
          <div class="hg err"><div class="n">{{ finiteN(health.summary.error) }}</div><div class="l">{{ t('health.errors') }}</div></div>
        </div>
        <div class="failed-checks" v-if="failedChecks.length">
          <div v-for="c in failedChecks.slice(0, 3)" :key="c.id" class="alert-item">
            <!-- error vs warn was the LED colour alone. -->
            <span class="led" :class="c.level === 'error' ? 'err' : 'warn'" aria-hidden="true"></span>
            <span class="sr-only">{{ c.level === 'error' ? t('common.error') : t('common.warn') }}</span>
            <div style="flex:1">
              <div class="name">{{ finiteText(c.name) }}</div>
              <div class="detail" style="margin:0">{{ finiteText(errText(c.detail)) }}</div>
            </div>
          </div>
        </div>
        <div class="sub" style="margin-top:8px" v-if="status?.adaptive">
          {{ t('dashboard.adaptive') }}：
          {{ t('dashboard.adaptive_line', {
            auto: finiteN(status.adaptive.auto_labeled, 0),
            orphan: finiteN(status.adaptive.orphan_count, 0),
            compose: (status.adaptive.compose_projects || []).length,
            nginx: (status.adaptive.nginx_sites || []).length,
          }) }}
        </div>
        <div class="bm-grid" v-if="bookmarks.length" style="margin-top:10px">
          <a
            v-for="b in bookmarks.slice(0, 9)"
            :key="b.url"
            class="bm-card"
            :class="bmClass(b)"
            :href="finiteText(b.url, '')"
            target="_blank"
            rel="noopener"
            :title="finiteText(b.url)"
          >
            <!-- Decoration: .bm-meta below already spells up/stopped/down
                 (bmLabel), so the LED only repeats it in colour — same
                 treatment as the Bookmarks page cards. -->
            <span class="led" :class="bmLed(b)" aria-hidden="true"></span>
            <span class="bm-name">{{ finiteText(b.name) }}</span>
            <span class="bm-meta">{{ bmLabel(b) }}</span>
          </a>
        </div>
      </div>
    </div>
    </template>
  </div>
</template>

<script setup>
import { computed, defineAsyncComponent, inject, onMounted, onUnmounted, ref, watch } from 'vue'
import {
  Battery, BatteryCharging, BatteryFull, BatteryLow, BatteryMedium,
  Bot, Monitor, Play, Square, Copy, Moon, RefreshCw, Power, Sparkles,
} from '@lucide/vue'
import { startVisibleInterval } from '../lib/poll'
import { authState } from '../lib/authState'
// Charts are first-screen but not first-paint: keep them out of the entry
// chunk so the 150 KiB budget stays on the shell + dashboard chrome.
const LineChart = defineAsyncComponent(() => import('../components/LineChart.vue'))
import {
  doAction, getAlerts, getBookmarks, getContainers, getHealthChecks, getHost,
  getListeningPorts, getMetricsRange, getPower, getSensors, getStatus,
  getOllamaStatus, getStorage, getUps, powerAction, setSystemSharing,
} from '../api/client'
import { openAssistant } from '../lib/assistant'
import { copyToClipboard } from '../lib/clipboard'
import { barPct, finiteN, finiteText, fmtGb, fmtTs, withUnit } from '../lib/finite'
import { injectI18n } from '../i18n'
import { injectTheme } from '../theme'

const toast = inject('toast')
const { t, errText } = injectI18n()
const { theme, resolveThemeId } = injectTheme()
const isMacSurface = computed(() => {
  const id = resolveThemeId(theme.value)
  return id === 'macos' || id === 'macos-dark'
})
const AM_CHART_HEIGHT = 88
const PROC_CHART_HEIGHT = 128

// Member sessions render the reduced services-only dashboard; the router
// guard refreshed authState before this component was allowed to mount.
const isMemberView = computed(() => authState.authenticated && authState.role === 'member')

const status = ref(null)
const highMode = computed(() => status.value?.resource_mode === 'high')
const storage = ref(null)
const host = ref(null)
const metrics = ref([])
const alerts = ref(null)
const containers = ref(null)
const cstats = ref({})
// When the CPU/MEM figures in cstats were last actually collected.  The 90s
// heavy tick deliberately skips `docker stats` (it costs ~2s), so those columns
// would otherwise freeze at whatever the first paint captured with no hint to
// the operator that they are no longer live.
const cstatsAt = ref(0)
//: True once the displayed CPU/MEM figures are older than two heavy ticks.
// Ticked by the 20s light interval.  Date.now() on its own is not a reactive
// dependency, so without this ref the staleness badge would be computed once
// and then never re-evaluated.
const clock = ref(Date.now())
const cstatsStale = computed(
  () => cstatsAt.value > 0 && clock.value - cstatsAt.value > 180000
)
const ports = ref(null)
// UPS / battery snapshot; the tile renders only when `present` is true, so a
// desktop with no UPS never shows an empty card.
const ups = ref(null)
const ollama = ref(null)
const sensors = ref(null)
const bookmarks = ref([])
const health = ref(null)
const busy = ref(false)
const loading = ref(false)
// Latched failure for the three loads the page cannot render without (status,
// sensors, host). Every loader here used to swallow its rejection, which had two
// consequences on the landing page: a backend that started failing left the
// previous numbers on screen indefinitely with nothing marking them stale, and a
// failed *first* load left the skeleton up forever because the skeleton is gated
// on host/sensors still being null. Secondary tiles (bookmarks, health, ports)
// keep their quiet .catch: one failing probe should not raise a page-level alarm.
const loadError = ref('')
const pwrBusy = ref(false)
const ssBusy = ref(false)
const powerData = ref({})
// False until getPower() has succeeded at least once, and again after a failure.
// Gates the Screen Sharing toggle so an unreadable state is never rendered as
// "off" with an Enable button next to it.
const powerLoaded = ref(false)
// Chart time ranges. Up to 48h the backend serves the raw 90s layer; 30d/1y
// come from the 5m/1h rollup tiers (data/metrics-5m.jsonl, metrics-1h.jsonl).
const METRIC_RANGES = ['1h', '6h', '24h', '48h', '30d', '1y']
const METRIC_RANGE_KEY = 'serverhub.metricsRange'
function savedMetricRange() {
  try {
    const v = localStorage.getItem(METRIC_RANGE_KEY)
    return METRIC_RANGES.includes(v) ? v : '1h'
  } catch { return '1h' }
}
const metricRange = ref(savedMetricRange())
// { since, until } of the last range response; null on the legacy shape.
const metricsMeta = ref(null)
// True only while an operator-initiated range switch is in flight; the 90s
// background refresh must not flash a loading line under stable charts.
const metricsSwitching = ref(false)
let timer = null
let heavyTimer = null
let actionRefreshTimer = null

function scheduleActionRefresh() {
  if (!dashAlive) return
  if (actionRefreshTimer) clearTimeout(actionRefreshTimer)
  actionRefreshTimer = setTimeout(() => {
    actionRefreshTimer = null
    if (!dashAlive) return
    void refresh()
  }, 1000)
}

const labels = computed(() => ({
  restart: t('dashboard.act_restart'),
  stop: t('dashboard.act_stop'),
  start: t('dashboard.act_start'),
  run: t('dashboard.act_run'),
}))

const sys = computed(() => status.value?.system || {})
const cpu = computed(() => sensors.value?.cpu || {})
const mem = computed(() => sensors.value?.memory || {})
const net = computed(() => sensors.value?.network || {})
const thermal = computed(() => cpu.value?.thermal || sensors.value?.thermal || {})
const smartDisks = computed(() => storage.value?.disks || [])
const topProcs = computed(() => sensors.value?.top_processes || [])
const engineUp = computed(() => !!status.value?.engine_up)
const ss = computed(() => powerData.value?.screen_sharing || {})
const ncpu = computed(() => finiteN(cpu.value.ncpu || sys.value.ncpu || host.value?.ncpu, 1))

const load1 = computed(() => cpu.value.load1 ?? sys.value.load1)
const load5 = computed(() => cpu.value.load5 ?? sys.value.load5)
const load15 = computed(() => cpu.value.load15 ?? sys.value.load15)
const loadPct = computed(() => finiteN(cpu.value.load_pct ?? sys.value.load_pct, 0))
const cpuUsed = computed(() => {
  const v = sensors.value?.cpu_used_pct ?? cpu.value.used_pct
  const n = v != null ? Number(v) : 0
  return Number.isFinite(n) ? n : 0
})
const cpuBadge = computed(() => {
  if (cpuUsed.value >= 90) return 'down'
  if (cpuUsed.value >= 70) return 'warn'
  return 'ok'
})
const thermalStatus = computed(() =>
  thermal.value.pressure === 'warning'
    ? t('dashboard.thermal_warning')
    : (thermal.value.pressure === 'normal' ? t('dashboard.thermal_normal') : t('dashboard.thermal_unknown'))
)
const cpuTempC = computed(() => finiteN(thermal.value.cpu_temp_c, null))
const gpu = computed(() => {
  const raw = sensors.value?.gpu
  return raw && typeof raw === 'object' ? raw : null
})
const gpuUtilPct = computed(() => finiteN(gpu.value?.util_pct, null))
const gpuBadge = computed(() => {
  const n = gpuUtilPct.value
  if (n == null) return ''
  if (n >= 90) return 'down'
  if (n >= 70) return 'warn'
  return 'ok'
})
function gpuBytesToGb(bytes) {
  const n = finiteN(bytes, null)
  if (n == null || n < 0) return null
  return Math.round((n / (1024 ** 3)) * 10) / 10
}
const gpuMemLabel = computed(() => {
  const used = gpuBytesToGb(gpu.value?.mem_used_bytes)
  const alloc = gpuBytesToGb(gpu.value?.mem_alloc_bytes)
  if (used == null && alloc == null) return ''
  return `${used == null ? '—' : fmtN(used)} / ${alloc == null ? '—' : fmtN(alloc)} GB`
})
const cpuBadgeText = computed(() => {
  const pct = `${cpuUsed.value}%`
  const gpuVisible = gpuUtilPct.value != null || !!gpuMemLabel.value
  return gpuVisible ? t('dashboard.cpu_pct', { p: cpuUsed.value }) : pct
})
function smartIsOk(d) {
  const h = String(d?.smart?.health || '').toUpperCase()
  return !!d?.smart && (h.includes('PASSED') || h === 'OK')
}
function smartBadgeClass(d) {
  if (!d?.smart) return ''
  return smartIsOk(d) ? 'ok' : 'down'
}
function smartHealthLabel(d) {
  if (!d?.smart) return t('dashboard.smart_na')
  return smartIsOk(d) ? t('dashboard.smart_passed') : t('dashboard.smart_warning')
}
function smartHealthTitle(d) {
  if (!d?.smart) return t('dashboard.smart_na_title')
  if (smartIsOk(d)) return t('dashboard.smart_passed_title')
  return finiteText(d.smart.health, '') || t('dashboard.smart_warning_title')
}
function formatSmartTemp(raw) {
  if (typeof raw === 'number') {
    if (!Number.isFinite(raw)) return '—'
    return `${formatSmartTempNumber(raw)}°C`
  }
  const text = finiteText(raw, '')
  if (!text) return finiteText(raw)
  const m = String(text).replace(/,/g, '').match(/-?\d+(?:\.\d+)?/)
  if (!m) return finiteText(raw)
  const n = Number(m[0])
  if (!Number.isFinite(n)) return finiteText(raw)
  return `${formatSmartTempNumber(n)}°C`
}
function formatSmartTempNumber(n) {
  const r = Math.round(n)
  return Math.abs(n - r) < 1e-6 ? String(r) : String(Math.round(n * 10) / 10)
}
function formatDiskSize(d) {
  const labeled = finiteText(d?.size, '')
  if (labeled) return labeled
  const gb = Number(d?.size_gb)
  if (!Number.isFinite(gb) || gb <= 0) return ''
  return gb >= 1024 ? `${(gb / 1024).toFixed(gb >= 10240 ? 0 : 1)} TB` : `${Math.round(gb)} GB`
}
function formatCapacityGb(value) {
  const gb = Number(value)
  if (!Number.isFinite(gb)) return '—'
  if (gb >= 1024) return `${(gb / 1024).toFixed(gb >= 10240 ? 0 : 2)} TB`
  return `${fmtN(gb)} GB`
}
const smartReadableCount = computed(() => smartDisks.value.filter(d => d.smart).length)
const smartHasWarning = computed(() => smartDisks.value.some(d => d.smart && !smartIsOk(d)))
const smartSummaryClass = computed(() => smartHasWarning.value ? 'down' : (smartReadableCount.value ? 'ok' : ''))
const smartSummary = computed(() => t('dashboard.smart_summary', {
  ok: smartReadableCount.value,
  total: smartDisks.value.length,
}))
const smartSummaryTitle = computed(() => t('dashboard.smart_summary_title', {
  ok: smartReadableCount.value,
  total: smartDisks.value.length,
}))
/** Activity Monitor red (system) + cyan (user). */
const CPU_APPLE_SYS = '#FF453A'
const CPU_APPLE_USER = '#5AC8FA'
const memTotal = computed(() => finiteN(mem.value.total_gb ?? sys.value.mem_total_gb ?? host.value?.mem_total_gb))
// pressure-based (macOS); NOT PhysMem cache-inflated used%
const memUsedPct = computed(() => {
  const raw = mem.value.pressure_used_pct ?? mem.value.used_pct
    ?? (sys.value.mem_free_pct != null ? 100 - sys.value.mem_free_pct : 0)
  const n = Number(raw)
  return Number.isFinite(n) ? n : 0
})
const memFreePct = computed(() =>
  finiteN(mem.value.pressure_free_pct ?? mem.value.free_pct ?? sys.value.mem_free_pct)
)
const memAvailGb = computed(() =>
  finiteN(mem.value.available_gb ?? mem.value.free_gb)
)
// Looser thresholds: pressure 12% is fine; red only when truly tight
const memBadge = computed(() => {
  const p = Number(memUsedPct.value) || 0
  if (p >= 85) return 'down'
  if (p >= 70) return 'warn'
  return 'ok'
})
const memBarClass = computed(() => {
  const p = Number(memUsedPct.value) || 0
  if (p >= 85) return 'danger'
  if (p >= 70) return 'warn'
  return ''
})
const memFootnote = computed(() => {
  const hint = t('dashboard.mem_hint')
  if (mem.value.phys_used_gb == null) return hint
  return `${hint} ${t('dashboard.mem_allocated', {
    used: fmtN(mem.value.phys_used_gb),
    total: memTotal.value,
  })}`
})

const diskArray = computed(() => storage.value?.array || {})
const diskUsed = computed(() => finiteN(diskArray.value.used_gb, null) ?? finiteN(sensors.value?.disk?.root_used_gb, null) ?? finiteN(sys.value.disk_used_gb))
const diskTotal = computed(() => finiteN(diskArray.value.total_gb, null) ?? finiteN(sensors.value?.disk?.root_total_gb, null) ?? finiteN(sys.value.disk_total_gb))
const diskFree = computed(() => finiteN(diskArray.value.free_gb, null) ?? finiteN(sensors.value?.disk?.root_free_gb, null) ?? finiteN(sys.value.disk_free_gb))
const diskPct = computed(() => {
  const total = Number(diskTotal.value)
  const used = Number(diskUsed.value)
  if (Number.isFinite(total) && total > 0 && Number.isFinite(used)) return Math.round(used / total * 100)
  return finiteN(sensors.value?.disk?.root_pct ?? sys.value.disk_pct, 0)
})

const uptimeText = computed(() =>
  finiteText(sensors.value?.uptime?.uptime_text, '') || finiteText(sys.value.uptime)
)

const upsPolicyPhase = computed(() => ups.value?.shutdown_state?.phase || 'idle')

const upsLow = computed(() => {
  const u = ups.value
  return u?.battery_percent != null
    && u.battery_percent <= (u.settings?.low_battery_pct ?? 20)
})
const upsChipClass = computed(() => {
  if (!ups.value?.present) return ''
  if (upsPolicyPhase.value === 'engaged' || upsLow.value) return 'danger'
  if (ups.value.on_battery || upsPolicyPhase.value === 'restoring') return 'warn'
  return ''
})
const upsIcon = computed(() => {
  const u = ups.value || {}
  if (u.charging) return BatteryCharging
  const p = Number(u.battery_percent)
  if (!Number.isFinite(p)) return Battery
  if (upsLow.value) return BatteryLow
  return p >= 85 ? BatteryFull : BatteryMedium
})
// Mid-outage the live phase matters more than the policy switch, so the chip
// promotes engaged/restoring (then plain on-battery) to visible text; on AC
// there is no state word at all.
const upsStateLabel = computed(() => {
  if (upsPolicyPhase.value === 'engaged') return t('dashboard.ups_policy_engaged')
  if (upsPolicyPhase.value === 'restoring') return t('dashboard.ups_policy_restoring')
  if (ups.value?.on_battery) return t('dashboard.ups_on_battery')
  return ''
})
// Everything the removed tile said, one hover away.
const ollamaChipVisible = computed(() => {
  const o = ollama.value
  return Boolean(o && (o.installed || o.reachable || o.service?.label))
})
const ollamaResidentName = computed(() => {
  const first = (ollama.value?.resident || [])[0]
  return finiteText(first?.name, '')
})
const ollamaChipClass = computed(() => {
  if (!ollama.value) return ''
  if (ollama.value.reachable) return 'ok'
  if (ollama.value.installed || ollama.value.service?.label) return 'warn'
  return ''
})
const ollamaChipLabel = computed(() => {
  if (ollamaResidentName.value) return ollamaResidentName.value
  if (ollama.value?.reachable) return t('dashboard.ollama_up')
  return t('dashboard.ollama_down')
})
const ollamaApiHost = computed(() => {
  const raw = finiteText(ollama.value?.url, '') || 'http://127.0.0.1:11434'
  try {
    return new URL(raw).host
  } catch {
    return '127.0.0.1:11434'
  }
})
const ollamaApiTitle = computed(() => finiteText(ollamaTooltip.value, '') || 'http://127.0.0.1:11434')
const ollamaTooltip = computed(() => {
  const o = ollama.value
  if (!o) return ''
  const lines = [t('dashboard.ollama_title')]
  const url = finiteText(o.url, '')
  if (url) lines.push(url)
  const ver = finiteText(o.version, '')
  if (ver) lines.push(`v${ver}`)
  if (ollamaResidentName.value) lines.push(t('dashboard.ollama_resident', { name: finiteText(ollamaResidentName.value) }))
  else if (o.reachable) lines.push(t('dashboard.ollama_none_resident'))
  else lines.push(t('dashboard.ollama_down'))
  return lines.join('\n')
})

const upsTooltip = computed(() => {
  const u = ups.value
  if (!u?.present) return ''
  const lines = [`${t('dashboard.ups_title')} · ${finiteText(u.name)}`]
  lines.push(
    (u.on_battery ? t('dashboard.ups_on_battery') : t('dashboard.ups_on_ac'))
    + (u.charging ? ` · ${t('dashboard.ups_charging')}` : ''),
  )
  if (finiteN(u.battery_percent, null) != null) lines.push(`${t('dashboard.ups_battery')} ${withUnit(u.battery_percent, '%')}`)
  if (finiteN(u.time_remaining_min, null) != null) lines.push(t('dashboard.ups_remaining', { m: finiteN(u.time_remaining_min) }))
  lines.push(t('dashboard.ups_threshold', { pct: finiteN(u.settings?.low_battery_pct, 20) }))
  const policy = upsPolicyPhase.value === 'engaged'
    ? t('dashboard.ups_policy_engaged')
    : upsPolicyPhase.value === 'restoring'
      ? t('dashboard.ups_policy_restoring')
      : t(u.settings?.shutdown?.enabled ? 'dashboard.ups_policy_on' : 'dashboard.ups_policy_off')
  lines.push(`${t('dashboard.ups_policy')}: ${policy}`)
  return lines.join('\n')
})

const healthOk = computed(() => {
  // Missing health is unknown, not OK: a failed or still-pending probe used
  // to paint the host-strip pill green.
  if (!health.value) return false
  return health.value.healthy !== false && !(health.value.summary?.error > 0)
})
const healthSummary = computed(() => {
  if (!health.value) return '…'
  if (health.value.healthy) return '✅ ' + t('common.healthy')
  const e = finiteN(health.value.summary?.error, 0)
  const w = finiteN(health.value.summary?.warn, 0)
  return e ? `❌ ${e}` : `⚠️ ${w}`
})
const failedChecks = computed(() => (health.value?.checks || []).filter(c => !c.ok))

const attention = computed(() => {
  if (!status.value) return []
  const list = []
  for (const g of status.value.groups || []) {
    for (const s of g.services || []) {
      // A deliberate stop is not actionable; only warn/down need attention
      if (s.state && s.state !== 'ok' && s.state !== 'stopped') list.push(s)
    }
  }
  return list
})

function bmHealth(b) {
  if (b?.health) return b.health
  return b?.ok ? 'ok' : 'error'
}
function bmClass(b) {
  const h = bmHealth(b)
  if (h === 'stopped') return 'stopped'
  if (h === 'error' || b?.ok === false) return 'down'
  return ''
}
function bmLed(b) {
  const h = bmHealth(b)
  if (h === 'ok') return 'on'
  if (h === 'stopped') return 'off'
  return 'err'
}
function bmLabel(b) {
  const h = bmHealth(b)
  if (h === 'ok') {
    const ms = Number(b.ms)
    return Number.isFinite(ms) ? ms + ' ms' : t('dashboard.bm_up')
  }
  if (h === 'stopped') return t('dashboard.bm_stopped')
  return t('dashboard.bm_down')
}

// Shared x-axis for the three resource charts. Index-based x used to
// squeeze omitted rollup windows together so a 30d hole looked like a
// 90s gap; LineChart plots these as (t - tMin) / (tMax - tMin).
const metricTimes = computed(() => (metrics.value || []).map(p => p.t ?? null))

// The `*_max` peak series only exist on aggregated points (5m/1h tiers and
// decimated raw): averaging a whole window would hide short spikes, so the
// stored per-window peak is drawn as a faint companion line. On raw
// pass-through points the fields are absent, the values are all null, and
// LineChart drops the series without rendering an empty legend entry.
const cpuChartSeries = computed(() => [
  {
    name: t('dashboard.chart_cpu'),
    values: (metrics.value || []).map(p => p.cpu_used_pct ?? null),
    color: 'var(--accent)',
  },
  {
    name: `${t('dashboard.chart_cpu')} ${t('dashboard.chart_peak')}`,
    values: (metrics.value || []).map(p => p.cpu_used_pct_max ?? null),
    color: 'color-mix(in srgb, var(--accent) 38%, transparent)',
  },
  {
    name: t('dashboard.chart_load_cap'),
    values: (metrics.value || []).map(p => {
      if (p.load_pct != null) return Math.min(100, p.load_pct)
      if (p.load1 != null) return Math.min(100, (p.load1 / (p.ncpu || ncpu.value || 1)) * 100)
      return null
    }),
    color: 'var(--warn)',
    width: 1.5,
  },
])

// History only stores total cpu_used_pct; split by the live user/sys mix so
// the Activity Monitor stack still reads as system (bottom) + user (top).
const cpuAppleChartSeries = computed(() => {
  const u = finiteN(cpu.value.user, 0)
  const s = finiteN(cpu.value.sys, 0)
  const busy = u + s
  const sysR = busy > 0 ? s / busy : 0.35
  const userR = busy > 0 ? u / busy : 0.65
  const pts = metrics.value || []
  return [
    {
      name: t('dashboard.cpu_system'),
      color: CPU_APPLE_SYS,
      values: pts.map(p => (p.cpu_used_pct != null ? p.cpu_used_pct * sysR : null)),
    },
    {
      name: t('dashboard.cpu_user'),
      color: CPU_APPLE_USER,
      values: pts.map(p => (p.cpu_used_pct != null ? p.cpu_used_pct * userR : null)),
    },
  ]
})

const memChartSeries = computed(() => [
  {
    name: t('dashboard.chart_mem_pressure'),
    values: (metrics.value || []).map(p => {
      if (p.mem_used_pct != null) return p.mem_used_pct
      if (p.mem_free_pct != null) return 100 - p.mem_free_pct
      return null
    }),
    color: 'var(--ok)',
  },
  {
    // No mem_free_pct fallback here: 100 - max(free) would be the window's
    // *minimum* pressure, not its peak.
    name: `${t('dashboard.chart_mem_pressure')} ${t('dashboard.chart_peak')}`,
    values: (metrics.value || []).map(p => p.mem_used_pct_max ?? null),
    color: 'color-mix(in srgb, var(--ok) 38%, transparent)',
  },
])

const diskChartSeries = computed(() => [
  {
    name: t('dashboard.chart_disk'),
    values: (metrics.value || []).map(p => p.disk_pct ?? null),
    color: 'var(--warn)',
  },
  {
    name: `${t('dashboard.chart_disk')} ${t('dashboard.chart_peak')}`,
    values: (metrics.value || []).map(p => p.disk_pct_max ?? null),
    color: 'color-mix(in srgb, var(--warn) 38%, transparent)',
  },
])

/** IOAccelerator util from metrics history; never invent a fake curve. */
const GPU_CHART = '#32D74B'
function seedLiveTail(values, live) {
  if (live == null || !values.length) return values
  if (values[values.length - 1] != null) return values
  const out = values.slice()
  out[out.length - 1] = live
  return out
}
const gpuChartTitle = computed(() => {
  const label = t('dashboard.gpu_util')
  if (gpuUtilPct.value == null) return label
  return `${label} ${fmtN(gpuUtilPct.value)}%`
})
const gpuChartSeries = computed(() => {
  const pts = metrics.value || []
  const live = gpuUtilPct.value
  return [
    {
      name: t('dashboard.gpu_util'),
      values: seedLiveTail(pts.map(p => p.gpu_util_pct ?? null), live),
      color: GPU_CHART,
    },
    {
      name: `${t('dashboard.gpu_util')} ${t('dashboard.chart_peak')}`,
      values: pts.map(p => p.gpu_util_pct_max ?? null),
      color: 'color-mix(in srgb, #32D74B 38%, transparent)',
    },
  ]
})

function setMetricRange(r) {
  if (!METRIC_RANGES.includes(r)) return
  metricRange.value = r
  try { localStorage.setItem(METRIC_RANGE_KEY, r) } catch {}
  metricsSwitching.value = true
  loadMetrics().finally(() => {
    // loadMetrics() bumps metricsGeneration, so a generation match would
    // leave the range chips stuck on "Loading" after an overlapping poll.
    if (dashAlive) metricsSwitching.value = false
  })
}

// "History accumulating" hint: the rollup tiers only contain data from the
// day they were enabled (and the panel only samples while awake), so a 30d/1y
// selection may cover a fraction of the window. Charts still draw what
// exists; this explains the short span. 10% slack keeps the hint quiet for
// ordinary holes (nightly sleep, brief restarts).
const historyHint = computed(() => {
  const meta = metricsMeta.value
  if (!meta || meta.since == null || meta.until == null) return ''
  const span = meta.until - meta.since
  if (span <= 0) return ''
  const pts = metrics.value || []
  if (!pts.length) return t('dashboard.chart_accumulating')
  const first = pts[0]?.t
  if (first == null || first - meta.since <= span * 0.1) return ''
  const d = new Date(first * 1000).toLocaleDateString()
  return `${t('dashboard.chart_accumulating')} · ${t('dashboard.chart_earliest', { d })}`
})
async function loadPower() {
  try {
    const next = await getPower()
    if (!dashAlive) return
    powerData.value = next
    powerLoaded.value = true
  } catch {
    if (!dashAlive) return
    // Do NOT clear powerData. ss.running is derived from it, so on failure the
    // old value is a better answer than {} -- with {} the pill rendered "Screen
    // Sharing off" and offered an Enable button whatever the real state was, so a
    // failed probe invited the operator to enable something already running.
    // powerLoaded going false is what the template uses to withhold the toggle
    // rather than guess at the state.
    powerLoaded.value = false
  }
}
async function doPower(action) {
  const names = { sleep: t('power.sleep'), restart: t('power.restart'), shutdown: t('power.shutdown') }
  if (!confirm(t('power.confirm1', { a: names[action] }))) return
  if (action !== 'sleep' && !confirm(t('power.confirm2', { a: names[action] }))) return
  pwrBusy.value = true
  try {
    const r = await powerAction(action, true)
    if (!dashAlive) return
    toast(r.ok ? `✅ ${finiteText(r.message)}` : `❌ ${finiteText(r.message)}`)
  } catch (e) {
    if (!dashAlive) return
    toast('❌ ' + finiteText(e.message))
  }
  if (dashAlive) pwrBusy.value = false
}
async function enableSS() {
  if (!confirm(t('power.confirm_enable_ss'))) return
  ssBusy.value = true
  try {
    const r = await setSystemSharing('screen_sharing', true)
    if (!dashAlive) return
    toast(r.ok ? `✅ ${finiteText(r.message)}` : `⚠️ ${finiteText(r.message)}`)
    await loadPower()
  } catch (e) {
    if (!dashAlive) return
    toast('❌ ' + finiteText(e.message))
  }
  if (dashAlive) ssBusy.value = false
}
async function disableSS() {
  if (!confirm(t('power.confirm_disable_ss'))) return
  ssBusy.value = true
  try {
    const r = await setSystemSharing('screen_sharing', false)
    if (!dashAlive) return
    toast(r.ok ? `✅ ${finiteText(r.message)}` : `⚠️ ${finiteText(r.message)}`)
    await loadPower()
  } catch (e) {
    if (!dashAlive) return
    toast('❌ ' + finiteText(e.message))
  }
  if (dashAlive) ssBusy.value = false
}
async function copyVnc() {
  const text = ss.value?.vnc_url
  if (!text) return
  // The write was never awaited, so a rejected copy still toasted success and
  // the URL the user needed was neither on the clipboard nor on screen.
  const ok = await copyToClipboard(text)
  if (!dashAlive) return
  toast(ok ? '✅ ' + t('power.copied') : '❌ ' + text)
}
async function copyOllamaApi() {
  const text = ollama.value?.url || 'http://127.0.0.1:11434'
  const ok = await copyToClipboard(text)
  if (!dashAlive) return
  toast(ok ? '✅ ' + t('common.copied') : '❌ ' + t('common.copy_failed'))
}
function barClass(pct) {
  if (pct >= 90) return 'danger'
  if (pct >= 75) return 'warn'
  return ''
}
function shortMount(v) {
  const mount = finiteText(v.mount, '')
  if (mount === '/') return t('dashboard.mount_system')
  if (mount === '/System/Volumes/Data') return 'Data'
  if (mount.startsWith('/Volumes/')) return mount.slice(9)
  if (v.kind === 'orbstack') return t('dashboard.mount_orbstack')
  return mount || '—'
}
function shortImage(img) {
  const s = String(finiteText(img, ''))
  if (!s) return ''
  const leaf = s.split('/').pop()
  return leaf.length > 36 ? leaf.slice(0, 34) + '…' : leaf
}
function led(state) {
  if (state === 'ok') return 'on'
  if (state === 'warn') return 'warn'
  if (state === 'stopped') return 'off'
  return 'err'
}
// Spelled-out twin of led() for the standalone LEDs (member cards, attention
// list): colour reaches a sighted reader and nobody else. Reuses the Services
// state words, so no new locale strings.
function ledText(state) {
  if (state === 'ok') return t('services.state_ok')
  if (state === 'warn') return t('services.state_warn')
  if (state === 'stopped') return t('services.state_stopped')
  return t('services.state_down')
}
function fmt(ts) {
  return fmtTs(ts, '')
}
function fmtN(v) {
  if (v == null || v === '') return '—'
  const n = typeof v === 'number' ? v : Number(v)
  if (!Number.isFinite(n)) return '—'
  return Math.abs(n) >= 10 ? Math.round(n * 10) / 10 : Number(n.toFixed(2))
}
function cpuNum(s) {
  if (!s) return null
  const n = parseFloat(String(s).replace('%', ''))
  return Number.isFinite(n) ? n : null
}
function formatBps(bps) {
  const n = Number(bps)
  if (!Number.isFinite(n) || n < 0) return '—'
  if (n < 1024) return `${n} B/s`
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB/s`
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MB/s`
  return `${(n / 1024 ** 3).toFixed(2)} GB/s`
}

// Both return `false` on failure so the 12s tick below can report it to
// lib/poll.js, whose backoff then slows a dead server's polling down.
let dashAlive = false
let heavyGeneration = 0
let sensorsGeneration = 0
async function refresh() {
  try {
    const next = await getStatus()
    if (!dashAlive) return
    status.value = next
    loadError.value = ''
  } catch (e) {
    if (!dashAlive) return false
    loadError.value = finiteText(e.message || String(e), '')
    return false
  }
}
async function loadSensors(force = false, { light = false } = {}) {
  const generation = ++sensorsGeneration
  try {
    // Prefer cache; force only on manual refresh.  The 20s tick uses
    // light=true so a sitting dashboard does not spawn ``top``.
    const next = await getSensors(force, { light })
    if (!dashAlive || generation !== sensorsGeneration) return
    if (light && sensors.value) {
      // Light payloads send empty top_processes / network. Replacing the
      // whole ref made the Top CPU table flip to "Loading" and RX/TX to
      // "—" until a full collect. Keep the last full extras across light
      // ticks (low-mode 20s + 90s); Refresh / high mode still replace.
      const prev = sensors.value
      const net = next.network && Object.keys(next.network).length ? next.network : prev.network
      sensors.value = {
        ...prev,
        ...next,
        top_processes: (next.top_processes && next.top_processes.length)
          ? next.top_processes
          : prev.top_processes,
        network: net,
        memory: { ...(prev.memory || {}), ...(next.memory || {}) },
      }
    } else {
      sensors.value = next
    }
    // Do not clear a banner another loader raised: a sensors tick used to
    // hide a failed host/status read and then Attention said "all healthy".
  } catch (e) {
    if (!dashAlive || generation !== sensorsGeneration) return false
    loadError.value = finiteText(e.message || String(e), '')
    return false
  }
}
let metricsGeneration = 0
async function loadMetrics() {
  const generation = ++metricsGeneration
  const wanted = metricRange.value
  try {
    const m = await getMetricsRange(wanted)
    if (generation !== metricsGeneration || !dashAlive) return
    metrics.value = m.points || []
    metricsMeta.value = m.since != null && m.until != null
      ? { since: m.since, until: m.until }
      : null
  } catch {}
}
async function refreshHeavy(forceSensors = false, withDockerStats = false) {
  // Secondary tiles keep their previous snapshot on failure (their catches stay
  // deliberately silent), so they cannot decide whether this tick "failed". The
  // host read is the canonical liveness probe — it already drives the failure
  // banner — so it alone reports the tick failed and lets the 90s heavy poll
  // back off through lib/poll.js while the server is unreachable.
  const generation = ++heavyGeneration
  const stillHere = () => dashAlive && generation === heavyGeneration
  let hostOk = true
  // Same contract as the skeleton (`!host && !sensors`): a 90s poll must
  // not disable Refresh or look like a first-paint reload.
  if (!host.value && !sensors.value) loading.value = true
  // None of these may sit in the skeleton Promise.all: on this host they
  // measured 1.1–3.4s and, when awaited next to docker stats, the cheap
  // list call queued behind it and put the 3s wait back on first paint.
  void getContainers(withDockerStats).then(c => {
    if (!stillHere()) return
    containers.value = c.containers || []
    if (c.stats && Object.keys(c.stats).length) {
      cstats.value = c.stats
      cstatsAt.value = Date.now()
    }
  }).catch(() => {})
  void getHealthChecks().then(h => { if (stillHere()) health.value = h }).catch(() => {})
  // Heavy tick always full-collects: low-mode light payloads omit network /
  // top_processes / proc counts, so first paint and idle 90s ticks showed "—".
  // The 20s admin tick stays light and merges last full extras.
  void loadSensors(forceSensors, { light: false })
  void getBookmarks().then(b => { if (stillHere()) bookmarks.value = b.bookmarks || [] }).catch(() => {})
  await Promise.all([
    loadMetrics(),
    getStorage(true).then(s => { if (stillHere()) storage.value = s }).catch(() => {}),
    // host drives the skeleton gate, so its failure has to be visible rather
    // than leaving the page on placeholders.
    getHost().then(h => { if (stillHere()) host.value = h }).catch(e => {
      if (!stillHere()) return
      loadError.value = finiteText(e.message || String(e), '')
      hostOk = false
    }),
    // Failures leave these null rather than fabricating []: an empty array is
    // the tile's "fetched, and none" claim, and a dead backend used to make
    // Ports say "None" and Recent alerts say "None" as if that were verified.
    // Null keeps the placeholder row, which reads load_failed once loadError
    // (the host probe, the canonical liveness signal) reports the tick failed.
    getAlerts(12).then(a => { if (stillHere()) alerts.value = a.alerts || [] }).catch(() => {}),
    getListeningPorts(40).then(p => { if (stillHere()) ports.value = p.ports || [] }).catch(() => {}),
    getUps().then(u => { if (stillHere()) ups.value = u }).catch(() => {}),
    getOllamaStatus().then(o => { if (stillHere()) ollama.value = o }).catch(() => {}),
    loadPower(),
  ])
  if (!stillHere()) return
  loading.value = false
  if (!hostOk) return false
}
function openAssistBrief() {
  openAssistant({ action: 'brief' })
}

async function refreshAll() {
  await Promise.all([refresh(), refreshHeavy(true, true)])
}
// The failure banner's retry has to match what this session may actually
// fetch: heavy loaders 401 for members and would re-raise the banner forever.
function retryLoad() {
  if (isMemberView.value) return refresh()
  return refreshAll()
}
async function act(svc, action) {
  if (busy.value) return
  if (action === 'restart' && !confirm(t('services.confirm_restart', { name: finiteText(svc.name) }))) return
  busy.value = true
  try {
    const r = await doAction(svc.id, action)
    if (!dashAlive) return
    toast(r.ok ? `✅ ${finiteText(svc.name)}` : `❌ ${finiteText(r.message, '').slice(0, 80)}`)
    if (r.ok) scheduleActionRefresh()
  } catch (e) {
    if (!dashAlive) return
    toast('❌ ' + finiteText(e.message))
  } finally {
    if (dashAlive) busy.value = false
  }
}

function stopDashTimers() {
  if (typeof timer === 'function') timer()
  if (typeof heavyTimer === 'function') heavyTimer()
  timer = null
  heavyTimer = null
}

async function tickMemberLight() {
  const ok = await refresh()
  if (!dashAlive) return ok
  clock.value = Date.now()
  return ok
}

async function tickAdminLight() {
  const results = await Promise.all([
    refresh(),
    loadSensors(false, { light: !highMode.value }),
  ])
  if (!dashAlive) return
  clock.value = Date.now()
  if (results.includes(false)) return false
}

function startDashTimers() {
  if (!dashAlive) return
  stopDashTimers()
  const lightMs = highMode.value ? 12000 : 20000
  if (isMemberView.value) {
    timer = startVisibleInterval(tickMemberLight, lightMs)
    return
  }
  // Low: light sensors (no top) on the 20s tick; full sensors on the 90s
  // heavy tick so RX/TX / Top CPU stay seeded. No docker stats on 90s.
  // High: full sensors every 12s and docker stats every 60s.
  timer = startVisibleInterval(tickAdminLight, lightMs)
  heavyTimer = startVisibleInterval(
    () => refreshHeavy(false, highMode.value),
    highMode.value ? 60000 : 90000,
  )
}

function onPtrRefresh() {
  if (isMemberView.value) void refresh()
  else void refreshAll()
}

onMounted(() => {
  dashAlive = true
  window.addEventListener('ptr-refresh', onPtrRefresh)
  void (async () => {
    await refresh()
    if (!dashAlive) return
    if (!isMemberView.value) {
      // Low: names/state only. High: docker stats fill CPU/MEM.
      void refreshHeavy(false, highMode.value)
    }
    if (!dashAlive) return
    startDashTimers()
  })()
})
watch(highMode, (_mode, _prev, onCleanup) => {
  if (!dashAlive) return
  startDashTimers()
  onCleanup(stopDashTimers)
})
onUnmounted(() => {
  dashAlive = false
  heavyGeneration += 1
  metricsGeneration += 1
  sensorsGeneration += 1
  window.removeEventListener('ptr-refresh', onPtrRefresh)
  stopDashTimers()
  if (actionRefreshTimer) clearTimeout(actionRefreshTimer)
  actionRefreshTimer = null
})
</script>

<style scoped>
.dash { }
.dash-grid { gap: 10px; }
:global([data-theme="macos"] .dash-grid),
:global([data-theme="macos-dark"] .dash-grid) { gap: 8px; }
:global([data-theme="macos"] .host-strip),
:global([data-theme="macos-dark"] .host-strip) {
  gap: 8px;
  margin-bottom: 8px;
  padding: 6px 8px;
}
:global([data-theme="macos"] .net-stats),
:global([data-theme="macos-dark"] .net-stats) { gap: 6px; }
:global([data-theme="macos"] .ns),
:global([data-theme="macos-dark"] .ns) {
  padding: 6px 8px;
  border: none;
  background: var(--bg);
  box-shadow: inset 0 0 0 1px color-mix(in srgb, var(--line) 40%, transparent);
}
:global([data-theme="macos"] .mb),
:global([data-theme="macos-dark"] .mb),
:global([data-theme="macos"] .disk-item),
:global([data-theme="macos-dark"] .disk-item) {
  border: none;
  box-shadow: none;
  background: transparent;
}
:global([data-theme="macos"] .disk-item),
:global([data-theme="macos-dark"] .disk-item) {
  border-radius: 0;
  padding: 2px 0;
}
:global([data-theme="macos"] table.top-cpu),
:global([data-theme="macos-dark"] table.top-cpu) {
  border: none;
}
:global([data-theme="macos"] table.top-cpu th),
:global([data-theme="macos"] table.top-cpu td),
:global([data-theme="macos-dark"] table.top-cpu th),
:global([data-theme="macos-dark"] table.top-cpu td) {
  border: none !important;
  border-bottom: none !important;
}
:global([data-theme="macos"] table.top-cpu tbody tr:nth-child(odd)),
:global([data-theme="macos-dark"] table.top-cpu tbody tr:nth-child(odd)){
  background: var(--card);
}
:global([data-theme="macos"] table.top-cpu tbody tr:nth-child(even)){
  background: #F5F5F7;
}
:global([data-theme="macos-dark"] table.top-cpu tbody tr:nth-child(even)){
  background: #232325;
}
:global([data-theme="macos"] table.top-cpu tbody tr.dim td),
:global([data-theme="macos-dark"] table.top-cpu tbody tr.dim td) {
  color: var(--sub);
  opacity: 1;
}
:global([data-theme="macos"] .top-cpu-head),
:global([data-theme="macos-dark"] .top-cpu-head) { margin-top: 6px; }
/* Shared monitor family: stats column left, chart column right on mac. */
.am-monitor {
  display: grid;
  grid-template-columns: 1fr;
  grid-template-areas:
    "stats"
    "chart";
  gap: 8px;
  align-items: stretch;
}
.am-monitor.chart-first {
  grid-template-areas:
    "chart"
    "stats";
}
.am-monitor-stats {
  grid-area: stats;
  display: flex;
  flex-direction: column;
  justify-content: flex-start;
  align-items: stretch;
  gap: 4px;
  min-width: 0;
  width: 100%;
}
.am-monitor-chart {
  grid-area: chart;
  min-width: 0;
  min-height: 0;
  display: flex;
  flex-direction: column;
  background: transparent;
  border: none;
  border-radius: 0;
  padding: 0;
  box-shadow: none;
}
.am-surface .am-monitor-chart > * {
  flex: 1 1 auto;
  min-height: 0;
  height: 100%;
}
/* Equal mac monitor cards: shared header + stats/chart grid stretch together. */
.am-surface.res-card {
  display: flex;
  flex-direction: column;
}
.am-surface .am-monitor,
.am-surface .cpu-charts {
  flex: 1 1 auto;
  min-height: 0;
}
.am-surface .am-monitor-chart { min-height: 88px; }
.am-surface .am-monitor,
.am-surface .am-monitor.chart-first,
.am-surface .am-monitor.am-disk {
  grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
  grid-template-areas: "stats chart";
  gap: 6px 10px;
  margin: 0;
}
.am-cpu :deep(.lc-legend) { display: none; }
.am-mem :deep(.lc-legend) { display: none; }
.am-disk .am-monitor-chart { position: relative; }
.am-disk :deep(.lc-legend) {
  position: absolute;
  top: 6px;
  right: 8px;
  margin-top: 0;
  z-index: 2;
  flex-direction: column;
  align-items: flex-end;
  gap: 4px;
  max-width: calc(100% - 16px);
}
.am-disk :deep(.leg-unit) { display: none; }
:global([data-theme="macos"] .am-monitor-chart .lc-plot),
:global([data-theme="macos-dark"] .am-monitor-chart .lc-plot),
:global([data-theme="macos"] .cpu-charts .lc-plot),
:global([data-theme="macos-dark"] .cpu-charts .lc-plot) {
  background: transparent;
  border: none;
  padding: 0;
}
.am-chart { margin-top: 6px; }
.am-monitor-chart .am-chart,
.cpu-charts .am-chart { margin-top: 0; min-width: 0; width: 100%; }
.am-surface .am-monitor-chart :deep(.lc-title),
.am-surface .cpu-charts :deep(.lc-title) {
  margin-bottom: 2px;
  padding-bottom: 0;
}
.am-surface .am-monitor-chart :deep(.lc-plot) { min-height: 0; }
.am-surface .cpu-charts :deep(.lc-plot) { min-height: 128px; }
.am-surface .res-head {
  flex-direction: column;
  align-items: flex-start;
  gap: 4px;
  margin-bottom: 4px;
}
.am-surface .big { font-size: 24px; }
.am-surface .res-side { width: 100%; }
.am-surface .kv-mini {
  width: 100%;
  grid-template-columns: 1fr auto;
  gap: 6px 10px;
}
.am-surface .kv-mini span {
  color: var(--txt);
  font-size: 11px;
  font-weight: 500;
  white-space: nowrap;
}
.am-surface .kv-mini b {
  font: 600 11px ui-monospace, SFMono-Regular, Menlo, monospace;
  font-variant-numeric: tabular-nums;
  white-space: nowrap;
}
.am-surface .mem-break {
  grid-template-columns: 1fr;
  gap: 2px;
}
.am-surface .mb {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
  gap: 8px;
  padding: 3px 0;
  border: none;
  background: transparent;
  border-radius: 0;
}
.am-surface .mb .k {
  font-size: 11px;
  text-transform: none;
  letter-spacing: 0;
  color: var(--txt);
  font-weight: 500;
  white-space: nowrap;
}
.am-surface .mb .v {
  margin-top: 0;
  font-size: 11px;
  font-weight: 600;
  white-space: nowrap;
}
.am-monitor-stats > .res-head { margin-bottom: 0; }
.am-monitor-stats > .pct-bar { margin-top: 0; }
.am-monitor-stats > .disk-list,
.am-monitor-stats > .mem-break { margin-top: 0; }
.am-surface .disk-list { gap: 1px; min-width: 0; }
.am-surface .disk-item {
  padding: 2px 0;
  border: none;
  border-radius: 0;
  background: transparent;
}
.am-surface .disk-primary,
.am-surface .disk-primary-meta { white-space: nowrap; }
.am-surface .disk-primary strong { font-size: 12px; font-weight: 500; }
.res-card > h2 { margin-bottom: 8px; }
.cpu-loadline { margin-top: 8px; }
.tile .mem-footnote {
  margin-top: 6px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  overflow-wrap: normal;
  word-break: keep-all;
}
@media (max-width: 640px) {
  .am-monitor,
  .am-monitor.chart-first,
  .am-surface .am-monitor,
  .am-surface .am-monitor.chart-first,
  .am-surface .am-monitor.am-disk {
    grid-template-columns: 1fr;
    grid-template-areas:
      "stats"
      "chart";
  }
  .cpu-charts { grid-template-columns: 1fr; }
}
.member-group { font-size: 14px; margin: 14px 0 8px; color: var(--sub); }
.member-svc .name { font-weight: 600; }
.member-svc .row { display: flex; align-items: center; gap: 8px; }
.dash-grid > .tile { min-width: 0; overflow: hidden; }
.alert-item > * { min-width: 0; overflow-wrap: anywhere; }
.host-strip {
  display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between;
  gap: 10px; margin-bottom: 12px;
  padding: 12px 16px;
  background: var(--card);
  border: 1px solid var(--line);
  border-left: 3px solid var(--accent);
  border-radius: var(--radius);
  box-shadow: var(--card-shadow);
}
.host-name {
  font-size: 18px; font-weight: 800; letter-spacing: -.2px;
  display: flex; flex-wrap: wrap; align-items: center; gap: 8px;
}
.host-ups {
  display: inline-flex; align-items: center; gap: 4px;
  padding: 2px 8px;
  background: var(--btn); border: 1px solid var(--line); border-radius: var(--radius-pill);
  font-size: 11px; font-weight: 600; letter-spacing: 0; line-height: 1.4;
  color: var(--txt);
  cursor: default;
}
.host-ups .ups-pct { font-family: ui-monospace, Menlo, monospace; font-weight: 700; }
.host-ups.warn { background: color-mix(in srgb, var(--warn) 14%, transparent); color: var(--warn-text); border-color: transparent; }
.host-ups.ok { background: color-mix(in srgb, var(--ok) 14%, transparent); color: var(--ok-text); border-color: transparent; }
.host-ups.danger { background: color-mix(in srgb, var(--down) 12%, transparent); color: var(--down-text); border-color: transparent; }
a.host-ollama { text-decoration: none; }
button.host-assist { cursor: pointer; font: inherit; color: inherit; }
.host-meta { color: var(--sub); font-size: 12px; margin-top: 4px; display: flex; flex-wrap: wrap; gap: 5px; }
.host-meta .dot { opacity: .35; }
.host-pills { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; }
.host-pills .pill {
  background: var(--btn); border: 1px solid var(--line);
  color: var(--txt); padding: 4px 10px; border-radius: var(--radius-pill); font-size: 11px; font-weight: 600;
}
/* The status text tokens (--ok-text/--down-text) exist because flat
   var(--ok)/var(--down) on their own 12-14% tint read 2.2:1 and 3.0:1 at 11px. */
.host-pills .pill.ok { background: color-mix(in srgb, var(--ok) 14%, transparent); color: var(--ok-text); border-color: transparent; }
.host-pills .pill.down { background: color-mix(in srgb, var(--down) 12%, transparent); color: var(--down-text); border-color: transparent; }

.res-card .big {
  font-size: 28px; font-weight: 800; line-height: 1.1;
  letter-spacing: -0.5px;
}
.res-card .big small {
  font-size: 13px; font-weight: 600; color: var(--sub); margin-left: 2px;
}
.res-head {
  display: flex; justify-content: space-between; align-items: flex-start;
  gap: 8px; margin-bottom: 8px;
}
.cpu-charts {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
  gap: 8px 12px;
  min-width: 0;
}
.cpu-charts > * { min-width: 0; }
.cpu-charts :deep(.lc-plot) { min-height: 128px; }
.cpu-charts :deep(.lc-title) {
  margin-bottom: 2px;
  padding-bottom: 0;
}

.pct-bar.thick { height: 9px; margin-top: 4px; }
.load-rows { margin-top: 8px; display: flex; flex-direction: column; gap: 4px; }
.load-row { display: grid; grid-template-columns: 28px 1fr 42px; gap: 8px; align-items: center; font-size: 11px; }
.lr-l { color: var(--sub); font-weight: 700; }
.lr-bar { height: 7px; background: var(--bar-track); border-radius: 3px; overflow: hidden; }
.lr-bar i { display: block; height: 100%; border-radius: 3px; transition: width .4s ease; }
.lr-v { text-align: right; }

.mem-break {
  display: grid; grid-template-columns: repeat(3, 1fr); gap: 6px;
  margin-top: 8px;
}
.mb {
  background: var(--bg); border-radius: var(--radius-sm); padding: 5px 8px;
  border: 1px solid var(--line);
}
.mb .k { font-size: 9px; color: var(--sub); text-transform: uppercase; letter-spacing: .3px; }
.mb .v { font-size: 13px; font-weight: 700; margin-top: 2px; font-family: ui-monospace, Menlo, monospace; }

.temp-warn { color: var(--warn-text) !important; }
.disk-head { align-items: end; }
.disk-head .sub { margin: 0; white-space: nowrap; }
.disk-list { display: flex; flex-direction: column; gap: 2px; margin-top: 6px; }
.disk-item { min-width: 0; padding: 3px 6px; border: 1px solid var(--line); border-radius: var(--radius-sm); background: var(--bg); }
.disk-primary { display: flex; align-items: center; justify-content: space-between; gap: 4px; min-width: 0; }
.disk-primary strong { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 11px; }
.disk-primary-meta { flex: 0 0 auto; display: inline-flex; align-items: center; gap: 3px; }
.disk-primary-meta .badge { padding: 1px 5px; min-width: 1.15em; text-align: center; letter-spacing: 0; }
.disk-capacity { color: var(--txt); font: 700 10px ui-monospace, Menlo, monospace; white-space: nowrap; }
.disk-facts { display: flex; flex-wrap: wrap; gap: 0 6px; margin-top: 1px; color: var(--sub); font-size: 10px; line-height: 1.3; }
.disk-facts b { color: var(--txt); font-family: ui-monospace, Menlo, monospace; }
.disk-temp { color: var(--txt); font-weight: 700; font-family: ui-monospace, Menlo, monospace; }
.disk-unavailable, .disk-empty { margin-top: 2px; color: var(--sub); font-size: 10px; line-height: 1.25; }

/* Now an h3 inside an h2-headed tile, so `.tile h3` claims margin-bottom where
   `.section-title` used to.  Pinned here so the level change is invisible. */
.top-cpu-head { justify-content: space-between; margin: 10px 0 8px; }
.ollama-api-wrap { display: inline-flex; align-items: center; gap: 4px; min-width: 0; }
.ollama-api {
  display: inline-flex; align-items: center; gap: 5px;
  text-decoration: none; color: var(--sub);
  font-size: 10px; font-weight: 700; letter-spacing: .3px;
  text-transform: uppercase; min-width: 0;
}
.ollama-api .mono {
  text-transform: none; letter-spacing: 0; color: var(--txt);
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.ollama-api:hover { color: var(--accent-text); }
table.top-cpu { table-layout: fixed; }
table.top-cpu .col-cpu { width: 112px; }
table.top-cpu .col-mem { width: 52px; }
table.top-cpu .col-rss { width: 58px; }
table.top-cpu th.num,
table.top-cpu td.num {
  text-align: right;
  font-variant-numeric: tabular-nums;
  white-space: nowrap;
  font-family: ui-monospace, Menlo, monospace;
}
table.top-cpu td.proc {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
table.top-cpu .cpu-n {
  display: inline-block;
  min-width: 4.2ch;
  text-align: right;
}
table.top-cpu .mini-bar { margin-left: 6px; }

.net-stats {
  display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px;
}
.ns {
  background: var(--bg); border: 1px solid var(--line); border-radius: var(--radius-sm); padding: 10px;
}
.ns .k { font-size: 9px; color: var(--sub); text-transform: uppercase; letter-spacing: .3px; }
.ns .v2 { font-size: 15px; font-weight: 800; margin-top: 3px; font-family: ui-monospace, Menlo, monospace; }

.chart-intro {
  display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 8px;
  font-size: 12px; color: var(--sub);
}
.chart-intro b { color: var(--txt); font-family: ui-monospace, Menlo, monospace; }
.tile-tools { display: inline-flex; align-items: center; gap: 6px; margin-left: auto; flex-wrap: wrap; justify-content: flex-end; }
.monitor-toolbar {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px 12px;
  min-width: 0;
}
.monitor-toolbar-hint {
  margin: 0;
  flex: 1 1 160px;
  min-width: 0;
}
.range-btns { display: inline-flex; gap: 3px; }
.pwr-group { display: inline-flex; align-items: center; gap: 3px; margin-left: 4px; }
.pwr-group .tiny { font-size: 12px; padding: 2px 6px; text-decoration: none; display: inline-flex; align-items: center; justify-content: center; }
.pwr-group a.tiny.disabled { opacity: .4; pointer-events: none; cursor: not-allowed; }
.hint-line { margin-top: 8px; font-size: 11px; color: var(--sub); line-height: 1.5; }
/* Flat var(--ok) is a 2.2:1 mint green on the card — the least legible text on
   the dashboard. --ok-text carries the AA-clearing shade for every palette. */
.ok-msg { color: var(--ok-text); font-weight: 600; padding: 8px 0; }

.health-grid {
  display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px;
}
.hg {
  text-align: center; padding: 12px 6px; border-radius: var(--radius-sm);
  border: 1px solid var(--line); background: var(--bg);
}
.hg .n { font-size: 24px; font-weight: 800; }
.hg .l { font-size: 9px; color: var(--sub); text-transform: uppercase; margin-top: 3px; letter-spacing: .3px; }
.hg.ok .n { color: var(--ok-text); }
.hg.warn .n { color: var(--warn-text); }
.hg.err .n { color: var(--down-text); }
.failed-checks { margin-top: 10px; display: flex; flex-direction: column; gap: 4px; }

/* Bookmark health — equal cards, aligned grid */
.bm-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(145px, 1fr));
  gap: 8px;
}
.bm-card {
  display: grid;
  grid-template-columns: 14px 1fr;
  grid-template-rows: auto auto;
  column-gap: 8px;
  row-gap: 4px;
  align-items: center;
  min-height: 56px;
  padding: 10px 12px;
  background: var(--bg);
  border: 1px solid var(--line);
  border-radius: var(--radius);
  color: var(--txt);
  text-decoration: none;
  transition: border-color .15s, background .15s, transform .1s;
}
.bm-card:hover { border-color: var(--accent); background: var(--table-hover); transform: translateY(-1px); }
.bm-card.down { border-color: color-mix(in srgb, var(--down) 45%, var(--line)); }
.bm-card.stopped { border-color: color-mix(in srgb, #888 35%, var(--line)); opacity: 0.85; }
.bm-card .led { grid-row: 1 / span 2; align-self: center; }
.bm-name {
  grid-column: 2;
  font-size: 12px;
  font-weight: 700;
  line-height: 1.25;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  min-width: 0;
  color: var(--accent-text);
}
.bm-card.down .bm-name { color: var(--down-text); }
.bm-card.stopped .bm-name { color: var(--sub); }
.bm-meta {
  grid-column: 2;
  font-size: 11px;
  color: var(--sub);
  font-variant-numeric: tabular-nums;
  font-family: ui-monospace, Menlo, monospace;
  line-height: 1.2;
}

/* === Mobile responsive === */
@media (max-width: 640px) {
  .host-strip { flex-direction: column; align-items: flex-start; padding: 10px 12px; gap: 8px; }
  .host-name { font-size: 15px; }
  .host-meta { font-size: 11px; }
  .host-pills { width: 100%; gap: 6px; }
  .host-pills .pill { padding: 3px 8px; font-size: 10px; }
  .pwr-group { margin-left: 0; }
  .pwr-group .tiny { min-width: 40px; min-height: 36px; padding: 6px 8px; }
  .tile-tools { margin-left: 0; width: 100%; justify-content: flex-start; }
  .res-head { flex-direction: column; align-items: flex-start; gap: 6px; }
  .disk-head .sub { white-space: normal; }
  .top-cpu-head { flex-wrap: wrap; gap: 6px; }
  .range-btns { flex-wrap: wrap; }
  .mem-break { grid-template-columns: repeat(2, 1fr); }
  .net-stats { grid-template-columns: 1fr 1fr; }
  .health-grid { grid-template-columns: repeat(2, 1fr); }
  .bm-grid { grid-template-columns: repeat(auto-fill, minmax(120px, 1fr)); gap: 6px; }
  .bm-card { padding: 8px 10px; min-height: 48px; }
  .res-card .big { font-size: 22px; }
  .disk-primary { flex-wrap: wrap; }
  .disk-facts { font-size: 9px; }
  .load-row { grid-template-columns: 24px 1fr 36px; font-size: 10px; }
  .chart-intro { font-size: 11px; gap: 8px; }
  .range-btns { margin-top: 0; }
}
@media (max-width: 380px) {
  .net-stats { grid-template-columns: 1fr; }
  .health-grid { grid-template-columns: 1fr 1fr; }
  .mem-break { grid-template-columns: 1fr; }
}
</style>
