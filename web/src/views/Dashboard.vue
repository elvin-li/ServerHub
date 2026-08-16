<template>
  <div class="dash">
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
      <div class="sub mono" style="margin-top:4px">{{ loadError }}</div>
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
            <span>{{ t('dashboard.services_count', { total: status?.service_total ?? '—', ok: status?.counts?.ok ?? 0 }) }}</span>
            <span class="dot">·</span>
            <span>{{ status?.ts || '…' }}</span>
          </div>
        </div>
        <div class="host-pills">
          <button class="tiny" @click="refresh" :disabled="loading">{{ t('common.refresh') }}</button>
        </div>
      </div>
      <template v-for="g in status?.groups || []" :key="g.group">
        <h2 class="member-group">{{ g.group }}</h2>
        <div class="dash-grid">
          <div v-for="s in g.services || []" :key="s.id" class="tile span-4 member-svc">
            <div class="row">
              <span class="led" :class="led(s.state)"></span>
              <span class="name">{{ s.name }}</span>
            </div>
            <div class="sub" style="margin-top:4px">{{ s.detail || s.state }}</div>
            <div class="row" style="margin-top:8px;gap:6px">
              <a v-if="s.url" class="btn tiny primary" :href="s.url" target="_blank" rel="noopener">{{ t('services.open') }}</a>
              <router-link class="btn tiny" to="/services">{{ t('services.more') }}</router-link>
            </div>
          </div>
        </div>
      </template>
      <div v-if="!(status?.groups || []).length && !loadError" class="tile" style="color:var(--sub)">
        {{ t('dashboard.member_empty') }}
      </div>
    </template>

    <!-- Skeleton loading state. Gated on loadError too: without that, a failed
         first load left this placeholder on screen permanently. -->
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
    <!-- Host strip — Unraid / Glances header -->
    <div class="host-strip">
      <div class="host-main">
        <div class="host-name">
          <span>{{ host?.hostname || '—' }}</span>
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
            <span v-if="ups.battery_percent != null" class="ups-pct">{{ ups.battery_percent }}%</span>
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
          <span>{{ host?.cpu || 'CPU' }}</span>
          <span class="dot">·</span>
          <span>{{ t('dashboard.cores', { n: ncpu }) }}</span>
          <span class="dot">·</span>
          <span>{{ memTotal }} GB RAM</span>
          <span class="dot">·</span>
          <span>{{ host?.lan_ip || host?.host_ip || '—' }}</span>
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
        <span class="pill">{{ sensors?.ts || status?.ts || '…' }}</span>
       <button class="tiny" @click="refreshAll" :disabled="loading">{{ t('common.refresh') }}</button>
      <span id="remote" class="pwr-group">
         <a class="tiny primary"
           :class="{ disabled: !ss.running }"
           :href="ss.running ? ss.vnc_url : undefined"
           :title="ss.running ? t('power.connect') : t('power.off')"
         ><Monitor :size="14" /></a>
         <!-- Both toggles require a successful power read. Without that gate a
              failed probe left powerData empty, so !ss.running was true and the
              Enable button appeared even when Screen Sharing was already on. -->
         <button v-if="powerLoaded && !ss.running" class="tiny primary" :disabled="ssBusy || loading" @click="enableSS" :title="t('power.enable_ss')"><Play :size="13" /></button>
         <button v-else-if="powerLoaded" class="tiny danger" :disabled="ssBusy" @click="disableSS" :title="t('power.disable_ss')"><Square :size="13" /></button>
         <button v-else class="tiny" disabled :title="t('power.state_unknown')"><Play :size="13" /></button>
         <button class="tiny hide-m" :disabled="!ss.vnc_url" @click="copyVnc" :title="t('power.copy')"><Copy :size="13" /></button>
      </span>
      <span class="pwr-group">
          <button class="tiny" @click="doPower('sleep')" :disabled="pwrBusy" title="Sleep"><Moon :size="13" /></button>
          <button class="tiny" @click="doPower('restart')" :disabled="pwrBusy" title="Restart"><RefreshCw :size="13" /></button>
          <button class="tiny danger" @click="doPower('shutdown')" :disabled="pwrBusy" title="Shutdown"><Power :size="13" /></button>
      </span>
      </div>
    </div>

    <div class="dash-grid">
      <!-- ===== CPU + Load ===== -->
      <div class="tile span-4 res-card">
        <h3>
          {{ t('dashboard.cpu') }}
          <span class="tile-tools">
            <span class="badge" :class="cpuBadge">{{ cpuUsed }}%</span>
            <span class="range-btns">
              <button
                v-for="r in METRIC_RANGES"
                :key="r"
                class="tiny"
                :class="metricRange===r?'primary':''"
                @click="setMetricRange(r)"
              >{{ r }}</button>
            </span>
          </span>
        </h3>
        <!-- Aggregate tiers only start filling from the day this feature is
             enabled; charts render whatever exists and this line says why the
             window looks short instead of leaving it blank. -->
        <div v-if="metricsSwitching || historyHint" class="sub" style="margin:-2px 0 4px">
          {{ metricsSwitching ? t('common.loading') : historyHint }}
        </div>
        <div class="res-head cpu-head">
          <div class="big">{{ cpuUsed }}<small>%</small></div>
        </div>
        <div class="cpu-facts">
          <div><span>user</span><b>{{ fmtN(cpu.user) }}%</b></div>
          <div><span>sys</span><b>{{ fmtN(cpu.sys) }}%</b></div>
          <div><span>idle</span><b>{{ fmtN(cpu.idle) }}%</b></div>
          <div><span>{{ t('dashboard.thermal_status') }}</span><b :class="thermal.pressure === 'warning' ? 'temp-warn' : ''">{{ thermalStatus }}</b></div>
        </div>
        <StackBar
          :segments="cpuStack"
          :total="100"
          unit="%"
        />
        <LineChart
          style="margin-top:8px"
          :height="80"
          :min="0"
          :max="100"
          percent
          :series="cpuChartSeries"
          unit="%"
        />
        <div class="sub" style="margin-top:6px">
          Load {{ fmtN(load1) }} / {{ fmtN(load5) }} / {{ fmtN(load15) }}
          · {{ t('dashboard.load_capacity', { p: loadPct }) }}
          <span class="badge" style="margin-left:4px">{{ t('dashboard.cores', { n: ncpu }) }}</span>
        </div>
      </div>

      <!-- ===== Memory ===== -->
      <div class="tile span-4 res-card">
        <h3>
          {{ t('dashboard.memory') }}
          <span class="badge" :class="memBadge">{{ t('dashboard.pressure_pct', { p: memUsedPct }) }}</span>
        </h3>
        <div class="res-head">
          <div class="big">{{ memAvailGb }}<small> {{ t('dashboard.gb_available') }}</small></div>
          <div class="res-side">
            <div class="kv-mini">
              <span>{{ t('dashboard.pressure') }}</span><b>{{ memUsedPct }}%</b>
              <span>{{ t('dashboard.free_rate') }}</span><b>{{ memFreePct }}%</b>
              <span>{{ t('dashboard.total') }}</span><b>{{ memTotal }} GB</b>
            </div>
          </div>
        </div>
        <div class="pct-bar thick" :class="memBarClass">
          <i :style="{ width: memUsedPct + '%' }"></i>
        </div>
        <div class="sub" style="margin-top:6px">
          {{ t('dashboard.mem_hint') }}
          <template v-if="mem.phys_used_gb != null">
            {{ t('dashboard.mem_allocated', { used: fmtN(mem.phys_used_gb), total: memTotal }) }}
          </template>
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
        <LineChart
          style="margin-top:6px"
          :height="72"
          :min="0"
          :max="100"
          percent
          :series="memChartSeries"
          unit="%"
        />
      </div>

      <!-- ===== Disk + SMART ===== -->
      <div class="tile span-4 res-card">
        <h3>
          {{ t('dashboard.disk_smart') }}
          <span class="disk-badges">
            <span class="badge" :class="barClass(diskPct) || ''">{{ diskPct }}%</span>
            <span class="badge" :class="smartSummaryClass">{{ smartSummary }}</span>
          </span>
        </h3>
        <div class="res-head disk-head">
          <div class="big">{{ formatCapacityGb(diskUsed) }}<small> / {{ formatCapacityGb(diskTotal) }}</small></div>
          <div class="sub">{{ t('dashboard.disk_free_short', { free: formatCapacityGb(diskFree) }) }}</div>
        </div>
        <div class="pct-bar thick" :class="barClass(diskPct)">
          <i :style="{ width: diskPct + '%' }"></i>
        </div>
        <div class="disk-list">
          <div v-for="d in smartDisks" :key="d.id" class="disk-item">
            <div class="disk-primary">
              <strong :title="d.smart?.model || d.name || d.id">{{ d.name || d.smart?.model || d.id }}</strong>
              <span class="disk-primary-meta">
                <span v-if="formatDiskSize(d)" class="disk-capacity">{{ formatDiskSize(d) }}</span>
                <span class="badge" :class="smartBadgeClass(d)">{{ smartHealthLabel(d) }}</span>
              </span>
            </div>
            <div v-if="d.smart" class="disk-facts">
              <span class="disk-temp">{{ d.smart.temp || '—' }}</span>
              <span>{{ t('dashboard.wear') }} <b>{{ d.smart.wear || '—' }}</b></span>
              <span>{{ t('dashboard.written') }} <b>{{ d.smart.written || '—' }}</b></span>
              <span v-if="d.smart.media_errors != null">{{ t('dashboard.media_errors') }} <b>{{ d.smart.media_errors }}</b></span>
            </div>
            <div v-else class="disk-unavailable" :title="d.error || ''">{{ t('dashboard.smart_unavailable_short') }}</div>
          </div>
          <div v-if="!smartDisks.length" class="disk-empty">{{ t('dashboard.no_smart_disks') }}</div>
        </div>
        <LineChart
          style="margin-top:5px"
          :height="52"
          :min="0"
          :max="100"
          percent
          :series="diskChartSeries"
          unit="%"
        />
      </div>

      <!-- ===== Network + processes ===== -->
      <div class="tile span-4">
        <h3>{{ t('dashboard.net_proc') }}</h3>
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
            <div class="v2">{{ cpu.proc_total ?? '—' }} <small class="sub">run {{ cpu.proc_running ?? '—' }}</small></div>
          </div>
        </div>
        <h2 class="section-title top-cpu-head">
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
              @click="copyOllamaApi"
            ><Copy :size="12" /></button>
          </span>
        </h2>
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
              <tr v-for="p in topProcs" :key="p.pid">
                <td class="proc" :title="'pid '+p.pid">
                  <strong>{{ p.name }}</strong>
                  <div class="show-m sub">{{ p.rss_mb }}M</div>
                </td>
                <td class="num cpu-cell">
                  <span class="cpu-n">{{ p.cpu }}</span>
                  <span class="mini-bar"><i :style="{ width: Math.min(100, Number(p.cpu) || 0) + '%' }"></i></span>
                </td>
                <td class="num">{{ p.mem }}</td>
                <td class="num col-hide-m">{{ p.rss_mb }}M</td>
              </tr>
              <tr v-if="!topProcs.length">
                <td colspan="4" style="color:var(--sub)">{{ t('common.loading') }}</td>
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
              <th></th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="v in (storage?.volumes || []).slice(0, 8)" :key="v.mount">
              <td class="mono">
                {{ shortMount(v) }}
                <div class="show-m sub">{{ v.kind }} · {{ v.used_gb }} / {{ v.avail_gb }} GB</div>
              </td>
              <td class="col-hide-m"><span class="badge accent">{{ v.kind }}</span></td>
              <td class="col-hide-m">{{ v.total_gb }} GB</td>
              <td class="col-hide-m">{{ v.used_gb }} GB</td>
              <td class="col-hide-m">{{ v.avail_gb }} GB</td>
              <td style="min-width:100px">
                <strong :style="{ color: v.pct >= 90 ? 'var(--down)' : (v.pct >= 75 ? 'var(--warn)' : 'inherit') }">{{ v.pct }}%</strong>
                <div class="pct-bar" :class="barClass(v.pct)" style="margin-top:3px">
                  <i :style="{ width: v.pct + '%' }"></i>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
        </div>
      </div>

      <!-- ===== Docker ===== -->
      <div class="tile span-4">
        <h3>
          Docker
          <span class="badge">{{ containers.length }}</span>
          <span v-if="cstatsStale" class="badge warn" :title="t('dashboard.stats_stale_hint')">
            {{ t('dashboard.stats_stale') }}
          </span>
          <router-link class="btn tiny" to="/containers">{{ t('common.manage') }}</router-link>
        </h3>
        <div class="table-wrap">
        <table class="dense fit-m">
          <thead>
            <tr><th></th><th>{{ t('dashboard.col_name') }}</th><th class="col-hide-m">{{ t('dashboard.col_status') }}</th><th>{{ t('dashboard.col_cpu') }}</th><th>{{ t('dashboard.col_mem') }}</th><th></th></tr>
          </thead>
          <tbody>
            <tr v-for="c in containers.slice(0, 10)" :key="c.id">
              <td><span class="led" :class="led(c.state)"></span></td>
              <td>
                <strong>{{ c.name }}</strong>
                <div class="mono" style="color:var(--sub);font-size:10px">{{ shortImage(c.image) }}</div>
                <div v-if="c.status" class="show-m sub">{{ c.status }}</div>
              </td>
              <td class="col-hide-m" style="font-size:11px">{{ c.status }}</td>
              <td class="mono">
                {{ cstats[c.id]?.cpu || '—' }}
                <span v-if="cpuNum(cstats[c.id]?.cpu)!=null" class="mini-bar">
                  <i :style="{ width: Math.min(100, cpuNum(cstats[c.id]?.cpu)) + '%' }"></i>
                </span>
              </td>
              <td class="mono">{{ cstats[c.id]?.mem_pct || cstats[c.id]?.mem || '—' }}</td>
              <td>
                <a v-if="c.url" class="btn tiny primary" :href="c.url" target="_blank">WebUI</a>
              </td>
            </tr>
            <tr v-if="!containers.length">
              <td colspan="6" style="color:var(--sub)">{{ t('dashboard.no_containers') }}</td>
            </tr>
          </tbody>
        </table>
        </div>
      </div>

      <!-- ===== Attention ===== -->
      <div class="tile span-4">
        <h3>
          {{ t('dashboard.attention') }}
          <span class="badge" :class="attention.length ? 'down' : 'ok'">{{ attention.length }}</span>
          <span class="sub" style="font-weight:500;text-transform:none;letter-spacing:0">
            {{ t('dashboard.services_count', { total: status?.service_total ?? '—', ok: status?.counts?.ok ?? 0 }) }}
          </span>
        </h3>
        <div v-if="!attention.length" class="sub ok-msg">{{ t('dashboard.all_ok') }}</div>
        <div v-else class="alert-list">
          <div v-for="s in attention.slice(0, 10)" :key="s.id" class="alert-item">
            <span class="led" :class="led(s.state)"></span>
            <div style="flex:1;min-width:0">
              <div class="name">{{ s.name }}</div>
              <div class="detail" style="margin:0">{{ s.group }} · {{ s.detail }}</div>
            </div>
            <button
              v-for="a in (s.actions || []).filter(x => ['start','restart'].includes(x)).slice(0,1)"
              :key="a"
              class="tiny primary"
              :disabled="busy"
              @click="act(s, a)"
            >{{ labels[a] || a }}</button>
          </div>
        </div>
        <h3 style="margin-top:12px">{{ t('dashboard.recent_alerts') }}</h3>
        <div v-if="!alerts.length" class="sub">{{ t('common.none') }}</div>
        <div v-for="(a,i) in alerts.slice(0,5)" :key="i" class="alert-item">
          <span class="led" :class="a.level === 'ok' ? 'on' : (a.level === 'warn' ? 'warn' : 'err')"></span>
          <div style="flex:1">
            <div class="name">{{ a.name }}</div>
            <div class="detail" style="margin:0">{{ fmt(a.t) }} · {{ a.message }}</div>
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
            <tr v-for="(p,i) in ports.slice(0, 12)" :key="i">
              <td>
                {{ p.process }}
                <div v-if="p.address" class="show-m sub mono">{{ p.address }}</div>
              </td>
              <td class="mono">{{ p.port }}</td>
              <td class="mono col-hide-m" style="font-size:10px">{{ p.address }}</td>
            </tr>
            <tr v-if="!ports.length"><td colspan="3" style="color:var(--sub)">—</td></tr>
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
          <div class="hg ok"><div class="n">{{ health.summary.ok }}</div><div class="l">{{ t('health.passed') }}</div></div>
          <div class="hg warn"><div class="n">{{ health.summary.warn }}</div><div class="l">{{ t('health.warnings') }}</div></div>
          <div class="hg err"><div class="n">{{ health.summary.error }}</div><div class="l">{{ t('health.errors') }}</div></div>
        </div>
        <div class="failed-checks" v-if="failedChecks.length">
          <div v-for="c in failedChecks.slice(0, 3)" :key="c.id" class="alert-item">
            <span class="led" :class="c.level === 'error' ? 'err' : 'warn'"></span>
            <div style="flex:1">
              <div class="name">{{ c.name }}</div>
              <div class="detail" style="margin:0">{{ errText(c.detail) }}</div>
            </div>
          </div>
        </div>
        <div class="sub" style="margin-top:8px" v-if="status?.adaptive">
          {{ t('dashboard.adaptive') }}：
          {{ t('dashboard.adaptive_line', {
            auto: status.adaptive.auto_labeled || 0,
            orphan: status.adaptive.orphan_count || 0,
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
            :href="b.url"
            target="_blank"
            rel="noopener"
            :title="b.url"
          >
            <span class="led" :class="bmLed(b)"></span>
            <span class="bm-name">{{ b.name }}</span>
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
const StackBar = defineAsyncComponent(() => import('../components/StackBar.vue'))
import {
  doAction, getAlerts, getBookmarks, getContainers, getHealthChecks, getHost,
  getListeningPorts, getMetricsRange, getPower, getSensors, getStatus,
  getOllamaStatus, getStorage, getUps, powerAction, setSystemSharing,
} from '../api/client'
import { openAssistant } from '../lib/assistant'
import { injectI18n } from '../i18n'

const toast = inject('toast')
const { t, errText } = injectI18n()

// Member sessions render the reduced services-only dashboard; the router
// guard refreshed authState before this component was allowed to mount.
const isMemberView = computed(() => authState.authenticated && authState.role === 'member')

const status = ref(null)
const storage = ref(null)
const host = ref(null)
const metrics = ref([])
const alerts = ref([])
const containers = ref([])
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
const ports = ref([])
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
  if (actionRefreshTimer) clearTimeout(actionRefreshTimer)
  actionRefreshTimer = setTimeout(() => {
    actionRefreshTimer = null
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
const ncpu = computed(() => cpu.value.ncpu || sys.value.ncpu || host.value?.ncpu || 1)

const load1 = computed(() => cpu.value.load1 ?? sys.value.load1)
const load5 = computed(() => cpu.value.load5 ?? sys.value.load5)
const load15 = computed(() => cpu.value.load15 ?? sys.value.load15)
const loadPct = computed(() => cpu.value.load_pct ?? sys.value.load_pct ?? 0)
const cpuUsed = computed(() => {
  const v = sensors.value?.cpu_used_pct ?? cpu.value.used_pct
  return v != null ? Number(v) : 0
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
  return smartIsOk(d) ? t('dashboard.smart_passed') : (d.smart.health || t('dashboard.smart_warning'))
}
function formatDiskSize(d) {
  if (d?.size) return d.size
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
const cpuStack = computed(() => [
  { label: 'user', value: cpu.value.user || 0, color: 'var(--accent)' },
  { label: 'sys', value: cpu.value.sys || 0, color: 'var(--warn)' },
  { label: 'idle', value: cpu.value.idle || 0, color: 'var(--bar-track)' },
])
const memTotal = computed(() => mem.value.total_gb ?? sys.value.mem_total_gb ?? host.value?.mem_total_gb ?? '—')
// pressure-based (macOS); NOT PhysMem cache-inflated used%
const memUsedPct = computed(() => {
  if (mem.value.pressure_used_pct != null) return mem.value.pressure_used_pct
  if (mem.value.used_pct != null) return mem.value.used_pct
  if (sys.value.mem_free_pct != null) return 100 - sys.value.mem_free_pct
  return 0
})
const memFreePct = computed(() =>
  mem.value.pressure_free_pct ?? mem.value.free_pct ?? sys.value.mem_free_pct ?? '—'
)
const memAvailGb = computed(() =>
  mem.value.available_gb ?? mem.value.free_gb ?? '—'
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

const diskArray = computed(() => storage.value?.array || {})
const diskUsed = computed(() => diskArray.value.used_gb ?? sensors.value?.disk?.root_used_gb ?? sys.value.disk_used_gb ?? '—')
const diskTotal = computed(() => diskArray.value.total_gb ?? sensors.value?.disk?.root_total_gb ?? sys.value.disk_total_gb ?? '—')
const diskFree = computed(() => diskArray.value.free_gb ?? sensors.value?.disk?.root_free_gb ?? sys.value.disk_free_gb ?? '—')
const diskPct = computed(() => {
  const total = Number(diskTotal.value)
  const used = Number(diskUsed.value)
  if (Number.isFinite(total) && total > 0 && Number.isFinite(used)) return Math.round(used / total * 100)
  return sensors.value?.disk?.root_pct ?? sys.value.disk_pct ?? 0
})

const uptimeText = computed(() =>
  sensors.value?.uptime?.uptime_text || sys.value.uptime || '—'
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
  return first?.name || ''
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
  const raw = ollama.value?.url || 'http://127.0.0.1:11434'
  try {
    return new URL(raw).host
  } catch {
    return '127.0.0.1:11434'
  }
})
const ollamaApiTitle = computed(() => ollamaTooltip.value || 'http://127.0.0.1:11434')
const ollamaTooltip = computed(() => {
  const o = ollama.value
  if (!o) return ''
  const lines = [t('dashboard.ollama_title')]
  if (o.url) lines.push(o.url)
  if (o.version) lines.push(`v${o.version}`)
  if (ollamaResidentName.value) lines.push(t('dashboard.ollama_resident', { name: ollamaResidentName.value }))
  else if (o.reachable) lines.push(t('dashboard.ollama_none_resident'))
  else lines.push(t('dashboard.ollama_down'))
  return lines.join('\n')
})

const upsTooltip = computed(() => {
  const u = ups.value
  if (!u?.present) return ''
  const lines = [`${t('dashboard.ups_title')} · ${u.name || '—'}`]
  lines.push(
    (u.on_battery ? t('dashboard.ups_on_battery') : t('dashboard.ups_on_ac'))
    + (u.charging ? ` · ${t('dashboard.ups_charging')}` : ''),
  )
  if (u.battery_percent != null) lines.push(`${t('dashboard.ups_battery')} ${u.battery_percent}%`)
  if (u.time_remaining_min != null) lines.push(t('dashboard.ups_remaining', { m: u.time_remaining_min }))
  lines.push(t('dashboard.ups_threshold', { pct: u.settings?.low_battery_pct ?? 20 }))
  const policy = upsPolicyPhase.value === 'engaged'
    ? t('dashboard.ups_policy_engaged')
    : upsPolicyPhase.value === 'restoring'
      ? t('dashboard.ups_policy_restoring')
      : t(u.settings?.shutdown?.enabled ? 'dashboard.ups_policy_on' : 'dashboard.ups_policy_off')
  lines.push(`${t('dashboard.ups_policy')}: ${policy}`)
  return lines.join('\n')
})

const healthOk = computed(() => health.value?.healthy !== false && !(health.value?.summary?.error > 0))
const healthSummary = computed(() => {
  if (!health.value) return '…'
  if (health.value.healthy) return '✅ ' + t('common.healthy')
  const e = health.value.summary?.error || 0
  const w = health.value.summary?.warn || 0
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
  if (h === 'ok') return b.ms != null ? b.ms + ' ms' : t('dashboard.bm_up')
  if (h === 'stopped') return t('dashboard.bm_stopped')
  return t('dashboard.bm_down')
}

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

function setMetricRange(r) {
  if (!METRIC_RANGES.includes(r)) return
  metricRange.value = r
  try { localStorage.setItem(METRIC_RANGE_KEY, r) } catch {}
  metricsSwitching.value = true
  loadMetrics().finally(() => { metricsSwitching.value = false })
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
    powerData.value = await getPower()
    powerLoaded.value = true
  } catch {
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
    toast(r.ok ? `✅ ${r.message}` : `❌ ${r.message}`)
  } catch (e) {
    toast('❌ ' + e.message)
  }
  pwrBusy.value = false
}
async function enableSS() {
  ssBusy.value = true
  try {
    const r = await setSystemSharing('screen_sharing', true)
    toast(r.ok ? `✅ ${r.message}` : `⚠️ ${r.message}`)
    await loadPower()
  } catch (e) {
    toast('❌ ' + e.message)
  }
  ssBusy.value = false
}
async function disableSS() {
  if (!confirm(t('power.confirm_disable_ss'))) return
  ssBusy.value = true
  try {
    const r = await setSystemSharing('screen_sharing', false)
    toast(r.ok ? `✅ ${r.message}` : `⚠️ ${r.message}`)
    await loadPower()
  } catch (e) {
    toast('❌ ' + e.message)
  }
  ssBusy.value = false
}
function copyVnc() {
  const text = ss.value?.vnc_url
  if (!text) return
  try {
    navigator.clipboard.writeText(text)
    toast('✅ ' + t('power.copied'))
  } catch {
    toast('❌ ' + text)
  }
}
function copyOllamaApi() {
  const text = ollama.value?.url || 'http://127.0.0.1:11434'
  try {
    navigator.clipboard.writeText(text)
    toast('✅ ' + t('common.copied'))
  } catch {
    toast('❌ ' + t('common.copy_failed'))
  }
}
function barClass(pct) {
  if (pct >= 90) return 'danger'
  if (pct >= 75) return 'warn'
  return ''
}
function shortMount(v) {
  if (v.mount === '/') return t('dashboard.mount_system')
  if (v.mount === '/System/Volumes/Data') return 'Data'
  if (v.mount.startsWith('/Volumes/')) return v.mount.slice(9)
  if (v.kind === 'orbstack') return t('dashboard.mount_orbstack')
  return v.mount
}
function shortImage(img) {
  if (!img) return ''
  const s = String(img).split('/').pop()
  return s.length > 36 ? s.slice(0, 34) + '…' : s
}
function led(state) {
  if (state === 'ok') return 'on'
  if (state === 'warn') return 'warn'
  if (state === 'stopped') return 'off'
  return 'err'
}
function fmt(ts) {
  return ts ? new Date(ts * 1000).toLocaleString() : ''
}
function fmtN(v) {
  if (v == null || Number.isNaN(v)) return '—'
  return typeof v === 'number' ? (Math.abs(v) >= 10 ? Math.round(v * 10) / 10 : Number(v.toFixed(2))) : v
}
function cpuNum(s) {
  if (!s) return null
  const n = parseFloat(String(s).replace('%', ''))
  return Number.isFinite(n) ? n : null
}
function formatBps(bps) {
  if (bps == null) return '—'
  if (bps < 1024) return `${bps} B/s`
  if (bps < 1024 ** 2) return `${(bps / 1024).toFixed(1)} KB/s`
  if (bps < 1024 ** 3) return `${(bps / 1024 ** 2).toFixed(1)} MB/s`
  return `${(bps / 1024 ** 3).toFixed(2)} GB/s`
}

// Both return `false` on failure so the 12s tick below can report it to
// lib/poll.js, whose backoff then slows a dead server's polling down.
async function refresh() {
  try {
    status.value = await getStatus()
    loadError.value = ''
  } catch (e) {
    loadError.value = e.message || String(e)
    return false
  }
}
async function loadSensors(force = false, { light = false } = {}) {
  try {
    // Prefer cache; force only on manual refresh.  The 20s tick uses
    // light=true so a sitting dashboard does not spawn ``top``.
    sensors.value = await getSensors(force, { light })
    loadError.value = ''
  } catch (e) {
    loadError.value = e.message || String(e)
    return false
  }
}
async function loadMetrics() {
  try {
    const m = await getMetricsRange(metricRange.value)
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
  let hostOk = true
  // Same contract as the skeleton (`!host && !sensors`): a 90s poll must
  // not disable Refresh or look like a first-paint reload.
  if (!host.value && !sensors.value) loading.value = true
  // None of these may sit in the skeleton Promise.all: on this host they
  // measured 1.1–3.4s and, when awaited next to docker stats, the cheap
  // list call queued behind it and put the 3s wait back on first paint.
  void getContainers(withDockerStats).then(c => {
    containers.value = c.containers || []
    if (c.stats && Object.keys(c.stats).length) {
      cstats.value = c.stats
      cstatsAt.value = Date.now()
    }
  }).catch(() => {})
  void getHealthChecks().then(h => { health.value = h }).catch(() => {})
  void loadSensors(forceSensors)
  void getBookmarks().then(b => { bookmarks.value = b.bookmarks || [] }).catch(() => {})
  await Promise.all([
    loadMetrics(),
    getStorage(true).then(s => { storage.value = s }).catch(() => {}),
    // host drives the skeleton gate, so its failure has to be visible rather
    // than leaving the page on placeholders.
    getHost().then(h => { host.value = h }).catch(e => {
      loadError.value = e.message || String(e)
      hostOk = false
    }),
    getAlerts(12).then(a => { alerts.value = a.alerts || [] }).catch(() => {}),
    getListeningPorts(40).then(p => { ports.value = p.ports || [] }).catch(() => {}),
    getUps().then(u => { ups.value = u }).catch(() => {}),
    getOllamaStatus().then(o => { ollama.value = o }).catch(() => {}),
    loadPower(),
  ])
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
  return refreshHeavy(true)
}
async function act(svc, action) {
  if (busy.value) return
  busy.value = true
  try {
    const r = await doAction(svc.id, action)
    toast(r.ok ? `✅ ${svc.name}` : `❌ ${(r.message || '').slice(0, 80)}`)
    if (r.ok) scheduleActionRefresh()
  } catch (e) {
    toast('❌ ' + e.message)
  } finally {
    busy.value = false
  }
}

const highMode = computed(() => status.value?.resource_mode === 'high')

function stopDashTimers() {
  if (typeof timer === 'function') timer()
  if (typeof heavyTimer === 'function') heavyTimer()
  timer = null
  heavyTimer = null
}

function startDashTimers() {
  stopDashTimers()
  const lightMs = highMode.value ? 12000 : 20000
  if (isMemberView.value) {
    timer = startVisibleInterval(async () => {
      const ok = await refresh()
      clock.value = Date.now()
      return ok
    }, lightMs)
    return
  }
  // Low: light sensors, no docker stats on the 90s tick.
  // High: full sensors every 12s and docker stats every 60s.
  timer = startVisibleInterval(async () => {
    const results = await Promise.all([
      refresh(),
      loadSensors(false, { light: !highMode.value }),
    ])
    clock.value = Date.now()
    if (results.includes(false)) return false
  }, lightMs)
  heavyTimer = startVisibleInterval(
    () => refreshHeavy(false, highMode.value),
    highMode.value ? 60000 : 90000,
  )
}

onMounted(() => {
  void (async () => {
    await refresh()
    if (!isMemberView.value) {
      // Low: names/state only. High: docker stats fill CPU/MEM.
      void refreshHeavy(false, highMode.value)
    }
    startDashTimers()
  })()
})
watch(highMode, () => startDashTimers())
onUnmounted(() => {
  stopDashTimers()
  if (actionRefreshTimer) clearTimeout(actionRefreshTimer)
  actionRefreshTimer = null
})
</script>

<style scoped>
.dash { }
.dash-grid { gap: 10px; }
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
.host-ups.warn { background: color-mix(in srgb, var(--warn) 14%, transparent); color: var(--warn); border-color: transparent; }
.host-ups.ok { background: color-mix(in srgb, var(--ok) 14%, transparent); color: var(--ok); border-color: transparent; }
.host-ups.danger { background: color-mix(in srgb, var(--down) 12%, transparent); color: var(--down); border-color: transparent; }
a.host-ollama { text-decoration: none; }
button.host-assist { cursor: pointer; font: inherit; color: inherit; }
.host-meta { color: var(--sub); font-size: 12px; margin-top: 4px; display: flex; flex-wrap: wrap; gap: 5px; }
.host-meta .dot { opacity: .35; }
.host-pills { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; }
.host-pills .pill {
  background: var(--btn); border: 1px solid var(--line);
  color: var(--txt); padding: 4px 10px; border-radius: var(--radius-pill); font-size: 11px; font-weight: 600;
}
.host-pills .pill.ok { background: color-mix(in srgb, var(--ok) 14%, transparent); color: var(--ok); border-color: transparent; }
.host-pills .pill.down { background: color-mix(in srgb, var(--down) 12%, transparent); color: var(--down); border-color: transparent; }

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
.cpu-head { margin-bottom: 4px; }
.cpu-facts { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 5px; margin-bottom: 8px; }
.cpu-facts > div { min-width: 0; padding: 5px 6px; border: 1px solid var(--line); border-radius: var(--radius-sm); background: var(--bg); }
.cpu-facts span, .cpu-facts b { display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.cpu-facts span { color: var(--sub); font-size: 9px; text-transform: uppercase; letter-spacing: .3px; }
.cpu-facts b { margin-top: 2px; color: var(--txt); font: 700 11px ui-monospace, Menlo, monospace; }

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

.temp-warn { color: var(--warn) !important; }
.disk-badges { display: inline-flex; align-items: center; gap: 4px; }
.disk-head { align-items: end; }
.disk-head .sub { margin: 0; white-space: nowrap; }
.disk-list { display: flex; flex-direction: column; gap: 4px; margin-top: 8px; }
.disk-item { min-width: 0; padding: 5px 8px; border: 1px solid var(--line); border-radius: var(--radius-sm); background: var(--bg); }
.disk-primary { display: flex; align-items: center; justify-content: space-between; gap: 6px; min-width: 0; }
.disk-primary strong { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 11px; }
.disk-primary-meta { flex: 0 0 auto; display: inline-flex; align-items: center; gap: 4px; }
.disk-capacity { color: var(--txt); font: 700 10px ui-monospace, Menlo, monospace; white-space: nowrap; }
.disk-facts { display: flex; flex-wrap: wrap; gap: 2px 8px; margin-top: 3px; color: var(--sub); font-size: 10px; line-height: 1.3; }
.disk-facts b { color: var(--txt); font-family: ui-monospace, Menlo, monospace; }
.disk-temp { color: var(--txt); font-weight: 700; font-family: ui-monospace, Menlo, monospace; }
.disk-unavailable, .disk-empty { margin-top: 2px; color: var(--sub); font-size: 10px; line-height: 1.25; }

.top-cpu-head { justify-content: space-between; margin-top: 10px; }
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
.ollama-api:hover { color: var(--accent); }
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
.range-btns { display: inline-flex; gap: 3px; }
.pwr-group { display: inline-flex; align-items: center; gap: 3px; margin-left: 4px; }
.pwr-group .tiny { font-size: 12px; padding: 2px 6px; text-decoration: none; display: inline-flex; align-items: center; justify-content: center; }
.pwr-group a.tiny.disabled { opacity: .4; pointer-events: none; cursor: not-allowed; }
.hint-line { margin-top: 8px; font-size: 11px; color: var(--sub); line-height: 1.5; }
.ok-msg { color: var(--ok); font-weight: 600; padding: 8px 0; }

.health-grid {
  display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px;
}
.hg {
  text-align: center; padding: 12px 6px; border-radius: var(--radius-sm);
  border: 1px solid var(--line); background: var(--bg);
}
.hg .n { font-size: 24px; font-weight: 800; }
.hg .l { font-size: 9px; color: var(--sub); text-transform: uppercase; margin-top: 3px; letter-spacing: .3px; }
.hg.ok .n { color: var(--ok); }
.hg.warn .n { color: var(--warn); }
.hg.err .n { color: var(--down); }
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
  color: var(--accent);
}
.bm-card.down .bm-name { color: var(--down); }
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
  .cpu-facts { grid-template-columns: repeat(2, 1fr); }
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
  .cpu-facts { grid-template-columns: 1fr 1fr; gap: 4px; }
  .net-stats { grid-template-columns: 1fr; }
  .health-grid { grid-template-columns: 1fr 1fr; }
  .mem-break { grid-template-columns: 1fr; }
}
</style>
