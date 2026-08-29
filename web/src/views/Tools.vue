<template>
  <div class="tools-page">
    <!-- No visible page title on this layout; see Dashboard.vue. -->
    <h1 class="sr-only">{{ t('tools.title') }}</h1>
    <div class="tabs">
      <button
        v-for="tb in tabs"
        :key="tb.id"
        type="button"
        :class="{ active: tab===tb.id }"
        :aria-pressed="tab===tb.id"
        @click="switchTab(tb.id)"
      >
        {{ t(tb.labelKey) }}
      </button>
    </div>
    <div class="toolbar">
      <button type="button" class="primary" @click="reload" :disabled="loading">{{ t('common.refresh') }}</button>
    </div>

    <!-- Tools home tiles -->
    <template v-if="tab==='home'">
      <LoadFailure v-if="catalogError" :detail="catalogError" :retry="reload" :busy="loading" />
      <SkeletonLoader v-else-if="!tabLoaded.home" variant="cards" :rows="8" />
      <template v-else>
        <p v-if="catalog.hint_key || catalog.hint" class="hint" style="margin-top:0">
          {{ catalog.hint_key ? t(catalog.hint_key) : finiteText(catalog.hint) }}
        </p>
        <div v-if="!asArray(catalog.tiles).length" class="placeholder">{{ t('common.none') }}</div>
        <div v-else class="tool-grid">
          <button
            v-for="tile in asArray(catalog.tiles)"
            :key="tile.id"
            type="button"
            class="tool-tile"
            @click="openTile(tile)"
          >
            <div class="tile-label">{{ tileLabel(tile) }}</div>
            <div class="tile-desc">{{ tileDesc(tile) }}</div>
          </button>
        </div>
      </template>
    </template>

    <!-- System info / diagnostics -->
    <template v-else-if="tab==='diag' && diag">
      <div class="dash-grid">
        <div class="tile span-4">
          <h3>{{ t('tools.host') }}</h3>
          <div class="kv">
            <div class="k">{{ t('tools.hostname') }}</div><div class="mono">{{ finiteText(diag.hostname) }}</div>
            <div class="k">CPU</div><div class="mono" style="font-size:11px">{{ finiteText(diag.cpu) }}</div>
            <div class="k">{{ t('tools.cores') }}</div><div>{{ finiteN(diag.ncpu) }}</div>
            <div class="k">{{ t('tools.memory') }}</div><div>{{ fmtGb(diag.mem_gb) }}</div>
            <div class="k">{{ t('tools.load') }}</div><div class="mono">{{ asArray(diag.load).map(n => finiteN(n)).join(' / ') }}</div>
            <div class="k">{{ t('tools.uptime') }}</div><div class="mono">{{ finiteText(diag.uptime_human) }}</div>
            <div class="k">{{ t('tools.root_disk') }}</div>
            <div class="mono">{{ withUnit(diag.root_disk_pct, '%') }} · {{ t('common.free') }} {{ fmtGb(diag.root_disk_free_gb) }}</div>
            <div class="k">{{ t('tools.platform') }}</div><div class="mono" style="font-size:11px">{{ finiteText(diag.platform) }}</div>
          </div>
        </div>
        <div class="tile span-4">
          <h3>{{ t('tools.runtime') }}</h3>
          <div class="kv">
            <div class="k">OrbStack</div>
            <div><span class="badge" :class="diag.orbstack?'ok':'down'">{{ diag.orbstack ? t('common.running') : t('common.off') }}</span></div>
            <div class="k">docker</div><div class="mono">{{ finiteText(diag.docker_cli) }}</div>
            <div class="k">orb</div><div class="mono">{{ finiteText(diag.orb_cli) }}</div>
            <div class="k">Python</div><div>{{ finiteText(diag.python) }}</div>
            <div class="k">Host IP</div><div class="mono">{{ finiteText(diag.host_ip) }}</div>
            <div class="k">{{ t('tools.metrics_pts') }}</div><div>{{ finiteN(diag.metrics_points) }} / 1h</div>
            <div class="k">{{ t('tools.time') }}</div><div class="mono">{{ finiteText(diag.ts) }}</div>
            <div class="k">{{ t('tools.version') }}</div><div>ServerHub {{ finiteText(diag.version) }}</div>
          </div>
        </div>
        <div class="tile span-4">
          <h3>{{ t('tools.diagnostics') }}</h3>
          <p class="hint" style="margin-top:0">{{ t('tools.diagnostics_hint') }}</p>
          <div class="btns" style="flex-direction:column;align-items:stretch">
            <a class="btn primary" href="/api/diagnostics/download">{{ t('tools.download_diag') }}</a>
            <button @click="genDiag" :disabled="loading">{{ t('tools.gen_diag') }}</button>
            <router-link class="btn" to="/health">{{ t('tools.fcp') }}</router-link>
            <router-link class="btn" to="/settings">{{ t('nav.settings') }}</router-link>
            <router-link class="btn" to="/maintenance">{{ t('nav.maintenance') }}</router-link>
          </div>
          <!-- role=status: the saved path (or the save failure) lands here after
               the click; without a live region it appeared silently. -->
          <p class="hint" v-if="diagMsg" style="margin-top:10px" role="status">{{ finiteText(diagMsg) }}</p>
        </div>
      </div>
    </template>

    <!-- Syslog -->
    <template v-else-if="tab==='syslog'">
      <div class="toolbar">
        <select v-model="syslogLevel" :aria-label="t('tools.syslog_level')" @change="loadSyslog">
          <option value="error">{{ t('tools.syslog_err') }}</option>
          <option value="fault">{{ t('tools.syslog_fault') }}</option>
          <option value="default">{{ t('tools.syslog_default') }}</option>
          <option value="all">{{ t('tools.syslog_all') }}</option>
        </select>
        <select v-model.number="syslogMinutes" :aria-label="t('tools.syslog_range')" @change="loadSyslog">
          <option :value="15">15m</option>
          <option :value="60">1h</option>
          <option :value="360">6h</option>
          <option :value="1440">24h</option>
        </select>
        <button @click="loadSyslog" :disabled="loading">{{ t('common.refresh') }}</button>
        <!-- role=status: the count is the answer to the level/range selects and
             the Refresh click, and it changed silently for a screen reader.
             Same pattern as the filter counts (filterCounts.test.js). -->
        <span class="meta" role="status">{{ t('tools.lines_n', { n: finiteN(syslog.count, 0) }) }}</span>
      </div>
      <p class="hint">{{ finiteText(syslog.hint, '') || t('tools.syslog_hint') }}</p>
      <SkeletonLoader v-if="!tabLoaded.syslog" :cols="1" :rows="8" />
      <template v-else>
        <!-- Banner above the content, not behind it: the old v-else-if chain put
             the lines branch first, so once any lines were on screen a failed
             re-load (level/range change, Refresh) rendered no banner at all —
             its only trace was a four-second toast. Stale lines still render
             below, which is the LoadFailure contract. -->
        <LoadFailure v-if="tabError.syslog" :detail="tabError.syslog" :retry="reload" :busy="loading" />
        <!-- tabindex=0: the box caps at 480px and scrolls; a scrollable region a
             keyboard cannot reach cannot be scrolled by one (WCAG 2.1.1). Same
             treatment as the Logs viewer. -->
        <div
          v-if="asArray(syslog.lines).length"
          class="log-box mono"
          tabindex="0"
          role="region"
          :aria-label="t('tools.tab_syslog')"
        >
          <div v-for="(ln,i) in asArray(syslog.lines)" :key="i">{{ finiteText(ln) }}</div>
        </div>
        <div v-else-if="!tabError.syslog" class="placeholder">{{ finiteText(syslog.message, '') || t('tools.no_data') }}</div>
      </template>
    </template>

    <!-- Processes -->
    <template v-else-if="tab==='proc'">
      <div class="toolbar">
        <input v-model="procQ" type="text" :placeholder="t('tools.filter_proc')" style="min-width:180px"  :aria-label="t('tools.filter_proc')"/>
        <!-- role=status: the count is the only feedback the filter box gives,
             and it changed silently for a screen reader. Same pattern as the
             Services filter count. -->
        <span class="meta-count" role="status">{{ filteredProc.length }} / {{ processes.length }}</span>
      </div>
      <SkeletonLoader v-if="!tabLoaded.proc" :cols="6" :rows="8" />
      <LoadFailure v-else-if="tabError.proc" :detail="tabError.proc" :retry="reload" :busy="loading" />
      <div v-else class="table-wrap">
        <table class="dense fit-m">
          <thead>
            <tr>
              <th>PID</th><th class="col-hide-m">{{ t('tools.user') }}</th><th>CPU%</th><th>MEM%</th><th class="col-hide-m">TIME</th><th>{{ t('tools.command') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="p in filteredProc" :key="p.pid + p.command">
              <td class="mono">{{ finiteN(p.pid) }}</td>
              <td class="col-hide-m">{{ finiteText(p.user) }}</td>
              <td class="mono">{{ fmtPct(p.cpu) }}</td>
              <td class="mono">{{ fmtPct(p.mem) }}</td>
              <td class="mono col-hide-m">{{ finiteText(p.time) }}</td>
              <td class="mono" style="max-width:480px;overflow:hidden;text-overflow:ellipsis" :title="finiteText(p.command)">{{ finiteText(p.command) }}</td>
            </tr>
            <!-- "No match" is only true while a filter is applied; with the box
                 empty a bare list means the host reported no processes, which is
                 a different (and stranger) fact worth stating as itself. -->
            <tr v-if="!filteredProc.length">
              <td colspan="6" class="empty-row">{{ procQ.trim() ? t('common.no_match') : t('tools.no_data') }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </template>

    <!-- Docker -->
    <template v-else-if="tab==='docker'">
      <h2 class="section-title">docker system df</h2>
      <SkeletonLoader v-if="!tabLoaded.docker" :cols="5" :rows="4" />
      <LoadFailure v-else-if="tabError.docker" :detail="tabError.docker" :retry="reload" :busy="loading" />
      <div v-else class="table-wrap" style="margin-bottom:12px">
        <table class="dense fit-m">
          <thead>
            <tr>
              <th>{{ t('tools.type') }}</th>
              <th>{{ t('tools.col_total') }}</th>
              <th class="col-hide-m">{{ t('tools.col_active') }}</th>
              <th>{{ t('common.size') }}</th>
              <th>{{ t('tools.col_reclaim') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="(l,i) in asArray(df.lines)" :key="i">
              <td>
                {{ finiteText(l.type) }}
                <div class="show-m sub">{{ t('tools.col_active') }} {{ finiteText(l.active) }}</div>
              </td>
              <td>{{ finiteText(l.total) }}</td>
              <td class="col-hide-m">{{ finiteText(l.active) }}</td>
              <td>{{ finiteText(l.size) }}</td>
              <td>{{ finiteText(l.reclaimable) }}</td>
            </tr>
            <tr v-if="!asArray(df.lines).length && !tabError.docker">
              <td colspan="5" class="empty-row">{{ df.engine_up === false ? t('tools.engine_off') : t('tools.no_data') }}</td>
            </tr>
          </tbody>
        </table>
      </div>

      <h2 class="section-title">{{ t('tools.docker_cleanup') }}</h2>
      <p class="hint" style="margin-top:0">{{ t('tools.docker_cleanup_hint') }}</p>
      <div class="btns" style="margin-bottom:14px;flex-wrap:wrap">
        <button :disabled="loading" @click="doPrune('dangling')">{{ t('tools.prune_dangling') }}</button>
        <button :disabled="loading" @click="doPrune('build')">{{ t('tools.prune_build') }}</button>
        <button :disabled="loading" @click="doPrune('volumes')">{{ t('tools.prune_volumes') }}</button>
        <button :disabled="loading" class="warn" @click="doPrune('all_unused')">{{ t('tools.prune_all') }}</button>
      </div>
      <!-- role=status: how much a prune reclaimed is the answer to the click,
           and it used to arrive silently for a screen reader. -->
      <p class="hint" v-if="pruneMsg" role="status">{{ finiteText(pruneMsg) }}</p>

      <h2 class="section-title">{{ t('tools.container_size') }}</h2>
      <div v-if="tabLoaded.docker && !tabError.docker" class="table-wrap">
        <table class="dense fit-m">
          <thead><tr><th>{{ t('common.name') }}</th><th class="col-hide-m">{{ t('tools.image') }}</th><th>{{ t('common.status') }}</th><th>{{ t('common.size') }}</th></tr></thead>
          <tbody>
            <tr v-for="c in sizes" :key="c.name">
              <td>
                <strong>{{ finiteText(c.name) }}</strong>
                <div class="show-m sub mono">{{ finiteText(c.image) }}</div>
              </td>
              <td class="mono col-hide-m">{{ finiteText(c.image) }}</td>
              <td>{{ finiteText(c.status) }}</td>
              <td class="mono">{{ finiteText(c.size) }}</td>
            </tr>
            <!-- Same engine-off / no-data split as the df table above: with the
                 engine (or its CLI) gone this list is empty because docker is
                 unreachable, not because zero containers exist, and "no data"
                 next to an "engine down" df row contradicted it. -->
            <tr v-if="!sizes.length">
              <td colspan="4" class="empty-row">{{ df.engine_up === false ? t('tools.engine_off') : t('tools.no_data') }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </template>

    <!-- Scheduler + agents -->
    <template v-else-if="tab==='sched'">
      <div class="toolbar">
        <router-link class="btn primary" to="/scheduler">{{ t('tools.open_scheduler') }}</router-link>
        <router-link class="btn" to="/maintenance">{{ t('nav.maintenance') }}</router-link>
        <!-- role=status: the timer count is the answer to the Refresh click,
             and it changed silently for a screen reader. Same pattern as the
             syslog line count and the listening-port count. -->
        <span class="meta" style="color:var(--sub)" role="status">{{ t('tools.tasks_n', { n: timers.length }) }}</span>
      </div>
      <h2 class="section-title">{{ t('tools.timers') }}</h2>
      <SkeletonLoader v-if="!tabLoaded.sched" :cols="4" :rows="5" />
      <LoadFailure v-else-if="tabError.sched" :detail="tabError.sched" :retry="reload" :busy="loading" />
      <div v-else class="table-wrap" style="margin-bottom:14px">
        <table class="dense fit-m">
          <thead>
            <tr>
              <th>{{ t('tools.col_label') }}</th>
              <th>{{ t('scheduler.interval') }}</th>
              <th class="col-hide-m">{{ t('scheduler.calendar') }}</th>
              <th class="col-hide-m">{{ t('tools.command') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="row in timers" :key="row.label">
              <td class="mono">
                {{ finiteText(row.label) }}
                <div v-if="formatCal(row.calendar)" class="show-m sub">{{ formatCal(row.calendar) }}</div>
                <div v-if="row.program" class="show-m sub">{{ finiteText(row.program) }}</div>
              </td>
              <td>{{ finiteN(row.interval_sec, null) ? withUnit(row.interval_sec, 's') : '—' }}</td>
              <td class="mono col-hide-m" style="font-size:11px">{{ formatCal(row.calendar) }}</td>
              <td class="mono col-hide-m" style="max-width:360px;overflow:hidden;text-overflow:ellipsis" :title="finiteText(row.program)">{{ finiteText(row.program) }}</td>
            </tr>
            <tr v-if="!timers.length && !tabError.sched">
              <td colspan="4" class="empty-row">{{ t('tools.no_timers') }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <h2 class="section-title">{{ t('tools.agents') }}</h2>
      <!-- Same pending/failure gate as the timers table above. This section used
           to render unconditionally, so while the sched load was in flight the
           timers slot showed a skeleton but this one already claimed "no agents"
           — and after a failure it kept a bare set of column headings under the
           timers' LoadFailure banner. That banner covers both tables (one load
           fills both), so the failed branch here renders nothing extra. -->
      <SkeletonLoader v-if="!tabLoaded.sched" :cols="5" :rows="4" />
      <template v-else-if="!tabError.sched">
      <p class="hint" style="margin-top:0">{{ finiteText(agents.hint) }} · {{ finiteN(agents.count, 0) }}</p>
      <div class="table-wrap">
        <table class="dense fit-m">
          <thead>
            <tr>
              <th>Label</th>
              <th class="col-hide-m">RunAtLoad</th>
              <th class="col-hide-m">KeepAlive</th>
              <th>Timer</th>
              <th class="col-hide-m">{{ t('tools.command') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="a in asArray(agents.agents)" :key="a.label">
              <td class="mono" style="font-size:11px">
                {{ finiteText(a.label) }}
                <div class="show-m sub">{{ a.run_at_load ? 'RunAtLoad' : '' }}{{ a.keep_alive ? (a.run_at_load ? ' · ' : '') + 'KeepAlive' : '' }}</div>
                <div v-if="a.program" class="show-m sub">{{ finiteText(a.program) }}</div>
              </td>
              <td class="col-hide-m">{{ a.run_at_load ? '✓' : '—' }}</td>
              <td class="col-hide-m">{{ a.keep_alive ? '✓' : '—' }}</td>
              <td class="mono">{{ finiteN(a.interval_sec, null) ? withUnit(a.interval_sec, 's') : (a.calendar ? 'cal' : '—') }}</td>
              <td class="mono col-hide-m" style="max-width:280px;overflow:hidden;text-overflow:ellipsis" :title="finiteText(a.program)">{{ finiteText(a.program) }}</td>
            </tr>
            <tr v-if="!asArray(agents.agents).length">
              <td colspan="5" class="empty-row">{{ t('tools.no_agents') }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      </template>
    </template>

    <!-- Hardware -->
    <template v-else-if="tab==='hw'">
      <div class="two-col" v-if="hw">
        <div class="card" v-for="(sec, key) in (hw.sections||{})" :key="key">
          <h2 class="section-title" style="margin-top:0">{{ finiteText(key) }} · {{ finiteText(sec.data_type) }}</h2>
          <!-- tabindex=0: system_profiler output overflows the 240px cap, and a
               scrollable region a keyboard cannot reach cannot be scrolled by
               one (WCAG 2.1.1). Named after its own section heading. -->
          <pre class="mono hw-pre" tabindex="0" role="region" :aria-label="finiteText(key)">{{ finiteText(sec.text) }}</pre>
        </div>
      </div>
      <div class="card" style="margin-top:12px" v-if="asArray(hw?.disks).length">
        <h2 class="section-title" style="margin-top:0">{{ t('tools.disks') }}</h2>
        <div class="table-wrap">
        <table class="dense fit-m">
          <thead><tr><th>ID</th><th>{{ t('common.name') }}</th><th>{{ t('common.size') }}</th><th class="col-hide-m">SSD</th><th>{{ t('common.status') }}</th></tr></thead>
          <tbody>
            <tr v-for="d in asArray(hw.disks)" :key="d.id">
              <td class="mono">{{ finiteText(d.id) }}</td>
              <td>
                {{ finiteText(d.name) }}
                <div class="show-m sub">{{ d.ssd ? 'SSD' : 'HDD' }}</div>
              </td>
              <td class="mono">{{ sizeGb(d.size_gb) }}</td>
              <td class="col-hide-m">{{ d.ssd ? 'SSD' : 'HDD' }}</td>
              <td><span class="badge">{{ finiteText(d.power_state) }}</span></td>
            </tr>
          </tbody>
        </table>
        </div>
      </div>
      <!-- This branch used to be the only thing a failed hardware read produced,
           so the tab sat on "Loading…" forever. -->
      <LoadFailure v-if="tabError.hw" :detail="tabError.hw" :retry="reload" :busy="loading" />
      <div v-else-if="!hw" class="placeholder">{{ t('common.loading') }}</div>
    </template>

    <!-- Updates -->
    <template v-else-if="tab==='updates'">
      <SkeletonLoader v-if="!tabLoaded.updates" variant="tiles" :rows="2" :span="6" :tile-height="120" />
      <LoadFailure v-else-if="tabError.updates" :detail="tabError.updates" :retry="reload" :busy="loading" />
      <template v-else>
      <div class="card" style="margin-bottom:16px">
        <h2 class="section-title" style="margin-top:0">{{ t('tools.github_title') }}</h2>
        <p class="hint" style="margin-top:0">
          {{ t('tools.installed_version', { v: finiteText(updates.github?.current, '') || '—' }) }}
          <template v-if="updates.github?.ok && updates.github?.latest">
            ·
            <span v-if="updates.github.update_available">{{ t('tools.github_newer', { v: finiteText(updates.github.latest) }) }}</span>
            <span v-else>{{ t('tools.github_latest', { v: finiteText(updates.github.latest) }) }} · {{ t('tools.up_to_date') }}</span>
          </template>
        </p>
        <p v-if="updates.github && !updates.github.ok && updates.github.error" class="hint">
          {{ finiteText(updates.github.error) }}
        </p>
        <pre
          v-if="updates.github?.notes"
          class="mono"
          style="font-size:12px;white-space:pre-wrap;max-height:160px;overflow:auto"
          role="log"
          aria-live="polite"
        >{{ finiteText(updates.github.notes) }}</pre>
        <div class="btns" style="margin-top:10px;flex-wrap:wrap">
          <a
            v-if="updates.github?.html_url"
            class="btn"
            :href="finiteText(updates.github.html_url, '')"
            target="_blank"
            rel="noopener"
          >GitHub</a>
          <button type="button" @click="checkGithub" :disabled="loading || !!updateJobId">{{ t('tools.check_github') }}</button>
          <button
            v-if="updates.github?.update_available && updates.github?.dirty"
            type="button"
            class="primary"
            :disabled="loading || !!updateJobId"
            @click="applyGithub(true)"
          >{{ t('tools.stash_and_update') }}</button>
          <button
            v-else-if="updates.github?.update_available"
            type="button"
            class="primary"
            :disabled="loading || !!updateJobId"
            @click="applyGithub(false)"
          >{{ t('tools.apply_update') }}</button>
        </div>
        <p v-if="updates.github?.dirty" class="hint">{{ t('tools.dirty_hint') }}</p>
        <pre
          v-if="updateJobLog"
          class="mono"
          style="font-size:12px;white-space:pre-wrap;max-height:220px;overflow:auto;margin-top:10px"
          role="log"
          aria-live="polite"
        >{{ finiteText(updateJobLog) }}</pre>
      </div>
      <div class="two-col">
        <div class="card">
          <h2 class="section-title" style="margin-top:0">Homebrew</h2>
          <p class="hint" style="margin-top:0">
            {{ t('tools.outdated_n', { n: finiteN(updates.brew?.count, 0) }) }}
          </p>
          <ul class="mono update-list" v-if="asArray(updates.brew?.outdated).length">
            <li v-for="(ln,i) in asArray(updates.brew.outdated)" :key="i">{{ finiteText(ln) }}</li>
          </ul>
          <div v-else class="sub">{{ t('tools.up_to_date') }}</div>
          <div class="btns" style="margin-top:10px" v-if="finiteN(updates.brew?.count, 0) > 0">
            <button type="button" class="primary" :disabled="loading || !!updateJobId" @click="applyBrew">{{ t('tools.brew_upgrade') }}</button>
          </div>
        </div>
        <div class="card">
          <h2 class="section-title" style="margin-top:0">macOS</h2>
          <div class="mono" style="font-size:12px;white-space:pre-wrap;max-height:280px;overflow:auto">
            {{ asArray(updates.macos?.lines).map(n => finiteText(n, '')).filter(Boolean).join('\n') || finiteText(updates.macos?.raw) }}
          </div>
          <p class="hint">{{ t('tools.macos_install_hint') }}</p>
        </div>
      </div>
      <p class="hint">{{ finiteText(updates.hint, '') || t('tools.updates_hint') }}</p>
      <div class="btns">
        <router-link class="btn primary" to="/maintenance">{{ t('nav.maintenance') }}</router-link>
        <button type="button" @click="loadUpdates(false)" :disabled="loading">{{ t('common.refresh') }}</button>
      </div>
      </template>
    </template>

    <!-- Network tools -->
    <template v-else-if="tab==='net'">
      <div class="two-col">
        <div class="card">
          <h2 class="section-title" style="margin-top:0">Ping</h2>
          <div class="form-row">
            <input v-model="pingHost" type="text" :placeholder="t('tools.ping_host_ph')"  :aria-label="t('tools.ping_host_ph')"/>
            <button class="primary" :disabled="loading" @click="doPing">Ping</button>
          </div>
          <pre class="mono net-out" v-if="pingOut" role="log" aria-live="polite">{{ finiteText(pingOut) }}</pre>
        </div>
        <div class="card">
          <h2 class="section-title" style="margin-top:0">DNS</h2>
          <div class="form-row">
            <input v-model="dnsName" type="text" placeholder="example.com" :aria-label="t('tools.dns_name')"/>
            <button class="primary" :disabled="loading" @click="doDns">Lookup</button>
            <button :disabled="loading" @click="doFlushDns">{{ t('tools.flush_dns') }}</button>
          </div>
          <pre class="mono net-out" v-if="dnsOut" role="log" aria-live="polite">{{ finiteText(dnsOut) }}</pre>
        </div>
      </div>
      <div class="card" style="margin-top:12px">
        <h2 class="section-title" style="margin-top:0">{{ t('tools.listen_ports') }}</h2>
        <div class="toolbar">
          <button @click="loadPorts" :disabled="loading">{{ t('common.refresh') }}</button>
          <router-link class="btn" to="/network">{{ t('nav.network') }}</router-link>
          <!-- Labeled and live: this was a bare number ("12") that said nothing
               about what it counted, and Refresh updated it silently for a
               screen reader. Reuses the Network summary's "{n} ports" key. -->
          <span class="meta" role="status">{{ t('network.sum_ports_n', { n: finiteN(ports.count, 0) }) }}</span>
        </div>
        <SkeletonLoader v-if="!tabLoaded.net" :cols="4" :rows="5" />
        <LoadFailure v-else-if="tabError.net" :detail="tabError.net" :retry="reload" :busy="loading" />
        <div v-else class="table-wrap">
        <table class="dense fit-m">
          <thead>
            <tr>
              <th>{{ t('tools.command') }}</th>
              <th class="col-hide-m">PID</th>
              <th class="col-hide-m">{{ t('tools.user') }}</th>
              <th>{{ t('tools.listen') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="(p,i) in asArray(ports.ports)" :key="i">
              <td class="mono">
                {{ finiteText(p.command) }}
                <div class="show-m sub">{{ finiteText(p.user) }} · {{ finiteN(p.pid) }}</div>
              </td>
              <td class="mono col-hide-m">{{ finiteN(p.pid) }}</td>
              <td class="col-hide-m">{{ finiteText(p.user) }}</td>
              <td class="mono">{{ finiteText(p.name) }}</td>
            </tr>
            <tr v-if="!asArray(ports.ports).length">
              <td colspan="4" class="empty-row">{{ t('tools.no_data') }}</td>
            </tr>
          </tbody>
        </table>
        </div>
      </div>
    </template>

    <!-- About -->
    <template v-else-if="tab==='about'">
      <LoadFailure v-if="tabError.about" :detail="tabError.about" :retry="reload" :busy="loading" />
      <SkeletonLoader v-else-if="!about" variant="tiles" :rows="2" :span="6" :tile-height="120" />
      <div class="two-col" v-else-if="about">
        <div class="card">
          <h2 class="section-title" style="margin-top:0">{{ finiteText(about.name) }} v{{ finiteText(about.version) }}</h2>
          <p class="hint" style="margin-top:0">{{ about.tagline_key ? t(about.tagline_key) : finiteText(about.tagline, '') }}</p>
          <div class="kv">
            <div class="k">{{ t('tools.host_ip') }}</div><div class="mono">{{ finiteText(about.host_ip) }}</div>
            <div class="k">{{ t('tools.platform') }}</div><div class="mono" style="font-size:11px">{{ finiteText(about.platform) }}</div>
            <div class="k">Python</div><div>{{ finiteText(about.python) }}</div>
            <div class="k">{{ t('tools.base_path') }}</div><div class="mono" style="font-size:11px;word-break:break-all">{{ finiteText(about.base) }}</div>
            <div class="k">GitHub</div>
            <div class="mono">
              <template v-if="about.github?.ok && about.github?.latest">
                {{ t('tools.github_latest', { v: finiteText(about.github.latest) }) }}
                <span v-if="about.github.update_available"> · {{ t('tools.github_newer', { v: finiteText(about.github.latest) }) }}</span>
              </template>
              <template v-else>{{ t('tools.check_github') }}</template>
            </div>
          </div>
        </div>
        <div class="card">
          <h2 class="section-title" style="margin-top:0">{{ t('tools.credits') }}</h2>
          <ul class="hint" style="margin:0;padding-left:18px;line-height:1.7">
            <li v-for="(x,i) in aboutCredits" :key="i">{{ finiteText(x) }}</li>
          </ul>
          <div class="btns" style="margin-top:12px;flex-wrap:wrap">
            <router-link
              v-for="l in asArray(about.links)"
              :key="l.href"
              class="btn"
              :to="l.href"
            >{{ l.label_key ? t(l.label_key) : finiteText(l.label) }}</router-link>
          </div>
        </div>
      </div>
    </template>

    <!-- Only the diagnostics branch above carries a data guard (`&& diag`), so
         this tail is what covers that tab before its first response — it was
         written as a generic `tab!=='home' && loading` but can never fire for any
         other tab. Spelled out here, with the failure case it was missing: when
         the load failed, neither branch matched and the tab rendered blank. -->
    <template v-else-if="tab === 'diag'">
      <div
        v-if="diagError"
        class="tile"
        style="border-left:3px solid var(--down)"
        role="alert"
      >
        <div class="row">
          <span class="name">{{ t('tools.diag_load_failed') }}</span>
          <button class="tiny" :disabled="loading" @click="reload">{{ t('common.retry') }}</button>
        </div>
        <div class="sub mono" style="margin-top:4px">{{ finiteText(diagError) }}</div>
      </div>
      <SkeletonLoader v-else variant="tiles" :rows="3" :span="4" :tile-height="120" />
    </template>
  </div>
</template>

<script setup>
import { computed, inject, onMounted, onUnmounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { asArray, finiteN, finiteText, fmtGb, withUnit } from '../lib/finite'
import {
  flushDns,
  generateDiagnostics,
  getDockerContainerSizes,
  getDockerDiskUsage,
  getListeningPorts,
  getScheduler,
  getSystemDiagnostics,
  getSystemProcesses,
  getSystemScheduler,
  getToolsAbout,
  getToolsAgents,
  getToolsCatalog,
  getToolsHardware,
  getToolsSyslog,
  getToolsUpdates,
  applyServerHubUpdate,
  applyBrewUpgrade,
  getMaintenanceLog,
  lookupDns,
  pingHost as pingHostApi,
  pruneDocker,
} from '../api/client'
import { injectI18n } from '../i18n'
import SkeletonLoader from '../components/SkeletonLoader.vue'
import LoadFailure from '../components/LoadFailure.vue'

const toast = inject('toast')
const route = useRoute()
const router = useRouter()
const { t } = injectI18n()

const tab = ref('home')
const loading = ref(false)
const catalog = ref({ tiles: [] })
const catalogError = ref('')
const diag = ref(null)
const diagError = ref('')
const diagMsg = ref('')
const processes = ref([])
const procQ = ref('')
// Which tabs have finished at least one load, keyed by tab id.
//
// Needed because every tab's template renders the moment it is selected, while
// its data is still in flight. The Docker tab therefore claimed "no data" (and
// could not even fall back to "engine off", since `df` starts as {} and
// `{}.engine_up === false` is false) and the Scheduler tab claimed "no timers".
// The existing `v-else-if="tab!=='home' && loading"` placeholder cannot cover
// this: it only fires when no tab template matched at all.
const tabLoaded = ref({})
// Failure text per tab, same keying as tabLoaded. Every loader here used to
// swallow its rejection into a toast, which left the tab showing whatever its
// no-data branch says — and for the hardware tab that branch is "Loading…", so a
// failed read claimed the page was still loading indefinitely.
const tabError = ref({})

/** Record a tab's load failure so its own panel can explain and offer a retry. */
function noteTabError(id, e) {
  tabError.value = { ...tabError.value, [id]: finiteText(e.message || String(e), '') }
  toast('❌ ' + finiteText(e.message))
}

/**
 * Drop a tab's latched failure after a load that succeeded.
 *
 * reload() clears the banner up front, but the syslog and ports loaders are
 * also wired straight to their toolbar controls (level/range selects, their
 * own Refresh), which stay clickable above the banner — without this a
 * direct retry that worked left the failure banner claiming otherwise.
 */
function clearTabError(id) {
  if (tabError.value[id]) tabError.value = { ...tabError.value, [id]: '' }
}
const df = ref({})
const sizes = ref([])
const timers = ref([])
const agents = ref({ agents: [] })
const syslog = ref({ lines: [] })
const syslogLevel = ref('error')
const syslogMinutes = ref(60)
const hw = ref(null)
const updates = ref({})
const about = ref(null)
const ports = ref({ ports: [] })
const pingHost = ref('')
const pingOut = ref('')
const dnsName = ref('apple.com')
const dnsOut = ref('')
const pruneMsg = ref('')

const tabs = [
  { id: 'home', labelKey: 'tools.tab_home' },
  { id: 'diag', labelKey: 'tools.tab_diag' },
  { id: 'syslog', labelKey: 'tools.tab_syslog' },
  { id: 'proc', labelKey: 'tools.tab_proc' },
  { id: 'hw', labelKey: 'tools.tab_hw' },
  { id: 'docker', labelKey: 'tools.tab_docker' },
  { id: 'sched', labelKey: 'tools.tab_sched' },
  { id: 'updates', labelKey: 'tools.tab_updates' },
  { id: 'net', labelKey: 'tools.tab_net' },
  { id: 'about', labelKey: 'tools.tab_about' },
]

const filteredProc = computed(() => {
  const q = procQ.value.trim().toLowerCase()
  if (!q) return processes.value
  return processes.value.filter(p =>
    (p.command || '').toLowerCase().includes(q)
    || (p.user || '').toLowerCase().includes(q)
    || String(p.pid).includes(q)
  )
})

const aboutCredits = computed(() => {
  const a = about.value || {}
  if (a.credit_keys?.length) return a.credit_keys.map((k) => t(k))
  return asArray(a.credits)
})

function tileLabel(tile) {
  if (tile?.label_key) return t(tile.label_key)
  return finiteText(tile?.label, '') || finiteText(tile?.id, '')
}
function tileDesc(tile) {
  if (tile?.desc_key) return t(tile.desc_key)
  return finiteText(tile?.desc, '')
}

function formatCal(c) {
  if (!c) return '—'
  if (typeof c !== 'object') return String(c)
  try {
    return JSON.stringify(c)
  } catch {
    return '—'
  }
}

function fmtPct(v) {
  const n = Number(v)
  return Number.isFinite(n) ? n.toFixed(1) : '—'
}

function switchTab(id) {
  tab.value = id
  reload()
}

function openTile(tile) {
  if (tile.href) {
    router.push(tile.href)
    return
  }
  if (tile.action === 'download_diag') {
    window.location.href = '/api/diagnostics/download'
    return
  }
  if (tile.tab) {
    tab.value = tile.tab
    reload()
  }
}

async function loadCatalog() {
  const generation = reloadGeneration
  try {
    const next = await getToolsCatalog()
    if (generation !== reloadGeneration || !pageAlive) return
    catalog.value = next
    catalogError.value = ''
  } catch (e) {
    if (generation !== reloadGeneration || !pageAlive) return
    catalogError.value = finiteText(e.message || String(e), '')
    toast('❌ ' + finiteText(e.message))
  }
}

async function loadDiag() {
  const generation = reloadGeneration
  try {
    const next = await getSystemDiagnostics()
    if (generation !== reloadGeneration || !pageAlive) return
    diag.value = next
    diagError.value = ''
  } catch (e) {
    // Latched, not just toasted. The toast is gone in four seconds, and the
    // diagnostics tab renders nothing at all without `diag`, so a failed load
    // used to leave a permanently blank page with no explanation and no way back.
    if (generation !== reloadGeneration || !pageAlive) return
    diagError.value = finiteText(e.message || String(e), '')
    toast('❌ ' + finiteText(e.message))
  }
}

async function genDiag() {
  const generation = reloadGeneration
  loading.value = true
  try {
    const j = await generateDiagnostics()
    if (generation !== reloadGeneration || !pageAlive) return
    if (j.saved_path) {
      diagMsg.value = j.saved_path
      toast('✅ ' + t('tools.diag_done'))
    } else {
      diagMsg.value = t('tools.diag_save_failed', { error: finiteText(j.save_error, '') || t('common.failed') })
      toast('❌ ' + finiteText(diagMsg.value))
    }
  } catch (e) {
    if (generation !== reloadGeneration || !pageAlive) return
    toast('❌ ' + finiteText(e.message))
  }
  finally {
    // reload() ++reloadGeneration; a generation match would leave Gen stuck
    // after a successful write if Refresh ran in parallel.
    if (pageAlive) loading.value = false
  }
}

async function loadSyslog() {
  const generation = reloadGeneration
  loading.value = true
  try {
    const next = await getToolsSyslog(syslogMinutes.value, syslogLevel.value, 100)
    if (generation !== reloadGeneration || !pageAlive) return
    syslog.value = next
    clearTabError('syslog')
  } catch (e) {
    if (generation !== reloadGeneration || !pageAlive) return
    noteTabError('syslog', e)
  }
  finally { if (pageAlive) loading.value = false }
}

async function loadProc() {
  const generation = reloadGeneration
  try {
    const j = await getSystemProcesses(40)
    if (generation !== reloadGeneration || !pageAlive) return
    processes.value = Array.isArray(j.processes) ? j.processes : []
  } catch (e) {
    if (generation !== reloadGeneration || !pageAlive) return
    noteTabError('proc', e)
  }
}

async function loadDocker() {
  const generation = reloadGeneration
  try {
    const [a, b] = await Promise.all([
      getDockerDiskUsage(),
      getDockerContainerSizes(),
    ])
    if (generation !== reloadGeneration || !pageAlive) return
    df.value = a
    sizes.value = asArray(b.containers)
  } catch (e) {
    if (generation !== reloadGeneration || !pageAlive) return
    noteTabError('docker', e)
  }
}

async function doPrune(what) {
  const labels = {
    dangling: t('tools.prune_dangling'),
    build: t('tools.prune_build'),
    volumes: t('tools.prune_volumes'),
    all_unused: t('tools.prune_all'),
  }
  if (!confirm(t('tools.prune_confirm', { what: finiteText(labels[what], '') || finiteText(what) }))) return
  const generation = reloadGeneration
  loading.value = true
  pruneMsg.value = ''
  try {
    const j = await pruneDocker(what)
    if (generation !== reloadGeneration || !pageAlive) return
    pruneMsg.value = j.ok ? (finiteText(j.message, '') || '') : softText(j)
    toast(j.ok ? '✅ ' + (finiteText(j.message, '') || t('common.ok')) : '❌ ' + softText(j))
    if (j.df) df.value = j.df
    await loadDocker()
  } catch (e) {
    if (generation !== reloadGeneration || !pageAlive) return
    toast('❌ ' + finiteText(e.message))
  }
  finally { if (pageAlive) loading.value = false }
}

async function loadSched() {
  const generation = reloadGeneration
  try {
    let j
    try {
      j = await getScheduler()
    } catch (e) {
      if (e.status !== 404) throw e
      j = await getSystemScheduler()
    }
    if (generation !== reloadGeneration || !pageAlive) return
    timers.value = asArray(j.timers)
    const nextAgents = await getToolsAgents()
    if (generation !== reloadGeneration || !pageAlive) return
    agents.value = nextAgents
  } catch (e) {
    if (generation !== reloadGeneration || !pageAlive) return
    noteTabError('sched', e)
  }
}

async function loadHw() {
  const generation = reloadGeneration
  loading.value = true
  try {
    const next = await getToolsHardware()
    if (generation !== reloadGeneration || !pageAlive) return
    hw.value = next
  } catch (e) {
    if (generation !== reloadGeneration || !pageAlive) return
    noteTabError('hw', e)
  }
  finally { if (pageAlive) loading.value = false }
}

async function loadUpdates(force = false) {
  const generation = reloadGeneration
  loading.value = true
  try {
    const next = await getToolsUpdates(force)
    if (generation !== reloadGeneration || !pageAlive) return
    updates.value = next
  } catch (e) {
    if (generation !== reloadGeneration || !pageAlive) return
    noteTabError('updates', e)
  }
  finally { if (pageAlive) loading.value = false }
}

async function checkGithub() {
  await loadUpdates(true)
}

const updateJobId = ref('')
const updateJobLog = ref('')
let updateJobTimer = null
let updateJobGen = 0

function stopUpdateJob() {
  updateJobGen += 1
  if (updateJobTimer) {
    clearTimeout(updateJobTimer)
    updateJobTimer = null
  }
}

function watchUpdateJob(id) {
  stopUpdateJob()
  const job = finiteText(id, '')
  if (!job) return
  updateJobId.value = job
  updateJobLog.value = t('common.loading')
  const generation = updateJobGen
  const poll = async () => {
    updateJobTimer = null
    if (typeof document !== 'undefined' && document.hidden) {
      if (generation === updateJobGen && pageAlive) updateJobTimer = setTimeout(poll, 1500)
      return
    }
    try {
      const j = await getMaintenanceLog(job)
      if (generation !== updateJobGen || !pageAlive) return
      updateJobLog.value = finiteText(j.log, '') + (j.running ? '\n⏳…' : '')
      if (!j.running) {
        stopUpdateJob()
        updateJobId.value = ''
        toast(j.rc === 0 ? '✅ ' + t('tools.apply_started') : '❌ rc ' + finiteN(j.rc))
        void loadUpdates(true)
        return
      }
    } catch (e) {
      if (generation !== updateJobGen || !pageAlive) return
      updateJobLog.value = `${updateJobLog.value || ''}\n⚠ ${finiteText(e.message || e)}`.trim()
    }
    if (generation === updateJobGen && pageAlive) updateJobTimer = setTimeout(poll, 1500)
  }
  void poll()
}

async function applyGithub(stash) {
  const latest = finiteText(updates.value?.github?.latest, '')
  const key = stash ? 'tools.confirm_stash_apply' : 'tools.confirm_apply'
  if (!confirm(t(key, { v: latest || '—' }))) return
  loading.value = true
  try {
    const result = await applyServerHubUpdate(!!stash)
    toast('🚀 ' + t('tools.apply_started'))
    watchUpdateJob(result?.job_id)
  } catch (e) {
    toast('❌ ' + finiteText(e.message))
  } finally {
    loading.value = false
  }
}

async function applyBrew() {
  if (!confirm(t('tools.confirm_brew_upgrade'))) return
  loading.value = true
  try {
    const result = await applyBrewUpgrade()
    toast('🚀 ' + t('tools.apply_started'))
    watchUpdateJob(result?.job_id)
  } catch (e) {
    toast('❌ ' + finiteText(e.message))
  } finally {
    loading.value = false
  }
}

async function loadAbout() {
  const generation = reloadGeneration
  try {
    const next = await getToolsAbout()
    if (generation !== reloadGeneration || !pageAlive) return
    about.value = next
  } catch (e) {
    if (generation !== reloadGeneration || !pageAlive) return
    noteTabError('about', e)
  }
}

async function loadPorts() {
  const generation = reloadGeneration
  try {
    const next = await getListeningPorts(50)
    if (generation !== reloadGeneration || !pageAlive) return
    ports.value = next
    clearTabError('net')
  } catch (e) {
    if (generation !== reloadGeneration || !pageAlive) return
    noteTabError('net', e)
  }
}

function softText(j, fallbackKey = 'common.fail') {
  if (j?.code) {
    const key = `err.${j.code}`
    const translated = t(key, j.params || {})
    if (translated !== key) return translated
  }
  return finiteText(j?.message, '') || t(fallbackKey)
}

async function doPing() {
  const generation = reloadGeneration
  loading.value = true
  pingOut.value = ''
  try {
    const j = await pingHostApi(pingHost.value, 3)
    if (generation !== reloadGeneration || !pageAlive) return
    pingOut.value = finiteText(j.output, '') || (j.ok ? '' : softText(j))
    toast(j.ok ? '✅ ' + t('tools.ping_ok') : '❌ ' + (j.code ? softText(j) : t('tools.ping_fail')))
  } catch (e) {
    if (generation !== reloadGeneration || !pageAlive) return
    toast('❌ ' + finiteText(e.message))
  }
  finally { if (pageAlive) loading.value = false }
}

async function doDns() {
  const generation = reloadGeneration
  loading.value = true
  dnsOut.value = ''
  try {
    const j = await lookupDns(dnsName.value)
    if (generation !== reloadGeneration || !pageAlive) return
    if (j.ok) {
      dnsOut.value = asArray(j.results).map(x => `${finiteText(x.family, '')} ${finiteText(x.ip, '')}`).filter(s => s.trim()).join('\n')
        + (finiteText(j.dig, '') ? `\n\ndig:\n${finiteText(j.dig)}` : '')
    } else {
      dnsOut.value = softText(j)
    }
  } catch (e) {
    if (generation !== reloadGeneration || !pageAlive) return
    toast('❌ ' + finiteText(e.message))
  }
  finally { if (pageAlive) loading.value = false }
}

async function doFlushDns() {
  const generation = reloadGeneration
  loading.value = true
  try {
    const j = await flushDns()
    if (generation !== reloadGeneration || !pageAlive) return
    toast(j.ok ? '✅ ' + t('tools.flush_ok') : '❌ ' + t('tools.flush_partial'))
    dnsOut.value = asArray(j.detail).map(n => finiteText(n, '')).filter(Boolean).join('\n')
  } catch (e) {
    if (generation !== reloadGeneration || !pageAlive) return
    toast('❌ ' + finiteText(e.message))
  }
  finally { if (pageAlive) loading.value = false }
}

// Owns `loading` for every tab. Only loadSyslog/loadHw/loadUpdates set it
// themselves, so on the other seven tabs the Refresh button's :disabled="loading"
// never engaged and repeated clicks issued concurrent duplicate requests. Setting
// it here covers all of them from one place; the three that also set it are
// idempotent about doing so.
// Deliberately no `if (loading) return` guard: switchTab() and openTile() also
// route through here, and dropping those calls would leave a newly selected tab
// empty whenever the previous tab was still loading. Preventing the duplicate
// Refresh click is the button's :disabled="loading", which now works on every tab
// because this function is what sets the flag.
function sizeGb(value) {
  const n = Number(value)
  return Number.isFinite(n) ? `${n} GB` : '—'
}

let pageAlive = true
let reloadGeneration = 0
async function reload() {
  const wanted = tab.value
  const generation = ++reloadGeneration
  loading.value = true
  // Clear this tab's previous failure up front: the loaders only ever set it, so
  // without this a banner would survive the reload that fixed it.
  if (tabError.value[wanted]) {
    tabError.value = { ...tabError.value, [wanted]: '' }
  }
  try {
    if (wanted === 'home') await loadCatalog()
    else if (wanted === 'diag') await loadDiag()
    else if (wanted === 'syslog') await loadSyslog()
    else if (wanted === 'proc') await loadProc()
    else if (wanted === 'docker') await loadDocker()
    else if (wanted === 'sched') await loadSched()
    else if (wanted === 'hw') await loadHw()
    else if (wanted === 'updates') await loadUpdates()
    else if (wanted === 'net') await loadPorts()
    else if (wanted === 'about') await loadAbout()
  } finally {
    if (generation !== reloadGeneration || !pageAlive) return
    loading.value = false
    // Replace rather than mutate so the template re-renders: `tabLoaded` is a
    // plain object behind one ref, not a reactive map.
    tabLoaded.value = { ...tabLoaded.value, [wanted]: true }
  }
}

onMounted(() => {
  pageAlive = true
  const q = route.query.tab
  if (typeof q === 'string' && tabs.some((tb) => tb.id === q)) tab.value = q
  void reload()
})

onUnmounted(() => {
  pageAlive = false
  reloadGeneration += 1
  stopUpdateJob()
})
</script>

<style scoped>
.tools-page {
  color: var(--txt);
  min-width: 0;
  overflow-x: hidden;
}

.hint-line,
.hint {
  color: var(--sub);
  font-size: 12px;
  line-height: 1.5;
  margin: 0 0 12px;
  word-break: break-word;
}

/* Home tiles */
.tool-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(min(100%, 180px), 1fr));
  gap: 10px;
  align-items: stretch;
  max-width: 100%;
}

.tool-tile {
  display: flex;
  flex-direction: column;
  align-items: stretch;
  text-align: left;
  padding: 12px 12px 14px;
  border-radius: var(--radius-lg);
  border: 1px solid var(--line);
  background: var(--card);
  color: var(--txt);
  cursor: pointer;
  min-height: 108px;
  min-width: 0;
  max-width: 100%;
  height: 100%;
  box-sizing: border-box;
  overflow: hidden;
  transition: border-color .15s, transform .1s;
  /* reset global button look */
  font: inherit;
  font-weight: 400;
}

.tool-tile:hover {
  border-color: var(--accent);
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(0,0,0,.06);
}

.tile-label {
  font-weight: 700;
  font-size: 14px;
  line-height: 1.35;
  margin-bottom: 4px;
  color: var(--txt);
  white-space: normal;
  overflow-wrap: anywhere;
  word-break: break-word;
  hyphens: auto;
}

.tile-desc {
  font-size: 12px;
  line-height: 1.45;
  color: var(--sub);
  margin-top: 6px;
  white-space: normal;
  overflow-wrap: anywhere;
  word-break: break-word;
  display: -webkit-box;
  -webkit-box-orient: vertical;
  -webkit-line-clamp: 3;
  line-clamp: 3;
  overflow: hidden;
  flex: 1 1 auto;
}

.log-box {
  background: var(--card);
  border: 1px solid var(--line);
  border-radius: 8px;
  padding: 10px 12px;
  max-height: 480px;
  overflow: auto;
  font-size: 11px;
  line-height: 1.45;
  color: var(--txt);
  word-break: break-word;
}

.hw-pre {
  white-space: pre-wrap;
  word-break: break-word;
  font-size: 11px;
  max-height: 240px;
  overflow: auto;
  margin: 0;
  line-height: 1.4;
  color: var(--txt);
}

.update-list {
  margin: 0;
  padding-left: 18px;
  font-size: 12px;
  max-height: 280px;
  overflow: auto;
  line-height: 1.5;
  color: var(--txt);
  word-break: break-word;
}

.form-row {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
  align-items: center;
  margin-bottom: 10px;
}

.form-row input {
  flex: 1;
  min-width: 140px;
  max-width: 100%;
  box-sizing: border-box;
}

.net-out {
  font-size: 11px;
  white-space: pre-wrap;
  word-break: break-word;
  max-height: 220px;
  overflow: auto;
  margin: 0;
  background: var(--bg);
  color: var(--txt);
  border: 1px solid var(--line);
  padding: 8px;
  border-radius: 6px;
}

button.warn {
  border-color: var(--warn);
}

@media (max-width: 520px) {
  .tool-grid {
    grid-template-columns: 1fr 1fr;
  }
}
@media (max-width: 380px) {
  .tool-grid { grid-template-columns: 1fr; }
}
</style>
