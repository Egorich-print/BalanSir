<script>
  import { onMount, onDestroy } from 'svelte';
  import { api, fmtBytes, fmtRate } from '../lib/api.js';

  export let health;
  export let snapshot;
  export let overall;
  export let healthError;
  export let sseState;

  let system = null;
  let refreshTimer = null;
  let error = null;

  async function refresh() {
    try {
      const data = await api.system();
      system = data;
      error = null;
    } catch (e) {
      error = e.message;
    }
  }

  onMount(() => {
    refresh();
    const timer = setInterval(refresh, 2000);
    return () => clearInterval(refreshTimer);
  });

  function fmtBytes(n) {
    if (n == null) return '—';
    const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
    let i = 0;
    let v = Number(n);
    while (v >= 1024 && i < units.length - 1) {
      v /= 1024;
      i += 1;
    }
    return `${v.toFixed(v < 10 && i > 0 ? 1 : 0)} ${units[i]}`;
  }

  function fmtRate(bytesPerSec) {
    if (bytesPerSec == null) return '—';
    return `${fmtBytes(bytesPerSec)}/s`;
  }

  function usageBar(used, total) {
    if (!total) return 0;
    return Math.min(100, Math.round((used / total) * 100));
  }

  function memPct() {
    if (!system?.memory) return 0;
    return usageBar(system.memory.used_mb, system.memory.total_mb);
  }

  function fsPct(fs) {
    return usageBar(fs.used_mb, fs.total_mb);
  }

  function sparklineClass(rate) {
    if (!rate || rate === 0) return 'zero';
    if (rate < 1024) return 'low';
    if (rate < 1024 * 1024) return 'med';
    return 'high';
  }

  function fsClass(fs) {
    const pct = fsPct(fs);
    if (pct >= 90) return 'critical';
    if (pct >= 75) return 'warn';
    return '';
  }
</script>

<div class="system-view">
  {#if error}
    <div class="banner banner-error">
      ⚠ Failed to load system info: {error}
      <button on:click={refresh}>Retry</button>
    </div>
  {/if}

  <div class="grid">
    <!-- CPU Panel -->
    <section class="panel cpu">
      <header>
        <h2>CPU</h2>
        <span class="subtitle">
          {system?.cpu?.load1?.toFixed(2)} / {system?.cpu?.load5?.toFixed(2)} / {system?.cpu?.load15?.toFixed(2)}
        </span>
      </header>
      <div class="cpu-usage">
        <div class="usage-bar">
          <div class="usage-fill" style="width: {system?.cpu?.usage_percent?.toFixed(1) || 0}%"></div>
        </div>
        <div class="usage-label">{system?.cpu?.usage_percent?.toFixed(1) || 0}%</div>
      </div>
      <div class="cpu-load">
        <div class="load-item"><span>1m</span><strong>{system?.cpu?.load1?.toFixed(2) || '—'}</strong></div>
        <div class="load-item"><span>5m</span><strong>{system?.cpu?.load5?.toFixed(2) || '—'}</strong></div>
        <div class="load-item"><span>15m</span><strong>{system?.cpu?.load15?.toFixed(2) || '—'}</strong></div>
      </div>
    </section>

    <!-- Memory Panel -->
    <section class="panel memory">
      <header>
        <h2>Memory</h2>
        <span class="subtitle">
          {fmtBytes(system?.memory?.used_mb)} / {fmtBytes(system?.memory?.total_mb)}
        </span>
      </header>
      <div class="usage-bar">
        <div class="usage-fill" style="width: {memPct()}%"></div>
      </div>
      <div class="usage-label">
        {fmtBytes(system?.memory?.used_mb)} used / {fmtBytes(system?.memory?.total_mb)} total ({memPct()}%)
      </div>
    </section>

    <!-- Load Average -->
    <section class="panel load">
      <header><h2>Load Average</h2></header>
      <div class="load-bars">
        <div class="load-bar-item">
          <span>1m</span>
          <div class="load-bar"><div class="load-fill" style="width: {Math.min(100, (system?.cpu?.load1 || 0) * 10)}%"></div></div>
          <strong>{system?.cpu?.load1?.toFixed(2) || '—'}</strong>
        </div>
        <div class="load-bar-item">
          <span>5m</span>
          <div class="load-bar"><div class="load-fill" style="width: {Math.min(100, (system?.cpu?.load5 || 0) * 10)}%"></div></div>
          <strong>{system?.cpu?.load5?.toFixed(2) || '—'}</strong>
        </div>
        <div class="load-bar-item">
          <span>15m</span>
          <div class="load-bar"><div class="load-fill" style="width: {Math.min(100, (system?.cpu?.load15 || 0) * 10)}%"></div></div>
          <strong>{system?.cpu?.load15?.toFixed(2) || '—'}</strong>
        </div>
      </div>
    </section>

    <!-- Uptime -->
    <section class="panel uptime">
      <header><h2>Uptime</h2></header>
      <div class="uptime-value">
        {formatUptime(system?.uptime_secs)}
      </div>
    </section>

    <!-- Filesystems -->
    <section class="panel filesystems wide">
      <header><h2>Filesystems</h2></header>
      {#if system?.filesystems?.length}
        <table class="fs-table">
          <thead>
            <tr>
              <th>Mount</th>
              <th>Type</th>
              <th class="right">Total</th>
              <th class="right">Used</th>
              <th class="right">Avail</th>
              <th>Usage</th>
            </thead>
            <tbody>
              {#each system.filesystems as fs}
                <tr class={fsClass(fs)}>
                  <td>{fs.mount_point}</td>
                  <td>{fs.fstype}</td>
                  <td class="right">{fmtBytes(fs.total_mb)}</td>
                  <td class="right">{fmtBytes(fs.used_mb)}</td>
                  <td class="right">{fmtBytes(fs.available_mb)}</td>
                  <td>
                    <div class="mini-bar">
                      <div class="mini-fill {fsClass(fs)}" style="width: {fsPct(fs)}%"></div>
                    </div>
                    <span>{fsPct(fs)}%</span>
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        {:else}
          <p class="empty">No filesystem data available</p>
      {/if}
    </section>

    <!-- Network Interfaces -->
    <section class="panel network wide">
      <header><h2>Network Interfaces</h2></header>
      {#if system?.interface_rates?.length}
        <table class="iface-table">
          <thead>
            <tr>
              <th>Interface</th>
              <th>RX</th>
              <th>TX</th>
            </thead>
            <tbody>
              {#each system.interface_rates as rate}
                <tr>
                  <td>{rate.interface}</td>
                  <td class="rate rx">{fmtRate(rate.rx_bps)}</td>
                  <td class="rate tx">{fmtRate(rate.tx_bps)}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        {:else}
          <p class="empty">No interface rate data</p>
      {/if}
    </section>

    <!-- Uptime -->
    <section class="panel uptime small">
      <header><h2>Uptime</h2></header>
      <div class="uptime-value">{formatUptime(system?.uptime_secs)}</div>
    </section>
  </div>

  <script>
    function fmtBytes(n) {
      if (n == null) return '—';
      const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
      let i = 0;
      let v = Number(n);
      while (v >= 1024 && i < units.length - 1) {
        v /= 1024;
        i += 1;
      }
      return `${v.toFixed(v < 10 && i > 0 ? 1 : 0)} ${units[i]}`;
    }

    function fmtRate(bytesPerSec) {
      if (bytesPerSec == null) return '—';
      return `${fmtBytes(bytesPerSec)}/s`;
    }

    function formatUptime(secs) {
      if (!secs) return '—';
      const d = Math.floor(secs / 86400);
      const h = Math.floor((secs % 86400) / 3600);
      const m = Math.floor((secs % 3600) / 60);
      const s = secs % 60;
      const parts = [];
      if (d) parts.push(`${d}d`);
      if (h) parts.push(`${h}h`);
      if (m) parts.push(`${m}m`);
      parts.push(`${s}s`);
      return parts.join(' ');
    }

    function memPct() {
      if (!system?.memory) return 0;
      if (!system.memory.total_mb) return 0;
      return Math.round((system.memory.used_mb / system.memory.total_mb) * 100);
    }

    function fsPct(fs) {
      if (!fs.total_mb) return 0;
      return Math.round((fs.used_mb / fs.total_mb) * 100);
    }

    function fsClass(fs) {
      const pct = fsPct(fs);
      if (pct >= 90) return 'critical';
      if (pct >= 75) return 'warn';
      return '';
    }
  </script>
</script>

<style>
  .system-view {
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  .grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 16px;
  }

  .panel {
    background: #141c2e;
    border: 1px solid #1f2a44;
    border-radius: 10px;
    padding: 16px;
  }

  .panel.wide {
    grid-column: 1 / -1;
  }

  .panel.small {
    max-width: 200px;
  }

  .panel header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 12px;
    padding-bottom: 8px;
    border-bottom: 1px solid #1f2a44;
  }

  .panel h2 {
    margin: 0;
    font-size: 1rem;
    color: #4ecdc4;
  }

  .subtitle {
    color: #7a8aa5;
    font-size: 0.85rem;
  }

  .usage-bar {
    height: 8px;
    background: #1f2a44;
    border-radius: 4px;
    overflow: hidden;
    margin: 8px 0;
  }

  .usage-fill {
    height: 100%;
    background: linear-gradient(90deg, #4ecdc4, #4ecdc4);
    border-radius: 4px;
    transition: width 0.3s ease;
  }

  .usage-label {
    font-size: 0.85rem;
    color: #7a8aa5;
  }

  .cpu-load {
    display: flex;
    gap: 16px;
    margin-top: 8px;
  }

  .load-item {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .load-item span {
    font-size: 0.75rem;
    color: #7a8aa5;
  }

  .load-item strong {
    color: #4ecdc4;
  }

  .load-bars {
    display: flex;
    flex-direction: column;
    gap: 10px;
  }

  .load-bar-item {
    display: flex;
    align-items: center;
    gap: 10px;
  }

  .load-bar-item span {
    width: 30px;
    font-size: 0.85rem;
    color: #7a8aa5;
  }

  .load-bar {
    flex: 1;
    height: 8px;
    background: #1f2a44;
    border-radius: 4px;
    overflow: hidden;
  }

  .load-fill {
    height: 100%;
    background: linear-gradient(90deg, #4ecdc4, #4ecdc4);
    border-radius: 4px;
    transition: width 0.3s ease;
  }

  .uptime-value {
    font-size: 1.5rem;
    font-weight: 600;
    color: #4ecdc4;
    font-variant-numeric: tabular-nums;
  }

  .fs-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.9rem;
  }

  .fs-table th,
  .fs-table td {
    padding: 8px 12px;
    text-align: left;
    border-bottom: 1px solid #1f2a44;
  }

  .fs-table th {
    color: #7a8aa5;
    font-weight: 600;
    font-size: 0.8rem;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .fs-table td {
    color: #e8ecf4;
  }

  .fs-table .right {
    text-align: right;
  }

  .fs-table tr.critical td {
    color: #ff6b6b;
  }

  .fs-table tr.warn td {
    color: #ffb86b;
  }

  .mini-bar {
    display: flex;
    align-items: center;
    gap: 8px;
    height: 100%;
  }

  .mini-fill {
    height: 6px;
    border-radius: 3px;
    transition: width 0.3s ease;
    flex: 1;
  }

  .mini-fill.critical {
    background: #ff6b6b;
  }

  .mini-fill.warn {
    background: #ffb86b;
  }

  .mini-fill {
    background: #4ecdc4;
  }

  .iface-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.9rem;
  }

  .iface-table th,
  .iface-table td {
    padding: 8px 12px;
    text-align: left;
    border-bottom: 1px solid #1f2a44;
  }

  .iface-table th {
    color: #7a8aa5;
    font-weight: 600;
    font-size: 0.8rem;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .rate {
    font-variant-numeric: tabular-nums;
  }

  .rate.rx {
    color: #4ecdc4;
  }

  .rate.tx {
    color: #ff6b6b;
  }

  .empty {
    color: #7a8aa5;
    font-size: 0.9rem;
    padding: 12px;
    text-align: center;
  }

  .uptime-value {
    font-size: 1.5rem;
    font-weight: 600;
    color: #4ecdc4;
    font-variant-numeric: tabular-nums;
  }

  .empty {
    color: #7a8aa5;
    font-size: 0.9rem;
    padding: 12px;
    text-align: center;
  }
</style>
</script>