<script>
  import { qosStatus, tailscaleStatus, networkStatus } from '../lib/status.js';
  import StatusBadge from '../components/StatusBadge.svelte';
  import { fmtBytes } from '../lib/api.js';

  export let health;
  export let snapshot;
  export let overall;
  export let healthError;

  $: qos = qosStatus(snapshot);
  $: net = networkStatus(snapshot);
  $: ts = tailscaleStatus(snapshot);

  $: totalRx = snapshot ? snapshot.interfaces.reduce((a, i) => a + i.rx_bytes, 0) : 0;
  $: totalTx = snapshot ? snapshot.interfaces.reduce((a, i) => a + i.tx_bytes, 0) : 0;
  $: upCount = snapshot ? snapshot.interfaces.filter((i) => i.link_up).length : 0;

  function uptime(secs) {
    if (!secs) return '—';
    const d = Math.floor(secs / 86400);
    const h = Math.floor((secs % 86400) / 3600);
    const m = Math.floor((secs % 3600) / 60);
    return [d ? `${d}d` : '', h ? `${h}h` : '', `${m}m`].filter(Boolean).join(' ') || '0m';
  }
</script>

<div class="dashboard">
  <section class="overview">
    <h2>What is happening with my network?</h2>
    <div class="reasons">
      {#if overall && overall.parts}
        {#each overall.parts as part}
          <div class="reason-row">
            <span class="reason-label">{part.title}</span>
            <StatusBadge status={part.status} title={part.title} />
            <ul>
              {#each part.reasons as r}
                <li>{r}</li>
              {/each}
            </ul>
          </div>
        {/each}
      {:else}
        <p>Loading operational state…</p>
      {/if}
    </div>
    {#if healthError}
      <p class="err">API error: {healthError}</p>
    {/if}
  </section>

  <section class="grid">
    <div class="card">
      <h3>Policy Engine</h3>
      <StatusBadge status={health && health.status === 'ok' ? 'healthy' : 'blocked'}
        title={health && health.status === 'ok' ? 'Healthy' : 'Unavailable'} />
      <p class="meta">Daemon {health && health.status === 'ok' ? 'responding' : 'not responding'}</p>
      <p class="meta">Uptime {uptime(health && health.uptime_seconds)}</p>
    </div>

    <div class="card">
      <h3>QoS / Shaping</h3>
      <StatusBadge status={qos.status} title={qos.title} />
      <ul class="reasons">
        {#each qos.reasons as r}
          <li>{r}</li>
        {/each}
      </ul>
      <p class="meta">
        {snapshot && snapshot.qos.desired.length} configured
        · {snapshot && snapshot.qos.applied.filter((a) => a.our_identity).length} applied
        {#if snapshot && snapshot.qos.capabilities && snapshot.qos.capabilities.cake}· CAKE{/if}
        {#if snapshot && snapshot.qos.capabilities && snapshot.qos.capabilities.fq_codel}· fq_codel{/if}
      </p>
    </div>

    <div class="card">
      <h3>Network</h3>
      <StatusBadge status={net.status} title={net.title} />
      <ul class="reasons">
        {#each net.reasons as r}
          <li>{r}</li>
        {/each}
      </ul>
      <p class="meta">{upCount} link(s) up · RX {fmtBytes(totalRx)} · TX {fmtBytes(totalTx)}</p>
    </div>

    <div class="card">
      <h3>Tailscale</h3>
      <StatusBadge status={ts.status} title={ts.title} />
      <ul class="reasons">
        {#each ts.reasons as r}
          <li>{r}</li>
        {/each}
      </ul>
      {#if snapshot && snapshot.tailscale.status && snapshot.tailscale.status.tailscale_ip}
        <p class="meta">Node {snapshot.tailscale.status.tailscale_ip}</p>
      {/if}
    </div>
  </section>
</div>

<style>
  .dashboard { display: flex; flex-direction: column; gap: 18px; }
  .overview { background: #16213e; border: 1px solid #0f3460; border-radius: 12px; padding: 18px; }
  .overview h2 { margin: 0 0 12px; color: #4ecdc4; font-size: 1.05rem; }
  .reasons { list-style: none; margin: 0; padding: 0; }
  .reason-row { padding: 8px 0; border-bottom: 1px solid #0f3460; display: flex; gap: 10px; align-items: baseline; flex-wrap: wrap; }
  .reason-row:last-child { border-bottom: 0; }
  .reason-label { font-weight: 700; min-width: 150px; }
  .reason-row ul { margin: 0 0 0 8px; padding-left: 16px; color: #a8b6cc; font-size: 0.88rem; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 14px; }
  .card { background: #16213e; border: 1px solid #0f3460; border-radius: 12px; padding: 16px; }
  .card h3 { margin: 0 0 10px; color: #4ecdc4; font-size: 0.95rem; }
  .meta { color: #7a8aa5; font-size: 0.82rem; margin: 8px 0 0; }
  .err { color: #ff6b6b; font-size: 0.85rem; }
  .reasons li { margin: 2px 0; }
</style>
