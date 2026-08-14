<script>
  import { api, fmtBytes } from '../lib/api.js';
  import { qosStatus } from '../lib/status.js';
  import StatusBadge from '../components/StatusBadge.svelte';

  export let snapshot;
  export let healthError;

  let interfaceName = '';
  let kind = 'fq_codel';
  let direction = 'egress';
  let bandwidthMbps = '';
  let latencyMs = '';
  let busy = false;
  let notice = '';

  $: status = qosStatus(snapshot);
  $: qos = snapshot ? snapshot.qos : null;

  function configuredBandwidth(iface) {
    if (!qos || !qos.desired) return null;
    const cfg = qos.desired.find((c) => c.interface === iface);
    return cfg ? cfg.bandwidth_bps : null;
  }

  function fmtBits(bps) {
    if (!bps) return 'unlimited';
    if (bps >= 1e9) return `${(bps / 1e9).toFixed(1)} Gbit/s`;
    return `${(bps / 1e6).toFixed(0)} Mbit/s`;
  }

  // Actionable saturation hint: when the queue is persistently backed up and
  // dropping, tell the operator what is configured vs. demanded, and the
  // implied queue delay — instead of a raw errno.
  function saturationHint(a) {
    const s = a && a.stats;
    if (!s || !a.our_identity) return null;
    const backlogBits = s.backlog_bytes * 8;
    const bw = configuredBandwidth(a.interface);
    const delayMs = bw ? Math.round((backlogBits / bw) * 1000) : null;
    if (!(s.drops > 0 && backlogBits > 0)) return null;
    const demand = s.bps || null;
    return {
      label: 'queue saturated',
      title:
        `WAN queue is saturated.\n` +
        `Configured: ${fmtBits(bw)}\n` +
        (demand ? `Current demand: ${fmtBits(demand)}\n` : '') +
        (delayMs ? `Queue delay: ${delayMs} ms` : `Backlog: ${fmtBytes(s.backlog_bytes)}`),
    };
  }

  async function apply() {
    busy = true;
    notice = '';
    try {
      await api.setQos([
        {
          interface: interfaceName,
          kind,
          direction,
          ...(bandwidthMbps ? { bandwidth_mbps: Number(bandwidthMbps) } : {}),
          ...(latencyMs ? { latency_target_ms: Number(latencyMs) } : {}),
        },
      ]);
      notice = 'Shaping intent applied';
      interfaceName = '';
      bandwidthMbps = '';
      latencyMs = '';
    } catch (e) {
      notice = `Failed: ${e.message}`;
    }
    busy = false;
  }

  async function clearAll() {
    busy = true;
    notice = '';
    try {
      await api.setQos([]);
      notice = 'All shaping intent cleared';
    } catch (e) {
      notice = `Failed: ${e.message}`;
    }
    busy = false;
  }

  async function removeOne(iface) {
    busy = true;
    notice = '';
    try {
      await api.removeQos(iface);
      notice = `Removed shaping on ${iface}`;
    } catch (e) {
      notice = `Failed: ${e.message}`;
    }
    busy = false;
  }
</script>

<h2>Traffic Shaping / QoS</h2>

{#if healthError}<p class="err">Cannot reach the daemon: {healthError}</p>{/if}

<section class="status-bar">
  <StatusBadge status={status.status} title={status.title} />
  {#each status.reasons as r}<span class="reason">{r}</span>{/each}
  {#if qos && qos.last_error}
    <p class="err">Last error: {qos.last_error}</p>
  {/if}
</section>

{#if qos && qos.capabilities}
  <section class="caps">
    <h3>Kernel shaping capabilities</h3>
    <div class="cap-grid">
      {#each Object.entries(qos.capabilities) as [key, value]}
        <span class="cap {value ? 'yes' : 'no'}">{value ? '✓' : '✕'} {key}</span>
      {/each}
    </div>
  </section>
{/if}

<section class="apply">
  <h3>Apply shaping</h3>
  <div class="row">
    <input placeholder="interface (e.g. eth0)" bind:value={interfaceName} />
    <select bind:value={kind}>
      <option value="fq_codel">fq_codel</option>
      <option value="cake">CAKE (if available)</option>
      <option value="ingress">ingress</option>
    </select>
    <select bind:value={direction}>
      <option value="egress">egress</option>
      <option value="ingress">ingress</option>
    </select>
    <input placeholder="bandwidth Mb/s" bind:value={bandwidthMbps} type="number" min="1" />
    <input placeholder="latency target ms" bind:value={latencyMs} type="number" min="1" />
    <button on:click={apply} disabled={busy || !interfaceName}>Apply</button>
    <button class="ghost" on:click={clearAll} disabled={busy}>Clear all</button>
  </div>
  {#if notice}<p class="notice">{notice}</p>{/if}
</section>

<section class="tables">
  <div class="table-card">
    <h3>Desired (intent)</h3>
    {#if qos && qos.desired.length}
      <table>
        <thead><tr><th>Interface</th><th>Kind</th><th>Direction</th><th>Bandwidth</th><th>Target</th></tr></thead>
        <tbody>
          {#each qos.desired as c}
            <tr>
              <td>{c.interface}</td>
              <td>{c.kind}</td>
              <td>{c.direction}</td>
              <td>{c.bandwidth_bps ? `${Math.round(c.bandwidth_bps / 1e6)} Mb/s` : 'default'}</td>
              <td>{c.latency_target_ms ? `${c.latency_target_ms} ms` : 'default'}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    {:else}
      <p class="empty">No shaping intent</p>
    {/if}
  </div>

  <div class="table-card">
    <h3>Applied in kernel</h3>
    {#if qos && qos.applied.length}
      <table>
        <thead>
          <tr>
            <th>Interface</th><th>Kind</th><th>Handle</th><th>BalanSir</th>
            <th>Drops</th><th>Backlog</th><th>Throughput</th><th>Health</th>
          </tr>
        </thead>
        <tbody>
          {#each qos.applied as a}
            {@const hint = saturationHint(a)}
            <tr>
              <td>{a.interface}</td>
              <td>{a.kind || '—'}</td>
              <td>{a.handle}</td>
              <td>{a.our_identity ? 'yes' : 'no'}
                {#if a.our_identity}
                  <button class="link" on:click={() => removeOne(a.interface)} disabled={busy}>remove</button>
                {/if}
              </td>
              <td>{a.stats ? a.stats.drops : '—'}</td>
              <td>{a.stats ? fmtBytes(a.stats.backlog_bytes) : '—'}</td>
              <td>{a.stats && a.stats.bps ? `${(a.stats.bps / 1e6).toFixed(1)} Mb/s` : '—'}</td>
              <td>
                {#if hint}
                  <span class="saturate" title={hint.title}>{hint.label}</span>
                {:else if a.stats && a.stats.drops > 0}
                  <span class="warn">drops</span>
                {:else}
                  <span class="ok">healthy</span>
                {/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    {:else}
      <p class="empty">No qdiscs reported</p>
    {/if}
  </div>
</section>

<style>
  h2 { color: #4ecdc4; font-size: 1.05rem; }
  .status-bar { display: flex; gap: 12px; align-items: center; flex-wrap: wrap; margin: 12px 0; }
  .reason { color: #a8b6cc; font-size: 0.85rem; }
  .caps { background: #16213e; border: 1px solid #0f3460; border-radius: 12px; padding: 14px; margin-bottom: 14px; }
  .caps h3 { margin: 0 0 8px; color: #7a8aa5; font-size: 0.8rem; text-transform: uppercase; }
  .cap-grid { display: flex; flex-wrap: wrap; gap: 8px; }
  .cap { font-size: 0.78rem; padding: 3px 8px; border-radius: 6px; }
  .cap.yes { background: #123b2a; color: #4cd07d; }
  .cap.no { background: #2a2222; color: #8a6a6a; }
  .apply { background: #16213e; border: 1px solid #0f3460; border-radius: 12px; padding: 14px; margin-bottom: 14px; }
  .apply h3 { margin: 0 0 10px; color: #4ecdc4; font-size: 0.95rem; }
  .row { display: flex; gap: 8px; flex-wrap: wrap; }
  input, select {
    background: #0f1524; color: #e8ecf4; border: 1px solid #1f2a44;
    border-radius: 6px; padding: 8px 10px; font-size: 0.85rem;
  }
  button {
    background: #4ecdc4; color: #0f1524; border: none; border-radius: 6px;
    padding: 8px 16px; font-weight: 700; cursor: pointer;
  }
  button:disabled { opacity: 0.5; cursor: default; }
  button.ghost { background: #1f2a44; color: #9fb0cc; }
  .notice { color: #4cd07d; font-size: 0.85rem; margin: 8px 0 0; }
  .err { color: #ff6b6b; font-size: 0.85rem; }
  .tables { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
  @media (max-width: 900px) { .tables { grid-template-columns: 1fr; } }
  .table-card { background: #16213e; border: 1px solid #0f3460; border-radius: 12px; padding: 14px; overflow-x: auto; }
  .table-card h3 { margin: 0 0 10px; color: #4ecdc4; font-size: 0.9rem; }
  table { width: 100%; border-collapse: collapse; font-size: 0.84rem; }
  th, td { padding: 8px 10px; text-align: left; border-bottom: 1px solid #0f3460; white-space: nowrap; }
  th { color: #7a8aa5; font-size: 0.72rem; text-transform: uppercase; }
  .empty { color: #5a6a85; font-size: 0.85rem; }
  .link { background: none; border: none; color: #4cc9f0; text-decoration: underline; cursor: pointer; font-size: 0.8rem; padding: 0; }
  .saturate { background: #3d1f1f; color: #ff8a8a; font-weight: 700; font-size: 0.75rem; padding: 2px 8px; border-radius: 8px; cursor: help; }
  .warn { color: #e8a44c; font-size: 0.75rem; font-weight: 700; }
  .ok { color: #4cd07d; font-size: 0.75rem; font-weight: 700; }
</style>
