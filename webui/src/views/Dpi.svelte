<script>
  import { api } from '../lib/api.js';
  import StatusBadge from '../components/StatusBadge.svelte';

  export let snapshot;
  export let healthError;

  $: dpi = snapshot ? snapshot.dpi : null;
  $: enabled = dpi && dpi.enabled;

  function fmt(n) {
    if (n == null) return '—';
    return Number(n).toLocaleString();
  }
</script>

<div class="panel">
  <h2>DPI-bypass (NFQUEUE)</h2>

  {#if !snapshot}
    <p class="muted">Loading…</p>
  {:else if !dpi}
    <p class="muted">DPI engine not configured (set BALANSIR_DPI_CONFIG).</p>
  {:else}
    <div class="grid">
      <div class="stat">
        <span>State</span>
        <StatusBadge status={enabled ? 'healthy' : 'disabled'} title={enabled ? 'Enabled' : 'Disabled'} />
      </div>
      <div class="stat"><span>Queue</span><b>{dpi.queue_num}</b></div>
      <div class="stat"><span>Profiles</span><b>{dpi.profiles.length}</b></div>
      <div class="stat"><span>Ports</span><b>{dpi.ports.join(', ') || '443'}</b></div>
    </div>

    {#if dpi.config_path}
      <p class="muted small">config: {dpi.config_path}</p>
    {/if}

    {#if dpi.last_error}
      <p class="error">Last error: {dpi.last_error}</p>
    {/if}

    <h3>Counters</h3>
    <div class="grid">
      <div class="stat"><span>Packets seen</span><b>{fmt(dpi.packets_seen)}</b></div>
      <div class="stat"><span>TLS (SNI)</span><b>{fmt(dpi.tls_packets)}</b></div>
      <div class="stat"><span>Mutated</span><b>{fmt(dpi.mutated)}</b></div>
      <div class="stat"><span>Accepted</span><b>{fmt(dpi.accepted)}</b></div>
    </div>

    <h3>Profiles</h3>
    {#if dpi.profiles.length === 0}
      <p class="muted">No profiles configured.</p>
    {:else}
      <ul>
        {#each dpi.profiles as name}
          <li>{name}</li>
        {/each}
      </ul>
    {/if}
  {/if}

  {#if healthError}
    <p class="error">{healthError}</p>
  {/if}
</div>

<style>
  .panel { padding: 4px 0; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 10px; margin: 10px 0; }
  .stat { background: #0f3460; border-radius: 8px; padding: 10px; }
  .stat span { display: block; font-size: 0.8em; color: #888; margin-bottom: 4px; }
  .stat b { font-size: 1.15em; }
  h3 { margin: 14px 0 6px; }
  .muted { color: #888; }
  .small { font-size: 0.85em; }
  .error { color: #ff8a80; }
</style>
