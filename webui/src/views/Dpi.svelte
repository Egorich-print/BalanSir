<script>
  import { api } from '../lib/api.js';
  import StatusBadge from '../components/StatusBadge.svelte';

  export let snapshot;
  export let healthError;

  $: dpi = snapshot ? snapshot.dpi : null;
  $: enabled = dpi && dpi.enabled;
  $: paused = !enabled;

  let busy = false;
  let notice = '';
  let domainInput = null;

  function fmt(n) {
    if (n == null) return '—';
    return Number(n).toLocaleString();
  }

  async function togglePause() {
    busy = true;
    notice = '';
    try {
      await api.setDpiPaused(!paused);
      notice = paused ? 'Engine resumed' : 'Engine paused';
    } catch (e) {
      notice = `Failed: ${e.message}`;
    }
    busy = false;
  }

  async function notifyDiscovery(domain) {
    busy = true;
    notice = '';
    try {
      const result = await api.notifyB4Discovery(domain);
      notice = result.selected
        ? `Discovery selected "${result.selected}" for ${domain}`
        : `Discovery: no bypass strategy found for ${domain}`;
    } catch (e) {
      notice = `Discovery failed: ${e.message}`;
    }
    busy = false;
  }

  function onTestDomain() {
    if (domainInput && domainInput.value && domainInput.value.trim()) {
      notifyDiscovery(domainInput.value.trim());
    }
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

    <div class="actions">
      <button on:click={togglePause} disabled={busy}>
        {paused ? '▶ Resume engine' : '⏸ Pause engine'}
      </button>
    </div>
    {#if notice}
      <p class="notice">{notice}</p>
    {/if}

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

    {#if dpi.discovery}
      <h3>B4 Discovery</h3>
      <div class="discovery">
        <p class="muted small">
          Auto-selected bypass strategies for blocked domains (mission §7).
        </p>
        {#if dpi.discovery.domains.length === 0}
          <p class="muted">No domains discovered yet. Report one below.</p>
        {:else}
          <table>
            <thead>
              <tr><th>Domain</th><th>Active</th><th>Blocked</th><th>Event</th></tr>
            </thead>
            <tbody>
              {#each dpi.discovery.domains as d}
                <tr>
                  <td>{d.domain}</td>
                  <td>{d.active || '—'}</td>
                  <td>{d.observed_blocked ? '⚠ yes' : 'no'}</td>
                  <td class="muted small">{d.last_event || '—'}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        {/if}
        <div class="discovery-notify">
          <input
            type="text"
            placeholder="domain (e.g. youtube.com)"
            bind:this={domainInput}
          />
          <button on:click={onTestDomain} disabled={busy}>
            Test domain
          </button>
        </div>
      </div>
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
  .notice { color: #4ecdc4; font-size: 0.9em; }
  .actions { margin: 10px 0; }
  .actions button, .discovery-notify button {
    background: #0f3460; color: #e8ecf4; border: 1px solid #1f2a44;
    border-radius: 6px; padding: 7px 14px; cursor: pointer;
  }
  .actions button:disabled, .discovery-notify button:disabled { opacity: 0.5; cursor: default; }
  .discovery table { width: 100%; border-collapse: collapse; font-size: 0.85em; }
  .discovery th, .discovery td { text-align: left; padding: 6px 8px; border-bottom: 1px solid #1f2a44; }
  .discovery th { color: #7a8aa5; font-weight: 600; }
  .discovery-notify { display: flex; gap: 8px; margin-top: 10px; }
  .discovery-notify input {
    flex: 1; background: #0f1a30; color: #e8ecf4; border: 1px solid #1f2a44;
    border-radius: 6px; padding: 7px 10px;
  }
</style>
