<script>
  import { api } from '../lib/api.js';
  import StatusBadge from '../components/StatusBadge.svelte';

  export let snapshot;
  export let healthError;

  $: mptcp = snapshot ? snapshot.mptcp : null;
  $: enabled = mptcp && mptcp.enabled;

  let busy = false;
  let notice = '';
  let newEndpoint = '';

  async function toggle() {
    busy = true;
    notice = '';
    try {
      const r = await api.setMptcpEnabled(!enabled);
      notice = r.detail || (enabled ? 'MPTCP disabled' : 'MPTCP enabled');
    } catch (e) {
      notice = `Failed: ${e.message}`;
    }
    busy = false;
  }

  async function addEndpoint() {
    busy = true;
    notice = '';
    try {
      const r = await api.setMptcpEndpoints([[newEndpoint, '']]);
      notice = r.detail || `Endpoint ${newEndpoint} added`;
    } catch (e) {
      notice = `Add endpoint failed: ${e.message}`;
    }
    busy = false;
  }
</script>

<div class="panel">
  <h2>Multipath TCP (MPTCP)</h2>

  {#if !snapshot}
    <p class="muted">Loading…</p>
  {:else if !mptcp}
    <p class="muted">MPTCP manager not attached.</p>
  {:else}
    <div class="grid">
      <div class="stat">
        <span>Kernel MPTCP</span>
        <StatusBadge status={enabled ? 'healthy' : 'disabled'}
          title={enabled ? 'Enabled' : 'Disabled / unsupported'} />
      </div>
      <div class="stat"><span>Endpoints</span><b>{mptcp.endpoints ? mptcp.endpoints.length : 0}</b></div>
      <div class="stat"><span>Subflows</span><b>{mptcp.subflows ? mptcp.subflows.length : 0}</b></div>
    </div>

    {#if mptcp.last_error}
      <p class="error">{mptcp.last_error}</p>
    {/if}

    <div class="actions">
      <button on:click={toggle} disabled={busy || !enabled && mptcp.last_error !== null}>
        {enabled ? 'Disable MPTCP' : 'Enable MPTCP'}
      </button>
    </div>

    <div class="endpoints">
      <h3>Local endpoints (paths)</h3>
      {#if mptcp.endpoints && mptcp.endpoints.length}
        <table>
          <thead><tr><th>Address</th><th>Interface</th><th>Flags</th><th>ID</th></tr></thead>
          <tbody>
            {#each mptcp.endpoints as ep}
              <tr>
                <td>{ep.address}</td>
                <td>{ep.iface || '—'}</td>
                <td>{ep.flags.join(', ') || '—'}</td>
                <td>{ep.local_id}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      {:else}
        <p class="muted">No endpoints advertised yet.</p>
      {/if}
      <div class="add">
        <input type="text" placeholder="local IP (e.g. 192.168.1.5)" bind:value={newEndpoint} />
        <button on:click={addEndpoint} disabled={busy || !newEndpoint}>Add endpoint</button>
      </div>
    </div>

    <div class="subflows">
      <h3>Live subflows</h3>
      {#if mptcp.subflows && mptcp.subflows.length}
        <table>
          <thead><tr><th>Local</th><th>Remote</th><th>State</th><th>Backup</th></tr></thead>
          <tbody>
            {#each mptcp.subflows as sf}
              <tr>
                <td>{sf.local}</td>
                <td>{sf.remote}</td>
                <td><StatusBadge status={sf.state === 'ESTABLISHED' ? 'healthy' : 'degraded'} title={sf.state} /></td>
                <td>{sf.backup ? 'yes' : 'no'}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      {:else}
        <p class="muted">No live subflows. MPTCP activates for new connections once paths exist.</p>
      {/if}
    </div>

    {#if notice}
      <p class="notice">{notice}</p>
    {/if}
  {/if}

  {#if healthError}
    <p class="error">{healthError}</p>
  {/if}
</div>

<style>
  .panel { padding: 4px 0; }
  h2 { color: #4ecdc4; font-size: 1.05rem; }
  h3 { margin: 16px 0 8px; font-size: 0.95rem; color: #e8ecf4; }
  .muted { color: #888; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 10px; margin: 10px 0; }
  .stat { background: #0f3460; border-radius: 8px; padding: 10px; }
  .stat span { display: block; font-size: 0.8em; color: #888; margin-bottom: 4px; }
  .stat b { font-size: 1.15em; }
  .actions { margin: 10px 0; }
  .actions button, .add button {
    background: #0f3460; color: #e8ecf4; border: 1px solid #1f2a44;
    border-radius: 6px; padding: 7px 14px; cursor: pointer;
  }
  .actions button:disabled, .add button:disabled { opacity: 0.5; cursor: default; }
  table { width: 100%; border-collapse: collapse; font-size: 0.88em; }
  th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid #1f2a44; }
  th { color: #7a8aa5; font-weight: 600; }
  .add { display: flex; gap: 8px; margin-top: 10px; }
  .add input {
    flex: 1; background: #0f1a30; color: #e8ecf4; border: 1px solid #1f2a44;
    border-radius: 6px; padding: 7px 10px;
  }
  .notice { color: #4ecdc4; font-size: 0.9em; }
  .error { color: #ff8a80; }
</style>