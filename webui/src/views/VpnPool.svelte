<script>
  import { api } from '../lib/api.js';

  export let snapshot;
  export let healthError;

  let busy = false;
  let notice = '';

  $: vpn = snapshot ? snapshot.vpn_pool : null;
  $: profiles = (vpn && vpn.profiles) || [];

  const STATE_LABEL = {
    Unknown: 'Unknown',
    Healthy: 'Healthy',
    Degraded: 'Degraded',
    Cooldown: 'Cooldown',
    Failed: 'Failed',
    Recovering: 'Recovering',
  };

  function shortId(id) {
    return id && id.length > 10 ? id.slice(0, 10) + '…' : id || '—';
  }

  function stateClass(state) {
    return (state || 'unknown').toLowerCase();
  }

  async function togglePause() {
    busy = true;
    notice = '';
    try {
      const target = !(vpn && vpn.paused);
      await api.setVpnPaused(target);
      notice = target ? 'VPN pool paused (traffic stays direct)' : 'VPN pool resumed';
      setTimeout(() => (notice = ''), 4000);
    } catch (e) {
      notice = `Failed: ${e.message}`;
    }
    busy = false;
  }

  async function refresh() {
    busy = true;
    notice = '';
    try {
      await api.vpnRefresh();
      notice = 'Subscription refresh requested (known-good pool stays on failure)';
      setTimeout(() => (notice = ''), 4000);
    } catch (e) {
      notice = `Failed: ${e.message}`;
    }
    busy = false;
  }

  async function rotate() {
    busy = true;
    notice = '';
    try {
      await api.vpnRotate();
      notice = 'Manual rotation requested';
      setTimeout(() => (notice = ''), 4000);
    } catch (e) {
      notice = `Failed: ${e.message}`;
    }
    busy = false;
  }

  async function pin(id) {
    busy = true;
    notice = '';
    try {
      await api.vpnPin(id);
      notice = `Pinned profile ${id.slice(0, 8)}…`;
      setTimeout(() => (notice = ''), 4000);
    } catch (e) {
      notice = `Failed: ${e.message}`;
    }
    busy = false;
  }

  async function unpin() {
    busy = true;
    notice = '';
    try {
      await api.vpnPin(null);
      notice = 'Pin cleared (selection returns to health-aware ranking)';
      setTimeout(() => (notice = ''), 4000);
    } catch (e) {
      notice = `Failed: ${e.message}`;
    }
    busy = false;
  }
</script>

{#if vpn}
  <div class="panel">
    <div class="row">
      <h2>VPN Pool</h2>
      <span class="health {vpn.paused ? 'unknown' : 'healthy'}">{vpn.paused ? 'Paused' : 'Active'}</span>
      <div class="spacer"></div>
      <button class="btn" on:click={togglePause} disabled={busy}>
        {vpn.paused ? 'Resume' : 'Pause'}
      </button>
      <button class="btn" on:click={refresh} disabled={busy}>Refresh sources</button>
      <button class="btn" on:click={rotate} disabled={busy}>Rotate</button>
    </div>

    {#if notice}<p class="notice">{notice}</p>{/if}
    {#if healthError}<p class="error">Snapshot unavailable: {healthError}</p>{/if}
    {#if vpn.last_error}<p class="error">{vpn.last_error}</p>{/if}

    <div class="summary">
      <div>
        <strong>{profiles.length}</strong>
        <span class="muted">profiles</span>
      </div>
      <div>
        <strong>{profiles.filter((p) => p.state === 'healthy').length}</strong>
        <span class="muted">healthy</span>
      </div>
      <div>
        <strong>{profiles.filter((p) => p.state === 'degraded' || p.state === 'recovering').length}</strong>
        <span class="muted">degraded/recovering</span>
      </div>
      <div>
        <strong>{profiles.filter((p) => p.state === 'failed' || p.state === 'cooldown').length}</strong>
        <span class="muted">failed/cooldown</span>
      </div>
      <div class="muted">active: {vpn.active ? shortId(vpn.active) : '—'}</div>
    </div>

    {#if vpn.last_rotation_reason}
      <p class="muted">Last rotation: {vpn.last_rotation_reason}</p>
    {/if}
    {#if vpn.last_refresh_reason}
      <p class="muted">Last refresh: {vpn.last_refresh_reason}</p>
    {/if}

    <table>
      <thead>
        <tr>
          <th>State</th>
          <th>Profile</th>
          <th>Latency</th>
          <th>Avail.</th>
          <th>Weight</th>
          <th>Why</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        {#each profiles as p, i}
          <tr>
            <td>
              <span class="health {stateClass(p.state)}">{STATE_LABEL[p.state] || p.state}</span>
            </td>
            <td>
              {p.label || shortId(p.profile_id)}
              <span class="muted tag">{shortId(p.profile_id)}</span>
            </td>
            <td>{p.latency_ms != null ? `${Math.round(p.latency_ms)} ms` : '—'}</td>
            <td>{p.availability != null ? `${Math.round(p.availability * 100)}%` : '—'}</td>
            <td>{p.weight || 0}</td>
            <td>
              {#if p.reasons && p.reasons.length}
                <ul class="why">
                  {#each p.reasons as r}
                    <li>{r}</li>
                  {/each}
                </ul>
              {:else}
                <span class="muted">—</span>
              {/if}
            </td>
            <td>
              {#if vpn.active === p.profile_id}
                <button class="btn small" on:click={unpin} disabled={busy}>Active</button>
              {:else}
                <button class="btn small" on:click={() => pin(p.profile_id)} disabled={busy}>Pin</button>
              {/if}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
    <p class="muted">
      Selection is health-aware and explainable: weight combines state, latency,
      availability and load headroom; flows are pinned (stickiness); recovering
      profiles ramp up gradually. The pool is the single authoritative path
      decision — the Xray manager runs exactly the selected profile. Credentials
      are never shown.
    </p>
  </div>
{:else}
  <div class="panel">
    <p class="muted">
      VPN pool is not configured. Set <code>BALANSIR_VPN_CONFIG</code> to a TOML
      file with a <code>source_url</code> (or <code>local_source</code>) pointing
      at a subscription of <code>vless://</code> config URIs and restart the daemon.
    </p>
  </div>
{/if}

<style>
  .health { font-weight: 600; }
  .health.healthy { color: var(--ok); }
  .health.degraded, .health.recovering { color: var(--warn); }
  .health.failed, .health.cooldown { color: var(--err); }
  .health.unknown { color: var(--muted); }
  .tag {
    margin-left: 0.4rem;
    font-size: 0.7rem;
    padding: 0.1rem 0.35rem;
    border-radius: 3px;
    background: var(--panel);
    border: 1px solid var(--border);
  }
  .row { display: flex; gap: 0.75rem; align-items: center; flex-wrap: wrap; }
  .spacer { flex: 1; }
  .summary { display: flex; gap: 2rem; margin: 0.75rem 0; flex-wrap: wrap; }
  .summary strong { display: block; font-size: 1.4rem; }
  .btn.small { padding: 0.2rem 0.6rem; font-size: 0.8rem; }
  .notice { color: var(--ok); }
  .error { color: var(--err); }
  ul.why { margin: 0; padding-left: 1rem; font-size: 0.8rem; }
</style>
