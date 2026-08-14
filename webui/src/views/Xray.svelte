<script>
  import { api } from '../lib/api.js';
  import { xrayStatus } from '../lib/status.js';
  import StatusBadge from '../components/StatusBadge.svelte';

  export let snapshot;
  export let healthError;

  let busy = false;
  let notice = '';

  $: status = xrayStatus(snapshot);
  $: xray = snapshot ? snapshot.xray : null;

  const HEALTH_LABEL = {
    Unknown: 'No probe yet',
    Healthy: 'Proxying',
    Degraded: 'Degraded',
    Unhealthy: 'Unreachable',
  };

  async function togglePause() {
    busy = true;
    notice = '';
    try {
      const target = !(xray && xray.paused);
      await api.setXrayPaused(target);
      notice = target ? 'Xray transport paused (traffic stays direct)' : 'Xray transport resumed';
      setTimeout(() => (notice = ''), 4000);
    } catch (e) {
      notice = `Failed: ${e.message}`;
    }
    busy = false;
  }

  async function selectProfile(name) {
    busy = true;
    notice = '';
    try {
      await api.xraySelect(name);
      notice = `Pinned endpoint '${name}' (failover stays active)`;
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
      await api.xrayRotate();
      notice = 'Rotated to the next enabled endpoint';
      setTimeout(() => (notice = ''), 4000);
    } catch (e) {
      notice = `Failed: ${e.message}`;
    }
    busy = false;
  }
</script>

<h2>Xray — Transport Endpoints</h2>

{#if healthError}<p class="err">Cannot reach the daemon: {healthError}</p>{/if}

<section class="status-bar">
  <StatusBadge status={status.status} title={status.title} />
  {#each status.reasons as r}<span class="reason">{r}</span>{/each}
</section>

{#if xray && xray.profiles.length > 0}
  <div class="panel">
    <h3>Transport</h3>
    <dl class="kv">
      <dt>Active endpoint</dt><dd>{xray.active ?? '— (not running)'}</dd>
      <dt>Selection</dt>
      <dd>{xray.pinned ? `Manual — pinned to '${xray.pinned}'` : 'Automatic (priority)'}</dd>
      <dt>Local SOCKS port</dt><dd>{xray.socks_port}</dd>
      <dt>Local HTTP port</dt><dd>{xray.http_port}</dd>
      <dt>Last switch</dt>
      <dd>
        {#if xray.switch_reason}
          {xray.switch_reason}{xray.last_switch_ms ? ` (${new Date(xray.last_switch_ms).toLocaleTimeString()})` : ''}
        {:else}—{/if}
      </dd>
      <dt>State</dt><dd>{xray.paused ? 'Paused (proxy stopped)' : 'Running'}</dd>
    </dl>
    <div class="row">
      <button class="btn" on:click={togglePause} disabled={busy}>
        {xray.paused ? '▶ Resume transport' : '⏸ Pause transport'}
      </button>
      <button class="btn" on:click={rotate} disabled={busy}>
        ⟳ Rotate endpoint
      </button>
    </div>
    {#if notice}<p class="ok">{notice}</p>{/if}
  </div>

  <div class="panel">
    <h3>Endpoints</h3>
    <table>
      <thead>
        <tr>
          <th>Endpoint</th><th>Server</th><th>Transport</th><th>TLS</th>
          <th>Priority</th><th>Health</th><th>Probe failures</th><th>Latency</th><th></th>
        </tr>
      </thead>
      <tbody>
        {#each xray.profiles as p}
          <tr class:inactive={!p.enabled}>
            <td>
              {p.active ? '● ' : ''}<strong>{p.name}</strong>
              {#if xray.pinned === p.name}<span class="tag">pinned</span>{/if}
              {#if !p.enabled}<span class="tag">disabled</span>{/if}
            </td>
            <td><code>{p.server}:{p.port}</code></td>
            <td>{p.transport}</td>
            <td>{p.tls ? 'Yes' : 'No'}</td>
            <td>{p.priority}</td>
            <td>
              <span
                class="health {p.health.toLowerCase()}"
                title={HEALTH_LABEL[p.health] ?? p.health}
              >{p.health}</span>
            </td>
            <td>{p.failure_count}</td>
            <td>{p.latency_ms != null ? `${p.latency_ms} ms` : '—'}</td>
            <td>
              {#if p.enabled}
                <button class="btn small" on:click={() => selectProfile(p.name)} disabled={busy || p.active}>
                  {p.active ? 'Active' : 'Use'}
                </button>
              {/if}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
    <p class="muted">
      Selection is explainable: when the active endpoint fails enough consecutive
      health probes it is replaced with the next enabled endpoint and the reason
      is recorded above. Manual pins still fail over — a dead endpoint can never
      pin the network permanently.
    </p>
  </div>
{:else}
  <div class="panel">
    <p class="muted">
      Xray is not configured. Set <code>BALANSIR_XRAY_CONFIG</code> to a TOML file
      with <code>[[profiles]]</code> entries (name, server, port, uuid, optional
      transport/TLS/flow/priority) and restart the daemon.
    </p>
  </div>
{/if}

<style>
  .health { font-weight: 600; }
  .health.healthy { color: var(--ok); }
  .health.degraded { color: var(--warn); }
  .health.unhealthy { color: var(--err); }
  .health.unknown { color: var(--muted); }
  .row { display: flex; gap: 0.75rem; flex-wrap: wrap; }
  .btn.small { padding: 0.2rem 0.6rem; font-size: 0.8rem; }
  .tag {
    margin-left: 0.4rem;
    font-size: 0.7rem;
    padding: 0.1rem 0.35rem;
    border-radius: 3px;
    background: var(--panel);
    border: 1px solid var(--border);
  }
  tr.inactive td { opacity: 0.55; }
</style>
