<script>
  import { api, fmtBytes } from '../lib/api.js';
  import { tailscaleStatus } from '../lib/status.js';
  import StatusBadge from '../components/StatusBadge.svelte';

  export let snapshot;
  export let healthError;

  let authKey = '';
  let routesText = '';
  let exitNode = false;
  let busy = false;
  let notice = '';

  $: status = tailscaleStatus(snapshot);
  $: ts = snapshot && snapshot.tailscale ? snapshot.tailscale : null;

  async function run(fn, okMsg) {
    busy = true;
    notice = '';
    try {
      await fn();
      notice = okMsg;
    } catch (e) {
      notice = `Failed: ${e.message}`;
    }
    busy = false;
  }

  async function up() {
    await run(() => api.tailscaleUp(authKey), 'tailscale up requested');
    authKey = '';
  }
  async function down() {
    await run(() => api.tailscaleDown(), 'tailscale down requested');
  }
  async function reconnect() {
    await run(() => api.tailscaleReconnect(), 'reconnect requested');
  }
  async function routes() {
    const list = routesText.split(',').map((s) => s.trim()).filter(Boolean);
    await run(() => api.tailscaleRoutes(list, exitNode), 'routes updated');
    routesText = '';
  }
</script>

<h2>Tailscale</h2>

{#if healthError}<p class="err">Cannot reach the daemon: {healthError}</p>{/if}

<section class="status-bar">
  <StatusBadge status={status.status} title={status.title} />
  {#each status.reasons as r}<span class="reason">{r}</span>{/each}
</section>

{#if ts && ts.error}
  <p class="err">Tailscale error: {ts.error}</p>
{/if}

{#if ts && ts.status}
  <section class="info">
    <div class="kv"><span>Backend state</span><strong>{ts.status.backend_state}</strong></div>
    <div class="kv"><span>Hostname</span><strong>{ts.status.hostname || '—'}</strong></div>
    <div class="kv"><span>Tailscale IP</span><strong>{ts.status.tailscale_ip || '—'}</strong></div>
    <div class="kv"><span>Online</span><strong>{ts.status.self_online ? 'yes' : 'no'}</strong></div>
    <div class="kv"><span>Exit node</span><strong>{ts.status.exit_node || '—'}</strong></div>
    <div class="kv"><span>Advertised routes</span><strong>{ts.status.advertise_routes.join(', ') || '—'}</strong></div>
    {#if ts.status.summary}<p class="summary">{ts.status.summary}</p>{/if}
  </section>

  {#if ts.status.installed}
    <section class="controls">
      <h3>Controls</h3>
      <div class="row">
        <input placeholder="auth key (optional for interactive login)" bind:value={authKey} />
        <button on:click={up} disabled={busy}>Up</button>
        <button class="ghost" on:click={down} disabled={busy}>Down</button>
        <button class="ghost" on:click={reconnect} disabled={busy}>Reconnect</button>
      </div>
      <div class="row routes">
        <input placeholder="subnet routes, comma-separated (e.g. 10.0.0.0/24)" bind:value={routesText} />
        <label><input type="checkbox" bind:checked={exitNode} /> use as exit node</label>
        <button on:click={routes} disabled={busy}>Set routes</button>
      </div>
      {#if notice}<p class="notice">{notice}</p>{/if}
    </section>

    <section class="peers">
      <h3>Peers</h3>
      {#if ts.status.peers.length}
        <table>
          <thead><tr><th>Name</th><th>Addresses</th><th>State</th><th>RX</th><th>TX</th></tr></thead>
          <tbody>
            {#each ts.status.peers as p}
              <tr>
                <td>
                  {p.name}
                  {#if p.exit_node}<span class="tag">exit node</span>{/if}
                </td>
                <td class="addr-cell">
                  {#each p.addrs as a}<span class="addr">{a}</span>{/each}
                </td>
                <td>
                  {p.online ? 'online' : 'offline'}
                  {#if p.active}<span class="tag">active</span>{/if}
                  {#if !p.online && p.last_seen_seconds_ago != null}
                    <span class="sub">{Math.round(p.last_seen_seconds_ago / 60)}m ago</span>
                  {/if}
                </td>
                <td>{fmtBytes(p.rx_bytes)}</td>
                <td>{fmtBytes(p.tx_bytes)}</td>
              </tr>
            {:else}
              <tr><td colspan="5" class="empty">No peers</td></tr>
            {/each}
          </tbody>
        </table>
      {:else}
        <p class="empty">No peers</p>
      {/if}
    </section>
  {/if}
{:else}
  <p class="empty">No Tailscale status yet.</p>
{/if}

<style>
  h2 { color: #4ecdc4; font-size: 1.05rem; }
  .status-bar { display: flex; gap: 12px; align-items: center; flex-wrap: wrap; margin: 12px 0; }
  .reason { color: #a8b6cc; font-size: 0.85rem; }
  .info, .controls, .peers { background: #16213e; border: 1px solid #0f3460; border-radius: 12px; padding: 14px; margin-bottom: 14px; }
  .info h3, .controls h3, .peers h3 { margin: 0 0 10px; color: #4ecdc4; font-size: 0.9rem; }
  .kv { display: flex; justify-content: space-between; padding: 5px 0; border-bottom: 1px solid #0f3460; font-size: 0.88rem; }
  .kv span { color: #7a8aa5; }
  .summary { color: #a8b6cc; font-size: 0.85rem; margin: 10px 0 0; }
  .row { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 8px; align-items: center; }
  input { background: #0f1524; color: #e8ecf4; border: 1px solid #1f2a44; border-radius: 6px; padding: 8px 10px; font-size: 0.85rem; flex: 1; min-width: 200px; }
  label { color: #a8b6cc; font-size: 0.85rem; }
  button { background: #4ecdc4; color: #0f1524; border: none; border-radius: 6px; padding: 8px 16px; font-weight: 700; cursor: pointer; }
  button.ghost { background: #1f2a44; color: #9fb0cc; }
  button:disabled { opacity: 0.5; cursor: default; }
  .notice { color: #4cd07d; font-size: 0.85rem; margin: 4px 0 0; }
  .err { color: #ff6b6b; font-size: 0.85rem; }
  .empty { color: #5a6a85; font-size: 0.85rem; }
  .peers table { width: 100%; border-collapse: collapse; font-size: 0.84rem; }
  th, td { padding: 8px 10px; text-align: left; border-bottom: 1px solid #0f3460; white-space: nowrap; }
  th { color: #7a8aa5; font-size: 0.72rem; text-transform: uppercase; }
  .addr-cell { max-width: 300px; overflow-x: auto; }
  .addr { display: inline-block; margin: 2px 4px 0 0; background: #0f1524; border-radius: 4px; padding: 1px 6px; font-size: 0.76rem; }
  .tag { background: #12344a; color: #4cc9f0; border-radius: 4px; padding: 1px 6px; font-size: 0.72rem; margin-left: 6px; }
  .sub { color: #5a6a85; font-size: 0.78rem; }
</style>
