<script>
  import { api } from '../lib/api.js';
  import { b4Status } from '../lib/status.js';
  import StatusBadge from '../components/StatusBadge.svelte';

  export let snapshot;
  export let healthError;

  let busy = false;
  let notice = '';

  $: status = b4Status(snapshot);
  $: b4 = snapshot ? snapshot.b4 : null;

  const STATE_HINT = {
    Idle: 'No observation yet for this flow',
    Observing: 'Collecting host-stack signals',
    Adapting: 'Applying an adaptation (MTU / DNS-path)',
    Monitoring: 'Verifying the adaptation recovered the path',
    Recovered: 'Direct path healthy, no adaptation needed',
    Fallback: 'Restricted fallback in use (per policy)',
    StrictFail: 'No secure mechanism — flow must fail, not bypass',
    Paused: 'Engine paused by operator',
    Running: 'Engine running',
  };

  async function togglePause() {
    busy = true;
    notice = '';
    try {
      const target = !(b4 && b4.paused);
      await api.setB4Paused(target);
      notice = target ? 'B4 engine paused' : 'B4 engine resumed';
      setTimeout(() => (notice = ''), 4000);
    } catch (e) {
      notice = `Failed: ${e.message}`;
    }
    busy = false;
  }

  function decisionKind(lastDecision) {
    if (!lastDecision) return '—';
    const d = String(lastDecision);
    if (d.includes('AdaptMtu')) return 'MTU adaptation';
    if (d.includes('SwitchDnsPath')) return 'DNS-path switch';
    if (d.includes('Fallback')) return 'Fallback';
    if (d.includes('FailStrict')) return 'Strict fail';
    if (d.includes('Recovered')) return 'Recovered';
    return d;
  }

  function signals(f) {
    const parts = [];
    if (f.rtt_ms) parts.push(`rtt ${f.rtt_ms}ms`);
    if (f.rtt_var_ms) parts.push(`±${f.rtt_var_ms}ms`);
    if (f.connect_latency_ms) parts.push(`c ${f.connect_latency_ms}ms`);
    if (f.retransmissions) parts.push(`retx ${f.retransmissions}`);
    if (f.throughput_bps) parts.push(`${(f.throughput_bps / 1e6).toFixed(1)} MB/s`);
    if (f.dns_ok === false) parts.push('dns✗');
    if (f.reset_or_timeout) parts.push('rst');
    return parts.length ? parts.join(' ') : '—';
  }
</script>

<h2>B4 — Connectivity Adaptation</h2>

{#if healthError}<p class="err">Cannot reach the daemon: {healthError}</p>{/if}

<section class="status-bar">
  <StatusBadge status={status.status} title={status.title} />
  {#each status.reasons as r}<span class="reason">{r}</span>{/each}
</section>

{#if b4 && b4.config_path}
  <div class="panel">
    <h3>Engine</h3>
    <dl class="kv">
      <dt>Config</dt><dd><code>{b4.config_path}</code></dd>
      <dt>Enabled</dt><dd>{b4.enabled ? 'Yes' : 'No'}</dd>
      <dt>MTU adaptation</dt><dd>{b4.mtu_enabled ? 'Allowed (policy gate)' : 'Gated off'}</dd>
      <dt>State</dt><dd>{b4.paused ? 'Paused' : 'Running'}</dd>
    </dl>
    <button class="btn" on:click={togglePause} disabled={busy}>
      {b4.paused ? '▶ Resume engine' : '⏸ Pause engine'}
    </button>
    {#if notice}<p class="ok">{notice}</p>{/if}
  </div>

  <div class="panel">
    <h3>Ownership — per-path MTU</h3>
    {#if b4.drift}
      <p class="err">Drift: intended and reported per-path MTU disagree.</p>
    {/if}
    <table>
      <thead><tr><th>Path</th><th>Intended MTU</th><th>Reported MTU</th><th></th></tr></thead>
      <tbody>
        {#each b4.intended_mtu as m}
          {@const reported = b4.reported_mtu.find((r) => r.path === m.path)}
          <tr>
            <td><code>{m.path}</code></td>
            <td>{m.mtu}</td>
            <td>{reported ? reported.mtu : '—'}</td>
            <td>{reported && reported.mtu !== m.mtu ? '⚠ drift' : ''}</td>
          </tr>
        {:else}
          {#each b4.reported_mtu as r}
            <tr>
              <td><code>{r.path}</code></td>
              <td>—</td>
              <td>{r.mtu}</td>
              <td>⚠ unexpected (orphan)</td>
            </tr>
          {/each}
        {/each}
      </tbody>
    </table>
  </div>

  <div class="panel">
    <h3>Flows</h3>
    {#if b4.flows.length === 0}
      <p class="muted">No flows tracked yet. The engine probes configured policy domains each cycle.</p>
    {/if}
    <table>
      <thead>
        <tr>
          <th>Flow</th><th>Health</th><th>State</th><th>Profile</th>
          <th>Last decision</th><th>Effective MTU</th><th>Signals</th><th>Hint</th>
        </tr>
      </thead>
      <tbody>
        {#each b4.flows as f}
          <tr>
            <td><code>{f.flow}</code></td>
            <td><span class="health health-{f.health.toLowerCase()}">{f.health}</span></td>
            <td><span class="state state-{f.state.toLowerCase()}">{f.state}</span></td>
            <td><code>{f.profile}</code></td>
            <td>{decisionKind(f.last_decision)}</td>
            <td>{f.mtu ?? '—'}</td>
            <td class="signals">{signals(f)}</td>
            <td class="muted">{STATE_HINT[f.state] || '—'}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
{:else}
  <div class="panel muted">
    <p><strong>B4 is not configured.</strong></p>
    <p>
      Set <code>BALANSIR_B4_CONFIG</code> to a B4 TOML policy file and restart the
      daemon. When enabled, B4 observes each flow's host-stack signals and
      adapts the direct path (per-path MTU, DNS path) within the policy's
      allowed capabilities — never bypassing security policy.
    </p>
  </div>
{/if}

<style>
  .status-bar { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; margin-bottom: 14px; }
  .reason { background: #16203a; color: #9fb0cc; padding: 4px 10px; border-radius: 12px; font-size: 0.8rem; }
  .panel { background: #131c30; border: 1px solid #1f2a44; border-radius: 10px; padding: 14px 16px; margin-bottom: 14px; }
  .panel h3 { margin: 0 0 10px; color: #4ecdc4; font-size: 0.95rem; }
  .kv { display: grid; grid-template-columns: max-content 1fr; gap: 6px 16px; margin: 0 0 12px; font-size: 0.9rem; }
  .kv dt { color: #7a8aa5; }
  .kv dd { margin: 0; }
  table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
  th { text-align: left; color: #7a8aa5; padding: 6px 8px; border-bottom: 1px solid #1f2a44; }
  td { padding: 6px 8px; border-bottom: 1px solid #16203a; }
  .state { padding: 2px 8px; border-radius: 10px; font-size: 0.75rem; }
  .health { padding: 2px 8px; border-radius: 10px; font-size: 0.75rem; font-weight: 700; }
  .health-direct, .health-unknown { background: #123b2a; color: #4cd07d; }
  .health-degraded { background: #3b3a12; color: #e8d44c; }
  .health-interfered, .health-blocked { background: #3a1513; color: #ff9c9c; }
  .signals { font-size: 0.76rem; color: #9fb0cc; white-space: nowrap; }
  .state-recovered, .state-idle { background: #123b2a; color: #4cd07d; }
  .state-observing, .state-monitoring { background: #26344f; color: #9fb0cc; }
  .state-adapting { background: #3b3a12; color: #e8d44c; }
  .state-fallback { background: #3a2a12; color: #e8a44c; }
  .state-strictfail { background: #3a1513; color: #ff9c9c; }
  .muted { color: #7a8aa5; }
  .err { color: #ff9c9c; font-size: 0.85rem; }
  .ok { color: #4cd07d; font-size: 0.85rem; }
  .btn {
    background: #1e5c3d; color: #e8ecf4; border: 1px solid #2a7a52;
    padding: 7px 14px; border-radius: 8px; cursor: pointer; font-size: 0.85rem;
  }
  .btn:hover { background: #26734a; }
</style>
