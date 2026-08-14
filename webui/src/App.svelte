<script>
  import { onMount, onDestroy } from 'svelte';
  import { api, eventsStream } from './lib/api.js';

  let health = null;
  let desired = null;
  let actual = null;
  let drift = null;
  let plan = null;
  let explain = null;
  let fingerprint = null;
  let metricsText = '';
  let events = [];
  let connected = false;
  let error = null;
  let tab = 'overview';
  let reloading = false;
  let tailscale = null;
  let tsBusy = false;
  let tsError = null;
  let qos = null;

  let pollTimer = null;
  let es = null;

  function statusClass() {
    if (!health) return 'unknown';
    if (health.status === 'ok') return 'healthy';
    if (health.status === 'error') return 'error';
    return 'degraded';
  }

  function overallState() {
    // Human-readable overall state: healthy / degraded / blocked.
    const hasDrift = drift && drift.drift_count > 0;
    const rulesOk = desired && actual && desired.rule_count > 0
      && desired.rule_count >= actual.rule_count;
    if (health?.status === 'error') return { label: 'Blocked', cls: 'error' };
    if (hasDrift) return { label: 'Degraded', cls: 'degraded' };
    if (rulesOk) return { label: 'Healthy', cls: 'healthy' };
    return { label: 'Recovering', cls: 'degraded' };
  }

  async function refresh() {
    try {
      const results = await Promise.allSettled([
        api.health(), api.desired(), api.actual(), api.drift(),
        api.plan(), api.explain(), api.fingerprint(),
      ]);
      [health, desired, actual, drift, plan, explain, fingerprint] = results.map(
        (r) => (r.status === 'fulfilled' ? r.value : null)
      );
      error = null;
    } catch (e) {
      error = e.message;
    }
    try {
      const ts = await api.tailscaleStatus();
      tailscale = ts;
      tsError = ts.error || null;
    } catch (e) {
      tailscale = null;
      tsError = e.message;
    }
    try {
      qos = await api.qosStatus();
    } catch (e) {
      qos = null;
    }
    try {
      const resp = await fetch('/api/metrics');
      metricsText = await resp.text();
    } catch (_) { /* metrics optional */ }
  }

  async function doReconcile() {
    reloading = true;
    try {
      await api.reconcile();
      await refresh();
    } catch (e) {
      error = e.message;
    } finally {
      reloading = false;
    }
  }

  async function tsUp() {
    tsBusy = true;
    try {
      await api.tailscaleUp();
      await refresh();
    } catch (e) {
      tsError = e.message;
    } finally {
      tsBusy = false;
    }
  }

  async function tsDown() {
    tsBusy = true;
    try {
      await api.tailscaleDown();
      await refresh();
    } catch (e) {
      tsError = e.message;
    } finally {
      tsBusy = false;
    }
  }

  onMount(() => {
    refresh();
    pollTimer = setInterval(refresh, 5000);
    es = eventsStream(
      (ev) => { events = [ev, ...events].slice(0, 100); },
      (ok) => { connected = ok; }
    );
  });

  onDestroy(() => {
    if (pollTimer) clearInterval(pollTimer);
    if (es) es.close();
  });
</script>

<main>
  <h1>🛡️ BalanSir — Network Control</h1>

  {#if error}
    <div class="banner error">{error}</div>
  {/if}

  <div class="state-row">
    <div class="state-card {overallState().cls}">
      <div class="state-label">Network state</div>
      <div class="state-value">{overallState().label}</div>
    </div>
    <div class="state-card">
      <div class="state-label">Health</div>
      <div class="state-value">{health ? health.status : '…'}</div>
    </div>
    <div class="state-card">
      <div class="state-label">Drift</div>
      <div class="state-value">{drift ? drift.drift_count : '…'}</div>
    </div>
    <div class="state-card">
      <div class="state-label">Rules (desired/actual)</div>
      <div class="state-value">
        {desired ? desired.rule_count : '…'} / {actual ? actual.rule_count : '…'}
      </div>
    </div>
    <div class="state-card">
      <div class="state-label">Config fingerprint</div>
      <div class="state-value mono">
        {fingerprint ? Number(fingerprint.fingerprint ?? fingerprint).toString(16).slice(0, 10) : '…'}
      </div>
    </div>
    <div class="state-card">
      <div class="state-label">SSE</div>
      <div class="state-value">{connected ? '🟢 live' : '🔴 offline'}</div>
    </div>
  </div>

  <nav class="tabs">
    <button class:active={tab === 'overview'} on:click={() => tab = 'overview'}>Overview</button>
    <button class:active={tab === 'policy'} on:click={() => tab = 'policy'}>Policy</button>
    <button class:active={tab === 'qos'} on:click={() => tab = 'qos'}>QoS</button>
    <button class:active={tab === 'tailscale'} on:click={() => tab = 'tailscale'}>Tailscale</button>
    <button class:active={tab === 'events'} on:click={() => tab = 'events'}>Events</button>
    <button class:active={tab === 'metrics'} on:click={() => tab = 'metrics'}>Metrics</button>
  </nav>

  {#if tab === 'overview'}
    <section>
      <div class="grid">
        <div class="card">
          <h2>Desired state</h2>
          {#if desired}
            <p><strong>Rules:</strong> {desired.rule_count}</p>
            <p><strong>Drivers:</strong> {desired.drivers}</p>
            <ul>
              {#each desired.rules as rule}
                <li>#{rule.id} — {rule.action} <span class="prio">P{rule.priority}</span></li>
              {/each}
            </ul>
          {:else}<p>Loading…</p>{/if}
          <button on:click={doReconcile} disabled={reloading}>
            {reloading ? 'Reconciling…' : '🔄 Reconcile now'}
          </button>
        </div>

        <div class="card">
          <h2>Actual (kernel)</h2>
          {#if actual}
            <p><strong>Active rules:</strong> {actual.rule_count}</p>
            <ul>
              {#each actual.active_rules as rule}
                <li>#{rule.id} — {rule.action}</li>
              {/each}
            </ul>
          {:else}<p>Loading…</p>{/if}
        </div>

        <div class="card">
          <h2>Drift</h2>
          {#if drift}
            {#if drift.items.length === 0}
              <p class="healthy">No drift — desired matches actual.</p>
            {:else}
              {#each drift.items as item}
                <div class="drift-item">
                  <strong>#{item.rule_id}</strong> {item.kind}: {item.details}
                </div>
              {/each}
            {/if}
          {:else}<p>Loading…</p>{/if}
        </div>

        <div class="card">
          <h2>Reconciliation plan</h2>
          <pre>{plan ? plan.plan : 'Loading…'}</pre>
        </div>
      </div>

      <div class="card">
        <h2>Explain</h2>
        <pre>{explain ? explain.explain : 'Loading…'}</pre>
      </div>
    </section>
  {/if}

  {#if tab === 'policy'}
    <section>
      <div class="card">
        <h2>Policy rules</h2>
        {#if desired}
          <table>
            <thead><tr><th>ID</th><th>Action</th><th>Priority</th><th>Flow</th></tr></thead>
            <tbody>
              {#each desired.rules as rule}
                <tr>
                  <td>#{rule.id}</td>
                  <td>{rule.action}</td>
                  <td>{rule.priority}</td>
                  <td class="mono">{JSON.stringify(rule.flow)}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        {:else}<p>Loading…</p>{/if}
      </div>
      <div class="card">
        <h2>Explain</h2>
        <pre>{explain ? explain.explain : 'Loading…'}</pre>
      </div>
    </section>
  {/if}

  {#if tab === 'events'}
    <section>
      <div class="card">
        <h2>Event stream {connected ? '🟢' : '🔴'}</h2>
        {#if events.length === 0}<p>No events yet.</p>{/if}
        {#each events as event}
          <div class="event">
            <span class="e-type">{event.event_type}</span>
            <span class="e-details">{event.details}</span>
            <span class="e-time">{new Date(event.timestamp * 1000).toLocaleTimeString()}</span>
          </div>
        {/each}
      </div>
    </section>
  {/if}

  {#if tab === 'qos'}
    <section>
      <div class="card">
        <h2>QoS / Traffic shaping</h2>
        {#if qos}
          <h3>Desired plans</h3>
          {#if (qos.desired || []).length === 0}
            <p>No shaping desired.</p>
          {:else}
            {#each qos.desired as plan}
              <div class="qos-plan">
                <b>{plan.interface}</b>
                <span>default {Math.round((plan.default_rate_bits || 0) / 1000)} kbit / ceil {Math.round((plan.default_ceil_bits || 0) / 1000)} kbit</span>
                <span class="qos-classes">
                  {#each plan.classes as c}
                    <span class="qos-class">class {c.class_id}: {Math.round(c.rate_bits / 1000)} kbit ({Math.round(c.ceil_bits / 1000)} ceil)</span>
                  {/each}
                </span>
              </div>
            {/each}
          {/if}
          <h3>Applied on</h3>
          {#if (qos.applied || []).length === 0}
            <p>No interfaces currently shaped.</p>
          {:else}
            {#each qos.applied as iface}<span class="qos-applied">{iface}</span>{/each}
          {/if}
        {:else}
          <p>QoS status unavailable.</p>
        {/if}
      </div>
    </section>
  {/if}

  {#if tab === 'tailscale'}
    <section>
      <div class="card">
        <h2>Tailscale</h2>
        {#if tailscale}
          <div class="ts-grid">
            <div class="ts-item"><span>Installed</span><b>{tailscale.installed ? 'yes' : 'no'}</b></div>
            <div class="ts-item"><span>Backend</span><b>{tailscale.backend_state || '—'}</b></div>
            <div class="ts-item"><span>Node IP</span><b>{tailscale.self_ip || '—'}</b></div>
            <div class="ts-item"><span>Hostname</span><b>{tailscale.hostname || '—'}</b></div>
            <div class="ts-item"><span>Peers</span><b>{tailscale.peers ?? '—'}</b></div>
            <div class="ts-item"><span>Version</span><b>{tailscale.version || '—'}</b></div>
          </div>
          {#if tsError}
            <p class="error">{tsError}</p>
          {/if}
          <div class="ts-actions">
            <button on:click={tsUp} disabled={tsBusy}>⬆ Up (login flow)</button>
            <button on:click={tsDown} disabled={tsBusy}>⬇ Down</button>
          </div>
        {:else}
          <p>Tailscale not available (daemon offline or not installed).</p>
        {/if}
      </div>
    </section>
  {/if}

  {#if tab === 'metrics'}
    <section>
      <div class="card">
        <h2>Metrics (Prometheus)</h2>
        <pre class="metrics">{metricsText || 'Loading…'}</pre>
      </div>
    </section>
  {/if}

  <div class="footer">BalanSir v0.1.0 · operational console</div>
</main>

<style>
  main { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    max-width: 1200px; margin: 0 auto; padding: 20px; background: #1a1a2e; color: #eee; min-height: 100vh; }
  h1 { text-align: center; color: #4ecdc4; margin-bottom: 20px; }
  .banner { padding: 10px; border-radius: 8px; margin-bottom: 10px; }
  .banner.error { background: #5c2e2e; color: #ff6b6b; }
  .state-row { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin-bottom: 20px; }
  .state-card { background: #16213e; border-radius: 12px; padding: 16px; border: 1px solid #0f3460; text-align: center; }
  .state-label { font-size: 0.8em; color: #888; text-transform: uppercase; }
  .state-value { font-size: 1.3em; font-weight: bold; margin-top: 4px; }
  .mono { font-family: ui-monospace, Menlo, monospace; }
  .healthy { color: #4ecdc4; }
  .degraded { color: #f1c40f; }
  .error { color: #ff6b6b; }
  .unknown { color: #888; }
  .tabs { display: flex; gap: 8px; margin-bottom: 16px; }
  .tabs button { background: #16213e; border: 1px solid #0f3460; color: #aaa; padding: 8px 16px; border-radius: 8px; cursor: pointer; }
  .tabs button.active { background: #4ecdc4; color: #1a1a2e; font-weight: bold; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; margin-bottom: 16px; }
  .card { background: #16213e; border-radius: 12px; padding: 16px; border: 1px solid #0f3460; margin-bottom: 16px; }
  .card h2 { color: #4ecdc4; margin-top: 0; font-size: 1.1em; }
  .prio { background: #0f3460; padding: 2px 6px; border-radius: 4px; font-size: 0.8em; margin-left: 8px; }
  .drift-item { padding: 6px; border-bottom: 1px solid #0f3460; font-size: 0.9em; }
  pre { background: #0f3460; padding: 10px; border-radius: 8px; overflow-x: auto; font-size: 0.8em; max-height: 300px; overflow-y: auto; }
  pre.metrics { max-height: 400px; }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; padding: 6px 10px; border-bottom: 1px solid #0f3460; font-size: 0.9em; }
  th { color: #4ecdc4; }
  button { background: #4ecdc4; color: #1a1a2e; border: none; padding: 10px 20px; border-radius: 8px; cursor: pointer; font-weight: bold; margin-top: 8px; }
  button:hover { background: #45b7d1; }
  button:disabled { opacity: 0.6; cursor: default; }
  .event { padding: 8px; border-bottom: 1px solid #0f3460; font-size: 0.9em; }
  .e-type { font-weight: bold; color: #4ecdc4; margin-right: 8px; }
  .e-time { float: right; color: #888; font-size: 0.8em; }
  .ts-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; margin-bottom: 12px; }
  .ts-item { background: #0f3460; border-radius: 8px; padding: 10px; }
  .ts-item span { display: block; font-size: 0.8em; color: #888; }
  .ts-item b { font-size: 1.1em; }
  .ts-actions { display: flex; gap: 10px; }
  .qos-plan { background: #0f3460; border-radius: 8px; padding: 10px; margin-bottom: 8px; }
  .qos-plan b { display: block; margin-bottom: 4px; }
  .qos-classes { display: flex; gap: 6px; flex-wrap: wrap; margin-top: 6px; }
  .qos-class, .qos-applied { background: #1a237e; border-radius: 6px; padding: 4px 8px; font-size: 0.85em; }
  .qos-applied { background: #2e7d32; margin-right: 6px; }
  .footer { text-align: center; margin-top: 30px; color: #666; font-size: 0.9em; }
</style>
