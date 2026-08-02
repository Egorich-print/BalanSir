<script>
  let health = null;
  let metrics = '';
  let desired = null;
  let events = [];
  let connected = false;
  let eventSource = null;

  async function fetchHealth() {
    try {
      const resp = await fetch('/health');
      health = await resp.json();
    } catch (e) {
      health = { status: 'error', error: e.message };
    }
  }

  async function fetchMetrics() {
    try {
      const resp = await fetch('/metrics');
      metrics = await resp.text();
    } catch (e) {
      metrics = 'Error loading metrics';
    }
  }

  async function fetchDesired() {
    try {
      const resp = await fetch('/desired');
      desired = await resp.json();
    } catch (e) {
      desired = { rules: [], rule_count: 0 };
    }
  }

  function connectSSE() {
    eventSource = new EventSource('/events/stream');
    eventSource.onmessage = (event) => {
      const data = JSON.parse(event.data);
      events = [data, ...events].slice(0, 50);
    };
    eventSource.onopen = () => { connected = true; };
    eventSource.onerror = () => { connected = false; };
  }

  async function triggerReconcile() {
    await fetch('/reconcile', { method: 'POST' });
    await fetchDesired();
  }

  // Initial load
  fetchHealth();
  fetchMetrics();
  fetchDesired();
  connectSSE();
</script>

<main>
  <h1>🛡️ BalanSir Dashboard</h1>
  
  <div class="grid">
    <div class="card">
      <h2>Health</h2>
      {#if health}
        <p class:healthy={health.status === 'ok'} class:error={health.status !== 'ok'}>
          Status: {health.status}
        </p>
        <p>Version: {health.version}</p>
        <p>Uptime: {health.uptime_seconds}s</p>
      {:else}
        <p>Loading...</p>
      {/if}
    </div>

    <div class="card">
      <h2>Events</h2>
      <p class:connected>
        SSE: {connected ? '🟢 Connected' : '🔴 Disconnected'}
      </p>
      <div class="event-list">
        {#each events as event}
          <div class="event">
            <span class="event-type">{event.event_type}</span>
            <span class="event-details">{event.details}</span>
            <span class="event-time">{new Date(event.timestamp * 1000).toLocaleTimeString()}</span>
          </div>
        {/each}
        {#if events.length === 0}
          <p>No events yet</p>
        {/if}
      </div>
    </div>

    <div class="card">
      <h2>Desired State</h2>
      {#if desired}
        <p>Rules: {desired.rule_count}</p>
        <ul>
          {#each desired.rules as rule}
            <li>
              <strong>#{rule.id}</strong> - {rule.action}
              <span class="priority">P{rule.priority}</span>
            </li>
          {/each}
        </ul>
      {:else}
        <p>Loading...</p>
      {/if}
      <button on:click={triggerReconcile}>🔄 Reconcile</button>
    </div>

    <div class="card metrics">
      <h2>Metrics</h2>
      <pre>{metrics}</pre>
    </div>
  </div>

  <div class="footer">
    <p>BalanSir v0.1.0 | Network Policy Engine</p>
  </div>
</main>

<style>
  main {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    max-width: 1200px;
    margin: 0 auto;
    padding: 20px;
    background: #1a1a2e;
    color: #eee;
    min-height: 100vh;
  }

  h1 {
    text-align: center;
    color: #4ecdc4;
    margin-bottom: 30px;
  }

  .grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 20px;
  }

  .card {
    background: #16213e;
    border-radius: 12px;
    padding: 20px;
    border: 1px solid #0f3460;
  }

  .card h2 {
    color: #4ecdc4;
    margin-top: 0;
    font-size: 1.2em;
  }

  .healthy { color: #4ecdc4; }
  .error { color: #ff6b6b; }
  .connected { color: #4ecdc4; }

  .event-list {
    max-height: 300px;
    overflow-y: auto;
  }

  .event {
    padding: 8px;
    border-bottom: 1px solid #0f3460;
    font-size: 0.9em;
  }

  .event-type {
    font-weight: bold;
    color: #4ecdc4;
    margin-right: 8px;
  }

  .event-time {
    float: right;
    color: #888;
    font-size: 0.8em;
  }

  .priority {
    background: #0f3460;
    padding: 2px 6px;
    border-radius: 4px;
    font-size: 0.8em;
    margin-left: 8px;
  }

  .metrics pre {
    background: #0f3460;
    padding: 10px;
    border-radius: 8px;
    overflow-x: auto;
    font-size: 0.8em;
    max-height: 300px;
  }

  button {
    background: #4ecdc4;
    color: #1a1a2e;
    border: none;
    padding: 10px 20px;
    border-radius: 8px;
    cursor: pointer;
    font-weight: bold;
    margin-top: 10px;
  }

  button:hover {
    background: #45b7d1;
  }

  .footer {
    text-align: center;
    margin-top: 40px;
    color: #666;
    font-size: 0.9em;
  }
</style>
