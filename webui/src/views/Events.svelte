<script>
  import { onMount, onDestroy } from 'svelte';
  import { api, subsystemEventUrl } from '../lib/api.js';

  export let sseState;

  let events = [];
  let subsystemEvents = [];
  let limit = 200;

  async function loadHistory() {
    try {
      const list = await api.events();
      events = Array.isArray(list) ? list.slice(-limit).reverse() : [];
    } catch (e) {
      events = [{ timestamp: Date.now() / 1000, event_type: 'error', details: `Cannot load history: ${e.message}` }];
    }
  }

  let es = null;
  let reconnectDelay = 1000;

  function connect() {
    es = new EventSource(subsystemEventUrl());
    es.onopen = () => (reconnectDelay = 1000);
    es.onmessage = (event) => {
      let payload = {};
      try { payload = JSON.parse(event.data); } catch (e) { /* keep raw */ }
      subsystemEvents = [
        {
          timestamp: Date.now() / 1000,
          event_type: event.type || 'message',
          details: JSON.stringify(payload),
        },
        ...subsystemEvents,
      ].slice(0, 100);
    };
    es.onerror = () => {
      es.close();
      setTimeout(connect, reconnectDelay);
      reconnectDelay = Math.min(reconnectDelay * 2, 15000);
    };
  }

  onMount(() => {
    loadHistory();
    connect();
    const t = setInterval(loadHistory, 30000);
    return () => { clearInterval(t); };
  });

  onDestroy(() => { if (es) es.close(); });

  function time(ts) {
    return new Date(ts * 1000).toLocaleTimeString();
  }
</script>

<h2>Events &amp; Diagnostics</h2>

<p class="sse-line">Live SSE stream: <span class:connected={sseState === 'connected'}>{sseState}</span>
  — subsystem events appear instantly; the log below is the persisted event history.
</p>

{#if subsystemEvents.length}
  <section class="card">
    <h3>Live subsystem events</h3>
    <div class="list">
      {#each subsystemEvents as e}
        <div class="event">
          <span class="type">{e.event_type}</span>
          <span class="details">{e.details}</span>
          <span class="time">{time(e.timestamp)}</span>
        </div>
      {/each}
    </div>
  </section>
{/if}

<section class="card">
  <h3>Event history</h3>
  <div class="list">
    {#each events as e}
      <div class="event">
        <span class="type">{e.event_type}</span>
        <span class="details">{e.details}</span>
        <span class="time">{time(e.timestamp)}</span>
      </div>
    {:else}
      <p class="empty">No events recorded yet</p>
    {/each}
  </div>
</section>

<style>
  h2 { color: #4ecdc4; font-size: 1.05rem; }
  .sse-line { color: #7a8aa5; font-size: 0.85rem; }
  .sse-line span.connected { color: #4cd07d; }
  .card { background: #16213e; border: 1px solid #0f3460; border-radius: 12px; padding: 14px; margin-bottom: 14px; }
  .card h3 { margin: 0 0 10px; color: #4ecdc4; font-size: 0.9rem; }
  .list { max-height: 420px; overflow-y: auto; }
  .event { padding: 7px 8px; border-bottom: 1px solid #0f3460; font-size: 0.85rem; display: flex; gap: 10px; align-items: baseline; }
  .type { font-weight: 700; color: #4ecdc4; min-width: 130px; }
  .details { color: #a8b6cc; flex: 1; word-break: break-all; font-family: monospace; font-size: 0.78rem; }
  .time { color: #5a6a85; font-size: 0.75rem; white-space: nowrap; }
  .empty { color: #5a6a85; font-size: 0.85rem; }
</style>
