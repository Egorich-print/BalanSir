<script>
  import { onMount } from 'svelte';
  import { api } from '../lib/api.js';

  export let health;
  export let snapshot;
  export let healthError;

  let metricsText = '';
  let metricsError = '';

  async function loadMetrics() {
    try {
      metricsText = await api.metrics();
      metricsError = '';
    } catch (e) {
      metricsError = e.message;
    }
  }

  onMount(loadMetrics);
</script>

<h2>Diagnostics</h2>

{#if healthError}<p class="err">API unreachable: {healthError}</p>{/if}

<div class="grid">
  <section class="card">
    <h3>Health</h3>
    <pre class="raw">{JSON.stringify(health, null, 2) || '…'}</pre>
  </section>

  <section class="card">
    <h3>Unified subsystem snapshot</h3>
    <pre class="raw">{JSON.stringify(snapshot, null, 2) || '…'}</pre>
  </section>
</div>

<section class="card">
  <h3>Prometheus metrics <button class="mini" on:click={loadMetrics}>refresh</button></h3>
  {#if metricsError}<p class="err">{metricsError}</p>{/if}
  <pre class="raw metrics">{metricsText || '…'}</pre>
</section>

<style>
  h2 { color: #4ecdc4; font-size: 1.05rem; }
  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
  @media (max-width: 900px) { .grid { grid-template-columns: 1fr; } }
  .card { background: #16213e; border: 1px solid #0f3460; border-radius: 12px; padding: 14px; margin-bottom: 14px; }
  .card h3 { margin: 0 0 10px; color: #4ecdc4; font-size: 0.9rem; }
  .raw { background: #0f1524; border-radius: 8px; padding: 12px; font-size: 0.76rem; overflow-x: auto; color: #9fb0cc; max-height: 480px; overflow-y: auto; }
  .metrics { white-space: pre-wrap; }
  .err { color: #ff6b6b; font-size: 0.85rem; }
  .mini { background: #1f2a44; color: #9fb0cc; border: none; border-radius: 4px; padding: 2px 8px; font-size: 0.72rem; cursor: pointer; margin-left: 8px; }
</style>
