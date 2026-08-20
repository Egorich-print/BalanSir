<script>
  import { onMount } from 'svelte';
  import { api } from '../lib/api.js';

  export let healthError;

  let desired = null;
  let actual = null;
  let state = null;
  let busy = false;
  let notice = '';

  async function load() {
    try {
      [desired, actual, state] = await Promise.all([
        api.desired(),
        api.actual(),
        api.state(),
      ]);
    } catch (e) {
      notice = `Cannot load policy state: ${e.message}`;
    }
  }

  async function reconcile() {
    busy = true;
    notice = '';
    try {
      await api.reconcile();
      notice = 'Reconciliation triggered';
      await load();
    } catch (e) {
      notice = `Reconcile failed: ${e.message}`;
    }
    busy = false;
  }

  onMount(load);
</script>

<h2>Policy</h2>

{#if healthError}<p class="err">Cannot reach the daemon: {healthError}</p>{/if}
{#if notice}<p class="notice">{notice}</p>{/if}

<div class="grid">
  <section class="card">
    <h3>Desired state ({desired ? desired.rule_count : '…'} rules)</h3>
    {#if desired && desired.error}
      <p class="err">{desired.error}</p>
    {/if}
    {#if desired && desired.rules.length}
      <table>
        <thead><tr><th>ID</th><th>Action</th><th>Priority</th></tr></thead>
        <tbody>
          {#each desired.rules as r}
            <tr>
              <td>#{r.id}</td>
              <td>{r.action}</td>
              <td>P{r.priority}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    {:else}
      <p class="empty">No desired rules configured</p>
    {/if}
    <button on:click={reconcile} disabled={busy}>🔄 Reconcile now</button>
  </section>

  <section class="card">
    <h3>Actual state</h3>
    {#if actual && actual.error}
      <p class="err">{actual.error}</p>
    {/if}
    {#if actual && actual.rules && actual.rules.length}
      <table>
        <thead><tr><th>ID</th><th>Action</th><th>Priority</th></tr></thead>
        <tbody>
          {#each actual.rules as r}
            <tr><td>#{r.id}</td><td>{r.action}</td><td>{r.priority != null ? `P${r.priority}` : '—'}</td></tr>
          {/each}
        </tbody>
      </table>
    {:else}
      <p class="empty">No actual rules reported</p>
    {/if}
  </section>
</div>

{#if state}
  <section class="card">
    <h3>Engine state</h3>
    <pre class="raw">{JSON.stringify(state, null, 2)}</pre>
  </section>
{/if}

<style>
  h2 { color: #4ecdc4; font-size: 1.05rem; }
  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
  @media (max-width: 900px) { .grid { grid-template-columns: 1fr; } }
  .card { background: #16213e; border: 1px solid #0f3460; border-radius: 12px; padding: 14px; margin-bottom: 14px; overflow-x: auto; }
  .card h3 { margin: 0 0 10px; color: #4ecdc4; font-size: 0.9rem; }
  table { width: 100%; border-collapse: collapse; font-size: 0.84rem; }
  th, td { padding: 8px 10px; text-align: left; border-bottom: 1px solid #0f3460; white-space: nowrap; }
  th { color: #7a8aa5; font-size: 0.72rem; text-transform: uppercase; }
  .empty { color: #5a6a85; font-size: 0.85rem; }
  .err { color: #ff6b6b; font-size: 0.85rem; }
  .notice { color: #4cd07d; font-size: 0.85rem; }
  button { background: #4ecdc4; color: #0f1524; border: none; border-radius: 6px; padding: 8px 16px; font-weight: 700; cursor: pointer; margin-top: 10px; }
  button:disabled { opacity: 0.5; cursor: default; }
  .raw { background: #0f1524; border-radius: 8px; padding: 12px; font-size: 0.78rem; overflow-x: auto; color: #9fb0cc; }
</style>
