<script>
  import { onMount } from 'svelte';
  import { api } from '../lib/api.js';

  let ota = null;
  let error = null;
  let actionInProgress = false;

  async function refresh() {
    try {
      ota = await api.otaStatus();
      error = null;
    } catch (e) {
      error = e.message;
    }
  }

  async function bootConfirm() {
    if (!confirm('Confirm this boot as healthy?')) return;
    actionInProgress = true;
    try {
      await api.otaBootConfirm();
      await refresh();
    } catch (e) { error = e.message; }
    actionInProgress = false;
  }

  async function rollback() {
    if (!confirm('Force rollback to the previous slot? The device will reboot.')) return;
    actionInProgress = true;
    try {
      await api.otaRollback();
      await refresh();
    } catch (e) { error = e.message; }
    actionInProgress = false;
  }

  onMount(() => { refresh(); });
</script>

<div class="ota-view">
  <div class="grid">
    <section class="panel">
      <header><h2>OTA Status</h2></header>
      {#if error}
        <p class="error">{error}</p>
      {:else if !ota || !ota.available}
        <p class="muted">OTA subsystem not available.</p>
      {:else}
        <table>
          <tr><td>Current slot</td><td><strong>{ota.currentSlot}</strong></td></tr>
          <tr><td>Next slot</td><td>{ota.nextSlot}</td></tr>
          <tr><td>State</td><td><span class="badge state-{(ota.state || '').toLowerCase()}">{ota.state}</span></td></tr>
          <tr><td>Active version</td><td>{ota.activeVersion || '—'}</td></tr>
          {#if ota.nextVersion}
            <tr><td>Candidate version</td><td>{ota.nextVersion}</td></tr>
          {/if}
          <tr><td>Rollback count</td><td>{ota.rollbackCount}</td></tr>
          {#if ota.lastRollbackReason}
            <tr><td>Last rollback</td><td class="warn">{ota.lastRollbackReason}</td></tr>
          {/if}
          <tr><td>Tries remaining</td><td>{ota.triesRemaining}</td></tr>
        </table>

        <div class="actions">
          {#if ota.state === 'Trying' || ota.state === 'Pending'}
            <button class="btn confirm" on:click={bootConfirm} disabled={actionInProgress}>
              ✓ Confirm Boot
            </button>
          {/if}
          {#if ota.currentSlot !== ota.nextSlot || ota.state !== 'Confirmed'}
            <button class="btn danger" on:click={rollback} disabled={actionInProgress}>
              ⟲ Rollback
            </button>
          {/if}
        </div>
      {/if}
    </section>
  </div>
</div>

<style>
  .ota-view { display: flex; flex-direction: column; gap: 16px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 16px; }
  .panel { background: #141c2e; border: 1px solid #1f2a44; border-radius: 10px; padding: 16px; }
  .panel header { margin-bottom: 12px; padding-bottom: 8px; border-bottom: 1px solid #1f2a44; }
  .panel h2 { margin: 0; font-size: 1rem; color: #4ecdc4; }
  table { width: 100%; border-collapse: collapse; font-size: 0.88rem; }
  td { padding: 6px 8px; border-bottom: 1px solid #1f2a44; color: #a8b6cc; }
  td:first-child { color: #7a8aa5; min-width: 130px; }
  td strong { color: #4ecdc4; }
  .badge { padding: 2px 8px; border-radius: 4px; font-weight: 600; font-size: 0.8rem; }
  .state-confirmed { background: #1f3d2b; color: #5fdba7; }
  .state-pending, .state-trying { background: #3d331f; color: #f5c26b; }
  .state-rolling_back { background: #3d1f1f; color: #ff6b6b; }
  .actions { margin-top: 14px; display: flex; gap: 8px; flex-wrap: wrap; }
  .btn { padding: 8px 16px; border-radius: 6px; border: none; cursor: pointer; font-weight: 600; font-size: 0.85rem; }
  .btn.confirm { background: #1f3d2b; color: #5fdba7; }
  .btn.danger { background: #3d1f1f; color: #ff6b6b; }
  .btn:disabled { opacity: 0.5; cursor: wait; }
  .muted { color: #7a8aa5; }
  .error { color: #ff6b6b; }
  .warn { color: #f5c26b; }
</style>
