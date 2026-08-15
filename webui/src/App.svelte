<script>
  import { onMount, onDestroy } from 'svelte';
  import { api, subsystemEventUrl, setToken, getToken } from './lib/api.js';
  import { systemStatus } from './lib/status.js';
  import StatusBadge from './components/StatusBadge.svelte';

  import Dashboard from './views/Dashboard.svelte';
  import Network from './views/Network.svelte';
  import Qos from './views/Qos.svelte';
  import B4 from './views/B4.svelte';
  import Dpi from './views/Dpi.svelte';
  import Xray from './views/Xray.svelte';
  import VpnPool from './views/VpnPool.svelte';
  import Tailscale from './views/Tailscale.svelte';
  import Policy from './views/Policy.svelte';
  import Events from './views/Events.svelte';
  import Diagnostics from './views/Diagnostics.svelte';

  export let view = 'dashboard';

  let health = null;
  let snapshot = null;
  let healthError = null;
  let sseState = 'connecting';
  let es = null;
  let reconnectDelay = 1000;
  let lastEventAt = null;
  let refreshTimer = null;
  let tokenInput = getToken();
  $: unauthorized = (healthError || '').includes('401');

  function saveToken() {
    setToken(tokenInput);
    refreshAll();
  }

  const views = [
    { id: 'dashboard', label: 'Dashboard', component: Dashboard },
    { id: 'network', label: 'Network', component: Network },
    { id: 'policy', label: 'Policy', component: Policy },
    { id: 'qos', label: 'QoS', component: Qos },
    { id: 'b4', label: 'B4', component: B4 },
    { id: 'dpi', label: 'DPI', component: Dpi },
    { id: 'xray', label: 'Xray', component: Xray },
    { id: 'vpn', label: 'VPN Pool', component: VpnPool },
    { id: 'tailscale', label: 'Tailscale', component: Tailscale },
    { id: 'events', label: 'Events', component: Events },
    { id: 'diagnostics', label: 'Diagnostics', component: Diagnostics },
  ];

  $: overall = systemStatus(snapshot, health);
  $: activeView = views.find((v) => v.id === view);

  async function refreshAll() {
    try {
      health = await api.health();
      healthError = null;
    } catch (e) {
      healthError = e.message;
    }
    try {
      snapshot = await api.subsystems();
    } catch (e) {
      healthError = healthError || `subsystems: ${e.message}`;
    }
  }

  function connectSSE() {
    es = new EventSource(subsystemEventUrl());
    es.onopen = () => {
      sseState = 'connected';
      reconnectDelay = 1000;
    };
    es.onmessage = () => {
      lastEventAt = new Date();
      refreshAll();
    };
    es.onerror = () => {
      sseState = 'disconnected';
      es.close();
      setTimeout(connectSSE, reconnectDelay);
      reconnectDelay = Math.min(reconnectDelay * 2, 15000);
    };
  }

  onMount(() => {
    refreshAll();
    connectSSE();
    refreshTimer = setInterval(() => {
      if (Date.now() - (lastEventAt ? lastEventAt.getTime() : 0) > 15000) {
        refreshAll();
      }
    }, 10000);
  });

  onDestroy(() => {
    if (es) es.close();
    if (refreshTimer) clearInterval(refreshTimer);
  });
</script>

<main>
  <header class="topbar">
    <div class="brand">
      <span class="logo">🛡️</span>
      <div>
        <h1>BalanSir</h1>
        <p class="subtitle">
          Network policy &amp; control platform
          {#if health}
            <span class="ver">v{health.version}</span>
          {/if}
        </p>
      </div>
    </div>
    <div class="topbar-right">
      <span class="sse {sseState}">● SSE {sseState}</span>
      <StatusBadge status={overall.status} title={overall.title} />
    </div>
  </header>

  {#if healthError}
    <div class="banner banner-error">
      ⚠ API unreachable — {healthError}
      <button on:click={refreshAll}>Retry</button>
    </div>
  {/if}

  {#if unauthorized}
    <div class="banner banner-error token-banner">
      <label>API token
        <input type="password" bind:value={tokenInput} placeholder="bearer token" />
      </label>
      <button on:click={saveToken}>Save</button>
      <span class="hint">Stored in your browser only; used for API requests.</span>
    </div>
  {/if}

  <nav class="tabs">
    {#each views as v}
      <button class:active={view === v.id} on:click={() => (view = v.id)}>
        {v.label}
      </button>
    {/each}
  </nav>

  <section class="content">
    <svelte:component this={activeView.component}
      {health}
      {snapshot}
      {overall}
      {healthError}
      {sseState}
    />
  </section>
</main>

<style>
  :global(body) {
    margin: 0;
    background: #0f1524;
    color: #e8ecf4;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  }
  main { max-width: 1280px; margin: 0 auto; padding: 16px 20px 60px; }
  .topbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding-bottom: 12px;
    border-bottom: 1px solid #1f2a44;
  }
  .brand { display: flex; gap: 12px; align-items: center; }
  .logo { font-size: 28px; }
  h1 { margin: 0; font-size: 1.4rem; color: #4ecdc4; }
  .subtitle { margin: 0; color: #7a8aa5; font-size: 0.85rem; }
  .ver { color: #4a5a75; margin-left: 6px; }
  .topbar-right { display: flex; align-items: center; gap: 14px; }
  .sse { font-size: 0.75rem; color: #7a8aa5; }
  .sse.connected { color: #4cd07d; }
  .sse.disconnected { color: #ff6b6b; }
  .banner {
    margin: 12px 0; padding: 10px 14px; border-radius: 8px; font-size: 0.9rem;
  }
  .banner-error { background: #3a1513; color: #ff9c9c; }
  .token-banner { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
  .token-banner label { display: flex; gap: 8px; align-items: center; font-size: 0.85rem; }
  .token-banner input { background: #0f1524; color: #e8ecf4; border: 1px solid #4a1210; border-radius: 6px; padding: 6px 10px; }
  .token-banner .hint { color: #7a8aa5; font-size: 0.75rem; }
  .tabs {
    display: flex; gap: 4px; margin: 14px 0; flex-wrap: wrap;
  }
  .tabs button {
    background: transparent; color: #9fb0cc; border: 1px solid #1f2a44;
    padding: 7px 16px; border-radius: 8px; cursor: pointer; font-size: 0.9rem;
  }
  .tabs button:hover { border-color: #3a4a6a; }
  .tabs button.active {
    background: #123b2a; color: #4cd07d; border-color: #1e5c3d;
  }
  .content { margin-top: 8px; }
</style>
