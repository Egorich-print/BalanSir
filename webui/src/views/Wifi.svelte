<script>
  import { api } from '../lib/api.js';
  import StatusBadge from '../components/StatusBadge.svelte';

  export let snapshot;
  export let healthError;

  $: wifi = snapshot ? snapshot.wifi : null;
  $: ifaces = wifi ? wifi.interfaces : [];
  $: states = wifi ? (wifi.states || []) : [];

  function stateOf(iface) {
    const s = states.find(([name]) => name === iface);
    return s ? s[1] : 'unknown';
  }

  let busy = false;
  let notice = '';
  let selectedIface = '';
  let ssid = '';
  let password = '';
  let identity = '';
  let security = '';

  async function scan() {
    busy = true;
    notice = '';
    try {
      const r = await api.wifiScan(selectedIface);
      notice = r.detail || `Scanned ${r.networks.length} networks`;
    } catch (e) {
      notice = `Scan failed: ${e.message}`;
    }
    busy = false;
  }

  async function connect() {
    busy = true;
    notice = '';
    const body = { interface: selectedIface, ssid };
    if (password) body.password = password;
    if (identity) body.identity = identity;
    if (security) body.security = security;
    try {
      const r = await api.wifiConnect(body);
      notice = r.detail || 'Connect initiated';
    } catch (e) {
      notice = `Connect failed: ${e.message}`;
    }
    busy = false;
  }

  async function disconnect() {
    busy = true;
    notice = '';
    try {
      const r = await api.wifiDisconnect(selectedIface);
      notice = r.detail || 'Disconnected';
    } catch (e) {
      notice = `Disconnect failed: ${e.message}`;
    }
    busy = false;
  }
</script>

<div class="panel">
  <h2>Wi-Fi (USB / external adapters)</h2>

  {#if !snapshot}
    <p class="muted">Loading…</p>
  {:else if !wifi}
    <p class="muted">No Wi-Fi data yet.</p>
  {:else}
    <div class="ifaces">
      {#if ifaces.length === 0}
        <p class="muted">No Wi-Fi interfaces detected. Plug in a USB Wi-Fi adapter
          (TP-Link TL-WN727N, RTL8188-based, MT76, …) and refresh.</p>
      {:else}
        {#each ifaces as iface}
          <div class="iface">
            <span class="name">{iface}</span>
            <StatusBadge status={stateOf(iface) === 'connected' ? 'healthy' : 'disabled'}
              title={stateOf(iface)} />
          </div>
        {/each}
        <div class="controls">
          <label>Interface
            <select bind:value={selectedIface}>
              {#each ifaces as iface}
                <option value={iface}>{iface}</option>
              {/each}
            </select>
          </label>
          <button on:click={scan} disabled={busy}>Scan</button>
          <button on:click={disconnect} disabled={busy}>Disconnect</button>
        </div>
      {/if}
    </div>

    <div class="connect">
      <h3>Connect</h3>
      <label>SSID <input type="text" bind:value={ssid} /></label>
      <label>Password (empty = open) <input type="password" bind:value={password} /></label>
      <label>Identity (EAP username) <input type="text" bind:value={identity} /></label>
      <label>Security (auto-detect if empty)
        <select bind:value={security}>
          <option value="">auto</option>
          <option value="open">open</option>
          <option value="wpa">wpa</option>
          <option value="wpa2">wpa2</option>
          <option value="wpa3">wpa3</option>
          <option value="eap">eap (PEAP/MSCHAPv2)</option>
        </select>
      </label>
      <button on:click={connect} disabled={busy || !selectedIface || !ssid}>Connect</button>
      {#if notice}
        <p class="notice">{notice}</p>
      {/if}
    </div>

    {#if wifi.networks && wifi.networks.length}
      <h3>Scan results</h3>
      <table class="nets">
        <thead>
          <tr><th>SSID</th><th>BSSID</th><th>Signal</th><th>Freq</th><th>Security</th><th></th></tr>
        </thead>
        <tbody>
          {#each wifi.networks as n}
            <tr>
              <td>{n.ssid || '&lt;hidden&gt;'}</td>
              <td class="muted small">{n.bssid || '—'}</td>
              <td>{n.signal_dbm} dBm</td>
              <td>{n.freq_mhz || '—'} MHz</td>
              <td>{n.security || 'open'}</td>
              <td>{n.selected ? '✓ connected' : ''}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}

    {#if wifi.last_error}
      <p class="error">Last error: {wifi.last_error}</p>
    {/if}
  {/if}

  {#if healthError}
    <p class="error">{healthError}</p>
  {/if}
</div>

<style>
  .panel { padding: 4px 0; }
  h2 { color: #4ecdc4; font-size: 1.05rem; }
  h3 { margin: 16px 0 8px; font-size: 0.95rem; color: #e8ecf4; }
  .muted { color: #888; }
  .small { font-size: 0.85em; }
  .iface { display: flex; align-items: center; gap: 10px; padding: 6px 0; }
  .name { font-weight: 600; }
  .controls { display: flex; gap: 10px; align-items: center; margin: 10px 0; flex-wrap: wrap; }
  .controls label, .connect label { display: flex; flex-direction: column; gap: 4px; font-size: 0.85em; color: #7a8aa5; }
  .controls select, .connect input, .connect select {
    background: #0f1a30; color: #e8ecf4; border: 1px solid #1f2a44;
    border-radius: 6px; padding: 7px 10px; min-width: 200px;
  }
  button {
    background: #0f3460; color: #e8ecf4; border: 1px solid #1f2a44;
    border-radius: 6px; padding: 7px 14px; cursor: pointer;
  }
  button:disabled { opacity: 0.5; cursor: default; }
  .connect { display: flex; flex-direction: column; gap: 10px; max-width: 340px; }
  .nets { width: 100%; border-collapse: collapse; font-size: 0.88em; }
  .nets th, .nets td { text-align: left; padding: 6px 8px; border-bottom: 1px solid #1f2a44; }
  .nets th { color: #7a8aa5; font-weight: 600; }
  .notice { color: #4ecdc4; font-size: 0.9em; }
  .error { color: #ff8a80; }
</style>