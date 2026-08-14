<script>
  import { api, fmtBytes } from '../lib/api.js';

  export let snapshot;
  export let healthError;

  let action = {};
  let macInput = {};

  async function restoreMac(iface) {
    action[iface.name] = 'working';
    try {
      await api.restoreMac(iface.name);
      action[iface.name] = 'ok';
    } catch (e) {
      action[iface.name] = e.message;
    }
    setTimeout(() => (action[iface.name] = ''), 3000);
  }

  async function applyCloneMac(iface) {
    const mac = (macInput[iface.name] || '').trim().toLowerCase();
    if (!/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(mac)) {
      action[iface.name] = 'invalid MAC (expected aa:bb:cc:dd:ee:ff)';
      return;
    }
    action[iface.name] = 'working';
    try {
      await api.setMac(iface.name, mac);
      action[iface.name] = 'ok';
      macInput[iface.name] = '';
    } catch (e) {
      action[iface.name] = e.message;
    }
    setTimeout(() => (action[iface.name] = ''), 4000);
  }

  $: interfaces = snapshot ? snapshot.interfaces : [];
  $: wan = snapshot ? snapshot.wan_identity : null;
</script>

<h2>WAN Identity</h2>

{#if healthError}
  <p class="err">Cannot reach the daemon: {healthError}</p>
{/if}

{#if wan}
  <div class="wan-card">
    <div class="wan-head">
      <strong>{wan.interface}</strong>
      <span class="wan-link {wan.link_up ? 'up' : 'down'}">{wan.link_up ? 'LINK UP' : 'LINK DOWN'}</span>
      {#if wan.cloning_active}
        <span class="tag clone-tag">MAC CLONING ACTIVE</span>
      {/if}
    </div>
    <div class="wan-grid">
      <div class="wan-item">
        <span class="wan-label">Hardware MAC</span>
        <code>{wan.hardware_mac || '—'}</code>
        <span class="wan-hint">factory address, never overwritten</span>
      </div>
      <div class="wan-item">
        <span class="wan-label">Current MAC</span>
        <code>{wan.current_mac || '—'}</code>
        <span class="wan-hint">{wan.cloning_active ? 'cloned — presents as the previous CPE' : 'matches hardware'}</span>
      </div>
      <div class="wan-item">
        <span class="wan-label">Configured MAC</span>
        <code>{wan.configured_mac || '—'}</code>
        <span class="wan-hint">operator-requested clone target</span>
      </div>
      <div class="wan-item">
        <span class="wan-label">MTU</span>
        <code>{wan.mtu}</code>
      </div>
      <div class="wan-item">
        <span class="wan-label">DHCP</span>
        <code>{wan.dhcp.observed ? 'observed' : 'not observed'}</code>
        <span class="wan-hint">
          {#if wan.dhcp.ip}IP {wan.dhcp.ip}{/if}
          {#if wan.dhcp.gateway} · gateway {wan.dhcp.gateway}{/if}
          {#if !wan.dhcp.ip && !wan.dhcp.gateway}no lease observed yet{/if}
        </span>
      </div>
    </div>
  </div>
{:else}
  <div class="wan-card empty">No WAN interface detected (no default route and no WAN pinned).</div>
{/if}

<h2>Network Interfaces</h2>

<div class="wrap">
  <table>
    <thead>
      <tr>
        <th>Interface</th>
        <th>State</th>
        <th>MAC</th>
        <th>MTU</th>
        <th>Speed</th>
        <th>Addresses</th>
        <th>RX</th>
        <th>TX</th>
        <th>Errors</th>
        <th>Dropped</th>
      </tr>
    </thead>
    <tbody>
      {#each interfaces as iface}
        <tr>
          <td>
            <strong>{iface.name}</strong>
            {#if iface.qdisc}<span class="tag">{iface.qdisc}</span>{/if}
          </td>
          <td>
            <span class:up={iface.link_up} class:down={!iface.link_up}>
              {iface.link_up ? 'UP' : 'DOWN'}
            </span>
            {#if iface.oper_state}<span class="sub">{iface.oper_state}</span>{/if}
          </td>
          <td>
            {iface.mac || '—'}
            {#if iface.hardware_mac && iface.hardware_mac !== iface.mac}
              <span class="sub" title="factory MAC">hw {iface.hardware_mac}</span>
            {/if}
            {#if iface.previous_mac}
              <span class="sub" title="MAC before last clone">prev {iface.previous_mac}</span>
            {/if}
            {#if iface.mac}
              {#if action[iface.name] === 'working'}<span class="sub">working…</span>
              {:else if action[iface.name] === 'ok'}<span class="ok">ok</span>
              {:else if action[iface.name]}<span class="err">{action[iface.name]}</span>
              {:else}
                <div class="mac-ctl">
                  <input
                    type="text"
                    placeholder="aa:bb:cc:dd:ee:ff"
                    value={macInput[iface.name] || ''}
                    on:input={(e) => (macInput[iface.name] = e.target.value)}
                  />
                  <button class="link" on:click={() => applyCloneMac(iface)}>clone</button>
                  <button class="link" on:click={() => restoreMac(iface)}>restore</button>
                </div>
              {/if}
            {/if}
          </td>
          <td>{iface.mtu}</td>
          <td>{iface.speed_mbps ? `${iface.speed_mbps} Mb/s` : '—'}</td>
          <td class="addr-cell">
            {#each iface.ipv4 as ip}<span class="addr">{ip}</span>{/each}
            {#each iface.ipv6 as ip}<span class="addr ipv6">{ip}</span>{/each}
          </td>
          <td>{fmtBytes(iface.rx_bytes)}<span class="sub">({iface.rx_packets} pkt)</span></td>
          <td>{fmtBytes(iface.tx_bytes)}<span class="sub">({iface.tx_packets} pkt)</span></td>
          <td>{iface.rx_errors + iface.tx_errors}</td>
          <td>{iface.rx_dropped + iface.tx_dropped}</td>
        </tr>
      {:else}
        <tr><td colspan="10" class="empty">No interfaces reported</td></tr>
      {/each}
    </tbody>
  </table>
</div>

<style>
  .wrap { overflow-x: auto; background: #16213e; border: 1px solid #0f3460; border-radius: 12px; }
  table { width: 100%; border-collapse: collapse; font-size: 0.86rem; min-width: 900px; }
  th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid #0f3460; white-space: nowrap; }
  th { color: #7a8aa5; font-size: 0.75rem; text-transform: uppercase; }
  tr:last-child td { border-bottom: 0; }
  .up { color: #4cd07d; font-weight: 700; }
  .down { color: #ff6b6b; font-weight: 700; }
  .sub { color: #5a6a85; font-size: 0.78rem; margin-left: 6px; }
  .tag { background: #0f3460; color: #4cc9f0; border-radius: 4px; padding: 1px 6px; font-size: 0.72rem; margin-left: 6px; }
  .addr { display: inline-block; margin: 2px 6px 0 0; background: #0f1524; border-radius: 4px; padding: 1px 6px; font-size: 0.78rem; }
  .addr.ipv6 { color: #c77dff; }
  .empty { color: #5a6a85; text-align: center; padding: 30px; }
  .err { color: #ff6b6b; font-size: 0.85rem; }
  .ok { color: #4cd07d; font-size: 0.8rem; margin-left: 6px; }
  .link { background: none; border: none; color: #4cc9f0; cursor: pointer; font-size: 0.8rem; text-decoration: underline; }
  .mac-ctl { display: flex; align-items: center; gap: 6px; margin-top: 4px; }
  .mac-ctl input {
    background: #0f1524; color: #e8ecf4; border: 1px solid #1f2a44;
    border-radius: 4px; padding: 3px 6px; font-size: 0.75rem; width: 150px;
  }
  h2 { color: #4ecdc4; font-size: 1.05rem; margin-top: 26px; }
  .wan-card { background: #16213e; border: 1px solid #0f3460; border-radius: 12px; padding: 16px; }
  .wan-card.empty { color: #5a6a85; }
  .wan-head { display: flex; align-items: center; gap: 12px; margin-bottom: 12px; font-size: 1.02rem; color: #e8ecf4; }
  .wan-link { font-size: 0.72rem; font-weight: 700; padding: 2px 8px; border-radius: 8px; }
  .wan-link.up { background: #1f3d2b; color: #5fdba7; }
  .wan-link.down { background: #3d1f1f; color: #ff6b6b; }
  .clone-tag { background: #3d331f; color: #f5c26b; font-weight: 700; }
  .wan-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 14px; }
  .wan-item { display: flex; flex-direction: column; gap: 3px; }
  .wan-label { color: #7a8aa5; font-size: 0.72rem; text-transform: uppercase; }
  .wan-item code { color: #e8ecf4; font-size: 0.88rem; }
  .wan-hint { color: #5a6a85; font-size: 0.75rem; }
</style>
