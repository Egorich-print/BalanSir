<script>
  import { api, fmtBytes } from '../lib/api.js';

  export let snapshot;
  export let healthError;

  let action = {};

  async function restoreMac(iface) {
    action[iface.name] = 'working';
    try {
      await api.restoreMac(iface.mac);
      action[iface.name] = 'ok';
    } catch (e) {
      action[iface.name] = e.message;
    }
    setTimeout(() => (action[iface.name] = ''), 3000);
  }

  $: interfaces = snapshot ? snapshot.interfaces : [];
</script>

<h2>Network Interfaces</h2>

{#if healthError}
  <p class="err">Cannot reach the daemon: {healthError}</p>
{/if}

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
            {#if iface.mac}
              {#if action[iface.name] === 'working'}<span class="sub">restoring…</span>
              {:else if action[iface.name] === 'ok'}<span class="ok">restored</span>
              {:else if action[iface.name]}<span class="err">{action[iface.name]}</span>
              {:else}<button class="link" on:click={() => restoreMac(iface)}>restore MAC</button>
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
  h2 { color: #4ecdc4; font-size: 1.05rem; }
</style>
