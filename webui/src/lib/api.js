// Thin client for the BalanSir REST API. All system logic lives in the Rust
// daemon; this file only maps HTTP/SSE to JS-friendly shapes.
//
// `VITE_BALANSIR_API_BASE` lets the Tauri desktop console (embedded SPA)
// point at a daemon without a same-origin webserver; the daemon-served build
// keeps the default '' (same origin).

const BASE =
  (typeof import.meta !== 'undefined' &&
    import.meta.env &&
    import.meta.env.VITE_BALANSIR_API_BASE) ||
  '';

let token = (typeof localStorage !== 'undefined' && localStorage.getItem('balansir_token')) || '';

export function setToken(value) {
  token = value || '';
  if (typeof localStorage !== 'undefined') {
    if (token) localStorage.setItem('balansir_token', token);
    else localStorage.removeItem('balansir_token');
  }
}

export function getToken() {
  return token;
}

async function req(path, options = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers.Authorization = `Bearer ${token}`;
  const resp = await fetch(BASE + path, { headers, ...options });
  if (!resp.ok) {
    const text = await resp.text().catch(() => '');
    throw new Error(`${resp.status} ${resp.statusText}: ${text.slice(0, 300)}`);
  }
  const ct = resp.headers.get('content-type') || '';
  return ct.includes('application/json') ? resp.json() : resp.text();
}

export const api = {
  health: () => req('/health'),
  desired: () => req('/desired'),
  actual: () => req('/actual'),
  state: () => req('/state'),
  reconcile: () => req('/reconcile', { method: 'POST' }),
  metrics: () => req('/metrics'),
  events: () => req('/events'),

  subsystems: () => req('/subsystems'),
  b4: () => req('/b4'),
  setB4Paused: (paused) =>
    req('/b4/pause', { method: 'POST', body: JSON.stringify({ paused }) }),
  dpi: () => req('/dpi'),
  setDpiPaused: (paused) =>
    req('/dpi/pause', { method: 'POST', body: JSON.stringify({ paused }) }),
  b4Discovery: () => req('/b4/discovery'),
  notifyB4Discovery: (domain) =>
    req('/b4/discovery/notify', {
      method: 'POST',
      body: JSON.stringify({ domain }),
    }),

  wifi: () => req('/wifi'),
  wifiScan: (iface) =>
    req('/wifi/scan', { method: 'POST', body: JSON.stringify({ interface: iface }) }),
  wifiConnect: (body) =>
    req('/wifi/connect', { method: 'POST', body: JSON.stringify(body) }),
  wifiDisconnect: (iface) =>
    req('/wifi/disconnect', {
      method: 'POST',
      body: JSON.stringify({ interface: iface }),
    }),
  mptcp: () => req('/mptcp'),
  setMptcpEnabled: (enabled) =>
    req('/mptcp/enabled', {
      method: 'POST',
      body: JSON.stringify({ enabled }),
    }),
  setMptcpEndpoints: (endpoints) =>
    req('/mptcp/endpoints', {
      method: 'POST',
      body: JSON.stringify({ endpoints }),
    }),

  xray: () => req('/xray'),
  setXrayPaused: (paused) =>
    req('/xray/pause', { method: 'POST', body: JSON.stringify({ paused }) }),
  xraySelect: (profile) =>
    req('/xray/select', {
      method: 'POST',
      body: JSON.stringify({ profile }),
    }),
  xrayRotate: () => req('/xray/rotate', { method: 'POST' }),

  vpnPool: () => req('/vpn/pool'),
  setVpnPaused: (paused) =>
    req('/vpn/pause', { method: 'POST', body: JSON.stringify({ paused }) }),
  vpnRefresh: () => req('/vpn/refresh', { method: 'POST' }),
  vpnRotate: () => req('/vpn/rotate', { method: 'POST' }),
  vpnPin: (profileId) =>
    req('/vpn/pin', {
      method: 'POST',
      body: JSON.stringify({ profile_id: profileId }),
    }),
  pathDecision: () => req('/path/decision'),

  qos: () => req('/qos'),
  setQos: (interfaces) =>
    req('/qos', { method: 'POST', body: JSON.stringify({ interfaces }) }),
  removeQos: (interfaceName) =>
    req(`/qos/${encodeURIComponent(interfaceName)}`, { method: 'DELETE' }),

  interfaces: () => req('/interfaces'),
  restoreMac: (mac) =>
    req(`/interfaces/${encodeURIComponent(mac)}/mac/restore`, {
      method: 'POST',
    }),
  setMac: (mac, newMac) =>
    req(`/interfaces/${encodeURIComponent(mac)}/mac`, {
      method: 'POST',
      body: JSON.stringify({ mac: newMac }),
    }),

  tailscale: () => req('/tailscale'),
  tailscaleUp: (authKey) =>
    req('/tailscale/up', {
      method: 'POST',
      body: JSON.stringify({ auth_key: authKey || null }),
    }),
  tailscaleDown: () => req('/tailscale/down', { method: 'POST' }),
  tailscaleReconnect: () => req('/tailscale/reconnect', { method: 'POST' }),
  tailscaleRoutes: (routes, exitNode) =>
    req('/tailscale/routes', {
      method: 'POST',
      body: JSON.stringify({ routes, exit_node: exitNode }),
    }),

  system: () => req('/system'),
};

export function subsystemEventUrl() {
  return BASE + '/subsystems/events';
}

export function fmtBytes(n) {
  if (n == null) return '—';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let i = 0;
  let v = Number(n);
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v.toFixed(v < 10 && i > 0 ? 1 : 0)} ${units[i]}`;
}

export function fmtRate(bytesPerSec) {
  if (bytesPerSec == null) return '—';
  return `${fmtBytes(bytesPerSec)}/s`;
}
