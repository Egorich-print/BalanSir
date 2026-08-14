// BalanSir API client (WebUI -> daemon REST/SSE).
// All calls go through the vite proxy /api -> http://localhost:8080.

const BASE = '/api';

async function get(path) {
  const resp = await fetch(`${BASE}${path}`);
  if (!resp.ok) throw new Error(`${path}: ${resp.status}`);
  return resp.json();
}

async function post(path, body) {
  const resp = await fetch(`${BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!resp.ok) {
    const data = await resp.json().catch(() => ({}));
    throw new Error(data.error || `${path}: ${resp.status}`);
  }
  return resp.json();
}

export const api = {
  health: () => get('/health'),
  metrics: () => get('/metrics'),
  desired: () => get('/desired'),
  actual: () => get('/actual'),
  drift: () => get('/drift'),
  plan: () => get('/plan'),
  explain: () => get('/explain'),
  fingerprint: () => get('/fingerprint'),
  drivers: () => get('/drivers'),
  events: () => get('/events'),
  reconcile: () => post('/reconcile'),
  setDesired: (state) => post('/desired', state),
  tailscaleStatus: () => get('/tailscale/status'),
  tailscaleUp: () => post('/tailscale/up'),
  tailscaleDown: () => post('/tailscale/down'),
  qosStatus: () => get('/qos/status'),
  pathHealth: () => get('/health/paths'),
  xrayStatus: () => get('/xray/status'),
};

export function eventsStream(onEvent, onStatus) {
  const es = new EventSource(`${BASE}/events/stream`);
  es.onmessage = (e) => {
    try {
      onEvent(JSON.parse(e.data));
    } catch (_) { /* ignore malformed */ }
  };
  es.onopen = () => onStatus?.(true);
  es.onerror = () => onStatus?.(false);
  return es;
}
