// Derive human-readable subsystem and overall status from the unified
// snapshot. This is a view concern only — the daemon owns the truth.

export const HEALTHY = 'healthy';
export const DEGRADED = 'degraded';
export const RECOVERING = 'recovering';
export const BLOCKED = 'blocked';
export const FALLBACK = 'fallback';
export const DISABLED = 'disabled';
export const UNAVAILABLE = 'unavailable';

const ORDER = [
  HEALTHY,
  DEGRADED,
  RECOVERING,
  BLOCKED,
  FALLBACK,
  DISABLED,
  UNAVAILABLE,
];

const RANK = Object.fromEntries(ORDER.map((s, i) => [s, i]));

function worst(...states) {
  return states
    .filter(Boolean)
    .sort((a, b) => RANK[b.status] - RANK[a.status])[0];
}

// A state carries a status, a short title and one or more reasons.
export function qosStatus(snap) {
  if (!snap) return { status: UNAVAILABLE, title: 'Unavailable', reasons: ['No snapshot yet'] };
  const { qos } = snap;
  const reasons = [];
  if (qos.last_error) reasons.push(`QoS error: ${qos.last_error}`);
  if (qos.drift) {
    reasons.push(
      qos.desired.length
        ? 'Desired shaping differs from the kernel state'
        : 'Kernel shaping differs from desired state',
    );
  }
  if (qos.desired.length === 0 && qos.applied.filter((a) => a.our_identity).length === 0) {
    return {
      status: DISABLED,
      title: 'Disabled',
      reasons: ['No shaping configured'],
    };
  }
  if (qos.desired.length === 0) {
    return { status: RECOVERING, title: 'Recovering', reasons: ['Shaping being removed'] };
  }
  if (qos.drift) {
    return {
      status: qos.last_error ? BLOCKED : DEGRADED,
      title: qos.last_error ? 'Blocked' : 'Degraded',
      reasons,
    };
  }
  return { status: HEALTHY, title: 'Healthy', reasons: ['Shaping applied and converged'] };
}

export function tailscaleStatus(snap) {
  if (!snap) return { status: UNAVAILABLE, title: 'Unavailable', reasons: ['No snapshot yet'] };
  const { tailscale } = snap;
  if (tailscale.error) {
    return { status: DEGRADED, title: 'Degraded', reasons: [tailscale.error] };
  }
  const status = tailscale.status;
  if (!status || !status.installed) {
    return { status: DISABLED, title: 'Not installed', reasons: ['tailscaled not found on this host'] };
  }
  const state = (status.backend_state || '').toLowerCase();
  const reasons = [];
  if (state === 'running') {
    if (status.self_online === false) reasons.push('Node is offline');
    return {
      status: status.self_online === false ? DEGRADED : HEALTHY,
      title: status.self_online === false ? 'Degraded' : 'Running',
      reasons: reasons.length ? reasons : ['Tailnet node connected'],
    };
  }
  if (state === 'stopped' || state === 'needslogin') {
    return { status: DISABLED, title: 'Not logged in', reasons: ['Authenticate to join the tailnet'] };
  }
  if (state === 'starting') return { status: RECOVERING, title: 'Starting', reasons: ['Daemon is starting'] };
  return { status: DEGRADED, title: 'Degraded', reasons: [`Backend state: ${status.backend_state || 'unknown'}`] };
}

export function networkStatus(snap) {
  if (!snap) return { status: UNAVAILABLE, title: 'Unavailable', reasons: ['No snapshot yet'] };
  const up = snap.interfaces.filter((i) => i.link_up && i.name !== 'lo');
  const down = snap.interfaces.filter((i) => i.name !== 'lo' && !i.link_up);
  if (up.length === 0) {
    return {
      status: down.length ? BLOCKED : DISABLED,
      title: 'No links up',
      reasons: down.map((i) => `${i.name} is down`),
    };
  }
  return {
    status: HEALTHY,
    title: 'Connected',
    reasons: [`${up.length} interface(s) up`],
  };
}

export function b4Status(snap) {
  if (!snap) return { status: UNAVAILABLE, title: 'Unavailable', reasons: ['No snapshot yet'] };
  const { b4 } = snap;
  if (!b4 || !b4.config_path) {
    return {
      status: DISABLED,
      title: 'Disabled',
      reasons: ['B4 not configured (set BALANSIR_B4_CONFIG)'],
    };
  }
  const reasons = [];
  if (b4.paused) reasons.push('Engine paused by operator');
  if (b4.last_error) reasons.push(`B4 error: ${b4.last_error}`);
  if (b4.drift) reasons.push('Per-path MTU ownership drift');
  const active = (b4.flows || []).filter(
    (f) => f.state === 'Adapting' || f.state === 'Monitoring' || f.state === 'Fallback' || f.state === 'StrictFail',
  );
  if (b4.paused) return { status: DISABLED, title: 'Paused', reasons };
  if (active.some((f) => f.state === 'StrictFail')) {
    reasons.push('A flow is in strict-fail (no secure path, not bypassing)');
    return { status: BLOCKED, title: 'Blocked', reasons };
  }
  if (active.some((f) => f.state === 'Fallback')) {
    reasons.push('A flow is using its restricted fallback');
    return { status: FALLBACK, title: 'Fallback', reasons };
  }
  if (active.length) {
    reasons.push(`${active.length} flow(s) adapting / monitoring`);
    return { status: DEGRADED, title: 'Degraded', reasons };
  }
  if (b4.drift) return { status: DEGRADED, title: 'Drift', reasons };
  return { status: HEALTHY, title: 'Healthy', reasons: ['B4 converged, direct paths healthy'] };
}

export function xrayStatus(snap) {
  if (!snap) return { status: UNAVAILABLE, title: 'Unavailable', reasons: ['No snapshot yet'] };
  const { xray } = snap;
  if (!xray || xray.profiles.length === 0) {
    return {
      status: DISABLED,
      title: 'Disabled',
      reasons: ['No Xray profiles (set BALANSIR_XRAY_CONFIG)'],
    };
  }
  const reasons = [];
  if (xray.last_error) reasons.push(`Xray error: ${xray.last_error}`);
  if (xray.switch_reason) reasons.push(`Last switch: ${xray.switch_reason}`);
  if (xray.paused) {
    return {
      status: DISABLED,
      title: 'Paused',
      reasons: ['Transport paused — traffic uses the direct path'],
    };
  }
  if (!xray.active) {
    return {
      status: xray.last_error ? BLOCKED : DEGRADED,
      title: xray.last_error ? 'Blocked' : 'Not running',
      reasons,
    };
  }
  const active = xray.profiles.find((p) => p.name === xray.active);
  if (active && (active.health === 'Unhealthy' || active.health === 'Degraded')) {
    const why = (active.path && active.path.reasons || [])
      .map((r) => r.toLowerCase())
      .join(', ');
    reasons.push(
      `Active endpoint '${active.name}' is ${active.health.toLowerCase()}` +
        (why ? ` — ${why}` : ` (${active.failure_count} failed probe(s))`),
    );
    return { status: DEGRADED, title: 'Degraded', reasons };
  }
  if (xray.pinned && xray.pinned !== xray.active) {
    reasons.push(`Pinned endpoint '${xray.pinned}' — converging`);
    return { status: RECOVERING, title: 'Recovering', reasons };
  }
  if (xray.pinned) reasons.push(`Pinned to '${xray.pinned}' (manual override)`);
  reasons.push(`Proxy active via '${xray.active}' (SOCKS ${xray.socks_port})`);
  return { status: HEALTHY, title: 'Healthy', reasons };
}

export function systemStatus(snap, health) {
  const parts = [
    health && health.status !== 'ok'
      ? { status: BLOCKED, title: 'API degraded', reasons: [`health: ${health.status}`] }
      : null,
    snap && snap.executor_unreachable
      ? { status: BLOCKED, title: 'Executor unreachable', reasons: ['Privileged executor did not respond'] }
      : null,
    qosStatus(snap),
    networkStatus(snap),
    tailscaleStatus(snap),
    b4Status(snap),
    xrayStatus(snap),
  ].filter(Boolean);
  const overall = worst(...parts);
  return {
    ...overall,
    parts: parts.map((p) => ({ ...p, status: p.status || UNAVAILABLE })),
  };
}

export function badgeClass(status) {
  return {
    [HEALTHY]: 'status-healthy',
    [DEGRADED]: 'status-degraded',
    [RECOVERING]: 'status-recovering',
    [BLOCKED]: 'status-blocked',
    [FALLBACK]: 'status-fallback',
    [DISABLED]: 'status-disabled',
    [UNAVAILABLE]: 'status-unavailable',
  }[status] || 'status-unavailable';
}
