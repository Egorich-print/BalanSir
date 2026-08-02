# BalanSir Web UI

Minimal dashboard for BalanSir Network Policy Engine.

## Features

- Health status display
- Real-time event streaming (SSE)
- Desired state view
- Manual reconciliation trigger
- Prometheus metrics viewer

## Development

```bash
# Install dependencies
npm install

# Start dev server
npm run dev

# Build for production
npm run build
```

## Architecture

```
Web UI (Svelte)
    ↓
REST API / SSE
    ↓
BalanSir API (axum)
    ↓
Reconciler / Policy Engine
```

## Endpoints Used

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/metrics` | GET | Prometheus metrics |
| `/desired` | GET | Desired state |
| `/drift` | GET | Drift status |
| `/reconcile` | POST | Trigger reconciliation |
| `/events` | GET | Event log |
| `/events/stream` | GET | SSE event stream |
