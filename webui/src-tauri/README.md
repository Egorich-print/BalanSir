# BalanSir Console (Tauri 2 desktop shell)

The operational console ships two ways:

1. **Daemon-served SPA** (default): the Rust daemon serves `webui/dist` and
   the REST API on one origin. No extra process.
2. **Desktop app** (this directory): a Tauri 2 shell that embeds the built
   SPA and talks to the daemon's API/SSE. All system logic still lives in the
   Rust daemon and the privileged executor — the shell has no privileged code.

## Build

```sh
# 1. Build the SPA with the daemon API base baked in
cd webui
VITE_BALANSIR_API_BASE=http://127.0.0.1:8080 npm run build

# 2. Build the desktop shell (Linux deps: libwebkit2gtk-4.1-dev, libgtk-3-dev, …)
cd src-tauri
cargo build
```

With `VITE_BALANSIR_API_BASE` unset the SPA keeps the same-origin layout
used by the daemon-served build; the Tauri shell then expects the daemon to
serve the UI on the same host (`BALANSIR_API_BIND`).

## Dev mode

```sh
npm run dev        # Vite dev server on :5173 (proxies /api to :8080)
cargo tauri dev    # desktop window against the Vite dev server
```

The main window is intentionally plain: navigation, live metrics, SSE events
and controls are the Svelte SPA's job. No secrets are stored in the shell.
