//! BalanSir desktop shell (Tauri 2).
//!
//! This is a deliberately thin wrapper: the operational console is the Svelte
//! SPA served by the Rust daemon. The desktop shell embeds the built SPA and
//! points it at the daemon API via `VITE_BALANSIR_API_BASE` (see
//! `webui/src/lib/api.js`). No system logic lives here — the daemon and the
//! privileged executor own every privileged action.

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .run(tauri::generate_context!())
        .expect("error while running the BalanSir console");
}
