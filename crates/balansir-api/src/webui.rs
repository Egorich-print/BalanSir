//! Serve the built BalanSir WebUI (Svelte SPA) from the same HTTP endpoint as
//! the REST API, so the operational console needs no separate Node server.
//!
//! The daemon serves API + WebUI on one origin; the SPA talks to relative
//! API paths. Resolution order for the assets directory:
//!   1. `BALANSIR_WEBUI_DIR` (absolute or relative path)
//!   2. `./webui/dist` (repo layout, when the daemon runs from the repo root)
//!   3. `./dist` (Tauri/bundled layout)
//! When no directory with an `index.html` is found the WebUI is simply not
//! served and the API keeps working as before.

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use serde_json::json;
use std::path::{Path, PathBuf};

fn webui_dir() -> Option<PathBuf> {
    let candidates = [
        std::env::var("BALANSIR_WEBUI_DIR").ok(),
        Some("webui/dist".to_string()),
        Some("dist".to_string()),
    ];
    for candidate in candidates.into_iter().flatten() {
        if candidate.is_empty() {
            continue;
        }
        let p = PathBuf::from(&candidate);
        if p.join("index.html").is_file() {
            return Some(p);
        }
    }
    None
}

fn content_type(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("js") | Some("mjs") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("json") => "application/json",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("ico") => "image/x-icon",
        Some("woff2") => "font/woff2",
        Some("woff") => "font/woff",
        Some("ttf") => "font/ttf",
        Some("wasm") => "application/wasm",
        Some("map") => "application/json",
        Some("txt") => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

/// Build the response for `GET /`: the SPA when the WebUI is available,
/// otherwise the JSON API info (backwards compatible).
pub async fn root() -> Response {
    if let Some(dir) = webui_dir() {
        return serve_file(&dir.join("index.html")).await;
    }
    Json(json!({
        "name": "BalanSir API",
        "version": "0.1.0",
    }))
    .into_response()
}

/// SPA fallback: serve static assets under the WebUI directory, and fall back
/// to `index.html` for client-side routes. Path traversal is rejected
/// regardless of whether the WebUI is installed.
pub async fn fallback(req: Request<Body>) -> Response {
    let path = req.uri().path();
    let mut rel = PathBuf::new();
    for segment in path.split('/') {
        if segment.is_empty() {
            continue;
        }
        // Reject traversal and encoded separators.
        if segment == ".." || segment.contains('\\') || segment.contains('\0') {
            return StatusCode::BAD_REQUEST.into_response();
        }
        rel.push(segment);
    }

    let Some(dir) = webui_dir() else {
        return StatusCode::NOT_FOUND.into_response();
    };

    let candidate = dir.join(&rel);
    // Defense in depth: even if an exotic encoding slips past the segment
    // checks, never serve a file outside the WebUI directory.
    if !candidate.starts_with(&dir) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let is_file = tokio::fs::metadata(&candidate)
        .await
        .map(|m| m.is_file())
        .unwrap_or(false);
    let final_path = if is_file {
        candidate
    } else {
        // Client-side route: serve the app shell.
        dir.join("index.html")
    };
    serve_file(&final_path).await
}

async fn serve_file(path: &Path) -> Response {
    match tokio::fs::read(path).await {
        Ok(bytes) => (
            [(header::CONTENT_TYPE, content_type(path))],
            bytes,
        )
            .into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::OnceLock;
    use tokio::sync::Mutex;

    // The fallback reads BALANSIR_WEBUI_DIR from the process environment, so
    // tests that mutate it must not run in parallel with each other.
    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[tokio::test]
    async fn traversal_is_rejected() {
        let _guard = env_lock().lock().await;
        let mut req = Request::new(Body::empty());
        *req.uri_mut() = "http://x/../../etc/passwd".parse().unwrap();
        assert_eq!(fallback(req).await.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn encoded_traversal_does_not_escape() {
        let _guard = env_lock().lock().await;
        let dir = test_dir();
        std::env::set_var("BALANSIR_WEBUI_DIR", &dir);
        // `%2e%2e` is a literal filename to the OS, never `..`.
        let mut req = Request::new(Body::empty());
        *req.uri_mut() = "http://x/%2e%2e/%2e%2e/etc/passwd".parse().unwrap();
        let resp = fallback(req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        assert_eq!(body, "<html>shell</html>".as_bytes());
        std::env::remove_var("BALANSIR_WEBUI_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn no_webui_dir_yields_not_found() {
        let _guard = env_lock().lock().await;
        std::env::remove_var("BALANSIR_WEBUI_DIR");
        // CWD during tests is the crate root; no webui/dist exists there.
        let mut req = Request::new(Body::empty());
        *req.uri_mut() = "http://x/assets/app.js".parse().unwrap();
        assert_eq!(fallback(req).await.status(), StatusCode::NOT_FOUND);
    }

    fn test_dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("bs-webui-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("assets")).unwrap();
        std::fs::write(dir.join("index.html"), "<html>shell</html>").unwrap();
        std::fs::write(dir.join("assets/app.js"), "console.log(1)").unwrap();
        dir
    }

    #[tokio::test]
    async fn serves_webui_files() {
        let _guard = env_lock().lock().await;
        let dir = test_dir();
        std::env::set_var("BALANSIR_WEBUI_DIR", &dir);

        // Root serves the SPA shell.
        assert_eq!(root().await.status(), StatusCode::OK);

        // Assets are served with a sensible content type.
        let mut req = Request::new(Body::empty());
        *req.uri_mut() = "http://x/assets/app.js".parse().unwrap();
        let resp = fallback(req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert!(ct.contains("javascript"), "got {ct}");

        // Unknown client-side route falls back to the shell.
        let mut req = Request::new(Body::empty());
        *req.uri_mut() = "http://x/some/client/route".parse().unwrap();
        assert_eq!(fallback(req).await.status(), StatusCode::OK);

        std::env::remove_var("BALANSIR_WEBUI_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
