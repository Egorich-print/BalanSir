//! M3.8 operational CLI for the BalanSir daemon.
//!
//! Connects to the daemon's unprivileged control socket and issues
//! control-plane queries (plan / explain / desired / actual / reload) that the
//! daemon serves via its `Reconciler` (M3.8). It does not reimplement any
//! planning or policy logic — the daemon remains the sole control-plane
//! authority.
//!
//! Usage:
//!   balansir-cli status
//!   balansir-cli plan
//!   balansir-cli explain
//!   balansir-cli desired
//!   balansir-cli actual
//!   balansir-cli reload <config.toml>
//!
//! The CLI is unprivileged; peer auth follows the same `BALANSIR_ALLOWED_UIDS`
//! rule as the executor connection.

use balansir_common::ipc::{IpcClientConnection, MsgType};
use balansir_common::Result;
use std::env;

const SOCKET_PATH: &str = "/run/balansir/daemon.sock";

fn usage() -> ! {
    eprintln!(
        "usage: balansir-cli {{status|plan|explain|desired|actual|fingerprint|reload <config.toml>|network|identify}}"
    );
    std::process::exit(2);
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().skip(1).collect();
    let cmd = args.first().map(|s| s.as_str()).unwrap_or_else(|| usage());

    let mut conn = IpcClientConnection::connect(SOCKET_PATH).await?;

    match cmd {
        "status" => {
            let hc = conn.request(MsgType::HealthCheck, Vec::new()).await?;
            println!("health: {:?}", hc.msg_type);
            let plan = conn.request(MsgType::GetPlan, Vec::new()).await?;
            println!("plan payload bytes: {}", plan.payload.len());
            let actual = conn.request(MsgType::GetActual, Vec::new()).await?;
            println!("actual payload bytes: {}", actual.payload.len());
            let fp = conn
                .request(MsgType::GetConfigFingerprint, Vec::new())
                .await?;
            match postcard::from_bytes::<Option<u64>>(&fp.payload) {
                Ok(Some(fp)) => println!("config fingerprint: {fp:#018x}"),
                Ok(None) => println!("config fingerprint: none"),
                Err(_) => println!("config fingerprint: <malformed>"),
            }
        }
        "fingerprint" => {
            let fp = conn
                .request(MsgType::GetConfigFingerprint, Vec::new())
                .await?;
            if fp.msg_type == MsgType::ResponseError {
                eprintln!("error: {}", String::from_utf8_lossy(&fp.payload));
                std::process::exit(1);
            }
            match postcard::from_bytes::<Option<u64>>(&fp.payload) {
                Ok(Some(fp)) => println!("{fp:#018x}"),
                Ok(None) => println!("none"),
                Err(_) => {
                    eprintln!("error: malformed fingerprint");
                    std::process::exit(1);
                }
            }
        }
        "plan" => {
            let resp = conn.request(MsgType::GetPlan, Vec::new()).await?;
            if resp.msg_type == MsgType::ResponseError {
                eprintln!("error: {}", String::from_utf8_lossy(&resp.payload));
                std::process::exit(1);
            }
            let plan: balansir_common::plan::ReconciliationPlan =
                postcard::from_bytes(&resp.payload)?;
            println!("{plan}");
        }
        "explain" => {
            let resp = conn.request(MsgType::GetExplain, Vec::new()).await?;
            if resp.msg_type == MsgType::ResponseError {
                eprintln!("error: {}", String::from_utf8_lossy(&resp.payload));
                std::process::exit(1);
            }
            print!("{}", String::from_utf8_lossy(&resp.payload));
        }
        "desired" => {
            let resp = conn.request(MsgType::GetDesired, Vec::new()).await?;
            if resp.msg_type == MsgType::ResponseError {
                eprintln!("error: {}", String::from_utf8_lossy(&resp.payload));
                std::process::exit(1);
            }
            let desired: balansir_common::DesiredState = postcard::from_bytes(&resp.payload)?;
            println!("rules: {}", desired.rules.len());
            println!("drivers: {}", desired.drivers.len());
        }
        "actual" => {
            let resp = conn.request(MsgType::GetActual, Vec::new()).await?;
            if resp.msg_type == MsgType::ResponseError {
                eprintln!("error: {}", String::from_utf8_lossy(&resp.payload));
                std::process::exit(1);
            }
            let actual: balansir_common::ActualState = postcard::from_bytes(&resp.payload)?;
            println!("active_rules: {}", actual.active_rules.len());
        }
        "reload" => {
            let path = args.get(1).unwrap_or_else(|| usage());
            // Parse the TOML config strictly (ADR-010) and send it as the
            // candidate DesiredState; the daemon reconciles transactionally.
            let config = balansir_control::provider::DesiredConfig::from_file(path)
                .map_err(|e| balansir_common::error::Error::Misconfiguration(e.to_string()))?;
            let desired = balansir_common::DesiredState::try_from(config)
                .map_err(|e| balansir_common::error::Error::Misconfiguration(e.to_string()))?;
            let payload = postcard::to_allocvec(&desired)?;
            let resp = conn.request(MsgType::Reload, payload).await?;
            if resp.msg_type == MsgType::ResponseError {
                eprintln!("error: {}", String::from_utf8_lossy(&resp.payload));
                std::process::exit(1);
            }
            println!("reloaded");
        }
        "network" | "identify" => {
            // Mission §55 diagnostics over the management API (no extra deps:
            // minimal HTTP/1.0 GET on a tokio TcpStream). Answers: what does
            // BalanSir see, what is WAN/LAN, and why (identity chain).
            drop(conn); // IPC socket unused for HTTP commands.
            let base = env::var("BALANSIR_API").unwrap_or_else(|_| "127.0.0.1:8080".into());
            let body = http_get(&base, "/interfaces").await?;

            let ifaces: serde_json::Value = serde_json::from_str(&body).map_err(|e| {
                balansir_common::error::Error::Misconfiguration(format!("api /interfaces: {e}"))
            })?;
            let Some(list) = ifaces.as_array() else {
                eprintln!("error: unexpected /interfaces payload");
                std::process::exit(1);
            };

            if cmd == "network" {
                let header = format!(
                    "{:<12} {:<5} {:<6} {:<14} {:<17} {:<22} {}",
                    "NAME", "LINK", "ROLE", "DRIVER", "MAC", "USB", "IPv4"
                );
                println!("{header}");
                for i in list {
                    println!(
                        "{:<12} {:<5} {:<6} {:<14} {:<17} {:<22} {}",
                        jstr(i, "name"),
                        if jbool(i, "link_up") { "UP" } else { "DOWN" },
                        jstr(i, "role"),
                        jstr(i, "driver"),
                        jstr(i, "mac"),
                        match (jstr_opt(i, "vendor_id"), jstr_opt(i, "product_id"),) {
                            (Some(v), Some(p)) => format!("{v}:{p}"),
                            _ => "-".into(),
                        },
                        jstr(i, "ipv4"),
                    );
                }
            } else {
                // identify: full identity chain per interface (mission §4).
                for i in list {
                    println!("interface {}", jstr(i, "name"));
                    println!("  role:       {}", jstr(i, "role"));
                    println!("  kind/bus:   {}/{}", jstr(i, "kind"), jstr(i, "bus"));
                    println!("  driver:     {}", jstr(i, "driver"));
                    println!(
                        "  mac:        {} (factory: {})",
                        jstr(i, "mac"),
                        jstr(i, "hardware_mac")
                    );
                    println!(
                        "  usb:        {}:{} ({})",
                        jstr(i, "vendor_id"),
                        jstr(i, "product_id"),
                        jstr(i, "device_model")
                    );
                    println!(
                        "  link:       {} speed={:?}Mbps duplex={:?}",
                        if jbool(i, "link_up") { "UP" } else { "DOWN" },
                        i.get("speed_mbps").and_then(|v| v.as_u64()),
                        i.get("duplex").and_then(|v| v.as_str())
                    );
                    println!("  ipv4:       {}", jstr(i, "ipv4"));
                    println!();
                }
            }
        }
        _ => usage(),
    }

    Ok(())
}

/// Minimal HTTP/1.0 GET against the management API. No client deps: the
/// response is small JSON and one-shot (ponytail: reqwest is 200 crates for
/// this).
async fn http_get(addr: &str, path: &str) -> Result<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(addr).await?;
    let req = format!("GET {path} HTTP/1.0\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;
    let raw = String::from_utf8_lossy(&buf);
    // Split headers from body on the first blank line.
    raw.split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .ok_or_else(|| {
            balansir_common::error::Error::IpcViolation("malformed HTTP response".into())
        })
}

fn jstr(v: &serde_json::Value, key: &str) -> String {
    match v.get(key) {
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(serde_json::Value::Array(a)) => a
            .iter()
            .map(|x| x.as_str().unwrap_or_default())
            .collect::<Vec<_>>()
            .join(","),
        Some(other) => other.to_string(),
        None => "-".into(),
    }
}

fn jstr_opt(v: &serde_json::Value, key: &str) -> Option<String> {
    match v.get(key) {
        Some(serde_json::Value::String(s)) => Some(s.clone()),
        _ => None,
    }
}

fn jbool(v: &serde_json::Value, key: &str) -> bool {
    v.get(key).and_then(|b| b.as_bool()).unwrap_or(false)
}
