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
    eprintln!("usage: balansir-cli {{status|plan|explain|desired|actual|reload <config.toml>}}");
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
        _ => usage(),
    }

    Ok(())
}
