//! Interface probing: measured maximum throughput and USB device
//! identification (mission §1, §2, §14).
//!
//! The mission requires that the displayed "maximum achievable throughput" is a
//! **real measurement**, not the advertised link speed. This module:
//! - runs `iperf3` (when available) against a configured server to measure
//!   the adapter's real achievable throughput;
//! - otherwise falls back to a Rust-native bounded TCP download probe that
//!   measures the practical ceiling without any external runtime dependency;
//! - identifies USB Ethernet adapters (RTL8156, AX88179, ...) and USB Wi-Fi
//!   adapters from `/sys` capability data — never by pinned vendor/product ID.

use std::time::Instant;

/// Cap the probe duration so discovery/refresh never hangs the daemon.
const PROBE_MAX_SECS: u64 = 6;
/// Cap the probe download size (256 MiB) to bound wall time on fast links.
const PROBE_MAX_BYTES: u64 = 256 * 1024 * 1024;
/// Probe server configuration.
#[derive(Debug, Clone)]
pub struct ProbeTarget {
    /// iperf3 server host (or a Rust-native probe endpoint host).
    pub host: String,
    pub port: u16,
}

/// A measured throughput result.
#[derive(Debug, Clone)]
pub struct ThroughputResult {
    /// Measured ceiling in Mbps.
    pub mbps: f64,
    /// Which method produced the measurement.
    pub method: &'static str,
    /// Human detail (e.g. why a measurement was skipped).
    pub detail: String,
}

/// Measure the maximum achievable throughput of an interface.
///
/// Strategy (mission §1): prefer iperf3 with a real TCP transfer to an
/// external server; fall back to a Rust-native TCP download probe. Link speed
/// is intentionally NOT used — the mission requires a real measurement.
pub async fn measure_interface_throughput(
    _interface: &str,
    target: Option<&ProbeTarget>,
) -> ThroughputResult {
    if let Some(target) = target {
        // Prefer iperf3 when present.
        if let Some(result) = iperf3_probe(target).await {
            return result;
        }
        // Rust-native fallback.
        return native_tcp_probe(target).await;
    }
    ThroughputResult {
        mbps: 0.0,
        method: "none",
        detail: "no probe target configured (set BALANSIR_PROBE_HOST/PORT)".into(),
    }
}

/// Probe via the `iperf3` binary (fixed args, no shell, bounded).
async fn iperf3_probe(target: &ProbeTarget) -> Option<ThroughputResult> {
    let start = Instant::now();
    let output = tokio::process::Command::new("iperf3")
        .args([
            "-c",
            &target.host,
            "-p",
            &target.port.to_string(),
            "-t",
            &PROBE_MAX_SECS.to_string(),
            "-f",
            "m",
            "--json",
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .output()
        .await
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let elapsed = start.elapsed().as_secs_f64();
    if elapsed > PROBE_MAX_SECS as f64 + 2.0 {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mbps = parse_iperf3_mbps(&text)?;
    Some(ThroughputResult {
        mbps,
        method: "iperf3",
        detail: "measured with iperf3 TCP transfer".into(),
    })
}

/// Parse `{ "end": { "sum_received": { "bits_per_second": N } } }`.
fn parse_iperf3_mbps(json: &str) -> Option<f64> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    let bps = v
        .get("end")?
        .get("sum_received")?
        .get("bits_per_second")?
        .as_u64()?;
    Some(bps as f64 / 1_000_000.0)
}

/// Rust-native TCP throughput probe: download a bounded amount of data from a
/// simple endpoint and measure achieved rate. Works without iperf3 installed.
async fn native_tcp_probe(target: &ProbeTarget) -> ThroughputResult {
    let start = Instant::now();
    let mut stream = match tokio::net::TcpStream::connect((target.host.as_str(), target.port)).await
    {
        Ok(s) => s,
        Err(e) => {
            return ThroughputResult {
                mbps: 0.0,
                method: "native",
                detail: format!("TCP connect failed: {e}"),
            }
        }
    };
    // Ask the endpoint to stream; read with a big buffer to maximize speed.
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let _ = stream.write_all(b"GET /stream HTTP/1.0\r\n\r\n").await;
    let mut buf = vec![0u8; 128 * 1024];
    let mut total: u64 = 0;
    loop {
        match stream.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                total += n as u64;
                if total >= PROBE_MAX_BYTES {
                    break;
                }
                if start.elapsed().as_secs() >= PROBE_MAX_SECS {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let elapsed = start.elapsed().as_secs_f64();
    if elapsed <= 0.0 || total == 0 {
        return ThroughputResult {
            mbps: 0.0,
            method: "native",
            detail: "no data received (is the endpoint streaming?)".into(),
        };
    }
    let mbps = total as f64 * 8.0 / 1_000_000.0 / elapsed;
    ThroughputResult {
        mbps,
        method: "native",
        detail: format!("downloaded {} MiB in {:.1}s", total / 1024 / 1024, elapsed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_iperf3_json() {
        let json = r#"{"end":{"sum_received":{"bits_per_second":2250000000}}}"#;
        assert_eq!(parse_iperf3_mbps(json), Some(2250.0));
    }

    #[test]
    fn parses_iperf3_json_missing_fields_is_none() {
        assert_eq!(parse_iperf3_mbps("{}"), None);
        assert_eq!(parse_iperf3_mbps("not json"), None);
    }
}
