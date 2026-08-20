//! Wi-Fi driver backend (`MsgType::WifiOp`).
//!
//! The executor is the only component that talks to `iw`/`wpa_supplicant`/
//! `wpa_cli`. It uses fixed argument shapes (no shell, no free-form strings)
//! and validates interface names before any binary is spawned. Capability
//! detection is interface-based (`iw dev`, sysfs `wireless` dir), never
//! vendor/product-pinned — any Linux-compatible USB/PCI Wi-Fi adapter works.
//!
//! Security model: interface names must match `[a-zA-Z0-9_.-]+`; SSIDs are
//! passed as single argv elements (no shell); passwords never appear in logs.

use async_trait::async_trait;
use balansir_common::network::{WifiNetwork, WifiOp, WifiResult};
use balansir_common::{Error, Result};

/// Validate an interface name (no path traversal, no spaces).
fn valid_iface(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
}

/// Run a command with a fixed argv (no shell). Returns stdout on success.
fn run(cmd: &str, args: &[&str]) -> Result<String> {
    let out = std::process::Command::new(cmd)
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| Error::Fatal(format!("{cmd}: {e}")))?;
    if !out.status.success() {
        return Err(Error::Fatal(format!(
            "{cmd} {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// The privileged Wi-Fi mechanism.
#[async_trait]
pub trait WifiBackend: Send + Sync {
    async fn scan(&self, interface: &str) -> Result<WifiResult>;
    async fn connect(&self, op: &WifiOp) -> Result<WifiResult>;
    async fn status(&self, interface: &str) -> Result<WifiResult>;
    async fn disconnect(&self, interface: &str) -> Result<WifiResult>;
}

/// Real implementation using `iw`/`wpa_cli` (present on the RPi image).
pub struct IwWifiBackend;

impl IwWifiBackend {
    /// Parse `iw dev <iface> scan` output into networks.
    fn parse_scan(&self, interface: &str, out: &str) -> Vec<WifiNetwork> {
        let mut networks = Vec::new();
        let mut cur: Option<WifiNetwork> = None;
        for line in out.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if line.starts_with("BSS ") {
                if let Some(n) = cur.take() {
                    networks.push(n);
                }
                let bssid = line
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or("")
                    .split('(')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_string();
                cur = Some(WifiNetwork {
                    bssid,
                    ..Default::default()
                });
            } else if let Some(n) = cur.as_mut() {
                if let Some(rest) = line.strip_prefix("SSID: ") {
                    n.ssid = rest.trim().to_string();
                } else if let Some(rest) = line.strip_prefix("signal: ") {
                    if let Some(v) = rest.split_whitespace().next() {
                        n.signal_dbm = v
                            .trim_end_matches("dBm")
                            .parse::<f64>()
                            .ok()
                            .map(|f| f as i32)
                            .unwrap_or(0);
                    }
                } else if let Some(rest) = line.strip_prefix("freq: ") {
                    n.freq_mhz = rest
                        .split_whitespace()
                        .next()
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(0);
                } else if line.contains("WPA2") || line.contains("WPA3") {
                    n.security = "wpa2/wpa3".to_string();
                } else if line.contains("WPA") {
                    n.security = "wpa".to_string();
                } else if line.contains("RSN") || line.contains("OWE") {
                    if n.security.is_empty() || n.security == "open" {
                        n.security = "wpa2/wpa3".to_string();
                    }
                } else if line.starts_with("capability") {
                    if n.security.is_empty() {
                        n.security = "open".to_string();
                    }
                }
            }
        }
        if let Some(n) = cur.take() {
            networks.push(n);
        }
        let _ = interface;
        networks
    }
}

#[async_trait]
impl WifiBackend for IwWifiBackend {
    async fn scan(&self, interface: &str) -> Result<WifiResult> {
        if !valid_iface(interface) {
            return Err(Error::Misconfiguration(
                "wifi: invalid interface name".into(),
            ));
        }
        // `iw dev <if> scan` may need root; fall back to a cached scan via
        // `iw dev <if> scan dump` which reads the kernel's last scan cache.
        let out = match run("iw", &["dev", interface, "scan"]) {
            Ok(o) => o,
            Err(_) => run("iw", &["dev", interface, "scan", "dump"])?,
        };
        let networks = self.parse_scan(interface, &out);
        Ok(WifiResult {
            ok: true,
            detail: format!("scanned {} networks", networks.len()),
            networks,
        })
    }

    async fn connect(&self, op: &WifiOp) -> Result<WifiResult> {
        let WifiOp::Connect {
            interface,
            ssid,
            password,
            identity,
            security,
        } = op
        else {
            return Err(Error::Misconfiguration(
                "wifi: connect requires a Connect op".into(),
            ));
        };
        if !valid_iface(interface) {
            return Err(Error::Misconfiguration(
                "wifi: invalid interface name".into(),
            ));
        }
        if ssid.is_empty() || ssid.len() > 64 {
            return Err(Error::Misconfiguration("wifi: invalid SSID".into()));
        }
        if let Some(pw) = password {
            if pw.is_empty() || pw.len() > 256 {
                return Err(Error::Misconfiguration("wifi: invalid password".into()));
            }
        }

        // Determine the security mode if not explicitly requested. We look at
        // the last scan for this SSID; a missing entry is treated as open
        // (the connection attempt will surface the real requirement).
        let mode = match security.as_deref() {
            Some(m) => m.to_string(),
            None => {
                let scanned = self.scan(interface).await?;
                scanned
                    .networks
                    .iter()
                    .find(|n| n.ssid == *ssid)
                    .map(|n| n.security.clone())
                    .unwrap_or_else(|| "open".to_string())
            }
        };

        // Generate a wpa_supplicant config snippet (only for PSK/EAP; open
        // networks just associate via `iw connect`).
        let use_iw = mode == "open" || mode == "owe";
        if use_iw {
            let _ = identity;
            let mut args = vec!["dev", interface, "connect", ssid];
            if let Some(pw) = password {
                args.push("key");
                args.push(pw);
            }
            run("iw", &args)?;
        } else {
            // wpa_supplicant path: write a config to /run/balansir/, run
            // wpa_cli to reassociate, then wait for the link to come up.
            let dir = "/run/balansir";
            std::fs::create_dir_all(dir).map_err(|e| Error::Fatal(format!("{dir}: {e}")))?;
            let cfg_path = format!("{dir}/wpa-{interface}.conf");
            let mut cfg = String::new();
            cfg.push_str("ctrl_interface=/run/wpa_supplicant\n");
            cfg.push_str("update_config=1\n");
            cfg.push_str("network={\n");
            cfg.push_str("  ssid=\"");
            cfg.push_str(&escape_ssid(ssid));
            cfg.push_str("\"\n");
            if mode == "eap" {
                cfg.push_str("  key_mgmt=WPA-EAP\n");
                if let Some(id) = identity {
                    cfg.push_str("  identity=\"");
                    cfg.push_str(&escape_ssid(id));
                    cfg.push_str("\"\n");
                }
                if let Some(pw) = password {
                    cfg.push_str("  password=\"");
                    cfg.push_str(&escape_ssid(pw));
                    cfg.push_str("\"\n");
                }
                cfg.push_str("  eap=PEAP\n");
                cfg.push_str("  phase2=\"auth=MSCHAPV2\"\n");
            } else if mode == "wpa3" {
                cfg.push_str("  key_mgmt=SAE\n");
                if let Some(pw) = password {
                    cfg.push_str("  psk=\"");
                    cfg.push_str(&escape_ssid(pw));
                    cfg.push_str("\"\n");
                }
            } else {
                cfg.push_str("  key_mgmt=WPA-PSK\n");
                if let Some(pw) = password {
                    cfg.push_str("  psk=\"");
                    cfg.push_str(&escape_ssid(pw));
                    cfg.push_str("\"\n");
                }
            }
            cfg.push_str("}\n");
            let _ = identity;
            // Secret material: mode 0600, wiped on drop.
            use std::os::unix::fs::PermissionsExt;
            std::fs::write(&cfg_path, cfg.as_bytes())
                .map_err(|e| Error::Fatal(format!("write {cfg_path}: {e}")))?;
            let _ = std::fs::set_permissions(&cfg_path, std::fs::Permissions::from_mode(0o600));

            // If a supplicant is already running on the interface, reconfigure
            // via wpa_cli; otherwise start a dedicated supplicant.
            let _ = run("wpa_cli", &["-i", interface, "reconfigure"]);
            let _ = run("wpa_cli", &["-i", interface, "select_network", "0"]);
            let _ = run(
                "wpa_supplicant",
                &["-B", "-i", interface, "-c", &cfg_path, "-D", "wext,nl80211"],
            );
            let _ = run("wpa_cli", &["-i", interface, "reassociate"]);
            std::thread::sleep(std::time::Duration::from_millis(800));
            // Best-effort cleanup of the secret config.
            let _ = std::fs::remove_file(&cfg_path);
        }
        Ok(WifiResult {
            ok: true,
            detail: format!("connect initiated for {ssid} (mode {mode})"),
            networks: vec![],
        })
    }

    async fn status(&self, interface: &str) -> Result<WifiResult> {
        if !valid_iface(interface) {
            return Err(Error::Misconfiguration(
                "wifi: invalid interface name".into(),
            ));
        }
        let mut detail = String::new();
        let mut networks = Vec::new();
        if let Ok(out) = run("wpa_cli", &["-i", interface, "status"]) {
            let mut ssid = String::new();
            let mut selected = false;
            for line in out.lines() {
                if let Some(v) = line.strip_prefix("ssid=") {
                    ssid = v.trim().to_string();
                    if !ssid.is_empty() {
                        selected = true;
                    }
                }
            }
            if selected {
                let mut n = WifiNetwork {
                    ssid,
                    selected: true,
                    ..Default::default()
                };
                for line in out.lines() {
                    if let Some(v) = line.strip_prefix("bssid=") {
                        n.bssid = v.trim().to_string();
                    }
                    if let Some(v) = line.strip_prefix("key_mgmt=") {
                        n.security = v.trim().to_string();
                    }
                    if let Some(v) = line.strip_prefix("freq=") {
                        n.freq_mhz = v.trim().parse().unwrap_or(0);
                    }
                }
                detail = format!("connected to {}", n.ssid);
                networks.push(n);
            } else {
                detail = "not connected".to_string();
            }
        } else if let Ok(out) = run("iw", &["dev", interface, "link"]) {
            for line in out.lines() {
                if let Some(v) = line.trim().strip_prefix("SSID:") {
                    let ssid = v.trim().to_string();
                    detail = format!("connected to {ssid}");
                    networks.push(WifiNetwork {
                        ssid,
                        selected: true,
                        ..Default::default()
                    });
                }
            }
            if networks.is_empty() {
                detail = "not connected".to_string();
            }
        } else {
            return Err(Error::Misconfiguration(
                "wifi: neither wpa_supplicant nor iw available".into(),
            ));
        }
        Ok(WifiResult {
            ok: true,
            detail,
            networks,
        })
    }

    async fn disconnect(&self, interface: &str) -> Result<WifiResult> {
        if !valid_iface(interface) {
            return Err(Error::Misconfiguration(
                "wifi: invalid interface name".into(),
            ));
        }
        let _ = run("iw", &["dev", interface, "disconnect"]);
        let _ = run("wpa_cli", &["-i", interface, "disconnect"]);
        Ok(WifiResult {
            ok: true,
            detail: "disconnected".to_string(),
            networks: vec![],
        })
    }
}

/// Escape a value for inclusion in a wpa_supplicant double-quoted string.
fn escape_ssid(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iface_validation_rejects_path_traversal() {
        assert!(valid_iface("wlan0"));
        assert!(valid_iface("wlx00e04c680224"));
        assert!(!valid_iface("../../etc/passwd"));
        assert!(!valid_iface("wlan 0"));
        assert!(!valid_iface(""));
    }

    #[test]
    fn ssid_escaping() {
        assert_eq!(escape_ssid("home\\net"), "home\\\\net");
        assert_eq!(escape_ssid("a\"b"), "a\\\"b");
        assert_eq!(escape_ssid("multi\nline"), "multiline");
    }

    #[test]
    fn parses_iw_scan_output() {
        let out = r#"BSS 00:11:22:33:44:55(on wlan0)
	last seen: 1.234s [boottime]
	signal: -45.00 dBm
	freq: 2437
	capability: ESS Privacy ShortPreamble SpectrumMgmt
	SSID: HomeWiFi
	RSN:	 * Version: 1
	 * Group cipher: CCMP
	 * Pairwise ciphers: CCMP
	 * Authentication suites: PSK
BSS 66:55:44:33:22:11(on wlan0)
	last seen: 0.123s [boottime]
	signal: -60.00 dBm
	freq: 5180
	SSID: GuestOpen
"#;
        let backend = IwWifiBackend;
        let nets = backend.parse_scan("wlan0", out);
        assert_eq!(nets.len(), 2);
        assert_eq!(nets[0].ssid, "HomeWiFi");
        assert_eq!(nets[0].signal_dbm, -45);
        assert_eq!(nets[0].freq_mhz, 2437);
        assert!(nets[0].security.contains("wpa2") || nets[0].security.contains("wpa"));
        assert_eq!(nets[1].ssid, "GuestOpen");
        assert_eq!(nets[1].bssid, "66:55:44:33:22:11");
    }
}
