//! Subscription importer: parse raw config URIs from an external source into
//! validated, normalized, deduplicated `VpnProfile`s.
//!
//! Security model (mission §6/§7/§15):
//! * raw input is treated as untrusted — every field is parsed, validated and
//!   normalized before it becomes a profile;
//! * unsupported schemes are rejected with a reason, never silently dropped
//!   into the pool;
//! * a profile is only accepted if it is *runnable by the current runtime*
//!   (protocol + transport + security + required fields present);
//! * stable identity is derived from the normalized endpoint, so the same
//!   endpoint re-imported from different sources dedupes to one profile.
//!
//! This module is pure (no I/O, no network); the fetch/refresh logic lives in
//! the daemon's `VpnSource` layer.

use std::collections::HashSet;

use crate::profile::{Protocol, Security, Transport, VpnProfile};
use crate::uri;

/// One rejected input line, with the reason (observability, never silently
/// ignored).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectedProfile {
    pub line: String,
    pub reason: String,
}

/// Result of importing a subscription body.
#[derive(Debug, Clone, Default)]
pub struct ImportResult {
    pub profiles: Vec<VpnProfile>,
    pub rejected: Vec<RejectedProfile>,
    pub duplicates_skipped: usize,
}

/// Build a stable identity from the normalized endpoint fields. Content hash
/// (FNV-1a) over protocol+host+port+transport+security — NOT the credentials,
/// so identity survives health/load changes and credential rotation.
fn stable_id(
    protocol: Protocol,
    server: &str,
    port: u16,
    transport: &Transport,
    security: &Security,
) -> String {
    let canonical = format!(
        "{}|{}|{}|{}|{}",
        protocol.name(),
        server.trim().to_ascii_lowercase(),
        port,
        transport.name(),
        security.name()
    );
    let bytes = canonical.as_bytes();
    let mut h: u64 = 0xcbf29ce484222325;
    for b in bytes {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{h:016x}")
}

/// Validate a host: IP or plausible hostname, bounded length. A single label
/// (e.g. `proxy`) is accepted — real subscriptions sometimes use single-label
/// hosts; the runtime still resolves them.
fn valid_host(host: &str) -> bool {
    let h = host.trim();
    if h.is_empty() || h.len() > 253 {
        return false;
    }
    if h.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    // Domain/hostname: labels of [a-z0-9-], each 1..63, dot-separated.
    let lower = h.to_ascii_lowercase();
    if lower
        .chars()
        .any(|c| !c.is_ascii_alphanumeric() && c != '.' && c != '-')
    {
        return false;
    }
    let labels: Vec<&str> = lower.split('.').filter(|l| !l.is_empty()).collect();
    if labels.is_empty() || labels.len() > 4 {
        return false;
    }
    labels
        .iter()
        .all(|l| l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-'))
}

/// Parse a single URI line into a profile (or a rejection reason).
pub fn parse_line(line: &str, source: &str, source_ts_ms: i64) -> Result<VpnProfile, String> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return Err("empty or comment".into());
    }
    let uri = uri::parse(line).ok_or_else(|| "malformed URI".to_string())?;

    let protocol = Protocol::from_scheme(&uri.scheme)
        .ok_or_else(|| format!("unsupported scheme '{}'", uri.scheme))?;

    if !valid_host(&uri.host) {
        return Err(format!("invalid host '{}'", uri.host));
    }
    let port = uri
        .port
        .filter(|p| *p > 0)
        .ok_or_else(|| "missing or invalid port".to_string())?;

    // Credential: VLESS requires a non-empty userinfo (uuid).
    let uuid = uri.userinfo.trim().to_string();
    if uuid.is_empty() || uuid.len() < 8 {
        return Err("missing or too-short credential".into());
    }

    // Transport: default tcp; ws/grpc/httpupgrade carry a path/service.
    let transport = match uri.get("type").unwrap_or("tcp") {
        "tcp" | "" => Transport::Tcp,
        "ws" | "websocket" => {
            let path = uri.get("path").unwrap_or("/");
            if !path.starts_with('/') {
                return Err("ws path must start with '/'".into());
            }
            // Keep the WS Host header (`host=` param) — without it the runtime
            // config silently loses the fronting domain.
            let host = uri
                .get("host")
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());
            Transport::WebSocket {
                path: path.to_string(),
                host,
            }
        }
        "grpc" => Transport::Grpc {
            service_name: uri.get("serviceName").unwrap_or("").to_string(),
        },
        "httpupgrade" | "http_upgrade" => {
            let path = uri.get("path").unwrap_or("/");
            if !path.starts_with('/') {
                return Err("httpupgrade path must start with '/'".into());
            }
            let host = uri
                .get("host")
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());
            Transport::HttpUpgrade {
                path: path.to_string(),
                host,
            }
        }
        "xhttp" | "splithttp" | "split_http" => {
            let path = uri.get("path").unwrap_or("/");
            if !path.starts_with('/') {
                return Err("xhttp path must start with '/'".into());
            }
            let host = uri
                .get("host")
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());
            let mode = uri
                .get("mode")
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());
            let extra = uri
                .get("extra")
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());
            Transport::Xhttp {
                path: path.to_string(),
                host,
                mode,
                extra,
            }
        }
        other => return Err(format!("unsupported transport type '{other}'")),
    };

    // Security + SNI.
    let security = match uri.get("security").unwrap_or("none") {
        // `security=false` is a common v2rayNG export quirk meaning "none".
        "none" | "" | "false" => Security::None,
        "tls" => Security::Tls,
        "reality" => Security::Reality,
        other => return Err(format!("unsupported security '{other}'")),
    };
    // SNI: explicit `sni=` wins; for WS/HttpUpgrade/Xhttp TLS configs the
    // VLESS share-URI convention derives the effective SNI from the `host=`
    // param (the fronting domain) when `sni` is absent.
    let sni = uri
        .get("sni")
        .filter(|s| !s.is_empty())
        .or_else(|| match &transport {
            Transport::WebSocket { host, .. }
            | Transport::HttpUpgrade { host, .. }
            | Transport::Xhttp { host, .. } => host.as_deref().filter(|s| !s.is_empty()),
            _ => None,
        })
        .map(|s| s.to_string());
    if security != Security::None && sni.is_none() {
        return Err("TLS/reality requires a non-empty sni".into());
    }

    let flow = uri
        .get("flow")
        .filter(|f| !f.is_empty())
        .map(|f| f.to_string());
    let reality_pbk = uri
        .get("pbk")
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    let reality_sid = uri
        .get("sid")
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    let fingerprint = uri
        .get("fp")
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    let label = uri.fragment.unwrap_or_default();
    let label = if label.trim().is_empty() {
        uri.host.clone()
    } else {
        label
    };

    Ok(VpnProfile {
        profile_id: stable_id(protocol, &uri.host, port, &transport, &security),
        protocol,
        server: uri.host.clone(),
        port,
        transport,
        security,
        sni,
        reality_pbk,
        reality_sid,
        flow,
        uuid,
        fingerprint,
        label,
        source: source.to_string(),
        source_ts_ms,
    })
}

/// Import a whole subscription body: parse each non-empty line, reject the
/// bad ones, deduplicate by stable identity (first occurrence wins).
pub fn import_subscription(body: &str, source: &str, source_ts_ms: i64) -> ImportResult {
    let mut profiles: Vec<VpnProfile> = Vec::new();
    let mut rejected: Vec<RejectedProfile> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut duplicates_skipped = 0usize;

    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match parse_line(line, source, source_ts_ms) {
            Ok(profile) => {
                if seen.insert(profile.profile_id.clone()) {
                    profiles.push(profile);
                } else {
                    duplicates_skipped += 1;
                }
            }
            Err(reason) => rejected.push(RejectedProfile {
                line: truncate(line, 120),
                reason,
            }),
        }
    }

    // Deterministic order (stable across imports).
    profiles.sort_by(|a, b| a.profile_id.cmp(&b.profile_id));
    ImportResult {
        profiles,
        rejected,
        duplicates_skipped,
    }
}

fn truncate(s: &str, n: usize) -> String {
    let mut out: String = s.chars().take(n).collect();
    if s.chars().count() > n {
        out.push('…');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const TS: i64 = 1_700_000_000_000;

    fn sample_vless(host: &str) -> String {
        format!(
            "vless://194302fe-9c53-4203-b17e-c0b30a4d79b6@{host}:443?sni=www.intel.com&type=tcp&security=reality&pbk=hgQ3Wa09f9ectEos7QyC1LQ8bBq8lEAcAtGIDFTKin0&flow=xtls-rprx-vision#Node"
        )
    }

    #[test]
    fn parses_valid_vless_reality() {
        let p = parse_line(&sample_vless("82.40.62.4"), "s", TS).unwrap();
        assert_eq!(p.protocol, Protocol::Vless);
        assert_eq!(p.server, "82.40.62.4");
        assert_eq!(p.port, 443);
        assert_eq!(p.transport, Transport::Tcp);
        assert_eq!(p.security, Security::Reality);
        assert_eq!(p.sni.as_deref(), Some("www.intel.com"));
        assert_eq!(p.flow.as_deref(), Some("xtls-rprx-vision"));
        assert_eq!(p.label, "Node");
        assert_eq!(p.uuid, "194302fe-9c53-4203-b17e-c0b30a4d79b6");
    }

    #[test]
    fn stable_id_is_content_hash_of_normalized_endpoint() {
        let a = parse_line(&sample_vless("82.40.62.4"), "s1", TS).unwrap();
        let b = parse_line(&sample_vless("82.40.62.4"), "s2", TS).unwrap();
        assert_eq!(
            a.profile_id, b.profile_id,
            "same endpoint dedupes across sources"
        );
        let c = parse_line(&sample_vless("82.40.62.5"), "s", TS).unwrap();
        assert_ne!(a.profile_id, c.profile_id, "different endpoint differs");
    }

    #[test]
    fn rejects_unsupported_protocols() {
        let err = parse_line("trojan://uuid@host:443#x", "s", TS).unwrap_err();
        assert!(err.contains("unsupported scheme"));
        let err = parse_line("ss://YWVzLTI1Ni1nY206cGFzcw@host:8388#x", "s", TS).unwrap_err();
        assert!(err.contains("unsupported scheme"));
        let err = parse_line("vmess://eyJhZGRyIjoieCJ9#x", "s", TS).unwrap_err();
        assert!(err.contains("unsupported scheme"));
    }

    #[test]
    fn rejects_missing_or_bad_fields() {
        let u = "194302fe-9c53-4203-b17e-c0b30a4d79b6";
        assert!(parse_line("vless://uuid@host#x", "s", TS).is_err()); // no port
        assert!(parse_line(&format!("vless://{u}@host:0#x"), "s", TS).is_err()); // port 0
        assert!(parse_line(&format!("vless://{u}@not a host!:443#x"), "s", TS).is_err()); // bad host
        assert!(parse_line(&format!("vless://{u}@host:443?type=quic#x"), "s", TS).is_err()); // bad transport
        assert!(parse_line(&format!("vless://{u}@host:443?security=quic#x"), "s", TS).is_err()); // bad security
        assert!(parse_line(&format!("vless://{u}@host:443?security=tls#x"), "s", TS).is_err());
        // tls w/o sni
    }

    #[test]
    fn rejects_short_credential() {
        assert!(parse_line("vless://short@host:443#x", "s", TS).is_err()); // uuid too short
    }

    #[test]
    fn import_dedupes_and_collects_rejections() {
        let body = format!(
            "{}\n{}\ntrojan://bad@host:443#x\n# comment\n\n",
            sample_vless("a.example.com"),
            sample_vless("a.example.com"),
        );
        let r = import_subscription(&body, "sub", TS);
        assert_eq!(r.profiles.len(), 1, "duplicate removed");
        assert_eq!(r.duplicates_skipped, 1);
        assert_eq!(r.rejected.len(), 1);
        assert!(r.rejected[0].reason.contains("unsupported scheme"));
    }

    #[test]
    fn import_orders_deterministically() {
        let body = format!(
            "{}\n{}",
            sample_vless("b.example.com"),
            sample_vless("a.example.com")
        );
        let r1 = import_subscription(&body, "s", TS);
        let r2 = import_subscription(&body, "s", TS);
        let ids1: Vec<_> = r1.profiles.iter().map(|p| p.profile_id.as_str()).collect();
        let ids2: Vec<_> = r2.profiles.iter().map(|p| p.profile_id.as_str()).collect();
        assert_eq!(ids1, ids2);
        assert!(ids1.windows(2).all(|w| w[0] <= w[1]));
    }

    #[test]
    fn percent_encoded_paths_and_labels_decode() {
        let line = "vless://194302fe-9c53-4203-b17e-c0b30a4d79b6@host:443?type=ws&path=%2Fvless&security=none#%F0%9F%87%A7%20Bulgaria";
        let p = parse_line(line, "s", TS).unwrap();
        assert_eq!(
            p.transport,
            Transport::WebSocket {
                path: "/vless".into(),
                host: None,
            }
        );
        assert!(p.label.contains("Bulgaria"));
    }

    /// Deterministic fixture modeled on the upstream `vpn-configs-for-russia`
    /// corpus (formats copied, all credentials/keys replaced with synthetic
    /// values — no real secrets in the repo).
    #[test]
    fn upstream_corpus_formats() {
        // 1. Valid VLESS+Reality+TCP (the dominant upstream format).
        let p = parse_line(
            "vless://11111111-2222-4333-8444-555555555555@203.0.113.10:443?type=tcp&security=reality&encryption=none&flow=xtls-rprx-vision&pbk=TEST_PUBLIC_KEY_PLACEHOLDER_0000000000000&sid=abcd1234&sni=www.example.com&fp=ios#Node-1",
            "fixture", TS,
        ).expect("vless reality tcp");
        assert_eq!(p.security, Security::Reality);
        assert_eq!(
            p.reality_pbk.as_deref(),
            Some("TEST_PUBLIC_KEY_PLACEHOLDER_0000000000000")
        );
        assert_eq!(p.reality_sid.as_deref(), Some("abcd1234"));
        assert_eq!(p.fingerprint.as_deref(), Some("ios"));

        // 2. Valid VLESS over IPv6 (bracketed literal).
        let p = parse_line(
            "vless://11111111-2222-4333-8444-555555555555@[2001:db8::10]:8443?type=tcp&security=none#v6",
            "fixture", TS,
        ).expect("v6");
        assert_eq!(p.server, "2001:db8::10");
        assert_eq!(p.endpoint(), "[2001:db8::10]:8443", "v6 endpoint bracketed");

        // 3. WS+TLS with host= but no sni= — SNI must fall back to the
        // fronting host (upstream corpus relies on this convention).
        let p = parse_line(
            "vless://11111111-2222-4333-8444-555555555555@cdn.example.com:8443?type=ws&path=%2F&host=front.example.net&security=tls#ws-tls",
            "fixture", TS,
        ).expect("ws tls with host-derived sni");
        assert_eq!(p.sni.as_deref(), Some("front.example.net"));
        assert_eq!(
            p.transport,
            Transport::WebSocket {
                path: "/".into(),
                host: Some("front.example.net".into()),
            },
            "WS Host header preserved"
        );

        // 4. `security=false` quirk (v2rayNG export) = no security.
        let p = parse_line(
            "vless://11111111-2222-4333-8444-555555555555@198.51.100.7:80?security=false&type=tcp#quirk",
            "fixture", TS,
        ).expect("security=false alias");
        assert_eq!(p.security, Security::None);

        // 5. Malformed URI → rejected with a reason.
        let err = parse_line("vless://not-a-valid-line", "fixture", TS).unwrap_err();
        assert!(!err.is_empty());

        // 6. Missing required field (TLS without any sni/host) → rejected.
        let err = parse_line(
            "vless://11111111-2222-4333-8444-555555555555@203.0.113.20:443?type=tcp&security=tls#no-sni",
            "fixture", TS,
        ).unwrap_err();
        assert!(err.contains("sni"));

        // 7. Unsupported protocols from the same corpus → rejected honestly.
        for line in [
            "hysteria2://syntheticpass0123456789abcdef@203.0.113.30:443?insecure=1&sni=hy.example.com#hy2",
            "trojan://11111111-2222-4333-8444-555555555555@203.0.113.40:8443?security=tls&sni=t.example.com#trojan",
            "vmess://eyJhZGQiOiIxOTguNTEuMTAwLjUwIn0=#vmess",
        ] {
            let err = parse_line(line, "fixture", TS).unwrap_err();
            assert!(err.contains("unsupported scheme"), "{line}: {err}");
        }

        // 8. xhttp transport is now supported (mission §10) — parses into the
        //    Xhttp variant with mode/extra preserved.
        let profile = parse_line(
            "vless://11111111-2222-4333-8444-555555555555@203.0.113.60:443?type=xhttp&security=reality&sni=x.example.com&pbk=TEST_PUBLIC_KEY_PLACEHOLDER_0000000000000&mode=auto&path=%2Fws#xhttp",
            "fixture", TS,
        ).unwrap();
        match &profile.transport {
            Transport::Xhttp { path, mode, .. } => {
                assert_eq!(path, "/ws");
                assert_eq!(mode.as_deref(), Some("auto"));
            }
            other => panic!("expected xhttp transport, got {other:?}"),
        }
        // A bare unknown transport is still rejected honestly.
        let err = parse_line(
            "vless://11111111-2222-4333-8444-555555555555@203.0.113.60:443?type=weird&security=none#x",
            "fixture", TS,
        ).unwrap_err();
        assert!(err.contains("unsupported transport"), "{err}");
    }

    #[test]
    fn host_validation() {
        assert!(valid_host("example.com"));
        assert!(valid_host("proxy")); // single-label accepted
        assert!(valid_host("203.0.113.5"));
        assert!(valid_host("2001:db8::1"));
        assert!(!valid_host(""));
        assert!(!valid_host("not_a_host!"));
        assert!(!valid_host("-bad.example.com"));
        assert!(!valid_host("a".repeat(300).as_str()));
    }
}
