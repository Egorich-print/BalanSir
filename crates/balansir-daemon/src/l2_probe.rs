//! Protocol-aware L2 probe for VPN endpoints.
//!
//! The existing [`TcpConnectProbe`] verifies TCP reachability only. Reality
//! servers accept TCP but immediately close the connection when the Reality
//! handshake fails (wrong key, expired short-id, server reconfigured). This
//! module adds a second-stage probe that sends a TLS ClientHello with the
//! profile's SNI and classifies the response:
//!
//! - clean TLS alert / ServerHello → endpoint is protocol-alive
//! - immediate EOF after ClientHello → server rejected the handshake
//! - RST → server or middlebox actively reset the connection
//! - timeout → endpoint unresponsive at protocol level

use std::time::Duration;

/// Result of a single L2 probe attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum L2Result {
    /// Endpoint completed a recognizable protocol exchange.
    Alive,
    /// TCP connected but server closed without sending data.
    ImmediateEof,
    /// TCP connected but server sent RST after our data.
    Reset,
    /// TLS handshake started but failed (alert, malformed response).
    TlsFailure(String),
    /// No response within the probe timeout.
    Timeout,
}

/// Perform an L2 protocol-aware probe: send a minimal TLS ClientHello with
/// `sni` to `server:port` and classify the server's reaction.
///
/// This is NOT a full VLESS/Reality handshake — it is a liveness check that
/// distinguishes "TCP port open" from "protocol actually works". A server
/// that accepts TCP but immediately EOFs on any ClientHello is dead for
/// practical purposes, even though TcpConnectProbe marks it Healthy.
pub async fn l2_tls_probe(server: &str, port: u16, sni: &str, timeout: Duration) -> L2Result {
    let addr = if server.contains(':') && !server.starts_with('[') {
        format!("[{server}]:{port}")
    } else {
        format!("{server}:{port}")
    };

    let connect_fut = tokio::net::TcpStream::connect(&addr);
    let stream = match tokio::time::timeout(timeout, connect_fut).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
            return L2Result::Reset;
        }
        _ => return L2Result::Timeout,
    };

    // Build a minimal TLS 1.2/1.3 ClientHello with the given SNI.
    let client_hello = build_client_hello(sni);

    let mut stream = stream;
    let write_fut = async {
        use tokio::io::AsyncWriteExt;
        stream.write_all(&client_hello).await?;
        stream.flush().await?;
        Ok::<(), std::io::Error>(())
    };
    if tokio::time::timeout(Duration::from_secs(5), write_fut)
        .await
        .is_err()
    {
        return L2Result::Timeout;
    }

    // Read the server's first response bytes.
    let mut buf = [0u8; 256];
    let read_fut = async {
        use tokio::io::AsyncReadExt;
        stream.read(&mut buf).await
    };
    match tokio::time::timeout(Duration::from_secs(5), read_fut).await {
        Ok(Ok(0)) => L2Result::ImmediateEof,
        Ok(Ok(n)) => {
            let resp = &buf[..n];
            if resp.len() >= 3 && resp[0] == 0x16 {
                // TLS handshake record — server is protocol-alive.
                // It might be a ServerHello or a TLS alert; either way the
                // endpoint speaks TLS, which is what we're checking.
                L2Result::Alive
            } else if resp.len() >= 2 && resp[0] == 0x15 {
                // TLS alert — server responded but with an error.
                L2Result::TlsFailure(format!("alert: {:?}", &resp[..n.min(8)]))
            } else {
                // Non-TLS response — unexpected but the endpoint is alive.
                L2Result::Alive
            }
        }
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionReset => L2Result::Reset,
        _ => L2Result::Timeout,
    }
}

/// Build a minimal TLS 1.2 ClientHello with one SNI extension.
///
/// This produces a structurally valid handshake record. The cipher suites are
/// real values so the packet doesn't look obviously malformed to DPI, but we
/// don't need to complete the handshake — just get past the initial gate.
fn build_client_hello(sni: &str) -> Vec<u8> {
    let sni_bytes = sni.as_bytes();

    // --- SNI extension (server_name, type 0x0000) ---
    // Entry: name_type(1) + host_len(2) + hostname(n)
    let entry_len = 3 + sni_bytes.len(); // 1 + 2 + n
                                         // List: list_len_field(2) + entry
    let list_content_len = entry_len;
    // Ext data (value of ext_len field): list_len_field(2) + list_content
    let sni_ext_data_len = 2 + list_content_len;
    // Total wire bytes for this extension
    let sni_ext_wire = 4 + sni_ext_data_len; // type(2) + len(2) + data

    // --- Supported versions extension (TLS 1.3), pre-encoded ---
    const SUPPORTED_VERSIONS_EXT: &[u8] = &[
        0x00, 0x2b, // ext_type
        0x00, 0x05, // ext_len
        0x04, // list_len
        0x03, 0x04, // TLS 1.3
    ];

    // --- Extensions block ---
    let extensions_data_len = sni_ext_wire + SUPPORTED_VERSIONS_EXT.len();

    // --- ClientHello body ---
    let body_len = 2   /* legacy_version */
                 + 32  /* random */
                 + 1   /* session_id_len (empty) */
                 + 12  /* cipher_suites (incl. 2-byte length) */
                 + 2   /* compression (incl. 1-byte length) */
                 + 2   /* extensions_len field */
                 + extensions_data_len;

    let handshake_body_len = 4 + body_len; // handshake header + body
    let record_body_len = handshake_body_len; // one handshake message

    let mut out = Vec::with_capacity(5 + record_body_len);

    // --- TLS record header ---
    out.push(0x16); // content_type: handshake (22)
    out.extend_from_slice(&[0x03, 0x01]); // legacy_version: TLS 1.0
    out.extend_from_slice(&(record_body_len as u16).to_be_bytes());

    // --- Handshake header ---
    out.push(0x01); // handshake_type: client_hello
    let hb = (body_len as u32).to_be_bytes();
    out.extend_from_slice(&hb[1..]); // 3-byte big-endian length

    // --- ClientHello body ---
    out.extend_from_slice(&[0x03, 0x03]); // client_version: TLS 1.2

    // Random: 32 bytes deterministic pseudo-random
    out.extend((0u8..32).map(|i| i.wrapping_mul(7).wrapping_add(0x42)));

    // Session ID: empty
    out.push(0x00);

    // Cipher suites (with 2-byte length prefix)
    out.extend_from_slice(&[
        0x00, 0x0a, // length: 10
        0x13, 0x01, // TLS_AES_128_GCM_SHA256
        0x13, 0x02, // TLS_AES_256_GCM_SHA384
        0xc0, 0x2f, // ECDHE_RSA_AES_128_GCM_SHA256
        0xc0, 0x30, // ECDHE_RSA_AES_256_GCM_SHA384
        0xff, 0x01, // renegotiation_info SCSV
    ]);

    // Compression methods (with 1-byte length prefix)
    out.extend_from_slice(&[0x01, 0x00]); // null only

    // Extensions length
    out.extend_from_slice(&(extensions_data_len as u16).to_be_bytes());

    // SNI extension
    out.extend_from_slice(&[0x00, 0x00]); // ext_type: server_name
    out.extend_from_slice(&(sni_ext_data_len as u16).to_be_bytes());
    out.extend_from_slice(&(list_content_len as u16).to_be_bytes());
    out.push(0x00); // name_type: host_name
    out.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(sni_bytes);

    // Supported versions extension
    out.extend_from_slice(SUPPORTED_VERSIONS_EXT);

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_hello_has_valid_structure() {
        let hello = build_client_hello("example.com");
        // TLS record header
        assert_eq!(hello[0], 0x16); // handshake
        assert_eq!(hello[1], 0x03); // version major
        assert!(hello[3] != 0 || hello[4] != 0); // non-zero length
                                                 // Handshake type
        assert_eq!(hello[5], 0x01); // client_hello
    }

    #[test]
    fn client_hello_contains_sni() {
        let hello = build_client_hello("test.example.org");
        let text = String::from_utf8_lossy(&hello);
        assert!(text.contains("test.example.org"));
    }

    #[test]
    fn client_hello_length_is_consistent() {
        for sni in [
            "a.io",
            "medium.example.com",
            "very.long.domain.name.for.testing.example.org",
        ] {
            let hello = build_client_hello(sni);
            // Extract record length from bytes 3..5
            let rec_len = u16::from_be_bytes([hello[3], hello[4]]) as usize + 5; // +5 for record header
            assert_eq!(hello.len(), rec_len, "record length mismatch for sni={sni}");
        }
    }
}
