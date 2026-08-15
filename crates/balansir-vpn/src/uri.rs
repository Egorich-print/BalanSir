//! Minimal, safe URI parsing for VPN config URIs (`vless://` etc).
//!
//! Deliberately tiny: a real URL crate is overkill and adds a large dependency
//! tree to the embedded build. We implement exactly the subset the supported
//! URI schemes need:
//!
//! * split `scheme://userinfo@host:port?query#fragment`
//! * percent-decode the userinfo and query values
//! * parse `k=v&k2=v2` query pairs (values percent-encoded)
//!
//! Everything is bounds-checked and lossy-safe: malformed input yields
//! `None`/empty rather than panicking.

/// One parsed URI component set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedUri {
    pub scheme: String,
    /// Percent-decoded userinfo (e.g. the VLESS uuid).
    pub userinfo: String,
    pub host: String,
    pub port: Option<u16>,
    /// Percent-decoded query params.
    pub query: Vec<(String, String)>,
    /// Percent-decoded fragment (label).
    pub fragment: Option<String>,
}

impl ParsedUri {
    /// Get the first value of a query key.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.query
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// Get the first value of a query key, or `default`.
    pub fn get_or<'a>(&'a self, key: &'a str, default: &'a str) -> &'a str {
        self.get(key).unwrap_or(default)
    }
}

/// Parse a `scheme://userinfo@host[:port][/path]?query#fragment` URI.
///
/// Returns `None` for anything that is not a valid, bounded URI (no scheme,
/// empty host, host/port that cannot be parsed, over-long input).
pub fn parse(uri: &str) -> Option<ParsedUri> {
    // Bound input to avoid pathological long strings.
    if uri.len() > 4096 || uri.is_empty() {
        return None;
    }
    let (scheme, rest) = uri.split_once("://")?;
    if scheme.is_empty()
        || !scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        return None;
    }

    // fragment
    let (before_frag, fragment) = match rest.split_once('#') {
        Some((b, f)) => (b, Some(percent_decode(f))),
        None => (rest, None),
    };

    // query
    let (before_query, query) = match before_frag.split_once('?') {
        Some((b, q)) => (b, parse_query(q)),
        None => (before_frag, Vec::new()),
    };

    // userinfo@host[:port]
    let (userinfo, hostport) = match before_query.split_once('@') {
        Some((u, h)) => (percent_decode(u), h),
        None => (String::new(), before_query),
    };

    // host[:port] — handle IPv6 brackets and trailing port.
    let (host, port) = split_host_port(hostport)?;
    if host.is_empty() {
        return None;
    }

    Some(ParsedUri {
        scheme: scheme.to_ascii_lowercase(),
        userinfo,
        host,
        port,
        query,
        fragment,
    })
}

/// Split `host[:port]`, supporting `[ipv6]:port` and a bare host with no port.
fn split_host_port(hostport: &str) -> Option<(String, Option<u16>)> {
    if hostport.is_empty() {
        return None;
    }
    if let Some(rest) = hostport.strip_prefix('[') {
        // [ipv6] or [ipv6]:port
        let end = rest.find(']')?;
        let host = &rest[..end];
        let tail = &rest[end + 1..];
        let port = if let Some(p) = tail.strip_prefix(':') {
            Some(p.parse().ok()?)
        } else if tail.is_empty() {
            None
        } else {
            return None;
        };
        return Some((host.to_string(), port));
    }
    // host or host:port
    if let Some((h, p)) = hostport.rsplit_once(':') {
        if h.is_empty() || p.is_empty() {
            return None;
        }
        // A bare host containing ':' without brackets is invalid IPv6-ish; be
        // strict and reject (callers can bracket IPv6).
        if h.contains(':') {
            return None;
        }
        return Some((h.to_string(), Some(p.parse().ok()?)));
    }
    Some((hostport.to_string(), None))
}

/// Parse `k=v&k2=v2` (values percent-decoded; keys kept raw).
fn parse_query(q: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if q.is_empty() {
        return out;
    }
    for pair in q.split('&') {
        if pair.is_empty() {
            continue;
        }
        match pair.split_once('=') {
            Some((k, v)) => out.push((k.to_string(), percent_decode(v))),
            None => out.push((pair.to_string(), String::new())),
        }
    }
    out
}

/// Percent-decode a string (`%XX` sequences and `+` as space for query
/// context is NOT applied here — VPN URIs use %20, and '+' is a literal
/// plus for base64-ish values). Lossy for invalid UTF-8.
pub fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_vless() {
        let uri = "vless://uuid@host:443?type=tcp&security=none#label";
        let p = parse(uri).unwrap();
        assert_eq!(p.scheme, "vless");
        assert_eq!(p.userinfo, "uuid");
        assert_eq!(p.host, "host");
        assert_eq!(p.port, Some(443));
        assert_eq!(p.get("type"), Some("tcp"));
        assert_eq!(p.fragment.as_deref(), Some("label"));
    }

    #[test]
    fn percent_decodes_userinfo_and_query() {
        let uri = "vless://uuid@host:443?path=%2Fvless&sni=www.intel.com#F%D0%A0";
        let p = parse(uri).unwrap();
        assert_eq!(p.get("path"), Some("/vless"));
        assert_eq!(p.get("sni"), Some("www.intel.com"));
        assert!(p.fragment.as_deref().unwrap_or("").contains("Р"));
    }

    #[test]
    fn parses_ipv6_bracketed() {
        let uri = "vless://uuid@[2001:db8::1]:443?type=tcp#x";
        let p = parse(uri).unwrap();
        assert_eq!(p.host, "2001:db8::1");
        assert_eq!(p.port, Some(443));
    }

    #[test]
    fn rejects_malformed() {
        assert!(parse("not a uri").is_none());
        assert!(parse("").is_none());
        assert!(parse("http://").is_none());
        assert!(parse("vless://uuid@host:notaport#x").is_none());
        assert!(parse("vless://uuid@host:70000#x").is_none());
    }

    #[test]
    fn port_optional() {
        let p = parse("vless://uuid@host#x").unwrap();
        assert_eq!(p.port, None);
        assert_eq!(p.host, "host");
    }

    #[test]
    fn percent_decode_handles_plus_literally() {
        assert_eq!(percent_decode("a+b"), "a+b");
        assert_eq!(percent_decode("a%20b"), "a b");
        assert_eq!(percent_decode("100%"), "100%");
    }
}
