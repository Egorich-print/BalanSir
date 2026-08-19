//! Measure real subscription import: accepted / rejected / duplicates.
//!
//! Usage: cargo run -p balansir-vpn --example import-census -- /path/to/sub.txt

use std::collections::BTreeMap;
use std::fs;

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: import-census <file>");
    let body = fs::read_to_string(&path).expect("read subscription");
    let result = balansir_vpn::import_subscription(&body, &path, 1_750_000_000_000);

    println!(
        "total lines: {} | accepted: {} | rejected: {} | duplicates skipped: {}",
        body.lines().count(),
        result.profiles.len(),
        result.rejected.len(),
        result.duplicates_skipped,
    );

    let mut by_reason: BTreeMap<String, usize> = BTreeMap::new();
    for r in &result.rejected {
        let reason = r.reason.split(':').next().unwrap_or(&r.reason).to_string();
        *by_reason.entry(reason).or_insert(0) += 1;
    }
    println!("\n-- rejection reasons --");
    for (reason, count) in by_reason {
        println!("  {count:>4}  {reason}");
    }

    let mut by_security: BTreeMap<&str, usize> = BTreeMap::new();
    let mut by_transport: BTreeMap<&str, usize> = BTreeMap::new();
    let mut ipv6 = 0usize;
    for p in &result.profiles {
        *by_security.entry(p.security.name()).or_insert(0) += 1;
        *by_transport.entry(p.transport.name()).or_insert(0) += 1;
        if p.server.contains(':') {
            ipv6 += 1;
        }
    }
    println!("\n-- accepted by security --");
    for (k, v) in by_security {
        println!("  {v:>4}  {k}");
    }
    println!("-- accepted by transport --");
    for (k, v) in by_transport {
        println!("  {v:>4}  {k}");
    }
    println!("ipv6 servers: {ipv6}");
}
