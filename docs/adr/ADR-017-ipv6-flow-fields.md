# ADR-017: IPv6-representable flow fields (A4)

## Status
Accepted (Architecture Gate A4)

## Context

Gate v1 §7 (A4) recorded that `ActionRequest.src_ip/dst_ip` were
`[u8; 4]` — IPv4 only. The nft table is `inet` (dual-stack), but the
emitted rules used `ip saddr` and IPv6 was unrepresentable, not hidden in
`Unsupported`. The same limitation applied to `PacketContext` and to the
policy `Matcher::IpRange`.

The gate offered two options: move to `std::net::IpAddr`/`Ipv4Addr`/
`Ipv6Addr`, or keep IPv4-only as an explicit contract. Choosing the former
unblocks per-flow IPv6 rules (relevant for A3) and removes the silent
"IPv6 is unmatchable" footgun.

## Decision

Replace the IPv4-only octet representation with `std::net::IpAddr`
throughout the flow-field path:

- `ActionRequest.src_ip` / `dst_ip`: `IpAddr` (wire contract). `serde` is
  enabled with the `std` feature in `balansir-common` so `IpAddr`
  (de)serializes through postcard unchanged by any hand-rolled codec.
- `PacketContext.src_ip` / `dst_ip`: `IpAddr`.
- `Matcher::IpRange { base: IpAddr, mask: u8 }`: prefix-matching handles
  both families — a 32-bit mask for IPv4, a 128-bit mask for IPv6. A
  family mismatch never matches.
- `parse_cidr` (TOML config) accepts `ip/prefix` for either family and
  validates the prefix against the family maximum (32 / 128).
- Executor nft rendering: the source CIDR string already carries the
  address; the renderer emits `ip6 saddr` when the CIDR contains `:`,
  `ip saddr` otherwise. Unspecified addresses (`0.0.0.0` / `::`) mean "no
  source matcher" (`cidr_for_src`).

The daemon still sends full IPv4 as before (unspecified v4 remains the
"no matcher" sentinel in the reconcile path); IPv6 is now representable
end-to-end (config → policy → ActionRequest → nft rule).

## Consequences

- IPv6 flow fields are representable and enforceable (nft `inet` chain
  accepts both `ip` and `ip6` matches). A4's "IPv6 is unrepresentable"
  finding is closed.
- A family mismatch in `IpRange` never matches (conservative, explicit).
- The postcard wire encoding of `ActionRequest` changes (it now carries
  `IpAddr`); daemon and executor must be upgraded together. The A1
  fingerprint is computed over this encoding, so fingerprints change —
  expected, deterministic per build.
- No A3 change is pre-empted: richer flow criteria (ports, protocol,
  CIDRs) still compose onto the existing fields.
- No cost to the embedded/musl story: `IpAddr` is `Copy + Eq`, postcard
  handles it via serde, and the common crate already links std.

## Verification

- `test_matcher_ip_range_v4` / `test_matcher_ip_range_v6`: prefix
  matching works per family; v4 base never matches a v6 dst.
- `test_cidr_parsing_v6`: `2001:db8::1/64` parses; `/129` rejected.
- `nft_spec_renders_ipv6_src_as_ip6_saddr`: a v6 src renders
  `ip6 saddr 2001:db8::1/128`; unspecified v6 renders no matcher.
- Workspace 18 suites green, clippy 0, fmt clean, x86_64 + aarch64 Linux
  check pass.

## Relation to other gates

- **A1 (ADR-015)** fingerprint now covers v6 flow fields automatically.
- **A2 (ADR-016)** inventory is id-based and unaffected.
- Primes **A3** (flow-level policy): per-flow criteria for both address
  families are representable in the contract and in compiled nft rules.
