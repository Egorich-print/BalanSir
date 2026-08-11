# VPN subscription sources for future transport rotation

Status: research note (no code) · Found during the Buildroot mission.

## Source

- **Repo:** https://github.com/Egorich-print/vpn-configs-for-russia
- Upstream origin: `igareck/vpn-configs-for-russia` (the README links to it;
  the user's copy is a fork).
- License: repo root has a LICENSE.

## What it contains (verified by inspection, 2026-08-11)

A collection of **public, free VPN subscriptions** tested for operation in
Russia (RFC-blocked environment). Files are TXT **URI subscriptions**
(sing-box / v2rayN style), auto-updating and auto-validated upstream:

| File | Content |
|---|---|
| `BLACK_VLESS_RUS.txt` | VLESS Reality servers (black list) — ~85 entries |
| `BLACK_VLESS_RUS_mobile.txt` | same, mobile subset |
| `BLACK_SS+All_RUS.txt` | Shadowsocks + all |
| `Vless-Reality-White-Lists-Rus-Mobile.txt` | VLESS Reality with white SNI lists |
| `WHITE-CIDR-RU-all.txt` / `WHITE-CIDR-RU-checked.txt` | RU CIDR whitelists |
| `WHITE-SNI-RU-all.txt` | RU SNI whitelist |
| `TOR-BRIDGES/` | Tor bridges (obfs4, webtunnel, vanilla, top100) |
| `Clash/`, `Base64/`, `QR-codes/` | other formats |

Format sample (verified):

```
# profile-title: ... BLACK LISTS ... VLESS
# profile-update-interval: 1
# Date/Time: 2026-08-11 / 22:46 (Moscow)
# Количество: 85
vless://<uuid>@<ip>:<port>?security=reality&encryption=none&pbk=<pubkey>...
```

## Relevance to BalanSir

- VPN drivers in BalanSir today are **stubs** (`DriverId::WireGuard/Xray/
  Hysteria/...`, `ComponentDriver` process wrappers). **No transport-rotation
  feature is implemented** — this note is future work, not a current hook.
- The subscription format maps cleanly onto the roadmap:
  - **P9 (VPN transport abstraction):** a subscription = a set of
    `TransportCandidate`s (URI, protocol, endpoint, keys).
  - **P10 (Discovery):** `profile-update-interval` = refresh TTL; fetch once,
    cache, validate (the vless:// scheme is parseable without a VPN client).
  - **B4/warm-up:** candidates become probe targets for warm-up/selection.
- Constraint: these are **third-party public servers**. Production use needs
  the operator's own subscriptions; BalanSir should treat any subscription as
  untrusted input (parse strictly, never execute, never treat as policy
  authority).
- The `WHITE-CIDR-RU`/`WHITE-SNI-RU` lists could feed a routing classifier
  (direct-vs-tunnel policy) — but that is product work, not this mission.

## Decision

No code now. Recorded so the future transport/discovery layers can reference
it. The subscription parser (vless:// + metadata) belongs to P9/P10, not to
the embedded image mission.
