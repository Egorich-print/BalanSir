# BalanSir on Raspberry Pi 3B+ — Buildroot image

Status: **image built and verified (Buildroot, QEMU-virt pending)** ·
Acceptance labels below.

## Artifacts (Buildroot 2026.05.1, output/images)

| File | Size | Note |
|---|---|---|
| `sdcard.img` | 320 MiB | bootable SD image (MBR: boot.vfat 64M + rootfs.ext4 256M) |
| `Image` | 23 MiB | ARM64 kernel (rpi custom, bcm2711 defconfig) |
| `bcm2710-rpi-3-b-plus.dtb` | 35K | device tree (3B/3B+/CM3) |
| `rootfs.ext4` | 256 MiB | ext4 rootfs (systemd, nftables, iproute2, openssh, balansir) |

Build metadata: Buildroot 2026.05.1 · Linux 6.18-ish rpi tree (commit
21b4101) · Bootlin aarch64 glibc toolchain · host-rustc 1.96.1 ·
`balansir_rpi3b_64_defconfig`.

## Verify the image (on the macOS host)

```sh
cargo run -p balansir-image -- inspect path/to/sdcard.img
cargo run -p balansir-image -- checksum path/to/sdcard.img
cargo run -p balansir-image -- verify path/to/sdcard.img path/to/Image
```

## Flash to the SD card (HUMAN EXECUTION REQUIRED — needs physical access)

```sh
# On Linux (or macOS with the SD device):
# sudo dd if=sdcard.img of=/dev/sdX bs=4M conv=fsync   # ⚠ replaces the disk!
```

On macOS the device is `/dev/diskN`; unmount first (`diskutil unmountDisk`).
**`dd` is destructive — confirm the target device.**

## First boot (factory behavior)

- Networking: DHCP on `eth0`.
- SSH: openssh server; root login — **change the root password / keys on
  first boot** (no password is set by default).
- BalanSir: `balansir-daemon` + `balansir-executor` auto-start (systemd,
  ADR-030 units). `/etc/balansir/balansir.toml` is the factory policy
  (fail-open on empty; operator should `balansir-cli reload` their config).
- Startup recovery (P7.2.1/ADR-027): the daemon loads `BALANSIR_CONFIG` at
  boot, before the first reconcile — a malformed file is a fatal startup
  error, never silently empty.

## Operate

```sh
balansir-cli status          # health + plan + actual
balansir-cli fingerprint     # config fingerprint
balansir-cli reload /etc/balansir/balansir.toml
```

## Acceptance labels

| Item | Status |
|---|---|
| BalanSir cross-build (aarch64 musl static, host) | VERIFIED (ADR-029) |
| Buildroot external tree + RPi defconfig | VERIFIED (image produced) |
| `sdcard.img` MBR/ext4 layout | VERIFIED (`balansir-image inspect` + `file`) |
| Image checksum manifest | VERIFIED (`balansir-image checksum/verify`) |
| QEMU `virt` full-stack boot/network test | **VERIFIED** — systemd multiuser, eth0 DHCP, balansir-daemon + balansir-executor active, `/run/balansir` sockets (split UID), `balansir-cli status/fingerprint/desired` respond, config loaded (fingerprint `0xdaa1…`), nft v1.1.4 |
| QEMU `raspi3b` boot of sdcard.img | ENVIRONMENT-BLOCKED (no NIC; SD power-of-2 quirk; would need kernel+firmware boot args) |
| Real Raspberry Pi 3B+ | NOT HARDWARE VERIFIED (human step) |

QEMU results are never claimed as hardware verification.

## Verification commands

```sh
# Build (in the QEMU aarch64 Ubuntu VM — see docs/BUILDROOT_IMAGE.md)
make BR2_EXTERNAL=... balansir_qemu_virt_defconfig
make BR2_EXTERNAL=... -j4

# On the macOS host
cargo run -p balansir-image -- inspect sdcard.img
cargo run -p balansir-image -- checksum sdcard.img
./deploy/buildroot/qemu-login-test.sh Image rootfs.ext4   # full-stack check
```

## Production baseline (2026-08-15)

Reproducible production Buildroot image for Raspberry Pi 3B+, built from the
Git tree at `main`. Validated autonomously in QEMU; physical RPi steps are
listed as MANUAL.

### Defconfig / kernel

- `buildroot-external/configs/balansir_rpi3b_64_defconfig`
- Kernel 6.12.61-v8 (`bcm2711` defconfig + `linux.fragment`)
- Fragment builds in: `CONFIG_TUN=y`, `CONFIG_NET_SCH_HTB/FQ_CODEL/CAKE/INGRESS/NETEM=y`,
  classifiers (`NET_CLS_FW/U32/FLOWER/BASIC`), actions, `NF_TABLES` (inet/ipv4/ipv6/netdev),
  `NFT_CT/NAT/MASQ/REJECT/LOG/LIMIT/COUNTER=y`, `NETLINK_DIAG=y`.
- Runtime packages: `nftables`, `iproute2` (tc), `iptables` (ip6tables, tailscaled dep),
  `tailscale`, `openssh`, `systemd`.

### What ships

- `balansir-daemon` / `balansir-executor` / `balansir-cli` → `/usr/local/bin` (aarch64, glibc)
- WebUI Svelte dist → `/usr/share/balansir/webui` (served by the daemon, `BALANSIR_WEBUI_DIR`)
- `tailscaled` real daemon ELF → `/usr/bin/tailscaled` (usrmerge-safe install hook)
- systemd units: `balansir-daemon`, `balansir-executor`, `tailscaled`, tmpfiles for `/run/balansir`
- Factory policy: `/etc/balansir/balansir.toml` (fail-open, provisioning-safe)

### Build

```sh
# in the aarch64 Ubuntu build VM
make BR2_EXTERNAL=/path/to/buildroot-external balansir_rpi3b_64_defconfig
make BR2_EXTERNAL=/path/to/buildroot-external -j$(nproc)
# NOTE: for SITE_METHOD=local, a source change requires a balansir rebuild:
rm -f output/build/balansir-0.4.0/.stamp_{built,target_installed,rsynced}
# (Buildroot does not track local-source changes automatically.)
```

### Verification status

**QEMU VERIFIED** (this baseline)
- Boot: kernel 6.18.7 (QEMU) → systemd → balansir-daemon + balansir-executor + tailscaled active
- Networking: eth0 UP, DHCP, gateway ping, DNS via systemd-resolved (A/AAAA resolve)
- BalanSir: `/health /state /qos /b4 /xray /tailscale /metrics /events` respond;
  desired==actual, drift 0; WebUI served at `/` with assets
- QoS: CAKE + HTB + fq_codel attach on eth0 via `/qos`, real `tc` readback,
  external-drift self-heal (deleted qdisc re-applied by reconcile)
- nftables: `inet balansir` table with policy rules; startup recovery re-applies
- B4: engine starts from `BALANSIR_B4_CONFIG`, observes/classifies `example.com`,
  DNS-path adaptation requested on loop (interval 10s); MTU state tracked
- Xray: graceful degraded (profiles empty, no binary — honest)
- Tailscale: `NeedsLogin` backend state (no tailnet in QEMU), TUN `tailscale0` created
- Recovery: daemon restart, executor restart (IPC reconnect), network ok,
  external nft/qdisc drift corrected, full reboot restores services + policy
- Resources (1 GB guest): daemon ~5 MB RSS, executor ~4 MB RSS, tailscaled ~47 MB RSS,
  WebUI 140 KB; stable over a 3+ min soak (no growth/event storm)

**PHYSICAL RPI MANUAL VERIFICATION REQUIRED**
- Real boot on RPi 3B+ (firmware/DTB, UART, SD power delivery)
- Real Ethernet (lan78xx) DHCP + LAN reachability of API/WebUI
- Tailscale auth flow + tailnet connectivity (needs interactive login)
- Real WAN QoS effect under actual load
- B4 real-path MTU/DNS adaptation against a real remote host
- Xray against a real proxy endpoint
- Physical long-run stability / reboot from SD

### Reproducibility

- Buildroot: 2026.05.1
- Kernel: raspberrypi/linux `21b410140c47ffab5668399f6f143c7d7b935c8b` (bcm2711 defconfig)
- Toolchain: ARM aarch64 external (download), glibc
- `BR2_REPRODUCIBLE=y`
- Final production image (2026-08-15):
  `sdcard-rpi-baseline.img` (built from Git `main` @ 3f1c9be), 335544832 bytes (320 MiB),
  SHA256 `0bfc140a9de8a008f9cfeda682045e80efcec7b453248ce616ce0f1cb5c9a123`
- Boot partition: `Image`, `bcm2710-rpi-3-b{-plus,cm3}.dtb`, `bootcode.bin`,
  `fixup.dat`, `start.elf`, `overlays/`, `cmdline.txt`
  (`... net.ifnames=0 biosdevname=0`), `config.txt` (UART debug, arm_64bit)

## DNS gateway (LAN DNS forwarder)

The daemon embeds a UDP DNS forwarder (`dns.rs`, feature `dns`) that can serve
DNS to the whole LAN. Enable it with a forwarder config:

```toml
# /etc/balansir/dns.toml
listen = "192.168.3.12:53"          # LAN address of the RPi
upstreams = ["1.1.1.1:53", "8.8.8.8:53"]
cache_size = 10000
log_queries = true
```

Point the daemon at it (systemd drop-in `balansir-daemon.service.d/dns.conf`):

```ini
[Service]
Environment=BALANSIR_DNS_CONFIG=/etc/balansir/dns.toml
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
```

The daemon runs unprivileged (User=balansir); `CAP_NET_BIND_SERVICE` lets it
bind privileged port 53 without any other privilege. `systemd-resolved` keeps
serving the loopback (127.0.0.53) for local processes.

**VERIFIED** on RPi 3B+: forwarder listens on 192.168.3.12:53, serves A/AAAA,
logs queries, cache on.

Then point LAN clients' DNS at 192.168.3.12 (router DHCP DNS option) to make
the RPi the network's DNS gateway.

## DPI-bypass (Rust-native NFQUEUE engine)

BalanSir ships a pure-Rust DPI-bypass engine (`balansir-b4` crate): it binds a
kernel NFQUEUE (netlink, no C dependency), inspects TCP TLS-SNI to identify
the destination host, and applies per-domain bypass strategies before the
packet is forwarded. Classic b4 ("Bye Bye Big Bro") techniques, implemented in
Rust: MSS rewrite, TCP-option (SACK) stripping, TTL disorientation.

Enable with a profile config:

```toml
# /etc/balansir/dpi.toml
queue_num = 0
ports = [443]

[[profiles]]
name = "youtube"
domains = ["youtube.com", "googlevideo.com"]
strategies = [
  { kind = "mss", mss = 1200 },
  { kind = "strip_sack" },
]

[[profiles]]
name = "chatgpt"
domains = ["openai.com", "chatgpt.com"]
strategies = [ { kind = "ttl", ttl = 63 } ]
```

Daemon drop-in `balansir-daemon.service.d/dpi.conf`:

```ini
[Service]
Environment=BALANSIR_DPI_CONFIG=/etc/balansir/dpi.toml
```

Kernel requirements (in `linux.fragment`): `CONFIG_NETFILTER_NETLINK_QUEUE=y`,
`CONFIG_NFT_QUEUE=y`, `CONFIG_NETFILTER_XT_TARGET_NFQUEUE=y`, `CONFIG_NF_QUEUE=y`.
The daemon runs unprivileged with `CAP_NET_ADMIN` to bind the queue + install
the nft `queue` rule. Status/counters: `GET /api/dpi` and the WebUI DPI view.

**QEMU VERIFIED**: engine binds NFQUEUE, loads profiles, `/dpi` reports
enabled/queue/ports/profiles/counters; kernel accepts `queue num` nft rules;
live interception verified end-to-end: TCP data is received, TLS SNI
extracted (`youtube.com`), profile strategies applied (MSS + TTL rewrite)
and the mutated packet returned via payload-replace verdict — `/dpi` counters
`packets_seen`/`tls_packets`/`mutated` increment and the queue drains (no
stall), while the peer still receives the (re-written) ClientHello intact.
Verified fixes against kernel 6.18: config message must not send
`NFQA_CFG_FLAGS` without `NFQA_CFG_MASK` (kernel rejects with `-EINVAL`,
leaving copy_mode=COPY_NONE which silently drops queued packets); verdict
header is `nfqnl_msg_verdict_hdr` (verdict + packet id, 8 bytes); netlink
recv buffers must be zero-length `Vec::with_capacity` (netlink_sys fills via
`BufMut::chunk_mut()`, which points past a pre-filled vec).

**PHYSICAL RPI MANUAL VERIFICATION REQUIRED**: real intercepted traffic against
a blocked/DPI'd endpoint to confirm a chosen strategy actually restores
connectivity (depends on the ISP's DPI behavior).

## VPN alternative-path pool

BalanSir selects the transport path through a single authoritative decision
engine (`path_decision`): Direct → B4 → VPN pool. The VPN pool
(`balansir-vpn` crate) manages a set of validated VLESS endpoint profiles
from an external subscription:

- **Importer**: parses `vless://` config URIs (percent-decoded, bounded),
  validates host/port/transport/security/credential, normalizes, dedupes by a
  stable content-hash identity, and rejects unsupported schemes with reasons
  (no fake protocol support). Only protocols the current Xray runtime speaks
  are accepted (VLESS + TCP/WS/gRPC/HTTPUpgrade + none/tls/reality).
- **Health**: each profile uses the unified `PathHealth` model (no second
  health system). States: Unknown / Healthy / Degraded / Cooldown / Failed /
  Recovering.
- **Selection**: deterministic weighted selection (state + latency +
  availability + load headroom), flow stickiness, capacity-aware load
  distribution, failure rotation + optional planned rotation (dwell +
  hysteresis + "don't break a significantly-better path"), recovery with
  ramp-up weights [10,25,50,100].
- **Atomic update**: a subscription refresh validates + dedupes, then replaces
  the pool only if non-empty; a failed/empty import keeps the known-good pool
  (mission §15 — never "download failed → empty pool").
- **Xray as consumer**: the Xray manager runs exactly the profile the pool
  selects (`apply_pool_selection(host:port)`); the pool is authoritative.
  `None` stops the proxy (traffic direct).

Enable with `BALANSIR_VPN_CONFIG`:

```toml
source_url = "https://example.com/sub.txt"   # external subscription (vless://)
# local_source = "/etc/balansir/local-sub.txt"  # offline alternative
refresh_interval_secs = 3600
health_interval_secs = 30
selection_interval_secs = 10

[pool]
min_dwell_secs = 120
failure_cooldown_secs = 60
rotation_interval_secs = 0   # 0 = planned rotation disabled
better_threshold = 25.0
capacity_per_profile = 64
```

Fetches run **unprivileged** in the daemon via bounded `curl` (no shell
interpolation, no executor involvement, `--max-filesize 1MiB`). API:
`GET /vpn/pool`, `POST /vpn/{pause,refresh,rotate,pin}`; unified decision:
`GET /path/decision`. WebUI: VPN Pool view + Dashboard path banner.

**QEMU VERIFIED**: pool crate unit tests (31) + vpn_manager integration tests
+ Xray pool-consumer tests + path-decision tests all green; aarch64 daemon
builds with the pool wired in.

**PHYSICAL RPI MANUAL VERIFICATION REQUIRED**: a real subscription fetch and
live Xray rotation on the RPi (depends on network availability of the external
source and of the endpoints).
