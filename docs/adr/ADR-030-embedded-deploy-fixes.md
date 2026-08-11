# ADR-030: Embedded deployment defect fixes (found during Buildroot mission)

## Status
Accepted

## Context

During the Buildroot embedded-image mission, a runtime/security audit of the
deployment units found defects that would break BalanSir on any real target
(systemd or Buildroot). These are defects, not design changes (§37 of the
mission: fix well-supported defects, minimal + tested + documented).

## Findings and fixes

### 1. `Type=notify` without `sd_notify` → units never become active
`balansir-daemon.service`/`balansir-executor.service` declared
`Type=notify` + `WatchdogSec=30`, but neither binary calls `sd_notify()`.
systemd waits for the readiness signal, times out, and (with `Restart=on-failure`)
kills/restarts the service forever. The service never becomes `active`.

**Fix:** `Type=simple`, `WatchdogSec` removed. (A future `sd_notify` upgrade
would be a separate feature; `Type=simple` is correct for the current
binaries.)

### 2. `BALANSIR_ALLOWED_UIDS=[0]` breaks daemon↔executor IPC auth
IPC peer auth (ADR-013) validates the peer's UID against
`BALANSIR_ALLOWED_UIDS`, default `[0]` (root only). The daemon runs as the
unprivileged `balansir` user (UID 1500); the executor is root. With the
default allowlist the executor rejects the daemon's control connection —
every reconcile fails, silently, on any real deployment.

**Fix:** both units set `BALANSIR_ALLOWED_UIDS=0,1500` (root for operator CLI +
the daemon's fixed UID). The daemon's UID is pinned to 1500 via `useradd --uid
1500` in the install path and via the Buildroot package user table.

### 3. `User=balansir` with no user created
The daemon unit ran as `balansir`, but no install path created the user.

**Fix:** `deploy/rpi3b/install.sh` and the Makefile install path now create the
`balansir` system user (UID 1500, nologin) and `/var/lib/balansir`. The
Buildroot package declares the user in its user table.

### 4. `/run/balansir` ownership between two UIDs
Both the daemon (UID 1500) and the executor (root) must create sockets in
`/run/balansir`. `RuntimeDirectory` on a single unit would pick one owner.

**Fix:** `deploy/systemd/tmpfiles.d/balansir.conf` creates `/run/balansir`
as `root:balansir 0775` before any service starts (systemd-tmpfiles), and both
units keep `ReadWritePaths=/run/balansir`. The install path installs the
tmpfiles config.

### 5. Stale `scripts/balansir-cli` bash wrapper clobbers the real CLI
`scripts/balansir-cli` was a leftover bash wrapper pointing at
`/tmp/balansir-test/daemon.sock`; the Makefile installed it instead of the
compiled CLI, breaking `balansir-cli status` on deployed systems.

**Fix:** the wrapper is removed; the Makefile (install-bin, deb target)
installs the compiled `target/release/balansir-cli`.

### 6. Executor `Requires=balansir-daemon.service` ordering
The executor declared `Requires=balansir-daemon.service`, forcing the daemon
to start before the executor — backwards (the daemon connects to the
executor). The daemon already retries, but the ordering was wrong.

**Fix:** the executor has no `Requires`; the daemon has
`After=balansir-executor.service` (start the executor first, daemon reconnects
on failure).

## Consequences

- Services become actually `active` under systemd.
- IPC auth works with the unprivileged daemon; reconcile runs for real.
- `/run/balansir` is writable by both UIDs.
- The installed CLI is the compiled binary.
- All fixes are packaging/deployment-level; no core architecture change
  (privilege separation, executor-as-dumb-mechanism, daemon authority all
  preserved).

## Verification

- `sh -n deploy/rpi3b/install.sh`; units inspected via `systemd-analyze
  verify` on a Linux host (Buildroot QEMU image, Phase 4 of the mission).
- Workspace 18 suites, clippy 0, fmt clean.
