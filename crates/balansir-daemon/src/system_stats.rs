//! Lightweight `/proc` readers for the live dashboard metrics.
//!
//! Deliberately small and allocation-light for low-memory targets: one file
//! read per metric group per refresh, no external collectors, no retained
//! history. CPU utilization is computed from deltas between the previous
//! and current `/proc/stat` samples (the caller keeps the previous sample).

use balansir_common::subsystems::FilesystemInfo;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::time::Duration;

/// A CPU time sample (`/proc/stat` first line).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CpuSample {
    pub idle: u64,
    pub total: u64,
}

/// Read the aggregate CPU sample from `/proc/stat`.
pub fn read_cpu_sample() -> Option<CpuSample> {
    let raw = std::fs::read_to_string("/proc/stat").ok()?;
    let line = raw.lines().next()?;
    let mut fields = line.split_whitespace();
    if fields.next() != Some("cpu") {
        return None;
    }
    let values: Vec<u64> = fields
        .filter_map(|f| f.parse::<u64>().ok())
        .take(8)
        .collect();
    if values.len() < 8 {
        return None;
    }
    // idle = idle + iowait; total = sum of all 8 fields.
    let idle = values[3] + values[4];
    let total: u64 = values.iter().sum();
    Some(CpuSample { idle, total })
}

/// CPU utilization percent between two samples, handling counter wrap.
pub fn cpu_percent(prev: &CpuSample, cur: &CpuSample) -> f64 {
    let total = cur.total.saturating_sub(prev.total);
    if total == 0 {
        return 0.0;
    }
    let idle = cur.idle.saturating_sub(prev.idle);
    let used = total.saturating_sub(idle);
    (used as f64 / total as f64) * 100.0
}

/// Memory in use (used = total - available, from `/proc/meminfo`).
pub fn mem_used_mb() -> Option<(u64, u64)> {
    let raw = std::fs::read_to_string("/proc/meminfo").ok()?;
    let mut total = 0u64;
    let mut available = 0u64;
    for line in raw.lines() {
        let mut parts = line.split_whitespace();
        match parts.next() {
            Some("MemTotal:") => total = parts.next().and_then(|v| v.parse().ok()).unwrap_or(0),
            Some("MemAvailable:") => {
                available = parts.next().and_then(|v| v.parse().ok()).unwrap_or(0)
            }
            _ => {}
        }
    }
    if total == 0 {
        return None;
    }
    let total_mb = total / 1024;
    let available_mb = available / 1024;
    Some((total_mb.saturating_sub(available_mb), total_mb))
}

/// Load averages from `/proc/loadavg` (first three fields).
pub fn load_averages() -> Option<(f64, f64, f64)> {
    let raw = std::fs::read_to_string("/proc/loadavg").ok()?;
    let mut fields = raw.split_whitespace();
    let l1 = fields.next()?.parse().ok()?;
    let l5 = fields.next()?.parse().ok()?;
    let l15 = fields.next()?.parse().ok()?;
    Some((l1, l5, l15))
}

/// System uptime in seconds from `/proc/uptime`.
pub fn uptime_secs() -> Option<u64> {
    let raw = std::fs::read_to_string("/proc/uptime").ok()?;
    let secs = raw.split_whitespace().next()?.parse::<f64>().ok()?;
    Some(secs as u64)
}

/// A full system stats sample; `None` when `/proc` is not available (non-Linux
/// or restricted sandbox).
pub fn system_stats(
    prev_cpu: Option<&CpuSample>,
) -> Option<(balansir_common::subsystems::SystemStats, CpuSample)> {
    let cur = read_cpu_sample()?;
    let (mem_used, mem_total) = mem_used_mb()?;
    let (l1, l5, l15) = load_averages()?;
    let up = uptime_secs().unwrap_or(0);
    let cpu = match prev_cpu {
        Some(prev) => cpu_percent(prev, &cur),
        None => 0.0,
    };
    let filesystems = read_filesystems().unwrap_or_default();
    let stats = balansir_common::subsystems::SystemStats {
        cpu_percent: cpu.round(),
        mem_used_mb: mem_used,
        mem_total_mb: mem_total,
        load1: l1,
        load5: l5,
        load15: l15,
        uptime_secs: up,
        filesystems,
    };
    Some((stats, cur))
}

/// Current unix epoch milliseconds.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Compute bits/sec between two counter samples separated by `elapsed`.
pub fn rate_bps(prev: u64, cur: u64, elapsed: Duration) -> u64 {
    let elapsed_ms = elapsed.as_millis();
    if elapsed_ms == 0 {
        return 0;
    }
    let delta = cur.saturating_sub(prev);
    // bytes per second * 8 → bits/sec
    ((delta as u128) * 8000 / elapsed_ms) as u64
}

/// Read filesystem usage from `/proc/mounts` using `statfs`.
pub fn read_filesystems() -> Option<Vec<FilesystemInfo>> {
    let raw = std::fs::read_to_string("/proc/mounts").ok()?;
    let mut filesystems = Vec::new();

    for line in raw.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            continue;
        }
        let _device = parts[0];
        let mount_point = parts[1];
        let fstype = parts[2];

        // Skip virtual filesystems
        let skip_fstypes = [
            "proc",
            "sysfs",
            "devtmpfs",
            "devpts",
            "tmpfs",
            "cgroup",
            "cgroup2",
            "autofs",
            "pstore",
            "efivarfs",
            "hugetlbfs",
            "mqueue",
            "debugfs",
            "tracefs",
            "configfs",
            "fusectl",
            "rpc_pipefs",
            "nfsd",
            "binfmt_misc",
            "nsfs",
            "overlay",
            "squashfs",
        ];
        if skip_fstypes.iter().any(|&fs| fs == fstype) {
            continue;
        }

        let mount_point = parts[1];
        // Skip mount points under /sys, /proc, /run, /dev (except root /dev)
        if mount_point.starts_with("/sys") || mount_point.starts_with("/proc") {
            continue;
        }
        if mount_point.starts_with("/run") && !mount_point.starts_with("/run/media") {
            continue;
        }
        if mount_point.starts_with("/dev") && mount_point != "/dev" {
            continue;
        }

        // Use statfs to get filesystem usage
        let mount_point_cstr = std::ffi::CString::new(mount_point).ok()?;
        let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
        unsafe {
            if libc::statfs(mount_point_cstr.as_ptr(), &mut stat) != 0 {
                continue;
            }
        }

        // statfs returns blocks, not bytes. Convert to MB.
        let block_size = stat.f_bsize as u64;
        let total_blocks = stat.f_blocks as u64;
        let free_blocks = stat.f_bavail as u64; // available to non-root
        let total_blocks = stat.f_blocks as u64;

        let total_mb = total_blocks.saturating_mul(stat.f_bsize as u64) / 1_048_576;
        let free_mb = stat.f_bavail as u64 * stat.f_bsize as u64 / 1_048_576;
        let used_mb = total_mb.saturating_sub(free_mb);
        let usage_percent = if total_mb > 0 {
            ((total_mb - free_mb) as f64 / total_mb as f64) * 100.0
        } else {
            0.0
        };

        filesystems.push(FilesystemInfo {
            mount_point: mount_point.to_string(),
            total_mb,
            used_mb,
            available_mb: free_mb,
            usage_percent: usage_percent as f64,
            fstype: fstype.to_string(),
        });
    }

    Some(filesystems)
}

#[test]
fn cpu_percent_is_reasonable() {
    let prev = CpuSample {
        idle: 1000,
        total: 2000,
    };
    let cur = CpuSample {
        idle: 1100,
        total: 2200,
    };
    // used = 100, total delta = 200 → 50%
    let pct = cpu_percent(&prev, &cur);
    assert!((pct - 50.0).abs() < 0.01);

    // No progress → 0% (not NaN).
    assert_eq!(cpu_percent(&prev, &prev), 0.0);
}

#[test]
fn cpu_percent_handles_wrap() {
    let prev = CpuSample {
        idle: u64::MAX - 10,
        total: u64::MAX,
    };
    let cur = CpuSample { idle: 5, total: 20 };
    // saturating deltas keep the result finite.
    let pct = cpu_percent(&prev, &cur);
    assert!(pct.is_finite() && (0.0..=100.0).contains(&pct));
}

#[test]
fn rate_computation() {
    let elapsed = Duration::from_secs(2);
    // 125000 bytes in 2s → 500000 bits/s
    assert_eq!(rate_bps(0, 125_000, elapsed), 500_000);
    assert_eq!(rate_bps(100, 50, elapsed), 0); // counter reset → 0
    assert_eq!(rate_bps(1000, 1000, Duration::ZERO), 0);
}

#[test]
#[cfg(target_os = "linux")]
fn proc_readers_work_on_linux() {
    // These may fail in restricted sandboxes without /proc — probe gently.
    if let (Some(mem), Some(load), Some(up)) = (mem_used_mb(), load_averages(), uptime_secs()) {
        assert!(mem.0 <= mem.1);
        assert!(up > 0);
        assert!(load.0.is_finite());
    }
}
