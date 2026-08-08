use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    pub device: DeviceConfig,
    pub runtime: RuntimeConfig,
    pub memory: MemoryConfig,
    pub drivers: DriversConfig,
    pub state: StateConfig,
    pub updates: UpdatesConfig,
    pub network: NetworkConfig,
    pub resources: ResourcesConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceConfig {
    pub name: String,
    pub arch: String,
    pub ram_mb: u32,
    pub cpu_cores: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeConfig {
    pub flavor: String,
    pub blocking_threads: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryConfig {
    pub daemon_rss_max_mb: u32,
    pub executor_rss_max_mb: u32,
    pub data_plane_rss_max_mb: u32,
    pub event_bus_capacity: usize,
    pub state_cache_mb: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriversConfig {
    pub max_active: u32,
    pub default: String,
    pub enabled: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateConfig {
    pub backend: String,
    pub journal_capacity: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdatesConfig {
    pub ab_slots: bool,
    pub boot_counter_max: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub max_firewall_rules: u32,
    pub max_routes: u32,
    pub nftables_batch_size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourcesConfig {
    pub max_fwmarks: u32,
    pub max_route_tables: u32,
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ProfileError {
    #[error("failed to read profile {path}: {reason}")]
    Io { path: String, reason: String },

    #[error("failed to parse profile {path}: {reason}")]
    Parse { path: String, reason: String },

    #[error("invalid profile: {0}")]
    Validation(String),
}

impl Profile {
    pub fn load(path: &Path) -> Result<Self, ProfileError> {
        let content = std::fs::read_to_string(path).map_err(|e| ProfileError::Io {
            path: path.display().to_string(),
            reason: e.to_string(),
        })?;

        let profile: Profile = toml::from_str(&content).map_err(|e| ProfileError::Parse {
            path: path.display().to_string(),
            reason: e.to_string(),
        })?;

        profile.validate()?;
        Ok(profile)
    }

    fn validate(&self) -> Result<(), ProfileError> {
        if self.device.ram_mb == 0 {
            return Err(ProfileError::Validation("ram_mb must be > 0".into()));
        }

        if self.device.cpu_cores == 0 {
            return Err(ProfileError::Validation("cpu_cores must be > 0".into()));
        }

        if self.memory.daemon_rss_max_mb == 0 {
            return Err(ProfileError::Validation(
                "daemon_rss_max_mb must be > 0".into(),
            ));
        }

        if self.drivers.max_active == 0 {
            return Err(ProfileError::Validation(
                "max_active drivers must be > 0".into(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_parse() {
        let toml = r#"
[device]
name = "Test"
arch = "x86_64"
ram_mb = 512
cpu_cores = 1

[runtime]
flavor = "current_thread"
blocking_threads = 2

[memory]
daemon_rss_max_mb = 12
executor_rss_max_mb = 8
data_plane_rss_max_mb = 45
event_bus_capacity = 64
state_cache_mb = 2

[drivers]
max_active = 1
default = "wireguard"
enabled = ["wireguard"]

[state]
backend = "file"
journal_capacity = 256

[updates]
ab_slots = true
boot_counter_max = 3

[network]
max_firewall_rules = 512
max_routes = 256
nftables_batch_size = 64

[resources]
max_fwmarks = 64
max_route_tables = 32
"#;

        let profile: Profile = toml::from_str(toml).unwrap();
        assert_eq!(profile.device.name, "Test");
        assert_eq!(profile.device.ram_mb, 512);
        assert_eq!(profile.drivers.max_active, 1);
    }
}
