use crate::{Error, Result};

/// Validate hardware profile
pub fn validate_profile(profile: &crate::Profile) -> Result<()> {
    // Device validation
    if profile.device.ram_mb == 0 {
        return Err(Error::Misconfiguration("ram_mb must be > 0".into()));
    }
    if profile.device.cpu_cores == 0 {
        return Err(Error::Misconfiguration("cpu_cores must be > 0".into()));
    }

    // Memory validation
    if profile.memory.daemon_rss_max_mb == 0 {
        return Err(Error::Misconfiguration(
            "daemon_rss_max_mb must be > 0".into(),
        ));
    }
    if profile.memory.executor_rss_max_mb == 0 {
        return Err(Error::Misconfiguration(
            "executor_rss_max_mb must be > 0".into(),
        ));
    }

    // Drivers validation
    if profile.drivers.max_active == 0 {
        return Err(Error::Misconfiguration(
            "max_active drivers must be > 0".into(),
        ));
    }

    // State validation
    if profile.state.journal_capacity == 0 {
        return Err(Error::Misconfiguration(
            "journal_capacity must be > 0".into(),
        ));
    }

    // Network validation
    if profile.network.max_firewall_rules == 0 {
        return Err(Error::Misconfiguration(
            "max_firewall_rules must be > 0".into(),
        ));
    }

    Ok(())
}

/// Validate policy rules
pub fn validate_policy_rules(rules: &[crate::DesiredRule]) -> Result<()> {
    let mut seen_ids = std::collections::HashSet::new();

    for rule in rules {
        if rule.id == 0 {
            return Err(Error::Misconfiguration(format!(
                "Rule ID must be > 0 (rule: {})",
                rule.id
            )));
        }

        if !seen_ids.insert(rule.id) {
            return Err(Error::Misconfiguration(format!(
                "Duplicate rule ID: {}",
                rule.id
            )));
        }
    }

    Ok(())
}

/// Validate IPC message
pub fn validate_ipc_message(msg: &crate::ipc::IpcMessage) -> Result<()> {
    if msg.payload.len() > crate::ipc::MAX_PAYLOAD_SIZE {
        return Err(Error::PayloadTooLarge {
            size: msg.payload.len(),
            max: crate::ipc::MAX_PAYLOAD_SIZE,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::{
        DeviceConfig, DriversConfig, MemoryConfig, NetworkConfig, Profile, ResourcesConfig,
        RuntimeConfig, StateConfig, UpdatesConfig,
    };

    fn test_profile() -> Profile {
        Profile {
            device: DeviceConfig {
                name: "test".to_string(),
                arch: "x86_64".to_string(),
                ram_mb: 512,
                cpu_cores: 1,
            },
            runtime: RuntimeConfig {
                flavor: "current_thread".to_string(),
                blocking_threads: 2,
            },
            memory: MemoryConfig {
                daemon_rss_max_mb: 12,
                executor_rss_max_mb: 8,
                data_plane_rss_max_mb: 45,
                event_bus_capacity: 64,
                state_cache_mb: 2,
            },
            drivers: DriversConfig {
                max_active: 1,
                default: "wireguard".to_string(),
                enabled: vec!["wireguard".to_string()],
            },
            state: StateConfig {
                backend: "file".to_string(),
                journal_capacity: 256,
            },
            updates: UpdatesConfig {
                ab_slots: true,
                boot_counter_max: 3,
            },
            network: NetworkConfig {
                max_firewall_rules: 512,
                max_routes: 256,
                nftables_batch_size: 64,
            },
            resources: ResourcesConfig {
                max_fwmarks: 64,
                max_route_tables: 32,
            },
        }
    }

    #[test]
    fn test_validate_profile_valid() {
        let profile = test_profile();
        assert!(validate_profile(&profile).is_ok());
    }

    #[test]
    fn test_validate_profile_invalid_ram() {
        let mut profile = test_profile();
        profile.device.ram_mb = 0;
        assert!(validate_profile(&profile).is_err());
    }

    #[test]
    fn test_validate_policy_rules_valid() {
        let rules = vec![crate::DesiredRule {
            id: 1,
            action: crate::Action::Block,
            priority: 100,
            flow: None,
        }];
        assert!(validate_policy_rules(&rules).is_ok());
    }

    #[test]
    fn test_validate_policy_rules_duplicate() {
        let rules = vec![
            crate::DesiredRule {
                id: 1,
                action: crate::Action::Block,
                priority: 100,
                flow: None,
            },
            crate::DesiredRule {
                id: 1,
                action: crate::Action::Allow,
                priority: 50,
                flow: None,
            },
        ];
        assert!(validate_policy_rules(&rules).is_err());
    }
}
