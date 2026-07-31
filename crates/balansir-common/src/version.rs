pub const IPC_VERSION: u8 = 1;
pub const STATE_VERSION: u32 = 1;
pub const POLICY_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompatStatus {
    Compatible,
    MigrationNeeded,
    Incompatible,
}

pub fn check_ipc_compatibility(remote_version: u8) -> bool {
    remote_version == IPC_VERSION
}

pub fn check_state_compatibility(stored_version: u32) -> CompatStatus {
    match stored_version {
        v if v == STATE_VERSION => CompatStatus::Compatible,
        v if v < STATE_VERSION => CompatStatus::MigrationNeeded,
        _ => CompatStatus::Incompatible,
    }
}
