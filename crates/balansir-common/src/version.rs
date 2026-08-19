pub const IPC_VERSION: u8 = 1;

pub fn check_ipc_compatibility(remote_version: u8) -> bool {
    remote_version == IPC_VERSION
}
