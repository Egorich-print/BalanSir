use balansir_common::DriverError;
use netlink_packet_route::link::LinkMessage;
use rtnetlink::new_connection;
use std::net::Ipv4Addr;

/// Network interface management via netlink
pub struct NetlinkManager {
    handle: rtnetlink::Handle,
}

impl NetlinkManager {
    /// Create a new netlink manager
    pub async fn new() -> Result<Self, DriverError> {
        let (connection, handle, _) = new_connection()
            .map_err(|e| DriverError::StartFailed(format!("Netlink connection failed: {}", e)))?;

        // Spawn the connection handler
        tokio::spawn(connection);

        Ok(Self { handle })
    }

    /// Create a WireGuard interface
    pub async fn create_wireguard_interface(&self, name: &str) -> Result<(), DriverError> {
        self.handle
            .link()
            .add()
            .name(name.to_string())
            .execute()
            .await
            .map_err(|e| {
                DriverError::InterfaceError(format!("Failed to create interface {}: {}", name, e))
            })?;

        Ok(())
    }

    /// Delete an interface
    pub async fn delete_interface(&self, name: &str) -> Result<(), DriverError> {
        let link = self.get_link_by_name(name).await?;
        self.handle
            .link()
            .del(link.index())
            .execute()
            .await
            .map_err(|e| {
                DriverError::InterfaceError(format!("Failed to delete interface {}: {}", name, e))
            })?;

        Ok(())
    }

    /// Bring interface up
    pub async fn set_interface_up(&self, name: &str) -> Result<(), DriverError> {
        let link = self.get_link_by_name(name).await?;
        self.handle
            .link()
            .set(link.index())
            .up()
            .execute()
            .await
            .map_err(|e| {
                DriverError::InterfaceError(format!("Failed to set interface {} up: {}", name, e))
            })?;

        Ok(())
    }

    /// Bring interface down
    pub async fn set_interface_down(&self, name: &str) -> Result<(), DriverError> {
        let link = self.get_link_by_name(name).await?;
        self.handle
            .link()
            .set(link.index())
            .down()
            .execute()
            .await
            .map_err(|e| {
                DriverError::InterfaceError(format!("Failed to set interface {} down: {}", name, e))
            })?;

        Ok(())
    }

    /// Add IP address to interface
    pub async fn add_address(
        &self,
        name: &str,
        addr: Ipv4Addr,
        prefix_len: u8,
    ) -> Result<(), DriverError> {
        let link = self.get_link_by_name(name).await?;
        self.handle
            .address()
            .add(link.index(), addr.into(), prefix_len)
            .execute()
            .await
            .map_err(|e| {
                DriverError::InterfaceError(format!("Failed to add address to {}: {}", name, e))
            })?;

        Ok(())
    }

    /// Add route
    pub async fn add_route(
        &self,
        dest: Option<(Ipv4Addr, u8)>,
        gateway: Option<Ipv4Addr>,
        interface: Option<&str>,
    ) -> Result<(), DriverError> {
        let mut request = self.handle.route().add();

        if let Some((addr, prefix)) = dest {
            request = request.destination(addr, prefix);
        }

        if let Some(gw) = gateway {
            request = request.gateway(gw.into());
        }

        if let Some(iface) = interface {
            let link = self.get_link_by_name(iface).await?;
            request = request.output_interface(link.index());
        }

        request
            .execute()
            .await
            .map_err(|e| DriverError::InterfaceError(format!("Failed to add route: {}", e)))?;

        Ok(())
    }

    /// Check if interface exists
    pub async fn interface_exists(&self, name: &str) -> bool {
        self.get_link_by_name(name).await.is_ok()
    }

    /// Get link by name
    async fn get_link_by_name(&self, name: &str) -> Result<LinkMessage, DriverError> {
        let mut links = self
            .handle
            .link()
            .get()
            .match_name(name.to_string())
            .execute();

        links
            .try_next()
            .await
            .map_err(|e| {
                DriverError::InterfaceError(format!("Failed to get link {}: {}", name, e))
            })?
            .ok_or_else(|| DriverError::InterfaceError(format!("Interface {} not found", name)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_netlink_manager_creation() {
        // This test requires root/CAP_NET_ADMIN
        // Skip in CI
        if !is_root() {
            return;
        }

        let manager = NetlinkManager::new().await;
        assert!(manager.is_ok());
    }

    fn is_root() -> bool {
        unsafe { libc::getuid() == 0 }
    }
}
