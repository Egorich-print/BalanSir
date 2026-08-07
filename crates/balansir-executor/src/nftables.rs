use balansir_common::error::{Error, Result};
use std::process::Command;
use tracing::{debug, info};

/// Absolute path to the `nft` binary, resolved from standard locations.
fn nft_bin() -> Result<std::path::PathBuf> {
    balansir_common::paths::resolve_bin("nft")
        .ok_or_else(|| Error::Misconfiguration("nft binary not found".into()))
}

pub struct NftablesBackend {
    table_name: String,
    chain_name: String,
}

impl NftablesBackend {
    pub fn new(table_name: &str, chain_name: &str) -> Self {
        Self {
            table_name: table_name.to_string(),
            chain_name: chain_name.to_string(),
        }
    }

    pub fn init(&self) -> Result<()> {
        // Create table if not exists
        let output = Command::new(nft_bin()?)
            .args(["add", "table", "inet", &self.table_name])
            .output();

        match output {
            Ok(_) => {
                debug!("Created nftables table: {}", self.table_name);
            }
            Err(e) => {
                // Table might already exist
                debug!("Table creation result: {}", e);
            }
        }

        // Create chain if not exists
        let output = Command::new(nft_bin()?)
            .args(["add", "chain", "inet", &self.table_name, &self.chain_name])
            .output();

        match output {
            Ok(_) => {
                debug!("Created nftables chain: {}", self.chain_name);
            }
            Err(e) => {
                debug!("Chain creation result: {}", e);
            }
        }

        Ok(())
    }

    pub fn add_rule(&self, rule: &str) -> Result<()> {
        let output = Command::new(nft_bin()?)
            .args([
                "add",
                "rule",
                "inet",
                &self.table_name,
                &self.chain_name,
                rule,
            ])
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(balansir_common::Error::Fatal(format!(
                "nft add rule failed: {}",
                stderr
            )));
        }

        debug!("Added nftables rule: {}", rule);
        Ok(())
    }

    pub fn flush(&self) -> Result<()> {
        let output = Command::new(nft_bin()?)
            .args(["flush", "chain", "inet", &self.table_name, &self.chain_name])
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(balansir_common::Error::Fatal(format!(
                "nft flush failed: {}",
                stderr
            )));
        }

        info!("Flushed nftables chain: {}", self.chain_name);
        Ok(())
    }

    pub fn list_rules(&self) -> Result<Vec<String>> {
        let output = Command::new(nft_bin()?)
            .args(["list", "chain", "inet", &self.table_name, &self.chain_name])
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(balansir_common::Error::Fatal(format!(
                "nft list failed: {}",
                stderr
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let rules: Vec<String> = stdout
            .lines()
            .filter(|line| line.contains("accept") || line.contains("drop"))
            .map(|line| line.trim().to_string())
            .collect();

        Ok(rules)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nftables_backend_creation() {
        let backend = NftablesBackend::new("balansir", "forward");
        assert_eq!(backend.table_name, "balansir");
        assert_eq!(backend.chain_name, "forward");
    }
}
