//! OTA update manifest and cryptographic verification.
//!
//! The manifest is the trust anchor for OTA updates. It contains metadata
//! about the firmware image and an Ed25519 signature over the canonical
//! TOML representation. The public key is embedded in the production firmware.

use balansir_common::{Error, Result};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::path::Path;
use std::str::FromStr;

/// Ed25519 public key identifier for key rotation support.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyId(pub String);

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// OTA update manifest.
///
/// This is the canonical format for update metadata. The `signature` field
/// covers the entire TOML document EXCEPT the signature field itself
/// (canonical serialization with signature omitted).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateManifest {
    /// Manifest format version.
    #[serde(default = "default_manifest_version")]
    pub version: u32,

    /// Firmware version being delivered (semver).
    pub firmware_version: String,

    /// Target hardware identifier (e.g., "rpi3b", "rpi3b-plus").
    pub target_device: String,

    /// Release channel (stable, beta, alpha).
    #[serde(default = "default_channel")]
    pub channel: String,

    /// Minimum firmware version required (anti-rollback).
    /// If absent, any older version is allowed (not recommended for production).
    pub min_version: Option<String>,

    /// Image metadata.
    pub image: ImageInfo,

    /// Cryptographic signature.
    pub signature: SignatureInfo,
}

fn default_manifest_version() -> u32 {
    1
}

fn default_channel() -> String {
    "stable".to_string()
}

/// Image download and verification info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageInfo {
    /// HTTPS URL to download the firmware image (.img.xz or .img.gz).
    /// Must be HTTPS with valid TLS certificate.
    pub url: String,

    /// Expected size in bytes.
    pub size: u64,

    /// SHA-256 hash of the decompressed image (lowercase hex).
    pub sha256: String,

    /// Compression format: "xz", "gz", or "none".
    #[serde(default = "default_compression")]
    pub compression: String,
}

fn default_compression() -> String {
    "xz".to_string()
}

/// Signature information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureInfo {
    /// Signature algorithm. Currently only "ed25519".
    #[serde(default = "default_algo")]
    pub algorithm: String,

    /// Key identifier for rotation.
    pub key_id: KeyId,

    /// Base64-encoded Ed25519 signature over canonical manifest TOML
    /// (with signature field omitted).
    pub signature: String,
}

fn default_algo() -> String {
    "ed25519".to_string()
}

/// Embedded public key for update verification.
///
/// In production, this is compiled into the firmware. In development/QEMU,
/// a test key is used.
#[derive(Debug, Clone)]
pub struct UpdateVerifier {
    verifying_key: VerifyingKey,
    key_id: KeyId,
}

impl UpdateVerifier {
    /// Create a verifier from a base64-encoded Ed25519 public key.
    pub fn from_base64(key_b64: &str, key_id: KeyId) -> Result<Self> {
        let key_bytes = base64::decode(key_b64)
            .map_err(|e| Error::Misconfiguration(format!("invalid base64 public key: {e}")))?;
        if key_bytes.len() != 32 {
            return Err(Error::Misconfiguration("Ed25519 public key must be 32 bytes".into()));
        }
        let verifying_key = VerifyingKey::from_bytes(&key_bytes.try_into().unwrap())
            .map_err(|e| Error::Misconfiguration(format!("invalid Ed25519 public key: {e}")))?;
        Ok(Self { verifying_key, key_id })
    }

    /// Create a verifier from raw 32-byte Ed25519 public key.
    pub fn from_bytes(key_bytes: &[u8], key_id: KeyId) -> Result<Self> {
        if key_bytes.len() != 32 {
            return Err(Error::Misconfiguration("Ed25519 public key must be 32 bytes".into()));
        }
        let verifying_key = VerifyingKey::from_bytes(&key_bytes.try_into().unwrap())
            .map_err(|e| Error::Misconfiguration(format!("invalid Ed25519 public key: {e}")))?;
        Ok(Self { verifying_key, key_id })
    }

    /// Verify an update manifest.
    ///
    /// Returns the parsed manifest on success.
    pub fn verify_manifest(&self, manifest_toml: &str) -> Result<UpdateManifest> {
        let manifest: UpdateManifest = toml::from_str(manifest_toml)
            .map_err(|e| Error::Misconfiguration(format!("manifest parse error: {e}")))?;

        // Verify key_id matches
        if manifest.signature.key_id != self.key_id {
            return Err(Error::Misconfiguration(format!(
                "manifest key_id {} does not match embedded key {}",
                manifest.signature.key_id, self.key_id
            )));
        }

        // Verify algorithm
        if manifest.signature.algorithm != "ed25519" {
            return Err(Error::Misconfiguration(format!(
                "unsupported signature algorithm: {}",
                manifest.signature.algorithm
            )));
        }

        // Compute canonical manifest TOML without signature field
        let canonical = self.canonicalize_manifest(manifest_toml)?;

        // Verify signature
        let sig_bytes = base64::decode(&manifest.signature.signature)
            .map_err(|e| Error::Misconfiguration(format!("invalid base64 signature: {e}")))?;
        let signature = Signature::from_bytes(&sig_bytes.try_into().unwrap());

        self.verifying_key.verify(canonical.as_bytes(), &signature)
            .map_err(|_| Error::Misconfiguration("manifest signature verification failed".into()))?;

        Ok(manifest)
    }

    /// Produce canonical TOML for signing/verification.
    ///
    /// Removes the signature field and ensures deterministic key ordering.
    fn canonicalize_manifest(&self, manifest_toml: &str) -> Result<String> {
        let mut value: toml::Value = manifest_toml.parse()
            .map_err(|e| Error::Misconfiguration(format!("manifest parse error: {e}")))?;

        // Remove signature field
        if let Some(table) = value.as_table_mut() {
            table.remove("signature");
        }

        // Serialize with deterministic ordering (toml crate does this)
        let canonical = toml::to_string(&value)
            .map_err(|e| Error::Misconfiguration(format!("canonical serialization failed: {e}")))?;

        Ok(canonical)
    }
}

/// UpdateManifest with additional metadata for the OTA daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedUpdate {
    pub manifest: UpdateManifest,
    pub manifest_raw: String,
}

impl VerifiedUpdate {
    pub fn verify(verifier: &UpdateVerifier, manifest_toml: &str) -> Result<Self> {
        let manifest = verifier.verify_manifest(manifest_toml)?;
        Ok(Self {
            manifest,
            manifest_raw: manifest_toml.to_string(),
        })
    }
}

/// Download and verify a firmware image.
pub async fn download_and_verify_image(
    client: &reqwest::Client,
    image_info: &ImageInfo,
    mut progress: Option<&mut dyn FnMut(u64, u64)>,
) -> Result<Vec<u8>> {
    let response = client.get(&image_info.url).send().await
        .map_err(|e| Error::Temporary(format!("download failed: {e}")))?;

    if !response.status().is_success() {
        return Err(Error::Fatal(format!("download failed: HTTP {}", response.status())));
    }

    let content_length = response.content_length().unwrap_or(image_info.size);
    if content_length != image_info.size as u64 {
        return Err(Error::Misconfiguration(format!(
            "size mismatch: expected {}, got {}",
            image_info.size, content_length
        )));
    }

    let mut stream = response.bytes_stream();
    let mut buffer = Vec::with_capacity(image_info.size as usize);
    let mut downloaded = 0u64;

    use futures::StreamExt;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| Error::Temporary(format!("download error: {e}")))?;
        downloaded += chunk.len() as u64;
        buffer.extend_from_slice(&chunk);

        if let Some(ref mut cb) = progress {
            cb(downloaded, image_info.size);
        }
    }

    if downloaded != image_info.size as u64 {
        return Err(Error::Misconfiguration(format!(
            "incomplete download: expected {}, got {}",
            image_info.size, downloaded
        )));
    }

    // Decompress if needed
    let decompressed = match image_info.compression.as_str() {
        "xz" => {
            let mut decoder = xz2::read::XzDecoder::new(std::io::Cursor::new(&buffer));
            let mut out = Vec::new();
            std::io::copy(&mut decoder, &mut out)
                .map_err(|e| Error::Misconfiguration(format!("xz decompress failed: {e}")))?;
            out
        }
        "gz" => {
            let mut decoder = flate2::read::GzDecoder::new(std::io::Cursor::new(&buffer));
            let mut out = Vec::new();
            std::io::copy(&mut decoder, &mut out)
                .map_err(|e| Error::Misconfiguration(format!("gz decompress failed: {e}")))?;
            out
        }
        "none" => buffer,
        other => return Err(Error::Misconfiguration(format!("unknown compression: {other}"))),
    };

    // Verify SHA-256
    let hash = Sha256::digest(&decompressed);
    let hash_hex = hex::encode(hash);
    if hash_hex != image_info.sha256 {
        return Err(Error::Misconfiguration(format!(
            "SHA-256 mismatch: expected {}, got {}",
            image_info.sha256, hash_hex
        )));
    }

    if decompressed.len() != image_info.size as usize {
        return Err(Error::Misconfiguration(format!(
            "decompressed size mismatch: expected {}, got {}",
            image_info.size, decompressed.len()
        )));
    }

    Ok(decompressed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_parses() {
        let toml = r#"
version = 1
firmware_version = "0.6.0"
target_device = "rpi3b"
channel = "stable"
min_version = "0.5.0"

[image]
url = "https://example.com/firmware.img.xz"
size = 123456789
sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
compression = "xz"

[signature]
algorithm = "ed25519"
key_id = "prod-2024-01"
signature = "BASE64SIGNATURE"
"#;

        let manifest: UpdateManifest = toml::from_str(toml).unwrap();
        assert_eq!(manifest.firmware_version, "0.6.0");
        assert_eq!(manifest.target_device, "rpi3b");
        assert_eq!(manifest.image.compression, "xz");
        assert_eq!(manifest.signature.key_id.0, "prod-2024-01");
    }

    #[test]
    fn canonicalization_removes_signature() {
        let toml = r#"
version = 1
firmware_version = "0.6.0"
target_device = "rpi3b"
channel = "stable"

[image]
url = "https://example.com/firmware.img.xz"
size = 123456789
sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
compression = "xz"

[signature]
algorithm = "ed25519"
key_id = "prod-2024-01"
signature = "BASE64SIGNATURE"
"#;

        let verifier = UpdateVerifier::from_bytes(&[1u8; 32], KeyId("test".into())).unwrap();
        let canonical = verifier.canonicalize_manifest(toml).unwrap();

        assert!(!canonical.contains("signature"));
        assert!(canonical.contains("firmware_version"));
        assert!(canonical.contains("image"));
    }
}