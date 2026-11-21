//! dApp Manifest and Sovereign Application Environment (Phase 3).
//! Defines `app.nexxus.json` manifest schema and SLIP-0010 app-isolated key derivation.

use nexxus_core::error::NexxusError;
use nexxus_core::keys::slip10::DerivedKey;
use serde::{Deserialize, Serialize};

/// Standard dApp Manifest (`app.nexxus.json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppManifest {
    pub name: String,
    pub app_id: u32,
    pub version: String,
    pub description: String,
    pub bundle_root_hex: String,
    pub storage_quota_mb: u64,
    pub permissions: Vec<String>,
}

impl AppManifest {
    /// Validates all manifest constraints per Phase 3 specifications.
    pub fn validate(&self) -> Result<(), NexxusError> {
        if self.name.trim().is_empty() {
            return Err(NexxusError::Io("app manifest: name cannot be empty".into()));
        }
        if self.app_id == 0 {
            return Err(NexxusError::Io("app manifest: app_id must be non-zero".into()));
        }
        if self.bundle_root_hex.len() != 64 || hex::decode(&self.bundle_root_hex).is_err() {
            return Err(NexxusError::Io("app manifest: bundle_root_hex must be 64-char hex string".into()));
        }
        if self.storage_quota_mb == 0 {
            return Err(NexxusError::Io("app manifest: storage_quota_mb must be > 0".into()));
        }
        for perm in &self.permissions {
            match perm.as_str() {
                "storage:read" | "storage:write" | "smp:send" | "network:peers" => {}
                other => {
                    return Err(NexxusError::Io(format!("app manifest: unknown permission '{other}'")));
                }
            }
        }
        Ok(())
    }

    /// Derives the cryptographic identity key isolated specifically for this application
    /// according to SLIP-0010: m / 44' / 999' / app_id' / 0 / 0.
    pub fn derive_isolated_key(&self, seed: &[u8; 64]) -> Result<DerivedKey, NexxusError> {
        self.validate()?;
        DerivedKey::for_dapp(seed, self.app_id)
    }

    /// Serializes manifest to canonical JSON.
    pub fn to_json(&self) -> Result<String, NexxusError> {
        serde_json::to_string_pretty(self).map_err(|e| NexxusError::Io(e.to_string()))
    }

    /// Parses manifest from JSON string.
    pub fn from_json(json_str: &str) -> Result<Self, NexxusError> {
        let manifest: Self = serde_json::from_str(json_str)
            .map_err(|e| NexxusError::Io(format!("invalid app.nexxus.json: {e}")))?;
        manifest.validate()?;
        Ok(manifest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_manifest_roundtrip_and_isolated_key() {
        let json = r#"{
            "name": "NeXXus Chat",
            "app_id": 42,
            "version": "1.0.0",
            "description": "Decentralized P2P Sovereign Messenger",
            "bundle_root_hex": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "storage_quota_mb": 50,
            "permissions": ["storage:read", "storage:write", "smp:send"]
        }"#;

        let manifest = AppManifest::from_json(json).unwrap();
        assert_eq!(manifest.name, "NeXXus Chat");
        assert_eq!(manifest.app_id, 42);

        let seed = [7u8; 64];
        let app_key = manifest.derive_isolated_key(&seed).unwrap();
        assert_eq!(app_key.path[2], 42 | 0x8000_0000);
    }

    #[test]
    fn rejects_invalid_permissions_or_zero_quota() {
        let bad_json = r#"{
            "name": "Malicious App",
            "app_id": 1,
            "version": "1.0.0",
            "description": "Bad App",
            "bundle_root_hex": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "storage_quota_mb": 0,
            "permissions": ["root:admin"]
        }"#;

        assert!(AppManifest::from_json(bad_json).is_err());
    }
}
