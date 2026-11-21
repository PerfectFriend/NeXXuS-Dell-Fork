//! Sync Folder Engine (Phase 2): Managed local sovereign drive folder (~/.nexxus/drive or ~/NeXXus).
//! Scans directory, digests files into 16 KB chunks, encodes into RS(4+2), seals with per-file key,
//! stores in CAS, and maintains local index mapping relative paths to manifest roots.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use nexxus_core::error::NexxusError;
use crate::net::network::P2pNetwork;
use crate::storage::ChunkStore;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncedFile {
    pub relative_path: String,
    pub root_hex: String,
    pub size_bytes: u64,
    pub mtime_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncReport {
    pub drive_path: String,
    pub scanned_files: usize,
    pub newly_synced: usize,
    pub total_bytes: u64,
    pub errors: Vec<String>,
}

pub struct SyncEngine {
    drive_dir: PathBuf,
    store: Arc<ChunkStore>,
    network: Arc<P2pNetwork>,
}

impl SyncEngine {
    pub fn new(drive_dir: PathBuf, store: Arc<ChunkStore>, network: Arc<P2pNetwork>) -> Self {
        Self { drive_dir, store, network }
    }

    pub fn drive_path(&self) -> &Path {
        &self.drive_dir
    }

    /// Scans the drive directory, identifies new/modified files, and syncs them to the vault.
    pub async fn scan_and_sync(&self) -> Result<SyncReport, NexxusError> {
        if !self.drive_path().exists() {
            std::fs::create_dir_all(self.drive_path())
                .map_err(|e| NexxusError::Io(format!("create drive dir: {e}")))?;
        }

        let mut scanned = 0usize;
        let mut newly_synced = 0usize;
        let mut total_bytes = 0u64;
        let mut errors = Vec::new();

        let entries = walk_dir(self.drive_path());
        for path in entries {
            if !path.is_file() {
                continue;
            }
            scanned += 1;
            let meta = match path.metadata() {
                Ok(m) => m,
                Err(e) => {
                    errors.push(format!("{}: metadata error {e}", path.display()));
                    continue;
                }
            };

            let size = meta.len();
            total_bytes += size;
            if size == 0 {
                continue;
            }

            let rel_path = path
                .strip_prefix(self.drive_path())
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_else(|_| path.file_name().unwrap_or_default().to_string_lossy().into_owned());

            // Check if already indexed under this size
            let sync_key = format!("sync_idx_{rel_path}");
            let needs_sync = match self.store.get_meta(&sync_key)? {
                Some(raw) => {
                    let prev: Result<SyncedFile, _> = serde_json::from_slice(&raw);
                    match prev {
                        Ok(p) => p.size_bytes != size,
                        Err(_) => true,
                    }
                }
                None => true,
            };

            if needs_sync {
                match crate::vault::upload_file(&self.network, &self.store, &path).await {
                    Ok(up) => {
                        let root_hex = up["root"].as_str().unwrap_or_default().to_string();
                        let synced = SyncedFile {
                            relative_path: rel_path.clone(),
                            root_hex,
                            size_bytes: size,
                            mtime_unix: meta
                                .modified()
                                .ok()
                                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                                .map(|d| d.as_secs())
                                .unwrap_or(0),
                        };
                        let raw = serde_json::to_vec(&synced).map_err(|e| NexxusError::Io(e.to_string()))?;
                        self.store.put_meta(&sync_key, &raw)?;
                        newly_synced += 1;
                    }
                    Err(e) => {
                        errors.push(format!("{}: sync upload error: {e}", path.display()));
                    }
                }
            }
        }

        Ok(SyncReport {
            drive_path: self.drive_dir.display().to_string(),
            scanned_files: scanned,
            newly_synced,
            total_bytes,
            errors,
        })
    }

    /// List all currently indexed files in this drive from the store metadata.
    pub fn list_synced(&self) -> Result<Vec<SyncedFile>, NexxusError> {
        let mut list = Vec::new();
        for (_k, v) in self.store.list_meta_prefix("sync_idx_")? {
            if let Ok(file) = serde_json::from_slice::<SyncedFile>(&v) {
                list.push(file);
            }
        }
        list.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
        Ok(list)
    }

    /// Query the status of the sovereign drive folder and its indexed files.
    pub fn status(&self) -> Result<Value, NexxusError> {
        let files = self.list_synced()?;
        let total_size: u64 = files.iter().map(|f| f.size_bytes).sum();
        Ok(serde_json::json!({
            "drive_path": self.drive_dir.display().to_string(),
            "exists": self.drive_dir.exists(),
            "synced_files_count": files.len(),
            "total_bytes": total_size,
            "files": files,
        }))
    }
}

/// Returns the standard default Sovereign Drive directory (~/.nexxus/drive).
pub fn default_drive_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".nexxus").join("drive")
}

fn walk_dir(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                files.push(path);
            } else if path.is_dir() {
                files.extend(walk_dir(&path));
            }
        }
    }
    files
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use crate::net::network::P2pNetwork;
    use nexxus_core::types::NodeId;

    #[tokio::test]
    async fn sync_engine_scans_and_uploads_files() {
        let dir = tempdir().unwrap();
        let store_path = dir.path().join("store.redb");
        let store = Arc::new(ChunkStore::open(&store_path).unwrap());
        let net = Arc::new(P2pNetwork::new(
            NodeId([0x55; 32]),
            "127.0.0.1:0".parse().unwrap(),
            store.clone(),
        ));

        let drive_dir = dir.path().join("drive");
        std::fs::create_dir_all(&drive_dir).unwrap();

        let doc1 = drive_dir.join("hello.txt");
        std::fs::write(&doc1, b"Hello NeXXus Sovereign Drive!").unwrap();

        let engine = SyncEngine::new(drive_dir.clone(), store.clone(), net.clone());
        assert_eq!(engine.drive_path(), &drive_dir);
        let rep = engine.scan_and_sync().await.unwrap();

        assert_eq!(rep.scanned_files, 1);
        assert_eq!(rep.newly_synced, 1);
        assert!(rep.total_bytes > 0);
        assert!(rep.errors.is_empty());

        // Subsequent scan with unchanged file does not re-upload
        let rep2 = engine.scan_and_sync().await.unwrap();
        assert_eq!(rep2.scanned_files, 1);
        assert_eq!(rep2.newly_synced, 0);

        // Verify status
        let st = engine.status().unwrap();
        assert_eq!(st["synced_files_count"], 1);
        assert_eq!(st["files"][0]["relative_path"], "hello.txt");
    }
}
