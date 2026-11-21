//! Vault operations (plan phase 6): chunked + RS(4+2) + AEAD upload/download,
//! local Proof-of-Retrievability benchmark, inter-host P2P diagnostic.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use nexxus_core::chunk::{self, ChunkAead};
use nexxus_core::error::NexxusError;
use nexxus_core::merkle::{self, PorChallenge};
use nexxus_core::rs;
use nexxus_core::types::ChunkHash;
use nexxus_core::wire::payloads::StoreChunk;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::net::network::P2pNetwork;
use crate::storage::ChunkStore;

/// Chunk size for vault slicing (README: exactly 16 KB micro-blocks).
pub const CHUNK_SIZE: usize = 16384;

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn meta_key(root_hex: &str) -> String {
    format!("manifest_{root_hex}")
}

/// Slice `path` into 16 KB chunks, RS(4+2)-encode and AEAD-seal each shard,
/// store locally and push to all known peers. Returns the file manifest root.
pub async fn upload_file(
    net: &P2pNetwork,
    store: &Arc<ChunkStore>,
    path: &Path,
) -> Result<Value, NexxusError> {
    let data = std::fs::read(path)
        .map_err(|e| NexxusError::Io(format!("read {}: {e}", path.display())))?;
    if data.is_empty() {
        return Err(NexxusError::Io("refusing to upload an empty file".into()));
    }
    // Per-file random vault key — travels inside the manifest (zero-knowledge:
    // storage nodes never see it), NOT derived from any node identity.
    let file_key: [u8; 32] = rand::random();
    let file_id: u32 = rand::random();
    let peers = net.known_peers().await;
    let chunks = chunk::slice(&data);
    let mut chunk_entries = Vec::with_capacity(chunks.len());
    let mut chunk_roots = Vec::with_capacity(chunks.len());
    for (i, plain) in chunks.iter().enumerate() {
        // C-3: сначала AEAD-seal всего чанка целиком (случайный nonce внутри),
        // затем RS-кодирование ШИФРТЕКСТА. Раньше RS делался над plaintext,
        // а seal вызывался на каждый шард с одним (key, index) и нулевым
        // nonce — все 6 шардов делили keystream.
        let sealed = ChunkAead::seal(&file_key, i as u64, plain)?;
        let shards = rs::encode(&sealed);
        let mut shard_hashes: Vec<ChunkHash> = Vec::with_capacity(rs::TOTAL_SHARDS);
        for (s, shard) in shards.iter().enumerate() {
            let _ = s;
            let hash = ChunkHash(sha256(shard));
            store.put_chunk(&hash, shard)?;
            for p in &peers {
                // E6 onion-only: чанк с флагом не отдаётся clearnet-пирам (routing table = TCP).
                if store.is_onion_only(&hash)? {
                    continue;
                }
                let sc = StoreChunk {
                    chunk_hash: hash,
                    file_id,
                    chunk_index: i as u32,
                    data: shard.clone(),
                };
                let _ = net.send_store_chunk(p.addr, &sc).await;
            }
            shard_hashes.push(hash);
        }
        chunk_roots.push(merkle::merkle_root(
            &shard_hashes.iter().map(|h| h.0).collect::<Vec<_>>(),
        ));
        chunk_entries.push(json!({
            "index": i,
            "plain_len": plain.len(),
            "sealed_len": sealed.len(),
            "shard_hashes": shard_hashes.iter().map(|h| hex::encode(h.0)).collect::<Vec<_>>(),
        }));
    }
    let root = merkle::merkle_root(&chunk_roots);
    let root_hex = hex::encode(root);
    let manifest = json!({
        "root": root_hex,
        "name": path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(),
        "file_id": file_id,
        "key": hex::encode(file_key),
        "total_len": data.len(),
        "chunk_size": CHUNK_SIZE,
        "chunks": chunk_entries,
    });
    store.put_meta(&meta_key(&root_hex), manifest.to_string().as_bytes())?;
    Ok(json!({
        "root": root_hex,
        "file_id": file_id,
        "bytes": data.len(),
        "chunks": chunk_entries.len(),
        "shards_per_chunk": rs::TOTAL_SHARDS,
        "peers_pushed": peers.len(),
    }))
}

/// Reassemble a file from its manifest root: fetch shards (local first, then
/// peers), AEAD-open, RS-decode, verify the merkle root, write to `out`.
pub async fn download_file(
    net: &P2pNetwork,
    store: &Arc<ChunkStore>,
    root_hex: &str,
    out: &Path,
) -> Result<Value, NexxusError> {
    let raw = store
        .get_meta(&meta_key(root_hex))?
        .ok_or_else(|| NexxusError::Io(format!("unknown file root: {root_hex}")))?;
    let manifest: Value = serde_json::from_slice(&raw)
        .map_err(|e| NexxusError::Io(format!("corrupt manifest: {e}")))?;
    let key_hex = manifest["key"]
        .as_str()
        .ok_or_else(|| NexxusError::Io("manifest has no vault key".into()))?;
    let file_key: [u8; 32] = hex::decode(key_hex)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .ok_or_else(|| NexxusError::Io("manifest vault key is not 32 bytes hex".into()))?;
    let peers = net.known_peers().await;
    let total_len = manifest["total_len"].as_u64().unwrap_or(0) as usize;
    let mut out_data: Vec<u8> = Vec::with_capacity(total_len);
    let mut chunk_roots = Vec::new();
    let chunk_list = manifest["chunks"].as_array().cloned().unwrap_or_default();
    for c in &chunk_list {
        let index = c["index"].as_u64().unwrap_or(0);
        let plain_len = c["plain_len"].as_u64().unwrap_or(0) as usize;
        // C-3: seal-then-RS — шард = кусок шифртекста; sealed_len = plain_len + 28 (nonce+tag)
        let sealed_len = c["sealed_len"].as_u64().unwrap_or(0) as usize;
        let sealed_len = if sealed_len == 0 { plain_len + 28 } else { sealed_len };
        let shard_hexes = c["shard_hashes"].as_array().cloned().unwrap_or_default();
        let shard_hashes: Vec<ChunkHash> = shard_hexes
            .iter()
            .filter_map(|h| {
                hex::decode(h.as_str()?)
                    .ok()
                    .and_then(|b| <[u8; 32]>::try_from(b).ok())
                    .map(ChunkHash)
            })
            .collect();
        let mut shards: Vec<(Vec<u8>, usize)> = Vec::with_capacity(rs::DATA_SHARDS);
        for (s, h) in shard_hashes.iter().enumerate() {
            if shards.len() >= rs::DATA_SHARDS {
                break;
            }
            let shard_raw = match store.get_chunk(h)? {
                Some(d) => d,
                None => {
                    let mut got = None;
                    for p in &peers {
                        if let Ok(d) = net.fetch_chunk_from_peer(p.addr, *h).await {
                            got = Some(d);
                            break;
                        }
                    }
                    got.ok_or_else(|| {
                        NexxusError::Io(format!(
                            "shard {s} of chunk {index} unavailable locally and on all peers"
                        ))
                    })?
                }
            };
            shards.push((shard_raw, s));
        }
        let refs: Vec<(&[u8], usize)> = shards.iter().map(|(d, i)| (d.as_slice(), *i)).collect();
        let sealed = rs::decode(&refs, sealed_len)?;
        let plain = ChunkAead::open(&file_key, index, &sealed)?;
        chunk_roots.push(merkle::merkle_root(
            &shard_hashes.iter().map(|h| h.0).collect::<Vec<_>>(),
        ));
        out_data.extend_from_slice(&plain);
    }
    let root = merkle::merkle_root(&chunk_roots);
    if hex::encode(root) != root_hex {
        return Err(NexxusError::Io(format!(
            "merkle root mismatch after download: computed {}",
            hex::encode(root)
        )));
    }
    std::fs::write(out, &out_data)
        .map_err(|e| NexxusError::Io(format!("write {}: {e}", out.display())))?;
    Ok(json!({
        "root": root_hex,
        "out": out.display().to_string(),
        "bytes": out_data.len(),
        "chunks": chunk_list.len(),
    }))
}

/// PROD-RESTORE-01 / Phase 2: Rehydrate missing shards for a manifest from connected peers in the mesh.
pub async fn rehydrate_manifest_from_mesh(
    net: &P2pNetwork,
    store: &ChunkStore,
    manifest: &Value,
) -> Result<Value, NexxusError> {
    let root_hex = manifest["root"].as_str().unwrap_or("unknown");
    let chunk_list = manifest["chunks"].as_array().cloned().unwrap_or_default();
    let peers = net.known_peers().await;

    let mut total_shards = 0usize;
    let mut already_local = 0usize;
    let mut fetched_count = 0usize;
    let mut missing_count = 0usize;

    for chunk in &chunk_list {
        let shard_hexes = chunk["shard_hashes"].as_array().cloned().unwrap_or_default();
        for h_val in shard_hexes {
            total_shards += 1;
            let Some(h_str) = h_val.as_str() else { continue; };
            let Ok(bytes) = hex::decode(h_str) else { continue; };
            let Ok(arr) = <[u8; 32]>::try_from(bytes) else { continue; };
            let hash = ChunkHash(arr);

            if store.get_chunk(&hash)?.is_some() {
                already_local += 1;
                continue;
            }

            let mut fetched_shard = None;
            for p in &peers {
                if let Ok(d) = net.fetch_chunk_from_peer(p.addr, hash).await {
                    fetched_shard = Some(d);
                    break;
                }
            }

            if let Some(data) = fetched_shard {
                store.put_chunk(&hash, &data)?;
                fetched_count += 1;
            } else {
                missing_count += 1;
            }
        }
    }

    let present_total = already_local + fetched_count;
    let progress_pct = if total_shards == 0 {
        100.0
    } else {
        (present_total as f64 / total_shards as f64) * 100.0
    };

    Ok(json!({
        "root": root_hex,
        "total_shards": total_shards,
        "already_local": already_local,
        "fetched": fetched_count,
        "missing": missing_count,
        "progress_pct": (progress_pct * 10.0).round() / 10.0,
        "peers_consulted": peers.len(),
    }))
}

/// Local Proof-of-Retrievability benchmark over a stored (or synthetic) chunk.
pub fn run_por(store: &ChunkStore) -> Result<Value, NexxusError> {
    let t0 = Instant::now();
    let hashes = store.list_chunk_hashes()?;
    let (hash, data) = match hashes
        .first()
        .and_then(|h| store.get_chunk(h).ok().flatten().map(|d| (*h, d)))
    {
        Some(x) => x,
        None => {
            let d: Vec<u8> = (0..CHUNK_SIZE).map(|_| rand::random::<u8>()).collect();
            (ChunkHash(sha256(&d)), d)
        }
    };
    let challenge = PorChallenge {
        seed: rand::random(),
        chunk_index: 0,
    };
    let resp = merkle::por_response(&data, &challenge);
    let ok = merkle::por_verify(&data, &resp, &challenge);
    Ok(json!({
        "chunk": hex::encode(hash.0),
        "ok": ok,
        "elapsed_ms": t0.elapsed().as_millis() as u64,
        "chunks_total": hashes.len(),
    }))
}

/// Full inter-host diagnostic against a peer: announce, find_node, store,
/// fetch+verify, ping RTT. Each phase reports ok + latency.
pub async fn test_interhost(net: &P2pNetwork, addr: SocketAddr) -> Result<Value, NexxusError> {
    let mut phases: Vec<Value> = Vec::new();

    let t = Instant::now();
    let r = net.send_node_announce(addr).await;
    phases.push(json!({
        "phase": 1, "name": "announce", "ok": r.is_ok(),
        "ms": t.elapsed().as_millis() as u64,
        "peer_node_id": r.ok().map(|id| hex::encode(id.0)),
    }));

    let t = Instant::now();
    let r = net.dial_find_node(addr, net.our_id(), 8).await;
    phases.push(json!({
        "phase": 2, "name": "find_node", "ok": r.is_ok(),
        "ms": t.elapsed().as_millis() as u64,
        "nodes": r.map(|v| v.len()).unwrap_or(0),
    }));

    let data: Vec<u8> = (0..CHUNK_SIZE).map(|i| (i % 251) as u8).collect();
    let hash = ChunkHash(sha256(&data));
    let sc = StoreChunk {
        chunk_hash: hash,
        file_id: 0xC0DE,
        chunk_index: 0,
        data: data.clone(),
    };
    let t = Instant::now();
    let r = net.send_store_chunk(addr, &sc).await;
    phases.push(json!({
        "phase": 3, "name": "store_chunk", "ok": r.is_ok(),
        "ms": t.elapsed().as_millis() as u64,
        "ack": r.ok().map(|h| hex::encode(h.0)),
    }));

    let t = Instant::now();
    let r = net.fetch_chunk_from_peer(addr, hash).await;
    let ok = matches!(&r, Ok(d) if *d == data);
    phases.push(json!({
        "phase": 4, "name": "fetch_chunk", "ok": ok,
        "ms": t.elapsed().as_millis() as u64,
    }));

    let t = Instant::now();
    let r = net.ping(addr).await;
    phases.push(json!({
        "phase": 5, "name": "ping", "ok": r.is_ok(),
        "ms": r.map(|d| d.as_millis() as u64).unwrap_or_else(|_| t.elapsed().as_millis() as u64),
    }));

    let ok = phases.iter().all(|p| p["ok"] == json!(true));
    Ok(json!({ "peer": addr.to_string(), "ok": ok, "phases": phases }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::network::P2pNetwork;
    use nexxus_core::types::NodeId;
    use tempfile::tempdir;

    async fn spawn(
        b: u8,
    ) -> (
        Arc<P2pNetwork>,
        SocketAddr,
        tokio::task::JoinHandle<Result<(), NexxusError>>,
    ) {
        let dir = tempdir().unwrap();
        let store = Arc::new(ChunkStore::open(dir.path().join("store.redb")).unwrap());
        let net = Arc::new(P2pNetwork::new(
            NodeId([b; 32]),
            "127.0.0.1:0".parse().unwrap(),
            store,
        ));
        let clone = Arc::clone(&net);
        let server = tokio::spawn(async move { clone.run().await });
        let mut addr = None;
        for _ in 0..100 {
            addr = net.bound_addr().await;
            if addr.is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        (net, addr.expect("bind"), server)
    }

    #[tokio::test]
    async fn upload_on_a_download_from_b_bit_identical() {
        let (net_a, addr_a, server_a) = spawn(0xA1).await;
        let (net_b, addr_b, server_b) = spawn(0xB2).await;
        // Both directions of the announce handshake so each routing table
        // knows the other.
        net_a.send_node_announce(addr_b).await.unwrap();
        net_b.send_node_announce(addr_a).await.unwrap();

        let dir = tempdir().unwrap();
        let file = dir.path().join("blob.bin");
        let data: Vec<u8> = (0..100_000u32).map(|i| (i % 256) as u8).collect();
        std::fs::write(&file, &data).unwrap();

        let up = upload_file(&net_a, net_a.store(), &file).await.unwrap();
        let root = up["root"].as_str().unwrap().to_string();
        assert!(up["peers_pushed"].as_u64().unwrap() >= 1, "shards must be pushed to B");

        // The manifest travels out-of-band; copy it into B's store.
        let key = format!("manifest_{root}");
        let manifest = net_a.store().get_meta(&key).unwrap().unwrap();
        net_b.store().put_meta(&key, &manifest).unwrap();

        let out = dir.path().join("restored.bin");
        let dl = download_file(&net_b, net_b.store(), &root, &out).await.unwrap();
        assert_eq!(dl["bytes"].as_u64().unwrap() as usize, data.len());
        assert_eq!(std::fs::read(&out).unwrap(), data, "bit-identical restore");

        server_a.abort();
        server_b.abort();
    }

    #[tokio::test]
    async fn rehydrate_missing_shards_from_mesh_recovers_all() {
        // PROD-RESTORE-01 / Phase 2: Fresh node with empty store imports manifest
        // and rehydrates all missing shards from the P2P mesh, achieving 100% restore.
        let (net_a, addr_a, server_a) = spawn(0x11).await;
        let (net_b, addr_b, server_b) = spawn(0x22).await;
        let (net_c, _addr_c, server_c) = spawn(0x33).await;

        net_a.send_node_announce(addr_b).await.unwrap();
        net_b.send_node_announce(addr_a).await.unwrap();

        let dir = tempdir().unwrap();
        let file = dir.path().join("source.bin");
        // 16KB fits in 1 chunk (6 shards total) to stay within per-test NET-01 IP rate limit
        let data: Vec<u8> = (0..16_000u32).map(|i| ((i * 31 + 7) % 256) as u8).collect();
        std::fs::write(&file, &data).unwrap();

        let up = upload_file(&net_a, net_a.store(), &file).await.unwrap();
        let root = up["root"].as_str().unwrap().to_string();

        // Fresh node C knows peer A and peer B
        net_c.send_node_announce(addr_a).await.unwrap();
        net_c.send_node_announce(addr_b).await.unwrap();

        // Manifest is imported into C's meta
        let key = format!("manifest_{root}");
        let manifest_bytes = net_a.store().get_meta(&key).unwrap().unwrap();
        let manifest_val: Value = serde_json::from_slice(&manifest_bytes).unwrap();
        net_c.store().put_meta(&key, &manifest_bytes).unwrap();

        // Node C has 0 shards initially
        assert_eq!(net_c.store().list_chunk_hashes().unwrap().len(), 0);

        // Rehydrate from mesh
        let rep = rehydrate_manifest_from_mesh(&net_c, net_c.store(), &manifest_val)
            .await
            .unwrap();

        assert_eq!(rep["already_local"], 0);
        assert!(rep["fetched"].as_u64().unwrap() > 0);
        assert_eq!(rep["missing"], 0);
        assert_eq!(rep["progress_pct"], 100.0);

        // Verify file can now be reconstructed from C's rehydrated store
        let out = dir.path().join("rehydrated.bin");
        let dl = download_file(&net_c, net_c.store(), &root, &out).await.unwrap();
        assert_eq!(dl["bytes"].as_u64().unwrap() as usize, data.len());
        assert_eq!(std::fs::read(&out).unwrap(), data, "bit-identical mesh rehydration");

        server_a.abort();
        server_b.abort();
        server_c.abort();
    }

    #[test]
    fn por_benchmark_ok_and_under_3s() {
        let dir = tempdir().unwrap();
        let store = ChunkStore::open(dir.path().join("s.redb")).unwrap();
        let r = run_por(&store).unwrap();
        assert_eq!(r["ok"], json!(true));
        assert!(r["elapsed_ms"].as_u64().unwrap() < 3000);
    }
}
