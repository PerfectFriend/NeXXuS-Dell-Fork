//! High-level NeXXUs Node Client (Phase 3).
//! Provides a typed async API for interacting with local or remote NeXXUs daemons over WebSocket JSON-RPC.

use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::Path;
use nexxus_core::error::NexxusError;
use nexxus_core::smp::ContactLink;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeStatus {
    pub node_id: String,
    pub uptime_secs: u64,
    pub used_bytes: u64,
    pub total_chunks: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadResult {
    pub root: String,
    pub size_bytes: u64,
    pub chunks_count: usize,
}

#[derive(Debug, Clone)]
pub struct NexxusClient {
    api_addr: String,
    auth_token: Option<String>,
}

impl NexxusClient {
    /// Create client with default local API address (127.0.0.1:4010).
    pub fn new() -> Self {
        Self {
            api_addr: "127.0.0.1:4010".to_string(),
            auth_token: None,
        }
    }

    pub fn with_addr(mut self, addr: impl Into<String>) -> Self {
        self.api_addr = addr.into();
        self
    }

    pub fn with_token(mut self, token: impl Into<String>) -> Self {
        self.auth_token = Some(token.into());
        self
    }

    /// Low-level JSON-RPC execution over WebSocket.
    pub async fn rpc_call(&self, method: &str, params: Value) -> Result<Value, NexxusError> {
        let url = format!("ws://{}", self.api_addr);
        let (ws, _) = tokio_tungstenite::connect_async(&url)
            .await
            .map_err(|e| NexxusError::Io(format!("connect {url}: {e}")))?;
        let (mut write, mut read) = ws.split();

        if let Some(token) = &self.auth_token {
            let auth_req = json!({
                "jsonrpc": "2.0", "id": 1, "method": "auth", "params": {"token": token}
            });
            write
                .send(tokio_tungstenite::tungstenite::Message::Text(auth_req.to_string()))
                .await
                .map_err(|e| NexxusError::Io(e.to_string()))?;

            if let Some(msg) = read.next().await {
                let text = msg.map_err(|e| NexxusError::Io(e.to_string()))?.into_text().map_err(|e| NexxusError::Io(e.to_string()))?;
                let v: Value = serde_json::from_str(&text).map_err(|e| NexxusError::Io(e.to_string()))?;
                if let Some(err) = v.get("error") {
                    if !err.is_null() {
                        return Err(NexxusError::Io(format!("auth error: {err}")));
                    }
                }
            }
        }

        let req = json!({
            "jsonrpc": "2.0", "id": 2, "method": method, "params": params
        });
        write
            .send(tokio_tungstenite::tungstenite::Message::Text(req.to_string()))
            .await
            .map_err(|e| NexxusError::Io(e.to_string()))?;

        while let Some(msg) = read.next().await {
            if let Ok(tokio_tungstenite::tungstenite::Message::Text(t)) = msg {
                let v: Value = serde_json::from_str(&t).map_err(|e| NexxusError::Io(e.to_string()))?;
                if let Some(err) = v.get("error") {
                    if !err.is_null() {
                        return Err(NexxusError::Io(err.to_string()));
                    }
                }
                return Ok(v.get("result").cloned().unwrap_or(Value::Null));
            }
        }

        Err(NexxusError::Io("connection closed before response".into()))
    }

    /// Query node status.
    pub async fn status(&self) -> Result<Value, NexxusError> {
        self.rpc_call("node_status", json!({})).await
    }

    /// Upload a file to sovereign CAS storage mesh.
    pub async fn upload_file(&self, path: &Path) -> Result<Value, NexxusError> {
        let abs = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        self.rpc_call("node_upload", json!({ "path": abs.display().to_string() })).await
    }

    /// Download a file by its Merkle manifest root hash.
    pub async fn download_file(&self, root_hex: &str, out_path: &Path) -> Result<Value, NexxusError> {
        self.rpc_call("node_download", json!({ "root": root_hex, "out": out_path.display().to_string() })).await
    }

    /// Send E2EE SMP message.
    pub async fn smp_send(
        &self,
        recipient_node_id: &str,
        recipient_pub: &str,
        message: &str,
    ) -> Result<Value, NexxusError> {
        self.rpc_call(
            "node_smp_send",
            json!({
                "recipient_node_id": recipient_node_id,
                "recipient_pub": recipient_pub,
                "message": message,
            }),
        )
        .await
    }

    /// Generate ContactLink URI (Spec §7).
    pub async fn contact_link(&self, name: &str) -> Result<ContactLink, NexxusError> {
        let res = self.rpc_call("node_contact_link", json!({ "name": name })).await?;
        let uri = res["uri"].as_str().ok_or_else(|| NexxusError::Io("missing uri".into()))?;
        ContactLink::from_uri(uri)
    }

    /// Parse ContactLink URI.
    pub async fn contact_parse(&self, uri: &str) -> Result<ContactLink, NexxusError> {
        let res = self.rpc_call("node_contact_parse", json!({ "uri": uri })).await?;
        let full_uri = res["uri"].as_str().unwrap_or(uri);
        ContactLink::from_uri(full_uri)
    }

    /// Trigger Proof-of-Retrievability (PoR) audit.
    pub async fn run_por(&self) -> Result<Value, NexxusError> {
        self.rpc_call("node_por", json!({})).await
    }
}

impl Default for NexxusClient {
    fn default() -> Self {
        Self::new()
    }
}
