//! NeXXUs Core SDK (crates/nexxus-sdk).
//! High-level SDK for third-party developers, dApps, mobile wrappers, and streaming integrations.
//!
//! # Architecture
//! - [`client::NexxusClient`]: Async WebSocket client interacting with local/remote node daemons.
//! - [`dapp::AppManifest`]: Standard dApp metadata format (`app.nexxus.json`) and SLIP-0010 isolated keys.
//! - [`streaming::ByteRange`]: Sequential chunk reading & Range Requests for media playback.

pub mod client;
pub mod dapp;
pub mod streaming;

pub use client::NexxusClient;
pub use dapp::AppManifest;
pub use streaming::{ByteRange, slice_range_from_chunks};
