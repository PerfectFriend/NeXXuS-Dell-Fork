//! Example P2P client for a NeXXuS node.
//!
//! Speaks the node's wire protocol v3 directly (no node code needed beyond
//! `nexxus-core`): Ed25519 `NodeAnnounce` handshake, then `Ping`, `StoreChunk`
//! and `FetchChunk` round-trip against the peer.
//!
//! Usage:
//!   cargo run -p nexxus-core --example p2p_client -- 127.0.0.1:4001
//!   cargo run -p nexxus-core --example p2p_client -- <onion>.onion:4001 --socks 127.0.0.1:9050
//!
//! Framing: `u32 BE length || frame`; frame = 110-byte v3 header + payload.
//! Every frame is Ed25519-signed over `v3_signing_bytes(opcode, req, payload, session_nonce)`.

use std::io::{Read, Write};
use std::net::TcpStream;

use ed25519_dalek::VerifyingKey;
use rand::RngCore;
use sha2::{Digest, Sha256};

use nexxus_core::keys::identity::Identity;
use nexxus_core::types::ChunkHash;
use nexxus_core::wire::header::{encode_v3, parse_v3, v3_signing_bytes, FrameV3};
use nexxus_core::wire::opcode::Opcode;
use nexxus_core::wire::payloads::{
    FetchChunk, FetchChunkResp, NodeAnnounce, Payload, Ping, Pong, StoreChunk, StoreChunkAck,
};

type BoxErr = Box<dyn std::error::Error>;

fn send_frame(s: &mut TcpStream, frame: Vec<u8>) -> Result<(), BoxErr> {
    s.write_all(&(frame.len() as u32).to_be_bytes())?;
    s.write_all(&frame)?;
    Ok(())
}

fn recv_exact(s: &mut TcpStream, n: usize) -> Result<Vec<u8>, BoxErr> {
    let mut buf = vec![0u8; n];
    s.read_exact(&mut buf)?;
    Ok(buf)
}

fn recv_frame(s: &mut TcpStream) -> Result<FrameV3, BoxErr> {
    let len = u32::from_be_bytes(recv_exact(s, 4)?.try_into().map_err(|_| "bad length prefix")? ) as usize;
    Ok(parse_v3(&recv_exact(s, len)?)?)
}

/// Connect through a SOCKS5 proxy (lets us dial `.onion` via a local Tor).
fn socks5_connect(socks: &str, target: &str) -> Result<TcpStream, BoxErr> {
    let mut s = TcpStream::connect(socks)?;
    s.write_all(&[0x05, 0x01, 0x00])?;
    let mut resp = [0u8; 2];
    s.read_exact(&mut resp)?;
    if resp != [0x05, 0x00] {
        return Err("socks5: no acceptable auth method".into());
    }
    let (host, port) = target.rsplit_once(':').ok_or("target must be host:port")?;
    let port: u16 = port.parse()?;
    let hb = host.as_bytes();
    let mut req = vec![0x05, 0x01, 0x00, 0x03, hb.len() as u8];
    req.extend_from_slice(hb);
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req)?;
    let mut head = [0u8; 4];
    s.read_exact(&mut head)?;
    if head[1] != 0x00 {
        return Err(format!("socks5: connect failed, code 0x{:02x}", head[1]).into());
    }
    match head[3] {
        0x01 => {
            recv_exact(&mut s, 4)?;
        }
        0x04 => {
            recv_exact(&mut s, 16)?;
        }
        0x03 => {
            let l = recv_exact(&mut s, 1)?[0] as usize;
            recv_exact(&mut s, l)?;
        }
        _ => {}
    }
    recv_exact(&mut s, 2)?;
    Ok(s)
}

fn send_signed(
    id: &Identity,
    nonce: &[u8; 32],
    s: &mut TcpStream,
    op: Opcode,
    req: u32,
    p: &impl Payload,
) -> Result<(), BoxErr> {
    let payload = p.encode();
    let sig = id.sign(&v3_signing_bytes(op, req, &payload, nonce));
    send_frame(s, encode_v3(op, req, &payload, &sig))
}

fn recv_verified(
    s: &mut TcpStream,
    peer_vk: &VerifyingKey,
    peer_nonce: &[u8; 32],
    expect_op: Opcode,
    expect_req: u32,
) -> Result<FrameV3, BoxErr> {
    let f = recv_frame(s)?;
    if f.opcode != expect_op {
        return Err(format!("expected {:?}, got {:?}", expect_op, f.opcode).into());
    }
    if f.request_id != expect_req {
        return Err(format!("expected req {}, got {}", expect_req, f.request_id).into());
    }
    let msg = v3_signing_bytes(f.opcode, f.request_id, &f.payload, peer_nonce);
    if !Identity::verify(peer_vk, &msg, &f.signature) {
        return Err("peer frame signature invalid".into());
    }
    Ok(f)
}

fn main() -> Result<(), BoxErr> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: {} <host:port> [--socks <host:port>]", args[0]);
        std::process::exit(2);
    }
    let target = args[1].clone();
    let socks = args
        .windows(2)
        .find(|w| w[0] == "--socks")
        .map(|w| w[1].clone());

    let mut stream = match &socks {
        Some(s) => socks5_connect(s, &target)?,
        None => TcpStream::connect(&target)?,
    };
    stream.set_read_timeout(Some(std::time::Duration::from_secs(60)))?;
    println!("[*] connected to {target}");

    let id = Identity::generate();
    let mut nonce = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    println!("[*] our node_id = {}", hex::encode(id.node_id().0));

    // --- 1. handshake: NodeAnnounce (must be the very first frame) ---
    let req = 1u32;
    let announce = NodeAnnounce {
        node_id: id.node_id().0,
        pubkey: id.verifying_key.to_bytes(),
        ip: 0,
        port: 0,
        session_nonce: nonce,
    };
    send_signed(&id, &nonce, &mut stream, Opcode::NodeAnnounce, req, &announce)?;
    let f = recv_frame(&mut stream)?;
    if f.opcode != Opcode::NodeAnnounce || f.request_id != req {
        return Err(format!("handshake failed: {:?} req {}", f.opcode, f.request_id).into());
    }
    let peer_ann = NodeAnnounce::decode(&f.payload)?;
    let peer_vk = VerifyingKey::from_bytes(&peer_ann.pubkey)?;
    let msg = v3_signing_bytes(f.opcode, f.request_id, &f.payload, &peer_ann.session_nonce);
    if !Identity::verify(&peer_vk, &msg, &f.signature) {
        return Err("peer announce signature invalid".into());
    }
    let peer_nonce = peer_ann.session_nonce;
    println!("[<] handshake ok, peer node_id = {}", hex::encode(peer_ann.node_id));

    // --- 2. Ping -> Pong ---
    send_signed(&id, &nonce, &mut stream, Opcode::Ping, 2, &Ping)?;
    let f = recv_verified(&mut stream, &peer_vk, &peer_nonce, Opcode::Pong, 2)?;
    let _ = Pong::decode(&f.payload)?;
    println!("[<] Pong ok (signed by peer)");

    // --- 3. StoreChunk -> StoreChunkAck ---
    let mut data = vec![0u8; 64 * 1024];
    rand::rngs::OsRng.fill_bytes(&mut data);
    let hash = Sha256::digest(&data);
    let chunk_hash = ChunkHash(hash.into());
    let store = StoreChunk {
        chunk_hash,
        file_id: 1,
        chunk_index: 0,
        data: data.clone(),
    };
    send_signed(&id, &nonce, &mut stream, Opcode::StoreChunk, 3, &store)?;
    let f = recv_verified(&mut stream, &peer_vk, &peer_nonce, Opcode::StoreChunkAck, 3)?;
    let ack = StoreChunkAck::decode(&f.payload)?;
    if ack.hash != chunk_hash.0 {
        return Err("ack hash mismatch".into());
    }
    println!("[<] StoreChunkAck ok, hash = {}", hex::encode(ack.hash));

    // --- 4. FetchChunk -> FetchChunkResp, compare data ---
    let fetch = FetchChunk { hash: chunk_hash.0 };
    send_signed(&id, &nonce, &mut stream, Opcode::FetchChunk, 4, &fetch)?;
    let f = recv_verified(&mut stream, &peer_vk, &peer_nonce, Opcode::FetchChunkResp, 4)?;
    let resp = FetchChunkResp::decode(&f.payload)?;
    if resp.data != data {
        return Err("fetched data differs from stored".into());
    }
    println!("[<] FetchChunkResp ok, {} bytes round-tripped", resp.data.len());

    println!("[✓] P2P client works end-to-end: handshake + ping + store + fetch");
    Ok(())
}
