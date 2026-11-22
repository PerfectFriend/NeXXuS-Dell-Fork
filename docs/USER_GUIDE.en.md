# USER GUIDE — NeXXuS Sovereign Protocol (v0.229.0)

> **Language versions:** [English](USER_GUIDE.en.md) | [Español](USER_GUIDE.es.md) | [Русский](USER_GUIDE.ru.md)

Welcome to the official User Guide for **NeXXuS Sovereign Protocol** — a fully decentralized, zero-knowledge P2P storage network and end-to-end encrypted messaging system operating natively over Tor Onion v3 with hybrid Post-Quantum cryptographic shielding.

---

## 📑 Table of Contents
1. [Architecture & Core Invariants](#1-architecture--core-invariants)
2. [Quickstart & Installation](#2-quickstart--installation)
   - [Linux / Ubuntu / Debian](#21-linux--ubuntu--debian)
   - [Windows 10 / 11](#22-windows-10--11)
   - [Android (Termux & Native)](#23-android)
3. [Configuration (`node.conf`) & Environment Variables](#3-configuration-nodeconf--environment-variables)
4. [Sovereign Cryptographic Identity & Seed Vault](#4-sovereign-cryptographic-identity--seed-vault)
5. [Sovereign Drive: Automatic Folder Synchronization](#5-sovereign-drive-automatic-folder-synchronization)
6. [E2EE SMP Messenger & QR Contacts (ContactLink)](#6-e2ee-smp-messenger--qr-contacts-contactlink)
7. [Disaster Recovery from Mesh Network (PROD-RESTORE-01)](#7-disaster-recovery-from-mesh-network-prod-restore-01)
8. [Storage Provider Hosting Mode (CLI & Desktop UI)](#8-storage-provider-hosting-mode-cli--desktop-ui)
9. [Post-Quantum Hybrid Shield (PQC) & ZK-SNARK PoR](#9-post-quantum-hybrid-shield-pqc--zk-snark-por)
10. [Complete CLI Command Reference (`nexxusd`)](#10-complete-cli-command-reference-nexxusd)
11. [Desktop Monitor (Tauri GUI Application)](#11-desktop-monitor-tauri-gui-application)
12. [Security, Auditing & Troubleshooting](#12-security-auditing--troubleshooting)

---

## 1. Architecture & Core Invariants

NeXXuS operates completely free of centralized servers, trusted third parties, or cloud dependencies:
- **16 KiB Fixed Slicing**: Every file is sliced into exact 16,384-byte chunks.
- **Reed-Solomon RS(4+2) Erasure Coding**: Each chunk expands into 6 shards (4 data + 2 parity). The file is 100% reconstructible even if any 2 out of 6 storing nodes permanently fail or go offline.
- **Per-File XChaCha20-Poly1305 AEAD**: Chunks are sealed with unique keys derived from the file manifest. Nodes holding raw shards store only pseudorandom ciphertext and cannot inspect content.
- **Native Tor Onion v3 Transport**: Peer-to-peer handshakes and routing occur through Tor `.onion` hidden services. This guarantees complete anonymity, masks physical IP addresses, and bypasses strict NAT/firewalls without manual port-forwarding.
- **Proof-of-Retrievability (PoR)**: Periodic sub-3-second cryptographic audits proving remote nodes physically store the required shards without streaming raw data over the network.

---

## 2. Quickstart & Installation

### 2.1. Linux / Ubuntu / Debian

**One-line installation via curl:**
```bash
curl -fsSL https://raw.githubusercontent.com/PerfectFriend/NeXXus-Node/main/install.sh | bash
```

The script performs automated setup:
1. Validates hardware prerequisites (CPU, RAM, storage space).
2. Builds/installs the `nexxusd` daemon in `/usr/local/bin/nexxusd`.
3. Prepares `~/.nexxus` working directory (CAS database, keyrings, logs).
4. Generates a fresh BIP-39 mnemonic identity and Tor Onion v3 address.
5. Enables and starts the `nexxus-node.service` systemd unit.

**Run manually in foreground:**
```bash
nexxusd serve
```

### 2.2. Windows 10 / 11

1. Download the standalone bundle `nexxus-node_latest_windows_x64.zip` from project releases.
2. Extract to your desired location (e.g., `C:\NeXXuS`).
3. Open an administrative PowerShell prompt:
   ```powershell
   Set-ExecutionPolicy RemoteSigned -Scope Process
   .\scripts\windows\install-service.ps1
   ```
4. The service will register under `NeXXuSNode` with automatic reboot recovery.

### 2.3. Android

**Via Termux (24/7 background appliance):**
```bash
curl -fsSL https://raw.githubusercontent.com/PerfectFriend/NeXXus-Node/main/scripts/install-android-termux.sh | bash
```
Automatically manages `termux-wake-lock` to sustain operation while screen is locked and registers auto-boot scripts via `Termux:Boot`.

---

## 3. Configuration (`node.conf`) & Environment Variables

Both the daemon and the desktop monitor share configuration from `~/.nexxus/node.conf`.

### Common `node.conf` keys:
```ini
listen=127.0.0.1:4001       # P2P listener address
api=127.0.0.1:4010          # Local JSON-RPC WebSocket listener
tor=1                       # Tor Onion v3 support (0 or 1)
threshold=3                 # Epoch auditor multisig threshold
epoch_secs=86400            # Daily epoch duration (seconds)
auto_backup_hours=24        # Database backup cadence
auto_backup_keep=5          # Backup retention depth
por_enabled=1               # Enable scheduled PoR audits
log_path=~/.nexxus/nexxusd.log
```

### Environment Variables:
| Variable | Default | Purpose |
|---|---|---|
| `NEXXUS_LISTEN` | `127.0.0.1:4001` | P2P incoming bind address |
| `NEXXUS_API_LISTEN` | `127.0.0.1:4010` | Local API bind address (token protected) |
| `NEXXUS_DATA_DIR` | `~/.nexxus` | Root data path for `store.redb` and keys |
| `NEXXUS_TOR` | `0` (or `1`) | Activates Tor Onion v3 routing |
| `NEXXUS_API_ONION` | `0` | Exposes an Onion v3 endpoint for remote API access |
| `NEXXUS_MAX_STORE_BYTES` | `0` (unlimited) | User-defined storage quota cap in bytes |
| `NEXXUS_SYNC_INTERVAL_SECS`| `300` | Sovereign Drive background scan interval |

---

## 4. Sovereign Cryptographic Identity & Seed Vault

NeXXuS derives all cryptographic keys from an industry-standard BIP-39 12-word seed phrase:
- **Node ID**: SHA-256 of the node's primary Ed25519 public key.
- **Onion v3 Address**: Deterministically generated from the node's Ed25519 identity key ($56\text{ base32 characters} + \text{.onion}$).
- **Seed Vault**: AES-256-GCM enclave protected with 600,000 PBKDF2 rounds. Plaintext mnemonics are zeroized from memory immediately after derivation.
- **Duress-PIN Security**: Entering an alternate duress PIN unlocks an isolated honeypot profile with decoy files, providing physical plausible deniability.

---

## 5. Sovereign Drive: Automatic Folder Synchronization

The `~/.nexxus/drive` directory serves as an encrypted local mount for continuous sync:
1. Copy or move files into `~/.nexxus/drive`.
2. The daemon automatically indexes changes, slices files into 16 KiB chunks, generates RS(4+2) parity shards, and distributes them across the mesh.
3. Local lookups are resolved via a high-performance content-addressed store.

**CLI commands:**
```bash
nexxusd sync                      # Trigger synchronization of default folder
nexxusd sync /path/to/custom/dir  # Sync a specific local directory
nexxusd sync status               # View indexed file count, disk usage, and state
```

---

## 6. E2EE SMP Messenger & QR Contacts (ContactLink)

The integrated Simple Messaging Protocol (SMP) provides resilient end-to-end encrypted messaging routed over the mesh:

### ContactLink Exchange Standard (Spec §7):
Contacts are shared as standard URIs:
```text
nexxus://contact?addr=<NodeID_Hex64>&onion=<Tor_v3_Address>&name=<Alias>&fp=<Pubkey_Fingerprint>
```

- In Desktop UI: click **"📷 My QR Contact"** to present your QR code.
- To add a peer, paste their URI or scan their QR code.
- Messages are sealed with ephemeral X25519-ChaCha20-Poly1305 keys for Perfect Forward Secrecy.

---

## 7. Disaster Recovery from Mesh Network (PROD-RESTORE-01)

If your local hardware suffers catastrophic failure:
1. Install `nexxusd` on any fresh computer or server.
2. Initialize with your master seed phrase:
   ```bash
   nexxusd init --mnemonic="your twelve secret BIP-39 mnemonic recovery words"
   ```
3. Execute remote mesh rehydration:
   ```bash
   nexxusd restore --from-mesh
   ```
4. The node connects to known swarm peers via Onion v3, discovers replicated RS(4+2) shards belonging to your account, verifies their hashes, and reconstructs your entire file vault.

---

## 8. Storage Provider Hosting Mode (CLI & Desktop UI)

Operators can monetize spare NVMe/SSD capacity by offering storage deals to network participants:

### Provider Commands:
```bash
# Pin content CID with custom price in nano-TON and duration in epochs
nexxusd provider pin 0123456789abcdef... --price 1000 --duration 60

# Inspect active hosting commitments and disk usage
nexxusd provider status

# List all active provider deals
nexxusd provider list
```

In `nexxus-desktop`, the **"🖥️ Hosting Provider"** panel visualizes capacity, pricing metrics, and active deals with one-click management.

---

## 9. Post-Quantum Hybrid Shield (PQC) & ZK-SNARK PoR

- **FIPS 203 ML-KEM-768 ⊕ X25519 (Hybrid Shield)**: Session exchanges fuse classical X25519 ECDH with lattice-based Kyber-768 key encapsulation via HKDF-SHA256, mitigating "Harvest Now, Decrypt Later" quantum threats.
- **Succinct ZK-SNARK PoR**: Succinct 384-byte zero-knowledge proofs enable instant verification of storage commitments without downloading raw data blocks.

---

## 10. Complete CLI Command Reference (`nexxusd`)

| Command | Description | Example |
|---|---|---|
| `nexxusd serve [store]` | Start P2P storage daemon | `nexxusd serve` |
| `nexxusd init [--mnemonic]`| Generate identity or import seed | `nexxusd init` |
| `nexxusd id` | Display Node ID and Onion v3 address | `nexxusd id` |
| `nexxusd status` | Storage health and allocation report | `nexxusd status` |
| `nexxusd peers` | Active peers and RTT latencies | `nexxusd peers` |
| `nexxusd peer add <IP:PORT>`| Manually connect to peer | `nexxusd peer add 10.0.0.1:4001` |
| `nexxusd upload <file>` | Slice (16K), RS(4+2), encrypt and store | `nexxusd upload data.zip` |
| `nexxusd download <root> <out>`| Download and reconstruct by Merkle root | `nexxusd download <root> /tmp/out.bin` |
| `nexxusd sync [path]` | Scan and synchronize Sovereign Drive | `nexxusd sync` |
| `nexxusd provider pin <root>` | Pin deal as a storage provider | `nexxusd provider pin <root> --price 500` |
| `nexxusd provider status` | Query provider capacity and stats | `nexxusd provider status` |
| `nexxusd provider list` | List registered hosting deals | `nexxusd provider list` |
| `nexxusd test-por` | Run local PoR benchmark (<3.0s) | `nexxusd test-por` |
| `nexxusd doctor` | Verify database integrity and state | `nexxusd doctor` |
| `nexxusd backup` | Create encrypted atomic database snapshot | `nexxusd backup` |
| `nexxusd restore` | Restore store from backup | `nexxusd restore candidate.redb` |
| `nexxusd update [--check]` | Cryptographically verified auto-updater | `nexxusd update` |

---

## 11. Desktop Monitor (Tauri GUI Application)

The official GUI monitor (`nexxus-desktop`) provides a comprehensive control plane:
- **Overview**: Daemon status, uptime, Tor connectivity, Telegram notifications.
- **Storage**: Chunk inspector, Sovereign Drive folder status, Provider controls, PoR auditor.
- **Network**: Kademlia DHT routing table, real-time RTT peer ping.
- **SMP Inbox**: Encrypted messaging center, QR code generation and parsing.
- **Security**: Seed backup management, Duress PIN configuration.

---

## 12. Security, Auditing & Troubleshooting

- **Diagnostic Check**:
  ```bash
  nexxusd doctor
  ```
- **Live Stream Logs**:
  ```bash
  nexxusd logs -n 100
  ```
- **Vulnerability Disclosure**: Follow the responsible reporting guidelines defined in `SECURITY.md`.
