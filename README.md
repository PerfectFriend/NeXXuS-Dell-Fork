<p align="center">
  <img src="assets/images/banner-top.jpg" alt="NeXXuS Sovereign Crypto-Cloud Hosting Banner" width="100%" style="border-radius: 12px; box-shadow: 0 20px 50px rgba(0,0,0,0.6);" />
</p>

# 🌌 NeXXuS — Sovereign Post-Quantum Decentralized Cloud & Mesh Storage

<p align="center">
  <strong>High-performance, quantum-resistant, zero-knowledge peer-to-peer storage, secure communications, and sovereign computing network.</strong>
</p>

<p align="center">
  <a href="#-quick-start"><img src="https://img.shields.io/badge/Release-v0.229.0--rc3-06b6d4?style=for-the-badge&logo=rust" alt="Release v0.229.0-rc3" /></a>
  <a href="#-testing--verification"><img src="https://img.shields.io/badge/Tests-431%20Passed%20(100%25)-10b981?style=for-the-badge&logo=checkmarx" alt="431 Tests Passing" /></a>
  <a href="#-cryptography--security"><img src="https://img.shields.io/badge/PQC-ML--KEM--768%20%2B%20X25519-8b5cf6?style=for-the-badge&logo=shield" alt="PQC Hybrid" /></a>
  <a href="#-zero-knowledge-por"><img src="https://img.shields.io/badge/ZK--SNARK-Groth16%20384B%20PoR-f59e0b?style=for-the-badge&logo=bitcoin" alt="ZK PoR" /></a>
  <a href="#-network-transport"><img src="https://img.shields.io/badge/Network-Tor%20v3%20%2B%20libp2p-ec4899?style=for-the-badge&logo=torproject" alt="Tor v3" /></a>
  <a href="#-smart-contracts"><img src="https://img.shields.io/badge/Clearing-TON%20State%20Channels-0088cc?style=for-the-badge&logo=telegram" alt="TON Clearing" /></a>
</p>

---

## 📚 Documentation & User Guides / Документация / Documentación

| Language | User Guide | Description |
| :--- | :--- | :--- |
| 🇷🇺 **Русский** | [**USER_GUIDE.ru.md**](docs/USER_GUIDE.ru.md) | Полное руководство пользователя (Архитектура, CLI, Vault, SMP, DePIN, PoR) |
| 🇬🇧 **English** | [**USER_GUIDE.en.md**](docs/USER_GUIDE.en.md) | Complete User Manual (Architecture, CLI, Vault, SMP, DePIN, PoR) |
| 🇪🇸 **Español** | [**USER_GUIDE.es.md**](docs/USER_GUIDE.es.md) | Guía Completa de Usuario (Arquitectura, CLI, Vault, SMP, DePIN, PoR) |
| 💼 **Investor** | [**INVESTOR_PRESENTATION_AND_TOKENOMICS.md**](docs/INVESTOR_PRESENTATION_AND_TOKENOMICS.md) | Презентация инвестору, 6 моделей монетизации и финансовый план на 3 года |
| 📐 **Specs** | [**docs/PROTOCOL_WIRE_SPEC.md**](docs/PROTOCOL_WIRE_SPEC.md) · [**docs/NEXXUS_SPECIFICATION_V2.md**](docs/NEXXUS_SPECIFICATION_V2.md) | Спецификация бинарного wire-протокола и архитектуры v2 |
| 🛡️ **Security** | [**docs/SECURITY.md**](docs/SECURITY.md) · [**docs/THREAT_MODEL.md**](docs/THREAT_MODEL.md) | Политика безопасности и модель угроз |

---

## ⚡ What is NeXXuS?

**NeXXuS** eliminates reliance on centralized cloud monopolies (AWS, Google Cloud, Cloudflare, Dropbox, 1Password) by replacing data centers with pure mathematics, post-quantum cryptography, and a peer-to-peer mesh.

### Core Architectural Pillars

1. **Zero-Knowledge Sovereign Storage**:
   * Files are chunked into 16 KB micro-blocks, hashed with **BLAKE3**, and encrypted client-side using **ChaCha20-Poly1305 AEAD**.
   * Master secrets are derived via **BIP-39 mnemonic + Argon2id** inside an isolated hardware/OS seed vault (`m/44/9999/0/1/0`). Storage host nodes never see plaintext or decryption keys.
2. **Post-Quantum Cryptography (PQC)**:
   * Next-generation hybrid key encapsulation: **ML-KEM-768 (Kyber-768)** paired with **X25519**.
   * Immune to *"Store Now, Decrypt Later"* (SNDL) attacks by quantum computers.
3. **ZK-SNARK Proof-of-Retrievability (PoR)**:
   * Audits storage integrity on foreign host nodes every 3 seconds using **Groth16 over the Bn254 curve**.
   * Generates a compact, constant-size **384-byte proof** verifying thousands of chunks without transferring file contents.
4. **Resilient Mesh & Erasure Coding**:
   * **Reed-Solomon (4+2) GF(2^8)**: files survive even if 2 out of 6 storage donor nodes permanently disappear.
   * **PROD-RESTORE-01 Mesh Rehydration**: instant full local disk restoration from distributed mesh fragments using only a 12-word mnemonic.
5. **Anonymous & Sybil-Resistant Network**:
   * Pure P2P transport over **Tor v3 hidden services (.onion)** with **Kademlia DHT** and **Gossipsub**.
   * Calibrated Proof-of-Work (PoW) and 14-day auditor bond lockups prevent Sybil attacks and churn abuse.
6. **Social Mesh Protocol (SMP)**:
   * Spec §7 zero-knowledge contact exchange via dynamic animated QR codes.
   * Decentralized private messaging and sync with mutual authentication.
7. **DePIN Barter & Micropayment Economy**:
   * **16 GB Section Model**: donate 16 GB of local drive space to receive 2.0 GB of private, distributed high-durability vault storage for free.
   * Off-chain state channels for high-frequency micro-settlements, with on-chain batch clearing on the **TON Blockchain**.

---

## 🏗️ Repository Architecture

```text
NeXXus-Node/
├── crates/                         # Core Rust workspace (high performance & memory safety)
│   ├── nexxus-core/                # Primitives: BLAKE3, ChaCha20-Poly1305, PQC Kyber, Merkle, SMP
│   ├── nexxus-node/                # Node daemon: CLI, Redb storage engine, RPC API, P2P sync, Vault
│   └── nexxus-sdk/                 # Client library and integration bindings
├── nexxus-desktop/                 # Cross-platform desktop UI (Tauri + Vite + React)
├── contracts/                      # TON smart contracts (Epoch controller, Vesting, Auditor bonds)
├── docs/                           # Centralized documentation hub
│   ├── USER_GUIDE.md               # User guide hub (RU, EN, ES)
│   ├── INVESTOR_PRESENTATION_AND_TOKENOMICS.md  # Investor deck & 3-year financial model
│   ├── PROTOCOL_WIRE_SPEC.md       # Binary protocol specification
│   ├── NEXXUS_SPECIFICATION_V2.md  # Core v2 specification
│   ├── SECURITY.md                 # Security disclosures & policy
│   ├── adr/                        # Architecture Decision Records (0000–0010)
│   └── audits/                     # Security and cryptographic audit reports
├── nexxus-vectors/                 # Cryptographic Golden Vectors (BIP-39, Tor v3, Reed-Solomon, etc.)
├── scripts/                        # CI gates, hygiene checks, build helpers
└── test/                           # End-to-end integration and contracts validation test suites
```

---

## 🚀 Quick Start

### 1. Build and Run the Node (CLI)

```bash
# Clone the repository
git clone https://github.com/PerfectFriend/NeXXuS-Node-Hermes-Rust.git
cd NeXXuS-Node-Hermes-Rust

# Build workspace release binaries
cargo build --release

# Initialize a new Sovereign Seed Vault
./target/release/nexxus-node vault init

# Start the node daemon
./target/release/nexxus-node start --config node.conf
```

### 2. Run the Desktop Application (Tauri)

```bash
# Enter the desktop directory
cd nexxus-desktop

# Install frontend dependencies and run dev mode
npm install
npm run tauri dev
```

### 3. Storage Provider CLI (DePIN Mode)

```bash
# Allocate 64 GB of free disk space to the network
nexxus-node provider allocate --path /mnt/storage --size 64G

# Check provider state and earned credits
nexxus-node provider status
```

### 4. Restore Vault from Mesh (PROD-RESTORE-01)

```bash
# Restore entire encrypted drive on a brand-new machine using your mnemonic
nexxus-node restore --mnemonic "twelve secret words..." --output ./restored_vault
```

---

## 🧪 Testing & Verification

NeXXuS adheres to a strict zero-warning, zero-flake verification policy:

```bash
# 1. Run all Rust workspace tests (244 tests)
cargo test --workspace --all-targets

# 2. Run compiler and lint checks (Strict zero-warning policy)
cargo clippy --workspace --all-targets -- -D warnings

# 3. Run Protocol, Golden Vector, and TON Contract tests (182 tests)
npm test

# 4. Run Desktop UI verification tests (5 tests)
cd nexxus-desktop && node --test tests/format.test.mjs && cd ..

# 5. Check tree hygiene (no leaked redb state or unauthorized large files)
bash scripts/check-tree-hygiene.sh
```

**Test Results:** **431 / 431 tests passing (100% green)**.

---

## 🔒 Cryptographic Golden Vectors

All critical algorithms are validated against standard test vectors and project golden vectors in `nexxus-vectors/`:
* **BIP-39 Mnemonic → PBKDF2 512-bit Seed**: 100% match.
* **Ed25519 → Tor v3 62-char Onion Address**: RFC 7686 bit-for-bit compliance.
* **Reed-Solomon (4+2) GF(2^8)**: Full packet reconstruction after losing 2 shards.
* **BLAKE3 & ChaCha20-Poly1305 AEAD**: RFC 8439 golden vectors pass.
* **ZK-SNARK Proof-of-Retrievability**: Groth16 Bn254 384-byte verification.

---

## 📄 License & Responsible Disclosure

NeXXuS is open-source software licensed under the **MIT / Apache 2.0** dual license.

* For security inquiries or vulnerability reports, please refer to [docs/SECURITY.md](docs/SECURITY.md).
* For architecture and technical details, explore [docs/](docs/).
