# NeXXuS Sovereign Protocol — User Guides & Documentation

Welcome to the documentation hub for **NeXXuS Sovereign Protocol** (v0.229.0).

Please select your preferred language:

- 🇷🇺 **[Русская версия (Руководство пользователя)](USER_GUIDE.ru.md)** — Полное руководство по установке, настройке, Sovereign Drive, мессенджеру SMP, режиму хостинг-провайдера и командам CLI.
- 🇬🇧 **[English Version (User Guide)](USER_GUIDE.en.md)** — Complete reference manual covering installation, configuration, Sovereign Drive, SMP messaging, Storage Provider hosting, and CLI commands.
- 🇪🇸 **[Versión en Español (Guía de Usuario)](USER_GUIDE.es.md)** — Manual completo que cubre instalación, configuración, Sovereign Drive, mensajería SMP, modo proveedor de almacenamiento y comandos CLI.

---

### Quick Architecture Overview
- **Storage**: 16 KiB fixed chunking, Reed-Solomon RS(4+2) fault tolerance.
- **Privacy & Transport**: Native Tor Onion v3 routing with CGNAT bypass.
- **Cryptographic Security**: ChaCha20-Poly1305, Post-Quantum ML-KEM-768 hybrid key exchange (FIPS 203), Succinct ZK-SNARK Proof-of-Retrievability (PoR).
- **Ecosystem**: High-level SDK (`nexxus-sdk`), desktop monitor (`nexxus-desktop`), mobile nodes (`nexxus-mobile`).
