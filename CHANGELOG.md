# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-09-09

Initial production-ready release of Mesh-Pulse.

### Added
- **Peer Discovery**: Signed UDP discovery beacons with Ed25519 cryptographic signatures and bounded replay attack protection.
- **Device Identity & Trust**: Persistent Ed25519 identity keys with public-key-derived device IDs and explicit fingerprint-based peer pairing.
- **Authenticated Transfers (Protocol v3)**: Mutual ephemeral X25519 key exchange signed by device identities, deriving transcript-bound session keys via HKDF-SHA256.
- **Encrypted TCP Streaming**: Length-prefixed frame protocol with AES-256-GCM chunk encryption and 12-byte nonce uniqueness.
- **Transfer Approval**: Interactive incoming transfer approval modal and system notifications before accepting inbound files.
- **Resumable Transfers**: Automatic detection and resumption of interrupted transfers using temporary partial files and verified byte offsets.
- **Data Integrity**: Full-file SHA-256 integrity verification before atomic filesystem commit, preventing partial or corrupt files from overwriting destination files.
- **Transfer History**: Persistent SQLite transfer history tracking with peer filtering, status aggregation, and speed calculations.
- **Network Intelligence**: Peer availability states (ONLINE, STALE, OFFLINE), TCP round-trip latency measurements, and explainable peer health scoring.
- **Textual Terminal UI**: Full-featured terminal interface featuring peer list, system resource monitor, transfer progress bar, event log, peer detail workspace, and inbox.
- **Showcase / Demo Mode**: Offline isolated showcase mode (`mesh-pulse --demo`) using temporary in-memory state without network broadcasts.
- **Distribution Support**: Standalone PyInstaller release executables for Windows and Linux, wheel/sdist packages, and pipx compatibility.
- **Legacy Compatibility**: Opt-in legacy protocol-v2 mode (`--key`) for compatibility with shared-passphrase peers.
