# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] — v2.0.0

### Added
- **AES-256-GCM** encryption end-to-end for all file transfers (upgraded from Fernet/AES-128)
- **JSON-framed transfer protocol** (v2): session + per-file headers eliminate pipe-injection risk
- **Session-level multi-file batching**: multiple files sent over a single TCP connection
- **Exponential back-off retry**: up to 3 automatic retry attempts on failed sends
- **Real TCP latency probing** (`LatencyProber` thread): replaces fake `age × 10` formula
- **Per-core CPU display** in System Health widget (block character mini-bars)
- **CPU temperature** row in System Health (Linux/macOS via `psutil.sensors_temperatures()`)
- **Cumulative transfer totals** (↑ sent / ↓ received) in File Transfers widget
- **Retry count indicator** on active and history transfer entries
- **`PeerDetailModal`**: full-detail modal for a selected peer with Send File action
- **`SettingsScreen`**: in-TUI settings screen (`G`) for persistent configuration
- **`[P]` keybind**: open peer detail for the most-recently-seen online peer
- **`[O]` keybind**: open the received-files folder in the OS file explorer
- **`[G]` keybind**: open the Settings screen
- **`~/.mesh_pulse_config.json`** persistent user config (key, ports, receive dir)
- **`MESH_PULSE_RECEIVE_DIR`** environment variable for receive directory override
- Config priority stack: CLI → env vars → config file → built-in defaults
- `derive_session_key()` in `crypto.py`: deterministic PBKDF2 key from passphrase (no salt exchange)
- `on_progress` callback on `FileClient` / `SecureTransfer` for live chunk-level progress
- New test files: `test_config.py` (14 tests), `test_engine.py` (8 tests)
- Expanded `test_monitor.py`: 15 tests covering history, callbacks, and broadcast dict
- Updated `test_multi_transfer.py` for v2 batch protocol
- Updated `test_path_traversal.py` for v2 JSON-framed protocol

### Changed
- `RECEIVE_DIR` now defaults to `~/mesh_pulse_received` (instead of CWD `received_files/`)
- Footer shows all 8 keyboard shortcuts
- `LatencyProber` starts automatically when `PeerDiscovery` is given a `PeerManager`
- `Peer` dataclass gains `latency_ms: float | None` field
- `TransferInfo` dataclass gains `retry_count: int` field
- README: accurate security description, full keybinds table, configuration section

### Fixed
- Fake latency display (`age × 10`) replaced with real TCP round-trip measurement
- Header injection via pipe characters in filenames or messages (JSON replaces pipe format)
- Encryption mismatch: README claimed AES-256, actual code used Fernet/AES-128

### Security
- All file transfers now use genuine AES-256-GCM (not AES-128 Fernet)
- JSON protocol headers prevent injection via pipe characters in filenames/messages
- Path traversal prevention confirmed via updated security test

---

## [1.0.0] - 2026-03-07

### Added
- TUI dashboard with 2×2 panel layout (Network Mesh, System Health, File Transfers, Event Log)
- P2P peer discovery via UDP broadcast on port 37020
- AES-256-GCM / Fernet encrypted file transfers over TCP port 5000
- Real-time system monitoring (CPU, RAM, Disk I/O, Network throughput) with sparklines
- File picker modal with directory browser, multi-file selection, and drive selector
- Keyboard shortcuts: `Q` quit, `S` send file, `R` refresh, `D` toggle theme, `C` clear logs
- Docker and Docker Compose support
- CI pipeline with pytest on GitHub Actions
- IP address validation for manual peer entry
- Auto-rotating event log file (`panel_output.txt`)
