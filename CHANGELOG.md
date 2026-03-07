# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
