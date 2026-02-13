<<<<<<< HEAD
# ⚡ Mesh-Pulse CLI

![Python application](https://github.com/USER_NAME/REPO_NAME/actions/workflows/python-app.yml/badge.svg)

**A lightweight, TUI-based Network Mesh & System Resource Monitor.**

Mesh-Pulse turns your terminal into a Command Center for your local network — discover peers, monitor system health in real-time, and transfer files securely with AES-256 encryption.

## Features

- **P2P Discovery** — Automatic peer detection via UDP broadcast
- **System Monitoring** — Live CPU, RAM, Disk I/O, and Network metrics
- **Secure File Transfer** — AES-256-GCM encrypted TCP transfers with progress tracking
- **TUI Dashboard** — Beautiful terminal UI with live-updating panels

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run the dashboard
python -m mesh_pulse

# Or with options
python -m mesh_pulse --broadcast-port 9999 --transfer-port 10000
```

## Send a File

Press `S` in the dashboard, then enter the peer IP and file path. All transfers are encrypted with AES-256-GCM.

```bash
# Set encryption key (or pass via --key)
set MESH_PULSE_KEY=my-secret-key
python -m mesh_pulse
```

## Architecture

```
mesh_pulse/
├── core/          # P2P discovery, file transfer, system monitor
├── tui/           # Textual dashboard and widgets
└── utils/         # Crypto, config, logging
```

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `Q` | Quit |
| `S` | Send file to a peer |
| `R` | Force refresh metrics |
| `T` | Toggle dark/light theme |

## License

MIT
=======
# ⚡ Mesh-Pulse CLI



**A lightweight, TUI-based Network Mesh & System Resource Monitor.**

Mesh-Pulse turns your terminal into a Command Center for your local network — discover peers, monitor system health in real-time, and transfer files securely with AES-256 encryption.

## Features

- **P2P Discovery** — Automatic peer detection via UDP broadcast
- **System Monitoring** — Live CPU, RAM, Disk I/O, and Network metrics
- **Secure File Transfer** — AES-256-GCM encrypted TCP transfers with progress tracking
- **TUI Dashboard** — Beautiful terminal UI with live-updating panels

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run the dashboard
python -m mesh_pulse

# Or with options
python -m mesh_pulse --broadcast-port 9999 --transfer-port 10000
```

## Send a File

Press `S` in the dashboard, then enter the peer IP and file path. All transfers are encrypted with AES-256-GCM.

```bash
# Set encryption key (or pass via --key)
set MESH_PULSE_KEY=my-secret-key
python -m mesh_pulse
```

## Architecture

```
mesh_pulse/
├── core/          # P2P discovery, file transfer, system monitor
├── tui/           # Textual dashboard and widgets
└── utils/         # Crypto, config, logging
```

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `Q` | Quit |
| `S` | Send file to a peer |
| `R` | Force refresh metrics |
| `T` | Toggle dark/light theme |

## License

MIT
>>>>>>> 790d368ba1b0738aef239655ffa4ea2d35e8f40f
