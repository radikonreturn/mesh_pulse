<div align="center">
  <h1>⚡ Mesh-Pulse</h1>
  <p><b>A lightweight, TUI-based Network Mesh & System Resource Monitor.</b></p>

  [![Python CI](https://github.com/radikonreturn/mesh_pulse/actions/workflows/python-app.yml/badge.svg)](https://github.com/radikonreturn/mesh_pulse/actions)
  [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
  [![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/downloads/)
</div>

<br>

Mesh-Pulse turns your terminal into a **Command Center** for your local network. It automatically discovers peers, monitors system health in real-time, and transfers files securely with AES-256 encryption—all from a beautifully crafted Textual-based Dashboard UI.

![Mesh-Pulse Dashboard](https://github.com/radikonreturn/mesh_pulse/assets/placeholder-dashboard.png "Replace with actual screenshot")

---

## 🌟 Key Features

* **📡 Auto P2P Discovery** 
  Zero-configuration peer detection on your local network using UDP broadcasts. Instantly see who is online.
* **📊 Live System Monitoring** 
  Real-time tracking of CPU usage, RAM capacity, Disk I/O, and Network metrics, displayed with live charts.
* **🔒 Secure Fast File Transfer** 
  TCP-based transfers protected by **AES-256-GCM** encryption. Transfer securely with real-time progress bars and speed tracking.
* **📂 Advanced File Browser Modal** 
  A built-in interactive file picker that allows selecting multiple files/folders, picking destinations, and resolving drive paths seamlessly inside the terminal.
* **🎨 Stunning TUI Dashboard** 
  Built on [Textual](https://textual.textualize.io/), featuring live-updating panels, an event log, toggle-able themes, and mouse support.

---

## 🚀 Quick Start

### 1. Installation

**Via NPM (Recommended)**
You can easily install and run Mesh-Pulse globally using NPM:

```bash
npm install -g mesh-pulse
```

**Via Git (For Development)**
Alternatively, clone the repository and install the Python dependencies directly:

```bash
git clone https://github.com/radikonreturn/mesh_pulse.git
cd mesh_pulse
pip install -r requirements.txt
```

### 2. Running the Dashboard

If you installed via NPM globally, you can start the dashboard from anywhere:

```bash
mesh-pulse
```

Alternatively, you can run it via `npx` without installing:

```bash
npx mesh-pulse
```

**Running from Source (Python)**
If you are running from the cloned repository:

```bash
python -m mesh_pulse
```

For advanced configuration, you can pass custom port settings (works identically for `mesh-pulse` and `python -m mesh_pulse`):
```bash
mesh-pulse --broadcast-port 9999 --transfer-port 10000
```

---

## 📁 Sending Files

1. Press `S` in the dashboard to open the **Send File Picker Modal**.
2. Select your target **drive** and browse your local directories.
3. Click on individual files or entire folders to selectively stage them for transfer.
4. Select a **peer** from the dropdown (or type an IP manually).
5. (Optional) Add a custom text message to accompany your transfer.
6. Click **`✓ Send`**.

### Custom Encryption Key
Because transfers are highly encrypted via AES-256, both ends must have the exact same passphrase key to decode traffic. You can specify a custom shared passphrase by using an environment variable:
```bash
# Windows (PowerShell)
$env:MESH_PULSE_KEY="my-super-secret"
python -m mesh_pulse

# Linux/macOS
MESH_PULSE_KEY="my-super-secret" python -m mesh_pulse
```
*(If unset, a default hardcoded demo key is used).*

---

## ⌨️ Keyboard Shortcuts

Navigate like a pro with the following bindings:

| Key | Action |
|-----|--------|
| `Q` | **Quit** the application |
| `S` | **Send File** — Opens the File Selection Modal |
| `R` | **Refresh** — Force a UI refresh of peers/metrics |
| `C` | **Clear Logs** — Wipes the event log history |
| `D` | **Toggle Theme** — Switch between dark and light modes |

---

## 🏗️ Architecture

Mesh-Pulse's codebase is heavily modularized for easy maintenance and expansion:

```text
mesh_pulse/
├── core/
│   ├── discovery.py    # UDP Broadcast / Peer Management
│   ├── engine.py       # Interconnects components (Hub)
│   ├── monitor.py      # Cross-platform psutil system metrics
│   └── transfer.py     # SECURE file streaming over TCP sockets
├── tui/
│   ├── dashboard.py    # Main textual visual layouts
│   └── widgets/        # Specialized textual widgets (transfer bar, etc.)
└── utils/
    ├── crypto.py       # AES-GCM Encryption / Decryption routines
    ├── config.py       # Ports, addresses, keys
    └── logger.py       # Headless log outputs
```

---

## 📄 License

This software is released under the [MIT License](LICENSE).
