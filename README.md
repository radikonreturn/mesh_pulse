# Mesh-Pulse

[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![PyPI](https://img.shields.io/badge/pypi-not%20yet%20published-lightgrey)](#)

**A terminal dashboard for your LAN: see every peer on your network, watch live system health, and send encrypted files — all without a GUI, an account, or a cloud server.**

<!--
DEMO GIF GOES HERE — this is the single highest-impact thing you can add.
Record a 10-15s clip with asciinema (https://asciinema.org/) or terminalizer
showing: app opens -> peer appears -> file sent -> received.
Convert asciinema to gif with agg, then:
![demo](docs/demo.gif)
-->

---

## Why Mesh-Pulse?

| | Mesh-Pulse | Syncthing | scp / rsync | LocalSend |
|---|---|---|---|---|
| Setup | zero-config, just run it | config + web UI | manual host/key setup | GUI app install |
| Interface | terminal (TUI) | web browser | terminal (no UI) | GUI |
| Peer discovery | automatic (UDP broadcast) | automatic | manual (you type the IP) | automatic |
| Live system stats | ✅ built in | ❌ | ❌ | ❌ |
| Encryption | AES-256-GCM | TLS | SSH | TLS |
| Best for | quick ad-hoc transfers + LAN visibility from the terminal | continuous folder sync | scripted/automated transfers | non-technical GUI users |

If you live in a terminal and want to glance at your network and fire off a file without opening a browser or remembering an IP, that's the gap Mesh-Pulse fills.

## Features

- Local peer discovery with UDP broadcast heartbeats.
- Live CPU, memory, disk, network, and latency views.
- Secure file transfer over TCP with encrypted chunk framing.
- Multi-file send support through a single transfer session.
- Transfer progress, history, retry handling, and file integrity checks.
- Textual-based dashboard with peer details, event logs, settings, and a file picker.
- Keyboard-selectable peer workspace with peer-filtered transfer history.
- Persistent Ed25519 device identity, fingerprint pairing, and explicit trust states.
- Persistent configuration through `~/.mesh_pulse_config.json`.

## Requirements

- Python 3.10 or newer
- A terminal that supports Textual applications
- Network access between peers on the configured discovery and transfer ports

Runtime dependencies are listed in `requirements.txt` and `pyproject.toml`.

## Install

For local development:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

On Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install -e .
```

The package also includes npm wrapper metadata. If installed through npm, the `mesh-pulse` command delegates to the Python application.

## Run

From the source tree:

```bash
python -m mesh_pulse
```

After editable installation:

```bash
mesh-pulse
```

Override ports when needed:

```bash
mesh-pulse --broadcast-port 37020 --transfer-port 5000
```

For deliberate legacy v2 interoperability, set a shared passphrase from the command line:

```bash
mesh-pulse --key "shared-passphrase"
```

Normal launches use authenticated protocol v3 and do not use the built-in default
passphrase. Devices must be explicitly trusted by fingerprint before v3 transfers
are accepted. The `--key` option enables the compatibility-only v2 path.

## Configuration

Configuration priority is:

1. CLI options
2. Environment variables
3. `~/.mesh_pulse_config.json`
4. Built-in defaults

Supported environment variables:

| Variable | Default | Purpose |
|---|---|---|
| `MESH_PULSE_KEY` | `mesh-pulse-default-key` | Shared transfer passphrase |
| `MESH_PULSE_BCAST_PORT` | `37020` | UDP discovery port |
| `MESH_PULSE_XFER_PORT` | `5000` | TCP transfer port |
| `MESH_PULSE_RECEIVE_DIR` | `~/mesh_pulse_received` | Directory for incoming files |

Example config file:

```json
{
  "broadcast_port": 37020,
  "transfer_port": 5000,
  "receive_dir": "~/mesh_pulse_received",
  "default_key": "legacy-only-passphrase"
}
```

The settings screen in the TUI can save these values. Restart the application after changing ports or the receive directory.

## File Transfer

Mesh-Pulse starts a transfer server when the dashboard opens. To send files, choose a peer, open the send dialog, select one or more files or folders, and start the transfer.

The transfer layer:

- authenticates trusted Ed25519 identities and signs fresh X25519 session keys;
- derives a fresh 32-byte session key with HKDF-SHA256 for every connection;
- encrypts headers and file chunks with AES-256-GCM;
- frames encrypted payloads with length prefixes;
- verifies received file hashes;
- records send and receive progress;
- retries failed sends with backoff.

Incoming files are written to the configured receive directory.

## Keyboard Shortcuts

| Key | Action |
|---|---|
| `S` | Open the send-file dialog |
| `Enter` | Open the selected peer workspace |
| `P` | Open the selected peer workspace |
| `O` | Open the received-files directory |
| `G` | Open settings |
| `R` | Refresh the dashboard |
| `C` | Clear the event log |
| `D` | Toggle dark/light theme |
| `Q` | Quit |

## Project Layout

```
mesh_pulse/
|-- app.py                  # Textual application and high-level UI actions
|-- __main__.py             # click CLI entry point
|-- core/
|   |-- discovery.py        # UDP broadcast discovery and peer state
|   |-- engine.py           # core subsystem startup helpers
|   |-- monitor.py          # psutil-based system metrics
|   |-- transfer.py         # encrypted TCP file transfer
|   |-- identity.py         # persistent Ed25519 device identity
|   |-- trust.py            # atomic trusted-device store
|   `-- session.py          # authenticated protocol-v3 handshake
|-- tui/
|   |-- dashboard.py        # main dashboard screen
|   |-- screens/            # settings and secondary screens
|   |-- styles/             # Textual CSS
|   `-- widgets/            # peer, health, transfer, and log widgets
`-- utils/
    |-- config.py           # defaults, environment, and user config
    |-- crypto.py           # encryption and socket framing helpers
    `-- logger.py           # Rich logging setup
```

Tests live in `tests/`.

## Development

Install dependencies and the package in editable mode:

```bash
pip install -r requirements.txt
pip install -e .
```

Run the test suite:

```bash
pytest
```

Run lint and format checks:

```bash
ruff check .
ruff format --check .
```

Run all configured pre-commit hooks:

```bash
pre-commit run --all-files
```

Some tests create localhost sockets. If your environment blocks socket creation, run the tests in a shell or sandbox that allows loopback TCP/UDP access.

## Security Notes

- Use a strong shared passphrase with `--key` or `MESH_PULSE_KEY`.
- Keep discovery and transfer ports limited to trusted local networks.
- Do not commit generated keys, logs, or received files.
- Received file paths are handled defensively so incoming filenames cannot intentionally write outside the receive directory.
- Transfer integrity is checked with SHA-256 hashes.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Mesh-Pulse is released under the MIT License. See [LICENSE](LICENSE).
