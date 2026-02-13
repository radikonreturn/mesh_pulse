"""Application-wide constants and configuration."""

import os
import socket


# ─── Network ────────────────────────────────────────────────────────
BROADCAST_PORT = int(os.getenv("MESH_PULSE_BCAST_PORT", "37020"))
TRANSFER_PORT = int(os.getenv("MESH_PULSE_XFER_PORT", "5000"))
BROADCAST_ADDR = "255.255.255.255"
BROADCAST_INTERVAL = 2          # seconds between heartbeats
PEER_STALE_TIMEOUT = 6          # seconds before marking peer stale
PEER_DEAD_TIMEOUT = 10          # seconds before removing peer
PEER_TIMEOUT = 10               # auto-remove unseen peers after N seconds

# ─── Transfer ───────────────────────────────────────────────────────
CHUNK_SIZE = 64 * 1024          # 64 KB per encrypted chunk
TRANSFER_BACKLOG = 5            # TCP listen backlog
HEADER_MAX_SIZE = 4096          # max header JSON size in bytes

# ─── Monitoring ─────────────────────────────────────────────────────
MONITOR_INTERVAL = 2            # seconds between metric snapshots
METRIC_HISTORY_SIZE = 60        # keep last N snapshots

# ─── Encryption ─────────────────────────────────────────────────────
DEFAULT_KEY = os.getenv("MESH_PULSE_KEY", "mesh-pulse-default-key")
PBKDF2_ITERATIONS = 480_000
SALT_SIZE = 16
NONCE_SIZE = 12                 # AES-GCM standard nonce size

# ─── Identity ──────────────────────────────────────────────────────
HOSTNAME = socket.gethostname()
try:
    LOCAL_IP = socket.gethostbyname(socket.gethostname())
except socket.gaierror:
    LOCAL_IP = "127.0.0.1"

# ─── Paths ──────────────────────────────────────────────────────────
RECEIVE_DIR = "received_files"
LOG_FILE = os.path.join(os.path.expanduser("~"), ".mesh_pulse.log")
KEY_FILE = os.path.join(os.path.expanduser("~"), ".mesh_pulse_key")
