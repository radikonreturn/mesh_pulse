"""Application-wide constants and configuration.

Priority (highest to lowest):
    1. CLI arguments  (handled in __main__.py)
    2. Environment variables  (MESH_PULSE_*)
    3. ~/.mesh_pulse_config.json  (persistent user config)
    4. Built-in defaults below
"""

from __future__ import annotations

import json
import os
import socket
from pathlib import Path

# ─── Persistent user config ─────────────────────────────────────────
_CONFIG_FILE = Path.home() / ".mesh_pulse_config.json"


def load_user_config() -> dict:
    """Load the user's persistent config file if it exists.

    Returns:
        Dict of config overrides, empty dict if no config file found.
    """
    if _CONFIG_FILE.is_file():
        try:
            return json.loads(_CONFIG_FILE.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def save_user_config(config: dict) -> None:
    """Write config overrides to ~/.mesh_pulse_config.json.

    Args:
        config: Dict containing any subset of configurable keys.
    """
    try:
        _CONFIG_FILE.write_text(json.dumps(config, indent=2), encoding="utf-8")
    except OSError:
        pass


def _get(key: str, env_var: str, default):
    """Resolve a config value: env var → user config file → default."""
    if env_var in os.environ:
        val = os.environ[env_var]
        # Coerce to the same type as default
        try:
            return type(default)(val)
        except (ValueError, TypeError):
            return val
    user_cfg = load_user_config()
    if key in user_cfg:
        return user_cfg[key]
    return default


# ─── Network ────────────────────────────────────────────────────────
BROADCAST_PORT: int = _get("broadcast_port", "MESH_PULSE_BCAST_PORT", 37020)
TRANSFER_PORT: int = _get("transfer_port", "MESH_PULSE_XFER_PORT", 5000)
BROADCAST_ADDR = "255.255.255.255"
BROADCAST_INTERVAL = 2  # seconds between heartbeats
PEER_STALE_TIMEOUT = 6  # seconds before marking peer stale
PEER_DEAD_TIMEOUT = 10  # seconds before removing peer
PEER_TIMEOUT = 10  # auto-remove unseen peers after N seconds

# ─── Transfer ───────────────────────────────────────────────────────
CHUNK_SIZE = 64 * 1024  # 64 KB per encrypted chunk
TRANSFER_BACKLOG = 5  # TCP listen backlog
HEADER_MAX_SIZE = 4096  # max header JSON size in bytes
MAX_FILES_PER_SESSION = 1024
MAX_FILE_SIZE = 100 * 1024 * 1024 * 1024  # 100 GiB
MAX_SESSION_SIZE = 1024 * 1024 * 1024 * 1024  # 1 TiB
MAX_RETRIES = 3  # max send retry attempts
RETRY_DELAYS = (1.0, 3.0, 8.0)  # seconds between retry attempts

# ─── Monitoring ─────────────────────────────────────────────────────
MONITOR_INTERVAL = 2  # seconds between metric snapshots
METRIC_HISTORY_SIZE = 60  # keep last N snapshots
LATENCY_PROBE_INTERVAL = 5  # seconds between TCP latency probes

# ─── Encryption ─────────────────────────────────────────────────────
# Compatibility-only v2 passphrase. Normal app launches use protocol v3 identity.
DEFAULT_KEY: str = _get("default_key", "MESH_PULSE_KEY", "mesh-pulse-default-key")
PBKDF2_ITERATIONS = 480_000
SALT_SIZE = 16
NONCE_SIZE = 12  # AES-GCM standard nonce size

# ─── Identity ──────────────────────────────────────────────────────
HOSTNAME = socket.gethostname()
try:
    LOCAL_IP = socket.gethostbyname(socket.gethostname())
except socket.gaierror:
    LOCAL_IP = "127.0.0.1"

# ─── Paths ──────────────────────────────────────────────────────────
_default_receive_dir = str(Path.home() / "mesh_pulse_received")
RECEIVE_DIR: str = _get("receive_dir", "MESH_PULSE_RECEIVE_DIR", _default_receive_dir)
LOG_FILE = str(Path.home() / ".mesh_pulse.log")
KEY_FILE = str(Path.home() / ".mesh_pulse_key")
