"""Tests for configuration loading, environment overrides, and persistent config."""

from __future__ import annotations

import json
import os
from unittest import mock

# ── load_user_config / save_user_config ─────────────────────────────


def test_load_user_config_missing_file(tmp_path):
    """load_user_config() returns an empty dict if no config file exists."""
    with mock.patch(
        "mesh_pulse.utils.config._CONFIG_FILE",
        tmp_path / "nonexistent.json",
    ):
        from mesh_pulse.utils.config import load_user_config

        result = load_user_config()
    assert result == {}


def test_save_and_load_user_config(tmp_path):
    """save_user_config() persists data that load_user_config() can read back."""
    config_path = tmp_path / "mesh_pulse_config.json"
    data = {"broadcast_port": 12345, "default_key": "test-key"}

    with mock.patch("mesh_pulse.utils.config._CONFIG_FILE", config_path):
        from mesh_pulse.utils.config import load_user_config, save_user_config

        save_user_config(data)
        assert config_path.is_file()

        loaded = load_user_config()

    assert loaded["broadcast_port"] == 12345
    assert loaded["default_key"] == "test-key"


def test_save_user_config_is_valid_json(tmp_path):
    """The file written by save_user_config() is valid JSON."""
    config_path = tmp_path / "cfg.json"
    with mock.patch("mesh_pulse.utils.config._CONFIG_FILE", config_path):
        from mesh_pulse.utils.config import save_user_config

        save_user_config({"transfer_port": 9999})

    raw = config_path.read_text(encoding="utf-8")
    parsed = json.loads(raw)
    assert parsed["transfer_port"] == 9999


def test_load_user_config_invalid_json(tmp_path):
    """load_user_config() returns {} if the config file contains invalid JSON."""
    config_path = tmp_path / "bad.json"
    config_path.write_text("not json {{{", encoding="utf-8")

    with mock.patch("mesh_pulse.utils.config._CONFIG_FILE", config_path):
        from mesh_pulse.utils.config import load_user_config

        result = load_user_config()

    assert result == {}


# ── Environment variable overrides ──────────────────────────────────


def test_env_broadcast_port_override():
    """MESH_PULSE_BCAST_PORT env var overrides the default broadcast port."""
    with mock.patch.dict(os.environ, {"MESH_PULSE_BCAST_PORT": "41000"}):
        # Re-evaluate _get() for broadcast_port
        from mesh_pulse.utils.config import _get

        val = _get("broadcast_port", "MESH_PULSE_BCAST_PORT", 37020)
    assert val == 41000


def test_env_transfer_port_override():
    """MESH_PULSE_XFER_PORT env var overrides the default transfer port."""
    with mock.patch.dict(os.environ, {"MESH_PULSE_XFER_PORT": "41001"}):
        from mesh_pulse.utils.config import _get

        val = _get("transfer_port", "MESH_PULSE_XFER_PORT", 5000)
    assert val == 41001


def test_env_key_override():
    """MESH_PULSE_KEY env var overrides the default encryption key."""
    with mock.patch.dict(os.environ, {"MESH_PULSE_KEY": "custom-secret"}):
        from mesh_pulse.utils.config import _get

        val = _get("default_key", "MESH_PULSE_KEY", "mesh-pulse-default-key")
    assert val == "custom-secret"


def test_env_receive_dir_override():
    """MESH_PULSE_RECEIVE_DIR env var overrides the default receive directory."""
    with mock.patch.dict(os.environ, {"MESH_PULSE_RECEIVE_DIR": "/tmp/custom_recv"}):
        from mesh_pulse.utils.config import _get

        val = _get("receive_dir", "MESH_PULSE_RECEIVE_DIR", "/default")
    assert val == "/tmp/custom_recv"


def test_env_var_takes_priority_over_config_file(tmp_path):
    """Env var beats the config file value."""
    config_path = tmp_path / "cfg.json"
    config_path.write_text('{"broadcast_port": 11111}', encoding="utf-8")

    with (
        mock.patch("mesh_pulse.utils.config._CONFIG_FILE", config_path),
        mock.patch.dict(os.environ, {"MESH_PULSE_BCAST_PORT": "22222"}),
    ):
        from mesh_pulse.utils.config import _get

        val = _get("broadcast_port", "MESH_PULSE_BCAST_PORT", 37020)

    assert val == 22222


def test_config_file_beats_default(tmp_path):
    """Config file value is used when env var is absent."""
    config_path = tmp_path / "cfg.json"
    config_path.write_text('{"broadcast_port": 33333}', encoding="utf-8")

    with (
        mock.patch("mesh_pulse.utils.config._CONFIG_FILE", config_path),
        mock.patch.dict(os.environ, {}, clear=False),
    ):
        # Ensure the env var is not set
        env_copy = {k: v for k, v in os.environ.items() if k != "MESH_PULSE_BCAST_PORT"}
        with mock.patch.dict(os.environ, env_copy, clear=True):
            from mesh_pulse.utils.config import _get

            val = _get("broadcast_port", "MESH_PULSE_BCAST_PORT", 37020)

    assert val == 33333


# ── Constants sanity checks ──────────────────────────────────────────


def test_default_constants_types():
    """Core config constants have the correct Python types."""
    import mesh_pulse.utils.config as cfg

    assert isinstance(cfg.BROADCAST_PORT, int)
    assert isinstance(cfg.TRANSFER_PORT, int)
    assert isinstance(cfg.DEFAULT_KEY, str)
    assert isinstance(cfg.HOSTNAME, str)
    assert isinstance(cfg.LOCAL_IP, str)
    assert isinstance(cfg.RECEIVE_DIR, str)


def test_default_ports_in_valid_range():
    """Default ports are in the valid TCP/UDP range."""
    import mesh_pulse.utils.config as cfg

    assert 1024 <= cfg.BROADCAST_PORT <= 65535
    assert 1024 <= cfg.TRANSFER_PORT <= 65535
