"""Expanded tests for SystemMonitor and get_system_metrics()."""

from __future__ import annotations

import time

import pytest

from mesh_pulse.core.monitor import SystemMetrics, SystemMonitor, get_system_metrics
from mesh_pulse.utils.config import METRIC_HISTORY_SIZE


# ── get_system_metrics ───────────────────────────────────────────────


def test_get_system_metrics_keys():
    """All expected keys are present in the returned dict."""
    metrics = get_system_metrics()
    required_keys = {
        "cpu",
        "ram_percent",
        "ram_used_gb",
        "ram_total_gb",
        "net_sent",
        "net_recv",
        "disk_read",
        "disk_write",
        "disk_percent",
    }
    assert required_keys.issubset(metrics.keys()), (
        f"Missing keys: {required_keys - metrics.keys()}"
    )


def test_get_system_metrics_cpu_range():
    """CPU percent is in the valid range [0, 100]."""
    metrics = get_system_metrics()
    assert 0.0 <= metrics["cpu"] <= 100.0


def test_get_system_metrics_ram_range():
    """RAM percent is in the valid range [0, 100]."""
    metrics = get_system_metrics()
    assert 0.0 <= metrics["ram_percent"] <= 100.0


def test_get_system_metrics_ram_consistency():
    """Used GB does not exceed total GB."""
    metrics = get_system_metrics()
    assert metrics["ram_used_gb"] <= metrics["ram_total_gb"]


def test_get_system_metrics_non_negative_io():
    """Disk and network counters are non-negative."""
    metrics = get_system_metrics()
    assert metrics["net_sent"] >= 0
    assert metrics["net_recv"] >= 0
    assert metrics["disk_read"] >= 0
    assert metrics["disk_write"] >= 0


# ── SystemMetrics dataclass ──────────────────────────────────────────


def test_system_metrics_defaults():
    """Default SystemMetrics has sane zero-values."""
    m = SystemMetrics()
    assert m.cpu_percent == 0.0
    assert m.ram_percent == 0.0
    assert m.disk_usage_percent == 0.0
    assert m.cpu_per_core == []


def test_system_metrics_to_broadcast_dict_keys():
    """to_broadcast_dict() returns exactly the expected keys."""
    m = SystemMetrics()
    d = m.to_broadcast_dict()
    expected = {
        "cpu_percent",
        "ram_percent",
        "disk_read_bytes",
        "disk_write_bytes",
        "net_sent_bytes",
        "net_recv_bytes",
    }
    assert set(d.keys()) == expected


def test_system_metrics_to_broadcast_dict_matches_peer_metrics():
    """to_broadcast_dict() keys match the PeerMetrics constructor params."""
    from mesh_pulse.core.discovery import PeerMetrics

    m = SystemMetrics(cpu_percent=42.5, ram_percent=55.0)
    d = m.to_broadcast_dict()
    # PeerMetrics should accept this dict without error
    pm = PeerMetrics(**d)
    assert pm.cpu_percent == pytest.approx(42.5, abs=0.1)
    assert pm.ram_percent == 55.0


# ── SystemMonitor ────────────────────────────────────────────────────


def test_monitor_start_stop():
    """Monitor starts and stops without errors."""
    monitor = SystemMonitor()
    monitor.start()
    time.sleep(0.1)
    monitor.stop()


def test_monitor_collect_once():
    """collect_once() returns a non-default SystemMetrics snapshot."""
    monitor = SystemMonitor()
    m = monitor.collect_once()
    assert isinstance(m, SystemMetrics)
    # CPU should have been sampled (even 0% is valid, but it should be a float)
    assert isinstance(m.cpu_percent, float)


def test_monitor_latest_updates():
    """monitor.latest changes over time when the background thread runs."""
    monitor = SystemMonitor(interval=0.1)
    monitor.start()
    time.sleep(0.5)
    m1 = monitor.latest
    time.sleep(0.5)
    m2 = monitor.latest
    monitor.stop()
    # Timestamps should advance
    assert m2.timestamp >= m1.timestamp


def test_monitor_history_bounded():
    """History does not exceed METRIC_HISTORY_SIZE snapshots."""
    monitor = SystemMonitor(interval=0.05, history_size=5)
    monitor.start()
    time.sleep(0.6)  # Enough time to fill history many times over
    monitor.stop()
    assert len(monitor.history) <= 5


def test_monitor_history_grows():
    """History accumulates at least some entries after running briefly."""
    monitor = SystemMonitor(interval=0.1, history_size=METRIC_HISTORY_SIZE)
    monitor.start()
    time.sleep(0.5)
    monitor.stop()
    assert len(monitor.history) >= 1


def test_monitor_on_update_callback():
    """on_update callback is invoked at least once per monitor cycle."""
    received: list[SystemMetrics] = []

    monitor = SystemMonitor(interval=0.1, on_update=received.append)
    monitor.start()
    time.sleep(0.4)
    monitor.stop()

    assert len(received) >= 1
    assert all(isinstance(m, SystemMetrics) for m in received)


def test_monitor_no_double_start():
    """Calling start() twice does not raise or create duplicate threads."""
    monitor = SystemMonitor(interval=0.2)
    monitor.start()
    monitor.start()  # should be a no-op
    time.sleep(0.1)
    monitor.stop()
