"""Tests for SystemMonitor metrics collection."""

import pytest

from mesh_pulse.core.monitor import SystemMetrics, SystemMonitor


class TestSystemMetrics:
    """Test SystemMetrics dataclass."""

    def test_default_metrics(self):
        m = SystemMetrics()
        assert m.cpu_percent == 0.0
        assert m.ram_percent == 0.0
        assert m.cpu_per_core == []

    def test_broadcast_dict(self):
        m = SystemMetrics(
            cpu_percent=55.3,
            ram_percent=72.8,
            disk_read_bytes=1000,
            disk_write_bytes=2000,
            net_sent_bytes=3000,
            net_recv_bytes=4000,
        )
        d = m.to_broadcast_dict()
        assert d["cpu_percent"] == 55.3
        assert d["ram_percent"] == 72.8
        assert d["net_sent_bytes"] == 3000


class TestSystemMonitor:
    """Test SystemMonitor sampling."""

    def test_collect_once_returns_metrics(self):
        monitor = SystemMonitor()
        metrics = monitor.collect_once()
        assert isinstance(metrics, SystemMetrics)
        assert 0.0 <= metrics.cpu_percent <= 100.0
        assert 0.0 <= metrics.ram_percent <= 100.0
        assert metrics.ram_total_gb > 0

    def test_cpu_per_core_populated(self):
        monitor = SystemMonitor()
        metrics = monitor.collect_once()
        assert len(metrics.cpu_per_core) > 0
        for pct in metrics.cpu_per_core:
            assert 0.0 <= pct <= 100.0

    def test_ram_values_consistent(self):
        monitor = SystemMonitor()
        metrics = monitor.collect_once()
        assert metrics.ram_used_gb <= metrics.ram_total_gb
        assert metrics.ram_available_gb <= metrics.ram_total_gb

    def test_network_counters_non_negative(self):
        monitor = SystemMonitor()
        metrics = monitor.collect_once()
        assert metrics.net_sent_bytes >= 0
        assert metrics.net_recv_bytes >= 0

    def test_latest_before_start_returns_default(self):
        monitor = SystemMonitor()
        latest = monitor.latest
        assert isinstance(latest, SystemMetrics)
        assert latest.cpu_percent == 0.0

    def test_history_empty_before_start(self):
        monitor = SystemMonitor()
        assert monitor.history == []
