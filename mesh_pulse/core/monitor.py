"""Real-time system resource monitoring via psutil.

Provides:
    - get_system_metrics(): standalone function returning a clean dict
    - SystemMonitor: threaded monitor with rolling history (for TUI sparklines)
    - SystemMetrics: dataclass snapshot of all system resource readings
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Callable

import psutil

from mesh_pulse.utils.config import METRIC_HISTORY_SIZE, MONITOR_INTERVAL
from mesh_pulse.utils.logger import get_logger

log = get_logger(__name__)


# ─── Standalone Function ───────────────────────────────────────────


def get_system_metrics() -> dict:
    """Return a clean dict of current system metrics.

    Uses only psutil. No AI/LLM libraries. No threads.

    Returns:
        dict with keys: cpu, ram_percent, ram_used_gb, ram_total_gb,
        net_sent, net_recv, disk_read, disk_write, disk_percent.
    """
    cpu = psutil.cpu_percent(interval=0.1)
    mem = psutil.virtual_memory()

    net = psutil.net_io_counters()
    net_sent = net.bytes_sent if net else 0
    net_recv = net.bytes_recv if net else 0

    try:
        disk_io = psutil.disk_io_counters()
        disk_read = disk_io.read_bytes if disk_io else 0
        disk_write = disk_io.write_bytes if disk_io else 0
    except Exception:
        disk_read = 0
        disk_write = 0

    try:
        disk_usage = psutil.disk_usage("/")
    except Exception:
        try:
            disk_usage = psutil.disk_usage("C:\\")
        except Exception:
            disk_usage = None

    return {
        "cpu": round(cpu, 1),
        "ram_percent": round(mem.percent, 1),
        "ram_used_gb": round(mem.used / (1024 ** 3), 2),
        "ram_total_gb": round(mem.total / (1024 ** 3), 2),
        "net_sent": net_sent,
        "net_recv": net_recv,
        "disk_read": disk_read,
        "disk_write": disk_write,
        "disk_percent": round(disk_usage.percent, 1) if disk_usage else 0.0,
    }


# ─── Data Model ────────────────────────────────────────────────────


@dataclass
class SystemMetrics:
    """Snapshot of system resource usage at a point in time."""

    timestamp: float = field(default_factory=time.time)

    # CPU
    cpu_percent: float = 0.0
    cpu_per_core: list[float] = field(default_factory=list)
    cpu_freq_mhz: float = 0.0

    # Memory
    ram_total_gb: float = 0.0
    ram_used_gb: float = 0.0
    ram_available_gb: float = 0.0
    ram_percent: float = 0.0

    # Disk I/O (cumulative counters)
    disk_read_bytes: int = 0
    disk_write_bytes: int = 0
    disk_read_count: int = 0
    disk_write_count: int = 0
    disk_usage_percent: float = 0.0

    # Disk I/O speed (bytes/sec, calculated from deltas)
    disk_read_speed: float = 0.0
    disk_write_speed: float = 0.0

    # Network I/O (cumulative counters)
    net_sent_bytes: int = 0
    net_recv_bytes: int = 0
    net_sent_packets: int = 0
    net_recv_packets: int = 0

    # Network throughput (bytes/sec, calculated from deltas)
    net_upload_speed: float = 0.0
    net_download_speed: float = 0.0

    def to_broadcast_dict(self) -> dict:
        """Lightweight dict for inclusion in UDP beacons."""
        return {
            "cpu_percent": round(self.cpu_percent, 1),
            "ram_percent": round(self.ram_percent, 1),
            "disk_read_bytes": self.disk_read_bytes,
            "disk_write_bytes": self.disk_write_bytes,
            "net_sent_bytes": self.net_sent_bytes,
            "net_recv_bytes": self.net_recv_bytes,
        }


# ─── Threaded Monitor ──────────────────────────────────────────────


class SystemMonitor:
    """Periodically collects system metrics via psutil.

    Runs a background daemon thread that samples metrics every
    MONITOR_INTERVAL seconds and maintains a rolling history.
    Computes real-time throughput by comparing consecutive samples.

    Usage:
        monitor = SystemMonitor()
        monitor.start()
        latest = monitor.latest    # most recent SystemMetrics
        history = monitor.history  # list of recent snapshots
    """

    def __init__(
        self,
        interval: float = MONITOR_INTERVAL,
        history_size: int = METRIC_HISTORY_SIZE,
        on_update: Callable[[SystemMetrics], None] | None = None,
    ):
        self._interval = interval
        self._history_size = history_size
        self._on_update = on_update
        self._history: list[SystemMetrics] = []
        self._lock = threading.Lock()
        self._running = False
        self._latest: SystemMetrics = SystemMetrics()
        self._prev_metrics: SystemMetrics | None = None

    # ── Public API ──────────────────────────────────────────────

    def start(self) -> None:
        """Start the monitoring background thread."""
        if self._running:
            return
        self._running = True
        thread = threading.Thread(
            target=self._monitor_loop, daemon=True, name="sys-monitor"
        )
        thread.start()
        log.info("System monitor started (interval=%ds)", self._interval)

    def stop(self) -> None:
        """Stop the monitoring thread."""
        self._running = False

    @property
    def latest(self) -> SystemMetrics:
        """Return the most recent metrics snapshot."""
        with self._lock:
            return self._latest

    @property
    def history(self) -> list[SystemMetrics]:
        """Return a copy of the metrics history."""
        with self._lock:
            return list(self._history)

    def collect_once(self) -> SystemMetrics:
        """Collect a single metrics snapshot immediately."""
        return self._sample()

    # ── Background Loop ─────────────────────────────────────────

    def _monitor_loop(self) -> None:
        """Continuously sample system metrics."""
        while self._running:
            try:
                metrics = self._sample()

                # Calculate throughput deltas from previous sample
                if self._prev_metrics is not None:
                    dt = metrics.timestamp - self._prev_metrics.timestamp
                    if dt > 0:
                        # Network throughput
                        metrics.net_upload_speed = max(0.0, (
                            metrics.net_sent_bytes - self._prev_metrics.net_sent_bytes
                        ) / dt)
                        metrics.net_download_speed = max(0.0, (
                            metrics.net_recv_bytes - self._prev_metrics.net_recv_bytes
                        ) / dt)
                        # Disk I/O speed
                        metrics.disk_read_speed = max(0.0, (
                            metrics.disk_read_bytes - self._prev_metrics.disk_read_bytes
                        ) / dt)
                        metrics.disk_write_speed = max(0.0, (
                            metrics.disk_write_bytes - self._prev_metrics.disk_write_bytes
                        ) / dt)

                self._prev_metrics = metrics

                with self._lock:
                    self._latest = metrics
                    self._history.append(metrics)
                    if len(self._history) > self._history_size:
                        self._history = self._history[-self._history_size:]

                if self._on_update:
                    self._on_update(metrics)

            except Exception as e:
                log.debug("Monitor sample error: %s", e)

            time.sleep(self._interval)

    # ── Sampling ────────────────────────────────────────────────

    @staticmethod
    def _sample() -> SystemMetrics:
        """Take a snapshot of all system metrics."""
        metrics = SystemMetrics()

        # CPU
        metrics.cpu_percent = psutil.cpu_percent(interval=0.1)
        metrics.cpu_per_core = psutil.cpu_percent(interval=0, percpu=True)
        freq = psutil.cpu_freq()
        if freq:
            metrics.cpu_freq_mhz = freq.current

        # Memory
        mem = psutil.virtual_memory()
        metrics.ram_total_gb = round(mem.total / (1024**3), 2)
        metrics.ram_used_gb = round(mem.used / (1024**3), 2)
        metrics.ram_available_gb = round(mem.available / (1024**3), 2)
        metrics.ram_percent = mem.percent

        # Disk I/O
        try:
            disk_io = psutil.disk_io_counters()
            if disk_io:
                metrics.disk_read_bytes = disk_io.read_bytes
                metrics.disk_write_bytes = disk_io.write_bytes
                metrics.disk_read_count = disk_io.read_count
                metrics.disk_write_count = disk_io.write_count
        except Exception:
            pass

        try:
            disk_usage = psutil.disk_usage("/")
            metrics.disk_usage_percent = disk_usage.percent
        except Exception:
            try:
                disk_usage = psutil.disk_usage("C:\\")
                metrics.disk_usage_percent = disk_usage.percent
            except Exception:
                pass

        # Network I/O
        try:
            net_io = psutil.net_io_counters()
            if net_io:
                metrics.net_sent_bytes = net_io.bytes_sent
                metrics.net_recv_bytes = net_io.bytes_recv
                metrics.net_sent_packets = net_io.packets_sent
                metrics.net_recv_packets = net_io.packets_recv
        except Exception:
            pass

        return metrics
