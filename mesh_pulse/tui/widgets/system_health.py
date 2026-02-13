"""System health widget — sparklines, throughput gauges, and disk I/O.

Replaces static per-core list with ASCII sparklines for CPU/RAM trends,
shows real-time network throughput (KB/s), and disk I/O read/write speed.
"""

from __future__ import annotations

from rich.bar import Bar
from rich.console import Group
from rich.table import Table
from rich.text import Text
from textual.widgets import Static

from mesh_pulse.core.monitor import SystemMonitor


# Sparkline characters (8-level Unicode block elements)
SPARK_CHARS = "▁▂▃▄▅▆▇█"


def _sparkline(values: list[float], max_val: float = 100.0, width: int = 30) -> Text:
    """Render a compact sparkline from a list of values.

    Args:
        values: Data points to plot.
        max_val: Maximum value for scaling.
        width: Number of characters in the sparkline.

    Returns:
        Rich Text with colored sparkline.
    """
    if not values:
        return Text("─" * width, style="dim")

    # Take the last `width` values
    data = values[-width:]

    chars = []
    for v in data:
        clamped = max(0.0, min(v, max_val))
        idx = int((clamped / max_val) * (len(SPARK_CHARS) - 1))
        chars.append(SPARK_CHARS[idx])

    # Pad left if not enough data
    padding = width - len(chars)
    spark_str = "─" * padding + "".join(chars)

    # Color based on latest value
    latest = data[-1] if data else 0
    if latest >= 90:
        color = "red"
    elif latest >= 70:
        color = "yellow"
    elif latest >= 50:
        color = "bright_yellow"
    else:
        color = "green"

    return Text(spark_str, style=color)


def _format_speed(bytes_per_sec: float) -> str:
    """Format bytes/sec into human-readable throughput."""
    if bytes_per_sec >= 1024 * 1024:
        return f"{bytes_per_sec / (1024 * 1024):.1f} MB/s"
    elif bytes_per_sec >= 1024:
        return f"{bytes_per_sec / 1024:.1f} KB/s"
    return f"{bytes_per_sec:.0f} B/s"


class SystemHealthWidget(Static):
    """Renders live system health with sparklines, throughput, and disk I/O.

    Layout:
        - CPU/RAM/Disk gauge bars with percentages
        - CPU sparkline (60s trend)
        - RAM sparkline (60s trend)
        - Network throughput (real-time ↑/↓ speed)
        - Disk I/O read/write speed
    """

    DEFAULT_CSS = """
    SystemHealthWidget {
        height: 100%;
        padding: 0 1;
    }
    """

    def __init__(self, monitor: SystemMonitor, **kwargs):
        super().__init__(**kwargs)
        self._monitor = monitor

    def on_mount(self) -> None:
        self.refresh_metrics()
        self.set_interval(2.0, self.refresh_metrics)

    def refresh_metrics(self) -> None:
        """Rebuild the health display from latest metrics and history."""
        m = self._monitor.latest
        history = self._monitor.history

        # Extract history arrays for sparklines
        cpu_history = [h.cpu_percent for h in history]
        ram_history = [h.ram_percent for h in history]

        # ── Main gauges ──
        gauges = Table.grid(padding=(0, 1), expand=True)
        gauges.add_column("label", width=5, justify="right")
        gauges.add_column("bar", ratio=1)
        gauges.add_column("pct", width=7, justify="right")

        gauges.add_row(
            Text("CPU", style="bold cyan"),
            self._make_bar(m.cpu_percent),
            self._pct_text(m.cpu_percent),
        )
        gauges.add_row(
            Text("RAM", style="bold magenta"),
            self._make_bar(m.ram_percent),
            self._pct_text(m.ram_percent),
        )
        gauges.add_row(
            Text("DISK", style="bold blue"),
            self._make_bar(m.disk_usage_percent),
            self._pct_text(m.disk_usage_percent),
        )

        # ── RAM detail ──
        ram_detail = Text(
            f"  {m.ram_used_gb:.1f} / {m.ram_total_gb:.1f} GB  │  "
            f"Freq: {m.cpu_freq_mhz:.0f} MHz",
            style="dim white",
        )

        # ── Sparklines ──
        cpu_spark_label = Text.assemble(
            ("  CPU ", "bold cyan"),
            ("(60s) ", "dim"),
        )
        ram_spark_label = Text.assemble(
            ("  RAM ", "bold magenta"),
            ("(60s) ", "dim"),
        )

        # ── Network throughput (real-time) ──
        net_text = Text.assemble(
            ("  NET  ", "bold bright_green"),
            ("↑ ", "green"),
            (_format_speed(m.net_upload_speed), "bold green"),
            ("  ", ""),
            ("↓ ", "bright_cyan"),
            (_format_speed(m.net_download_speed), "bold bright_cyan"),
        )

        # ── Disk I/O speed ──
        disk_io_text = Text.assemble(
            ("  DISK ", "bold blue"),
            ("R ", "bright_cyan"),
            (_format_speed(m.disk_read_speed), "bold bright_cyan"),
            ("  ", ""),
            ("W ", "bright_yellow"),
            (_format_speed(m.disk_write_speed), "bold bright_yellow"),
        )

        # ── Assemble ──
        header = Text("💻 SYSTEM HEALTH", style="bold cyan")

        content = Group(
            header,
            Text(""),
            gauges,
            ram_detail,
            Text(""),
            Text("  ─── Trends (60s) ───", style="dim bright_cyan"),
            cpu_spark_label,
            Text("  ") + _sparkline(cpu_history),
            Text(""),
            ram_spark_label,
            Text("  ") + _sparkline(ram_history),
            Text(""),
            Text("  ─── Throughput ───", style="dim bright_cyan"),
            net_text,
            disk_io_text,
        )

        self.update(content)

    @staticmethod
    def _make_bar(percent: float, width: int = 16) -> Bar:
        color = SystemHealthWidget._bar_color(percent)
        return Bar(
            size=100,
            begin=0,
            end=percent,
            width=width,
            color=color,
            bgcolor="grey23",
        )

    @staticmethod
    def _pct_text(percent: float) -> Text:
        color = SystemHealthWidget._bar_color(percent)
        return Text(f"{percent:5.1f}%", style=f"bold {color}")

    @staticmethod
    def _bar_color(percent: float) -> str:
        if percent >= 90:
            return "red"
        elif percent >= 70:
            return "yellow"
        elif percent >= 50:
            return "bright_yellow"
        return "green"
