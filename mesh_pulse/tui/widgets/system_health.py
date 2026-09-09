"""System health widget — sparklines, per-core CPU, throughput gauges, and disk I/O.

Layout:
    💻 SYSTEM HEALTH
    CPU  ████░░░░░░  42.0%
    RAM  ████████░░  78.3%
    DISK ██░░░░░░░░  23.1%
    RAM: 6.1 / 15.8 GB  │  Freq: 3200 MHz
    ── Cores ──
    0:▅ 1:▂ 2:▇ 3:▃  … (per-core mini-sparkline)
    ── Trends (60s) ──
    CPU (60s) ▁▂▃▄▅▆▇…
    RAM (60s) ▁▁▂▂▃▃▄…
    ── Throughput ──
    NET  ↑ 1.2 MB/s  ↓ 3.4 MB/s
    DISK R 0.0 B/s   W 128.0 KB/s
    TEMP 72°C  (Linux/macOS only)
"""

from __future__ import annotations

import platform

from rich.bar import Bar
from rich.console import Group
from rich.table import Table
from rich.text import Text
from textual.widgets import Static

from mesh_pulse.core.monitor import SystemMonitor

# ── Sparkline helpers ────────────────────────────────────────────────
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

    data = values[-width:]
    chars = []
    for v in data:
        clamped = max(0.0, min(v, max_val))
        idx = int((clamped / max_val) * (len(SPARK_CHARS) - 1))
        chars.append(SPARK_CHARS[idx])

    padding = width - len(chars)
    spark_str = "─" * padding + "".join(chars)

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


def _core_bar(percent: float) -> str:
    """Single character representing a core load level."""
    if not 0 <= percent <= 100:
        return "─"
    idx = int((percent / 100.0) * (len(SPARK_CHARS) - 1))
    return SPARK_CHARS[idx]


def _format_speed(bytes_per_sec: float) -> str:
    """Format bytes/sec into human-readable throughput."""
    if bytes_per_sec >= 1024 * 1024:
        return f"{bytes_per_sec / (1024 * 1024):.1f} MB/s"
    elif bytes_per_sec >= 1024:
        return f"{bytes_per_sec / 1024:.1f} KB/s"
    return f"{bytes_per_sec:.0f} B/s"


def _get_cpu_temp() -> str | None:
    """Return a CPU temperature string if available, else None."""
    if platform.system() == "Windows":
        return None
    try:
        import psutil

        temps = psutil.sensors_temperatures()
        # Try common sensor names
        for key in ("coretemp", "cpu_thermal", "k10temp", "acpitz"):
            entries = temps.get(key, [])
            if entries:
                avg = sum(e.current for e in entries) / len(entries)
                return f"{avg:.0f}°C"
    except (OSError, ValueError):
        return None
    return None


class SystemHealthWidget(Static):
    """Renders live system health with sparklines, per-core CPU, throughput, and disk I/O."""

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

        # ── Per-core CPU ──
        from rich.console import RenderableType

        rows: list[RenderableType] = [
            Text("SYSTEM", style="bold"),
            Text(""),
            gauges,
            ram_detail,
            Text(""),
        ]

        if m.cpu_per_core:
            core_line = Text("  Cores", style="dim")
            # Build a compact row: "0:▅ 1:▂ 2:▇ …"
            core_parts: list[tuple[str, str]] = []
            for i, pct in enumerate(m.cpu_per_core):
                char = _core_bar(pct)
                color = self._bar_color(pct)
                core_parts.append((f"C{i}:", "dim"))
                core_parts.append((char, f"bold {color}"))
                core_parts.append(("  ", ""))
            cores_text = Text.assemble(("  ", ""), *core_parts)
            rows.extend([core_line, cores_text, Text("")])

        # ── Sparklines ──
        rows.append(Text("  Trends · 60 seconds", style="dim"))
        rows.append(Text.assemble(("  CPU ", "bold cyan"), ("(60s) ", "dim")))
        rows.append(Text("  ") + _sparkline(cpu_history))
        rows.append(Text(""))
        rows.append(Text.assemble(("  RAM ", "bold magenta"), ("(60s) ", "dim")))
        rows.append(Text("  ") + _sparkline(ram_history))
        rows.append(Text(""))

        # ── Network throughput ──
        rows.append(Text("  Throughput", style="dim"))
        rows.append(
            Text.assemble(
                ("  NET  ", "bold bright_green"),
                ("↑ ", "green"),
                (_format_speed(m.net_upload_speed), "bold green"),
                ("  ", ""),
                ("↓ ", "bright_cyan"),
                (_format_speed(m.net_download_speed), "bold bright_cyan"),
            )
        )
        rows.append(
            Text.assemble(
                ("  DISK ", "bold blue"),
                ("R ", "bright_cyan"),
                (_format_speed(m.disk_read_speed), "bold bright_cyan"),
                ("  ", ""),
                ("W ", "bright_yellow"),
                (_format_speed(m.disk_write_speed), "bold bright_yellow"),
            )
        )

        # ── Temperature (Linux/macOS) ──
        temp = _get_cpu_temp()
        if temp is not None:
            rows.append(
                Text.assemble(
                    ("  TEMP ", "bold red"),
                    (temp, "bold bright_red"),
                )
            )

        self.update(Group(*rows))

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
