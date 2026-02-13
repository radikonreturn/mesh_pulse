"""Peer list widget — live-updating table of discovered network nodes.

Columns: Status indicator, Hostname, IP Address, CPU, RAM, Latency, Last Seen.
"""

from __future__ import annotations

from rich.table import Table
from rich.text import Text
from textual.widgets import Static

from mesh_pulse.core.discovery import Peer, PeerManager, PeerStatus


class PeerListWidget(Static):
    """Displays a live list of discovered peers with status indicators,
    latency, and last-seen timestamps.
    """

    DEFAULT_CSS = """
    PeerListWidget {
        height: 100%;
        padding: 0 1;
    }
    """

    def __init__(self, peer_manager: PeerManager, **kwargs):
        super().__init__(**kwargs)
        self._pm = peer_manager

    def on_mount(self) -> None:
        self.refresh_peers()
        self.set_interval(2.0, self.refresh_peers)

    def refresh_peers(self) -> None:
        """Rebuild the peer table from current PeerManager state."""
        peers = self._pm.get_peers()
        table = Table(
            title="🌐 NETWORK MESH",
            title_style="bold cyan",
            expand=True,
            show_header=True,
            header_style="bold bright_white on grey23",
            border_style="bright_cyan",
            padding=(0, 1),
            show_lines=False,
        )
        table.add_column("", width=2, justify="center")
        table.add_column("Host", style="bold white", min_width=10, ratio=2, no_wrap=True)
        table.add_column("IP Address", style="white", min_width=15, no_wrap=True)
        table.add_column("Status", justify="center", width=8, no_wrap=True)
        table.add_column("CPU", justify="right", width=5)
        table.add_column("RAM", justify="right", width=5)
        table.add_column("Latency", justify="right", width=7)
        table.add_column("Last Seen", justify="right", width=9, no_wrap=True)

        if not peers:
            table.add_row(
                "",
                Text("Scanning network...", style="dim italic"),
                "", "", "", "", "", "",
            )
        else:
            for peer in sorted(peers, key=lambda p: p.last_seen, reverse=True):
                indicator = self._status_dot(peer)
                status_text = self._status_badge(peer)
                cpu_text = Text(
                    f"{peer.metrics.cpu_percent:.0f}%",
                    style=self._load_color(peer.metrics.cpu_percent),
                )
                ram_text = Text(
                    f"{peer.metrics.ram_percent:.0f}%",
                    style=self._load_color(peer.metrics.ram_percent),
                )
                # Simulated latency based on age (real ping would need ICMP)
                latency_ms = min(peer.age * 10, 999)
                latency_text = Text(
                    f"{latency_ms:.0f}ms",
                    style=self._latency_color(latency_ms),
                )
                last_seen = self._format_last_seen(peer.age)

                table.add_row(
                    indicator,
                    peer.hostname,
                    peer.ip,
                    status_text,
                    cpu_text,
                    ram_text,
                    latency_text,
                    last_seen,
                )

        self.update(table)

    @staticmethod
    def _status_dot(peer: Peer) -> Text:
        if peer.status == PeerStatus.ONLINE:
            return Text("●", style="bold green")
        return Text("●", style="bold red")

    @staticmethod
    def _status_badge(peer: Peer) -> Text:
        if peer.status == PeerStatus.ONLINE:
            return Text("ONLINE", style="bold green")
        return Text("STALE", style="bold red")

    @staticmethod
    def _format_last_seen(age: float) -> Text:
        if age < 60:
            return Text(f"{age:.0f}s ago", style="dim bright_white")
        elif age < 3600:
            return Text(f"{age / 60:.0f}m ago", style="dim yellow")
        return Text(f"{age / 3600:.0f}h ago", style="dim red")

    @staticmethod
    def _latency_color(ms: float) -> str:
        if ms < 50:
            return "bold green"
        elif ms < 150:
            return "bold yellow"
        return "bold red"

    @staticmethod
    def _load_color(percent: float) -> str:
        if percent >= 90:
            return "bold red"
        elif percent >= 70:
            return "bold yellow"
        elif percent >= 50:
            return "bold bright_yellow"
        return "bold green"
