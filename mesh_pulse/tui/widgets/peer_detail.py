"""Peer detail modal — full metrics + actions for a selected peer."""

from __future__ import annotations

from typing import ClassVar

from rich.table import Table
from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Static

from mesh_pulse.core.discovery import Peer, PeerStatus


class PeerDetailModal(ModalScreen):
    """Full-detail modal for a single discovered peer.

    Shows:
        - Identity (hostname, IP, port, status)
        - Remote metrics (CPU, RAM)
        - Real TCP latency
        - Time first seen / last seen
        - [Send File] action button

    The modal dismisses with:
        None       — user cancelled
        peer.ip    — user clicked Send File (caller opens SendFileModal)
    """

    DEFAULT_CSS = """
    PeerDetailModal {
        align: center middle;
        background: rgba(0, 0, 0, 0.82);
    }

    #detail-box {
        width: 64;
        height: auto;
        background: #0d1117;
        border: thick #0ea5e9;
        padding: 1 2;
    }

    #detail-title {
        width: 100%;
        text-align: center;
        text-style: bold;
        color: #58a6ff;
        padding: 0 0 1 0;
    }

    .detail-section {
        color: #58a6ff;
        text-style: bold;
        margin: 1 0 0 0;
    }

    #detail-table {
        width: 100%;
        margin: 0;
    }

    #detail-btn-row {
        width: 100%;
        height: 3;
        align: center middle;
        margin-top: 1;
    }

    #send-to-btn {
        margin: 0 1;
        min-width: 20;
    }

    #close-btn {
        margin: 0 1;
        min-width: 14;
    }
    """

    BINDINGS: ClassVar[list[Binding]] = [
        Binding("escape", "cancel", "Close", show=False),
        Binding("s", "send_to", "Send File"),
    ]

    def __init__(self, peer: Peer, **kwargs):
        super().__init__(**kwargs)
        self._peer = peer

    def compose(self) -> ComposeResult:
        p = self._peer
        status_style = "bold green" if p.status == PeerStatus.ONLINE else "bold red"
        status_label = p.status.value.upper()

        # Latency
        if p.latency_ms is None:
            latency_str = "probing…"
        else:
            latency_str = f"{p.latency_ms:.1f} ms"

        # Last seen
        age = p.age
        if age < 60:
            last_seen = f"{age:.0f}s ago"
        elif age < 3600:
            last_seen = f"{age / 60:.0f}m ago"
        else:
            last_seen = f"{age / 3600:.1f}h ago"

        import time

        first_seen_str = time.strftime(
            "%Y-%m-%d %H:%M:%S", time.localtime(p.first_seen)
        )

        grid = Table.grid(padding=(0, 2))
        grid.add_column("key", style="bold dim", no_wrap=True)
        grid.add_column("val", style="white")

        grid.add_row("Hostname", p.hostname)
        grid.add_row("IP Address", p.ip)
        grid.add_row("Transfer Port", str(p.port))
        grid.add_row("Status", Text(status_label, style=status_style))
        grid.add_row("Latency", latency_str)
        grid.add_row("CPU", f"{p.metrics.cpu_percent:.1f}%")
        grid.add_row("RAM", f"{p.metrics.ram_percent:.1f}%")
        grid.add_row("First Seen", first_seen_str)
        grid.add_row("Last Seen", last_seen)

        with Vertical(id="detail-box"):
            yield Static(f"🔍 Peer: {p.hostname}", id="detail-title")
            yield Static(grid, id="detail-table")
            with Horizontal(id="detail-btn-row"):
                yield Button("📤 Send File", variant="success", id="send-to-btn")
                yield Button("✗ Close", variant="error", id="close-btn")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "send-to-btn":
            self.dismiss(self._peer.ip)
        elif event.button.id == "close-btn":
            self.dismiss(None)

    def action_cancel(self) -> None:
        self.dismiss(None)

    def action_send_to(self) -> None:
        self.dismiss(self._peer.ip)
