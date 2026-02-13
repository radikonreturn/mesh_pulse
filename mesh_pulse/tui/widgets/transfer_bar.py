"""File transfer progress widget — active transfers + recent history."""

from __future__ import annotations

import time

from rich.progress_bar import ProgressBar
from rich.table import Table
from rich.text import Text
from rich.console import Group
from textual.widgets import Static

from mesh_pulse.core.transfer import (
    SecureTransfer,
    TransferDirection,
    TransferInfo,
    TransferStatus,
)


class TransferBarWidget(Static):
    """Displays active file transfers with progress bars and a recent
    history section showing completed/failed transfers.
    """

    DEFAULT_CSS = """
    TransferBarWidget {
        height: 100%;
        padding: 0 1;
    }
    """

    def __init__(self, transfer_engine: SecureTransfer, **kwargs):
        super().__init__(**kwargs)
        self._engine = transfer_engine

    def on_mount(self) -> None:
        self.refresh_transfers()
        self.set_interval(1.0, self.refresh_transfers)

    def refresh_transfers(self) -> None:
        """Rebuild the transfer display with active + history sections."""
        transfers = self._engine.get_transfers()

        header = Text("📁 FILE TRANSFERS", style="bold cyan")

        # Split into active and completed
        active = [t for t in transfers if t.status == TransferStatus.ACTIVE]
        completed = [
            t for t in transfers
            if t.status in (TransferStatus.COMPLETE, TransferStatus.FAILED)
        ]

        rows = [header, Text("")]

        # ── Active transfers ──
        if active:
            rows.append(Text("  ─── Active ───", style="dim bright_green"))
            for xfer in active[-5:]:
                rows.append(self._render_transfer(xfer))
                rows.append(Text(""))
        else:
            rows.append(Text("  No active transfers", style="dim italic"))
            rows.append(Text("  Press [S] to send a file", style="dim"))
            rows.append(Text(""))

        # ── Recent history ──
        if completed:
            rows.append(Text("  ─── Recent History ───", style="dim bright_cyan"))
            for xfer in completed[-6:]:
                rows.append(self._render_history_entry(xfer))

        self.update(Group(*rows))

    @staticmethod
    def _render_transfer(xfer: TransferInfo) -> Group:
        """Render an active transfer entry with progress bar."""
        if xfer.direction == TransferDirection.SEND:
            arrow = Text(" → ", style="bold bright_green")
        else:
            arrow = Text(" ← ", style="bold bright_cyan")

        name_line = Text.assemble(
            ("  ", ""),
            (xfer.filename, "bold white"),
            arrow,
            (xfer.peer_ip, "dim white"),
        )

        bar = ProgressBar(total=100, completed=xfer.progress, width=28)

        status_text = Text(
            f"  {xfer.progress:5.1f}%  {xfer.speed_mbps:.1f} MB/s",
            style="bold bright_yellow",
        )

        size_mb = xfer.filesize / (1024 * 1024)
        transferred_mb = xfer.bytes_transferred / (1024 * 1024)
        size_text = Text(
            f"  {transferred_mb:.1f} / {size_mb:.1f} MB",
            style="dim",
        )

        return Group(name_line, bar, status_text, size_text)

    @staticmethod
    def _render_history_entry(xfer: TransferInfo) -> Text:
        """Render a completed/failed transfer as a compact single line."""
        if xfer.direction == TransferDirection.SEND:
            arrow = "→"
            dir_style = "green"
        else:
            arrow = "←"
            dir_style = "bright_cyan"

        if xfer.status == TransferStatus.COMPLETE:
            icon = "✓"
            icon_style = "bold green"
            detail = f"{xfer.speed_mbps:.1f} MB/s"
        else:
            icon = "✗"
            icon_style = "bold red"
            detail = (xfer.error or "Failed")[:20]

        elapsed = time.strftime(
            "%H:%M:%S", time.localtime(xfer.started_at)
        )

        return Text.assemble(
            ("  ", ""),
            (f"{icon} ", icon_style),
            (elapsed, "dim"),
            (" ", ""),
            (xfer.filename[:18], "white"),
            (f" {arrow} ", dir_style),
            (xfer.peer_ip, "dim"),
            (" ", ""),
            (detail, "dim bright_white"),
        )
