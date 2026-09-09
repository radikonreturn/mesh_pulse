"""File transfer progress widget — active transfers + recent history + totals."""

from __future__ import annotations

import time

from rich.console import Group
from rich.progress_bar import ProgressBar
from rich.text import Text
from textual.widgets import Static

from mesh_pulse.core.transfer import (
    SecureTransfer,
    TransferDirection,
    TransferInfo,
    TransferStatus,
)


def _human_size(nbytes: float) -> str:
    """Convert bytes to human-readable string."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(nbytes) < 1024:
            return f"{nbytes:.1f} {unit}"
        nbytes /= 1024
    return f"{nbytes:.1f} PB"


class TransferBarWidget(Static):
    """Displays active file transfers with progress bars, a history section,
    and cumulative sent/received counters.
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
        """Rebuild the transfer display with active + history + totals."""
        transfers = self._engine.get_transfers()

        # Cumulative totals
        total_sent = sum(
            t.bytes_transferred
            for t in transfers
            if t.direction == TransferDirection.SEND
            and t.status == TransferStatus.COMPLETE
        )
        total_recv = sum(
            t.bytes_transferred
            for t in transfers
            if t.direction == TransferDirection.RECV
            and t.status == TransferStatus.COMPLETE
        )

        header = Text.assemble(
            ("TRANSFERS", "bold"),
        )
        totals = Text.assemble(
            ("  ↑ ", "bold green"),
            (_human_size(total_sent), "green"),
            ("  sent    ", "dim"),
            ("↓ ", "bold bright_cyan"),
            (_human_size(total_recv), "bright_cyan"),
            ("  received", "dim"),
        )

        active_statuses = {
            TransferStatus.PENDING_APPROVAL,
            TransferStatus.ACCEPTED,
            TransferStatus.ACTIVE,
            TransferStatus.INTERRUPTED,
            TransferStatus.RESUMING,
        }
        active = [t for t in transfers if t.status in active_statuses]
        completed = [
            t
            for t in transfers
            if t.status
            in {
                TransferStatus.COMPLETE,
                TransferStatus.FAILED,
                TransferStatus.REJECTED,
                TransferStatus.CANCELLED,
            }
        ]

        rows: list = [header, totals, Text("")]

        # ── Active transfers ──
        if active:
            rows.append(Text("  ─── Active ───", style="dim bright_green"))
            for xfer in active[-5:]:
                rows.append(self._render_transfer(xfer))
                rows.append(Text(""))
            rows.append(Text("  C Cancel latest outgoing transfer", style="dim"))
        else:
            rows.append(Text("  No recent transfers", style="dim italic"))
            rows.append(Text("  Press S to send a file.", style="dim"))
            rows.append(Text(""))

        # ── Recent history ──
        if completed:
            rows.append(Text("  Recent", style="dim"))
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

        retry_suffix = ""
        if xfer.retry_count > 0:
            retry_suffix = f" [retry {xfer.retry_count}]"

        name_line = Text.assemble(
            ("  ", ""),
            (xfer.filename, "bold white"),
            arrow,
            (xfer.peer_ip, "dim white"),
            (retry_suffix, "dim yellow"),
        )

        bar = ProgressBar(total=100, completed=xfer.progress, width=28)

        state = xfer.status.value.replace("_", " ").title()
        status_text = Text(
            f"  {state}  ·  {xfer.progress:5.1f}%  ·  {xfer.speed_mbps:.1f} MB/s",
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
        elif xfer.status == TransferStatus.CANCELLED:
            icon = "–"
            icon_style = "bold yellow"
            detail = "Cancelled"
        elif xfer.status == TransferStatus.REJECTED:
            icon = "–"
            icon_style = "bold yellow"
            detail = "Rejected"
        else:
            icon = "✗"
            icon_style = "bold red"
            detail = (xfer.error or "Failed")[:20]

        elapsed = time.strftime("%H:%M:%S", time.localtime(xfer.started_at))

        retry_info = f" [{xfer.retry_count}↺]" if xfer.retry_count > 0 else ""

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
            (retry_info, "dim yellow"),
        )
