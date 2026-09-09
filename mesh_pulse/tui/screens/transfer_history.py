"""Peer-filtered transfer history screen."""

from __future__ import annotations

import time
from collections.abc import Iterable
from typing import ClassVar

from textual.app import ComposeResult
from textual.binding import Binding
from textual.screen import Screen
from textual.widgets import DataTable, Static

from mesh_pulse.core.transfer import SecureTransfer, TransferInfo


def transfers_for_peer(
    transfers: Iterable[TransferInfo], peer_id: str, peer_ip: str
) -> list[TransferInfo]:
    """Filter transfer records by stable identity when available, then IP."""
    return [
        transfer
        for transfer in transfers
        if getattr(transfer, "peer_device_id", None) == peer_id
        or transfer.peer_ip == peer_ip
    ]


def human_size(nbytes: float) -> str:
    """Format a byte count for the history table."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(nbytes) < 1024:
            return f"{nbytes:.1f} {unit}"
        nbytes /= 1024
    return f"{nbytes:.1f} PB"


class TransferHistoryScreen(Screen):
    """Show in-memory send/receive history for one peer."""

    BINDINGS: ClassVar[list[Binding]] = [
        Binding("escape", "go_back", "Back", priority=True)
    ]

    DEFAULT_CSS = """
    TransferHistoryScreen {
        background: $surface;
        padding: 1 2;
    }

    TransferHistoryScreen #history-title {
        height: 2;
        text-style: bold;
        color: $text;
    }

    TransferHistoryScreen #history-table {
        height: 1fr;
        border: none;
    }

    TransferHistoryScreen #history-empty {
        height: 1fr;
        color: $text-muted;
        padding-top: 1;
    }

    TransferHistoryScreen #history-footer {
        dock: bottom;
        height: 1;
        color: $text-muted;
    }
    """

    def __init__(
        self,
        peer_id: str,
        peer_ip: str,
        peer_name: str,
        transfer_engine: SecureTransfer,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self._peer_id = peer_id
        self._peer_ip = peer_ip
        self._peer_name = peer_name
        self._transfer = transfer_engine

    def compose(self) -> ComposeResult:
        yield Static(f"Transfer history · {self._peer_name}", id="history-title")
        yield DataTable(id="history-table", cursor_type="row", zebra_stripes=True)
        yield Static("No transfers with this peer yet.", id="history-empty")
        yield Static("Esc Back", id="history-footer")

    def on_mount(self) -> None:
        table = self.query_one("#history-table", DataTable)
        table.add_columns("TIME", "DIRECTION", "FILE", "SIZE", "STATUS")
        self.refresh_history()
        self.set_interval(1.0, self.refresh_history)

    def refresh_history(self) -> None:
        table = self.query_one("#history-table", DataTable)
        records = transfers_for_peer(
            self._transfer.get_transfers(), self._peer_id, self._peer_ip
        )
        table.clear(columns=False)
        for index, transfer in enumerate(
            sorted(records, key=lambda item: item.started_at, reverse=True)
        ):
            table.add_row(
                time.strftime("%H:%M:%S", time.localtime(transfer.started_at)),
                transfer.direction.value.upper(),
                transfer.filename,
                human_size(transfer.filesize),
                transfer.status.value.upper(),
                key=f"{transfer.started_at}:{index}",
            )
        table.display = bool(records)
        self.query_one("#history-empty", Static).display = not records

    def action_go_back(self) -> None:
        self.app.pop_screen()
