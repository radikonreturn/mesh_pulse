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
        Binding("enter", "open_transfer", "Details"),
        Binding("escape", "go_back", "Back", priority=True),
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
        self._selected_id: str | None = None

    def compose(self) -> ComposeResult:
        yield Static(f"Transfer history · {self._peer_name}", id="history-title")
        yield DataTable(id="history-table", cursor_type="row", zebra_stripes=True)
        yield Static("No transfers with this peer yet.", id="history-empty")
        yield Static("Esc Back", id="history-footer")

    def on_mount(self) -> None:
        table = self.query_one("#history-table", DataTable)
        table.add_columns("TIME", "DIRECTION", "FILES", "SIZE", "STATUS")
        self.refresh_history()
        self.set_interval(1.0, self.refresh_history)

    def refresh_history(self) -> None:
        table = self.query_one("#history-table", DataTable)
        table.clear(columns=False)
        history = self._transfer.history_store
        if history is not None:
            records = history.list_for_peer(self._peer_id, self._peer_ip)
            for record in records:
                table.add_row(
                    time.strftime("%H:%M:%S", time.localtime(record.started_at)),
                    record.direction.upper(),
                    str(record.file_count),
                    human_size(record.total_size),
                    record.status.upper(),
                    key=record.transfer_id,
                )
        else:
            runtime_records = transfers_for_peer(
                self._transfer.get_transfers(), self._peer_id, self._peer_ip
            )
            records = runtime_records
            for index, transfer in enumerate(
                sorted(runtime_records, key=lambda item: item.started_at, reverse=True)
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

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.data_table.id == "history-table" and event.row_key:
            self._selected_id = str(event.row_key.value)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if self._transfer.history_store is None or event.row_key is None:
            return
        from mesh_pulse.tui.screens.history import TransferDetailScreen

        self.app.push_screen(
            TransferDetailScreen(str(event.row_key.value), self._transfer.history_store)
        )

    def action_open_transfer(self) -> None:
        if not self._selected_id or self._transfer.history_store is None:
            return
        from mesh_pulse.tui.screens.history import TransferDetailScreen

        self.app.push_screen(
            TransferDetailScreen(self._selected_id, self._transfer.history_store)
        )

    def action_go_back(self) -> None:
        self.app.pop_screen()
