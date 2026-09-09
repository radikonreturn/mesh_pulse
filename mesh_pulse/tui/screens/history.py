"""Persistent global transfer history and transfer detail screens."""

from __future__ import annotations

import time
from typing import ClassVar

from rich.table import Table
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen, Screen
from textual.widgets import Button, DataTable, Input, Select, Static

from mesh_pulse.core.history import TransferHistoryStore, TransferRecord
from mesh_pulse.tui.screens.transfer_history import human_size


class ConfirmClearHistoryModal(ModalScreen[bool]):
    """Require explicit confirmation before removing history records."""

    BINDINGS: ClassVar[list[Binding]] = [
        Binding("escape", "cancel", "Cancel", priority=True)
    ]

    DEFAULT_CSS = """
    ConfirmClearHistoryModal { align: center middle; }
    ConfirmClearHistoryModal #clear-dialog {
        width: min(56, 90%);
        height: auto;
        padding: 1 2;
        background: $surface;
        border: solid $warning;
    }
    ConfirmClearHistoryModal Horizontal { height: 3; align: right middle; }
    """

    def compose(self) -> ComposeResult:
        with Vertical(id="clear-dialog"):
            yield Static("Clear transfer history?\nReceived files will not be deleted.")
            yield Horizontal(
                Button("Cancel", id="clear-cancel"),
                Button("Clear History", id="clear-confirm", variant="warning"),
            )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "clear-confirm")

    def action_cancel(self) -> None:
        self.dismiss(False)


class TransferDetailScreen(Screen):
    """Persistent detail view for a single transfer session."""

    BINDINGS: ClassVar[list[Binding]] = [
        Binding("escape", "go_back", "Back", priority=True)
    ]

    DEFAULT_CSS = """
    TransferDetailScreen { background: $surface; padding: 1 2; }
    TransferDetailScreen #transfer-detail-title { height: 2; text-style: bold; }
    TransferDetailScreen #transfer-detail-data { height: 1fr; }
    TransferDetailScreen #transfer-detail-footer {
        dock: bottom; height: 1; color: $text-muted;
    }
    """

    def __init__(
        self, transfer_id: str, history_store: TransferHistoryStore, **kwargs
    ) -> None:
        super().__init__(**kwargs)
        self._transfer_id = transfer_id
        self._history = history_store

    def compose(self) -> ComposeResult:
        yield Static("Transfer details", id="transfer-detail-title")
        yield Static(id="transfer-detail-data")
        yield Static("Esc Back", id="transfer-detail-footer")

    def on_mount(self) -> None:
        record = self._history.get_transfer(self._transfer_id)
        if record is None:
            self.query_one("#transfer-detail-data", Static).update(
                "Transfer history is no longer available."
            )
            return
        self.query_one("#transfer-detail-data", Static).update(
            self._render_detail(record)
        )

    def _render_detail(self, record: TransferRecord) -> Table:
        table = Table.grid(padding=(0, 3))
        table.add_column(style="dim", no_wrap=True)
        table.add_column()
        table.add_row("Transfer ID", record.transfer_id)
        table.add_row("Peer", record.peer_hostname or record.peer_ip)
        table.add_row("Device ID", record.peer_device_id or "Legacy peer")
        table.add_row("Direction", record.direction.upper())
        table.add_row("Status", record.status.upper())
        table.add_row("Started", _timestamp(record.started_at))
        table.add_row(
            "Completed",
            _timestamp(record.completed_at) if record.completed_at else "—",
        )
        duration = (
            max(0, record.completed_at - record.started_at)
            if record.completed_at
            else None
        )
        table.add_row("Duration", f"{duration:.1f}s" if duration is not None else "—")
        table.add_row("Message", record.message or "None")
        table.add_row("Total", human_size(record.total_size))
        if record.error:
            table.add_row("Error", record.error[:512])
        table.add_row("Files", "")
        for file_record in self._history.get_files(record.transfer_id):
            table.add_row(
                "",
                f"{file_record.filename[:64]}  "
                f"{human_size(file_record.filesize)}  "
                f"{file_record.status.upper()}",
            )
        return table

    def action_go_back(self) -> None:
        self.app.pop_screen()


class GlobalHistoryScreen(Screen):
    """Searchable, filterable global transfer history."""

    BINDINGS: ClassVar[list[Binding]] = [
        Binding("c", "clear_history", "Clear History", priority=True),
        Binding("r", "refresh_history", "Refresh"),
        Binding("escape", "go_back", "Back", priority=True),
    ]

    DEFAULT_CSS = """
    GlobalHistoryScreen { background: $surface; padding: 1 2; }
    GlobalHistoryScreen #global-history-title { height: 2; text-style: bold; }
    GlobalHistoryScreen #history-controls { height: 3; }
    GlobalHistoryScreen #history-search { width: 2fr; }
    GlobalHistoryScreen #history-filter { width: 1fr; min-width: 18; }
    GlobalHistoryScreen #global-history-table { height: 1fr; border: none; }
    GlobalHistoryScreen #global-history-empty {
        height: 1fr; color: $text-muted; padding-top: 1;
    }
    GlobalHistoryScreen #global-history-footer {
        dock: bottom; height: 1; color: $text-muted;
    }
    """

    def __init__(self, history_store: TransferHistoryStore, **kwargs) -> None:
        super().__init__(**kwargs)
        self._history = history_store
        self._selected_id: str | None = None

    def compose(self) -> ComposeResult:
        yield Static("Transfer history", id="global-history-title")
        yield Horizontal(
            Input(placeholder="Filter by peer or transfer ID", id="history-search"),
            Select(
                [
                    ("All", "all"),
                    ("Sent", "send"),
                    ("Received", "recv"),
                    ("Complete", "complete"),
                    ("Failed", "failed"),
                    ("Cancelled", "cancelled"),
                ],
                value="all",
                allow_blank=False,
                id="history-filter",
            ),
            id="history-controls",
        )
        yield DataTable(
            id="global-history-table", cursor_type="row", zebra_stripes=True
        )
        yield Static(
            "No transfer history\nCompleted and interrupted transfers will appear here.",
            id="global-history-empty",
        )
        yield Static(
            "Enter Details  ·  C Clear History  ·  R Refresh  ·  Esc Back",
            id="global-history-footer",
        )

    def on_mount(self) -> None:
        table = self.query_one("#global-history-table", DataTable)
        table.add_columns("TIME", "PEER", "DIR", "FILES", "SIZE", "STATUS")
        self.refresh_history()

    def refresh_history(self) -> None:
        table = self.query_one("#global-history-table", DataTable)
        filter_value = self.query_one("#history-filter", Select).value
        search = self.query_one("#history-search", Input).value.strip()
        direction = filter_value if filter_value in {"send", "recv"} else None
        status = (
            filter_value
            if filter_value in {"complete", "failed", "cancelled"}
            else None
        )
        records = self._history.list_transfers(
            direction=direction, status=status, search=search or None
        )
        prior = self._selected_id
        table.clear(columns=False)
        for record in records:
            table.add_row(
                _timestamp(record.started_at),
                (record.peer_hostname or record.peer_ip)[:32],
                record.direction.upper(),
                str(record.file_count),
                human_size(record.total_size),
                record.status.upper(),
                key=record.transfer_id,
            )
        ids = [record.transfer_id for record in records]
        if prior in ids:
            table.move_cursor(row=ids.index(prior))
        elif ids:
            self._selected_id = ids[0]
        else:
            self._selected_id = None
        table.display = bool(records)
        self.query_one("#global-history-empty", Static).display = not records

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "history-search":
            self.refresh_history()

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "history-filter":
            self.refresh_history()

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.data_table.id == "global-history-table" and event.row_key:
            self._selected_id = str(event.row_key.value)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.data_table.id == "global-history-table" and event.row_key:
            self.app.push_screen(
                TransferDetailScreen(str(event.row_key.value), self._history)
            )

    def action_clear_history(self) -> None:
        def clear(confirmed: bool | None) -> None:
            if confirmed and self._history.clear():
                self.refresh_history()
                self.notify("Transfer history cleared.")

        self.app.push_screen(ConfirmClearHistoryModal(), callback=clear)

    def action_refresh_history(self) -> None:
        self.refresh_history()

    def action_go_back(self) -> None:
        self.app.pop_screen()


def _timestamp(value: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(value))
