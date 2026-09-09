"""Incoming transfer inbox for authenticated protocol-v3 offers."""

from __future__ import annotations

import time
from typing import ClassVar

from rich.table import Table
from textual.app import ComposeResult
from textual.binding import Binding
from textual.screen import Screen
from textual.widgets import DataTable, Static

from mesh_pulse.core.inbox import IncomingTransferRequest
from mesh_pulse.core.transfer import SecureTransfer
from mesh_pulse.core.trust import TrustStore
from mesh_pulse.tui.screens.transfer_history import human_size


def format_request_detail(
    request: IncomingTransferRequest, fingerprint: str | None
) -> Table:
    """Build a compact, bounded detail view for an incoming request."""
    table = Table.grid(padding=(0, 3))
    table.add_column(style="dim", no_wrap=True)
    table.add_column()
    table.add_row("From", request.peer_name or request.peer_ip)
    table.add_row("Fingerprint", fingerprint or "Unavailable")
    table.add_row("Files", str(len(request.files)))
    for offered in request.files[:20]:
        table.add_row("", f"{offered.name[:64]}  {human_size(offered.size)}")
    if len(request.files) > 20:
        table.add_row("", f"…and {len(request.files) - 20} more")
    table.add_row("Total", human_size(request.total_size))
    table.add_row("Message", (request.message or "None")[:256])
    return table


class InboxScreen(Screen):
    """Selectable inbox with explicit accept and reject actions."""

    BINDINGS: ClassVar[list[Binding]] = [
        Binding("enter", "open_request", "Open"),
        Binding("a", "accept", "Accept"),
        Binding("r", "reject", "Reject"),
        Binding("escape", "go_back", "Back", priority=True),
    ]

    DEFAULT_CSS = """
    InboxScreen {
        background: $surface;
        padding: 1 2;
    }

    InboxScreen #inbox-title {
        height: 2;
        text-style: bold;
    }

    InboxScreen #inbox-table {
        height: 2fr;
        border: none;
    }

    InboxScreen #inbox-detail {
        height: 3fr;
        padding-top: 1;
    }

    InboxScreen #inbox-empty {
        height: 1fr;
        color: $text-muted;
        padding-top: 1;
    }

    InboxScreen #inbox-footer {
        dock: bottom;
        height: 1;
        color: $text-muted;
    }
    """

    def __init__(
        self,
        transfer_engine: SecureTransfer,
        trust_store: TrustStore,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self._transfer = transfer_engine
        self._trust_store = trust_store
        self._selected_id: str | None = None

    def compose(self) -> ComposeResult:
        yield Static("Incoming transfers", id="inbox-title")
        yield DataTable(id="inbox-table", cursor_type="row", zebra_stripes=True)
        yield Static(
            "No incoming requests\nAuthenticated transfer offers will appear here.",
            id="inbox-empty",
        )
        yield Static("Select a request to inspect it.", id="inbox-detail")
        yield Static(
            "Enter Details  ·  A Accept  ·  R Reject  ·  Esc Back", id="inbox-footer"
        )

    def on_mount(self) -> None:
        table = self.query_one("#inbox-table", DataTable)
        table.add_columns("FROM", "FILES", "SIZE", "RECEIVED")
        self.refresh_requests()
        self.set_interval(0.5, self.refresh_requests)

    def refresh_requests(self) -> None:
        table = self.query_one("#inbox-table", DataTable)
        requests = self._transfer.get_pending_requests()
        prior = self._selected_id
        table.clear(columns=False)
        for request in requests:
            age = max(0, int(time.time() - request.received_at))
            received = "just now" if age < 2 else f"{age}s ago"
            table.add_row(
                (request.peer_name or request.peer_ip)[:40],
                str(len(request.files)),
                human_size(request.total_size),
                received,
                key=request.transfer_id,
            )
        table.display = bool(requests)
        self.query_one("#inbox-empty", Static).display = not requests
        ids = [request.transfer_id for request in requests]
        if prior in ids:
            table.move_cursor(row=ids.index(prior))
        elif ids:
            self._selected_id = ids[0]
        else:
            self._selected_id = None
            self.query_one("#inbox-detail", Static).update(
                "Select a request to inspect it."
            )
        self._show_selected()

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.data_table.id != "inbox-table" or event.row_key is None:
            return
        self._selected_id = str(event.row_key.value)
        self._show_selected()

    def action_open_request(self) -> None:
        self._show_selected()

    def action_accept(self) -> None:
        if self._selected_id and self._transfer.accept_request(self._selected_id):
            self.notify("Transfer accepted.", severity="information")
            self.refresh_requests()

    def action_reject(self) -> None:
        if self._selected_id and self._transfer.reject_request(self._selected_id):
            self.notify("Transfer rejected.", severity="information")
            self.refresh_requests()

    def _show_selected(self) -> None:
        if not self._selected_id:
            return
        request = self._transfer.get_incoming_request(self._selected_id)
        if request is None:
            return
        trusted = self._trust_store.get(request.peer_device_id)
        fingerprint = trusted.fingerprint if trusted is not None else None
        self.query_one("#inbox-detail", Static).update(
            format_request_detail(request, fingerprint)
        )

    def action_go_back(self) -> None:
        self.app.pop_screen()
