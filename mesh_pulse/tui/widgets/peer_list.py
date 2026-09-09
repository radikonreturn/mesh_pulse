"""Keyboard-first peer browser for the dashboard."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import DataTable, Static

from mesh_pulse.core.discovery import Peer, PeerManager, PeerStatus


class PeerListWidget(Vertical):
    """Selectable, live-updating list of discovered peers.

    Rows use a stable peer key, so refreshing metrics does not reset the
    cursor. If the selected peer disappears, the cursor moves to the nearest
    remaining row instead of jumping to the beginning.
    """

    DEFAULT_CSS = """
    PeerListWidget {
        height: 100%;
        padding: 0 1;
    }

    PeerListWidget #peer-list-title {
        height: 2;
        padding-top: 1;
        color: $text;
        text-style: bold;
    }

    PeerListWidget #peer-table {
        height: 1fr;
        border: none;
        background: transparent;
    }

    PeerListWidget #peer-empty {
        height: 1fr;
        padding: 1 0;
        color: $text-muted;
    }
    """

    def __init__(self, peer_manager: PeerManager, **kwargs):
        super().__init__(**kwargs)
        self._pm = peer_manager
        self._selected_key: str | None = None

    def compose(self) -> ComposeResult:
        yield Static("PEERS", id="peer-list-title")
        yield DataTable(
            id="peer-table",
            cursor_type="row",
            zebra_stripes=True,
        )
        yield Static(
            "No peers discovered\n\n"
            "Scanning the local network…\n"
            "Devices running Mesh-Pulse will appear automatically.",
            id="peer-empty",
        )

    def on_mount(self) -> None:
        table = self.query_one("#peer-table", DataTable)
        table.add_columns(
            "Status",
            "Hostname",
            "IP",
            "CPU",
            "RAM",
            "Latency",
            "Last Seen",
            "Trust",
        )
        self.refresh_peers()
        self.set_interval(2.0, self.refresh_peers)
        table.focus()

    @property
    def selected_peer(self) -> Peer | None:
        """Return the currently selected peer, if it still exists."""
        if self._selected_key is None:
            return None
        return self._pm.get_peer(self._selected_key)

    @property
    def selected_key(self) -> str | None:
        """Stable key of the current row, exposed for screen actions/tests."""
        return self._selected_key

    def refresh_peers(self) -> None:
        """Refresh peer data while retaining the selected stable row key."""
        table = self.query_one("#peer-table", DataTable)
        empty = self.query_one("#peer-empty", Static)
        peers = sorted(self._pm.get_peers(), key=lambda peer: peer.hostname.lower())

        previous_key = self._cursor_key(table) or self._selected_key
        previous_row = table.cursor_row
        table.clear(columns=False)

        for peer in peers:
            table.add_row(
                self._status_text(peer),
                peer.hostname,
                peer.ip,
                f"{peer.metrics.cpu_percent:.0f}%",
                f"{peer.metrics.ram_percent:.0f}%",
                self.format_latency(peer.latency_ms),
                self.format_last_seen(peer.age),
                self._trust_text(peer),
                key=peer.stable_id,
            )

        has_peers = bool(peers)
        table.display = has_peers
        empty.display = not has_peers
        if not has_peers:
            self._selected_key = None
            return

        keys = [peer.stable_id for peer in peers]
        if previous_key in keys:
            cursor_row = keys.index(previous_key)
        else:
            cursor_row = min(previous_row, len(keys) - 1)
        table.move_cursor(row=cursor_row, column=0, animate=False)
        self._selected_key = keys[cursor_row]

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.data_table.id == "peer-table":
            self._selected_key = event.row_key.value

    @staticmethod
    def _cursor_key(table: DataTable) -> str | None:
        if not table.row_count or not table.is_valid_row_index(table.cursor_row):
            return None
        return table.ordered_rows[table.cursor_row].key.value

    @staticmethod
    def _status_text(peer: Peer) -> str:
        if peer.status == PeerStatus.ONLINE:
            return "●"
        if peer.status == PeerStatus.STALE:
            return "◐"
        return "○"

    @staticmethod
    def _trust_text(peer: Peer) -> str:
        trust_status = getattr(peer, "trust_status", None)
        value = getattr(trust_status, "value", trust_status)
        return str(value or "new").upper()

    @staticmethod
    def format_latency(ms: float | None) -> str:
        """Format a measured TCP latency for compact table display."""
        return "—" if ms is None else f"{ms:.0f} ms"

    @staticmethod
    def format_last_seen(age: float) -> str:
        """Format an age using the shortest useful unit."""
        if age < 60:
            return f"{age:.0f}s ago"
        if age < 3600:
            return f"{age / 60:.0f}m ago"
        return f"{age / 3600:.0f}h ago"
