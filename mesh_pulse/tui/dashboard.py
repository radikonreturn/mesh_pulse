"""Peer-first dashboard composing discovery, system, transfer, and event views."""

from __future__ import annotations

from textual import events
from textual.app import ComposeResult
from textual.containers import Container
from textual.screen import Screen
from textual.widgets import DataTable, Static

from mesh_pulse.core.discovery import Peer, PeerManager
from mesh_pulse.core.monitor import SystemMonitor
from mesh_pulse.core.transfer import SecureTransfer
from mesh_pulse.tui.widgets.event_log import EventLog, EventLogWidget
from mesh_pulse.tui.widgets.peer_list import PeerListWidget
from mesh_pulse.tui.widgets.system_health import SystemHealthWidget
from mesh_pulse.tui.widgets.transfer_bar import TransferBarWidget
from mesh_pulse.utils.config import HOSTNAME, LOCAL_IP


class NodeHeader(Static):
    """Compact application and local-node status header."""

    def __init__(self, peer_manager: PeerManager, **kwargs):
        super().__init__(**kwargs)
        self._pm = peer_manager

    def on_mount(self) -> None:
        self.refresh_status()
        self.set_interval(2.0, self.refresh_status)

    def refresh_status(self) -> None:
        count = self._pm.count
        peers = f"{count} peer" if count == 1 else f"{count} peers"
        self.update(
            f"Mesh-Pulse\n[dim]{HOSTNAME} · {LOCAL_IP} · {peers} · secure[/dim]"
        )


class DashboardScreen(Screen):
    """Primary dashboard with peers as the dominant workspace."""

    def __init__(
        self,
        peer_manager: PeerManager,
        monitor: SystemMonitor,
        transfer_engine: SecureTransfer,
        event_log: EventLog,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self._pm = peer_manager
        self._monitor = monitor
        self._transfer = transfer_engine
        self._event_log = event_log

    @property
    def selected_peer(self) -> Peer | None:
        """Return the peer highlighted in the primary browser."""
        return self.query_one(PeerListWidget).selected_peer

    def compose(self) -> ComposeResult:
        yield NodeHeader(self._pm, id="header")
        yield Container(PeerListWidget(self._pm), id="peer-panel")
        yield Container(SystemHealthWidget(self._monitor), id="health-panel")
        yield Container(TransferBarWidget(self._transfer), id="transfer-panel")
        yield Container(EventLogWidget(self._event_log), id="log-panel")
        yield Static(
            "↑↓ Navigate  ·  Enter Details  ·  S Send  ·  G Settings  ·  Q Quit",
            id="footer",
        )

    def on_resize(self, event: events.Resize) -> None:
        """Stack dashboard panels when the terminal becomes narrow."""
        self.set_class(event.size.width < 100, "compact")

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Open the peer workspace when Enter activates a peer row."""
        if event.data_table.id == "peer-table" and event.row_key.value:
            self.app.action_open_peer(event.row_key.value)
