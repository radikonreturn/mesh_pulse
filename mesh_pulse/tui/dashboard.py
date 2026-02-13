"""Dashboard screen — main TUI layout composing all widgets.

Layout (2×2 grid):
    ┌────────────── HEADER ──────────────┐
    │ Network Mesh    │ System Health    │
    │ File Transfers  │ Event Log        │
    └────────────── FOOTER ──────────────┘
"""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Container
from textual.screen import Screen
from textual.widgets import Static

from mesh_pulse.core.discovery import PeerManager
from mesh_pulse.core.monitor import SystemMonitor
from mesh_pulse.core.transfer import SecureTransfer
from mesh_pulse.tui.widgets.event_log import EventLog, EventLogWidget
from mesh_pulse.tui.widgets.peer_list import PeerListWidget
from mesh_pulse.tui.widgets.system_health import SystemHealthWidget
from mesh_pulse.tui.widgets.transfer_bar import TransferBarWidget
from mesh_pulse.utils.config import HOSTNAME, LOCAL_IP


class DashboardScreen(Screen):
    """Primary dashboard screen with 2×2 panel layout + event log."""

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

    def compose(self) -> ComposeResult:
        # Header
        yield Static(
            f"⚡ MESH-PULSE COMMAND CENTER"
            f"                [Node: {HOSTNAME}]  [IP: {LOCAL_IP}]",
            id="header",
        )

        # Top row
        yield Container(
            PeerListWidget(self._pm),
            id="peer-panel",
        )
        yield Container(
            SystemHealthWidget(self._monitor),
            id="health-panel",
        )

        # Bottom row
        yield Container(
            TransferBarWidget(self._transfer),
            id="transfer-panel",
        )
        yield Container(
            EventLogWidget(self._event_log),
            id="log-panel",
        )

        # Sticky footer with keyboard shortcuts
        yield Static(
            "  [R] Refresh  │  [S] Send File  │  "
            "[C] Clear Logs  │  [Q] Quit",
            id="footer",
        )
