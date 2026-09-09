"""Dedicated peer workspace screen."""

from __future__ import annotations

import time
from typing import ClassVar

from rich.table import Table
from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.screen import Screen
from textual.widgets import Static

from mesh_pulse.core.discovery import Peer, PeerManager, PeerStatus
from mesh_pulse.core.network_intelligence import peer_health
from mesh_pulse.core.transfer import SecureTransfer
from mesh_pulse.core.trust import TrustStatus, TrustStore
from mesh_pulse.tui.modals.pairing import PairingModal
from mesh_pulse.tui.screens.transfer_history import TransferHistoryScreen
from mesh_pulse.tui.widgets.peer_list import PeerListWidget


def format_peer_detail(peer: Peer, *, online: bool = True) -> Table:
    """Build the peer detail grid independently of the screen lifecycle."""
    metrics = peer.metrics
    status = peer.status.value.title() if online else "Offline"
    trust = PeerListWidget._trust_text(peer).title()
    latency = PeerListWidget.format_latency(peer.latency_ms)
    first_seen = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(peer.first_seen))
    last_seen = PeerListWidget.format_last_seen(peer.age)

    grid = Table.grid(padding=(0, 3))
    grid.add_column("key", style="dim", no_wrap=True)
    grid.add_column("value", style="white")
    grid.add_row("Peer Name", peer.hostname)
    grid.add_row("Device ID", getattr(peer, "device_id", None) or "Legacy peer")
    grid.add_row("IP", peer.ip)
    grid.add_row("Port", str(peer.port))
    grid.add_row("Status", status)
    grid.add_row("Quality", peer_health(peer))
    grid.add_row("Trust", trust)
    grid.add_row("Fingerprint", peer.fingerprint or "Unavailable")
    grid.add_row("Latency", latency)
    grid.add_row(
        "Latency updated",
        time.strftime("%H:%M:%S", time.localtime(peer.latency_updated_at))
        if peer.latency_updated_at
        else "Unavailable",
    )
    grid.add_row(
        "Transfer security",
        "Authenticated v3" if peer.protocol_version == 3 else "Legacy v2",
    )
    grid.add_row("CPU", f"{metrics.cpu_percent:.1f}%")
    grid.add_row("RAM", f"{metrics.ram_percent:.1f}%")
    grid.add_row("Network sent", str(metrics.net_sent_bytes))
    grid.add_row("Network received", str(metrics.net_recv_bytes))
    grid.add_row("Disk read", str(metrics.disk_read_bytes))
    grid.add_row("Disk written", str(metrics.disk_write_bytes))
    grid.add_row("First seen", first_seen)
    grid.add_row("Last seen", last_seen)
    grid.add_row("Beacons seen", str(peer.seen_count))
    grid.add_row(
        "Recent transfers",
        f"{peer.successful_transfers} successful · {peer.failed_transfers} failed",
    )
    return grid


class PeerDetailScreen(Screen):
    """Live peer workspace that remains safe when a peer goes offline."""

    BINDINGS: ClassVar[list[Binding]] = [
        Binding("s", "send_file", "Send"),
        Binding("h", "history", "History"),
        Binding("t", "trust_device", "Trust"),
        Binding("u", "untrust_device", "Untrust"),
        Binding("r", "refresh_peer", "Refresh"),
        Binding("escape", "go_back", "Back", priority=True),
    ]

    DEFAULT_CSS = """
    PeerDetailScreen {
        background: $surface;
        padding: 1 2;
    }

    PeerDetailScreen #peer-detail-title {
        height: 2;
        text-style: bold;
        color: $text;
    }

    PeerDetailScreen #peer-detail-offline {
        height: auto;
        color: $warning;
        padding-bottom: 1;
    }

    PeerDetailScreen #peer-detail-data {
        height: 1fr;
    }

    PeerDetailScreen #peer-detail-footer {
        dock: bottom;
        height: 1;
        color: $text-muted;
    }
    """

    def __init__(
        self,
        peer_id: str,
        peer_manager: PeerManager,
        transfer_engine: SecureTransfer,
        trust_store: TrustStore,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self._peer_id = peer_id
        self._pm = peer_manager
        self._transfer = transfer_engine
        self._trust_store = trust_store
        peer = peer_manager.get_peer(peer_id)
        if peer is None:
            raise ValueError(f"Unknown peer: {peer_id}")
        self._last_peer = peer

    def compose(self) -> ComposeResult:
        yield Static(self._last_peer.hostname, id="peer-detail-title")
        yield Static("", id="peer-detail-offline")
        yield Static(id="peer-detail-data")
        yield Static(
            "",
            id="peer-detail-footer",
        )

    def on_mount(self) -> None:
        self.refresh_peer()
        self.set_interval(1.0, self.refresh_peer)

    def refresh_peer(self) -> None:
        peer = self._pm.get_peer(self._peer_id)
        present = peer is not None
        if peer is not None:
            self._last_peer = peer

        offline = self.query_one("#peer-detail-offline", Static)
        if peer is None:
            offline.update(
                Text(
                    "Peer is currently offline. "
                    f"Last seen {PeerListWidget.format_last_seen(self._last_peer.age)}.",
                    style="yellow",
                )
            )
        elif peer.status == PeerStatus.STALE:
            offline.update("Peer heartbeat is stale; availability may be limited.")
        elif peer.status == PeerStatus.OFFLINE:
            offline.update(
                "Peer is offline. "
                f"Last seen {PeerListWidget.format_last_seen(peer.age)}."
            )
        else:
            offline.update("")

        self.query_one("#peer-detail-title", Static).update(self._last_peer.hostname)
        self.query_one("#peer-detail-data", Static).update(
            format_peer_detail(self._last_peer, online=present)
        )
        self._refresh_footer()

    def _refresh_footer(self) -> None:
        trust_action = (
            "U Untrust"
            if self._last_peer.trust_status == TrustStatus.TRUSTED
            else "T Trust"
        )
        self.query_one("#peer-detail-footer", Static).update(
            f"S Send  ·  H History  ·  {trust_action}  ·  R Refresh  ·  Esc Back"
        )

    def action_send_file(self) -> None:
        peer = self._pm.get_peer(self._peer_id)
        if peer is None or peer.status != PeerStatus.ONLINE:
            self.notify("Peer went offline.", severity="warning")
            return
        self.app.action_send_file(preselect_ip=peer.ip)

    def action_history(self) -> None:
        peer = self._last_peer
        self.app.push_screen(
            TransferHistoryScreen(
                peer_id=self._peer_id,
                peer_ip=peer.ip,
                peer_name=peer.hostname,
                transfer_engine=self._transfer,
            )
        )

    def action_trust_device(self) -> None:
        peer = self._pm.get_peer(self._peer_id) or self._last_peer
        if peer.trust_status == TrustStatus.TRUSTED:
            self.notify("Device is already trusted.", severity="information")
            return
        previous = self._trust_store.get(peer.device_id) if peer.device_id else None

        def complete(confirmed: bool | None) -> None:
            if not confirmed or not peer.device_id or not peer.public_key:
                return
            try:
                self._trust_store.trust(
                    peer.device_id,
                    peer.hostname,
                    peer.public_key,
                    last_seen_at=peer.last_seen,
                )
            except (OSError, ValueError):
                self.notify("Pairing failed.", severity="error")
                return
            self._pm.refresh_trust(peer.stable_id)
            self.refresh_peer()
            self.notify("Device trusted.", severity="information")

        self.app.push_screen(PairingModal(peer, previous), callback=complete)

    def action_untrust_device(self) -> None:
        peer = self._pm.get_peer(self._peer_id) or self._last_peer
        if peer.trust_status != TrustStatus.TRUSTED or not peer.device_id:
            return
        try:
            self._trust_store.untrust(peer.device_id)
        except OSError:
            self.notify("Unable to update device trust.", severity="error")
            return
        self._pm.refresh_trust(peer.stable_id)
        self.refresh_peer()
        self.notify("Device is no longer trusted.", severity="information")

    def action_refresh_peer(self) -> None:
        self.refresh_peer()

    def action_go_back(self) -> None:
        self.app.pop_screen()
