"""Mesh-Pulse TUI Application — the main Textual App entry point.

Orchestrates all core subsystems (P2P discovery, file transfer,
system monitoring) and renders the dashboard TUI.
"""

from __future__ import annotations

import ipaddress
import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import ClassVar

import psutil
from textual import events
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import (
    Button,
    DirectoryTree,
    Input,
    Label,
    ListItem,
    ListView,
    Select,
    Static,
)

from mesh_pulse.core.composition import build_services
from mesh_pulse.core.events import (
    IncomingTransferOffered,
    TransferCompleted,
    TransferEvent,
    TransferFailed,
)
from mesh_pulse.core.transfer import TransferInfo, TransferStatus
from mesh_pulse.core.trust import TrustStatus
from mesh_pulse.tui.dashboard import DashboardScreen
from mesh_pulse.tui.screens.history import GlobalHistoryScreen
from mesh_pulse.tui.screens.inbox import InboxScreen
from mesh_pulse.tui.screens.peer_detail import PeerDetailScreen
from mesh_pulse.tui.screens.settings import SettingsScreen
from mesh_pulse.tui.widgets.event_log import EventLog
from mesh_pulse.utils.config import (
    BROADCAST_PORT,
    RECEIVE_DIR,
    TRANSFER_PORT,
)
from mesh_pulse.utils.logger import get_logger

log = get_logger(__name__)


# ── Send File Modal with File Picker ───────────────────────────────


class SendFileModal(ModalScreen):
    """Ergonomic file transfer dialog with directory browser,
    peer selector, file-size info, selection counter, and
    optional manual IP entry.

    Layout:
        ┌─────────────── 📡 Initiate File Transfer ───────────────┐
        │  📂 Browse Files (55%)       │  Transfer Details (45%)  │
        │  ┌──────────────────────┐    │  Recipient:  [▾ peer]    │
        │  │  DirectoryTree       │    │  ─── or type IP ───      │
        │  │  ...                 │    │  [ manual IP input  ]    │
        │  └──────────────────────┘    │  ── Selected (3, 4MB) ── │
        │                              │  📁 folder/              │
        │                              │  📄 file.txt   1.2 MB    │
        │                              │  ── Message ──           │
        │                              │  [ optional message ]    │
        ├──────────────────────────────┴──────────────────────────┤
        │  [ESC] Cancel    [✓ Send]  [✗ Clear]  [✗ Cancel]       │
        └────────────────────────────────────────────────────────┘
    """

    DEFAULT_CSS = """
    SendFileModal {
        align: center middle;
        background: rgba(0, 0, 0, 0.82);
    }

    #modal-box {
        width: 92%;
        max-width: 100;
        min-width: 60;
        height: 90%;
        max-height: 36;
        min-height: 22;
        background: $surface;
        border: solid $accent;
        padding: 1 2;
    }

    /* ── Title ── */
    #modal-title {
        width: 100%;
        text-align: left;
        text-style: bold;
        color: $text;
        padding: 0 0 1 0;
    }

    /* ── Body grid ── */
    #modal-body {
        layout: grid;
        grid-size: 2 1;
        grid-columns: 55fr 45fr;
        height: 1fr;
    }

    /* ── Left panel — file browser ── */
    #browser-panel {
        border: solid $panel;
        height: 100%;
        overflow-y: auto;
        padding: 0;
        margin: 0 1 0 0;
    }

    #browser-panel DirectoryTree {
        height: auto;
        padding: 0 1;
    }

    /* ── Right panel — transfer details ── */
    #details-panel {
        height: 100%;
        padding: 0 1;
        overflow-y: auto;
    }

    .section-label {
        color: $text;
        text-style: bold;
        margin: 1 0 0 0;
    }

    .form-label {
        color: $text-muted;
        margin: 1 0 0 0;
    }

    .section-divider {
        color: #30363d;
        margin: 0;
        height: 1;
    }

    /* ── Peer selector ── */
    #peer-select {
        width: 100%;
        margin: 0 0 0 0;
    }

    #manual-ip {
        width: 100%;
        margin: 0 0 0 0;
        background: $surface-darken-1;
        border: tall $panel;
        color: $text;
    }

    /* ── Selection counter ── */
    #selection-counter {
        width: 100%;
        color: $success;
        text-style: bold;
        margin: 0;
        height: 1;
    }

    /* ── File list ── */
    #file-list {
        width: 100%;
        margin: 0;
        height: 1fr;
        min-height: 4;
        padding: 0;
        background: $surface-darken-1;
        border: tall $panel;
        overflow-y: auto;
    }

    #file-list ListItem {
        height: 1;
        padding: 0 1;
        color: $text;
        background: $surface-darken-1;
    }

    #file-list ListItem:hover {
        background: #da36364d;
        color: #f85149;
    }

    #file-list .file-item-label {
        width: 100%;
    }

    #file-placeholder {
        width: 100%;
        height: 1fr;
        min-height: 4;
        padding: 1 1;
        background: $surface-darken-1;
        border: tall $panel;
        color: $text-muted;
        text-style: italic;
    }

    /* ── Message input ── */
    #transfer-message {
        width: 100%;
        margin: 0;
        background: $surface-darken-1;
        border: tall $panel;
        color: $text;
    }

    /* ── Button row ── */
    #btn-row {
        width: 100%;
        height: auto;
        align: center middle;
        margin-top: 1;
        dock: bottom;
    }

    #shortcut-hints {
        width: 100%;
        color: $text-muted;
        text-align: center;
        height: 1;
        margin: 0;
    }

    #btn-container {
        width: 100%;
        height: 3;
        align: center middle;
    }

    #send-btn {
        margin: 0 1;
        min-width: 18;
    }

    #clear-btn {
        margin: 0 1;
        min-width: 14;
    }

    #cancel-btn {
        margin: 0 1;
        min-width: 14;
    }

    SendFileModal.compact #modal-box {
        width: 96%;
        min-width: 40;
        height: 96%;
        max-height: 100%;
        padding: 0 1;
    }

    SendFileModal.compact #modal-body {
        layout: vertical;
    }

    SendFileModal.compact #browser-panel {
        height: 1fr;
        margin: 0;
    }

    SendFileModal.compact #details-panel {
        height: 14;
    }
    """

    BINDINGS: ClassVar[list[Binding]] = [
        Binding("escape", "cancel", "Cancel", show=False),
    ]

    def __init__(
        self,
        peer_ips: list[str],
        start_path: str = ".",
        preselect_ip: str | None = None,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self._peer_ips = peer_ips
        self._start_path = start_path
        self._preselect_ip = preselect_ip
        self._selected_files: list[str] = []
        self._selected_folders: list[str] = []

    @property
    def preselected_peer_ip(self) -> str | None:
        """Peer IP requested by the launching workspace, if any."""
        return self._preselect_ip

    # ── Helpers ──────────────────────────────────────────────

    @staticmethod
    def _human_size(nbytes: float) -> str:
        """Convert bytes to a human-readable string."""
        for unit in ("B", "KB", "MB", "GB"):
            if abs(nbytes) < 1024:
                return f"{nbytes:.1f} {unit}"
            nbytes /= 1024
        return f"{nbytes:.1f} TB"

    @staticmethod
    def _get_size(path: str) -> int:
        """Get size: file size or recursive folder size."""
        p = Path(path)
        if p.is_file():
            return p.stat().st_size
        total = 0
        for f in p.rglob("*"):
            if f.is_file():
                try:
                    total += f.stat().st_size
                except OSError:
                    pass
        return total

    def _get_drives(self) -> list[tuple[str, str]]:
        drives = []
        if platform.system() == "Windows":
            for p in psutil.disk_partitions(all=False):
                drives.append((p.device, p.mountpoint))
        else:
            drives.append(("Root (/)", "/"))
            for p in psutil.disk_partitions(all=True):
                if (
                    p.mountpoint.startswith("/mnt/")
                    or p.mountpoint.startswith("/media/")
                ) and len(p.mountpoint.split("/")) == 3:
                    drives.append((p.mountpoint, p.mountpoint))

        seen = set()
        unique_drives = []
        for d in drives:
            if d[1] not in seen:
                seen.add(d[1])
                unique_drives.append(d)
        return unique_drives

    # ── Compose ──────────────────────────────────────────────

    def compose(self) -> ComposeResult:
        if self._peer_ips:
            options = [(ip, ip) for ip in self._peer_ips]
        else:
            options = [("No peers discovered", "__none__")]

        drives = self._get_drives()
        initial_drive = (
            self._start_path
            if any(d[1] == self._start_path for d in drives)
            else (drives[0][1] if drives else Select.NULL)
        )

        # Pre-selected IP value
        from typing import Any

        peer_value: Any = Select.NULL
        if self._preselect_ip and self._preselect_ip in self._peer_ips:
            peer_value = self._preselect_ip

        with Vertical(id="modal-box"):
            yield Static("Send files", id="modal-title")

            with Horizontal(id="modal-body"):
                # ── Left: file browser ──
                with Vertical(id="browser-panel"):
                    yield Select(
                        drives,
                        id="drive-select",
                        prompt="Select Drive...",
                        value=initial_drive,
                    )
                    yield Static(
                        "Browse · select files or folders",
                        classes="form-label",
                    )
                    yield DirectoryTree(self._start_path, id="file-tree")

                # ── Right: transfer details ──
                with Vertical(id="details-panel"):
                    # Recipient section
                    yield Static("Recipient", classes="section-label")
                    yield Select(
                        options,
                        id="peer-select",
                        prompt="Select a peer…",
                        value=peer_value,
                    )
                    yield Static(
                        "── or enter IP manually ──", classes="section-divider"
                    )
                    yield Input(
                        placeholder="192.168.1.x",
                        id="manual-ip",
                    )

                    # Selected files section
                    yield Static(
                        "Selected items · select again to remove",
                        classes="section-label",
                    )
                    yield Static("", id="selection-counter")
                    yield Static(
                        "  Click files or folders on the left",
                        id="file-placeholder",
                    )
                    yield ListView(id="file-list")

                    # Message section
                    yield Static("Message", classes="section-label")
                    yield Input(
                        placeholder="Optional note to recipient…",
                        id="transfer-message",
                    )

            # ── Bottom: shortcuts + buttons ──
            with Vertical(id="btn-row"):
                yield Static(
                    "[ESC] Close  ·  [Tab] Navigate  ·  Click file = toggle select",
                    id="shortcut-hints",
                )
                with Horizontal(id="btn-container"):
                    yield Button(
                        "Send",
                        variant="success",
                        id="send-btn",
                        disabled=True,
                    )
                    yield Button("Clear", variant="warning", id="clear-btn")
                    yield Button("Cancel", id="cancel-btn")

    def on_resize(self, event: events.Resize) -> None:
        self.set_class(event.size.width < 80 or event.size.height < 30, "compact")

    # ── Event Handlers ──────────────────────────────────────────

    def on_directory_tree_file_selected(
        self, event: DirectoryTree.FileSelected
    ) -> None:
        """Toggle file selection — click to add, click again to remove."""
        path = str(event.path.resolve())
        if path in self._selected_files:
            self._selected_files.remove(path)
        else:
            self._selected_files.append(path)
        self._refresh_file_display()
        self._update_send_button()

    def on_directory_tree_directory_selected(
        self, event: DirectoryTree.DirectorySelected
    ) -> None:
        """Toggle folder selection — click to add, click again to remove."""
        path = str(event.path.resolve())
        if path in self._selected_folders:
            self._selected_folders.remove(path)
        else:
            self._selected_folders.append(path)
        self._refresh_file_display()
        self._update_send_button()

    def _refresh_file_display(self) -> None:
        """Rebuild the clickable file list and update the counter."""
        counter = self.query_one("#selection-counter", Static)
        file_list = self.query_one("#file-list", ListView)
        placeholder = self.query_one("#file-placeholder", Static)

        if not self._selected_files and not self._selected_folders:
            placeholder.display = True
            file_list.display = False
            counter.update("")
            return

        placeholder.display = False
        file_list.display = True

        file_list.clear()

        total_size = 0
        n_files = len(self._selected_files)
        n_folders = len(self._selected_folders)

        for fp in self._selected_folders:
            name = Path(fp).name
            size = self._get_size(fp)
            total_size += size
            item = ListItem(
                Label(
                    f"{name}/  ({self._human_size(size)})", classes="file-item-label"
                ),
                name=fp,
            )
            file_list.append(item)

        for fp in self._selected_files:
            name = Path(fp).name
            size = self._get_size(fp)
            total_size += size
            item = ListItem(
                Label(f"{name}  — {self._human_size(size)}", classes="file-item-label"),
                name=fp,
            )
            file_list.append(item)

        parts: list[str] = []
        if n_files:
            parts.append(f"{n_files} file{'s' if n_files > 1 else ''}")
        if n_folders:
            parts.append(f"{n_folders} folder{'s' if n_folders > 1 else ''}")
        counter.update(f"  {', '.join(parts)}  ·  {self._human_size(total_size)} total")

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        """Deselect a file/folder when clicked in the selected items list."""
        path = event.item.name
        if path in self._selected_files:
            self._selected_files.remove(path)
        elif path in self._selected_folders:
            self._selected_folders.remove(path)
        self._refresh_file_display()
        self._update_send_button()

    def on_select_changed(self, event: Select.Changed) -> None:
        """Handle dropdown changes."""
        if event.select.id == "drive-select":
            if event.value is not Select.NULL:
                tree = self.query_one("#file-tree", DirectoryTree)
                tree.path = str(event.value)
                tree.reload()
        else:
            self._update_send_button()

    def on_input_changed(self, event: Input.Changed) -> None:
        """Re-evaluate the Send button when manual IP changes."""
        if event.input.id == "manual-ip":
            self._update_send_button()

    def _resolve_peer_ip(self) -> str | None:
        """Return the chosen peer IP from selector or manual input."""
        select = self.query_one("#peer-select", Select)
        if select.value is not Select.NULL and select.value != "__none__":
            return str(select.value)
        manual = self.query_one("#manual-ip", Input).value.strip()
        if manual:
            try:
                ipaddress.ip_address(manual)
                return manual
            except ValueError:
                return None
        return None

    def _update_send_button(self) -> None:
        """Enable Send only when both items and a peer are chosen."""
        btn = self.query_one("#send-btn", Button)
        has_peer = self._resolve_peer_ip() is not None
        has_items = len(self._selected_files) > 0 or len(self._selected_folders) > 0
        btn.disabled = not (has_peer and has_items)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "send-btn":
            peer_ip = self._resolve_peer_ip()
            all_items = self._selected_files + self._selected_folders
            message = self.query_one("#transfer-message", Input).value
            if all_items and peer_ip:
                self.dismiss((peer_ip, all_items, message))
        elif event.button.id == "clear-btn":
            self._selected_files = []
            self._selected_folders = []
            self._refresh_file_display()
            self._update_send_button()
            self.query_one("#transfer-message", Input).value = ""
        elif event.button.id == "cancel-btn":
            self.dismiss(None)

    def action_cancel(self) -> None:
        self.dismiss(None)


def _resolve_css_path() -> Path:
    """Resolve dashboard.tcss path across source checkout, wheel install, and PyInstaller."""
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        meipass_dir = Path(sys._MEIPASS)
        candidate = meipass_dir / "mesh_pulse" / "tui" / "styles" / "dashboard.tcss"
        if candidate.exists():
            return candidate
        candidate_flat = meipass_dir / "tui" / "styles" / "dashboard.tcss"
        if candidate_flat.exists():
            return candidate_flat
    default_path = Path(__file__).resolve().parent / "tui" / "styles" / "dashboard.tcss"
    if default_path.exists():
        return default_path
    try:
        from importlib.resources import files

        res_file = files("mesh_pulse").joinpath("tui", "styles", "dashboard.tcss")
        as_path = Path(str(res_file))
        if as_path.exists():
            return as_path
    except Exception:
        pass
    return default_path


# ── Main Application ───────────────────────────────────────────────


class MeshPulseApp(App):
    """Mesh-Pulse peer workspace application."""

    TITLE = "Mesh-Pulse"
    SUB_TITLE = "Local encrypted peer workspace"
    CSS_PATH = _resolve_css_path()

    BINDINGS: ClassVar[list[Binding]] = [
        Binding("q", "quit", "Quit", priority=True),
        Binding("s", "send_file", "Send File"),
        Binding("p", "peer_detail", "Peer Detail"),
        Binding("o", "open_received", "Open Received"),
        Binding("g", "settings", "Settings"),
        Binding("i", "inbox", "Inbox"),
        Binding("h", "history", "History"),
        Binding("r", "refresh_all", "Refresh"),
        Binding("c", "cancel_transfer", "Cancel Transfer"),
        Binding("d", "toggle_dark", "Toggle Dark"),
    ]

    def __init__(
        self,
        passphrase: str | None = None,
        broadcast_port: int = BROADCAST_PORT,
        transfer_port: int = TRANSFER_PORT,
        identity_directory: str | Path | None = None,
        demo_mode: bool = False,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self.demo_mode = demo_mode
        self._demo_tempdir = None
        if self.demo_mode:
            import tempfile

            self._demo_tempdir = tempfile.TemporaryDirectory(prefix="mesh_pulse_demo_")
            identity_directory = Path(self._demo_tempdir.name)

        self.event_log = EventLog()
        services = build_services(
            passphrase=passphrase,
            broadcast_port=broadcast_port,
            transfer_port=transfer_port,
            identity_directory=identity_directory,
            on_file_received=self._on_file_received,
            on_event=self._on_transfer_event,
        )
        self.legacy_mode = services.legacy_mode
        self.monitor = services.monitor
        self.identity = services.identity
        self.trust_store = services.trust_store
        self.history_store = services.history_store
        self.peer_manager = services.peer_manager
        self.broadcaster = services.broadcaster
        self.transfer = services.transfer

    @staticmethod
    def _is_connection_failure(transfer: TransferInfo) -> bool:
        """Determine whether a transfer failure was caused by network/connection issues."""
        if not transfer.error:
            return True
        err = transfer.error.lower()
        non_connection_markers = (
            "rejected",
            "cancelled",
            "canceled",
            "checksum",
            "sha256",
            "hash mismatch",
            "invalid tag",
            "decryption failed",
            "authentication",
            "permission",
            "disk full",
            "file not found",
            "protocol",
        )
        if any(marker in err for marker in non_connection_markers):
            return False
        return True

    def _on_transfer_event(self, event: TransferEvent) -> None:
        """Translate core events into Textual-thread-safe application updates."""
        if isinstance(event, IncomingTransferOffered):
            self._on_incoming_request(event.request)
        elif isinstance(event, TransferCompleted):
            transfer = event.transfer
            self.peer_manager.record_transfer_result(
                transfer.peer_device_id or transfer.peer_ip,
                success=True,
            )
        elif isinstance(event, TransferFailed):
            transfer = event.transfer
            # User-level actions (rejections, cancellations) do NOT count as network failures
            if transfer.status in {TransferStatus.REJECTED, TransferStatus.CANCELLED}:
                return
            is_connection_failure = self._is_connection_failure(transfer)
            self.peer_manager.record_transfer_result(
                transfer.peer_device_id or transfer.peer_ip,
                success=False,
                connection_failure=is_connection_failure,
            )

    def _on_incoming_request(self, request) -> None:
        """Publish an authenticated offer to Textual from its worker thread."""
        peer = request.peer_name or request.peer_ip
        count = len(request.files)
        size_mb = request.total_size / (1024 * 1024)
        message = (
            f"Incoming transfer from {peer}: "
            f"{count} file{'s' if count != 1 else ''} · {size_mb:.1f} MB"
        )
        try:
            self.call_from_thread(self.event_log.log, message, "info")
            self.call_from_thread(
                self.notify,
                message,
                title="Incoming transfer",
                severity="information",
            )
        except RuntimeError as error:
            log.debug("Unable to post incoming transfer notification: %s", error)

    def _on_file_received(self, info: TransferInfo) -> None:
        """Called from FileServer thread when a file reception finishes."""
        size_mb = info.filesize / (1024 * 1024)
        if info.status == TransferStatus.COMPLETE:
            msg = (
                f"Received '{info.filename}' from {info.peer_ip} "
                f"({size_mb:.1f} MB, {info.speed_mbps:.1f} MB/s)"
            )
            level = "success"
            severity = "information"
        else:
            msg = (
                f"Failed to receive '{info.filename}' from {info.peer_ip}: "
                f"{info.error or 'Unknown error'}"
            )
            level = "error"
            severity = "warning"

        try:
            self.call_from_thread(self.event_log.log, msg, level)
            user_message = (
                msg if info.status == TransferStatus.COMPLETE else "Transfer failed."
            )
            self.call_from_thread(self.notify, user_message, severity=severity)
        except RuntimeError as error:
            log.debug("Unable to post transfer notification: %s", error)

    def on_mount(self) -> None:
        """Start background subsystems or seed isolated demo state."""
        self.event_log.log("Mesh-Pulse starting up…", "info")
        self.monitor.start()
        self.event_log.log("System monitor active", "success")

        if self.demo_mode:
            self._setup_demo_data()
        else:
            self.broadcaster.start()
            self.event_log.log(
                f"P2P discovery broadcasting on port {BROADCAST_PORT}", "success"
            )
            self.transfer.start_server()
            self.event_log.log(
                f"Transfer server listening on port {TRANSFER_PORT}", "success"
            )

        self.push_screen(
            DashboardScreen(
                peer_manager=self.peer_manager,
                monitor=self.monitor,
                transfer_engine=self.transfer,
                event_log=self.event_log,
                legacy_mode=self.legacy_mode,
            )
        )
        self.event_log.log("Dashboard ready", "success")
        log.info("Dashboard ready")

    def _setup_demo_data(self) -> None:
        """Seed deterministic local showcase state without any network traffic."""
        import time

        from mesh_pulse.core.discovery import Peer, PeerStatus
        from mesh_pulse.core.inbox import IncomingFile, IncomingTransferRequest
        from mesh_pulse.core.trust import TrustStatus

        now = time.time()
        mono = time.monotonic()

        p1 = Peer(
            hostname="laptop-dev",
            ip="192.168.1.105",
            port=5000,
            status=PeerStatus.ONLINE,
            trust_status=TrustStatus.TRUSTED,
            device_id="mp-a1b2c3d4e5f60001",
            fingerprint="A1B2:C3D4:E5F6:7890:1234:5678:9ABC:DEF0",
            latency_ms=4.2,
            successful_transfers=5,
            failed_transfers=0,
            last_seen_monotonic=mono,
            last_transfer_at=now - 300,
            protocol_version=3,
        )
        p2 = Peer(
            hostname="workstation-alpha",
            ip="192.168.1.42",
            port=5000,
            status=PeerStatus.ONLINE,
            trust_status=TrustStatus.NEW,
            device_id="mp-b2c3d4e5f6a10002",
            fingerprint="B2C3:D4E5:F6A1:0123:4567:89AB:CDEF:0123",
            latency_ms=18.5,
            successful_transfers=1,
            failed_transfers=0,
            last_seen_monotonic=mono,
            last_transfer_at=now - 1200,
            protocol_version=3,
        )
        p3 = Peer(
            hostname="backup-server",
            ip="192.168.1.200",
            port=5000,
            status=PeerStatus.STALE,
            trust_status=TrustStatus.TRUSTED,
            device_id="mp-c3d4e5f6a1b20003",
            fingerprint="C3D4:E5F6:A1B2:3456:789A:BCDE:F012:3456",
            latency_ms=112.0,
            successful_transfers=12,
            failed_transfers=1,
            last_seen_monotonic=mono - 10,
            last_transfer_at=now - 86400,
            protocol_version=3,
        )
        p4 = Peer(
            hostname="old-thinkpad",
            ip="192.168.1.88",
            port=5000,
            status=PeerStatus.OFFLINE,
            trust_status=TrustStatus.NEW,
            device_id="mp-d4e5f6a1b2c30004",
            fingerprint="D4E5:F6A1:B2C3:4567:89AB:CDEF:0123:4567",
            latency_ms=None,
            successful_transfers=0,
            failed_transfers=2,
            last_seen_monotonic=mono - 60,
            last_transfer_at=None,
            protocol_version=2,
        )

        for peer in (p1, p2, p3, p4):
            self.peer_manager.add_demo_peer(peer)

        if self.history_store:
            try:
                self.history_store.record_transfer(
                    transfer_id="demo-transfer-001",
                    peer_ip="192.168.1.105",
                    peer_device_id="mp-a1b2c3d4e5f60001",
                    peer_name="laptop-dev",
                    direction="send",
                    status="complete",
                    files=[
                        {
                            "filename": "dataset-q3.tar.gz",
                            "filesize": 14_250_000,
                            "status": "complete",
                            "bytes_transferred": 14_250_000,
                            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                        },
                        {
                            "filename": "analysis_notes.md",
                            "filesize": 4200,
                            "status": "complete",
                            "bytes_transferred": 4200,
                            "sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                        },
                    ],
                    error=None,
                )
            except Exception as e:
                log.debug("Demo history recording ignored: %s", e)

        if self.transfer and hasattr(self.transfer, "incoming"):
            req = IncomingTransferRequest(
                transfer_id="demo-incoming-001",
                peer_device_id="mp-a1b2c3d4e5f60001",
                peer_name="laptop-dev",
                peer_ip="192.168.1.105",
                files=(
                    IncomingFile(
                        name="shared-assets.zip",
                        size=8_500_000,
                        sha256="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                        file_id="demo-file-1",
                    ),
                ),
                message="Review release assets",
                total_size=8_500_000,
            )
            self.transfer.incoming.register(req)

        self.event_log.log(
            "Demo mode active: isolated in-memory workspace (no LAN traffic)",
            "info",
        )

    # ── Actions ────────────────────────────────────────────────────

    def action_toggle_dark(self) -> None:
        self.theme = "textual-light" if self.theme == "textual-dark" else "textual-dark"

    def action_send_file(self, preselect_ip: str | None = None) -> None:
        """Open the file picker modal populated with discovered peers."""
        if preselect_ip is None and isinstance(self.screen, DashboardScreen):
            selected = self.screen.selected_peer
            if selected is not None:
                preselect_ip = selected.ip
        selected_peer = (
            self.peer_manager.get_peer(preselect_ip) if preselect_ip else None
        )

        local_protocol = 2 if self.legacy_mode else 3

        if (
            selected_peer is not None
            and selected_peer.protocol_version != local_protocol
        ):
            self.notify(
                (
                    f"Peer requires transfer protocol "
                    f"v{selected_peer.protocol_version}; "
                    f"this node is running v{local_protocol}."
                ),
                severity="warning",
            )
            return

        if (
            selected_peer is not None
            and not self.legacy_mode
            and selected_peer.trust_status != TrustStatus.TRUSTED
        ):
            self.notify("Trust this device before sending.", severity="warning")
            return
        peers = self.peer_manager.get_peers()
        peer_ips = [p.ip for p in peers]

        def _on_result(result: tuple[str, list[str], str] | None) -> None:
            if result:
                peer_ip, items, message = result
                peer = self.peer_manager.get_peer(peer_ip)
                if peer is not None and peer.protocol_version != local_protocol:
                    self.event_log.log(
                        (
                            f"Blocked incompatible transfer to {peer_ip}: "
                            f"peer=v{peer.protocol_version}, "
                            f"local=v{local_protocol}"
                        ),
                        "warning",
                    )
                    self.notify(
                        "Peer uses an incompatible transfer protocol.",
                        severity="warning",
                    )
                    return

                if not self.legacy_mode and (
                    peer is None or peer.trust_status != TrustStatus.TRUSTED
                ):
                    self.event_log.log(
                        f"Blocked transfer to untrusted peer {peer_ip}", "warning"
                    )
                    self.notify("Device is not trusted.", severity="warning")
                    return
                all_files: list[str] = []
                for item in items:
                    if os.path.isdir(item):
                        for root, _dirs, files in os.walk(item):
                            for f in files:
                                all_files.append(os.path.join(root, f))
                    elif os.path.isfile(item):
                        all_files.append(item)

                if all_files:
                    try:
                        self.transfer.send_file(peer_ip, all_files, message=message)
                    except RuntimeError as error:
                        log.warning("Unable to start transfer: %s", error)
                        self.notify(
                            "Too many transfers are already active.",
                            severity="warning",
                        )
                        return
                    count = len(all_files)
                    msg = f"Started sending {count} file{'s' if count > 1 else ''} to {peer_ip}"
                    if message:
                        msg += f' with message: "{message}"'
                    self.event_log.log(msg, "info")
                    self.notify(msg, severity="information")
                else:
                    self.event_log.log("No valid files found to send", "error")

        self.push_screen(
            SendFileModal(
                peer_ips=peer_ips,
                start_path=os.path.abspath(os.sep),
                preselect_ip=preselect_ip,
            ),
            callback=_on_result,
        )

    def action_open_peer(self, peer_id: str) -> None:
        """Open a peer-centric workspace by stable peer identifier."""
        peer = self.peer_manager.get_peer(peer_id)
        if peer is None:
            self.notify("Peer went offline.", severity="warning")
            return
        self.push_screen(
            PeerDetailScreen(
                peer_id=peer.stable_id,
                peer_manager=self.peer_manager,
                transfer_engine=self.transfer,
                trust_store=self.trust_store,
            )
        )

    def action_peer_detail(self) -> None:
        """Open details for the selected dashboard peer."""
        screen = self.screen
        peer = screen.selected_peer if isinstance(screen, DashboardScreen) else None
        if peer is None:
            self.notify("No online peers to inspect", severity="warning")
            return
        self.action_open_peer(peer.stable_id)

    def action_open_received(self) -> None:
        """Open the received-files folder in the system file explorer."""
        folder = Path(RECEIVE_DIR)
        folder.mkdir(parents=True, exist_ok=True)

        try:
            if platform.system() == "Windows":
                os.startfile(str(folder))  # type: ignore[attr-defined]
            elif platform.system() == "Darwin":
                subprocess.Popen(["open", str(folder)])
            else:
                subprocess.Popen(["xdg-open", str(folder)])
            self.event_log.log(f"Opened received files folder: {folder}", "info")
        except (OSError, subprocess.SubprocessError) as e:
            self.event_log.log(f"Could not open folder: {e}", "error")
            self.notify(
                str(folder), title="Received Files Folder", severity="information"
            )

    def action_settings(self) -> None:
        """Open settings and local identity information."""
        self.push_screen(
            SettingsScreen(
                identity=self.identity,
                legacy_mode=self.legacy_mode,
            )
        )

    def action_inbox(self) -> None:
        """Open authenticated incoming transfer requests."""
        if self.legacy_mode:
            self.notify("Transfer approval is available in protocol v3.")
            return
        self.push_screen(InboxScreen(self.transfer, self.trust_store))

    def action_history(self) -> None:
        """Open persistent global transfer history."""
        self.push_screen(GlobalHistoryScreen(self.history_store))

    def action_refresh_all(self) -> None:
        self.refresh()
        self.event_log.log("Manual refresh triggered", "info")
        self.notify("Refreshed", severity="information")

    def action_clear_logs(self) -> None:
        self.event_log.clear()
        self.event_log.log("Event log cleared", "info")
        self.notify("Logs cleared", severity="information")

    def action_cancel_transfer(self) -> None:
        """Cancel the most recent non-terminal outgoing transfer session."""
        cancellable = {
            TransferStatus.PENDING,
            TransferStatus.PENDING_APPROVAL,
            TransferStatus.ACCEPTED,
            TransferStatus.ACTIVE,
            TransferStatus.INTERRUPTED,
            TransferStatus.RESUMING,
        }
        outgoing = [
            transfer
            for transfer in self.transfer.get_transfers()
            if transfer.direction.value == "send" and transfer.status in cancellable
        ]
        if not outgoing:
            self.notify("No active outgoing transfer to cancel.")
            return
        latest = max(outgoing, key=lambda transfer: transfer.started_at)
        if self.transfer.cancel_transfer(latest.transfer_id):
            self.notify("Cancelling transfer…", severity="warning")

    def on_unmount(self) -> None:
        log.info("Mesh-Pulse shutting down…")
        if not self.demo_mode:
            self.transfer.stop_server()
            self.broadcaster.stop()
        self.monitor.stop()
        if self._demo_tempdir is not None:
            try:
                self._demo_tempdir.cleanup()
            except Exception as e:
                log.debug("Demo tempdir cleanup: %s", e)
