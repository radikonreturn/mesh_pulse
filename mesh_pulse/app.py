"""Mesh-Pulse TUI Application — the main Textual App entry point.

Orchestrates all core subsystems (P2P discovery, file transfer,
system monitoring) and renders the dashboard TUI.
"""

from __future__ import annotations

import ipaddress
import os
import platform
from pathlib import Path
import psutil

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, Horizontal, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import (
    Input,
    Static,
    Button,
    Label,
    Select,
    DirectoryTree,
    ListView,
    ListItem,
)

from mesh_pulse.core.discovery import PeerManager, UDPBroadcaster
from mesh_pulse.core.monitor import SystemMonitor
from mesh_pulse.core.transfer import SecureTransfer, TransferInfo, TransferStatus
from mesh_pulse.tui.dashboard import DashboardScreen
from mesh_pulse.tui.widgets.event_log import EventLog
from mesh_pulse.utils.config import (
    BROADCAST_PORT,
    DEFAULT_KEY,
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
        width: 100;
        height: 36;
        background: #0d1117;
        border: thick #0ea5e9;
        border-title-color: #0ea5e9;
        padding: 1 2;
    }

    /* ── Title ── */
    #modal-title {
        width: 100%;
        text-align: center;
        text-style: bold;
        color: #58a6ff;
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
        border: round #1d76db;
        border-title-color: #58a6ff;
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
        color: #58a6ff;
        text-style: bold;
        margin: 1 0 0 0;
    }

    .form-label {
        color: #8b949e;
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
        background: #161b22;
        border: tall #30363d;
        color: #e6edf3;
    }

    /* ── Selection counter ── */
    #selection-counter {
        width: 100%;
        color: #3fb950;
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
        background: #161b22;
        border: tall #30363d;
        overflow-y: auto;
    }

    #file-list ListItem {
        height: 1;
        padding: 0 1;
        color: #e6edf3;
        background: #161b22;
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
        background: #161b22;
        border: tall #30363d;
        color: #484f58;
        text-style: italic;
    }

    /* ── Message input ── */
    #transfer-message {
        width: 100%;
        margin: 0;
        background: #161b22;
        border: tall #30363d;
        color: #e6edf3;
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
        color: #484f58;
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
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel", show=False),
    ]

    def __init__(self, peer_ips: list[str], start_path: str = ".", **kwargs):
        super().__init__(**kwargs)
        self._peer_ips = peer_ips
        self._start_path = start_path
        self._selected_files: list[str] = []
        self._selected_folders: list[str] = []

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
                drives.append((f"💾 {p.device}", p.mountpoint))
        else:
            drives.append(("💾 Root (/)", "/"))
            for p in psutil.disk_partitions(all=True):
                if (p.mountpoint.startswith("/mnt/") or p.mountpoint.startswith("/media/")) and len(p.mountpoint.split("/")) == 3:
                    drives.append((f"💾 {p.mountpoint}", p.mountpoint))
        
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
            options = [(f"📡  {ip}", ip) for ip in self._peer_ips]
        else:
            options = [("No peers discovered", "__none__")]

        drives = self._get_drives()
        initial_drive = self._start_path if any(d[1] == self._start_path for d in drives) else (drives[0][1] if drives else Select.BLANK)

        with Vertical(id="modal-box"):
            yield Static("📡  Initiate File Transfer", id="modal-title")

            with Horizontal(id="modal-body"):
                # ── Left: file browser ──
                with Vertical(id="browser-panel"):
                    yield Select(
                        drives, id="drive-select", prompt="Select Drive...", value=initial_drive
                    )
                    yield Static(
                        "📂 Browse — click to select / deselect",
                        classes="form-label",
                    )
                    yield DirectoryTree(self._start_path, id="file-tree")

                # ── Right: transfer details ──
                with Vertical(id="details-panel"):
                    # Recipient section
                    yield Static("🎯 Recipient", classes="section-label")
                    yield Select(
                        options, id="peer-select", prompt="Select a peer…"
                    )
                    yield Static("── or enter IP manually ──", classes="section-divider")
                    yield Input(
                        placeholder="192.168.1.x",
                        id="manual-ip",
                    )

                    # Selected files section
                    yield Static("📦 Selected Items  (click to remove)", classes="section-label")
                    yield Static("", id="selection-counter")
                    yield Static(
                        "  Click files or folders on the left",
                        id="file-placeholder",
                    )
                    yield ListView(id="file-list")

                    # Message section
                    yield Static("💬 Message", classes="section-label")
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
                        "✓ Send",
                        variant="success",
                        id="send-btn",
                        disabled=True,
                    )
                    yield Button("✗ Clear", variant="warning", id="clear-btn")
                    yield Button("✗ Cancel", variant="error", id="cancel-btn")

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

        # Clear existing items
        file_list.clear()

        total_size = 0
        n_files = len(self._selected_files)
        n_folders = len(self._selected_folders)

        for fp in self._selected_folders:
            name = Path(fp).name
            size = self._get_size(fp)
            total_size += size
            item = ListItem(Label(f"📁 {name}/  ({self._human_size(size)})", classes="file-item-label"), name=fp)
            file_list.append(item)

        for fp in self._selected_files:
            name = Path(fp).name
            size = self._get_size(fp)
            total_size += size
            item = ListItem(Label(f"📄 {name}  — {self._human_size(size)}", classes="file-item-label"), name=fp)
            file_list.append(item)

        parts: list[str] = []
        if n_files:
            parts.append(f"{n_files} file{'s' if n_files > 1 else ''}")
        if n_folders:
            parts.append(f"{n_folders} folder{'s' if n_folders > 1 else ''}")
        counter.update(f"  📊 {', '.join(parts)}  ·  {self._human_size(total_size)} total")

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
            if event.value is not Select.BLANK:
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
        if select.value is not Select.BLANK and select.value != "__none__":
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


# ── Main Application ───────────────────────────────────────────────


class MeshPulseApp(App):
    """Mesh-Pulse Command Center — TUI Application."""

    TITLE = "⚡ Mesh-Pulse Command Center"
    SUB_TITLE = "Network Mesh & System Resource Monitor"
    CSS_PATH = Path(__file__).parent / "tui" / "styles" / "dashboard.tcss"

    BINDINGS = [
        Binding("q", "quit", "Quit", priority=True),
        Binding("s", "send_file", "Send File"),
        Binding("r", "refresh_all", "Refresh"),
        Binding("c", "clear_logs", "Clear Logs"),
        Binding("d", "toggle_dark", "Toggle Dark"),
    ]

    def __init__(
        self,
        passphrase: str = DEFAULT_KEY,
        broadcast_port: int = BROADCAST_PORT,
        transfer_port: int = TRANSFER_PORT,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self.event_log = EventLog()
        self.monitor = SystemMonitor()
        self.peer_manager = PeerManager()
        self.broadcaster = UDPBroadcaster(
            peer_manager=self.peer_manager,
            broadcast_port=broadcast_port,
            transfer_port=transfer_port,
            local_metrics_fn=lambda: self.monitor.latest.to_broadcast_dict(),
        )
        self.transfer = SecureTransfer(
            passphrase=passphrase,
            transfer_port=transfer_port,
            on_file_received=self._on_file_received,
        )

    def _on_file_received(self, info: TransferInfo) -> None:
        """Called from FileServer thread when a file reception finishes."""
        size_mb = info.filesize / (1024 * 1024)
        if info.status == TransferStatus.COMPLETE:
            msg = (
                f"📥 Received '{info.filename}' from {info.peer_ip} "
                f"({size_mb:.1f} MB, {info.speed_mbps:.1f} MB/s)"
            )
            level = "success"
            severity = "information"
        else:
            msg = (
                f"❌ Failed to receive '{info.filename}' from {info.peer_ip}: "
                f"{info.error or 'Unknown error'}"
            )
            level = "error"
            severity = "warning"

        # Thread-safe: schedule on the Textual event loop
        try:
            self.call_from_thread(self.event_log.log, msg, level)
            self.call_from_thread(self.notify, msg, severity=severity)
        except Exception:
            pass  # App may be shutting down

    def on_mount(self) -> None:
        """Start all background subsystems when the app mounts."""
        self.event_log.log("Mesh-Pulse starting up...", "info")
        self.monitor.start()
        self.event_log.log("System monitor active", "success")
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
            )
        )
        self.event_log.log("Dashboard loaded — all systems operational", "success")
        log.info("Dashboard loaded — all systems operational")

    def action_toggle_dark(self) -> None:
        self.dark = not self.dark

    def action_send_file(self) -> None:
        """Open the file picker modal populated with discovered peers."""
        peers = self.peer_manager.get_peers()
        peer_ips = [p.ip for p in peers]

        def _on_result(result: tuple[str, list[str], str] | None) -> None:
            if result:
                peer_ip, items, message = result
                # Expand folders into individual files
                all_files: list[str] = []
                for item in items:
                    if os.path.isdir(item):
                        for root, _dirs, files in os.walk(item):
                            for f in files:
                                all_files.append(os.path.join(root, f))
                    elif os.path.isfile(item):
                        all_files.append(item)
                
                if all_files:
                    self.transfer.send_file(peer_ip, all_files, message=message)
                    count = len(all_files)
                    msg = f"Started sending {count} file{'s' if count > 1 else ''} to {peer_ip}"
                    if message:
                        msg += f" with message: {message}"
                    self.event_log.log(msg, "info")
                    self.notify(msg, severity="information")
                else:
                    self.event_log.log("No valid files found to send", "error")

        self.push_screen(
            SendFileModal(peer_ips=peer_ips, start_path=os.path.abspath(os.sep)),
            callback=_on_result,
        )

    def action_refresh_all(self) -> None:
        self.refresh()
        self.event_log.log("Manual refresh triggered", "info")
        self.notify("Refreshed", severity="information")

    def action_clear_logs(self) -> None:
        self.event_log.clear()
        self.event_log.log("Event log cleared", "info")
        self.notify("Logs cleared", severity="information")

    def on_unmount(self) -> None:
        log.info("Mesh-Pulse shutting down...")
        self.broadcaster.stop()
        self.monitor.stop()
        self.transfer.stop_server()
