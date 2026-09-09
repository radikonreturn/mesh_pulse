"""Interactive peer workspace and peer-specific history tests."""

from __future__ import annotations

import asyncio

from rich.console import Console
from textual.app import App, ComposeResult
from textual.widgets import DataTable, Static

from mesh_pulse.app import SendFileModal
from mesh_pulse.core.discovery import Peer, PeerManager
from mesh_pulse.core.transfer import (
    TransferDirection,
    TransferInfo,
    TransferStatus,
)
from mesh_pulse.tui.screens.peer_detail import format_peer_detail
from mesh_pulse.tui.screens.transfer_history import transfers_for_peer
from mesh_pulse.tui.widgets.peer_list import PeerListWidget


class PeerListApp(App):
    def __init__(self, peer_manager: PeerManager):
        super().__init__()
        self.peer_manager = peer_manager

    def compose(self) -> ComposeResult:
        yield PeerListWidget(self.peer_manager)


def test_peer_selection_preserved_during_refresh():
    async def exercise() -> None:
        manager = PeerManager()
        manager.update_peer("alpha", "192.0.2.1", 5000)
        manager.update_peer("bravo", "192.0.2.2", 5000)
        app = PeerListApp(manager)
        async with app.run_test(size=(100, 30)) as pilot:
            table = app.query_one("#peer-table", DataTable)
            widget = app.query_one(PeerListWidget)
            table.move_cursor(row=1)
            await pilot.pause()
            assert widget.selected_key == "192.0.2.2"

            manager.update_peer(
                "bravo",
                "192.0.2.2",
                5000,
                metrics={"cpu_percent": 42.0},
            )
            widget.refresh_peers()
            assert widget.selected_key == "192.0.2.2"
            assert table.cursor_row == 1

    asyncio.run(exercise())


def test_peer_disappears_while_selected_uses_nearest_row():
    async def exercise() -> None:
        manager = PeerManager()
        manager.update_peer("alpha", "192.0.2.1", 5000)
        manager.update_peer("bravo", "192.0.2.2", 5000)
        app = PeerListApp(manager)
        async with app.run_test(size=(100, 30)) as pilot:
            table = app.query_one("#peer-table", DataTable)
            widget = app.query_one(PeerListWidget)
            table.move_cursor(row=1)
            await pilot.pause()
            assert manager.remove_peer("192.0.2.2") is not None
            widget.refresh_peers()

            assert widget.selected_key == "192.0.2.1"
            assert table.cursor_row == 0

    asyncio.run(exercise())


def test_empty_peer_state_is_visible():
    async def exercise() -> None:
        app = PeerListApp(PeerManager())
        async with app.run_test(size=(80, 24)):
            assert app.query_one("#peer-empty", Static).display
            assert not app.query_one("#peer-table", DataTable).display

    asyncio.run(exercise())


def test_peer_detail_data_formatting():
    peer = Peer(
        hostname="workstation",
        ip="192.0.2.10",
        port=5000,
        device_id="mp-12345678",
    )
    peer.metrics.cpu_percent = 23.0
    peer.metrics.ram_percent = 48.0
    peer.latency_ms = 3.4
    console = Console(record=True, width=100)
    console.print(format_peer_detail(peer))
    rendered = console.export_text()
    assert "workstation" in rendered
    assert "mp-12345678" in rendered
    assert "23.0%" in rendered
    assert "3 ms" in rendered


def test_peer_history_filtering_prefers_identity_and_supports_ip():
    matching_id = TransferInfo(
        "a.txt",
        10,
        TransferDirection.SEND,
        "198.51.100.99",
        status=TransferStatus.COMPLETE,
    )
    matching_id.peer_device_id = "mp-12345678"
    matching_ip = TransferInfo(
        "b.txt",
        20,
        TransferDirection.RECV,
        "192.0.2.10",
        status=TransferStatus.COMPLETE,
    )
    unrelated = TransferInfo(
        "c.txt",
        30,
        TransferDirection.SEND,
        "192.0.2.11",
    )
    assert transfers_for_peer(
        [matching_id, matching_ip, unrelated], "mp-12345678", "192.0.2.10"
    ) == [matching_id, matching_ip]


def test_send_modal_receives_preselected_peer(tmp_path):
    modal = SendFileModal(
        ["192.0.2.1", "192.0.2.2"],
        start_path=str(tmp_path),
        preselect_ip="192.0.2.2",
    )
    assert modal.preselected_peer_ip == "192.0.2.2"
