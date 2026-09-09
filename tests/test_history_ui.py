"""Persistent history screen behavior tests."""

from __future__ import annotations

import asyncio
import time

from textual.app import App
from textual.widgets import DataTable, Input, Select, Static

from mesh_pulse.core.history import TransferHistoryStore, TransferRecord
from mesh_pulse.tui.screens.history import GlobalHistoryScreen


def _record(transfer_id: str, status: str, direction: str) -> TransferRecord:
    return TransferRecord(
        transfer_id=transfer_id,
        peer_device_id="mp-12345678",
        peer_ip="192.0.2.1",
        peer_hostname="workstation",
        direction=direction,
        status=status,
        message=None,
        file_count=2,
        total_size=1024,
        bytes_transferred=1024 if status == "complete" else 512,
        started_at=time.time(),
    )


class _HistoryApp(App):
    def __init__(self, store: TransferHistoryStore):
        super().__init__()
        self.store = store

    def on_mount(self) -> None:
        self.push_screen(GlobalHistoryScreen(self.store))


def test_global_history_filters_and_empty_search(tmp_path):
    async def exercise() -> None:
        store = TransferHistoryStore(tmp_path / "history.db")
        store.create_transfer(_record("a" * 32, "complete", "send"))
        store.create_transfer(_record("b" * 32, "failed", "recv"))
        app = _HistoryApp(store)
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            screen = app.screen
            table = screen.query_one("#global-history-table", DataTable)
            assert table.row_count == 2
            screen.query_one("#history-filter", Select).value = "failed"
            screen.refresh_history()
            assert table.row_count == 1
            screen.query_one("#history-filter", Select).value = "all"
            screen.query_one("#history-search", Input).value = "no-match"
            screen.refresh_history()
            assert table.row_count == 0
            assert screen.query_one("#global-history-empty", Static).display

    asyncio.run(exercise())
