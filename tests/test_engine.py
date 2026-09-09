"""Tests for the MeshEngine context manager and start/stop_engine helpers."""

from __future__ import annotations

import time

from mesh_pulse.core.discovery import PeerDiscovery, PeerManager
from mesh_pulse.core.engine import EngineHandles, MeshEngine, start_engine, stop_engine
from mesh_pulse.core.monitor import SystemMonitor
from mesh_pulse.core.transfer import FileClient, FileServer

# ── start_engine / stop_engine ──────────────────────────────────────


def test_start_engine_returns_handles():
    """start_engine() returns an EngineHandles with all subsystem references."""
    handles = start_engine(broadcast_port=39900, transfer_port=39901)
    try:
        assert isinstance(handles, EngineHandles)
        assert isinstance(handles.peer_manager, PeerManager)
        assert isinstance(handles.discovery, PeerDiscovery)
        assert isinstance(handles.file_server, FileServer)
        assert isinstance(handles.file_client, FileClient)
        assert isinstance(handles.monitor, SystemMonitor)
    finally:
        stop_engine(handles)


def test_start_engine_threads_alive():
    """After start_engine(), background threads are alive."""
    handles = start_engine(broadcast_port=39902, transfer_port=39903)
    try:
        time.sleep(0.2)
        assert handles.discovery.is_alive(), "PeerDiscovery thread should be alive"
        assert handles.file_server.is_alive(), "FileServer thread should be alive"
        assert handles.monitor._running, "SystemMonitor should be running"
    finally:
        stop_engine(handles)


def test_stop_engine_signals_threads():
    """stop_engine() signals the discovery and file server to stop."""
    handles = start_engine(broadcast_port=39904, transfer_port=39905)
    time.sleep(0.2)
    stop_engine(handles)
    # Give daemon threads a moment to respond to shutdown signal
    time.sleep(0.3)
    assert not handles.discovery._running.is_set(), (
        "PeerDiscovery _running event should be cleared after stop"
    )
    assert not handles.monitor._running, (
        "SystemMonitor _running should be False after stop"
    )


def test_start_engine_monitor_produces_data():
    """SystemMonitor collects at least one sample during engine run."""
    handles = start_engine(broadcast_port=39906, transfer_port=39907)
    try:
        time.sleep(0.5)
        assert handles.monitor.latest.timestamp > 0
    finally:
        stop_engine(handles)


# ── MeshEngine context manager ───────────────────────────────────────


def test_mesh_engine_context_manager_basic():
    """MeshEngine context manager starts and stops without errors."""
    with MeshEngine(broadcast_port=39910, transfer_port=39911) as handles:
        assert isinstance(handles, EngineHandles)
        assert handles.discovery.is_alive()


def test_mesh_engine_context_manager_stops_on_exit():
    """MeshEngine cleans up after the with block."""
    with MeshEngine(broadcast_port=39912, transfer_port=39913) as handles:
        discovery = handles.discovery
        monitor = handles.monitor

    time.sleep(0.3)
    assert not discovery._running.is_set()
    assert not monitor._running


def test_mesh_engine_peer_manager_accessible():
    """PeerManager inside MeshEngine is a usable registry."""
    with MeshEngine(broadcast_port=39914, transfer_port=39915) as handles:
        assert isinstance(handles.peer_manager, PeerManager)
        assert handles.peer_manager.count == 0  # no peers on loopback


def test_mesh_engine_file_client_accessible():
    """FileClient inside MeshEngine can be accessed."""
    with MeshEngine(broadcast_port=39916, transfer_port=39917) as handles:
        assert isinstance(handles.file_client, FileClient)
        assert handles.file_client.get_transfers() == []
