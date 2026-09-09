"""Deterministic tests for bounded, explainable LAN observations."""

from __future__ import annotations

import socket
import time
from collections import namedtuple

from mesh_pulse.core.discovery import Peer, PeerManager, PeerStatus
from mesh_pulse.core.network_intelligence import peer_health, summarize_network
from mesh_pulse.core.network_interfaces import lan_ipv4_interfaces
from mesh_pulse.core.trust import TrustStatus


def test_peer_availability_online_stale_offline_then_forgotten():
    manager = PeerManager(
        stale_timeout=1,
        dead_timeout=2,
        forget_timeout=3,
    )
    manager.update_peer("peer", "192.0.2.10", 5000)
    peer = manager.get_peer("192.0.2.10")
    assert peer is not None and peer.status == PeerStatus.ONLINE

    peer.last_seen_monotonic = time.monotonic() - 1.5
    manager.sweep()
    assert peer.status == PeerStatus.STALE

    peer.last_seen_monotonic = time.monotonic() - 2.5
    manager.sweep()
    assert peer.status == PeerStatus.OFFLINE

    peer.last_seen_monotonic = time.monotonic() - 3.5
    manager.sweep()
    assert manager.get_peer("192.0.2.10") is None


def test_same_device_new_ip_updates_without_duplicate():
    manager = PeerManager()
    manager.update_peer("peer", "192.0.2.10", 5000, device_id="mp-deadbeef")
    manager.update_peer("peer", "192.0.2.42", 5000, device_id="mp-deadbeef")
    assert manager.count == 1
    assert manager.get_peer("mp-deadbeef").ip == "192.0.2.42"
    assert manager.get_peer("192.0.2.10") is None
    assert manager.get_peer("mp-deadbeef").seen_count == 2


def test_invalid_latency_measurements_are_ignored():
    manager = PeerManager()
    manager.update_peer("peer", "192.0.2.10", 5000)
    manager.update_latency("192.0.2.10", 3.5)
    manager.update_latency("192.0.2.10", float("nan"))
    manager.update_latency("192.0.2.10", -1)
    assert manager.get_peer("192.0.2.10").latency_ms == 3.5
    manager.update_latency("192.0.2.10", None)
    assert manager.get_peer("192.0.2.10").latency_ms is None


def test_network_summary_keeps_unavailable_latency_unknown():
    peer = Peer("peer", "192.0.2.10", 5000, trust_status=TrustStatus.TRUSTED)
    overview = summarize_network([peer], active_transfers=2)
    assert overview.online == 1
    assert overview.trusted_online == 1
    assert overview.median_latency_ms is None
    assert overview.active_transfers == 2
    assert peer_health(peer) == "Good"


def test_interface_selection_excludes_loopback_down_and_duplicates(monkeypatch):
    Address = namedtuple("Address", "family address netmask broadcast ptp")
    Stats = namedtuple("Stats", "isup")
    monkeypatch.setattr(
        "mesh_pulse.core.network_interfaces.psutil.net_if_addrs",
        lambda: {
            "loop": [Address(socket.AF_INET, "127.0.0.1", None, None, None)],
            "down": [Address(socket.AF_INET, "192.0.2.3", None, None, None)],
            "lan": [Address(socket.AF_INET, "192.0.2.2", None, "192.0.2.255", None)],
            "duplicate": [
                Address(socket.AF_INET, "192.0.2.2", None, "192.0.2.255", None)
            ],
        },
    )
    monkeypatch.setattr(
        "mesh_pulse.core.network_interfaces.psutil.net_if_stats",
        lambda: {
            "loop": Stats(True),
            "down": Stats(False),
            "lan": Stats(True),
            "duplicate": Stats(True),
        },
    )
    interfaces = lan_ipv4_interfaces()
    assert [(item.address, item.broadcast) for item in interfaces] == [
        ("192.0.2.2", "192.0.2.255")
    ]


def test_transfer_complete_increments_success_stats():
    manager = PeerManager()
    manager.update_peer("peer", "192.0.2.10", 5000)
    peer = manager.get_peer("192.0.2.10")
    assert peer.successful_transfers == 0
    assert peer.failed_transfers == 0
    assert peer.connection_failures == 0

    manager.record_transfer_result("192.0.2.10", success=True)
    assert peer.successful_transfers == 1
    assert peer.failed_transfers == 0
    assert peer.connection_failures == 0
    assert peer_health(peer) == "Good"


def test_transfer_failed_increments_failure_stats():
    manager = PeerManager()
    manager.update_peer("peer", "192.0.2.10", 5000)
    peer = manager.get_peer("192.0.2.10")

    # Connection failure increments both failed_transfers and connection_failures
    manager.record_transfer_result("192.0.2.10", success=False, connection_failure=True)
    assert peer.successful_transfers == 0
    assert peer.failed_transfers == 1
    assert peer.connection_failures == 1

    # Non-connection failure increments failed_transfers but not connection_failures
    manager.record_transfer_result(
        "192.0.2.10", success=False, connection_failure=False
    )
    assert peer.successful_transfers == 0
    assert peer.failed_transfers == 2
    assert peer.connection_failures == 1


def test_app_transfer_event_rejected_and_cancelled_do_not_degrade_health():
    from mesh_pulse.app import MeshPulseApp
    from mesh_pulse.core.events import TransferCompleted, TransferFailed
    from mesh_pulse.core.transfer_models import (
        TransferDirection,
        TransferInfo,
        TransferStatus,
    )

    # Use an uninitialized app instance to test event dispatch in isolation
    app = MeshPulseApp.__new__(MeshPulseApp)
    app.peer_manager = PeerManager()
    app.peer_manager.update_peer("peer", "192.0.2.10", 5000)
    peer = app.peer_manager.get_peer("192.0.2.10")

    # REJECTED transfer: must not count as failure
    rejected_info = TransferInfo(
        filename="test.txt",
        filesize=100,
        direction=TransferDirection.SEND,
        peer_ip="192.0.2.10",
        status=TransferStatus.REJECTED,
        error="Transfer rejected by peer.",
    )
    app._on_transfer_event(TransferFailed(rejected_info))
    assert peer.successful_transfers == 0
    assert peer.failed_transfers == 0
    assert peer.connection_failures == 0
    assert peer_health(peer) == "Good"

    # CANCELLED transfer: must not count as failure
    cancelled_info = TransferInfo(
        filename="test.txt",
        filesize=100,
        direction=TransferDirection.SEND,
        peer_ip="192.0.2.10",
        status=TransferStatus.CANCELLED,
        error="Transfer cancelled by user.",
    )
    app._on_transfer_event(TransferFailed(cancelled_info))
    assert peer.successful_transfers == 0
    assert peer.failed_transfers == 0
    assert peer.connection_failures == 0
    assert peer_health(peer) == "Good"

    # COMPLETED transfer: increments success
    completed_info = TransferInfo(
        filename="test.txt",
        filesize=100,
        direction=TransferDirection.SEND,
        peer_ip="192.0.2.10",
        status=TransferStatus.COMPLETE,
    )
    app._on_transfer_event(TransferCompleted(completed_info))
    assert peer.successful_transfers == 1
    assert peer.failed_transfers == 0
    assert peer.connection_failures == 0
    assert peer_health(peer) == "Good"

    # FAILED transfer with connection error: increments connection failure
    failed_info = TransferInfo(
        filename="test.txt",
        filesize=100,
        direction=TransferDirection.SEND,
        peer_ip="192.0.2.10",
        status=TransferStatus.FAILED,
        error="Unable to connect to peer.",
    )
    app._on_transfer_event(TransferFailed(failed_info))
    app._on_transfer_event(TransferFailed(failed_info))
    app._on_transfer_event(TransferFailed(failed_info))
    assert peer.failed_transfers == 3
    assert peer.connection_failures == 3
    # 3 connection failures > 1 success + 1 -> peer becomes Unstable
    assert peer_health(peer) == "Unstable"
