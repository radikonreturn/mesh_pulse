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
