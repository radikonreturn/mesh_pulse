"""Tests for P2P peer discovery and management."""

import time
import pytest

from mesh_pulse.core.discovery import Peer, PeerManager, PeerStatus


class TestPeerManager:
    """Test PeerManager peer lifecycle management."""

    def test_add_new_peer(self):
        pm = PeerManager()
        pm.update_peer("HOST-A", "192.168.1.10", 10000)
        peers = pm.get_peers()
        assert len(peers) == 1
        assert peers[0].hostname == "HOST-A"
        assert peers[0].ip == "192.168.1.10"
        assert peers[0].status == PeerStatus.ONLINE

    def test_update_existing_peer_refreshes_timestamp(self):
        pm = PeerManager()
        pm.update_peer("HOST-A", "192.168.1.10", 10000)
        time.sleep(0.1)
        pm.update_peer("HOST-A", "192.168.1.10", 10000)
        peer = pm.get_peer("192.168.1.10")
        assert peer is not None
        assert peer.age < 0.2  # just refreshed

    def test_multiple_peers(self):
        pm = PeerManager()
        pm.update_peer("HOST-A", "192.168.1.10", 10000)
        pm.update_peer("HOST-B", "192.168.1.11", 10000)
        pm.update_peer("HOST-C", "192.168.1.12", 10000)
        assert pm.count == 3

    def test_stale_timeout(self):
        pm = PeerManager(stale_timeout=0.1, dead_timeout=10.0)
        pm.update_peer("HOST-A", "192.168.1.10", 10000)
        time.sleep(0.15)
        pm.sweep()
        peer = pm.get_peer("192.168.1.10")
        assert peer is not None
        assert peer.status == PeerStatus.STALE

    def test_dead_timeout_removes_peer(self):
        pm = PeerManager(stale_timeout=0.05, dead_timeout=0.1)
        pm.update_peer("HOST-A", "192.168.1.10", 10000)
        time.sleep(0.15)
        pm.sweep()
        assert pm.count == 0

    def test_refresh_prevents_staleness(self):
        pm = PeerManager(stale_timeout=0.2, dead_timeout=1.0)
        pm.update_peer("HOST-A", "192.168.1.10", 10000)
        time.sleep(0.1)
        pm.update_peer("HOST-A", "192.168.1.10", 10000)  # refresh
        pm.sweep()
        peer = pm.get_peer("192.168.1.10")
        assert peer is not None
        assert peer.status == PeerStatus.ONLINE

    def test_peer_metrics_update(self):
        pm = PeerManager()
        metrics = {"cpu_percent": 55.0, "ram_percent": 70.0}
        pm.update_peer("HOST-A", "192.168.1.10", 10000, metrics=metrics)
        peer = pm.get_peer("192.168.1.10")
        assert peer is not None
        assert peer.metrics.cpu_percent == 55.0
        assert peer.metrics.ram_percent == 70.0

    def test_on_change_callback(self):
        changes = []
        pm = PeerManager(on_peer_change=lambda: changes.append(1))
        pm.update_peer("HOST-A", "192.168.1.10", 10000)
        assert len(changes) == 1

    def test_get_nonexistent_peer_returns_none(self):
        pm = PeerManager()
        assert pm.get_peer("10.0.0.1") is None


class TestPeer:
    """Test Peer dataclass."""

    def test_peer_age(self):
        peer = Peer(hostname="test", ip="1.2.3.4", port=10000)
        time.sleep(0.1)
        assert peer.age >= 0.1

    def test_peer_to_dict(self):
        peer = Peer(hostname="test", ip="1.2.3.4", port=10000)
        d = peer.to_dict()
        assert d["hostname"] == "test"
        assert d["ip"] == "1.2.3.4"
        assert d["status"] == "online"
        assert "age" in d
