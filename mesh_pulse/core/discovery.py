"""P2P discovery via UDP broadcast with heartbeat-based peer management.

Architecture:
    - PeerDiscovery(Thread): single-threaded broadcaster + listener on UDP 37020
    - PeerManager: thread-safe registry of discovered peers (used by TUI widgets)
    - UDPBroadcaster: legacy facade wrapping PeerDiscovery (used by app.py)

Peers auto-transition: ONLINE → STALE → removed, based on heartbeat age.
"""

from __future__ import annotations

import json
import socket
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable

from mesh_pulse.utils.config import (
    BROADCAST_ADDR,
    BROADCAST_INTERVAL,
    BROADCAST_PORT,
    HOSTNAME,
    LOCAL_IP,
    PEER_DEAD_TIMEOUT,
    PEER_STALE_TIMEOUT,
    PEER_TIMEOUT,
    TRANSFER_PORT,
)
from mesh_pulse.utils.logger import get_logger

log = get_logger(__name__)


# ─── Data Models ────────────────────────────────────────────────────


class PeerStatus(Enum):
    """Lifecycle states for a discovered peer."""
    ONLINE = "online"
    STALE = "stale"


@dataclass
class PeerMetrics:
    """Lightweight system metrics snapshot from a peer."""
    cpu_percent: float = 0.0
    ram_percent: float = 0.0
    disk_read_bytes: int = 0
    disk_write_bytes: int = 0
    net_sent_bytes: int = 0
    net_recv_bytes: int = 0


@dataclass
class Peer:
    """Represents a discovered network peer."""
    hostname: str
    ip: str
    port: int
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    status: PeerStatus = PeerStatus.ONLINE
    metrics: PeerMetrics = field(default_factory=PeerMetrics)

    @property
    def age(self) -> float:
        """Seconds since last heartbeat."""
        return time.time() - self.last_seen

    def to_dict(self) -> dict:
        return {
            "hostname": self.hostname,
            "ip": self.ip,
            "port": self.port,
            "status": self.status.value,
            "age": round(self.age, 1),
        }


# ─── Peer Manager ──────────────────────────────────────────────────


class PeerManager:
    """Thread-safe registry of discovered peers with timeout management.

    Peers transition: ONLINE → STALE → removed, based on heartbeat age.
    """

    def __init__(
        self,
        stale_timeout: float = PEER_STALE_TIMEOUT,
        dead_timeout: float = PEER_DEAD_TIMEOUT,
        on_peer_change: Callable | None = None,
    ):
        self._peers: dict[str, Peer] = {}
        self._lock = threading.Lock()
        self._stale_timeout = stale_timeout
        self._dead_timeout = dead_timeout
        self._on_peer_change = on_peer_change

    def update_peer(
        self,
        hostname: str,
        ip: str,
        port: int,
        metrics: dict | None = None,
    ) -> None:
        """Register or refresh a peer from a received beacon.

        Args:
            hostname: Peer's hostname.
            ip: Peer's IP address.
            port: Peer's transfer port.
            metrics: Optional metrics dict from the beacon.
        """
        with self._lock:
            if ip in self._peers:
                peer = self._peers[ip]
                peer.last_seen = time.time()
                peer.status = PeerStatus.ONLINE
                if metrics:
                    peer.metrics = PeerMetrics(**metrics)
            else:
                peer = Peer(hostname=hostname, ip=ip, port=port)
                if metrics:
                    peer.metrics = PeerMetrics(**metrics)
                self._peers[ip] = peer
                log.info("Discovered new peer: %s (%s)", hostname, ip)

        if self._on_peer_change:
            self._on_peer_change()

    def sweep(self) -> None:
        """Mark stale peers and remove dead ones."""
        now = time.time()
        changed = False
        with self._lock:
            dead_ips = []
            for ip, peer in self._peers.items():
                age = now - peer.last_seen
                if age > self._dead_timeout:
                    dead_ips.append(ip)
                    changed = True
                elif age > self._stale_timeout and peer.status == PeerStatus.ONLINE:
                    peer.status = PeerStatus.STALE
                    changed = True
                    log.info("Peer stale: %s (%s)", peer.hostname, ip)

            for ip in dead_ips:
                removed = self._peers.pop(ip)
                log.info("Peer removed: %s (%s)", removed.hostname, ip)

        if changed and self._on_peer_change:
            self._on_peer_change()

    def get_peers(self) -> list[Peer]:
        """Return a snapshot of all known peers."""
        with self._lock:
            return list(self._peers.values())

    def get_peer(self, ip: str) -> Peer | None:
        """Look up a single peer by IP."""
        with self._lock:
            return self._peers.get(ip)

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._peers)


# ─── PeerDiscovery Thread ──────────────────────────────────────────


class PeerDiscovery(threading.Thread):
    """Single-threaded UDP peer discovery.

    Acts as both a Broadcaster (sends JSON heartbeats every 2s) and a
    Listener (binds to UDP port 37020). Discovered peers are stored in
    a shared dict ``self.peers`` {IP: LastSeenTimestamp} and auto-removed
    if unseen for PEER_TIMEOUT seconds.

    Usage:
        discovery = PeerDiscovery()
        discovery.start()
        print(discovery.peers)
        discovery.shutdown()
    """

    def __init__(
        self,
        port: int = BROADCAST_PORT,
        transfer_port: int = TRANSFER_PORT,
        interval: float = BROADCAST_INTERVAL,
        peer_timeout: float = PEER_TIMEOUT,
        local_metrics_fn: Callable[[], dict] | None = None,
        peer_manager: PeerManager | None = None,
    ):
        super().__init__(daemon=True, name="peer-discovery")
        self._port = port
        self._transfer_port = transfer_port
        self._interval = interval
        self._peer_timeout = peer_timeout
        self._local_metrics_fn = local_metrics_fn
        self._pm = peer_manager
        self._running = threading.Event()
        self._running.set()

        # Shared dict: {IP: LastSeenTimestamp}
        self.peers: dict[str, float] = {}
        self._peers_lock = threading.Lock()

    def run(self) -> None:
        """Main thread loop: broadcast, listen, and sweep concurrently."""
        # Start a separate listener thread (uses select-style timeout)
        listener = threading.Thread(
            target=self._listen_loop, daemon=True, name="udp-listen"
        )
        listener.start()

        # This thread handles broadcasting + sweep
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(1.0)

        while self._running.is_set():
            # ── Broadcast ──
            try:
                beacon = self._build_beacon()
                sock.sendto(beacon, (BROADCAST_ADDR, self._port))
            except OSError as e:
                log.debug("Broadcast send error: %s", e)

            # ── Sweep dead peers ──
            self._sweep_peers()

            # ── Wait for next interval ──
            self._running.wait(self._interval)

        sock.close()
        log.info("PeerDiscovery stopped")

    def shutdown(self) -> None:
        """Signal the discovery thread to stop."""
        self._running.clear()

    def get_active_peers(self) -> dict[str, float]:
        """Return a copy of the active peers dict."""
        with self._peers_lock:
            return dict(self.peers)

    # ── Internal ────────────────────────────────────────────────

    def _build_beacon(self) -> bytes:
        """Build a JSON heartbeat beacon."""
        payload: dict = {
            "hostname": HOSTNAME,
            "ip": LOCAL_IP,
            "port": self._transfer_port,
            "timestamp": time.time(),
        }
        if self._local_metrics_fn:
            try:
                payload["metrics"] = self._local_metrics_fn()
            except Exception:
                pass
        return json.dumps(payload).encode("utf-8")

    def _listen_loop(self) -> None:
        """Listen for incoming beacons from other peers."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(1.0)

        try:
            sock.bind(("", self._port))
        except OSError as e:
            log.error("Cannot bind UDP listener on port %d: %s", self._port, e)
            return

        while self._running.is_set():
            try:
                data, addr = sock.recvfrom(4096)
                beacon = json.loads(data.decode("utf-8"))

                # Ignore our own beacons
                if beacon.get("ip") == LOCAL_IP:
                    continue

                peer_ip = beacon.get("ip", addr[0])

                # Update shared peers dict
                with self._peers_lock:
                    self.peers[peer_ip] = time.time()

                # Also update PeerManager if attached (for TUI widgets)
                if self._pm:
                    self._pm.update_peer(
                        hostname=beacon.get("hostname", "unknown"),
                        ip=peer_ip,
                        port=beacon.get("port", self._transfer_port),
                        metrics=beacon.get("metrics"),
                    )

            except socket.timeout:
                continue
            except (json.JSONDecodeError, OSError) as e:
                log.debug("Listen error: %s", e)

        sock.close()

    def _sweep_peers(self) -> None:
        """Remove peers not seen within PEER_TIMEOUT seconds."""
        now = time.time()
        with self._peers_lock:
            dead = [ip for ip, ts in self.peers.items() if now - ts > self._peer_timeout]
            for ip in dead:
                del self.peers[ip]
                log.info("Peer auto-removed (timeout): %s", ip)

        # Also sweep the PeerManager
        if self._pm:
            self._pm.sweep()


# ─── UDPBroadcaster (Legacy facade for app.py) ────────────────────


class UDPBroadcaster:
    """Legacy facade wrapping PeerDiscovery for backwards compatibility.

    Used by app.py and TUI. Delegates to PeerDiscovery internally.

    Usage:
        pm = PeerManager()
        broadcaster = UDPBroadcaster(pm)
        broadcaster.start()
        broadcaster.stop()
    """

    def __init__(
        self,
        peer_manager: PeerManager,
        broadcast_port: int = BROADCAST_PORT,
        transfer_port: int = TRANSFER_PORT,
        interval: float = BROADCAST_INTERVAL,
        local_metrics_fn: Callable[[], dict] | None = None,
    ):
        self._discovery = PeerDiscovery(
            port=broadcast_port,
            transfer_port=transfer_port,
            interval=interval,
            local_metrics_fn=local_metrics_fn,
            peer_manager=peer_manager,
        )

    def start(self) -> None:
        """Start the discovery thread."""
        if self._discovery.is_alive():
            return
        self._discovery.start()
        log.info("UDP Broadcaster started on port %d", self._discovery._port)

    def stop(self) -> None:
        """Stop the discovery thread."""
        self._discovery.shutdown()
        log.info("UDP Broadcaster stopped")

    @property
    def discovery(self) -> PeerDiscovery:
        """Access the underlying PeerDiscovery thread."""
        return self._discovery
