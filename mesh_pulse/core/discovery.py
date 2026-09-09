"""P2P discovery via UDP broadcast with heartbeat-based peer management.

Architecture:
    - PeerDiscovery(Thread): single-threaded broadcaster + listener on UDP 37020
    - PeerManager: thread-safe registry of discovered peers (used by TUI widgets)
    - LatencyProber: background TCP-connect latency measurement per peer
    - UDPBroadcaster: facade wrapping PeerDiscovery (used by app.py)

Peers auto-transition: ONLINE → STALE → removed, based on heartbeat age.
"""

from __future__ import annotations

import base64
import json
import math
import re
import socket
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum

from cryptography.exceptions import InvalidSignature

from mesh_pulse.core.identity import (
    DeviceIdentity,
    decode_public_key,
    device_id_from_public_key,
    fingerprint_from_public_key,
)
from mesh_pulse.core.trust import TrustStatus, TrustStore
from mesh_pulse.utils.config import (
    BROADCAST_ADDR,
    BROADCAST_INTERVAL,
    BROADCAST_PORT,
    HOSTNAME,
    LATENCY_PROBE_INTERVAL,
    LOCAL_IP,
    PEER_DEAD_TIMEOUT,
    PEER_STALE_TIMEOUT,
    PEER_TIMEOUT,
    TRANSFER_PORT,
)
from mesh_pulse.utils.logger import get_logger

log = get_logger(__name__)

DISCOVERY_PROTOCOL = 3
MAX_BEACON_SIZE = 4096
MAX_HOSTNAME_LENGTH = 255
_DEVICE_ID_PATTERN = re.compile(r"^mp-[0-9a-f]{8}$")
_METRIC_FIELDS = {
    "cpu_percent",
    "ram_percent",
    "disk_read_bytes",
    "disk_write_bytes",
    "net_sent_bytes",
    "net_recv_bytes",
}
_DISCOVERY_DOMAIN = b"mesh-pulse-discovery-v3\x00"
SUPPORTED_TRANSFER_PROTOCOLS = {2, 3}


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
    latency_ms: float | None = None  # None = not yet measured
    device_id: str | None = None
    public_key: str | None = None
    fingerprint: str | None = None
    trust_status: TrustStatus = TrustStatus.NEW
    protocol_version: int = 2

    @property
    def stable_id(self) -> str:
        """Stable UI/registry key, falling back to IP for legacy peers."""
        return self.device_id or self.ip

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
            "latency_ms": round(self.latency_ms, 1)
            if self.latency_ms is not None
            else None,
            "device_id": self.device_id,
            "fingerprint": self.fingerprint,
            "trust_status": self.trust_status.value,
            "protocol_version": self.protocol_version,
        }


def _validated_metrics(metrics: object) -> dict:
    """Return only finite, bounded metric fields from a remote beacon."""
    if not isinstance(metrics, dict):
        return {}
    clean: dict[str, float | int] = {}
    for name in _METRIC_FIELDS:
        value = metrics.get(name)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            continue
        if not math.isfinite(float(value)):
            continue
        if name in {"cpu_percent", "ram_percent"}:
            clean[name] = max(0.0, min(100.0, float(value)))
        elif value >= 0:
            clean[name] = min(int(value), 2**63 - 1)
    return clean


def _canonical_discovery_payload(payload: dict) -> bytes:
    """Canonical JSON representation used by discovery signatures."""
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _discovery_signed_bytes(payload: dict) -> bytes:
    """Return the exact bytes covered by an identity signature."""
    unsigned = {key: value for key, value in payload.items() if key != "signature"}
    return _DISCOVERY_DOMAIN + _canonical_discovery_payload(unsigned)


def _verify_discovery_signature(
    payload: dict,
    public_key: str,
) -> bool:
    """Verify a protocol-v3 UDP discovery advertisement."""
    signature_text = payload.get("signature")

    if not isinstance(signature_text, str) or len(signature_text) > 128:
        return False

    try:
        signature = base64.b64decode(
            signature_text,
            validate=True,
        )
    except (ValueError, base64.binascii.Error):
        return False

    if len(signature) != 64:
        return False

    try:
        key = decode_public_key(public_key)
        key.verify(
            signature,
            _discovery_signed_bytes(payload),
        )
    except (ValueError, InvalidSignature):
        return False

    return True


def build_discovery_beacon(
    identity: DeviceIdentity | None,
    *,
    hostname: str = HOSTNAME,
    advertised_ip: str = LOCAL_IP,
    port: int = TRANSFER_PORT,
    metrics: dict | None = None,
    transfer_protocol: int = 3,
    timestamp: float | None = None,
) -> bytes:
    """Create a validated discovery beacon.

    Discovery schema v3 is independent from the file-transfer protocol.
    A signed identity can therefore advertise transfer protocol v2 or v3
    without lying about the discovery schema.
    """

    if transfer_protocol not in SUPPORTED_TRANSFER_PROTOCOLS:
        raise ValueError("Unsupported transfer protocol")

    if identity is None:
        # Old anonymous discovery remains protocol 2.
        payload: dict = {
            "protocol": 2,
            "hostname": hostname,
            "ip": advertised_ip,
            "port": port,
            "timestamp": timestamp or time.time(),
        }
    else:
        payload = {
            "protocol": DISCOVERY_PROTOCOL,
            "transfer_protocol": transfer_protocol,
            "hostname": hostname,
            "ip": advertised_ip,
            "port": port,
            "timestamp": timestamp or time.time(),
            "device_id": identity.device_id,
            "public_key": identity.public_key,
        }

    if metrics:
        payload["metrics"] = metrics

    if identity is not None:
        signature = identity.sign(_discovery_signed_bytes(payload))
        payload["signature"] = base64.b64encode(signature).decode("ascii")

    encoded = _canonical_discovery_payload(payload)

    if len(encoded) > MAX_BEACON_SIZE:
        raise ValueError("Discovery beacon exceeds size limit")

    return encoded


def parse_discovery_beacon(
    data: bytes,
    source_ip: str,
    default_port: int = TRANSFER_PORT,
) -> dict | None:
    """Validate an incoming discovery advertisement.

    The UDP packet source remains authoritative for the network address.
    Protocol-v3 identity advertisements must have a valid Ed25519
    signature and a device ID derived from their public key.
    """

    if not data or len(data) > MAX_BEACON_SIZE:
        return None

    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None

    if not isinstance(payload, dict):
        return None

    hostname = payload.get("hostname", "unknown")

    if (
        not isinstance(hostname, str)
        or not hostname.strip()
        or len(hostname) > MAX_HOSTNAME_LENGTH
        or not hostname.isprintable()
    ):
        return None

    port = payload.get("port", default_port)

    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        return None

    protocol = payload.get("protocol", 2)

    if isinstance(protocol, bool) or not isinstance(protocol, int):
        return None

    timestamp = payload.get("timestamp", time.time())

    if (
        isinstance(timestamp, bool)
        or not isinstance(timestamp, (int, float))
        or not math.isfinite(float(timestamp))
    ):
        return None

    try:
        socket.inet_pton(socket.AF_INET, source_ip)
    except OSError:
        return None

    device_id: str | None = None
    public_key: str | None = None
    fingerprint: str | None = None

    # This field represents FILE TRANSFER protocol,
    # not discovery schema.
    transfer_protocol = 2

    if protocol == DISCOVERY_PROTOCOL:
        device_id = payload.get("device_id")
        public_key = payload.get("public_key")

        if (
            not isinstance(device_id, str)
            or not _DEVICE_ID_PATTERN.fullmatch(device_id)
            or not isinstance(public_key, str)
        ):
            return None

        try:
            decode_public_key(public_key)
        except ValueError:
            return None

        # Cryptographically bind ID -> public key.
        if device_id_from_public_key(public_key) != device_id:
            return None

        # A v3 identity advertisement without a valid signature
        # must never reach PeerManager / TRUSTED UI state.
        if not _verify_discovery_signature(
            payload,
            public_key,
        ):
            return None

        transfer_protocol = payload.get(
            "transfer_protocol",
            3,
        )

        if (
            isinstance(transfer_protocol, bool)
            or not isinstance(transfer_protocol, int)
            or transfer_protocol not in SUPPORTED_TRANSFER_PROTOCOLS
        ):
            return None

        fingerprint = fingerprint_from_public_key(public_key)

    elif protocol == 2:
        # Backward-compatible anonymous/legacy peer.
        transfer_protocol = 2

    else:
        return None

    return {
        "hostname": hostname.strip(),
        # Packet source is authoritative.
        "ip": source_ip,
        "port": port,
        "metrics": _validated_metrics(payload.get("metrics")),
        "device_id": device_id,
        "public_key": public_key,
        "fingerprint": fingerprint,
        "protocol_version": transfer_protocol,
    }


# ─── Latency Prober ────────────────────────────────────────────────


class LatencyProber(threading.Thread):
    """Background thread that measures real TCP round-trip latency to each peer.

    For each known peer, attempts a TCP connect to the peer's transfer port and
    records the wall-clock time.  Results are stored back on the Peer object.

    Probes run every LATENCY_PROBE_INTERVAL seconds (default 5s).
    """

    def __init__(self, peer_manager: PeerManager):
        super().__init__(daemon=True, name="latency-prober")
        self._pm = peer_manager
        self._running = threading.Event()
        self._running.set()

    def run(self) -> None:
        while self._running.is_set():
            self._probe_all()
            self._running.wait(LATENCY_PROBE_INTERVAL)

    def shutdown(self) -> None:
        self._running.clear()

    def _probe_all(self) -> None:
        for peer in self._pm.get_peers():
            if peer.status != PeerStatus.ONLINE:
                continue
            ms = self._tcp_ping(peer.ip, peer.port)
            self._pm.update_latency(peer.stable_id, ms)

    @staticmethod
    def _tcp_ping(ip: str, port: int, timeout: float = 2.0) -> float | None:
        """Attempt a TCP connect and return round-trip time in ms, or None."""
        try:
            start = time.perf_counter()
            with socket.create_connection((ip, port), timeout=timeout):
                pass
            return (time.perf_counter() - start) * 1000.0
        except (OSError, TimeoutError):
            return None


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
        trust_store: TrustStore | None = None,
    ):
        self._peers: dict[str, Peer] = {}
        self._lock = threading.Lock()
        self._stale_timeout = stale_timeout
        self._dead_timeout = dead_timeout
        self._on_peer_change = on_peer_change
        self._trust_store = trust_store

    def update_peer(
        self,
        hostname: str,
        ip: str,
        port: int,
        metrics: dict | None = None,
        device_id: str | None = None,
        public_key: str | None = None,
        fingerprint: str | None = None,
        protocol_version: int = 2,
    ) -> None:
        """Register or refresh a peer from a received beacon.

        Args:
            hostname: Peer's hostname.
            ip: Peer's IP address.
            port: Peer's transfer port.
            metrics: Optional metrics dict from the beacon.
        """
        clean_metrics = _validated_metrics(metrics)
        trust_status = (
            self._trust_store.assess(device_id, public_key)
            if self._trust_store
            else TrustStatus.NEW
        )
        with self._lock:
            existing_key = ip
            if device_id:
                existing_key = next(
                    (
                        key
                        for key, candidate in self._peers.items()
                        if candidate.device_id == device_id
                    ),
                    ip,
                )
            if existing_key in self._peers:
                peer = self._peers[existing_key]
                peer.last_seen = time.time()
                peer.status = PeerStatus.ONLINE
                peer.hostname = hostname
                peer.ip = ip
                peer.port = port
                peer.device_id = device_id
                peer.public_key = public_key
                peer.fingerprint = fingerprint
                peer.trust_status = trust_status
                peer.protocol_version = protocol_version
                if clean_metrics:
                    peer.metrics = PeerMetrics(**clean_metrics)
                if existing_key != ip:
                    del self._peers[existing_key]
                    self._peers[ip] = peer
            else:
                peer = Peer(
                    hostname=hostname,
                    ip=ip,
                    port=port,
                    device_id=device_id,
                    public_key=public_key,
                    fingerprint=fingerprint,
                    trust_status=trust_status,
                    protocol_version=protocol_version,
                )
                if clean_metrics:
                    peer.metrics = PeerMetrics(**clean_metrics)
                self._peers[ip] = peer
                log.info("Discovered new peer: %s (%s)", hostname, ip)

        if self._trust_store and device_id and trust_status != TrustStatus.CHANGED:
            self._trust_store.update_last_seen(device_id, peer.last_seen)

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
        """Look up a single peer by stable identifier or current IP."""
        with self._lock:
            peer = self._peers.get(ip)
            if peer is not None:
                return peer
            return next(
                (
                    candidate
                    for candidate in self._peers.values()
                    if candidate.stable_id == ip
                ),
                None,
            )

    def remove_peer(self, identifier: str) -> Peer | None:
        """Remove a peer by stable identifier or IP and return it."""
        with self._lock:
            key = next(
                (
                    peer_ip
                    for peer_ip, peer in self._peers.items()
                    if peer_ip == identifier or peer.stable_id == identifier
                ),
                None,
            )
            removed = self._peers.pop(key, None) if key is not None else None
        if removed is not None and self._on_peer_change:
            self._on_peer_change()
        return removed

    def update_latency(self, identifier: str, latency_ms: float | None) -> None:
        """Safely update latency without exposing registry internals."""
        with self._lock:
            peer = next(
                (
                    candidate
                    for key, candidate in self._peers.items()
                    if key == identifier or candidate.stable_id == identifier
                ),
                None,
            )
            if peer is not None:
                peer.latency_ms = latency_ms

    def refresh_trust(self, identifier: str) -> TrustStatus | None:
        """Re-assess a peer after an explicit local trust-store change."""
        with self._lock:
            peer = next(
                (
                    candidate
                    for key, candidate in self._peers.items()
                    if key == identifier or candidate.stable_id == identifier
                ),
                None,
            )
            if peer is None:
                return None
            peer.trust_status = (
                self._trust_store.assess(peer.device_id, peer.public_key)
                if self._trust_store
                else TrustStatus.NEW
            )
            return peer.trust_status

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._peers)


# ─── PeerDiscovery Thread ──────────────────────────────────────────


class PeerDiscovery(threading.Thread):
    """Single-threaded UDP peer discovery.

    Acts as both a Broadcaster (sends JSON heartbeats every 2s) and a
    Listener (binds to UDP port 37020).  Discovered peers are stored in
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
        identity: DeviceIdentity | None = None,
        transfer_protocol: int = 3,
    ):
        super().__init__(daemon=True, name="peer-discovery")
        self._port = port
        self._transfer_port = transfer_port
        self._interval = interval
        self._peer_timeout = peer_timeout
        self._local_metrics_fn = local_metrics_fn
        self._pm = peer_manager
        self._identity = identity

        if transfer_protocol not in SUPPORTED_TRANSFER_PROTOCOLS:
            raise ValueError(f"Unsupported transfer protocol: {transfer_protocol}")

        self._transfer_protocol = transfer_protocol
        self._running = threading.Event()
        self._running.set()

        # Shared dict: {IP: LastSeenTimestamp}
        self.peers: dict[str, float] = {}
        self._peers_lock = threading.Lock()

        # Start latency prober if a PeerManager is provided
        self._prober: LatencyProber | None = None
        if peer_manager:
            self._prober = LatencyProber(peer_manager)

    def run(self) -> None:
        """Main thread loop: broadcast, listen, and sweep concurrently."""
        if self._prober:
            self._prober.start()

        listener = threading.Thread(
            target=self._listen_loop, daemon=True, name="udp-listen"
        )
        listener.start()

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(1.0)

        while self._running.is_set():
            try:
                beacon = self._build_beacon()
                sock.sendto(beacon, (BROADCAST_ADDR, self._port))
            except (OSError, ValueError) as e:
                log.debug("Broadcast send error: %s", e)

            self._sweep_peers()
            self._running.wait(self._interval)

        sock.close()
        log.info("PeerDiscovery stopped")

    def shutdown(self) -> None:
        """Signal the discovery thread to stop."""
        self._running.clear()
        if self._prober:
            self._prober.shutdown()

    def get_active_peers(self) -> dict[str, float]:
        """Return a copy of the active peers dict."""
        with self._peers_lock:
            return dict(self.peers)

    # ── Internal ────────────────────────────────────────────────

    def _build_beacon(self) -> bytes:
        """Build a signed discovery heartbeat."""

        metrics = None

        if self._local_metrics_fn:
            try:
                metrics = self._local_metrics_fn()
            except (
                AttributeError,
                RuntimeError,
                TypeError,
                ValueError,
            ) as error:
                log.debug(
                    "Unable to collect beacon metrics: %s",
                    error,
                )

        return build_discovery_beacon(
            self._identity,
            hostname=HOSTNAME,
            advertised_ip=LOCAL_IP,
            port=self._transfer_port,
            metrics=metrics,
            transfer_protocol=self._transfer_protocol,
        )

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
                data, addr = sock.recvfrom(MAX_BEACON_SIZE + 1)
                beacon = parse_discovery_beacon(data, addr[0], self._transfer_port)
                if beacon is None:
                    continue
                if self._identity and beacon["device_id"] == self._identity.device_id:
                    continue
                if not self._identity and addr[0] == LOCAL_IP:
                    continue

                peer_ip = beacon["ip"]

                with self._peers_lock:
                    self.peers[peer_ip] = time.time()

                if self._pm:
                    self._pm.update_peer(
                        hostname=beacon.get("hostname", "unknown"),
                        ip=peer_ip,
                        port=beacon.get("port", self._transfer_port),
                        metrics=beacon.get("metrics"),
                        device_id=beacon.get("device_id"),
                        public_key=beacon.get("public_key"),
                        fingerprint=beacon.get("fingerprint"),
                        protocol_version=beacon.get("protocol_version", 2),
                    )

            except TimeoutError:
                continue
            except OSError as e:
                log.debug("Listen error: %s", e)

        sock.close()

    def _sweep_peers(self) -> None:
        """Remove peers not seen within PEER_TIMEOUT seconds."""
        now = time.time()
        with self._peers_lock:
            dead = [
                ip for ip, ts in self.peers.items() if now - ts > self._peer_timeout
            ]
            for ip in dead:
                del self.peers[ip]
                log.info("Peer auto-removed (timeout): %s", ip)

        if self._pm:
            self._pm.sweep()


# ─── UDPBroadcaster (facade for app.py) ─────────────────────────


class UDPBroadcaster:
    """Facade wrapping PeerDiscovery for backwards compatibility.

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
        identity: DeviceIdentity | None = None,
        transfer_protocol: int = 3,
    ):
        self._discovery = PeerDiscovery(
            port=broadcast_port,
            transfer_port=transfer_port,
            interval=interval,
            local_metrics_fn=local_metrics_fn,
            peer_manager=peer_manager,
            identity=identity,
            transfer_protocol=transfer_protocol,
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
