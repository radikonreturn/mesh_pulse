"""Explainable summaries derived from bounded local peer observations."""

from __future__ import annotations

import math
import statistics
from dataclasses import dataclass
from typing import TYPE_CHECKING

from mesh_pulse.core.trust import TrustStatus

if TYPE_CHECKING:
    from mesh_pulse.core.discovery import Peer


@dataclass(frozen=True)
class NetworkOverview:
    """Compact dashboard summary; absent measurements remain unknown."""

    online: int
    trusted_online: int
    untrusted: int
    unavailable: int
    active_transfers: int = 0
    median_latency_ms: float | None = None


def peer_health(peer: Peer) -> str:
    """Return an explainable quality label based on visible observations."""
    status = getattr(peer.status, "value", peer.status)
    if status == "offline":
        return "Offline"
    if status == "stale":
        return "Unstable"
    latency = peer.latency_ms
    if peer.connection_failures > peer.successful_transfers + 1:
        return "Unstable"
    if latency is not None and latency > 100:
        return "Unstable"
    if latency is not None and latency <= 10 and peer.connection_failures == 0:
        return "Excellent"
    return "Good"


def summarize_network(
    peers: list[Peer], *, active_transfers: int = 0
) -> NetworkOverview:
    """Summarize peer availability without manufacturing missing latency data."""
    online = [peer for peer in peers if peer.status.value == "online"]
    latencies = [
        peer.latency_ms
        for peer in online
        if peer.latency_ms is not None
        and math.isfinite(peer.latency_ms)
        and peer.latency_ms >= 0
    ]
    return NetworkOverview(
        online=len(online),
        trusted_online=sum(peer.trust_status == TrustStatus.TRUSTED for peer in online),
        untrusted=sum(peer.trust_status != TrustStatus.TRUSTED for peer in peers),
        unavailable=len(peers) - len(online),
        active_transfers=max(0, active_transfers),
        median_latency_ms=(statistics.median(latencies) if latencies else None),
    )
