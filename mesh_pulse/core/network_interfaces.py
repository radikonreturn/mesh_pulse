"""Cross-platform selection of useful LAN IPv4 broadcast interfaces."""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass

import psutil

from mesh_pulse.utils.config import BROADCAST_ADDR


@dataclass(frozen=True)
class LanInterface:
    name: str
    address: str
    broadcast: str | None


def lan_ipv4_interfaces() -> list[LanInterface]:
    """Return up, non-loopback IPv4 interfaces, deduplicated by address."""
    addresses = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    found: dict[str, LanInterface] = {}
    for name, entries in addresses.items():
        state = stats.get(name)
        if state is not None and not state.isup:
            continue
        for entry in entries:
            if entry.family != socket.AF_INET:
                continue
            try:
                address = ipaddress.ip_address(entry.address)
            except ValueError:
                continue
            if address.is_loopback or address.is_link_local or address.is_unspecified:
                continue
            found.setdefault(
                entry.address,
                LanInterface(name, entry.address, entry.broadcast or None),
            )
    return sorted(found.values(), key=lambda item: (item.name, item.address))


def discovery_broadcast_targets() -> tuple[str, ...]:
    """Return bounded directed broadcasts with a global fallback."""
    targets = {
        interface.broadcast
        for interface in lan_ipv4_interfaces()
        if interface.broadcast
    }
    return tuple(sorted(targets)) or (BROADCAST_ADDR,)
