"""Single composition root for core services used by CLI and Textual hosts."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from mesh_pulse.core.discovery import PeerManager, UDPBroadcaster
from mesh_pulse.core.events import TransferEvent
from mesh_pulse.core.history import TransferHistoryStore
from mesh_pulse.core.identity import DeviceIdentity
from mesh_pulse.core.monitor import SystemMonitor
from mesh_pulse.core.transfer import SecureTransfer
from mesh_pulse.core.transfer_models import TransferInfo
from mesh_pulse.core.trust import TrustStore
from mesh_pulse.utils.config import (
    BROADCAST_PORT,
    RECEIVE_DIR,
    TRANSFER_PORT,
)


@dataclass(frozen=True)
class ApplicationServices:
    identity: DeviceIdentity
    trust_store: TrustStore
    history_store: TransferHistoryStore
    peer_manager: PeerManager
    monitor: SystemMonitor
    broadcaster: UDPBroadcaster
    transfer: SecureTransfer
    legacy_mode: bool


def build_services(
    *,
    passphrase: str | None = None,
    broadcast_port: int = BROADCAST_PORT,
    transfer_port: int = TRANSFER_PORT,
    identity_directory: str | Path | None = None,
    receive_dir: str | Path = RECEIVE_DIR,
    on_file_received: Callable[[TransferInfo], None] | None = None,
    on_event: Callable[[TransferEvent], None] | None = None,
) -> ApplicationServices:
    """Construct one coherent set of long-lived application services."""
    legacy_mode = passphrase is not None
    identity = DeviceIdentity.load_or_create(identity_directory)
    trust_store = TrustStore(identity.directory / "trusted_devices.json")
    history_store = TransferHistoryStore(identity.directory / "history.db")
    peer_manager = PeerManager(trust_store=trust_store)
    monitor = SystemMonitor()
    broadcaster = UDPBroadcaster(
        peer_manager=peer_manager,
        broadcast_port=broadcast_port,
        transfer_port=transfer_port,
        local_metrics_fn=lambda: monitor.latest.to_broadcast_dict(),
        identity=identity,
        transfer_protocol=2 if legacy_mode else 3,
    )
    transfer = SecureTransfer(
        passphrase=passphrase or "",
        transfer_port=transfer_port,
        receive_dir=str(receive_dir),
        on_file_received=on_file_received,
        on_event=on_event,
        history_store=history_store,
        identity=identity,
        trust_store=trust_store,
        peer_resolver=peer_manager.get_peer,
        legacy_mode=legacy_mode,
    )
    return ApplicationServices(
        identity,
        trust_store,
        history_store,
        peer_manager,
        monitor,
        broadcaster,
        transfer,
        legacy_mode,
    )
