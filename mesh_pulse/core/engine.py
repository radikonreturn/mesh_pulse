"""Engine integration — start all Mesh-Pulse subsystems safely.

Provides start_engine() / stop_engine() helpers for non-blocking startup
from any main.py entry point. All threads are daemon threads so they
will not prevent the main process from exiting.

Usage from a main.py:
    from mesh_pulse.core.engine import start_engine, stop_engine

    engine = start_engine()
    # ... your main loop or TUI ...
    stop_engine(engine)

Or use the context manager:
    from mesh_pulse.core.engine import MeshEngine

    with MeshEngine() as engine:
        print(engine.discovery.peers)
        print(engine.monitor.latest)
"""

from __future__ import annotations

from dataclasses import dataclass

from mesh_pulse.core.discovery import PeerDiscovery, PeerManager
from mesh_pulse.core.monitor import SystemMonitor, get_system_metrics
from mesh_pulse.core.transfer import FileClient, FileServer
from mesh_pulse.utils.config import BROADCAST_PORT, TRANSFER_PORT
from mesh_pulse.utils.logger import get_logger

log = get_logger(__name__)


@dataclass
class EngineHandles:
    """Handles to all running subsystem threads."""
    discovery: PeerDiscovery
    peer_manager: PeerManager
    file_server: FileServer
    file_client: FileClient
    monitor: SystemMonitor


def start_engine(
    broadcast_port: int = BROADCAST_PORT,
    transfer_port: int = TRANSFER_PORT,
) -> EngineHandles:
    """Start all Mesh-Pulse subsystems without blocking the main thread.

    Starts:
        1. PeerDiscovery — UDP broadcast + listen on port 37020
        2. FileServer — TCP receiver on port 5000
        3. SystemMonitor — psutil sampling every 2s

    All threads are daemon threads and will exit when the main process exits.

    Args:
        broadcast_port: UDP discovery port (default 37020).
        transfer_port: TCP transfer port (default 5000).

    Returns:
        EngineHandles with references to all running subsystems.
    """
    peer_manager = PeerManager()
    monitor = SystemMonitor()

    discovery = PeerDiscovery(
        port=broadcast_port,
        transfer_port=transfer_port,
        local_metrics_fn=lambda: monitor.latest.to_broadcast_dict(),
        peer_manager=peer_manager,
    )

    file_server = FileServer(port=transfer_port)
    file_client = FileClient(port=transfer_port)

    # Start all threads (all are daemon=True, non-blocking)
    monitor.start()
    log.info("System monitor active")

    discovery.start()
    log.info("PeerDiscovery broadcasting on port %d", broadcast_port)

    file_server.start()
    log.info("FileServer listening on port %d", transfer_port)

    log.info("All engine subsystems started")

    return EngineHandles(
        discovery=discovery,
        peer_manager=peer_manager,
        file_server=file_server,
        file_client=file_client,
        monitor=monitor,
    )


def stop_engine(handles: EngineHandles) -> None:
    """Gracefully stop all subsystems.

    Args:
        handles: EngineHandles returned by start_engine().
    """
    handles.discovery.shutdown()
    handles.file_server.shutdown()
    handles.monitor.stop()
    log.info("All engine subsystems stopped")


class MeshEngine:
    """Context manager for the full Mesh-Pulse engine.

    Usage:
        with MeshEngine() as engine:
            print(engine.discovery.peers)
            engine.file_client.send("192.168.1.10", "/path/to/file.txt")
    """

    def __init__(
        self,
        broadcast_port: int = BROADCAST_PORT,
        transfer_port: int = TRANSFER_PORT,
    ):
        self._bcast_port = broadcast_port
        self._xfer_port = transfer_port
        self._handles: EngineHandles | None = None

    def __enter__(self) -> EngineHandles:
        self._handles = start_engine(self._bcast_port, self._xfer_port)
        return self._handles

    def __exit__(self, *exc) -> None:
        if self._handles:
            stop_engine(self._handles)
