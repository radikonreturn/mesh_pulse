"""Mesh-Pulse CLI entry point.

Usage:
    python -m mesh_pulse [OPTIONS]

Options:
    --key TEXT             Encryption key for file transfers
    --broadcast-port INT   UDP broadcast port (default: 9999)
    --transfer-port INT    TCP transfer port (default: 10000)
"""

import click

from mesh_pulse import __version__
from mesh_pulse.utils.config import BROADCAST_PORT, DEFAULT_KEY, TRANSFER_PORT


@click.command()
@click.option(
    "--key",
    default=DEFAULT_KEY,
    envvar="MESH_PULSE_KEY",
    help="Encryption passphrase for file transfers.",
)
@click.option(
    "--broadcast-port",
    default=BROADCAST_PORT,
    type=int,
    help=f"UDP broadcast port (default: {BROADCAST_PORT}).",
)
@click.option(
    "--transfer-port",
    default=TRANSFER_PORT,
    type=int,
    help=f"TCP transfer port (default: {TRANSFER_PORT}).",
)
@click.version_option(version=__version__, prog_name="mesh-pulse")
def main(key: str, broadcast_port: int, transfer_port: int) -> None:
    """⚡ Mesh-Pulse — Network Mesh & System Resource Monitor."""
    from mesh_pulse.app import MeshPulseApp

    app = MeshPulseApp(
        passphrase=key,
        broadcast_port=broadcast_port,
        transfer_port=transfer_port,
    )
    app.run()


if __name__ == "__main__":
    main()
