"""Mesh-Pulse CLI entry point.

Usage:
    python -m mesh_pulse [OPTIONS]

Options:
    --key TEXT             Encryption key for file transfers
    --broadcast-port INT   UDP broadcast port (default: 37020)
    --transfer-port INT    TCP transfer port (default: 5000)
"""

import click

from mesh_pulse import __version__
from mesh_pulse.utils.config import BROADCAST_PORT, TRANSFER_PORT


@click.command()
@click.option(
    "--key",
    envvar="MESH_PULSE_KEY",
    help="Enable explicit legacy v2 transfers with this shared passphrase.",
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
@click.option(
    "--demo",
    is_flag=True,
    help="Run an isolated local showcase with mock peers and transfer data (no network traffic).",
)
@click.version_option(version=__version__, prog_name="mesh-pulse")
def main(
    key: str | None,
    broadcast_port: int,
    transfer_port: int,
    demo: bool = False,
) -> None:
    """Mesh-Pulse — local encrypted peer workspace."""
    from mesh_pulse.app import MeshPulseApp

    app = MeshPulseApp(
        passphrase=key,
        broadcast_port=broadcast_port,
        transfer_port=transfer_port,
        demo_mode=demo,
    )
    app.run()


if __name__ == "__main__":
    main()
