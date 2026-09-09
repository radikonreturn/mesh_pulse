"""Fingerprint confirmation modal for explicit device trust."""

from __future__ import annotations

from typing import ClassVar

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Static

from mesh_pulse.core.discovery import Peer
from mesh_pulse.core.trust import TrustedDevice


class PairingModal(ModalScreen[bool]):
    """Ask the user to compare and explicitly trust a device fingerprint."""

    BINDINGS: ClassVar[list[Binding]] = [
        Binding("t", "trust", "Trust"),
        Binding("escape", "cancel", "Cancel", priority=True),
    ]

    DEFAULT_CSS = """
    PairingModal {
        align: center middle;
        background: rgba(0, 0, 0, 0.75);
    }

    PairingModal #pairing-box {
        width: 70%;
        max-width: 64;
        min-width: 40;
        height: auto;
        background: $surface;
        border: solid $accent;
        padding: 1 2;
    }

    PairingModal #pairing-title {
        height: 2;
        text-style: bold;
    }

    PairingModal .pairing-label {
        color: $text-muted;
        margin-top: 1;
    }

    PairingModal #pairing-fingerprint,
    PairingModal #pairing-old-fingerprint {
        text-style: bold;
        color: $text;
    }

    PairingModal #pairing-warning {
        color: $warning;
        margin-top: 1;
    }

    PairingModal #pairing-buttons {
        height: 3;
        align: right middle;
        margin-top: 1;
    }

    PairingModal Button {
        margin-left: 1;
    }
    """

    def __init__(
        self,
        peer: Peer,
        previous_identity: TrustedDevice | None = None,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self._peer = peer
        self._previous = previous_identity

    def compose(self) -> ComposeResult:
        verifiable = bool(
            self._peer.device_id and self._peer.public_key and self._peer.fingerprint
        )
        title = "Re-establish trust?" if self._previous else "Trust this device?"
        with Vertical(id="pairing-box"):
            yield Static(title, id="pairing-title")
            yield Static("Hostname", classes="pairing-label")
            yield Static(self._peer.hostname)
            yield Static("IP", classes="pairing-label")
            yield Static(self._peer.ip)
            yield Static("Fingerprint", classes="pairing-label")
            yield Static(
                self._peer.fingerprint or "Unavailable", id="pairing-fingerprint"
            )
            if self._previous:
                yield Static("Previously trusted fingerprint", classes="pairing-label")
                yield Static(self._previous.fingerprint, id="pairing-old-fingerprint")
                yield Static(
                    "Identity changed. Verify the new fingerprint on the other "
                    "device before replacing trust.",
                    id="pairing-warning",
                )
            elif verifiable:
                yield Static(
                    "Compare this fingerprint on the other device before trusting.",
                    id="pairing-warning",
                )
            else:
                yield Static(
                    "This legacy peer has no verifiable device identity.",
                    id="pairing-warning",
                )
            with Horizontal(id="pairing-buttons"):
                yield Button(
                    "Trust",
                    variant="success",
                    id="pairing-trust",
                    disabled=not verifiable,
                )
                yield Button("Cancel", id="pairing-cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "pairing-trust":
            self.action_trust()
        elif event.button.id == "pairing-cancel":
            self.action_cancel()

    def action_trust(self) -> None:
        if self._peer.device_id and self._peer.public_key:
            self.dismiss(True)

    def action_cancel(self) -> None:
        self.dismiss(False)
