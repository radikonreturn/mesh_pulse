"""Mesh-Pulse configuration and local device identity."""

from __future__ import annotations

from typing import ClassVar

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, Input, Label, Static

from mesh_pulse.core.identity import DeviceIdentity
from mesh_pulse.utils.config import (
    BROADCAST_PORT,
    RECEIVE_DIR,
    TRANSFER_PORT,
    load_user_config,
    save_user_config,
)


class SettingsScreen(Screen):
    """Configuration screen with local cryptographic identity."""

    TITLE = "Settings"
    SUB_TITLE = "Mesh-Pulse configuration"

    BINDINGS: ClassVar[list[Binding]] = [
        Binding(
            "escape",
            "go_back",
            "Back",
            priority=True,
        ),
        Binding(
            "ctrl+s",
            "save",
            "Save",
        ),
    ]

    DEFAULT_CSS = """
    SettingsScreen {
        background: $surface;
        padding: 1 3;
        overflow-y: auto;
    }

    #settings-title {
        width: 100%;
        height: 2;
        text-style: bold;
        color: $text;
    }

    #settings-subtitle {
        width: 100%;
        color: $text-muted;
        margin-bottom: 1;
    }

    #identity-panel {
        width: 100%;
        height: auto;
        background: $surface-darken-1;
        border: solid $panel;
        padding: 1 2;
        margin-bottom: 1;
    }

    .section-title {
        color: $text;
        text-style: bold;
        margin-bottom: 1;
    }

    .identity-label {
        color: $text-muted;
    }

    .identity-value {
        color: $text;
        text-style: bold;
        margin-bottom: 1;
    }

    #security-mode {
        color: $success;
    }

    #security-mode.legacy {
        color: $warning;
    }

    .field-group {
        width: 100%;
        margin: 1 0;
    }

    .field-label {
        color: $text;
        text-style: bold;
    }

    .field-hint {
        color: $text-muted;
    }

    .field-input {
        width: 100%;
        background: $surface-darken-1;
        border: tall $panel;
        color: $text;
    }

    .field-input:focus {
        border: tall $accent;
    }

    #btn-row {
        width: 100%;
        height: 3;
        align: left middle;
        margin-top: 1;
    }

    #btn-row Button {
        margin-right: 1;
    }

    #status-bar {
        width: 100%;
        height: 2;
        color: $text-muted;
    }
    """

    def __init__(
        self,
        identity: DeviceIdentity,
        legacy_mode: bool = False,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self._identity = identity
        self._legacy_mode = legacy_mode

    def compose(self) -> ComposeResult:
        cfg = load_user_config()

        yield Static(
            "Mesh-Pulse settings",
            id="settings-title",
        )

        yield Static(
            "Configuration changes apply on the next launch.",
            id="settings-subtitle",
        )

        with Vertical(id="identity-panel"):
            yield Static(
                "LOCAL IDENTITY",
                classes="section-title",
            )

            yield Static(
                "Device ID",
                classes="identity-label",
            )
            yield Static(
                self._identity.device_id,
                classes="identity-value",
            )

            yield Static(
                "Fingerprint",
                classes="identity-label",
            )
            yield Static(
                self._identity.fingerprint,
                classes="identity-value",
            )

            yield Static(
                "Transfer security",
                classes="identity-label",
            )

            security = Static(
                (
                    "Legacy protocol v2 · shared passphrase"
                    if self._legacy_mode
                    else "Authenticated protocol v3 · trusted devices"
                ),
                id="security-mode",
            )

            if self._legacy_mode:
                security.add_class("legacy")

            yield security

        with Vertical(classes="field-group"):
            yield Label(
                "Broadcast port",
                classes="field-label",
            )
            yield Label(
                (
                    f"UDP discovery · default {BROADCAST_PORT} · "
                    "MESH_PULSE_BCAST_PORT overrides"
                ),
                classes="field-hint",
            )
            yield Input(
                value=str(
                    cfg.get(
                        "broadcast_port",
                        BROADCAST_PORT,
                    )
                ),
                id="bcast-port-input",
                classes="field-input",
            )

        with Vertical(classes="field-group"):
            yield Label(
                "Transfer port",
                classes="field-label",
            )
            yield Label(
                (
                    f"TCP transfer · default {TRANSFER_PORT} · "
                    "MESH_PULSE_XFER_PORT overrides"
                ),
                classes="field-hint",
            )
            yield Input(
                value=str(
                    cfg.get(
                        "transfer_port",
                        TRANSFER_PORT,
                    )
                ),
                id="xfer-port-input",
                classes="field-input",
            )

        with Vertical(classes="field-group"):
            yield Label(
                "Receive directory",
                classes="field-label",
            )
            yield Label(
                "Incoming file destination",
                classes="field-hint",
            )
            yield Input(
                value=cfg.get(
                    "receive_dir",
                    RECEIVE_DIR,
                ),
                id="recv-dir-input",
                classes="field-input",
            )

        with Horizontal(id="btn-row"):
            yield Button(
                "Save",
                variant="success",
                id="save-btn",
            )
            yield Button(
                "Reset defaults",
                id="reset-btn",
            )
            yield Button(
                "Back",
                id="back-btn",
            )

        yield Static("", id="status-bar")

    def on_button_pressed(
        self,
        event: Button.Pressed,
    ) -> None:
        if event.button.id == "save-btn":
            self.action_save()
        elif event.button.id == "reset-btn":
            self._reset_defaults()
        elif event.button.id == "back-btn":
            self.action_go_back()

    def action_save(self) -> None:
        errors: list[str] = []

        try:
            bcast_port = int(
                self.query_one(
                    "#bcast-port-input",
                    Input,
                ).value.strip()
            )

            if not 1024 <= bcast_port <= 65535:
                raise ValueError

        except ValueError:
            errors.append("Broadcast port must be 1024-65535")
            bcast_port = BROADCAST_PORT

        try:
            xfer_port = int(
                self.query_one(
                    "#xfer-port-input",
                    Input,
                ).value.strip()
            )

            if not 1024 <= xfer_port <= 65535:
                raise ValueError

        except ValueError:
            errors.append("Transfer port must be 1024-65535")
            xfer_port = TRANSFER_PORT

        recv_dir = self.query_one(
            "#recv-dir-input",
            Input,
        ).value.strip()

        if not recv_dir:
            errors.append("Receive directory cannot be empty")

        status = self.query_one(
            "#status-bar",
            Static,
        )

        if errors:
            status.update(" · ".join(errors))
            status.styles.color = "red"
            return

        save_user_config(
            {
                "broadcast_port": bcast_port,
                "transfer_port": xfer_port,
                "receive_dir": recv_dir,
            }
        )

        status.update("Settings saved · restart Mesh-Pulse to apply.")
        status.styles.color = "green"

    def _reset_defaults(self) -> None:
        save_user_config({})

        self.query_one(
            "#bcast-port-input",
            Input,
        ).value = str(BROADCAST_PORT)

        self.query_one(
            "#xfer-port-input",
            Input,
        ).value = str(TRANSFER_PORT)

        self.query_one(
            "#recv-dir-input",
            Input,
        ).value = RECEIVE_DIR

        self.query_one(
            "#status-bar",
            Static,
        ).update("Defaults restored")

    def action_go_back(self) -> None:
        self.app.pop_screen()
