"""In-TUI Settings screen — configure ports, encryption key, and receive directory.

Keybind: [G] from the main dashboard opens this screen.
Changes are saved to ~/.mesh_pulse_config.json and take effect on next launch.
"""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, Horizontal
from textual.screen import Screen
from textual.widgets import Button, Input, Label, Static

from mesh_pulse.utils.config import (
    BROADCAST_PORT,
    DEFAULT_KEY,
    RECEIVE_DIR,
    TRANSFER_PORT,
    load_user_config,
    save_user_config,
)


class SettingsScreen(Screen):
    """Settings screen — edit persistent configuration values.

    Fields:
        Encryption Key    — shared passphrase for AES-256-GCM transfers
        Broadcast Port    — UDP discovery port (default 37020)
        Transfer Port     — TCP file transfer port (default 5000)
        Receive Directory — where incoming files are saved
    """

    TITLE = "⚙ Settings"
    SUB_TITLE = "Changes saved to ~/.mesh_pulse_config.json"

    DEFAULT_CSS = """
    SettingsScreen {
        background: #0d1117;
        padding: 2 4;
    }

    #settings-title {
        width: 100%;
        text-align: center;
        text-style: bold;
        color: #58a6ff;
        padding: 0 0 1 0;
    }

    #settings-subtitle {
        width: 100%;
        text-align: center;
        color: #8b949e;
        padding: 0 0 2 0;
    }

    .field-group {
        width: 100%;
        margin: 1 0;
    }

    .field-label {
        color: #58a6ff;
        text-style: bold;
        margin: 0 0 0 0;
    }

    .field-hint {
        color: #484f58;
        margin: 0 0 0 1;
    }

    .field-input {
        width: 100%;
        background: #161b22;
        border: tall #30363d;
        color: #e6edf3;
        margin: 0;
    }

    .field-input:focus {
        border: tall #0ea5e9;
    }

    #divider {
        color: #30363d;
        margin: 1 0;
    }

    #btn-row {
        width: 100%;
        height: 3;
        align: center middle;
        margin-top: 2;
    }

    #save-btn {
        margin: 0 1;
        min-width: 18;
    }

    #reset-btn {
        margin: 0 1;
        min-width: 18;
    }

    #back-btn {
        margin: 0 1;
        min-width: 14;
    }

    #status-bar {
        width: 100%;
        text-align: center;
        color: #3fb950;
        height: 1;
        margin-top: 1;
    }
    """

    BINDINGS = [
        Binding("escape", "go_back", "Back", priority=True),
        Binding("ctrl+s", "save", "Save"),
    ]

    def compose(self) -> ComposeResult:
        cfg = load_user_config()

        yield Static("⚙  Mesh-Pulse Settings", id="settings-title")
        yield Static(
            "Changes are saved to ~/.mesh_pulse_config.json and apply on next launch",
            id="settings-subtitle",
        )

        # Encryption Key
        with Vertical(classes="field-group"):
            yield Label("🔑  Encryption Key", classes="field-label")
            yield Label(
                "Shared passphrase — both sender and receiver must use the same key",
                classes="field-hint",
            )
            yield Input(
                value=cfg.get("default_key", DEFAULT_KEY),
                placeholder="mesh-pulse-default-key",
                id="key-input",
                classes="field-input",
                password=False,
            )

        # Broadcast Port
        with Vertical(classes="field-group"):
            yield Label("📡  Broadcast Port (UDP Discovery)", classes="field-label")
            yield Label(
                f"Default: {BROADCAST_PORT}  ·  MESH_PULSE_BCAST_PORT env var overrides this",
                classes="field-hint",
            )
            yield Input(
                value=str(cfg.get("broadcast_port", BROADCAST_PORT)),
                placeholder=str(BROADCAST_PORT),
                id="bcast-port-input",
                classes="field-input",
            )

        # Transfer Port
        with Vertical(classes="field-group"):
            yield Label("🔌  Transfer Port (TCP File Transfer)", classes="field-label")
            yield Label(
                f"Default: {TRANSFER_PORT}  ·  MESH_PULSE_XFER_PORT env var overrides this",
                classes="field-hint",
            )
            yield Input(
                value=str(cfg.get("transfer_port", TRANSFER_PORT)),
                placeholder=str(TRANSFER_PORT),
                id="xfer-port-input",
                classes="field-input",
            )

        # Receive Directory
        with Vertical(classes="field-group"):
            yield Label("📁  Receive Directory", classes="field-label")
            yield Label(
                "Where incoming files are saved  ·  MESH_PULSE_RECEIVE_DIR env var overrides",
                classes="field-hint",
            )
            yield Input(
                value=cfg.get("receive_dir", RECEIVE_DIR),
                placeholder=RECEIVE_DIR,
                id="recv-dir-input",
                classes="field-input",
            )

        yield Static("", id="divider")

        with Horizontal(id="btn-row"):
            yield Button("💾 Save", variant="success", id="save-btn")
            yield Button("↺ Reset Defaults", variant="warning", id="reset-btn")
            yield Button("← Back", variant="error", id="back-btn")

        yield Static("", id="status-bar")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "save-btn":
            self.action_save()
        elif event.button.id == "reset-btn":
            self._reset_defaults()
        elif event.button.id == "back-btn":
            self.action_go_back()

    def action_save(self) -> None:
        """Validate inputs and persist to config file."""
        errors = []

        key_val = self.query_one("#key-input", Input).value.strip()
        if not key_val:
            errors.append("Encryption key cannot be empty")

        try:
            bcast_port = int(self.query_one("#bcast-port-input", Input).value.strip())
            if not (1024 <= bcast_port <= 65535):
                raise ValueError
        except ValueError:
            errors.append("Broadcast port must be 1024–65535")
            bcast_port = BROADCAST_PORT

        try:
            xfer_port = int(self.query_one("#xfer-port-input", Input).value.strip())
            if not (1024 <= xfer_port <= 65535):
                raise ValueError
        except ValueError:
            errors.append("Transfer port must be 1024–65535")
            xfer_port = TRANSFER_PORT

        recv_dir = self.query_one("#recv-dir-input", Input).value.strip()
        if not recv_dir:
            errors.append("Receive directory cannot be empty")

        status = self.query_one("#status-bar", Static)
        if errors:
            status.update("  ⚠  " + "  ·  ".join(errors))
            status.styles.color = "red"
            return

        save_user_config(
            {
                "default_key": key_val,
                "broadcast_port": bcast_port,
                "transfer_port": xfer_port,
                "receive_dir": recv_dir,
            }
        )
        status.update("  ✓  Settings saved — restart to apply port/directory changes")
        status.styles.color = "green"

    def _reset_defaults(self) -> None:
        """Clear the config file and reset inputs to built-in defaults."""
        save_user_config({})
        self.query_one("#key-input", Input).value = "mesh-pulse-default-key"
        self.query_one("#bcast-port-input", Input).value = str(BROADCAST_PORT)
        self.query_one("#xfer-port-input", Input).value = str(TRANSFER_PORT)
        self.query_one("#recv-dir-input", Input).value = RECEIVE_DIR
        self.query_one("#status-bar", Static).update("  ↺  Defaults restored")

    def action_go_back(self) -> None:
        self.app.pop_screen()
