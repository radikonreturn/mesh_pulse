"""Event log widget — scrollable streaming system event log."""

from __future__ import annotations

import os
import time
import threading
from collections import deque
from datetime import datetime
from pathlib import Path

from rich.console import Group
from rich.text import Text
from textual.widgets import Static

# Mirror file lives next to the working directory
_LOG_FILE = Path(os.getcwd()) / "panel_output.txt"


class EventLog:
    """Thread-safe event log buffer.

    Stores timestamped events that can be rendered by EventLogWidget.
    Can be shared across all subsystems to log events centrally.
    Every logged message is also mirrored to ``panel_output.txt``.
    """

    def __init__(self, max_events: int = 200):
        self._events: deque[tuple[float, str, str]] = deque(maxlen=max_events)
        self._lock = threading.Lock()

    def log(self, message: str, level: str = "info") -> None:
        """Add an event to the log.

        Args:
            message: Event description.
            level: One of 'info', 'success', 'warning', 'error'.
        """
        now = time.time()
        with self._lock:
            self._events.append((now, level, message))

        # ── Mirror to panel_output.txt ──
        timestamp = datetime.fromtimestamp(now).strftime("%H:%M:%S")
        line = f"[{timestamp}] {message}\n"
        try:
            with open(_LOG_FILE, "a", encoding="utf-8") as fh:
                fh.write(line)
        except OSError:
            pass  # Silently skip if file cannot be written

    def get_events(self, count: int = 50) -> list[tuple[float, str, str]]:
        """Return the most recent events."""
        with self._lock:
            return list(self._events)[-count:]

    def clear(self) -> None:
        """Clear all events."""
        with self._lock:
            self._events.clear()

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._events)


class EventLogWidget(Static):
    """Displays a scrollable stream of system events.

    Events are color-coded by level:
        info    → dim white
        success → green
        warning → yellow
        error   → red
    """

    DEFAULT_CSS = """
    EventLogWidget {
        height: 100%;
        padding: 0 1;
        overflow-y: auto;
    }
    """

    LEVEL_STYLES = {
        "info": "dim white",
        "success": "bold green",
        "warning": "bold yellow",
        "error": "bold red",
    }

    LEVEL_ICONS = {
        "info": "│",
        "success": "✓",
        "warning": "⚠",
        "error": "✗",
    }

    def __init__(self, event_log: EventLog, **kwargs):
        super().__init__(**kwargs)
        self._log = event_log

    def on_mount(self) -> None:
        self.refresh_log()
        self.set_interval(1.0, self.refresh_log)

    def refresh_log(self) -> None:
        """Rebuild the event log display."""
        events = self._log.get_events(30)

        header = Text("📋 EVENT LOG", style="bold cyan")

        if not events:
            content = Group(
                header,
                Text(""),
                Text("  Waiting for events...", style="dim italic"),
            )
            self.update(content)
            return

        rows = [header, Text("")]

        for ts, level, message in reversed(events):
            t = time.strftime("%H:%M:%S", time.localtime(ts))
            style = self.LEVEL_STYLES.get(level, "dim white")
            icon = self.LEVEL_ICONS.get(level, "│")

            line = Text.assemble(
                (f"  {t} ", "dim"),
                (f"{icon} ", style),
                (message, style),
            )
            rows.append(line)

        self.update(Group(*rows))
