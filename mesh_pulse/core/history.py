"""Versioned SQLite persistence for transfer sessions and files."""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from mesh_pulse.utils.logger import get_logger

log = get_logger(__name__)
SCHEMA_VERSION = 1
_INTERRUPTIBLE = (
    "pending",
    "pending_approval",
    "accepted",
    "active",
    "interrupted",
    "resuming",
)


@dataclass(frozen=True)
class TransferRecord:
    transfer_id: str
    peer_device_id: str | None
    peer_ip: str
    peer_hostname: str | None
    direction: str
    status: str
    message: str | None
    file_count: int
    total_size: int
    bytes_transferred: int
    started_at: float
    completed_at: float | None = None
    error: str | None = None


@dataclass(frozen=True)
class TransferFileRecord:
    id: int | None
    transfer_id: str
    file_id: str
    filename: str
    final_path: str | None
    filesize: int
    sha256: str | None
    bytes_transferred: int
    status: str


class TransferHistoryStore:
    """Thread-safe repository using a short-lived SQLite connection per call."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.available = True
        try:
            self._migrate()
        except (OSError, sqlite3.DatabaseError) as error:
            self.available = False
            log.error("Transfer history is unavailable: %s", error)

    def create_transfer(
        self,
        record: TransferRecord,
        files: list[TransferFileRecord] | None = None,
    ) -> bool:
        if not self.available:
            return False
        try:
            with self._lock, self._connection() as connection:
                connection.execute(
                    """
                    INSERT INTO transfers (
                        transfer_id, peer_device_id, peer_ip, peer_hostname,
                        direction, status, message, file_count, total_size,
                        bytes_transferred, started_at, completed_at, error
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(transfer_id) DO UPDATE SET
                        peer_device_id=excluded.peer_device_id,
                        peer_ip=excluded.peer_ip,
                        peer_hostname=COALESCE(excluded.peer_hostname, peer_hostname),
                        direction=excluded.direction,
                        status=excluded.status,
                        message=COALESCE(excluded.message, message),
                        file_count=excluded.file_count,
                        total_size=excluded.total_size,
                        bytes_transferred=excluded.bytes_transferred,
                        completed_at=excluded.completed_at,
                        error=excluded.error
                    """,
                    self._transfer_values(record),
                )
                for file_record in files or []:
                    self._upsert_file(connection, file_record)
            return True
        except sqlite3.DatabaseError as error:
            log.error("Unable to create transfer history record: %s", error)
            return False

    def update_transfer(self, transfer_id: str, **changes) -> bool:
        allowed = {
            "peer_hostname",
            "status",
            "bytes_transferred",
            "completed_at",
            "error",
            "file_count",
            "total_size",
        }
        values = {key: value for key, value in changes.items() if key in allowed}
        if not self.available or not values:
            return False
        assignments = ", ".join(f"{key} = ?" for key in values)
        try:
            with self._lock, self._connection() as connection:
                cursor = connection.execute(
                    f"UPDATE transfers SET {assignments} WHERE transfer_id = ?",
                    (*values.values(), transfer_id),
                )
                return cursor.rowcount > 0
        except sqlite3.DatabaseError as error:
            log.error("Unable to update transfer history record: %s", error)
            return False

    def add_file(self, record: TransferFileRecord) -> bool:
        if not self.available:
            return False
        try:
            with self._lock, self._connection() as connection:
                self._upsert_file(connection, record)
            return True
        except sqlite3.DatabaseError as error:
            log.error("Unable to create transfer file record: %s", error)
            return False

    def update_file(self, transfer_id: str, file_id: str, **changes) -> bool:
        allowed = {"final_path", "bytes_transferred", "status", "sha256"}
        values = {key: value for key, value in changes.items() if key in allowed}
        if not self.available or not values:
            return False
        assignments = ", ".join(f"{key} = ?" for key in values)
        try:
            with self._lock, self._connection() as connection:
                cursor = connection.execute(
                    f"""UPDATE transfer_files SET {assignments}
                    WHERE transfer_id = ? AND file_id = ?""",
                    (*values.values(), transfer_id, file_id),
                )
                return cursor.rowcount > 0
        except sqlite3.DatabaseError as error:
            log.error("Unable to update transfer file record: %s", error)
            return False

    def get_transfer(self, transfer_id: str) -> TransferRecord | None:
        rows = self._query_transfers("WHERE transfer_id = ?", (transfer_id,), limit=1)
        return rows[0] if rows else None

    def get_files(self, transfer_id: str) -> list[TransferFileRecord]:
        if not self.available:
            return []
        try:
            with self._lock, self._connection() as connection:
                rows = connection.execute(
                    """SELECT id, transfer_id, file_id, filename, final_path,
                    filesize, sha256, bytes_transferred, status
                    FROM transfer_files WHERE transfer_id = ? ORDER BY id""",
                    (transfer_id,),
                ).fetchall()
            return [TransferFileRecord(*row) for row in rows]
        except sqlite3.DatabaseError as error:
            log.error("Unable to read transfer file history: %s", error)
            return []

    def list_transfers(
        self,
        *,
        direction: str | None = None,
        status: str | None = None,
        search: str | None = None,
        limit: int = 500,
    ) -> list[TransferRecord]:
        clauses: list[str] = []
        params: list[object] = []
        if direction:
            clauses.append("direction = ?")
            params.append(direction)
        if status:
            clauses.append("status = ?")
            params.append(status)
        if search:
            clauses.append(
                "(peer_hostname LIKE ? OR peer_ip LIKE ? OR transfer_id LIKE ?)"
            )
            pattern = f"%{search[:128]}%"
            params.extend((pattern, pattern, pattern))
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        return self._query_transfers(where, tuple(params), limit=limit)

    def list_for_peer(
        self, peer_device_id: str | None, peer_ip: str, limit: int = 500
    ) -> list[TransferRecord]:
        if peer_device_id:
            return self._query_transfers(
                "WHERE peer_device_id = ? OR peer_ip = ?",
                (peer_device_id, peer_ip),
                limit=limit,
            )
        return self._query_transfers("WHERE peer_ip = ?", (peer_ip,), limit=limit)

    def search(self, query: str, limit: int = 500) -> list[TransferRecord]:
        return self.list_transfers(search=query, limit=limit)

    def delete(self, transfer_id: str) -> bool:
        if not self.available:
            return False
        try:
            with self._lock, self._connection() as connection:
                cursor = connection.execute(
                    "DELETE FROM transfers WHERE transfer_id = ?", (transfer_id,)
                )
                return cursor.rowcount > 0
        except sqlite3.DatabaseError as error:
            log.error("Unable to delete transfer history record: %s", error)
            return False

    def clear(self) -> bool:
        if not self.available:
            return False
        try:
            with self._lock, self._connection() as connection:
                connection.execute("DELETE FROM transfers")
            return True
        except sqlite3.DatabaseError as error:
            log.error("Unable to clear transfer history: %s", error)
            return False

    def _query_transfers(
        self, where: str, params: tuple[object, ...], *, limit: int
    ) -> list[TransferRecord]:
        if not self.available:
            return []
        bounded_limit = max(1, min(limit, 5000))
        try:
            with self._lock, self._connection() as connection:
                rows = connection.execute(
                    f"""SELECT transfer_id, peer_device_id, peer_ip, peer_hostname,
                    direction, status, message, file_count, total_size,
                    bytes_transferred, started_at, completed_at, error
                    FROM transfers {where}
                    ORDER BY started_at DESC LIMIT ?""",
                    (*params, bounded_limit),
                ).fetchall()
            return [TransferRecord(*row) for row in rows]
        except sqlite3.DatabaseError as error:
            log.error("Unable to read transfer history: %s", error)
            return []

    def _migrate(self) -> None:
        with self._lock, self._connection() as connection:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version > SCHEMA_VERSION:
                raise sqlite3.DatabaseError("History schema is newer than this app")
            if version < 1:
                connection.executescript(
                    """
                    CREATE TABLE transfers (
                        transfer_id TEXT PRIMARY KEY,
                        peer_device_id TEXT,
                        peer_ip TEXT NOT NULL,
                        peer_hostname TEXT,
                        direction TEXT NOT NULL,
                        status TEXT NOT NULL,
                        message TEXT,
                        file_count INTEGER NOT NULL,
                        total_size INTEGER NOT NULL,
                        bytes_transferred INTEGER NOT NULL,
                        started_at REAL NOT NULL,
                        completed_at REAL,
                        error TEXT
                    );
                    CREATE TABLE transfer_files (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        transfer_id TEXT NOT NULL,
                        file_id TEXT NOT NULL,
                        filename TEXT NOT NULL,
                        final_path TEXT,
                        filesize INTEGER NOT NULL,
                        sha256 TEXT,
                        bytes_transferred INTEGER NOT NULL,
                        status TEXT NOT NULL,
                        FOREIGN KEY (transfer_id) REFERENCES transfers(transfer_id)
                            ON DELETE CASCADE,
                        UNIQUE (transfer_id, file_id)
                    );
                    CREATE INDEX idx_transfers_peer ON transfers(peer_device_id);
                    CREATE INDEX idx_transfers_started ON transfers(started_at);
                    CREATE INDEX idx_transfers_status ON transfers(status);
                    PRAGMA user_version = 1;
                    """
                )
            placeholders = ",".join("?" for _ in _INTERRUPTIBLE)
            connection.execute(
                f"UPDATE transfers SET status = 'interrupted' "
                f"WHERE status IN ({placeholders})",
                _INTERRUPTIBLE,
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=0.25)
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 250")
        return connection

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    @staticmethod
    def _transfer_values(record: TransferRecord) -> tuple:
        return (
            record.transfer_id,
            record.peer_device_id,
            record.peer_ip,
            record.peer_hostname,
            record.direction,
            record.status,
            record.message,
            record.file_count,
            record.total_size,
            record.bytes_transferred,
            record.started_at,
            record.completed_at,
            record.error,
        )

    @staticmethod
    def _upsert_file(
        connection: sqlite3.Connection, record: TransferFileRecord
    ) -> None:
        connection.execute(
            """
            INSERT INTO transfer_files (
                transfer_id, file_id, filename, final_path, filesize,
                sha256, bytes_transferred, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(transfer_id, file_id) DO UPDATE SET
                final_path=COALESCE(excluded.final_path, final_path),
                sha256=COALESCE(excluded.sha256, sha256),
                bytes_transferred=excluded.bytes_transferred,
                status=excluded.status
            """,
            (
                record.transfer_id,
                record.file_id,
                record.filename,
                record.final_path,
                record.filesize,
                record.sha256,
                record.bytes_transferred,
                record.status,
            ),
        )
