"""Secure file transfer over TCP with AES encryption.

Architecture:
    - FileServer(Thread): threaded TCP server on port 5000, receives files
    - FileClient: sends files to a peer with Fernet encryption
    - SecureTransfer: legacy facade wrapping both (used by app.py / TUI)

Protocol (header):
    [FILENAME]|[FILESIZE]|[SHA256_HASH]

Security:
    - Fernet (AES-128-CBC + HMAC-SHA256) for FileServer/FileClient
    - AES-256-GCM (legacy) available via SecureTransfer
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import socket
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable

from mesh_pulse.utils.config import (
    CHUNK_SIZE,
    RECEIVE_DIR,
    TRANSFER_BACKLOG,
    TRANSFER_PORT,
)
from mesh_pulse.utils.crypto import (
    decrypt_chunk,
    derive_key,
    encrypt_chunk,
    fernet_decrypt,
    fernet_encrypt,
    load_or_generate_key,
    pack_frame,
    unpack_frame,
)
from mesh_pulse.utils.logger import get_logger

log = get_logger(__name__)


# ─── Data Models ────────────────────────────────────────────────────


class TransferDirection(Enum):
    SEND = "send"
    RECV = "recv"


class TransferStatus(Enum):
    PENDING = "pending"
    ACTIVE = "active"
    COMPLETE = "complete"
    FAILED = "failed"


@dataclass
class TransferInfo:
    """Tracks the state of an active file transfer."""
    filename: str
    filesize: int
    direction: TransferDirection
    peer_ip: str
    status: TransferStatus = TransferStatus.PENDING
    bytes_transferred: int = 0
    started_at: float = field(default_factory=time.time)
    error: str | None = None

    @property
    def progress(self) -> float:
        """Completion percentage 0.0 – 100.0."""
        if self.filesize == 0:
            return 100.0
        return min(100.0, (self.bytes_transferred / self.filesize) * 100)

    @property
    def elapsed(self) -> float:
        return time.time() - self.started_at

    @property
    def speed_mbps(self) -> float:
        """Transfer speed in MB/s."""
        if self.elapsed == 0:
            return 0.0
        return (self.bytes_transferred / (1024 * 1024)) / self.elapsed

    def to_dict(self) -> dict:
        return {
            "filename": self.filename,
            "filesize": self.filesize,
            "direction": self.direction.value,
            "peer_ip": self.peer_ip,
            "status": self.status.value,
            "progress": round(self.progress, 1),
            "speed_mbps": round(self.speed_mbps, 2),
        }


# ─── FileServer (Threaded TCP Receiver) ───────────────────────────


class FileServer(threading.Thread):
    """Threaded TCP server that listens for incoming encrypted files.

    Protocol:
        1. Receive Fernet-encrypted header: FILENAME|FILESIZE|SHA256_HASH
        2. Receive Fernet-encrypted 64KB chunks
        3. Verify SHA-256 hash after reconstruction

    Usage:
        server = FileServer()
        server.start()
        # ... server runs in background ...
        server.shutdown()
    """

    def __init__(
        self,
        port: int = TRANSFER_PORT,
        receive_dir: str = RECEIVE_DIR,
        fernet_key: bytes | None = None,
        on_transfer_update: Callable | None = None,
        on_file_received: Callable[[TransferInfo], None] | None = None,
    ):
        super().__init__(daemon=True, name="file-server")
        self._port = port
        self._receive_dir = Path(receive_dir)
        self._receive_dir.mkdir(parents=True, exist_ok=True)
        self._key = fernet_key or load_or_generate_key()
        self._on_update = on_transfer_update
        self._on_file_received = on_file_received
        self._running = threading.Event()
        self._running.set()
        self._server_socket: socket.socket | None = None
        self._transfers: list[TransferInfo] = []
        self._lock = threading.Lock()

    def run(self) -> None:
        """TCP accept loop: receive files from peers."""
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.settimeout(1.0)

        try:
            self._server_socket.bind(("", self._port))
            self._server_socket.listen(TRANSFER_BACKLOG)
        except OSError as e:
            log.error("Cannot bind TCP server on port %d: %s", self._port, e)
            return

        log.info("FileServer listening on port %d", self._port)

        while self._running.is_set():
            try:
                conn, addr = self._server_socket.accept()
                handler = threading.Thread(
                    target=self._receive_file,
                    args=(conn, addr[0]),
                    daemon=True,
                    name=f"recv-{addr[0]}",
                )
                handler.start()
            except socket.timeout:
                continue
            except OSError:
                if self._running.is_set():
                    log.error("Server accept error")
                break

        self._server_socket.close()
        log.info("FileServer stopped")

    def shutdown(self) -> None:
        """Signal the server to stop."""
        self._running.clear()
        if self._server_socket:
            try:
                self._server_socket.close()
            except OSError:
                pass

    def get_transfers(self) -> list[TransferInfo]:
        """Return a snapshot of all transfer records."""
        with self._lock:
            return list(self._transfers)

    def _receive_file(self, conn: socket.socket, peer_ip: str) -> None:
        """Receive, decrypt, and verify a single file."""
        info: TransferInfo | None = None
        try:
            # ── Receive & decrypt header ──
            enc_header = unpack_frame(conn)
            header_raw = fernet_decrypt(enc_header, self._key)
            header_str = header_raw.decode("utf-8")

            # Parse protocol header: FILENAME|FILESIZE|SHA256_HASH
            parts = header_str.split("|")
            if len(parts) < 3:
                raise ValueError(f"Invalid header format: {header_str}")

            filename = Path(parts[0]).name  # sanitize
            filesize = int(parts[1])
            expected_hash = parts[2]
            message = parts[3] if len(parts) > 3 else None

            chunk_count = math.ceil(filesize / CHUNK_SIZE) if filesize > 0 else 0

            info = TransferInfo(
                filename=filename,
                filesize=filesize,
                direction=TransferDirection.RECV,
                peer_ip=peer_ip,
                status=TransferStatus.ACTIVE,
            )
            self._register_transfer(info)

            if message:
                log.info("Message from %s: %s", peer_ip, message)

            # ── Receive & decrypt chunks ──
            dest = self._receive_dir / filename
            hasher = hashlib.sha256()

            with open(dest, "wb") as f:
                for _ in range(chunk_count):
                    enc_chunk = unpack_frame(conn)
                    plaintext = fernet_decrypt(enc_chunk, self._key)
                    f.write(plaintext)
                    hasher.update(plaintext)
                    info.bytes_transferred += len(plaintext)
                    self._notify()

            # ── Verify hash ──
            actual_hash = hasher.hexdigest()
            if actual_hash != expected_hash:
                info.status = TransferStatus.FAILED
                info.error = f"Hash mismatch: expected {expected_hash[:12]}..., got {actual_hash[:12]}..."
                log.error("Hash mismatch for %s from %s", filename, peer_ip)
            else:
                info.status = TransferStatus.COMPLETE
                log.info(
                    "Received %s from %s (%.2f MB/s, hash OK)",
                    filename, peer_ip, info.speed_mbps,
                )

        except Exception as e:
            if info:
                info.status = TransferStatus.FAILED
                info.error = str(e)
            log.error("Receive failed from %s: %s", peer_ip, e)

        finally:
            conn.close()
            self._notify()
            # Fire the file-received callback
            if info and self._on_file_received:
                try:
                    self._on_file_received(info)
                except Exception:
                    pass

    def _register_transfer(self, info: TransferInfo) -> None:
        with self._lock:
            self._transfers.append(info)
        self._notify()

    def _notify(self) -> None:
        if self._on_update:
            try:
                self._on_update()
            except Exception:
                pass


# ─── FileClient (TCP Sender) ──────────────────────────────────────


class FileClient:
    """Sends files to a peer over TCP with Fernet encryption.

    Protocol:
        1. Connect to peer's FileServer TCP port
        2. Send encrypted header: FILENAME|FILESIZE|SHA256_HASH
        3. Stream encrypted 64KB chunks

    Usage:
        client = FileClient()
        client.send("192.168.1.10", "/path/to/file.pdf")
    """

    def __init__(
        self,
        port: int = TRANSFER_PORT,
        fernet_key: bytes | None = None,
        on_transfer_update: Callable | None = None,
    ):
        self._port = port
        self._key = fernet_key or load_or_generate_key()
        self._on_update = on_transfer_update
        self._transfers: list[TransferInfo] = []
        self._lock = threading.Lock()

    def send(
        self,
        peer_ip: str,
        filepath: str,
        message: str | None = None,
    ) -> None:
        """Send a single file to a peer in a background thread.

        Args:
            peer_ip: Target peer's IP address.
            filepath: Path to the file to send.
            message: Optional text message.
        """
        thread = threading.Thread(
            target=self._send_worker,
            args=(peer_ip, filepath, message),
            daemon=True,
            name=f"send-{Path(filepath).name}",
        )
        thread.start()

    def send_multiple(
        self,
        peer_ip: str,
        filepaths: list[str],
        message: str | None = None,
    ) -> None:
        """Send multiple files to a peer.

        Args:
            peer_ip: Target peer's IP address.
            filepaths: List of file paths to send.
            message: Optional text message (sent with first file).
        """
        for i, fp in enumerate(filepaths):
            msg = message if i == 0 else None
            self.send(peer_ip, fp, msg)

    def get_transfers(self) -> list[TransferInfo]:
        """Return a snapshot of all transfer records."""
        with self._lock:
            return list(self._transfers)

    def _send_worker(
        self, peer_ip: str, filepath: str, message: str | None
    ) -> None:
        """Worker: compute hash, encrypt, and send a file over TCP."""
        path = Path(filepath)
        if not path.is_file():
            log.error("File not found: %s", filepath)
            return

        filesize = path.stat().st_size
        chunk_count = math.ceil(filesize / CHUNK_SIZE) if filesize > 0 else 0

        # Pre-compute SHA-256 hash
        hasher = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                block = f.read(CHUNK_SIZE)
                if not block:
                    break
                hasher.update(block)
        file_hash = hasher.hexdigest()

        info = TransferInfo(
            filename=path.name,
            filesize=filesize,
            direction=TransferDirection.SEND,
            peer_ip=peer_ip,
            status=TransferStatus.ACTIVE,
        )
        self._register_transfer(info)

        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(30)
            sock.connect((peer_ip, self._port))

            # ── Send encrypted header: FILENAME|FILESIZE|SHA256_HASH[|MESSAGE] ──
            header_str = f"{path.name}|{filesize}|{file_hash}"
            if message:
                header_str += f"|{message}"

            enc_header = fernet_encrypt(header_str.encode("utf-8"), self._key)
            sock.sendall(pack_frame(enc_header))

            # ── Stream encrypted chunks ──
            with open(path, "rb") as f:
                for _ in range(chunk_count):
                    raw = f.read(CHUNK_SIZE)
                    encrypted = fernet_encrypt(raw, self._key)
                    sock.sendall(pack_frame(encrypted))
                    info.bytes_transferred += len(raw)
                    self._notify()

            info.status = TransferStatus.COMPLETE
            log.info(
                "Sent %s to %s (%.2f MB/s)", path.name, peer_ip, info.speed_mbps
            )

        except (OSError, ConnectionError) as e:
            info.status = TransferStatus.FAILED
            info.error = str(e)
            log.error("Send failed %s → %s: %s", path.name, peer_ip, e)

        finally:
            if sock:
                sock.close()
            self._notify()

    def _register_transfer(self, info: TransferInfo) -> None:
        with self._lock:
            self._transfers.append(info)
        self._notify()

    def _notify(self) -> None:
        if self._on_update:
            try:
                self._on_update()
            except Exception:
                pass


# ─── SecureTransfer (Legacy facade for app.py / TUI) ──────────────


class SecureTransfer:
    """Unified file transfer engine wrapping FileServer + FileClient.

    Preserves the same API used by app.py and TUI widgets:
        - start_server() / stop_server()
        - send_file(peer_ip, filepath_or_list)
        - get_transfers()

    Uses Fernet encryption internally (via FileServer/FileClient).
    """

    def __init__(
        self,
        passphrase: str = "",
        transfer_port: int = TRANSFER_PORT,
        receive_dir: str = RECEIVE_DIR,
        on_transfer_update: Callable | None = None,
        on_file_received: Callable[[TransferInfo], None] | None = None,
    ):
        self._key = load_or_generate_key()
        self._port = transfer_port
        self._on_update = on_transfer_update

        self._server = FileServer(
            port=transfer_port,
            receive_dir=receive_dir,
            fernet_key=self._key,
            on_transfer_update=on_transfer_update,
            on_file_received=on_file_received,
        )
        self._client = FileClient(
            port=transfer_port,
            fernet_key=self._key,
            on_transfer_update=on_transfer_update,
        )

    def start_server(self) -> None:
        """Start the TCP file-receive server in a background thread."""
        if self._server.is_alive():
            return
        self._server.start()
        log.info("Transfer server started on port %d", self._port)

    def stop_server(self) -> None:
        """Stop the TCP server."""
        self._server.shutdown()
        log.info("Transfer server stopped")

    def send_file(
        self,
        peer_ip: str,
        filepath: str | list[str],
        message: str | None = None,
    ) -> None:
        """Send one or more files to a peer.

        Args:
            peer_ip: Target peer's IP address.
            filepath: Single path or list of paths.
            message: Optional message.
        """
        paths = [filepath] if isinstance(filepath, str) else filepath
        for i, fp in enumerate(paths):
            msg = message if i == 0 else None
            self._client.send(peer_ip, fp, msg)

    def get_transfers(self) -> list[TransferInfo]:
        """Return combined transfer records from server + client."""
        return self._server.get_transfers() + self._client.get_transfers()

    @property
    def file_server(self) -> FileServer:
        return self._server

    @property
    def file_client(self) -> FileClient:
        return self._client
