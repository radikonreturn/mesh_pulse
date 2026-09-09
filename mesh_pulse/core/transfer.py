"""Secure file transfer over TCP with AES-256-GCM encryption.

Architecture:
    - FileServer(Thread): threaded TCP server, receives file sessions
    - FileClient: sends file batches to a peer
    - SecureTransfer: unified facade wrapping both (used by app.py / TUI)

Protocol (v3 trusted mode, v2 explicit legacy mode):
    Session open  → authenticated handshake, then encrypted JSON control frame
                     {"type": "session", "version": 3, "count": N}
    Per file      → encrypted JSON header:        {"type": "file", "name": "...", "size": N, "sha256": "..."}
                  → N encrypted data chunks (64 KB each)
    Session close → encrypted JSON frame:         {"type": "fin"}

All frames are length-prefixed (4-byte big-endian) and AES-256-GCM encrypted.

Security:
    AES-256-GCM with a per-chunk random 12-byte nonce.
    Trusted mode derives an independent key from Ed25519-authenticated ephemeral
    X25519 keys. The compatibility-only v2 mode derives a PBKDF2 passphrase key.

Retry:
    FileClient retries failed sends up to MAX_RETRIES times with exponential backoff.
"""

from __future__ import annotations

import hashlib
import json
import math
import socket
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from cryptography.exceptions import InvalidTag

from mesh_pulse.core.identity import DeviceIdentity
from mesh_pulse.core.session import (
    PROTOCOL_VERSION,
    AuthenticationError,
    ProtocolError,
    client_handshake,
    server_handshake,
)
from mesh_pulse.core.trust import TrustedDevice, TrustStatus, TrustStore
from mesh_pulse.utils.config import (
    CHUNK_SIZE,
    HEADER_MAX_SIZE,
    MAX_FILE_SIZE,
    MAX_FILES_PER_SESSION,
    MAX_RETRIES,
    MAX_SESSION_SIZE,
    RECEIVE_DIR,
    RETRY_DELAYS,
    TRANSFER_BACKLOG,
    TRANSFER_PORT,
)
from mesh_pulse.utils.crypto import (
    decrypt_chunk,
    derive_session_key,
    encrypt_chunk,
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
    retry_count: int = 0
    peer_device_id: str | None = None

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
            "retry_count": self.retry_count,
            "peer_device_id": self.peer_device_id,
        }


# ─── Internal helpers ────────────────────────────────────────────────


def _send_frame(sock: socket.socket, key: bytes, payload: dict | bytes) -> None:
    """Encrypt and send a length-prefixed frame.

    Args:
        sock: Connected socket.
        key: 32-byte AES-256 key.
        payload: Dict (serialized to JSON) or raw bytes to encrypt.
    """
    if isinstance(payload, dict):
        raw = json.dumps(payload).encode("utf-8")
    else:
        raw = payload
    encrypted = encrypt_chunk(raw, key)
    sock.sendall(pack_frame(encrypted))


def _recv_frame_json(sock: socket.socket, key: bytes) -> dict:
    """Receive, decrypt and JSON-parse a control frame.

    Args:
        sock: Connected socket.
        key: 32-byte AES-256 key.

    Returns:
        Parsed dict from the decrypted JSON frame.
    """
    encrypted = unpack_frame(sock, max_size=HEADER_MAX_SIZE + 64)
    raw = decrypt_chunk(encrypted, key)
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProtocolError("Invalid transfer control frame") from error
    if not isinstance(payload, dict):
        raise ProtocolError("Transfer control frame must be an object")
    return payload


def _recv_frame_bytes(sock: socket.socket, key: bytes) -> bytes:
    """Receive and decrypt a raw data frame.

    Args:
        sock: Connected socket.
        key: 32-byte AES-256 key.

    Returns:
        Decrypted plaintext bytes.
    """
    encrypted = unpack_frame(sock, max_size=CHUNK_SIZE + 64)
    return decrypt_chunk(encrypted, key)


def _validate_session_header(
    session: dict, expected_version: int
) -> tuple[int, str | None]:
    """Validate bounded session metadata before accepting any file frames."""
    if session.get("type") != "session":
        raise ProtocolError("Expected session frame")
    if session.get("version") != expected_version:
        raise ProtocolError("Protocol version mismatch")
    count = session.get("count")
    if (
        isinstance(count, bool)
        or not isinstance(count, int)
        or not 1 <= count <= MAX_FILES_PER_SESSION
    ):
        raise ProtocolError("Invalid file count")
    message = session.get("message")
    if message is not None and (not isinstance(message, str) or len(message) > 4096):
        raise ProtocolError("Invalid transfer message")
    return count, message


def _validate_file_header(header: dict) -> tuple[str, int, str]:
    """Validate and sanitize remote file metadata."""
    if header.get("type") != "file":
        raise ProtocolError("Expected file frame")
    raw_name = header.get("name")
    if not isinstance(raw_name, str) or not raw_name or len(raw_name) > 255:
        raise ProtocolError("Invalid filename")
    filename = Path(raw_name).name
    if filename in {"", ".", ".."}:
        raise ProtocolError("Invalid filename")
    filesize = header.get("size")
    if (
        isinstance(filesize, bool)
        or not isinstance(filesize, int)
        or not 0 <= filesize <= MAX_FILE_SIZE
    ):
        raise ProtocolError("Invalid file size")
    expected_hash = header.get("sha256")
    if (
        not isinstance(expected_hash, str)
        or len(expected_hash) != 64
        or any(character not in "0123456789abcdef" for character in expected_hash)
    ):
        raise ProtocolError("Invalid SHA-256 digest")
    return filename, filesize, expected_hash


def _sha256_of_file(path: Path) -> str:
    """Compute SHA-256 hash of a file."""
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            block = f.read(CHUNK_SIZE)
            if not block:
                break
            hasher.update(block)
    return hasher.hexdigest()


# ─── FileServer (Threaded TCP Receiver) ───────────────────────────


class FileServer(threading.Thread):
    """Threaded TCP server that receives AES-256-GCM encrypted file sessions.

    Protocol (v2):
        Session:  {"type":"session","version":2,"count":N}
        Per file: {"type":"file","name":"...","size":N,"sha256":"..."}
                  + N encrypted 64 KB data chunks
        FIN:      {"type":"fin"}

    Usage:
        server = FileServer(passphrase="secret")
        server.start()
        server.shutdown()
    """

    def __init__(
        self,
        port: int = TRANSFER_PORT,
        receive_dir: str = RECEIVE_DIR,
        passphrase: str = "",
        on_transfer_update: Callable | None = None,
        on_file_received: Callable[[TransferInfo], None] | None = None,
        # Legacy compat: accept fernet_key but ignore (unused in v2)
        fernet_key: bytes | None = None,
        identity: DeviceIdentity | None = None,
        trust_store: TrustStore | None = None,
        legacy_mode: bool | None = None,
    ):
        super().__init__(daemon=True, name="file-server")
        self._port = port
        self._receive_dir = Path(receive_dir)
        self._receive_dir.mkdir(parents=True, exist_ok=True)
        self._key = (
            derive_session_key(passphrase) if passphrase else derive_session_key("")
        )
        self._identity = identity
        self._trust_store = trust_store
        self._legacy_mode = (
            (identity is None or trust_store is None)
            if legacy_mode is None
            else legacy_mode
        )
        if not self._legacy_mode and (identity is None or trust_store is None):
            raise ValueError("Trusted protocol mode requires identity and trust store")
        self._on_update = on_transfer_update
        self._on_file_received = on_file_received
        self._running = threading.Event()
        self._running.set()
        self._server_socket: socket.socket | None = None
        self._transfers: list[TransferInfo] = []
        self._lock = threading.Lock()

    def run(self) -> None:
        """TCP accept loop: receive file sessions from peers."""
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
                    target=self._receive_session,
                    args=(conn, addr[0]),
                    daemon=True,
                    name=f"recv-{addr[0]}",
                )
                handler.start()
            except TimeoutError:
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

    def _receive_session(self, conn: socket.socket, peer_ip: str) -> None:
        """Handle a single session connection from a peer."""
        try:
            if self._legacy_mode:
                session_key = self._key
                peer_device_id = None
                expected_version = 2
            else:
                authenticated = server_handshake(
                    conn,
                    self._identity,
                    self._trust_store,
                )
                session_key = authenticated.key
                peer_device_id = authenticated.peer_device_id
                expected_version = PROTOCOL_VERSION

            session = _recv_frame_json(conn, session_key)
            count, message = _validate_session_header(session, expected_version)
            if message:
                log.info("Message from %s: %s", peer_ip, message)

            # ── Receive each file ──
            session_size = 0
            for _ in range(count):
                ctrl = _recv_frame_json(conn, session_key)
                if ctrl.get("type") == "fin":
                    break
                _, filesize, _ = _validate_file_header(ctrl)
                session_size += filesize
                if session_size > MAX_SESSION_SIZE:
                    raise ProtocolError("Transfer session exceeds size limit")
                self._receive_one_file(
                    conn,
                    peer_ip,
                    ctrl,
                    session_key,
                    peer_device_id,
                )

        except (AuthenticationError, ProtocolError, InvalidTag) as e:
            log.warning("Rejected transfer session from %s: %s", peer_ip, e)
        except (ConnectionError, OSError, ValueError) as e:
            log.error("Session error from %s: %s", peer_ip, e)
        finally:
            conn.close()

    def _receive_one_file(
        self,
        conn: socket.socket,
        peer_ip: str,
        header: dict,
        session_key: bytes | None = None,
        peer_device_id: str | None = None,
    ) -> None:
        """Receive a single file within an open session."""
        info: TransferInfo | None = None
        try:
            filename, filesize, expected_hash = _validate_file_header(header)
            frame_key = session_key or self._key

            chunk_count = math.ceil(filesize / CHUNK_SIZE) if filesize > 0 else 0

            info = TransferInfo(
                filename=filename,
                filesize=filesize,
                direction=TransferDirection.RECV,
                peer_ip=peer_ip,
                status=TransferStatus.ACTIVE,
                peer_device_id=peer_device_id,
            )
            self._register_transfer(info)

            # ── Receive data chunks ──
            dest = self._receive_dir / filename
            hasher = hashlib.sha256()

            with open(dest, "wb") as f:
                for _ in range(chunk_count):
                    plaintext = _recv_frame_bytes(conn, frame_key)
                    remaining = filesize - info.bytes_transferred
                    if len(plaintext) > min(CHUNK_SIZE, remaining):
                        raise ProtocolError("File chunk exceeds declared size")
                    f.write(plaintext)
                    hasher.update(plaintext)
                    info.bytes_transferred += len(plaintext)
                    self._notify()

            # ── Verify integrity ──
            actual_hash = hasher.hexdigest()
            if actual_hash != expected_hash:
                info.status = TransferStatus.FAILED
                info.error = (
                    f"Hash mismatch: expected {expected_hash[:12]}…, "
                    f"got {actual_hash[:12]}…"
                )
                log.error("Hash mismatch for %s from %s", filename, peer_ip)
            else:
                info.status = TransferStatus.COMPLETE
                log.info(
                    "Received %s from %s (%.2f MB/s, hash OK)",
                    filename,
                    peer_ip,
                    info.speed_mbps,
                )

        except (ConnectionError, OSError, ProtocolError, InvalidTag, ValueError) as e:
            if info:
                info.status = TransferStatus.FAILED
                info.error = str(e)
            log.error("Receive failed from %s: %s", peer_ip, e)

        finally:
            self._notify()
            if info and self._on_file_received:
                try:
                    self._on_file_received(info)
                except (RuntimeError, TypeError, ValueError):
                    log.exception("File-received callback failed")

    def _register_transfer(self, info: TransferInfo) -> None:
        with self._lock:
            self._transfers.append(info)
        self._notify()

    def _notify(self) -> None:
        if self._on_update:
            try:
                self._on_update()
            except (RuntimeError, TypeError, ValueError):
                log.exception("Transfer update callback failed")


# ─── FileClient (TCP Sender) ──────────────────────────────────────


class FileClient:
    """Sends files to a peer over TCP with AES-256-GCM encryption.

    Protocol (v2):
        Session:  {"type":"session","version":2,"count":N,"message":"..."}
        Per file: {"type":"file","name":"...","size":N,"sha256":"..."}
                  + N encrypted 64 KB data chunks
        FIN:      {"type":"fin"}

    Retry:
        On connection or send failure, retries up to MAX_RETRIES times with
        exponential backoff before marking the transfer as FAILED.

    Usage:
        client = FileClient(passphrase="secret")
        client.send_batch("192.168.1.10", ["/path/to/a.txt", "/path/to/b.pdf"])
    """

    def __init__(
        self,
        port: int = TRANSFER_PORT,
        passphrase: str = "",
        on_transfer_update: Callable | None = None,
        on_progress: Callable[[str, int, int], None] | None = None,
        # Legacy compat: accept fernet_key but ignore (unused in v2)
        fernet_key: bytes | None = None,
        identity: DeviceIdentity | None = None,
        trust_store: TrustStore | None = None,
        peer_resolver: Callable[[str], object | None] | None = None,
        legacy_mode: bool | None = None,
    ):
        self._port = port
        self._key = (
            derive_session_key(passphrase) if passphrase else derive_session_key("")
        )
        self._identity = identity
        self._trust_store = trust_store
        self._peer_resolver = peer_resolver
        self._legacy_mode = (
            (identity is None or trust_store is None)
            if legacy_mode is None
            else legacy_mode
        )
        if not self._legacy_mode and (identity is None or trust_store is None):
            raise ValueError("Trusted protocol mode requires identity and trust store")
        self._on_update = on_transfer_update
        self._on_progress = on_progress
        self._transfers: list[TransferInfo] = []
        self._lock = threading.Lock()

    # ── Public API ──────────────────────────────────────────────────

    def send(
        self,
        peer_ip: str,
        filepath: str,
        message: str | None = None,
    ) -> None:
        """Send a single file to a peer in a background thread."""
        self.send_batch(peer_ip, [filepath], message=message)

    def send_batch(
        self,
        peer_ip: str,
        filepaths: list[str],
        message: str | None = None,
    ) -> None:
        """Send a batch of files to a peer in a single TCP session.

        Args:
            peer_ip: Target peer's IP address.
            filepaths: List of file paths to send.
            message: Optional text message (sent in session header).
        """
        thread = threading.Thread(
            target=self._batch_worker,
            args=(peer_ip, filepaths, message),
            daemon=True,
            name=f"send-batch-{peer_ip}",
        )
        thread.start()

    # Legacy single-file compat (kept so existing callers don't break)
    def send_multiple(
        self,
        peer_ip: str,
        filepaths: list[str],
        message: str | None = None,
    ) -> None:
        """Legacy alias for send_batch."""
        self.send_batch(peer_ip, filepaths, message=message)

    def get_transfers(self) -> list[TransferInfo]:
        """Return a snapshot of all transfer records."""
        with self._lock:
            return list(self._transfers)

    def _assert_peer_protocol(
        self,
        peer_ip: str,
        expected_protocol: int,
    ) -> None:
        """Fail before connecting when discovery reports an incompatible peer."""

        if self._peer_resolver is None:
            # Keep low-level/manual legacy clients backwards compatible.
            return

        peer = self._peer_resolver(peer_ip)

        if peer is None:
            if expected_protocol == PROTOCOL_VERSION:
                raise AuthenticationError("Peer identity is unavailable")
            return

        remote_protocol = getattr(
            peer,
            "protocol_version",
            None,
        )

        if remote_protocol is not None and remote_protocol != expected_protocol:
            raise ProtocolError(
                f"Incompatible transfer protocol: "
                f"peer requires v{remote_protocol}, "
                f"local mode is v{expected_protocol}"
            )

    # ── Workers ─────────────────────────────────────────────────────

    def _batch_worker(
        self, peer_ip: str, filepaths: list[str], message: str | None
    ) -> None:
        """Open one TCP session and send all files with retry on failure."""
        # Validate files exist
        valid_paths = []
        for fp in filepaths:
            p = Path(fp)
            if p.is_file():
                valid_paths.append(p)
            else:
                log.warning("File not found, skipping: %s", fp)

        if not valid_paths:
            log.error("No valid files to send to %s", peer_ip)
            return
        if len(valid_paths) > MAX_FILES_PER_SESSION:
            log.error("Too many files in transfer to %s", peer_ip)
            return

        # Pre-compute hashes so they're ready when we connect
        file_meta: list[tuple[Path, int, str]] = []
        for p in valid_paths:
            size = p.stat().st_size
            if size > MAX_FILE_SIZE:
                log.error("File exceeds configured transfer limit: %s", p.name)
                return
            sha = _sha256_of_file(p)
            file_meta.append((p, size, sha))
        if sum(size for _, size, _ in file_meta) > MAX_SESSION_SIZE:
            log.error("Transfer batch exceeds configured session limit")
            return

        # Create TransferInfo entries for each file
        infos: list[TransferInfo] = []
        for p, size, _ in file_meta:
            info = TransferInfo(
                filename=p.name,
                filesize=size,
                direction=TransferDirection.SEND,
                peer_ip=peer_ip,
                status=TransferStatus.PENDING,
                peer_device_id=self._peer_device_id(peer_ip),
            )
            self._register_transfer(info)
            infos.append(info)

        # ── Retry loop ──
        for attempt in range(MAX_RETRIES + 1):
            if attempt > 0:
                delay = RETRY_DELAYS[min(attempt - 1, len(RETRY_DELAYS) - 1)]
                log.info(
                    "Retry %d/%d for batch to %s (waiting %.1fs)",
                    attempt,
                    MAX_RETRIES,
                    peer_ip,
                    delay,
                )
                time.sleep(delay)
                for info in infos:
                    info.retry_count = attempt
                    info.bytes_transferred = 0
                    info.status = TransferStatus.ACTIVE

            try:
                self._send_session(peer_ip, file_meta, infos, message)
                # If we get here, all files sent successfully
                return
            except (AuthenticationError, ProtocolError) as e:
                log.warning("Transfer authentication failed for %s: %s", peer_ip, e)
                for info in infos:
                    info.status = TransferStatus.FAILED
                    info.error = "Transfer rejected."
                self._notify()
                return
            except (OSError, ConnectionError) as e:
                log.warning("Batch send attempt %d failed: %s", attempt + 1, e)
                for info in infos:
                    info.status = TransferStatus.FAILED
                    info.error = str(e)
                self._notify()
                if attempt == MAX_RETRIES:
                    log.error(
                        "Batch to %s permanently failed after %d attempts",
                        peer_ip,
                        MAX_RETRIES + 1,
                    )

    def _send_session(
        self,
        peer_ip: str,
        file_meta: list[tuple[Path, int, str]],
        infos: list[TransferInfo],
        message: str | None,
    ) -> None:
        """Open one TCP connection and stream all files."""

        protocol_version = 2 if self._legacy_mode else PROTOCOL_VERSION

        self._assert_peer_protocol(
            peer_ip,
            protocol_version,
        )

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM,
        )
        sock.settimeout(30)

        try:
            sock.connect((peer_ip, self._port))

            if self._legacy_mode:
                session_key = self._key
            else:
                trusted_peer = self._resolve_trusted_peer(peer_ip)

                authenticated = client_handshake(
                    sock,
                    self._identity,
                    trusted_peer,
                )

                session_key = authenticated.key

            # ── Session header ──
            session_frame: dict = {
                "type": "session",
                "version": protocol_version,
                "count": len(file_meta),
            }
            if message:
                session_frame["message"] = message
            _send_frame(sock, session_key, session_frame)

            # ── Send each file ──
            for (path, size, sha), info in zip(file_meta, infos):
                info.status = TransferStatus.ACTIVE
                info.started_at = time.time()
                self._notify()

                chunk_count = math.ceil(size / CHUNK_SIZE) if size > 0 else 0

                # File header
                _send_frame(
                    sock,
                    session_key,
                    {
                        "type": "file",
                        "name": path.name,
                        "size": size,
                        "sha256": sha,
                    },
                )

                # Data chunks
                with open(path, "rb") as f:
                    for _ in range(chunk_count):
                        raw = f.read(CHUNK_SIZE)
                        _send_frame(sock, session_key, raw)
                        info.bytes_transferred += len(raw)
                        if self._on_progress:
                            try:
                                self._on_progress(
                                    path.name, info.bytes_transferred, size
                                )
                            except (RuntimeError, TypeError, ValueError):
                                log.exception("Transfer progress callback failed")
                        self._notify()

                info.status = TransferStatus.COMPLETE
                log.info(
                    "Sent %s to %s (%.2f MB/s)", path.name, peer_ip, info.speed_mbps
                )
                self._notify()

            # ── FIN ──
            _send_frame(sock, session_key, {"type": "fin"})

        finally:
            sock.close()

    def _peer_device_id(self, peer_ip: str) -> str | None:
        if self._peer_resolver is None:
            return None
        peer = self._peer_resolver(peer_ip)
        return getattr(peer, "device_id", None) if peer is not None else None

    def _resolve_trusted_peer(self, peer_ip: str) -> TrustedDevice:
        if self._peer_resolver is None or self._trust_store is None:
            raise AuthenticationError("Peer identity is unavailable")
        peer = self._peer_resolver(peer_ip)
        device_id = getattr(peer, "device_id", None)
        public_key = getattr(peer, "public_key", None)
        trust_status = getattr(peer, "trust_status", TrustStatus.NEW)
        if not device_id or not public_key or trust_status != TrustStatus.TRUSTED:
            raise AuthenticationError("Peer is not trusted")
        record = self._trust_store.get(device_id)
        if record is None or record.public_key != public_key:
            raise AuthenticationError("Wrong peer identity")
        return record

    def _register_transfer(self, info: TransferInfo) -> None:
        with self._lock:
            self._transfers.append(info)
        self._notify()

    def _notify(self) -> None:
        if self._on_update:
            try:
                self._on_update()
            except (RuntimeError, TypeError, ValueError):
                log.exception("Transfer update callback failed")


# ─── SecureTransfer (Unified facade for app.py / TUI) ─────────────


class SecureTransfer:
    """Unified file transfer engine wrapping FileServer + FileClient.

    Public API (unchanged from v1 so app.py needs no edits):
        - start_server() / stop_server()
        - send_file(peer_ip, filepath_or_list, message)
        - get_transfers()

    Internally uses AES-256-GCM via FileServer/FileClient (v2 protocol).
    """

    def __init__(
        self,
        passphrase: str = "",
        transfer_port: int = TRANSFER_PORT,
        receive_dir: str = RECEIVE_DIR,
        on_transfer_update: Callable | None = None,
        on_file_received: Callable[[TransferInfo], None] | None = None,
        on_progress: Callable[[str, int, int], None] | None = None,
        identity: DeviceIdentity | None = None,
        trust_store: TrustStore | None = None,
        peer_resolver: Callable[[str], object | None] | None = None,
        legacy_mode: bool | None = None,
    ):
        self._port = transfer_port
        self._on_update = on_transfer_update

        self._server = FileServer(
            port=transfer_port,
            receive_dir=receive_dir,
            passphrase=passphrase,
            on_transfer_update=on_transfer_update,
            on_file_received=on_file_received,
            identity=identity,
            trust_store=trust_store,
            legacy_mode=legacy_mode,
        )
        self._client = FileClient(
            port=transfer_port,
            passphrase=passphrase,
            on_transfer_update=on_transfer_update,
            on_progress=on_progress,
            identity=identity,
            trust_store=trust_store,
            peer_resolver=peer_resolver,
            legacy_mode=legacy_mode,
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
        """Send one or more files to a peer as a single session.

        Args:
            peer_ip: Target peer's IP address.
            filepath: Single path or list of paths.
            message: Optional message sent in the session header.
        """
        paths = [filepath] if isinstance(filepath, str) else list(filepath)
        self._client.send_batch(peer_ip, paths, message=message)

    def get_transfers(self) -> list[TransferInfo]:
        """Return combined transfer records from server + client."""
        return self._server.get_transfers() + self._client.get_transfers()

    @property
    def file_server(self) -> FileServer:
        return self._server

    @property
    def file_client(self) -> FileClient:
        return self._client
