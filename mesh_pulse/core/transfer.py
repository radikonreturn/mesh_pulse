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
import select
import socket
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from cryptography.exceptions import InvalidTag

from mesh_pulse.core.history import (
    TransferFileRecord,
    TransferHistoryStore,
    TransferRecord,
)
from mesh_pulse.core.identity import DeviceIdentity
from mesh_pulse.core.inbox import (
    IncomingRequestManager,
    IncomingRequestStatus,
    IncomingTransferRequest,
)
from mesh_pulse.core.resume import PartialTransferStore, commit_partial_file
from mesh_pulse.core.session import (
    PROTOCOL_VERSION,
    AuthenticationError,
    ProtocolError,
    client_handshake,
    server_handshake,
)
from mesh_pulse.core.transfer_protocol import (
    TransferOffer,
    build_response,
    validate_offer,
    validate_response,
)
from mesh_pulse.core.trust import TrustedDevice, TrustStatus, TrustStore
from mesh_pulse.utils.config import (
    CHUNK_SIZE,
    CHUNK_TIMEOUT,
    CONNECT_TIMEOUT,
    HANDSHAKE_TIMEOUT,
    HEADER_MAX_SIZE,
    IDLE_TRANSFER_TIMEOUT,
    MAX_FILE_SIZE,
    MAX_FILES_PER_SESSION,
    MAX_RETRIES,
    MAX_SESSION_SIZE,
    RECEIVE_DIR,
    RETRY_DELAYS,
    TRANSFER_APPROVAL_TIMEOUT,
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
    PENDING_APPROVAL = "pending_approval"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    ACTIVE = "active"
    INTERRUPTED = "interrupted"
    RESUMING = "resuming"
    COMPLETE = "complete"
    FAILED = "failed"
    CANCELLED = "cancelled"


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
    transfer_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    file_id: str | None = None
    resume_offset: int = 0
    bytes_transferred_this_attempt: int = 0
    completed_at: float | None = None
    message: str | None = None
    sha256: str | None = None
    final_path: str | None = None

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
            "transfer_id": self.transfer_id,
            "resume_offset": self.resume_offset,
        }


class TransferRejected(ProtocolError):
    """The authenticated peer explicitly declined a transfer offer."""


class ApprovalTimeout(ProtocolError):
    """The peer did not decide on a transfer offer in time."""


class TransferCancelled(ConnectionError):
    """A user deliberately cancelled an active transfer."""


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
        incoming_manager: IncomingRequestManager | None = None,
        peer_name_resolver: Callable[[str], str | None] | None = None,
        approval_timeout: float = TRANSFER_APPROVAL_TIMEOUT,
    ):
        super().__init__(daemon=True, name="file-server")
        self._port = port
        self._receive_dir = Path(receive_dir)
        self._receive_dir.mkdir(parents=True, exist_ok=True)
        self._partials = PartialTransferStore(self._receive_dir)
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
        self._incoming_manager = incoming_manager
        self._peer_name_resolver = peer_name_resolver
        self._approval_timeout = approval_timeout
        self._running = threading.Event()
        self._running.set()
        self._server_socket: socket.socket | None = None
        self._transfers: list[TransferInfo] = []
        self._transfer_index: dict[tuple[str, str], TransferInfo] = {}
        self._lock = threading.Lock()

    def _get_or_create_v3_transfer(
        self,
        *,
        transfer_id: str,
        file_id: str,
        filename: str,
        filesize: int,
        peer_ip: str,
        peer_device_id: str | None,
        resume_offset: int,
        message: str | None,
        sha256: str | None,
    ) -> TransferInfo:
        with self._lock:
            key = (transfer_id, file_id)
            existing = self._transfer_index.get(key)
            if existing is not None:
                existing.status = (
                    TransferStatus.RESUMING if resume_offset else TransferStatus.ACTIVE
                )
                existing.resume_offset = resume_offset
                existing.bytes_transferred = resume_offset
                existing.bytes_transferred_this_attempt = 0
                existing.error = None
                existing.final_path = None
                existing.completed_at = None
                if sha256 and not existing.sha256:
                    existing.sha256 = sha256
                info = existing
            else:
                info = TransferInfo(
                    filename=filename,
                    filesize=filesize,
                    direction=TransferDirection.RECV,
                    peer_ip=peer_ip,
                    status=(
                        TransferStatus.RESUMING
                        if resume_offset
                        else TransferStatus.ACTIVE
                    ),
                    bytes_transferred=resume_offset,
                    peer_device_id=peer_device_id,
                    transfer_id=transfer_id,
                    file_id=file_id,
                    resume_offset=resume_offset,
                    message=message,
                    sha256=sha256,
                )
                self._transfer_index[key] = info
                self._transfers.append(info)
        self._notify()
        return info

    def run(self) -> None:
        """TCP accept loop: receive file sessions from peers."""
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.settimeout(1.0)

        try:
            self._server_socket.bind(("", self._port))
            self._server_socket.listen(TRANSFER_BACKLOG)
        except OSError as e:
            if self._running.is_set():
                log.error("Cannot bind TCP server on port %d: %s", self._port, e)
            else:
                log.debug("Transfer server stopped during startup: %s", e)
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
                session = _recv_frame_json(conn, session_key)
                count, message = _validate_session_header(session, expected_version)
                if message:
                    log.info("Message from %s: %s", peer_ip, message)
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
                return

            conn.settimeout(HANDSHAKE_TIMEOUT)
            authenticated = server_handshake(
                conn,
                self._identity,
                self._trust_store,
            )
            session_key = authenticated.key
            peer_device_id = authenticated.peer_device_id
            offer = validate_offer(_recv_frame_json(conn, session_key))
            request = IncomingTransferRequest(
                transfer_id=offer.transfer_id,
                peer_device_id=peer_device_id,
                peer_ip=peer_ip,
                peer_name=(
                    self._peer_name_resolver(peer_device_id)
                    if self._peer_name_resolver is not None
                    else None
                ),
                files=offer.files,
                total_size=offer.total_size,
                message=offer.message,
                received_at=time.time(),
            )
            if self._incoming_manager is None:
                decision = IncomingRequestStatus.ACCEPTED
                reason = None
            else:
                self._incoming_manager.publish(request)
                decided = self._await_incoming_decision(
                    conn, session_key, offer.transfer_id
                )
                decision = decided.status
                reason = decided.reason
            accepted = decision == IncomingRequestStatus.ACCEPTED
            _send_frame(
                conn,
                session_key,
                build_response(offer.transfer_id, accepted, reason),
            )
            if not accepted:
                return
            conn.settimeout(IDLE_TRANSFER_TIMEOUT)
            self._receive_v3_session(conn, peer_ip, peer_device_id, session_key, offer)

        except (AuthenticationError, ProtocolError, InvalidTag) as e:
            log.warning("Rejected transfer session from %s: %s", peer_ip, e)
        except (ConnectionError, OSError, ValueError) as e:
            log.error("Session error from %s: %s", peer_ip, e)
        finally:
            conn.close()

    def _await_incoming_decision(
        self, conn: socket.socket, session_key: bytes, transfer_id: str
    ) -> IncomingTransferRequest:
        """Wait for UI input while also honoring an authenticated peer cancel."""
        deadline = time.monotonic() + self._approval_timeout
        while time.monotonic() < deadline:
            request = self._incoming_manager.get_request(transfer_id)
            if (
                request is not None
                and request.status != IncomingRequestStatus.PENDING_APPROVAL
            ):
                return request
            remaining = deadline - time.monotonic()
            readable, _, _ = select.select([conn], [], [], min(0.25, remaining))
            if readable:
                try:
                    control = _recv_frame_json(conn, session_key)
                except (ConnectionError, OSError):
                    self._incoming_manager.cancel_request(
                        transfer_id, "Peer disconnected"
                    )
                    raise
                if control != {"type": "cancel", "transfer_id": transfer_id}:
                    self._incoming_manager.reject_request(
                        transfer_id, "Invalid transfer protocol"
                    )
                    raise ProtocolError("File payload sent before approval")
                self._incoming_manager.cancel_request(transfer_id, "Cancelled by peer")
        return self._incoming_manager.wait_for_decision(transfer_id, 0)

    def _receive_v3_session(
        self,
        conn: socket.socket,
        peer_ip: str,
        peer_device_id: str,
        session_key: bytes,
        offer: TransferOffer,
    ) -> None:
        """Resume and receive a validated v3 offer into hidden partial files."""
        query = _recv_frame_json(conn, session_key)
        self._partials.validate_resume_query(query, offer)
        states = self._partials.prepare(offer)
        _send_frame(
            conn,
            session_key,
            {
                "type": "resume_state",
                "transfer_id": offer.transfer_id,
                "files": [
                    {"file_id": item.file_id, "offset": states[item.file_id].offset}
                    for item in offer.files
                ],
            },
        )

        for offered in offer.files:
            control = _recv_frame_json(conn, session_key)
            if control.get("type") == "cancel":
                raise TransferCancelled("Transfer cancelled by peer")
            if (
                control.get("type") != "file_start"
                or control.get("transfer_id") != offer.transfer_id
                or control.get("file_id") != offered.file_id
            ):
                raise ProtocolError("Invalid file start")
            state = states[offered.file_id]
            info = self._get_or_create_v3_transfer(
                transfer_id=offer.transfer_id,
                file_id=offered.file_id,
                filename=offered.name,
                filesize=offered.size,
                peer_ip=peer_ip,
                peer_device_id=peer_device_id,
                resume_offset=state.offset,
                message=offer.message,
                sha256=offered.sha256,
            )
            try:
                if state.final_path is None:
                    info.status = TransferStatus.ACTIVE
                    self._receive_v3_file_data(
                        conn, session_key, offer, offered, state.partial_path, info
                    )
                    actual_hash = _sha256_of_file(state.partial_path)
                    if actual_hash != offered.sha256:
                        _send_frame(
                            conn,
                            session_key,
                            {
                                "type": "file_result",
                                "transfer_id": offer.transfer_id,
                                "file_id": offered.file_id,
                                "ok": False,
                                "reason": "SHA-256 verification failed",
                            },
                        )
                        raise ProtocolError("SHA-256 verification failed")
                    final_path = commit_partial_file(
                        state.partial_path, self._receive_dir, offered.name
                    )
                    self._partials.mark_completed(offer, offered.file_id, final_path)
                else:
                    final_path = state.final_path
                    self._expect_file_end(conn, session_key, offer, offered.file_id)

                info.bytes_transferred = offered.size
                info.final_path = str(final_path)
                info.status = TransferStatus.COMPLETE
                info.completed_at = time.time()
                _send_frame(
                    conn,
                    session_key,
                    {
                        "type": "file_result",
                        "transfer_id": offer.transfer_id,
                        "file_id": offered.file_id,
                        "ok": True,
                        "name": final_path.name,
                    },
                )
                self._notify()
                if self._on_file_received:
                    try:
                        self._on_file_received(info)
                    except (RuntimeError, TypeError, ValueError):
                        log.exception("File-received callback failed")
            except TransferCancelled as error:
                info.status = TransferStatus.CANCELLED
                info.error = str(error)
                info.completed_at = time.time()
                self._notify()
                return
            except (ProtocolError, InvalidTag, ValueError) as error:
                info.status = TransferStatus.FAILED
                info.error = str(error)
                info.completed_at = time.time()
                self._notify()
                raise
            except (ConnectionError, OSError, TimeoutError):
                info.status = TransferStatus.INTERRUPTED
                info.error = "Connection interrupted"
                self._notify()
                raise

        final = _recv_frame_json(conn, session_key)
        if final != {"type": "fin", "transfer_id": offer.transfer_id}:
            raise ProtocolError("Invalid session finish")
        _send_frame(
            conn,
            session_key,
            {"type": "session_complete", "transfer_id": offer.transfer_id},
        )
        self._partials.complete_session(offer.transfer_id)

    def _receive_v3_file_data(
        self,
        conn: socket.socket,
        session_key: bytes,
        offer: TransferOffer,
        offered,
        partial_path: Path,
        info: TransferInfo,
    ) -> None:
        partial_path.parent.mkdir(parents=True, exist_ok=True)
        mode = "r+b" if partial_path.exists() else "wb"
        with open(partial_path, mode) as file_handle:
            file_handle.seek(info.bytes_transferred)
            index = info.bytes_transferred // CHUNK_SIZE
            while info.bytes_transferred < offered.size:
                control = _recv_frame_json(conn, session_key)
                if control.get("type") == "cancel":
                    if control.get("transfer_id") != offer.transfer_id:
                        raise ProtocolError("Cancel transfer ID mismatch")
                    raise TransferCancelled("Transfer cancelled by peer")
                remaining = offered.size - info.bytes_transferred
                declared_size = control.get("size")
                if (
                    control.get("type") != "chunk"
                    or control.get("transfer_id") != offer.transfer_id
                    or control.get("file_id") != offered.file_id
                    or control.get("index") != index
                    or control.get("offset") != info.bytes_transferred
                    or isinstance(declared_size, bool)
                    or not isinstance(declared_size, int)
                    or not 0 < declared_size <= min(CHUNK_SIZE, remaining)
                ):
                    raise ProtocolError("Invalid chunk metadata")
                conn.settimeout(CHUNK_TIMEOUT)
                plaintext = _recv_frame_bytes(conn, session_key)
                conn.settimeout(IDLE_TRANSFER_TIMEOUT)
                if len(plaintext) != declared_size:
                    raise ProtocolError("Chunk length mismatch")
                file_handle.write(plaintext)
                info.bytes_transferred += len(plaintext)
                info.bytes_transferred_this_attempt += len(plaintext)
                index += 1
                self._notify()
        self._expect_file_end(conn, session_key, offer, offered.file_id)

    @staticmethod
    def _expect_file_end(
        conn: socket.socket,
        session_key: bytes,
        offer: TransferOffer,
        file_id: str,
    ) -> None:
        control = _recv_frame_json(conn, session_key)
        if control != {
            "type": "file_end",
            "transfer_id": offer.transfer_id,
            "file_id": file_id,
        }:
            raise ProtocolError("Invalid file finish")

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
            if info.transfer_id and info.file_id:
                key = (info.transfer_id, info.file_id)
                if key in self._transfer_index:
                    return
                self._transfer_index[key] = info
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
        approval_timeout: float = TRANSFER_APPROVAL_TIMEOUT,
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
        self._approval_timeout = approval_timeout
        self._transfers: list[TransferInfo] = []
        self._lock = threading.Lock()
        self._cancel_events: dict[str, threading.Event] = {}

    # ── Public API ──────────────────────────────────────────────────

    def send(
        self,
        peer_ip: str,
        filepath: str,
        message: str | None = None,
    ) -> str:
        """Send a single file to a peer in a background thread."""
        return self.send_batch(peer_ip, [filepath], message=message)

    def send_batch(
        self,
        peer_ip: str,
        filepaths: list[str],
        message: str | None = None,
    ) -> str:
        """Send a batch of files to a peer in a single TCP session.

        Args:
            peer_ip: Target peer's IP address.
            filepaths: List of file paths to send.
            message: Optional text message (sent in session header).
        """
        transfer_id = uuid.uuid4().hex
        cancel_event = threading.Event()
        with self._lock:
            self._cancel_events[transfer_id] = cancel_event
        thread = threading.Thread(
            target=self._batch_worker_entry,
            args=(peer_ip, filepaths, message, transfer_id, cancel_event),
            daemon=True,
            name=f"send-batch-{peer_ip}",
        )
        thread.start()
        return transfer_id

    def cancel_transfer(self, transfer_id: str) -> bool:
        """Cooperatively cancel a queued, approval-waiting, or active send."""
        with self._lock:
            event = self._cancel_events.get(transfer_id)
        if event is None:
            return False
        event.set()
        return True

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

    def _batch_worker_entry(
        self,
        peer_ip: str,
        filepaths: list[str],
        message: str | None,
        transfer_id: str,
        cancel_event: threading.Event,
    ) -> None:
        try:
            self._batch_worker(peer_ip, filepaths, message, transfer_id, cancel_event)
        finally:
            with self._lock:
                self._cancel_events.pop(transfer_id, None)

    def _batch_worker(
        self,
        peer_ip: str,
        filepaths: list[str],
        message: str | None,
        transfer_id: str,
        cancel_event: threading.Event,
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
        for index, (p, size, _) in enumerate(file_meta):
            info = TransferInfo(
                filename=p.name,
                filesize=size,
                direction=TransferDirection.SEND,
                peer_ip=peer_ip,
                status=(
                    TransferStatus.PENDING
                    if self._legacy_mode
                    else TransferStatus.PENDING_APPROVAL
                ),
                peer_device_id=self._peer_device_id(peer_ip),
                transfer_id=transfer_id,
                file_id=f"file-{index}",
                message=message,
                sha256=file_meta[index][2],
            )
            self._register_transfer(info)
            infos.append(info)

        # ── Retry loop ──
        for attempt in range(MAX_RETRIES + 1):
            if cancel_event.is_set():
                self._mark_cancelled(infos)
                return
            if attempt > 0:
                delay = RETRY_DELAYS[min(attempt - 1, len(RETRY_DELAYS) - 1)]
                log.info(
                    "Retry %d/%d for batch to %s (waiting %.1fs)",
                    attempt,
                    MAX_RETRIES,
                    peer_ip,
                    delay,
                )
                if cancel_event.wait(delay):
                    self._mark_cancelled(infos)
                    return
                for info in infos:
                    info.retry_count = attempt
                    info.status = TransferStatus.RESUMING

            try:
                self._send_session(
                    peer_ip,
                    file_meta,
                    infos,
                    message,
                    transfer_id,
                    cancel_event,
                )
                # If we get here, all files sent successfully
                return
            except TransferRejected as error:
                log.info("Transfer rejected by %s: %s", peer_ip, error)
                for info in infos:
                    info.status = TransferStatus.REJECTED
                    info.error = "Transfer rejected by peer."
                    info.completed_at = time.time()
                self._notify()
                return
            except ApprovalTimeout:
                for info in infos:
                    info.status = TransferStatus.FAILED
                    info.error = "Peer did not respond to transfer request."
                    info.completed_at = time.time()
                self._notify()
                return
            except TransferCancelled:
                self._mark_cancelled(infos)
                return
            except (AuthenticationError, ProtocolError) as e:
                log.warning("Transfer authentication failed for %s: %s", peer_ip, e)
                for info in infos:
                    info.status = TransferStatus.FAILED
                    info.error = "Transfer rejected."
                    info.completed_at = time.time()
                self._notify()
                return
            except (OSError, ConnectionError) as e:
                log.warning("Batch send attempt %d failed: %s", attempt + 1, e)
                for info in infos:
                    info.status = (
                        TransferStatus.FAILED
                        if attempt == MAX_RETRIES
                        else TransferStatus.INTERRUPTED
                    )
                    info.error = (
                        "Unable to connect to peer."
                        if attempt == MAX_RETRIES
                        else "Connection interrupted"
                    )
                    if attempt == MAX_RETRIES:
                        info.completed_at = time.time()
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
        transfer_id: str,
        cancel_event: threading.Event,
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
        sock.settimeout(CONNECT_TIMEOUT)

        try:
            sock.connect((peer_ip, self._port))

            if self._legacy_mode:
                session_key = self._key
            else:
                trusted_peer = self._resolve_trusted_peer(peer_ip)

                sock.settimeout(HANDSHAKE_TIMEOUT)
                authenticated = client_handshake(
                    sock,
                    self._identity,
                    trusted_peer,
                )

                session_key = authenticated.key

                offer_frame = {
                    "type": "transfer_offer",
                    "version": PROTOCOL_VERSION,
                    "transfer_id": transfer_id,
                    "count": len(file_meta),
                    "total_size": sum(size for _, size, _ in file_meta),
                    "files": [
                        {
                            "file_id": info.file_id,
                            "name": path.name,
                            "size": size,
                            "sha256": sha,
                        }
                        for (path, size, sha), info in zip(file_meta, infos)
                    ],
                }
                if message:
                    offer_frame["message"] = message
                _send_frame(sock, session_key, offer_frame)
                response = self._wait_for_approval(
                    sock, session_key, transfer_id, cancel_event
                )
                accepted, reason = validate_response(response, transfer_id)
                if not accepted:
                    if reason == "Transfer request expired":
                        raise ApprovalTimeout(reason)
                    raise TransferRejected(reason or "Rejected by user")
                for info in infos:
                    info.status = TransferStatus.ACCEPTED
                self._notify()
                sock.settimeout(IDLE_TRANSFER_TIMEOUT)
                self._send_v3_payload(
                    sock,
                    session_key,
                    validate_offer(offer_frame),
                    file_meta,
                    infos,
                    cancel_event,
                )
                return

            # Compatibility-only protocol-v2 framing.
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
                info.completed_at = time.time()
                log.info(
                    "Sent %s to %s (%.2f MB/s)", path.name, peer_ip, info.speed_mbps
                )
                self._notify()

            # ── FIN ──
            _send_frame(sock, session_key, {"type": "fin"})

        finally:
            sock.close()

    def _wait_for_approval(
        self,
        sock: socket.socket,
        session_key: bytes,
        transfer_id: str,
        cancel_event: threading.Event,
    ) -> dict:
        """Wait responsively so cancellation and approval expiry remain bounded."""
        deadline = time.monotonic() + self._approval_timeout
        sock.settimeout(min(0.25, self._approval_timeout))
        while time.monotonic() < deadline:
            if cancel_event.is_set():
                _send_frame(
                    sock,
                    session_key,
                    {"type": "cancel", "transfer_id": transfer_id},
                )
                raise TransferCancelled("Transfer cancelled")
            try:
                return _recv_frame_json(sock, session_key)
            except TimeoutError:
                continue
        raise ApprovalTimeout("Peer did not respond to transfer request")

    def _send_v3_payload(
        self,
        sock: socket.socket,
        session_key: bytes,
        offer: TransferOffer,
        file_meta: list[tuple[Path, int, str]],
        infos: list[TransferInfo],
        cancel_event: threading.Event,
    ) -> None:
        """Negotiate resume offsets and stream explicitly numbered v3 chunks."""
        file_descriptions = [
            {
                "file_id": offered.file_id,
                "name": offered.name,
                "size": offered.size,
                "sha256": offered.sha256,
            }
            for offered in offer.files
        ]
        _send_frame(
            sock,
            session_key,
            {
                "type": "resume_query",
                "transfer_id": offer.transfer_id,
                "files": file_descriptions,
            },
        )
        offsets = PartialTransferStore.validate_resume_state(
            _recv_frame_json(sock, session_key), offer
        )

        for (path, size, _sha), info, offered in zip(file_meta, infos, offer.files):
            offset = offsets[offered.file_id]
            info.resume_offset = offset
            info.bytes_transferred = offset
            info.bytes_transferred_this_attempt = 0
            info.status = TransferStatus.RESUMING if offset else TransferStatus.ACTIVE
            self._notify()
            _send_frame(
                sock,
                session_key,
                {
                    "type": "file_start",
                    "transfer_id": offer.transfer_id,
                    "file_id": offered.file_id,
                },
            )
            with open(path, "rb") as file_handle:
                file_handle.seek(offset)
                index = offset // CHUNK_SIZE
                while info.bytes_transferred < size:
                    if cancel_event.is_set():
                        _send_frame(
                            sock,
                            session_key,
                            {"type": "cancel", "transfer_id": offer.transfer_id},
                        )
                        raise TransferCancelled("Transfer cancelled")
                    raw = file_handle.read(CHUNK_SIZE)
                    if not raw:
                        raise ProtocolError("Source file changed during transfer")
                    _send_frame(
                        sock,
                        session_key,
                        {
                            "type": "chunk",
                            "transfer_id": offer.transfer_id,
                            "file_id": offered.file_id,
                            "index": index,
                            "offset": info.bytes_transferred,
                            "size": len(raw),
                        },
                    )
                    _send_frame(sock, session_key, raw)
                    info.bytes_transferred += len(raw)
                    info.bytes_transferred_this_attempt += len(raw)
                    index += 1
                    self._report_progress(path, info, size)
            _send_frame(
                sock,
                session_key,
                {
                    "type": "file_end",
                    "transfer_id": offer.transfer_id,
                    "file_id": offered.file_id,
                },
            )
            result = _recv_frame_json(sock, session_key)
            if (
                result.get("type") != "file_result"
                or result.get("transfer_id") != offer.transfer_id
                or result.get("file_id") != offered.file_id
                or result.get("ok") is not True
            ):
                raise ProtocolError("Receiver failed file verification")
            info.status = TransferStatus.COMPLETE
            info.completed_at = time.time()
            self._notify()

        _send_frame(
            sock,
            session_key,
            {"type": "fin", "transfer_id": offer.transfer_id},
        )
        result = _recv_frame_json(sock, session_key)
        if result != {
            "type": "session_complete",
            "transfer_id": offer.transfer_id,
        }:
            raise ProtocolError("Invalid session completion")

    def _report_progress(self, path: Path, info: TransferInfo, size: int) -> None:
        if self._on_progress:
            try:
                self._on_progress(path.name, info.bytes_transferred, size)
            except (RuntimeError, TypeError, ValueError):
                log.exception("Transfer progress callback failed")
        self._notify()

    def _mark_cancelled(self, infos: list[TransferInfo]) -> None:
        for info in infos:
            if info.status != TransferStatus.COMPLETE:
                info.status = TransferStatus.CANCELLED
                info.error = "Cancelled by user"
                info.completed_at = time.time()
        self._notify()

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
        on_incoming_request: Callable[[IncomingTransferRequest], None] | None = None,
        history_store: TransferHistoryStore | None = None,
        identity: DeviceIdentity | None = None,
        trust_store: TrustStore | None = None,
        peer_resolver: Callable[[str], object | None] | None = None,
        legacy_mode: bool | None = None,
        approval_timeout: float = TRANSFER_APPROVAL_TIMEOUT,
    ):
        self._port = transfer_port
        self._on_update = on_transfer_update
        self._on_incoming_request = on_incoming_request
        self._history = history_store
        self._history_lock = threading.RLock()
        self._persisted_progress: dict[str, tuple[float, int, str]] = {}
        self._peer_resolver = peer_resolver
        self._incoming = IncomingRequestManager(
            self._handle_incoming_request,
            self._handle_request_decision,
        )

        self._server = FileServer(
            port=transfer_port,
            receive_dir=receive_dir,
            passphrase=passphrase,
            on_transfer_update=self._handle_transfer_update,
            on_file_received=on_file_received,
            identity=identity,
            trust_store=trust_store,
            legacy_mode=legacy_mode,
            incoming_manager=None if legacy_mode else self._incoming,
            peer_name_resolver=self._resolve_peer_name(peer_resolver),
            approval_timeout=approval_timeout,
        )
        self._client = FileClient(
            port=transfer_port,
            passphrase=passphrase,
            on_transfer_update=self._handle_transfer_update,
            on_progress=on_progress,
            identity=identity,
            trust_store=trust_store,
            peer_resolver=peer_resolver,
            legacy_mode=legacy_mode,
            approval_timeout=approval_timeout,
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
    ) -> str:
        """Send one or more files to a peer as a single session.

        Args:
            peer_ip: Target peer's IP address.
            filepath: Single path or list of paths.
            message: Optional message sent in the session header.
        """
        paths = [filepath] if isinstance(filepath, str) else list(filepath)
        return self._client.send_batch(peer_ip, paths, message=message)

    def get_transfers(self) -> list[TransferInfo]:
        """Return combined transfer records from server + client."""
        return self._server.get_transfers() + self._client.get_transfers()

    def get_pending_requests(self) -> list[IncomingTransferRequest]:
        return self._incoming.get_pending_requests()

    def get_incoming_request(self, transfer_id: str) -> IncomingTransferRequest | None:
        return self._incoming.get_request(transfer_id)

    def accept_request(self, transfer_id: str) -> bool:
        return self._incoming.accept_request(transfer_id)

    def reject_request(self, transfer_id: str) -> bool:
        return self._incoming.reject_request(transfer_id)

    def cancel_incoming_request(
        self, transfer_id: str, reason: str = "Cancelled"
    ) -> bool:
        return self._incoming.cancel_request(transfer_id, reason)

    def cancel_transfer(self, transfer_id: str) -> bool:
        """Cooperatively cancel an outgoing transfer session."""
        return self._client.cancel_transfer(transfer_id)

    @property
    def history_store(self) -> TransferHistoryStore | None:
        return self._history

    def _handle_incoming_request(self, request: IncomingTransferRequest) -> None:
        if self._history is not None:
            self._history.create_transfer(
                TransferRecord(
                    transfer_id=request.transfer_id,
                    peer_device_id=request.peer_device_id,
                    peer_ip=request.peer_ip,
                    peer_hostname=request.peer_name,
                    direction=TransferDirection.RECV.value,
                    status=TransferStatus.PENDING_APPROVAL.value,
                    message=request.message,
                    file_count=len(request.files),
                    total_size=request.total_size,
                    bytes_transferred=0,
                    started_at=request.received_at,
                ),
                [
                    TransferFileRecord(
                        id=None,
                        transfer_id=request.transfer_id,
                        file_id=item.file_id,
                        filename=item.name,
                        final_path=None,
                        filesize=item.size,
                        sha256=item.sha256,
                        bytes_transferred=0,
                        status=TransferStatus.PENDING_APPROVAL.value,
                    )
                    for item in request.files
                ],
            )
        if self._on_incoming_request is not None:
            self._on_incoming_request(request)

    def _handle_request_decision(self, request: IncomingTransferRequest) -> None:
        if self._history is None:
            return
        status = {
            IncomingRequestStatus.ACCEPTED: TransferStatus.ACCEPTED.value,
            IncomingRequestStatus.REJECTED: TransferStatus.REJECTED.value,
            IncomingRequestStatus.EXPIRED: TransferStatus.FAILED.value,
            IncomingRequestStatus.CANCELLED: TransferStatus.CANCELLED.value,
        }.get(request.status, TransferStatus.PENDING_APPROVAL.value)
        error = request.reason
        if request.status == IncomingRequestStatus.EXPIRED and not error:
            error = "Transfer request expired"
        child_status = {
            IncomingRequestStatus.REJECTED: TransferStatus.REJECTED.value,
            IncomingRequestStatus.EXPIRED: TransferStatus.FAILED.value,
            IncomingRequestStatus.CANCELLED: TransferStatus.CANCELLED.value,
        }.get(request.status)
        self._history.update_transfer(
            request.transfer_id,
            status=status,
            completed_at=(
                time.time()
                if request.status
                in {
                    IncomingRequestStatus.REJECTED,
                    IncomingRequestStatus.EXPIRED,
                    IncomingRequestStatus.CANCELLED,
                }
                else None
            ),
            error=error,
            file_status=child_status,
        )

    def _handle_transfer_update(self) -> None:
        """Persist throttled progress, then fan out to the UI callback."""
        if self._history is not None:
            with self._history_lock:
                self._persist_runtime_transfers()
        if self._on_update is not None:
            self._on_update()

    @staticmethod
    def _file_status_rank(status: TransferStatus) -> int:
        ranking = {
            TransferStatus.COMPLETE: 100,
            TransferStatus.CANCELLED: 90,
            TransferStatus.FAILED: 80,
            TransferStatus.REJECTED: 70,
            TransferStatus.ACTIVE: 60,
            TransferStatus.RESUMING: 50,
            TransferStatus.INTERRUPTED: 40,
            TransferStatus.ACCEPTED: 30,
            TransferStatus.PENDING_APPROVAL: 20,
            TransferStatus.PENDING: 10,
        }
        return ranking.get(status, 0)

    @classmethod
    def _resolve_authoritative_file_info(
        cls, items: list[TransferInfo]
    ) -> TransferInfo:
        if len(items) == 1:
            return items[0]
        best = max(
            items,
            key=lambda x: (
                cls._file_status_rank(x.status),
                x.bytes_transferred,
                x.started_at,
            ),
        )
        max_bytes = max(item.bytes_transferred for item in items)
        if best.status == TransferStatus.COMPLETE:
            max_bytes = best.filesize
        completed_at = (
            max((item.completed_at or 0 for item in items), default=0) or None
        )
        final_path = next(
            (item.final_path for item in items if item.final_path), best.final_path
        )
        return TransferInfo(
            filename=best.filename,
            filesize=best.filesize,
            direction=best.direction,
            peer_ip=best.peer_ip,
            status=best.status,
            bytes_transferred=max_bytes,
            started_at=min(item.started_at for item in items),
            error=best.error if best.status != TransferStatus.COMPLETE else None,
            retry_count=max(item.retry_count for item in items),
            peer_device_id=best.peer_device_id,
            transfer_id=best.transfer_id,
            file_id=best.file_id,
            resume_offset=max(item.resume_offset for item in items),
            bytes_transferred_this_attempt=best.bytes_transferred_this_attempt,
            completed_at=completed_at
            if best.status
            in {
                TransferStatus.COMPLETE,
                TransferStatus.FAILED,
                TransferStatus.CANCELLED,
                TransferStatus.REJECTED,
            }
            else None,
            message=best.message,
            sha256=best.sha256,
            final_path=final_path,
        )

    def _persist_runtime_transfers(self) -> None:
        grouped: dict[str, list[TransferInfo]] = {}
        for info in self.get_transfers():
            grouped.setdefault(info.transfer_id, []).append(info)
        terminal = {
            TransferStatus.COMPLETE,
            TransferStatus.FAILED,
            TransferStatus.REJECTED,
            TransferStatus.CANCELLED,
        }
        now = time.monotonic()
        for transfer_id, raw_infos in grouped.items():
            # Deduplicate by logical file: (transfer_id + file_id/filename + direction)
            file_groups: dict[tuple[str, str], list[TransferInfo]] = {}
            for item in raw_infos:
                file_key = (item.file_id or item.filename, item.direction.value)
                file_groups.setdefault(file_key, []).append(item)

            infos = [
                self._resolve_authoritative_file_info(items)
                for items in file_groups.values()
            ]

            status = self._aggregate_status(infos)
            existing = self._history.get_transfer(transfer_id)
            if (
                existing is not None
                and existing.status == TransferStatus.COMPLETE.value
            ):
                status = TransferStatus.COMPLETE
            elif (
                status == TransferStatus.COMPLETE
                and existing is not None
                and existing.file_count > len(infos)
            ):
                status = TransferStatus.ACTIVE
            byte_count = sum(item.bytes_transferred for item in infos)
            if status == TransferStatus.COMPLETE and existing is not None:
                byte_count = max(byte_count, existing.bytes_transferred)
            previous = self._persisted_progress.get(transfer_id)
            should_flush = (
                previous is None
                or previous[2] != status.value
                or status in terminal
                or byte_count - previous[1] >= 4 * 1024 * 1024
                or now - previous[0] >= 2.0
            )
            if not should_flush:
                continue
            peer = (
                self._peer_resolver(infos[0].peer_ip)
                if self._peer_resolver is not None
                else None
            )
            record = TransferRecord(
                transfer_id=transfer_id,
                peer_device_id=infos[0].peer_device_id,
                peer_ip=infos[0].peer_ip,
                peer_hostname=getattr(peer, "hostname", None),
                direction=infos[0].direction.value,
                status=status.value,
                message=infos[0].message,
                file_count=max(len(infos), existing.file_count if existing else 0),
                total_size=max(
                    sum(item.filesize for item in infos),
                    existing.total_size if existing else 0,
                ),
                bytes_transferred=byte_count,
                started_at=min(item.started_at for item in infos),
                completed_at=max((item.completed_at or 0 for item in infos), default=0)
                or (existing.completed_at if existing else None)
                or None,
                error=next((item.error for item in infos if item.error), None)
                if status != TransferStatus.COMPLETE
                else None,
            )
            files = [
                TransferFileRecord(
                    id=None,
                    transfer_id=transfer_id,
                    file_id=item.file_id or f"file-{index}",
                    filename=item.filename,
                    final_path=item.final_path,
                    filesize=item.filesize,
                    sha256=item.sha256,
                    bytes_transferred=item.bytes_transferred,
                    status=item.status.value,
                )
                for index, item in enumerate(infos)
            ]
            self._history.create_transfer(record, files)
            self._persisted_progress[transfer_id] = (
                now,
                byte_count,
                status.value,
            )

    @staticmethod
    def _aggregate_status(infos: list[TransferInfo]) -> TransferStatus:
        priorities = (
            TransferStatus.FAILED,
            TransferStatus.CANCELLED,
            TransferStatus.REJECTED,
            TransferStatus.INTERRUPTED,
            TransferStatus.RESUMING,
            TransferStatus.ACTIVE,
            TransferStatus.ACCEPTED,
            TransferStatus.PENDING_APPROVAL,
            TransferStatus.PENDING,
        )
        for status in priorities:
            if any(item.status == status for item in infos):
                return status
        return TransferStatus.COMPLETE

    @staticmethod
    def _resolve_peer_name(
        resolver: Callable[[str], object | None] | None,
    ) -> Callable[[str], str | None] | None:
        if resolver is None:
            return None

        def get_name(device_id: str) -> str | None:
            peer = resolver(device_id)
            return getattr(peer, "hostname", None) if peer is not None else None

        return get_name

    @property
    def file_server(self) -> FileServer:
        return self._server

    @property
    def file_client(self) -> FileClient:
        return self._client
