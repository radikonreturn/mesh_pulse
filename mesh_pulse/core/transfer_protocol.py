"""Validated protocol-v3 transfer offer and response controls."""

from __future__ import annotations

import hashlib
import json
import os
import re
import socket
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath

from mesh_pulse.core.inbox import IncomingFile
from mesh_pulse.core.session import PROTOCOL_VERSION, ProtocolError
from mesh_pulse.utils.config import (
    CHUNK_SIZE,
    HEADER_MAX_SIZE,
    MAX_FILE_SIZE,
    MAX_FILES_PER_SESSION,
    MAX_SESSION_SIZE,
)
from mesh_pulse.utils.crypto import (
    decrypt_chunk,
    encrypt_chunk,
    pack_frame,
    unpack_frame,
)

TRANSFER_ID_PATTERN = re.compile(r"^[0-9a-f]{32}$")
FILE_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
MAX_TRANSFER_MESSAGE_LENGTH = 4096


def send_encrypted_frame(
    sock: socket.socket, key: bytes, payload: dict | bytes
) -> None:
    raw = (
        json.dumps(payload, separators=(",", ":")).encode("utf-8")
        if isinstance(payload, dict)
        else payload
    )
    sock.sendall(pack_frame(encrypt_chunk(raw, key)))


def receive_control_frame(sock: socket.socket, key: bytes) -> dict:
    encrypted = unpack_frame(sock, max_size=HEADER_MAX_SIZE + 64)
    raw = decrypt_chunk(encrypted, key)
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise ProtocolError("Invalid transfer control frame") from error
    if not isinstance(payload, dict):
        raise ProtocolError("Transfer control frame must be an object")
    return payload


def receive_data_frame(sock: socket.socket, key: bytes) -> bytes:
    encrypted = unpack_frame(sock, max_size=CHUNK_SIZE + 64)
    return decrypt_chunk(encrypted, key)


def validate_session_header(
    session: dict, expected_version: int
) -> tuple[int, str | None]:
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
    if message is not None and (
        not isinstance(message, str) or len(message) > MAX_TRANSFER_MESSAGE_LENGTH
    ):
        raise ProtocolError("Invalid transfer message")
    return count, message


def _is_reserved_filename(name: str) -> bool:
    if hasattr(os.path, "isreserved"):
        return os.path.isreserved(name)
    try:
        return PureWindowsPath(name).is_reserved()
    except Exception:
        return False


def sanitize_filename(value: str) -> str:
    """Validate remote file basenames defensively against path injection."""
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 255
        or len(value.encode("utf-8")) > 255
        or not value.isprintable()
        or value != value.rstrip(" .")
    ):
        raise ProtocolError("Invalid filename")
    windows_path = PureWindowsPath(value)
    if (
        Path(value).name != value
        or windows_path.name != value
        or _is_reserved_filename(value)
        or value in {".", ".."}
    ):
        raise ProtocolError("Invalid filename")
    return value


def validate_filename(value: object) -> str:
    """Validate a portable basename supplied by an untrusted peer."""
    if not isinstance(value, str):
        raise ProtocolError("Invalid filename")
    return sanitize_filename(value)


def validate_file_header(header: dict) -> tuple[str, int, str]:
    if header.get("type") != "file":
        raise ProtocolError("Expected file frame")
    raw_name = header.get("name")
    if (
        not isinstance(raw_name, str)
        or not raw_name
        or len(raw_name) > 255
        or len(raw_name.encode("utf-8")) > 1024
        or not raw_name.isprintable()
    ):
        raise ProtocolError("Invalid filename")
    # Explicit legacy-v2 compatibility: retain its basename sanitization while
    # v3 offers use strict portable-basename validation above.
    filename = Path(raw_name.replace("\\", "/")).name.rstrip(" .")
    if not filename or filename in {".", ".."}:
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


def sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as file_handle:
        for block in iter(lambda: file_handle.read(CHUNK_SIZE), b""):
            hasher.update(block)
    return hasher.hexdigest()


@dataclass(frozen=True)
class TransferOffer:
    transfer_id: str
    files: tuple[IncomingFile, ...]
    total_size: int
    message: str | None


def validate_transfer_id(value: object) -> str:
    if not isinstance(value, str) or not TRANSFER_ID_PATTERN.fullmatch(value):
        raise ProtocolError("Invalid transfer ID")
    return value


def validate_chunk_control(
    payload: object,
    *,
    transfer_id: str,
    file_id: str,
    expected_index: int,
    expected_offset: int,
    remaining: int,
) -> int:
    """Validate one bounded v3 chunk header and return its declared size."""
    if not isinstance(payload, dict) or payload.get("type") != "chunk":
        raise ProtocolError("Invalid chunk metadata")
    validate_transfer_id(transfer_id)
    if not FILE_ID_PATTERN.fullmatch(file_id):
        raise ProtocolError("Invalid file ID")
    index = payload.get("index")
    offset = payload.get("offset")
    size = payload.get("size")
    if (
        payload.get("transfer_id") != transfer_id
        or payload.get("file_id") != file_id
        or isinstance(index, bool)
        or not isinstance(index, int)
        or index < 0
        or index != expected_index
        or isinstance(offset, bool)
        or not isinstance(offset, int)
        or offset < 0
        or offset != expected_offset
        or isinstance(size, bool)
        or not isinstance(size, int)
        or not 0 < size <= min(CHUNK_SIZE, remaining)
    ):
        raise ProtocolError("Invalid chunk metadata")
    return size


def validate_offer(payload: object) -> TransferOffer:
    """Validate a bounded transfer offer before publishing it to the inbox."""
    if not isinstance(payload, dict) or payload.get("type") != "transfer_offer":
        raise ProtocolError("Expected transfer offer")
    if payload.get("version") != PROTOCOL_VERSION:
        raise ProtocolError("Protocol version mismatch")
    transfer_id = validate_transfer_id(payload.get("transfer_id"))
    raw_files = payload.get("files")
    count = payload.get("count")
    if (
        not isinstance(raw_files, list)
        or isinstance(count, bool)
        or not isinstance(count, int)
        or count != len(raw_files)
        or not 1 <= count <= MAX_FILES_PER_SESSION
    ):
        raise ProtocolError("Invalid file count")

    files: list[IncomingFile] = []
    seen_file_ids: set[str] = set()
    computed_total = 0
    for raw_file in raw_files:
        if not isinstance(raw_file, dict):
            raise ProtocolError("Invalid file metadata")
        file_id = raw_file.get("file_id")
        if (
            not isinstance(file_id, str)
            or not FILE_ID_PATTERN.fullmatch(file_id)
            or file_id in seen_file_ids
        ):
            raise ProtocolError("Invalid file ID")
        filename = validate_filename(raw_file.get("name"))
        size = raw_file.get("size")
        if (
            isinstance(size, bool)
            or not isinstance(size, int)
            or not 0 <= size <= MAX_FILE_SIZE
        ):
            raise ProtocolError("Invalid file size")
        digest = raw_file.get("sha256")
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise ProtocolError("Invalid SHA-256 digest")
        seen_file_ids.add(file_id)
        computed_total += size
        if computed_total > MAX_SESSION_SIZE:
            raise ProtocolError("Transfer session exceeds size limit")
        files.append(IncomingFile(file_id, filename, size, digest))

    total_size = payload.get("total_size")
    if (
        isinstance(total_size, bool)
        or not isinstance(total_size, int)
        or total_size != computed_total
    ):
        raise ProtocolError("Invalid total transfer size")
    message = payload.get("message")
    if message is not None and (
        not isinstance(message, str) or len(message) > MAX_TRANSFER_MESSAGE_LENGTH
    ):
        raise ProtocolError("Invalid transfer message")
    return TransferOffer(transfer_id, tuple(files), total_size, message)


def build_response(transfer_id: str, accepted: bool, reason: str | None = None) -> dict:
    payload: dict = {
        "type": "transfer_response",
        "transfer_id": validate_transfer_id(transfer_id),
        "accepted": accepted,
    }
    if reason:
        payload["reason"] = reason[:512]
    return payload


def validate_response(payload: object, transfer_id: str) -> tuple[bool, str | None]:
    if not isinstance(payload, dict) or payload.get("type") != "transfer_response":
        raise ProtocolError("Invalid transfer response")
    if payload.get("transfer_id") != validate_transfer_id(transfer_id):
        raise ProtocolError("Transfer response ID mismatch")
    accepted = payload.get("accepted")
    if not isinstance(accepted, bool):
        raise ProtocolError("Invalid transfer response")
    reason = payload.get("reason")
    if reason is not None and (not isinstance(reason, str) or len(reason) > 512):
        raise ProtocolError("Invalid transfer response reason")
    return accepted, reason
