"""Validated protocol-v3 transfer offer and response controls."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from mesh_pulse.core.inbox import IncomingFile
from mesh_pulse.core.session import PROTOCOL_VERSION, ProtocolError
from mesh_pulse.utils.config import (
    MAX_FILE_SIZE,
    MAX_FILES_PER_SESSION,
    MAX_SESSION_SIZE,
)

TRANSFER_ID_PATTERN = re.compile(r"^[0-9a-f]{32}$")
FILE_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
MAX_TRANSFER_MESSAGE_LENGTH = 4096


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
        raw_name = raw_file.get("name")
        if not isinstance(raw_name, str) or not raw_name or len(raw_name) > 255:
            raise ProtocolError("Invalid filename")
        filename = Path(raw_name).name
        if filename in {"", ".", ".."} or filename != raw_name:
            raise ProtocolError("Invalid filename")
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
