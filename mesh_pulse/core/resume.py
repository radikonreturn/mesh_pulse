"""Protocol-v3 partial-file persistence and collision-safe completion."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import threading
import uuid
from dataclasses import dataclass
from pathlib import Path

from mesh_pulse.core.session import ProtocolError
from mesh_pulse.core.transfer_protocol import TransferOffer
from mesh_pulse.utils.logger import get_logger

log = get_logger(__name__)


def resolve_destination_collision(receive_dir: str | Path, filename: str) -> Path:
    """Return a path that does not currently exist, preserving the extension."""
    directory = Path(receive_dir).resolve()
    safe_name = Path(filename).name
    if safe_name in {"", ".", ".."} or safe_name != filename:
        raise ValueError("Invalid destination filename")
    suffix = "".join(Path(safe_name).suffixes)
    stem = safe_name[: -len(suffix)] if suffix else safe_name
    candidate = directory / safe_name
    index = 0
    while candidate.exists():
        index += 1
        candidate = directory / f"{stem} ({index}){suffix}"
    if candidate.parent.resolve() != directory:
        raise ValueError("Destination escapes receive directory")
    return candidate


def commit_partial_file(
    partial_path: Path, receive_dir: str | Path, filename: str
) -> Path:
    """Atomically expose a verified partial file without overwriting a peer file."""
    directory = Path(receive_dir).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    while True:
        destination = resolve_destination_collision(directory, filename)
        try:
            os.link(partial_path, destination)
            partial_path.unlink(missing_ok=True)
            return destination
        except FileExistsError:
            continue
        except (OSError, AttributeError) as link_error:
            # Fallback for filesystems that do not support hard links (EXDEV, EPERM, ENOTSUP, etc.)
            log.debug(
                "os.link failed (%s); falling back to safe copy-rename", link_error
            )
            break

    # Fallback path: copy verified partial to temporary file inside receive_dir, then atomic rename
    temp_path = directory / f".tmp-commit-{uuid.uuid4().hex}"
    try:
        with open(partial_path, "rb") as src, open(temp_path, "wb") as dst:
            shutil.copyfileobj(src, dst, length=65536)
            dst.flush()
            os.fsync(dst.fileno())

        while True:
            destination = resolve_destination_collision(directory, filename)
            try:
                if os.name == "nt":
                    try:
                        os.rename(temp_path, destination)
                        break
                    except FileExistsError:
                        continue

                if destination.exists():
                    continue
                os.replace(temp_path, destination)
                break
            except FileExistsError:
                continue

        partial_path.unlink(missing_ok=True)
        return destination
    finally:
        if temp_path.exists():
            temp_path.unlink(missing_ok=True)


@dataclass(frozen=True)
class ResumeFileState:
    file_id: str
    offset: int
    partial_path: Path | None
    final_path: Path | None = None


class PartialTransferStore:
    """Persist validated v3 partial metadata beneath the receive directory."""

    def __init__(self, receive_dir: str | Path) -> None:
        self._receive_dir = Path(receive_dir)
        self._root = self._receive_dir / ".mesh-pulse-partials"
        self._lock = threading.RLock()

    def prepare(self, offer: TransferOffer) -> dict[str, ResumeFileState]:
        """Return safe offsets, resetting only metadata-mismatched partials."""
        with self._lock:
            session_dir = self._root / offer.transfer_id
            session_dir.mkdir(parents=True, exist_ok=True)
            metadata_path = session_dir / "metadata.json"
            existing = self._read_metadata(metadata_path)
            result: dict[str, ResumeFileState] = {}
            stored_files = existing.get("files", {}) if existing else {}
            updated_files: dict[str, dict] = {}

            for offered in offer.files:
                partial = session_dir / f"{offered.file_id}.part"
                stored = stored_files.get(offered.file_id)
                expected = {
                    "name": offered.name,
                    "size": offered.size,
                    "sha256": offered.sha256,
                }
                final_path: Path | None = None
                offset = 0
                if isinstance(stored, dict) and all(
                    stored.get(key) == value for key, value in expected.items()
                ):
                    raw_final = stored.get("final_path")
                    if isinstance(raw_final, str):
                        candidate = Path(raw_final).resolve()
                        receive_root = self._receive_dir.resolve()
                        if (
                            candidate.is_relative_to(receive_root)
                            and candidate.is_file()
                            and candidate.stat().st_size == offered.size
                            and self._sha256(candidate) == offered.sha256
                        ):
                            final_path = candidate
                            offset = offered.size
                    elif partial.is_file():
                        offset = partial.stat().st_size
                        if offset > offered.size:
                            partial.unlink(missing_ok=True)
                            offset = 0
                else:
                    partial.unlink(missing_ok=True)

                record = dict(expected)
                if final_path is not None:
                    record["final_path"] = str(final_path)
                updated_files[offered.file_id] = record
                result[offered.file_id] = ResumeFileState(
                    offered.file_id,
                    offset,
                    None if final_path is not None else partial,
                    final_path,
                )

            self._atomic_write(
                metadata_path,
                {"transfer_id": offer.transfer_id, "files": updated_files},
            )
            return result

    def mark_completed(
        self, offer: TransferOffer, file_id: str, final_path: Path
    ) -> None:
        with self._lock:
            metadata_path = self._root / offer.transfer_id / "metadata.json"
            metadata = self._read_metadata(metadata_path)
            record = metadata.get("files", {}).get(file_id)
            if not isinstance(record, dict):
                raise ProtocolError("Missing resume metadata")
            record["final_path"] = str(final_path)
            self._atomic_write(metadata_path, metadata)

    def complete_session(self, transfer_id: str) -> None:
        with self._lock:
            session_dir = self._root / transfer_id
            if session_dir.is_dir():
                shutil.rmtree(session_dir)

    @staticmethod
    def validate_resume_query(payload: object, offer: TransferOffer) -> None:
        if not isinstance(payload, dict) or payload.get("type") != "resume_query":
            raise ProtocolError("Expected resume query")
        if payload.get("transfer_id") != offer.transfer_id:
            raise ProtocolError("Resume transfer ID mismatch")
        files = payload.get("files")
        expected = [
            {
                "file_id": item.file_id,
                "name": item.name,
                "size": item.size,
                "sha256": item.sha256,
            }
            for item in offer.files
        ]
        if files != expected:
            raise ProtocolError("Resume metadata mismatch")

    @staticmethod
    def validate_resume_state(payload: object, offer: TransferOffer) -> dict[str, int]:
        if not isinstance(payload, dict) or payload.get("type") != "resume_state":
            raise ProtocolError("Expected resume state")
        if payload.get("transfer_id") != offer.transfer_id:
            raise ProtocolError("Resume transfer ID mismatch")
        raw_files = payload.get("files")
        if not isinstance(raw_files, list) or len(raw_files) != len(offer.files):
            raise ProtocolError("Invalid resume state")
        expected = {item.file_id: item for item in offer.files}
        offsets: dict[str, int] = {}
        for item in raw_files:
            if not isinstance(item, dict) or item.get("file_id") not in expected:
                raise ProtocolError("Invalid resume file ID")
            file_id = item["file_id"]
            offset = item.get("offset")
            if (
                file_id in offsets
                or isinstance(offset, bool)
                or not isinstance(offset, int)
                or not 0 <= offset <= expected[file_id].size
            ):
                raise ProtocolError("Invalid resume offset")
            offsets[file_id] = offset
        if offsets.keys() != expected.keys():
            raise ProtocolError("Incomplete resume state")
        return offsets

    @staticmethod
    def _read_metadata(path: Path) -> dict:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        except (OSError, json.JSONDecodeError) as error:
            raise ProtocolError("Invalid resume metadata") from error
        if not isinstance(value, dict) or not isinstance(value.get("files"), dict):
            raise ProtocolError("Invalid resume metadata")
        return value

    @staticmethod
    def _atomic_write(path: Path, value: dict) -> None:
        temporary = path.with_suffix(".tmp")
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"))
        temporary.write_text(encoded, encoding="utf-8")
        os.replace(temporary, path)

    @staticmethod
    def _sha256(path: Path) -> str:
        hasher = hashlib.sha256()
        with path.open("rb") as file_handle:
            for block in iter(lambda: file_handle.read(1024 * 1024), b""):
                hasher.update(block)
        return hasher.hexdigest()
