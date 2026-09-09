"""Malformed-input, replay, trust, and filesystem race regressions."""

from __future__ import annotations

import json
import threading
import time
from dataclasses import asdict

import pytest

from mesh_pulse.core.discovery import (
    DiscoveryReplayCache,
    build_discovery_beacon,
    parse_discovery_beacon,
)
from mesh_pulse.core.identity import DeviceIdentity
from mesh_pulse.core.resume import commit_partial_file
from mesh_pulse.core.session import ProtocolError
from mesh_pulse.core.transfer import FileClient
from mesh_pulse.core.transfer_protocol import (
    validate_chunk_control,
    validate_filename,
    validate_offer,
)
from mesh_pulse.core.trust import TrustStore
from mesh_pulse.utils.config import MAX_CONCURRENT_TRANSFER_SESSIONS


def test_signed_discovery_freshness_and_replay(tmp_path):
    identity = DeviceIdentity.load_or_create(tmp_path / "identity")
    cache = DiscoveryReplayCache()
    now = time.time()
    fresh = build_discovery_beacon(identity, timestamp=now)
    assert parse_discovery_beacon(fresh, "192.0.2.10", now=now, replay_cache=cache)
    assert (
        parse_discovery_beacon(fresh, "192.0.2.99", now=now, replay_cache=cache) is None
    )
    subsequent = build_discovery_beacon(identity, timestamp=now + 0.1)
    assert parse_discovery_beacon(
        subsequent, "192.0.2.10", now=now + 0.1, replay_cache=cache
    )


@pytest.mark.parametrize("offset", [-31, 6])
def test_signed_discovery_rejects_stale_or_future(tmp_path, offset):
    identity = DeviceIdentity.load_or_create(tmp_path / "identity")
    now = time.time()
    beacon = build_discovery_beacon(identity, timestamp=now + offset)
    assert parse_discovery_beacon(beacon, "192.0.2.10", now=now) is None


def test_replay_cache_is_bounded():
    cache = DiscoveryReplayCache(max_devices=2, max_per_device=2, ttl=30)
    for device in range(4):
        for nonce in range(4):
            assert cache.check_and_add(
                f"mp-{device:08x}", f"nonce-{nonce}", now=100 + device
            )
    assert cache.size <= 4


def test_one_corrupt_trust_record_does_not_erase_valid_record(tmp_path):
    identity = DeviceIdentity.load_or_create(tmp_path / "valid")
    path = tmp_path / "trust.json"
    store = TrustStore(path)
    expected = store.trust(identity.device_id, "valid-peer", identity.public_key)
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["devices"]["mp-deadbeef"] = {
        **asdict(expected),
        "device_id": "mp-deadbeef",
    }
    path.write_text(json.dumps(payload), encoding="utf-8")

    reopened = TrustStore(path)
    assert reopened.get(identity.device_id) == expected
    assert reopened.get("mp-deadbeef") is None


@pytest.mark.parametrize(
    "filename",
    ["../file", "folder/file", r"C:\Windows\file", "/etc/passwd", "CON", "x\x00y"],
)
def test_portable_filename_validation_rejects_unsafe_names(filename):
    with pytest.raises(ProtocolError):
        validate_filename(filename)


def test_offer_rejects_duplicate_file_ids_and_bool_sizes():
    common = {
        "type": "transfer_offer",
        "version": 3,
        "transfer_id": "a" * 32,
        "count": 2,
        "total_size": 2,
        "files": [
            {"file_id": "same", "name": "a.txt", "size": 1, "sha256": "0" * 64},
            {"file_id": "same", "name": "b.txt", "size": 1, "sha256": "1" * 64},
        ],
    }
    with pytest.raises(ProtocolError):
        validate_offer(common)
    common["count"] = 1
    common["files"] = [
        {"file_id": "a", "name": "a.txt", "size": True, "sha256": "0" * 64}
    ]
    common["total_size"] = True
    with pytest.raises(ProtocolError):
        validate_offer(common)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("index", True),
        ("index", -1),
        ("index", 2),
        ("offset", True),
        ("offset", -1),
        ("offset", 65),
        ("size", True),
        ("size", 0),
        ("size", 65 * 1024),
        ("file_id", "wrong"),
        ("transfer_id", "b" * 32),
    ],
)
def test_impossible_chunk_metadata_is_rejected(field, value):
    payload = {
        "type": "chunk",
        "transfer_id": "a" * 32,
        "file_id": "file-1",
        "index": 1,
        "offset": 64,
        "size": 16,
    }
    payload[field] = value
    with pytest.raises(ProtocolError):
        validate_chunk_control(
            payload,
            transfer_id="a" * 32,
            file_id="file-1",
            expected_index=1,
            expected_offset=64,
            remaining=16,
        )


def test_concurrent_collision_commits_never_overwrite(tmp_path):
    receive_dir = tmp_path / "received"
    receive_dir.mkdir()
    (receive_dir / "file.txt").write_bytes(b"existing")
    partials = []
    for index in range(2):
        partial = tmp_path / f"{index}.part"
        partial.write_bytes(f"new-{index}".encode())
        partials.append(partial)
    barrier = threading.Barrier(2)
    destinations = []

    def commit(partial):
        barrier.wait()
        destinations.append(commit_partial_file(partial, receive_dir, "file.txt"))

    workers = [threading.Thread(target=commit, args=(partial,)) for partial in partials]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=2)

    assert all(not worker.is_alive() for worker in workers)
    assert (receive_dir / "file.txt").read_bytes() == b"existing"
    assert len({path.name for path in destinations}) == 2
    assert {path.read_bytes() for path in destinations} == {b"new-0", b"new-1"}


def test_outgoing_transfer_workers_are_bounded(monkeypatch):
    client = FileClient(passphrase="explicit-legacy", legacy_mode=True)
    release = threading.Event()
    monkeypatch.setattr(client, "_batch_worker", lambda *_args: release.wait(2))
    for index in range(MAX_CONCURRENT_TRANSFER_SESSIONS):
        client.send("192.0.2.10", f"ignored-{index}")
    assert client.active_worker_count == MAX_CONCURRENT_TRANSFER_SESSIONS
    with pytest.raises(RuntimeError, match="session limit"):
        client.send("192.0.2.10", "one-too-many")
    release.set()
    deadline = time.monotonic() + 2
    while client.active_worker_count and time.monotonic() < deadline:
        time.sleep(0.01)
    client.shutdown()
    assert client.active_worker_count == 0
