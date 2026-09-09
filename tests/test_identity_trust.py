"""Persistent identity, trust decisions, and discovery validation tests."""

from __future__ import annotations

import base64
import json
import os
import stat

from mesh_pulse.core.discovery import (
    DISCOVERY_PROTOCOL,
    MAX_BEACON_SIZE,
    PeerDiscovery,
    PeerManager,
    _discovery_signed_bytes,
    parse_discovery_beacon,
)
from mesh_pulse.core.identity import (
    DeviceIdentity,
    device_id_from_public_key,
    fingerprint_from_public_key,
)
from mesh_pulse.core.trust import TrustStatus, TrustStore


def test_identity_generation_and_persistence(tmp_path):
    first = DeviceIdentity.load_or_create(tmp_path)
    second = DeviceIdentity.load_or_create(tmp_path)

    assert first.device_id.startswith("mp-")
    assert first.device_id == second.device_id
    assert first.public_key == second.public_key
    assert first.fingerprint == second.fingerprint
    assert first.verify(first.sign(b"mesh-pulse"), b"mesh-pulse")
    assert (tmp_path / "identity.key").is_file()
    assert (tmp_path / "identity.json").is_file()


def test_private_identity_file_is_user_only_where_supported(tmp_path):
    DeviceIdentity.load_or_create(tmp_path)
    if os.name != "nt":
        mode = stat.S_IMODE((tmp_path / "identity.key").stat().st_mode)
        assert mode == 0o600


def test_fingerprint_is_deterministic(tmp_path):
    identity = DeviceIdentity.load_or_create(tmp_path)
    assert fingerprint_from_public_key(identity.public_key) == identity.fingerprint
    assert identity.fingerprint == fingerprint_from_public_key(identity.public_key)
    assert len(identity.fingerprint.split()) == 4


def test_trust_store_persistence_trust_untrust_and_reject(tmp_path):
    identity = DeviceIdentity.load_or_create(tmp_path / "peer")
    path = tmp_path / "trusted_devices.json"
    store = TrustStore(path)

    store.trust(identity.device_id, "workstation", identity.public_key)
    reloaded = TrustStore(path)
    assert (
        reloaded.assess(identity.device_id, identity.public_key) == TrustStatus.TRUSTED
    )
    assert reloaded.get(identity.device_id).hostname == "workstation"

    assert reloaded.untrust(identity.device_id)
    assert reloaded.assess(identity.device_id, identity.public_key) == TrustStatus.NEW

    reloaded.reject(identity.device_id, "workstation", identity.public_key)
    assert (
        reloaded.assess(identity.device_id, identity.public_key) == TrustStatus.REJECTED
    )


def test_identity_key_change_is_not_silently_trusted(tmp_path):
    old_identity = DeviceIdentity.load_or_create(tmp_path / "old")
    new_identity = DeviceIdentity.load_or_create(tmp_path / "new")
    store = TrustStore(tmp_path / "trust.json")
    store.trust(old_identity.device_id, "peer", old_identity.public_key)

    # A known ID presenting different key material is suspicious even though a
    # legitimate key derives a different natural device ID.
    assert (
        store.assess(old_identity.device_id, new_identity.public_key)
        == TrustStatus.CHANGED
    )


def test_invalid_trust_store_does_not_crash(tmp_path):
    path = tmp_path / "trusted_devices.json"
    path.write_text("not-json", encoding="utf-8")
    store = TrustStore(path)
    assert store.all() == []


def _beacon(
    identity: DeviceIdentity,
    **overrides,
) -> bytes:
    payload = {
        "protocol": DISCOVERY_PROTOCOL,
        "transfer_protocol": 3,
        "device_id": identity.device_id,
        "hostname": "workstation",
        "ip": "203.0.113.200",
        "port": 5000,
        "public_key": identity.public_key,
        "timestamp": 1.0,
        "metrics": {
            "cpu_percent": 21,
            "ram_percent": 43,
        },
    }

    payload.update(overrides)

    payload["signature"] = base64.b64encode(
        identity.sign(_discovery_signed_bytes(payload))
    ).decode("ascii")

    return json.dumps(payload).encode()


def test_discovery_uses_udp_source_and_ignores_unknown_fields(tmp_path):
    identity = DeviceIdentity.load_or_create(tmp_path)
    parsed = parse_discovery_beacon(
        _beacon(identity, unknown={"ignored": True}), "192.0.2.12"
    )
    assert parsed is not None
    assert parsed["ip"] == "192.0.2.12"
    assert set(parsed["metrics"]) == {"cpu_percent", "ram_percent"}


def test_malformed_discovery_beacons_are_rejected(tmp_path):
    identity = DeviceIdentity.load_or_create(tmp_path)
    assert parse_discovery_beacon(b"{broken", "192.0.2.1") is None
    assert parse_discovery_beacon(b"x" * (MAX_BEACON_SIZE + 1), "192.0.2.1") is None
    assert parse_discovery_beacon(_beacon(identity, port=70000), "192.0.2.1") is None
    assert (
        parse_discovery_beacon(_beacon(identity, hostname="x" * 256), "192.0.2.1")
        is None
    )


def test_invalid_public_key_and_device_id_are_rejected(tmp_path):
    identity = DeviceIdentity.load_or_create(tmp_path)
    assert (
        parse_discovery_beacon(_beacon(identity, public_key="not-base64"), "192.0.2.1")
        is None
    )
    assert (
        parse_discovery_beacon(_beacon(identity, device_id="not-a-device"), "192.0.2.1")
        is None
    )


def test_peer_manager_exposes_changed_identity(tmp_path):
    old_identity = DeviceIdentity.load_or_create(tmp_path / "old")
    new_identity = DeviceIdentity.load_or_create(tmp_path / "new")
    store = TrustStore(tmp_path / "trust.json")
    store.trust(old_identity.device_id, "peer", old_identity.public_key)
    manager = PeerManager(trust_store=store)
    manager.update_peer(
        "peer",
        "192.0.2.5",
        5000,
        device_id=old_identity.device_id,
        public_key=new_identity.public_key,
    )
    assert manager.get_peer(old_identity.device_id).trust_status == TrustStatus.CHANGED


def test_new_peer_is_not_automatically_trusted(tmp_path):
    identity = DeviceIdentity.load_or_create(tmp_path / "peer")
    manager = PeerManager(trust_store=TrustStore(tmp_path / "trust.json"))
    manager.update_peer(
        "peer",
        "192.0.2.6",
        5000,
        device_id=identity.device_id,
        public_key=identity.public_key,
    )
    assert manager.get_peer(identity.device_id).trust_status == TrustStatus.NEW


def test_discovery_rejects_tampered_signed_beacon(tmp_path):
    identity = DeviceIdentity.load_or_create(tmp_path / "identity")

    payload = json.loads(_beacon(identity).decode())

    # Change signed content without re-signing it.
    payload["hostname"] = "attacker"

    tampered = json.dumps(payload).encode()

    assert (
        parse_discovery_beacon(
            tampered,
            "192.0.2.10",
        )
        is None
    )


def test_discovery_requires_device_id_public_key_binding(tmp_path):
    identity = DeviceIdentity.load_or_create(tmp_path / "identity")

    # Valid format, but not the ID derived from this key.
    forged = _beacon(
        identity,
        device_id="mp-deadbeef",
    )

    assert (
        parse_discovery_beacon(
            forged,
            "192.0.2.10",
        )
        is None
    )


def test_v3_discovery_advertises_transfer_v3(tmp_path):
    identity = DeviceIdentity.load_or_create(tmp_path / "identity")

    discovery = PeerDiscovery(
        identity=identity,
        transfer_protocol=3,
    )

    parsed = parse_discovery_beacon(
        discovery._build_beacon(),
        "192.0.2.10",
    )

    assert parsed is not None
    assert parsed["device_id"] == identity.device_id
    assert parsed["protocol_version"] == 3


def test_signed_identity_can_advertise_legacy_transfer_v2(tmp_path):
    identity = DeviceIdentity.load_or_create(tmp_path / "identity")

    discovery = PeerDiscovery(
        identity=identity,
        transfer_protocol=2,
    )

    parsed = parse_discovery_beacon(
        discovery._build_beacon(),
        "192.0.2.10",
    )

    assert parsed is not None

    # Discovery identity is still present and signed...
    assert parsed["device_id"] == identity.device_id

    # ...but file transfer mode is explicitly legacy.
    assert parsed["protocol_version"] == 2


def test_trust_store_rejects_mismatched_device_id_and_key(tmp_path):
    identity = DeviceIdentity.load_or_create(tmp_path / "identity")

    store = TrustStore(tmp_path / "trust.json")

    try:
        store.trust(
            "mp-deadbeef",
            "forged",
            identity.public_key,
        )
    except ValueError:
        pass
    else:
        raise AssertionError("TrustStore accepted a forged device ID")


def test_identity_metadata_cannot_override_derived_device_id(tmp_path):
    DeviceIdentity.load_or_create(tmp_path)

    metadata_path = tmp_path / "identity.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))

    metadata["device_id"] = "mp-deadbeef"

    metadata_path.write_text(
        json.dumps(metadata),
        encoding="utf-8",
    )

    repaired = DeviceIdentity.load_or_create(tmp_path)

    expected = device_id_from_public_key(repaired.public_key)

    assert repaired.device_id == expected
    assert repaired.device_id != "mp-deadbeef"
