# Mesh-Pulse security model

Mesh-Pulse is a local-network file-transfer utility. It assumes the host
operating system and the user's application-data directory are trusted. It
treats discovery packets, TCP connections, protocol metadata, and file bytes
as attacker-controlled.

## Identity and trust

Each installation creates a persistent Ed25519 signing identity. Its device ID
is derived from the public key, so a device ID cannot be rebound to another key
without being detected. The private key is stored with restrictive permissions
where the operating system supports them and is never sent over the network.

Pairing is an explicit local decision based on a human-comparable public-key
fingerprint. Discovery does not confer trust. A known device ID presenting a
different public key is reported as changed and must be paired again manually.
The trust store validates every record independently; a corrupt record is
skipped and never becomes trusted.

## Discovery

Protocol-v3 discovery beacons contain the public identity, a timestamp, and a
random nonce covered by an Ed25519 signature. Receivers reject beacons outside
a conservative clock-skew window and retain a bounded, expiring per-device
nonce cache to reject exact replays inside that window.

The signed identity answers “which installation sent this beacon.” The UDP
packet source answers “where this installation is currently reachable.” The
advertised IP is intentionally not authoritative because WSL, VPNs, and
multihomed hosts may advertise a different local address. A captured beacon
cannot relocate an already-observed identity by exact replay, but Mesh-Pulse is
not a routing protocol and does not defend against an attacker who controls the
local network path.

## Authenticated transfers

Normal transfers use protocol v3. Both peers sign fresh ephemeral X25519 keys
with their persistent Ed25519 identities. The transcript-bound X25519 secret is
expanded with HKDF-SHA256 into a new 256-bit AES-GCM session key for every TCP
connection. File data is not accepted until authentication succeeds and the
receiving user approves the authenticated transfer offer.

Encrypted frames use bounded lengths and fresh AES-GCM nonces. Authentication,
protocol, and cryptographic-tag failures are terminal rather than retried. The
UI receives short failure categories; cryptographic keys and plaintext content
are not logged.

## Files, integrity, and resume

Remote filenames must be portable basenames; paths, drive-qualified names,
reserved Windows device names, control characters, and oversized metadata are
rejected. Protocol-v3 data is streamed into hidden transfer-ID partials. Resume
offsets are accepted only when stored metadata and actual partial-file sizes
match the original offer. Every completed file receives a full SHA-256 check.

A verified partial is committed with a collision-safe name. Hard-link creation
is the primary atomic no-overwrite operation. On filesystems without hard-link
support, a complete hidden copy is made first and its final name is reserved
with exclusive creation before atomic replacement. Existing unrelated files
are not silently overwritten.

## Persistence and resource limits

Transfer history uses local SQLite with foreign keys, a schema version, bounded
queries, short-lived connections, and serialized access. History failures are
reported through logs but do not stop networking. Transfers left active by a
crash become interrupted on the next database open.

Discovery frames, handshakes, control frames, chunks, file/session sizes,
pending approvals, peer observations, replay entries, and simultaneous transfer
workers are bounded. Shutdown signals workers, closes sockets, expires pending
decisions, and joins network threads with finite waits.

## Legacy protocol v2

Protocol v2 remains available only when the user explicitly supplies a shared
passphrase. It is labeled legacy and does not silently replace a failed v3
authentication. V2 uses PBKDF2-derived shared-key encryption but does not offer
v3's persistent peer authentication, approval, or resume guarantees. Protocol
version mismatches are rejected.

## Out of scope

Mesh-Pulse does not provide internet relay, NAT traversal, anonymity, endpoint
malware protection, compromised-host protection, centralized revocation, or
protection against a user approving the wrong fingerprint. SHA-256 verifies
that received bytes match the authenticated offer; it does not establish that
the content itself is safe to open.
