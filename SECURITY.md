# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 1.0.x   | ✅ Yes             |

## Reporting a Vulnerability

If you discover a security vulnerability in Mesh-Pulse, please report it responsibly:

1. **Do NOT open a public GitHub issue.**
2. Email the maintainers directly with:
   - A description of the vulnerability
   - Steps to reproduce
   - Potential impact
3. You will receive an acknowledgement within **48 hours**.
4. A fix will be prioritized and released as a patch version.

## Security Considerations

Mesh-Pulse uses the following cryptographic primitives:

- **Fernet (AES-128-CBC + HMAC-SHA256)** for file transfer encryption
- **AES-256-GCM** (legacy backend) with PBKDF2-HMAC-SHA256 key derivation (480,000 iterations)
- Encryption keys are stored at `~/.mesh_pulse_key` with owner-only file permissions

### Known Limitations

- Peer discovery beacons are **unencrypted** UDP broadcasts. A network observer can see which hosts are running Mesh-Pulse.
- File transfers rely on both peers sharing the same encryption key. There is no key exchange protocol — the key must be distributed out-of-band.
- The application binds to `0.0.0.0` by default, accepting connections from any network interface.
