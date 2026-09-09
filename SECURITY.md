# Security Policy

## Supported Versions

Only the latest release receives security updates.

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

---

## Reporting a Vulnerability

The Mesh-Pulse team takes the security of local networking and cryptographic implementations seriously.

If you believe you have discovered a security vulnerability in Mesh-Pulse:

1. **Do NOT open a public issue.** Public issues are visible to everyone and could put users at risk before a fix is available.
2. **Report via GitHub Private Vulnerability Reporting:**
   - Navigate to the repository's **Security** tab on GitHub.
   - Click **Report a vulnerability** to open an encrypted advisory draft directly with the project maintainers.
3. If GitHub Private Vulnerability Reporting is unavailable, open a minimal GitHub issue requesting a private security contact channel without including exploit code or vulnerability details.

### What to Include

Please provide:
- A clear description of the vulnerability and affected components.
- Step-by-step reproduction instructions or a minimal proof of concept.
- An assessment of the potential impact on confidentiality, integrity, or availability.

### Disclosure Policy

- Maintainers will review the report and provide an initial response.
- Once a fix is verified, a patch release will be published along with a security advisory acknowledging responsible disclosure.

---

## Security Architecture

For a detailed breakdown of the cryptographic primitives, Ed25519 identity derivation, transcript-bound X25519 session keys, AES-256-GCM framing, and threat model boundaries, see [docs/security.md](docs/security.md).
