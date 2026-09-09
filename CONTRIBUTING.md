# Contributing to Mesh-Pulse

Thank you for contributing to Mesh-Pulse!

---

## Development Setup

1. **Prerequisites**: Python 3.10, 3.11, 3.12, or 3.13.
2. **Clone & Virtual Environment**:
   ```bash
   git clone https://github.com/radikonreturn/mesh_pulse.git
   cd mesh_pulse
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .\.venv\Scripts\Activate.ps1
   ```
3. **Install Dependencies**:
   ```bash
   pip install --upgrade pip
   pip install -r requirements.txt
   pip install -e .
   pip install pytest ruff build wheel pyinstaller
   ```

---

## Code Quality & Testing

Before submitting a pull request, ensure all checks pass:

```bash
# Run test suite
pytest -q

# Code formatting and linting
ruff check .
ruff format --check .

# Auto-format code if needed
ruff format .
```

---

## Code Style & Architecture Guidelines

- **Standard Library & Typing**: Mesh-Pulse targets Python 3.10–3.13. Do not introduce Python 3.11+-only syntax without compatibility guards.
- **Layer Separation**: Core modules (`mesh_pulse/core/`) must remain strictly decoupled from the Textual TUI (`mesh_pulse/tui/`).
- **Cryptographic Security**: Do not weaken cryptographic primitives, nonce uniqueness, replay windows, or path sanitization. Any modifications to `identity.py`, `trust.py`, `session.py`, `transfer_protocol.py`, or `crypto.py` require thorough regression tests.

---

## Pull Request Expectations

1. Keep PRs focused on a single change or fix.
2. Include regression tests for bug fixes and new behavior.
3. Update relevant documentation in `docs/` and `README.md` if user-facing behavior changes.
4. Ensure the GitHub Actions CI test matrix (Python 3.10–3.13) passes completely.
