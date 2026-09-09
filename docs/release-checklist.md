# Release Checklist

This document details the step-by-step procedure required before tagging and publishing a release of Mesh-Pulse.

---

## 1. Quality & Test Validation

Ensure all tests pass and linters report clean:

```bash
# Run pytest test suite
pytest -q

# Verify code formatting and linting
ruff check .
ruff format --check .
```

---

## 2. Version Consistency Check

Confirm that the version strings are synchronized:

1. `mesh_pulse/__init__.py`: `__version__ = "X.Y.Z"`
2. `pyproject.toml`: `version = "X.Y.Z"`
3. Verify CLI report:
   ```bash
   python -m mesh_pulse --version
   ```

---

## 3. Package Build & Smoke Test

Build distribution wheel and source archive:

```bash
# Clean previous build artifacts
rm -rf build/ dist/ *.egg-info

# Build wheel and sdist
python -m build

# Verify wheel installation in an isolated virtual environment
python -m venv test_env
source test_env/bin/activate  # Or .\test_env\Scripts\Activate.ps1 on Windows
pip install dist/*.whl
mesh-pulse --help
mesh-pulse --version
deactivate
rm -rf test_env
```

---

## 4. Standalone Binary Build

Build standalone release executables with PyInstaller:

```bash
python scripts/build_standalone.py
```

Verify that the generated archive exists in `dist/`:
- Windows: `dist/mesh-pulse-windows-x64.zip`
- Linux: `dist/mesh-pulse-linux-x64.tar.gz`

Test execution:
```bash
./dist/mesh-pulse-windows-x64.exe --help
./dist/mesh-pulse-windows-x64.exe --version
```

---

## 5. Security & Documentation Review

1. Review `docs/security.md` and `SECURITY.md` for technical accuracy.
2. Confirm that `.gitignore` prevents committing keys, databases, or partial transfer files.
3. Update `CHANGELOG.md` with release notes under the release version heading.

---

## 6. Git Tag & GitHub Release

1. Commit all final release files:
   ```bash
   git add .
   git commit -m "Release v1.0.0"
   ```
2. Push to main:
   ```bash
   git push origin main
   ```
3. Create and push the release tag:
   ```bash
   git tag -a v1.0.0 -m "Mesh-Pulse v1.0.0"
   git push origin v1.0.0
   ```
4. Verify that the GitHub Actions Release workflow triggers:
   - Builds packages and standalone executables.
   - Creates a GitHub Release and attaches wheel, sdist, and standalone zip/tar.gz archives.
