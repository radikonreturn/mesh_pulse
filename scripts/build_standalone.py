"""Build standalone PyInstaller release executables and compressed archives."""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    dist_dir = repo_root / "dist"
    dist_dir.mkdir(exist_ok=True)

    is_windows = sys.platform.startswith("win")
    is_linux = sys.platform.startswith("linux")

    if is_windows:
        target_name = "mesh-pulse-windows-x64"
        exe_file = dist_dir / f"{target_name}.exe"
        archive_file = dist_dir / f"{target_name}.zip"
    elif is_linux:
        target_name = "mesh-pulse-linux-x64"
        exe_file = dist_dir / target_name
        archive_file = dist_dir / f"{target_name}.tar.gz"
    else:
        target_name = f"mesh-pulse-{sys.platform}-{platform.machine().lower()}"
        exe_file = dist_dir / target_name
        archive_file = dist_dir / f"{target_name}.tar.gz"

    print(f"Building standalone binary for {target_name}...")

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--clean",
        "--noconfirm",
        str(repo_root / "mesh_pulse.spec"),
    ]
    result = subprocess.run(cmd, cwd=str(repo_root))
    if result.returncode != 0:
        print(f"PyInstaller build failed with exit code {result.returncode}")
        return result.returncode

    if not exe_file.exists():
        print(f"Expected executable not found at: {exe_file}")
        return 1

    print(f"Standalone executable created at: {exe_file}")

    # Smoke test built executable
    print("Running smoke verification (--help, --version)...")
    help_res = subprocess.run([str(exe_file), "--help"], capture_output=True, text=True)
    if help_res.returncode != 0:
        print(f"Smoke test failed for --help: {help_res.stderr}")
        return 1
    print(f"--help output verified ({len(help_res.stdout)} chars)")

    ver_res = subprocess.run([str(exe_file), "--version"], capture_output=True, text=True)
    if ver_res.returncode != 0:
        print(f"Smoke test failed for --version: {ver_res.stderr}")
        return 1
    print(f"--version output verified: {ver_res.stdout.strip()}")

    # Package into archive
    print(f"Creating release archive at: {archive_file}")
    if is_windows:
        with zipfile.ZipFile(archive_file, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.write(exe_file, arcname="mesh-pulse.exe")
            # Also include LICENSE and README
            if (repo_root / "LICENSE").exists():
                zf.write(repo_root / "LICENSE", arcname="LICENSE")
            if (repo_root / "README.md").exists():
                zf.write(repo_root / "README.md", arcname="README.md")
    else:
        with tarfile.open(archive_file, "w:gz") as tf:
            tf.add(exe_file, arcname="mesh-pulse")
            if (repo_root / "LICENSE").exists():
                tf.add(repo_root / "LICENSE", arcname="LICENSE")
            if (repo_root / "README.md").exists():
                tf.add(repo_root / "README.md", arcname="README.md")

    print(f"Successfully generated archive: {archive_file} ({archive_file.stat().st_size:,} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
