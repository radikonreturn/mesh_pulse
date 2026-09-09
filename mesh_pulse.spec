# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path
import sys

block_cipher = None
repo_root = Path.cwd()

datas = [
    (
        str(repo_root / "mesh_pulse" / "tui" / "styles" / "dashboard.tcss"),
        "mesh_pulse/tui/styles",
    ),
    (
        str(repo_root / "mesh_pulse" / "py.typed"),
        "mesh_pulse",
    ),
]

hiddenimports = [
    "textual",
    "textual.app",
    "textual.containers",
    "textual.widgets",
    "textual.binding",
    "textual.screen",
    "cryptography",
    "cryptography.hazmat.primitives.ciphers.aead",
    "cryptography.hazmat.primitives.asymmetric.ed25519",
    "cryptography.hazmat.primitives.asymmetric.x25519",
    "cryptography.hazmat.primitives.kdf.hkdf",
    "cryptography.hazmat.primitives.kdf.pbkdf2",
    "psutil",
    "click",
    "platformdirs",
    "rich",
]

a = Analysis(
    [str(repo_root / "mesh_pulse" / "__main__.py")],
    pathex=[str(repo_root)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe_name = (
    "mesh-pulse-windows-x64.exe"
    if sys.platform.startswith("win")
    else "mesh-pulse-linux-x64"
)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name=exe_name,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
