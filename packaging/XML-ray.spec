# -*- mode: python ; coding: utf-8 -*-
# PyInstaller recipe for XML-ray. Built by builder/release_manager.py, or manually:
#   python -m PyInstaller packaging/XML-ray.spec --noconfirm --distpath dist --workpath build
import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules

ROOT = Path(SPECPATH).parent
# keyring picks its storage backend at run time (Windows Credential Manager on Windows),
# so PyInstaller has to be told to bundle the backends explicitly.
HIDDEN = ["defusedxml.ElementTree"] + collect_submodules("keyring.backends")
if sys.platform == "win32":
    HIDDEN.append("win32ctypes.core")

a = Analysis(
    [str(ROOT / "run.py")],
    pathex=[str(ROOT)],
    datas=[(str(ROOT / "xmlray" / "assets"), "xmlray/assets")],
    hiddenimports=HIDDEN,
    excludes=["tkinter", "PySide6.QtWebEngineCore", "PySide6.QtWebEngineWidgets",
              "PySide6.Qt3DCore", "PySide6.QtQuick", "PySide6.QtQml", "PySide6.QtMultimedia"],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="XML-ray",
    console=False,
    icon=str(ROOT / "xmlray" / "assets" / "icon.ico"),
    upx=False,
)
coll = COLLECT(exe, a.binaries, a.datas, name="XML-ray", upx=False)
