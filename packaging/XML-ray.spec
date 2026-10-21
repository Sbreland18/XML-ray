# -*- mode: python ; coding: utf-8 -*-
# PyInstaller recipe for XML-ray. Built by builder/release_manager.py, or manually:
#   python -m PyInstaller packaging/XML-ray.spec --noconfirm --distpath dist --workpath build
from pathlib import Path

ROOT = Path(SPECPATH).parent

a = Analysis(
    [str(ROOT / "run.py")],
    pathex=[str(ROOT)],
    datas=[(str(ROOT / "xmlray" / "assets"), "xmlray/assets")],
    hiddenimports=["defusedxml.ElementTree"],
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
