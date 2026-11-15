# PyInstaller onedir spec. Build: pwsh -File scripts\build.ps1
# AndroidQF and adb are never bundled; the operator installs them under tools\ (see README).
from PyInstaller.building.api import COLLECT, EXE, PYZ
from PyInstaller.building.build_main import Analysis

analysis = Analysis(
    ["scripts/launcher.py"],
    pathex=["src"],
    hiddenimports=[],
    excludes=["tkinter", "unittest", "pydoc", "test", "pytest", "hypothesis"],
    noarchive=False,
)
pyz = PYZ(analysis.pure)
exe = EXE(
    pyz,
    analysis.scripts,
    [],
    exclude_binaries=True,
    name="astria-collector",
    console=True,
    upx=False,  # packers raise antivirus false positives
    debug=False,
    strip=False,
)
COLLECT(exe, analysis.binaries, analysis.datas, upx=False, name="astria-collector")
