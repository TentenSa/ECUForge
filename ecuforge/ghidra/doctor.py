"""`ecuforge doctor ghidra`: what the local Ghidra install can and cannot do for TriCore.

Static checks only (no JVM start): PyGhidra importable, Ghidra install and version, TriCore processor module,
its language variants, and which TriCore 1.6.2 instructions its SLEIGH spec text names.

The TriCore 1.6.2 list holds instructions the open TriCore binutils accept with -mtc162 and reject with -mtc16
(checked with the pinned reference toolchain). A mnemonic found in the spec text means Ghidra may decode it;
whether its P-code is real is the job of the P-code probe, not of this check.
"""
from __future__ import annotations

import importlib.util
import os
import re
import shutil
from pathlib import Path

TC162_ONLY = ("crcn", "shuffle", "popcnt.w", "ftohp", "hptof", "crc32l.w", "crc32.b")
TESTED_VERSIONS: tuple[str, ...] = ()  # filled in once the release workflow passes on a version


def _version(install: Path) -> str | None:
    f = install / "Ghidra" / "application.properties"
    if not f.is_file():
        return None
    m = re.search(r"^application\.version=(\S+)", f.read_text(), re.M)
    return m.group(1) if m else None


def _mnemonics(langdir: Path) -> set[str]:
    names: set[str] = set()
    for f in list(langdir.glob("*.sinc")) + list(langdir.glob("*.slaspec")):
        names |= {m.lower() for m in re.findall(r"^:([A-Za-z0-9_.]+)", f.read_text(errors="replace"), re.M)}
    return names


def check(install_dir: str | None = None) -> dict:
    r: dict = {"pyghidra": importlib.util.find_spec("pyghidra") is not None,
               "java": shutil.which("java") is not None}
    install = Path(install_dir or os.environ.get("GHIDRA_INSTALL_DIR", "")) if (
        install_dir or os.environ.get("GHIDRA_INSTALL_DIR")) else None
    r["install_dir_set"] = install is not None
    r["version"] = _version(install) if install else None
    r["version_tested"] = r["version"] in TESTED_VERSIONS if r["version"] else False
    langdir = install / "Ghidra" / "Processors" / "tricore" / "data" / "languages" if install else None
    r["tricore_module"] = bool(langdir and langdir.is_dir())
    r["tricore_languages"] = []
    r["tc162_missing"] = None
    if r["tricore_module"]:
        ldefs = langdir / "tricore.ldefs"
        if ldefs.is_file():
            r["tricore_languages"] = re.findall(r'id="(tricore:[^"]+)"', ldefs.read_text())
        names = _mnemonics(langdir)
        r["tc162_missing"] = [m for m in TC162_ONLY if m not in names] if names else None
    return r


def render(r: dict) -> tuple[str, int]:
    def yn(b):
        return "yes" if b else "no"
    lines = [f"PyGhidra importable:   {yn(r['pyghidra'])}",
             f"Java on PATH:          {yn(r['java'])}",
             f"GHIDRA_INSTALL_DIR:    {'set' if r['install_dir_set'] else 'not set'}",
             f"Ghidra version:        {r['version'] or 'unknown'}"
             + ("" if not r["version"] else ("  (tested)" if r["version_tested"] else "  (not yet tested with ECUForge)")),
             f"TriCore module:        {'present' if r['tricore_module'] else 'missing'}"]
    if r["tricore_languages"]:
        lines.append(f"TriCore languages:     {', '.join(r['tricore_languages'])}")
    if r["tc162_missing"] is not None:
        lines.append("TC3xx (TriCore 1.6.2): " + ("all 1.6.2 mnemonics named in the spec" if not r["tc162_missing"]
                                                 else "not named in the spec: " + ", ".join(r["tc162_missing"])))
    lines.append("TC4x (TriCore 1.8):    experimental, not verified")
    ok = r["pyghidra"] and r["java"] and r["install_dir_set"] and r["tricore_module"]
    return "\n".join(lines), 0 if ok else 1
