#!/usr/bin/env python3
"""Repository provenance and content guard (run in CI and by tests/test_repo_guard.py).

Fails when:
  1. a binary-like or build-artifact file (ELF, HEX, S-record, MAP, LSL, A2L, ARXML,
     objects, raw binaries, or any file containing NUL bytes) is tracked outside an
     approved fixture directory;
  2. a fixture directory has no valid provenance.yaml, or a file in it is not listed
     with a matching SHA-256;
  3. a fixture under fixtures/public/ lacks a public origin, source URL, license or
     redistribution permission;
  4. any tracked file exceeds the size cap (default 5 MiB, --max-mib).

Usage:
  python scripts/check_repo.py [--max-mib N]
  python scripts/check_repo.py --hashes fixtures/<dir>     # print sha256 lines for provenance.yaml
"""
from __future__ import annotations

import argparse
import hashlib
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APPROVED = ("fixtures/synthetic/", "fixtures/reference/", "fixtures/fuzz/", "fixtures/public/")
RESTRICTED_EXT = {".elf", ".hex", ".ihex", ".s19", ".s28", ".s37", ".srec", ".mot", ".a2l", ".map", ".lsl",
                  ".arxml", ".bin", ".o", ".a", ".out", ".axf", ".abs", ".dll", ".so", ".exe"}
ORIGIN_TYPES = {"generated", "authored", "public", "owner-contributed"}
FIXTURE_CLASSES = {"synthetic", "reference", "fuzz", "public"}


def tracked_files() -> list[str]:
    try:
        out = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True).stdout
        files = [f for f in out.decode().split("\0") if f]
        if files:
            return files
    except (OSError, subprocess.CalledProcessError):
        pass
    return [str(p.relative_to(ROOT)) for p in ROOT.rglob("*")
            if p.is_file() and ".git" not in p.parts and "generated" not in p.parts and "__pycache__" not in p.parts
            and not any(x.endswith(".egg-info") for x in p.parts) and ".pytest_cache" not in p.parts]


def sha256(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def is_binary_like(rel: str) -> bool:
    p = ROOT / rel
    if p.suffix.lower() in RESTRICTED_EXT:
        return True
    try:
        return b"\0" in p.read_bytes()[:8192]
    except OSError:
        return False


def fixture_dirs() -> list[Path]:
    dirs = []
    for cls in ("synthetic", "fuzz"):
        d = ROOT / "fixtures" / cls
        if d.is_dir():
            dirs.append(d)
    for cls in ("reference", "public"):
        d = ROOT / "fixtures" / cls
        if d.is_dir():
            dirs += [x for x in d.iterdir() if x.is_dir()]
    return dirs


def check_provenance(d: Path, tracked: set[str]) -> list[str]:
    import yaml
    errs, rel = [], d.relative_to(ROOT).as_posix()
    pf = d / "provenance.yaml"
    if not pf.exists():
        return [f"{rel}: missing provenance.yaml"]
    try:
        y = yaml.safe_load(pf.read_text())
    except yaml.YAMLError as e:
        return [f"{rel}/provenance.yaml: invalid YAML ({e})"]
    if y.get("schema_version") != 1:
        errs.append(f"{rel}: schema_version must be 1")
    origin, rights, purpose = y.get("origin") or {}, y.get("rights") or {}, y.get("purpose") or {}
    if origin.get("type") not in ORIGIN_TYPES:
        errs.append(f"{rel}: origin.type must be one of {sorted(ORIGIN_TYPES)}")
    if not rights.get("license") or rights.get("redistribution_allowed") is not True:
        errs.append(f"{rel}: rights.license and rights.redistribution_allowed: true are required")
    if purpose.get("fixture_class") not in FIXTURE_CLASSES:
        errs.append(f"{rel}: purpose.fixture_class must be one of {sorted(FIXTURE_CLASSES)}")
    if not (y.get("verification") or {}).get("reviewed"):
        errs.append(f"{rel}: verification.reviewed must be true")
    if origin.get("type") == "generated" and not (y.get("generator") or {}).get("name"):
        errs.append(f"{rel}: generated fixtures need generator.name")
    if rel.startswith("fixtures/public/") and (origin.get("type") != "public" or not origin.get("source_url")):
        errs.append(f"{rel}: public fixtures need origin.type public and origin.source_url")
    listed = {a.get("name"): a.get("sha256") for a in (y.get("artifacts") or [])}
    for f in sorted(x for x in d.rglob("*") if x.is_file() and x.name != "provenance.yaml"
                    and "__pycache__" not in x.parts):
        frel = f.relative_to(ROOT).as_posix()
        if tracked and frel not in tracked:
            continue
        name = f.relative_to(d).as_posix()
        if name not in listed:
            errs.append(f"{frel}: not listed in {rel}/provenance.yaml")
        elif listed[name] != sha256(f):
            errs.append(f"{frel}: sha256 differs from provenance.yaml")
    for name in listed:
        if not (d / name).exists():
            errs.append(f"{rel}/provenance.yaml lists missing file {name}")
    return errs


def run(max_mib: float) -> list[str]:
    files = tracked_files()
    tracked = set(files)
    errs = []
    for rel in files:
        p = ROOT / rel
        if not p.is_file():
            continue
        if p.stat().st_size > max_mib * 1024 * 1024:
            errs.append(f"{rel}: {p.stat().st_size} bytes exceeds the {max_mib} MiB cap")
        if is_binary_like(rel) and not rel.startswith(APPROVED):
            errs.append(f"{rel}: binary or build-artifact file outside an approved fixture directory")
    for d in fixture_dirs():
        errs += check_provenance(d, tracked)
    return errs


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-mib", type=float, default=5.0)
    ap.add_argument("--hashes", help="print 'name: sha256' for every file under a fixture dir")
    a = ap.parse_args(argv)
    if a.hashes:
        d = ROOT / a.hashes
        for f in sorted(x for x in d.rglob("*") if x.is_file() and x.name != "provenance.yaml"):
            print(f"  - name: {f.relative_to(d).as_posix()}\n    sha256: {sha256(f)}")
        return 0
    errs = run(a.max_mib)
    for e in errs:
        print(f"FAIL {e}")
    print("repository guard: " + ("OK" if not errs else f"{len(errs)} problem(s)"))
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
