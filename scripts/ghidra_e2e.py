"""End-to-end check of the Ghidra bridge against a real Ghidra install (synthetic fixtures only).

Needs GHIDRA_INSTALL_DIR, Java, PyGhidra and ECUForge installed. Run by the manual `ghidra-e2e` workflow;
also runnable locally:  python scripts/ghidra_e2e.py <work dir>

Steps: generate fixtures -> ECUForge workspace and export -> headless import of app.hex as
tricore:LE:32:tc29x -> apply (dry run, apply, apply again: must change nothing) -> inspect the program
with PyGhidra -> import an image moved to the non-cached alias and check that apply refuses it.
Exit code 0 only when every check passes.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LANG = "tricore:LE:32:tc29x"
results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, note: str = "") -> bool:
    results.append((name, bool(ok), note))
    print(("PASS " if ok else "FAIL ") + name + (f": {note}" if note else ""), flush=True)
    return ok


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    print("$ " + " ".join(str(c) for c in cmd), flush=True)
    p = subprocess.run([str(c) for c in cmd], capture_output=True, text=True, **kw)
    out = (p.stdout + p.stderr).strip()
    print("\n".join(out.splitlines()[-40:]), flush=True)
    return p


def ecuforge(*args) -> subprocess.CompletedProcess:
    return run([sys.executable, "-m", "ecuforge.cli", *args])


def headless_import(ghidra: Path, proj_dir: Path, name: str, image: Path) -> bool:
    script = ghidra / "support" / ("analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless")
    proj_dir.mkdir(parents=True, exist_ok=True)
    p = run([script, proj_dir, name, "-import", image, "-processor", LANG, "-loader", "IntelHexLoader",
             "-noanalysis"])
    return p.returncode == 0 and (proj_dir / f"{name}.gpr").is_file()


def shift_ihex(src: Path, dst: Path, lo: int, hi: int, delta: int) -> None:
    """Move every Extended Linear Address record whose upper 16 bits are in [lo, hi] by delta (checksums redone)."""
    out = []
    for line in src.read_text(encoding="ascii").splitlines():
        if line.startswith(":02000004"):
            upper = int(line[9:13], 16)
            if lo <= upper <= hi:
                upper += delta
                body = bytes.fromhex(f"02000004{upper:04X}")
                line = f":{body.hex().upper()}{(-sum(body)) & 0xFF:02X}"
        out.append(line)
    dst.write_text("\n".join(out) + "\n", encoding="ascii")


def inspect(proj_dir: Path, name: str, export: dict, image_sha: str) -> None:
    import pyghidra
    if not pyghidra.started():
        pyghidra.start()
    project = pyghidra.open_project(str(proj_dir), name)
    try:
        with pyghidra.program_context(project, "/app.hex") as program:
            space = program.getAddressFactory().getDefaultAddressSpace()
            mem = program.getMemory()
            blocks = {b.getStart().getOffset(): b for b in mem.getBlocks()}
            alias = blocks.get(0xA0000000)
            mapped = None
            if alias is not None and alias.isMapped():
                rng = alias.getSourceInfos()[0].getMappedRange()
                mapped = rng.get().getMinAddress().getOffset() if rng.isPresent() else None
            check("non-cached PFLASH view is byte-mapped onto 0x80000000", mapped == 0x80000000,
                  f"block={alias.getName() if alias else None}, mapped_to={mapped and hex(mapped)}")
            dspr = [b for o, b in blocks.items() if 0x70000000 <= o < 0x70100000]
            check("CPU0 DSPR has one uninitialized block", len(dspr) == 1 and not dspr[0].isInitialized(),
                  ", ".join(f"{b.getName()} init={b.isInitialized()}" for b in dspr))
            d = program.getListing().getDefinedDataAt(space.getAddress(0xAF400000))
            check("BMHD structure applied at 0xAF400000", d is not None and d.getDataType().getName() == "ECUForge_BMHD",
                  str(d.getDataType().getName()) if d else "no data")
            main = next(s for s in export["model"]["symbols"] if s["name"] == "main")
            names = [str(s.getName()) for s in program.getSymbolTable().getSymbols(space.getAddress(main["addr"]))]
            check("symbol main at its map address", "main" in names, ", ".join(names))
            bm = program.getBookmarkManager()
            ours = list(bm.getBookmarksIterator("ECUForge"))
            check("ECUForge bookmarks present", len(ours) > 0, f"{len(ours)} bookmarks")
            hdr = bm.getBookmark(space.getAddress(0xAF400000), "ECUForge", "ECUForge.Observed")
            check("BMHD bookmark carries its key and sources",
                  hdr is not None and "bmhd.header@" in str(hdr.getComment()) and "sources:" in str(hdr.getComment()))
            opts = program.getOptions("ECUForge")
            owned = json.loads(str(opts.getString("owned", "{}")))
            check("ownership record names the image hash", owned.get("program_sha256") == image_sha)
            check("program notes written", bool(str(opts.getString("notes", "") or "")))
    finally:
        project.close()


def main(work: Path) -> int:
    ghidra = Path(os.environ.get("GHIDRA_INSTALL_DIR", ""))
    if not (ghidra / "support").is_dir():
        print("GHIDRA_INSTALL_DIR does not point at a Ghidra install", file=sys.stderr)
        return 2
    work.mkdir(parents=True, exist_ok=True)
    fx, ws = work / "fixtures", work / "ws"
    run([sys.executable, ROOT / "fixtures/synthetic/make_fixtures.py", fx], check=True)
    doc = ecuforge("doctor", "ghidra")
    check("doctor finds the Ghidra install", doc.returncode == 0)
    ok = ecuforge("init", ws, "--device", fx / "profile_synthetic_tc38x.json").returncode == 0
    for f in ("app.hex", "app.elf", "app_gnu.map"):
        ok &= ecuforge("add", fx / f, "-C", ws).returncode == 0
    ok &= ecuforge("analyze", "-C", ws).returncode == 0
    ok &= ecuforge("export", "ghidra", "-C", ws).returncode == 0
    if not check("workspace and export", ok):
        return report()
    export = json.loads((ws / "exports/ghidra/ecuforge-ghidra.json").read_text(encoding="utf-8"))
    image_sha = hashlib.sha256((fx / "app.hex").read_bytes()).hexdigest()

    gproj = work / "gproj"
    if not check(f"headless import of app.hex as {LANG}", headless_import(ghidra, gproj, "E2E", fx / "app.hex")):
        return report()
    apply = ["ghidra", "apply", "-C", ws, "--ghidra-project", gproj / "E2E.gpr", "--program", "/app.hex"]
    p = ecuforge(*apply, "--dry-run")
    check("dry run plans changes", p.returncode == 0 and "would apply:" in p.stdout)
    p = ecuforge(*apply)
    check("first apply", p.returncode == 0 and "applied:" in p.stdout and "nothing to change" not in p.stdout)
    p = ecuforge(*apply)
    check("second apply changes nothing", p.returncode == 0 and "applied: nothing to change" in p.stdout)
    try:
        inspect(gproj, "E2E", export, image_sha)
    except Exception as e:  # report, do not hide
        check("inspect the program with PyGhidra", False, f"{type(e).__name__}: {e}")

    shift_ihex(fx / "app.hex", fx / "app_alias.hex", 0x8000, 0x8FFF, 0x2000)
    aproj = work / "gproj_alias"
    if check("headless import of the image moved to 0xA0000000",
             headless_import(ghidra, aproj, "Alias", fx / "app_alias.hex")):
        p = ecuforge("ghidra", "apply", "-C", ws, "--ghidra-project", aproj / "Alias.gpr", "--program",
                     "/app_alias.hex")
        check("apply refuses an image whose hash differs", p.returncode == 1 and "differs" in p.stderr)
    return report()


def report() -> int:
    print("\n| check | result | note |\n|---|---|---|")
    for name, ok, note in results:
        print(f"| {name} | {'PASS' if ok else 'FAIL'} | {note} |")
    failed = [n for n, ok, _ in results if not ok]
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write("## Ghidra bridge end-to-end\n\n| check | result | note |\n|---|---|---|\n")
            fh.writelines(f"| {n} | {'PASS' if ok else 'FAIL'} | {note} |\n" for n, ok, note in results)
    print(f"\n{len(results) - len(failed)} passed, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1] if len(sys.argv) > 1 else "ghidra-e2e")))
