"""ECUForge command line."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .analyze import open_project, render_markdown, run_all
from .silicon.infineon.aurix.profile import DeviceProfile


def _common(ap: argparse.ArgumentParser) -> None:
    ap.add_argument("--image", help="Intel HEX / S-record / ELF image")
    ap.add_argument("--elf", help="ELF with symbols")
    ap.add_argument("--map", dest="map_", help="linker map (GNU/HighTec or TASKING)")
    ap.add_argument("--toolchain", choices=["gnu", "tasking"], help="force map format")
    ap.add_argument("--lsl", help="TASKING LSL (optional)")
    ap.add_argument("--a2l", help="A2L (L2, needs --experimental)")
    ap.add_argument("--device", default="tc38x",
                    help=f"MCU profile name or JSON path ({', '.join(DeviceProfile.available())})")
    ap.add_argument("--bmhd-crc-mode", choices=["discover", "profile", "strict"],
                    help="override the profile's BMHD CRC mode")
    ap.add_argument("--experimental", action="store_true", help="enable L2 semantics (A2L, AUTOSAR attribution)")


def _open(a):
    return open_project(a.image, a.elf, a.map_, a.lsl, a.a2l, a.device, a.toolchain, a.bmhd_crc_mode, a.experimental)


def _has_inputs(a) -> bool:
    return any(getattr(a, k, None) for k in ("image", "elf", "map_", "lsl", "a2l"))


def _ghidra_apply(args) -> int:
    from pathlib import Path

    from .workspace import Workspace, WorkspaceError
    try:
        export = Path(args.export) if args.export else Workspace(args.workspace).root / "exports/ghidra/ecuforge-ghidra.json"
    except WorkspaceError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    if not export.is_file():
        print(f"error: {export}: no export; run `ecuforge export ghidra` first", file=sys.stderr)
        return 2
    proj = Path(args.ghidra_project)
    if proj.suffix == ".gpr":
        proj = proj.with_suffix("")
    try:
        from .ghidra.adapter import apply_export
        plan = apply_export(json.loads(export.read_text()), str(proj), args.program, args.dry_run)
    except ImportError:
        print("error: PyGhidra is not installed; see `ecuforge doctor ghidra`", file=sys.stderr)
        return 2
    if plan.refused:
        print(f"refused: {plan.refused}", file=sys.stderr)
        return 1
    from collections import Counter
    counts = ", ".join(f"{k}={v}" for k, v in sorted(Counter(plan.kinds()).items())) or "nothing to change"
    print(("would apply: " if args.dry_run else "applied: ") + counts)
    for r in plan.report:
        print(f"  note: {r}")
    return 0


def _workspace_cmd(args) -> int:
    from .workspace import Workspace, WorkspaceError
    try:
        if args.cmd == "init":
            ws = Workspace.init(args.path, args.device, args.toolchain, args.bmhd_crc_mode, args.experimental)
            print(f"initialised workspace {ws.data['name']}")
            return 0
        ws = Workspace(args.workspace)
        if args.cmd == "add":
            e, added = ws.add(args.file, args.role)
            print(f"{'added' if added else 'already present'}: {e['role']:<6} {e['name']}@{e['sha256'][:12]}")
            return 0
        if args.cmd == "export":
            out = ws.export_ghidra(args.output)
            print(f"wrote {out}")
            return 0
        if args.cmd == "analyze":
            rec, run_id = ws.analyze()
            s = rec["result"]["evidence"]["summary"]
            print(f"run {run_id}: {s['total']} findings "
                  f"({', '.join(f'{k}={v}' for k, v in s['by_severity'].items())})")
            return 1 if s["by_severity"].get("error") else 0
        if args.what == "artifacts":
            for e in ws.data["artifacts"]:
                print(f"{e['role']:<8} {e['sha256'][:12]}  {e['size']:>10}  {e['name']}")
            return 0
        cur = ws.current()
        if cur is None:
            print("no analysis yet; run `ecuforge analyze`", file=sys.stderr)
            return 1
        r = cur["result"]
        if args.what == "run":
            print(json.dumps({k: v for k, v in r.items() if k not in ("evidence", "linker_draft")} |
                             {"run_id": cur["run_id"], "created_at": cur["created_at"]}, indent=2))
        else:
            for f in r["evidence"]["findings"]:
                if args.topic in (None, f["topic"]):
                    print(f"{f['id']:<13} {f['level']} {f['severity']:<8} {f['kind']:<9} {f['claim']}")
        return 0
    except WorkspaceError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


def main(argv=None) -> int:
    ap = argparse.ArgumentParser("ecuforge", description="Evidence-first analysis of automotive embedded builds")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("analyze", help="run all analyses: in a workspace (no input flags) or on the given files")
    _common(a)
    a.add_argument("-o", "--out", default="ecuforge-out", help="output directory (file mode only)")
    a.add_argument("-C", "--workspace", default=".", help="workspace directory (default: current)")
    i = sub.add_parser("init", help="create a project workspace")
    i.add_argument("path")
    i.add_argument("--device", default="tc38x", help="MCU profile name or JSON path")
    i.add_argument("--toolchain", choices=["gnu", "tasking"])
    i.add_argument("--bmhd-crc-mode", choices=["discover", "profile", "strict"])
    i.add_argument("--experimental", action="store_true")
    ad = sub.add_parser("add", help="add an artifact to the workspace")
    ad.add_argument("file")
    ad.add_argument("--role", choices=["image", "elf", "map", "lsl", "a2l"])
    ad.add_argument("-C", "--workspace", default=".")
    ex = sub.add_parser("export", help="write an export of the workspace for another tool")
    ex.add_argument("target", choices=["ghidra"])
    ex.add_argument("-o", "--output", help="output file (default: <workspace>/exports/ghidra/ecuforge-ghidra.json)")
    ex.add_argument("-C", "--workspace", default=".")
    dr = sub.add_parser("doctor", help="check an external tool for use with ECUForge")
    dr.add_argument("target", choices=["ghidra"])
    dr.add_argument("--install-dir", help="Ghidra install (default: $GHIDRA_INSTALL_DIR)")
    gh = sub.add_parser("ghidra", help="apply the Ghidra export to a program in a Ghidra project (PyGhidra)")
    gh.add_argument("action", choices=["apply"])
    gh.add_argument("--ghidra-project", required=True, help="Ghidra project: its .gpr file or <dir>/<name>")
    gh.add_argument("--program", required=True, help="program path in the project, e.g. /app.hex")
    gh.add_argument("--export", help="export file (default: <workspace>/exports/ghidra/ecuforge-ghidra.json)")
    gh.add_argument("--dry-run", action="store_true", help="show the plan, change nothing")
    gh.add_argument("-C", "--workspace", default=".")
    sh = sub.add_parser("show", help="show workspace contents or the latest analysis")
    sh.add_argument("what", choices=["artifacts", "findings", "run"])
    sh.add_argument("--topic", choices=["input", "layout", "symbols", "startup", "a2l", "autosar"])
    sh.add_argument("-C", "--workspace", default=".")
    f = sub.add_parser("findings", help="run all analyses and print findings")
    _common(f)
    f.add_argument("--topic", choices=["input", "layout", "symbols", "startup", "a2l", "autosar"])
    f.add_argument("--level", choices=["L0", "L1", "L2"])
    f.add_argument("--kind", choices=["observed", "derived", "inferred", "unknown", "conflict"])
    f.add_argument("--json", action="store_true")
    d = sub.add_parser("linker-draft", help="print the reconstructed linker layout draft")
    _common(d)
    q = sub.add_parser("lookup", help="resolve a symbol name or an address")
    _common(q)
    q.add_argument("what")
    v = sub.add_parser("verify", help="score ECUForge against a fixture manifest")
    v.add_argument("manifest")
    v.add_argument("-o", "--out", help="write verify run record JSON here")
    sub.add_parser("profiles", help="list MCU profiles")
    args = ap.parse_args(argv)

    if args.cmd == "profiles":
        for n in DeviceProfile.available():
            d_ = DeviceProfile.load(n).describe()
            print(f"{n:8} {d_['id']} v{d_['version']}  unknown facts: {d_['unknown_facts']}")
        return 0
    if args.cmd == "verify":
        from .verify import render, verify
        vr, rec = verify(args.manifest)
        print(render(vr, args.manifest))
        if args.out:
            Path(args.out).write_text(json.dumps(rec, indent=2))
        return 0 if vr.ok else 1

    if args.cmd == "doctor":
        from .ghidra.doctor import check, render
        text, code = render(check(args.install_dir))
        print(text)
        return code
    if args.cmd == "ghidra":
        return _ghidra_apply(args)
    if args.cmd in ("init", "add", "show", "export") or (args.cmd == "analyze" and not _has_inputs(args)):
        return _workspace_cmd(args)

    p = _open(args)
    if args.cmd == "lookup":
        try:
            addr = int(args.what, 0)
        except ValueError:
            s = p.symbols().get(args.what)
            print(json.dumps(None if s is None else {"name": s.name, "addr": hex(s.addr), "size": s.size,
                                                     "size_kind": s.size_kind, "origin": s.origin,
                                                     "source": str(s.source)}, indent=2))
            return 0
        sym, win = p.symbol_at(addr), p.profile.classify(addr)
        print(json.dumps({"addr": hex(addr), "symbol": sym.name if sym else None,
                          "linker_section": (p.map.section_of(addr).name if p.map and p.map.section_of(addr) else None),
                          "linker_region": (p.map.region_of(addr).name if p.map and p.map.region_of(addr) else None),
                          "physical": win.name if win else None,
                          "bytes": (p.image.read(addr, 16) or b"").hex() or None}, indent=2))
        return 0

    res = run_all(p)
    if args.cmd == "linker-draft":
        print(res["linker_draft"] or "no linker regions available")
        return 0
    if args.cmd == "findings":
        fs = p.store.query(args.topic, args.kind, None, args.level)
        if args.json:
            print(json.dumps([x.to_dict() for x in fs], indent=2))
        else:
            for x in fs:
                print(f"{x.id:<13} {x.level} {x.severity:<8} {x.kind:<9} {x.claim}")
        return 0
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.md").write_text(render_markdown(p, res))
    (out / "evidence.json").write_text(p.store.to_json())
    (out / "run.json").write_text(json.dumps(res["run"], indent=2))
    if res["linker_draft"]:
        (out / "linker_draft.ld").write_text(res["linker_draft"])
    s = p.store.summary()
    print(f"{s['total']} findings ({', '.join(f'{k}={v}' for k, v in s['by_severity'].items())}) -> {out}/")
    return 1 if s["by_severity"].get("error") else 0


if __name__ == "__main__":
    sys.exit(main())
