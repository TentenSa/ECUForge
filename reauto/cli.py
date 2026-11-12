"""rea-auto command line."""
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


def main(argv=None) -> int:
    ap = argparse.ArgumentParser("rea-auto", description="Evidence-first analysis of automotive embedded builds")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("analyze", help="run all analyses; write report.md, evidence.json, run.json")
    _common(a)
    a.add_argument("-o", "--out", default="rea-auto-out")
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
    v = sub.add_parser("verify", help="score rea-auto against a fixture manifest")
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
