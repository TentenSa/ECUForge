"""TASKING copy table (_lc_cp / _lc_ub_table).

TASKING documents what the table means (initialised data: ROM source, RAM
destination, byte count; zero-initialised data: RAM destination, byte count) and
how to inspect it (`hldumptc app.elf -F2 --sections=table`), but the binary
record encoding is toolset-version specific. Candidate encodings are decoded and
each is validated by core.raminit against the linker and image views. Every
candidate keeps its rejection reason.

  exactly one candidate valid (or all valid ones agree) -> derived
  none valid, or valid candidates disagree             -> unknown
  profile pins a layout                                 -> only that one runs
"""
from __future__ import annotations

from ...core.raminit import validate_table

MAX_ENTRIES = 256


def _words(img, addr, n):
    return [img.u32(addr + 4 * k) for k in range(n)]


def _untagged(img, addr):
    """12-byte records: copy = (src, dst, len); clear = (dst, len, 0); all-zero / all-ones end."""
    copy, clear, a = [], [], addr
    for _ in range(MAX_ENTRIES):
        w = _words(img, a, 3)
        if None in w:
            return None, "table runs off the image", 0
        a += 12
        if w in ([0, 0, 0], [0xFFFFFFFF] * 3):
            return (copy, clear), None, a - addr
        if w[2] == 0:
            clear.append({"addr": w[0], "size": w[1]})
        else:
            copy.append({"src": w[0], "dst": w[1], "size": w[2]})
    return None, "no terminator within 256 records", 0


def _tagged(img, addr):
    """16-byte records: action, dst, src, len; action 0 / 0xFFFFFFFF ends; src 0 means clear."""
    copy, clear, a = [], [], addr
    for _ in range(MAX_ENTRIES):
        w = _words(img, a, 4)
        if None in w:
            return None, "table runs off the image", 0
        act, dst, src, ln = w
        a += 16
        if act in (0, 0xFFFFFFFF):
            return (copy, clear), None, a - addr
        if act > 0xFF:
            return None, f"action word {act:#x} is not a small code", 0
        (copy.append({"src": src, "dst": dst, "size": ln}) if src else clear.append({"addr": dst, "size": ln}))
    return None, "no terminator within 256 records", 0


def _dst_src_len(img, addr):
    """12-byte records: dst, src, len; src 0 means clear."""
    copy, clear, a = [], [], addr
    for _ in range(MAX_ENTRIES):
        w = _words(img, a, 3)
        if None in w:
            return None, "table runs off the image", 0
        a += 12
        if w in ([0, 0, 0], [0xFFFFFFFF] * 3):
            return (copy, clear), None, a - addr
        (copy.append({"src": w[1], "dst": w[0], "size": w[2]}) if w[1] else clear.append({"addr": w[0], "size": w[2]}))
    return None, "no terminator within 256 records", 0


LAYOUTS = {
    "untagged 12B: copy(src,dst,len) / clear(dst,len,0)": _untagged,
    "tagged 16B: action,dst,src,len": _tagged,
    "12B: dst,src,len (src=0 clear)": _dst_src_len,
}


def _sig(c):
    return sorted([("c", r["src"], r["dst"], r["size"]) for r in c["copy"]] +
                  [("z", r["addr"], 0, r["size"]) for r in c["clear"]])


def decode_tasking_table(p) -> dict | None:
    syms = p.symbols()
    sym = syms.get("_lc_cp") or syms.get("_lc_ub_table")
    if sym is None:
        return None
    pinned = ((p.profile.data.get("tasking_copy_table") or {}).get("layout"))
    cands = []
    for name, fn in LAYOUTS.items():
        if pinned and name != pinned:
            continue
        res, err, nbytes = fn(p.image, sym.addr)
        c = {"layout": name, "status": "REJECTED", "reason": err, "copy": [], "clear": [], "bytes": nbytes}
        if res is not None:
            c["copy"], c["clear"] = res
            v = validate_table(p, c["copy"], c["clear"])
            if v["valid"]:
                c.update(status="VALID", reason=None, exact_hits=v["exact_hits"])
            else:
                c["reason"] = v["reasons"][0] if v["reasons"] else "empty table"
        cands.append(c)
    valid = [c for c in cands if c["status"] == "VALID"]
    out = {"toolchain": "tasking", "symbol": sym.name, "addr": sym.addr, "sources": [sym.source],
           "candidates": [{k: c.get(k) for k in ("layout", "status", "reason", "exact_hits")} for c in cands],
           "copy": [], "clear": [], "problems": [], "pinned": bool(pinned)}
    if valid and all(_sig(c) == _sig(valid[0]) for c in valid):
        best = max(valid, key=lambda c: c.get("exact_hits", 0))
        out.update(copy=best["copy"], clear=best["clear"], layout=best["layout"], kind="derived", bytes=best["bytes"],
                   summary=f"TASKING {sym.name}: {len(best['copy'])} copy and {len(best['clear'])} clear records, "
                           f"encoding [{best['layout']}]" + (" pinned by profile" if pinned else
                           f" is the only candidate consistent with linker and image "
                           f"({best.get('exact_hits', 0)} records match a section exactly)"))
    else:
        out.update(kind="unknown", summary=f"TASKING {sym.name}: "
                   + ("valid candidates disagree" if valid else "no candidate encoding validated")
                   + "; confirm with `hldumptc app.elf -F2 --sections=table`")
    return out
