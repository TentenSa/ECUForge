"""GNU / iLLD C-runtime init tables built by the linker script:
  __clear_table: {addr, size} records, terminated by addr == 0xFFFFFFFF
  __copy_table : {src, dst, size} records, terminated by src == 0xFFFFFFFF
Returned entries are validated against the image by the caller."""
from __future__ import annotations

from ...core.evidence import Source


def _walk(p, sym, width):
    rows, a = [], sym.addr
    for _ in range(512):
        vals = [p.image.u32(a + 4 * k) for k in range(width)]
        if None in vals:
            return rows, f"table runs off the image at {a:#010x}"
        if vals[0] == 0xFFFFFFFF:
            return rows, None
        rows.append(tuple(vals))
        a += 4 * width
    return rows, "no terminator within 512 records"


def decode_gnu_tables(p) -> dict | None:
    syms = p.symbols()
    if "__clear_table" not in syms and "__copy_table" not in syms:
        return None
    out = {"toolchain": "gnu/iLLD", "copy": [], "clear": [], "sources": [], "problems": [], "kind": "derived",
           "summary": ""}
    if "__clear_table" in syms:
        s = syms["__clear_table"]
        rows, err = _walk(p, s, 2)
        out["clear"] = [{"addr": a, "size": z} for a, z in rows]
        out["sources"].append(s.source)
        if err:
            out["problems"].append(f"__clear_table: {err}")
    if "__copy_table" in syms:
        s = syms["__copy_table"]
        rows, err = _walk(p, s, 3)
        out["copy"] = [{"src": a, "dst": d, "size": z} for a, d, z in rows]
        out["sources"].append(s.source)
        if err:
            out["problems"].append(f"__copy_table: {err}")
    out["summary"] = (f"GNU/iLLD init tables: {len(out['copy'])} copy and {len(out['clear'])} clear records "
                      "(record format per iLLD GNU linker script convention)")
    return out
