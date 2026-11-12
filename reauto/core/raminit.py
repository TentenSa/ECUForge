"""Toolchain-independent RAM initialisation analysis.

Toolchain plug-ins decode their own init tables into copy / clear records. This
module validates every record against the linker and image views and checks
that each initialised RAM section is covered, so the HighTec/GNU and TASKING
paths give the same kind of answer.
"""
from __future__ import annotations

from .evidence import Source
from .views import linker_mem_kind


def ram_sections(p):
    """Located sections the build itself marks as RAM data (ELF flags / region attributes / class)."""
    out = []
    for row in p.layout_rows:
        if row.cls in ("data", "bss"):
            out.append(row)
    return out


def validate_record(p, rec: dict, op: str) -> tuple[str | None, str | None]:
    """Return (rejection reason or None, exactly matching section name or None)."""
    dst, length = (rec["dst"], rec["size"]) if op == "copy" else (rec["addr"], rec["size"])
    if length <= 0:
        return f"non-positive length {length:#x}", None
    secs = ram_sections(p)
    host = [s for s in secs if s.vma <= dst and dst + length <= s.vma + s.size]
    if secs and not host:
        kind, _ = linker_mem_kind(p, dst)
        if kind != "ram":
            return f"destination {dst:#010x}+{length:#x} not inside a linked RAM data section", None
    if op == "copy" and p.image.coverage(rec["src"], length) < length:
        return f"copy source {rec['src']:#010x}+{length:#x} absent from image", None
    exact = next((s.name for s in host if s.vma == dst and s.size == length), None)
    return None, exact


def validate_table(p, copy: list[dict], clear: list[dict]) -> dict:
    reasons, exact = [], 0
    for op, recs in (("copy", copy), ("clear", clear)):
        for r in recs:
            why, hit = validate_record(p, r, op)
            r["section"] = hit
            if why:
                reasons.append(why)
            elif hit:
                exact += 1
    return {"valid": not reasons and bool(copy or clear), "reasons": reasons, "exact_hits": exact}


def coverage_check(p, copy: list[dict], clear: list[dict], sources: list[Source]) -> None:
    st = p.store
    cover = [(r["addr"], r["size"]) for r in clear] + [(r["dst"], r["size"]) for r in copy]
    for s in ram_sections(p):
        if any(a <= s.vma and s.vma + s.size <= a + z for a, z in cover):
            continue
        st.add("startup", "derived", "warning",
               f"{s.name} [{s.vma:#010x}+{s.size:#x}] is linked as RAM data but no init-table record covers it; "
               "uninitialised at startup unless other code handles it", [s.source] + sources[:1],
               {"section": s.name}, [s.finding])


def recover_init(p) -> dict:
    """Run every toolchain init-table decoder (each returns validated, normalised records), report, and check
    coverage. No toolchain-specific branching here."""
    from ..toolchains import init_table_decoders
    st = p.store
    results = []
    if not p.image.segments:
        return {"tables": []}
    for dec in init_table_decoders():
        r = dec(p)
        if r is None:
            continue
        entries = ([{"op": "copy", "src": hex(e["src"]), "dst": hex(e["dst"]), "size": hex(e["size"]),
                     "section": e.get("section")} for e in r["copy"]] +
                   [{"op": "clear", "dst": hex(e["addr"]), "size": hex(e["size"]), "section": e.get("section")}
                    for e in r["clear"]])
        st.add("startup", r["kind"], "info" if r["kind"] == "derived" else "warning",
               r["summary"] + ("" if r["kind"] == "derived" else f"; problems: {'; '.join(r['problems'][:3])}"
                               if r["problems"] else ""),
               r["sources"], {"entries": entries, "candidates": r.get("candidates"), "problems": r["problems"]})
        results.append(r)
    good = [r for r in results if r["kind"] == "derived"]
    if good:
        coverage_check(p, [e for r in good for e in r["copy"]], [e for r in good for e in r["clear"]],
                       [s for r in good for s in r["sources"]])
    elif not results:
        st.add("startup", "unknown", "note", "No init table found by any toolchain plug-in", [])
    return {"tables": results}
