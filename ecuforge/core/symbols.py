"""Map <-> ELF symbol correlation (L1). Disagreements are CONFLICT findings."""
from __future__ import annotations

from .evidence import Source


def correlate_symbols(p) -> dict:
    st, prof = p.store, p.profile
    res: dict = {"matched": 0, "addr_mismatch": [], "map_only": [], "elf_only": 0, "section_size_diff": []}
    if not (p.map and p.elf):
        st.add("symbols", "unknown", "note",
               "Map/ELF correlation needs both a map and an ELF; skipped", [])
    else:
        elf_syms = {}
        for s in p.elf.symbols:
            if s.type not in ("file", "section"):
                elf_syms.setdefault(s.name, s)
        for ms in p.map.symbols:
            es = elf_syms.get(ms.name)
            if es is None:
                if not ms.assignment:
                    res["map_only"].append(ms.name)
                continue
            if prof.same_location(es.value, ms.addr):
                res["matched"] += 1
            else:
                res["addr_mismatch"].append((ms.name, ms.addr, es.value))
                st.conflict("symbols", "error", f"{ms.name}: map says {ms.addr:#010x}, ELF says {es.value:#010x}",
                            [(Source(p.map.artifact, f"line {ms.line}"), hex(ms.addr)),
                             (Source(p.elf_art.short, f"symtab {ms.name}"), hex(es.value))])
        map_names = {s.name for s in p.map.symbols}
        res["elf_only"] = sum(1 for n, s in elf_syms.items() if s.bind == "global" and n not in map_names)
        elf_secs = {s.name: s for s in p.elf.sections}
        for ms in p.map.sections:
            es = elf_secs.get(ms.name)
            if es and es.size != ms.size:
                res["section_size_diff"].append((ms.name, ms.size, es.size))
                st.conflict("symbols", "error", f"Section {ms.name}: map size {ms.size:#x} vs ELF size {es.size:#x}",
                            [(Source(p.map.artifact, f"line {ms.line}"), hex(ms.size)),
                             (Source(p.elf_art.short, f"section {ms.name}"), hex(es.size))])
        n_map = len(p.map.symbols)
        bad = len(res["addr_mismatch"]) + len(res["section_size_diff"])
        st.add("symbols", "derived", "error" if bad else "info",
               (f"Map and ELF look like DIFFERENT builds: {bad} address/size conflicts" if bad else
                f"Map and ELF agree: {res['matched']} symbols matched by name and address")
               + f"; {len(res['map_only'])} map-only, {res['elf_only']} ELF-only globals (of {n_map} map symbols)",
               [Source(p.map.artifact, "whole file"), Source(p.elf_art.short, "symtab")],
               {k: (v if isinstance(v, int) else len(v)) for k, v in res.items()})
        if res["map_only"]:
            st.add("symbols", "derived", "note",
                   f"{len(res['map_only'])} symbols in map but not in ELF symtab (stripped ELF or different build)",
                   [Source(p.map.artifact, "symbols")], {"names": res["map_only"][:50]})
    return res


