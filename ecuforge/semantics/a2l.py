"""A2L <-> ELF/map/image correlation (L2, experimental in 0.1.x): addresses, sizes,
segments, placement, values. Memory type comes from documented profile facts, else
from what the build itself states (core.views.mem_kind)."""
from __future__ import annotations

import re

from ..core.evidence import Source
from ..core.views import mem_kind
from ..formats.a2l.parser import DTYPE

RE_BASE = re.compile(r"^([A-Za-z_]\w*)")


def correlate_a2l(p, decode_limit: int = 2000) -> dict:
    st, prof, a2l = p.store, p.profile, p.a2l
    if a2l is None:
        st.add("a2l", "unknown", "note", "No A2L loaded; calibration correlation skipped", [], key="a2l.none")
        return {}
    art = p.a2l_art.short
    syms = p.symbols()
    stats = {"objects": 0, "exact": 0, "inside": 0, "by_address_only": 0, "unresolved": 0,
             "addr_mismatch": 0, "size_mismatch": 0, "outside_segments": 0, "zero_address": 0,
             "decoded": 0, "out_of_limits": 0}

    # memory segments vs map regions
    for seg in a2l.segments:
        src = Source(art, f"line {seg.line}", f"MEMORY_SEGMENT {seg.name}")
        r = p.map.region_of(seg.address) if p.map else None
        w = prof.classify(seg.address)
        st.add("a2l", "derived" if r else "inferred", "info",
               f"A2L segment {seg.name} {seg.prg_type}/{seg.mem_type} [{seg.address:#010x}+{seg.size:#x}] -> "
               + (f"map region {r.name}" if r else f"{w.name if w else 'unknown window'}"), [src], key=f"a2l.segment@{seg.name}")
        if r and seg.address + seg.size > r.end and not prof.same_location(seg.address, r.origin):
            st.add("a2l", "derived", "warning", f"A2L segment {seg.name} extends beyond map region {r.name}", [src],
                   key=f"a2l.segment_beyond_region@{seg.name}")

    decoded = 0
    for o in a2l.objects():
        stats["objects"] += 1
        src = Source(art, f"line {o.line}", f"{o.kind} {o.name}")
        if not o.address:
            stats["zero_address"] += 1
            st.add("a2l", "observed", "warning",
                   f"{o.kind} {o.name} has address 0 - A2L not updated from the ELF/map?", [src],
                   key=f"a2l.zero_address@{o.name}")
            continue
        size, size_note = a2l.size_of(o)
        link = o.symbol_link[0] if o.symbol_link else o.name
        base = RE_BASE.match(link)
        sym = syms.get(link)
        how = "exact"
        if sym is None and base and base.group(1) != link:
            sym, how = syms.get(base.group(1)), "member"
        if sym is not None:
            expect = sym.addr + (o.symbol_link[1] if o.symbol_link else 0)
            if how == "exact" and prof.same_location(expect, o.address):
                stats["exact"] += 1
            elif how == "member" and sym.size and (
                    prof.canonical(sym.addr) <= prof.canonical(o.address) < prof.canonical(sym.addr) + sym.size):
                stats["inside"] += 1
                if sym.size_kind != "exact":
                    st.add("a2l", "inferred", "note",
                           f"{o.kind} {o.name} resolved inside {sym.name} using a size upper bound "
                           f"({sym.size:#x}, gap to next map symbol)", [src, sym.source], key=f"a2l.size_upper_bound@{o.name}")
            else:
                stats["addr_mismatch"] += 1
                st.conflict("a2l", "error",
                            f"{o.kind} {o.name}: A2L address {o.address:#010x} but {sym.origin} symbol {sym.name} "
                            f"is at {sym.addr:#010x}" + (" (member access outside symbol)" if how == "member" else ""),
                            [(src, hex(o.address)), (sym.source, hex(sym.addr))], key=f"a2l.addr_conflict@{o.name}")
            if (how == "exact" and size and sym.size and sym.size_kind == "exact" and size != sym.size
                    and o.kind != "MEASUREMENT"):
                stats["size_mismatch"] += 1
                st.add("a2l", "derived", "warning",
                       f"{o.kind} {o.name}: A2L layout implies {size} bytes, symbol size is {sym.size} "
                       f"({size_note or 'exact layout'})", [src, sym.source], {"a2l_size": size, "sym_size": sym.size},
                            key=f"a2l.size_mismatch@{o.name}")
        else:
            other = p.symbol_at(o.address)
            if other:
                stats["by_address_only"] += 1
                st.add("a2l", "inferred", "warning",
                       f"{o.kind} {o.name}: no symbol of that name; its address {o.address:#010x} falls in "
                       f"{other.name} - renamed variable or stale A2L?", [src, other.source], key=f"a2l.by_address_only@{o.name}")
            else:
                stats["unresolved"] += 1
                st.add("a2l", "unknown", "warning",
                       f"{o.kind} {o.name} at {o.address:#010x}: no symbol by name or address", [src],
                       key=f"a2l.unresolved@{o.name}")

        if a2l.segments and not any(
                prof.canonical(s.address) <= prof.canonical(o.address) < prof.canonical(s.address) + s.size
                for s in a2l.segments):
            stats["outside_segments"] += 1
            st.add("a2l", "derived", "warning",
                   f"{o.kind} {o.name} at {o.address:#010x} is outside every A2L MEMORY_SEGMENT", [src],
                       key=f"a2l.outside_segments@{o.name}")

        kind, basis = mem_kind(p, o.address)
        flash = kind == "flash"
        if o.kind == "MEASUREMENT" and flash:
            st.add("a2l", "inferred", "note", f"MEASUREMENT {o.name} lives in flash (constant being measured)",
                   [src], key=f"a2l.measurement_in_flash@{o.name}")
        if o.kind == "CHARACTERISTIC" and kind == "ram":
            st.add("a2l", "inferred", "note",
                   f"CHARACTERISTIC {o.name} is in RAM: needs a calibration overlay / init-from-flash path",
                   [src], key=f"a2l.characteristic_in_ram@{o.name}")

        # decode scalar characteristics from the image
        if o.kind == "CHARACTERISTIC" and o.ctype == "VALUE" and flash and decoded < decode_limit:
            dt = a2l.value_dtype(o)
            raw = p.image.read(o.address, DTYPE[dt][0]) if dt in DTYPE else None
            if raw is None:
                st.add("a2l", "unknown", "note", f"{o.name}: bytes not in image, value not decodable", [src],
                       key=f"a2l.value@{o.name}")
                continue
            decoded += 1
            stats["decoded"] += 1
            rv = a2l.decode(o, raw)
            cm = a2l.compu.get(o.conversion or "")
            phys = cm.to_phys(rv) if cm else (rv if o.conversion == "NO_COMPU_METHOD" else None)
            inside = phys is None or o.lower is None or (o.lower - 1e-9 <= phys <= o.upper + 1e-9)
            if not inside:
                stats["out_of_limits"] += 1
            img_src = Source(p.image.find_any(o.address).origin, f"addr {o.address:#010x}+{len(raw)}")
            st.add("a2l", "derived", "info" if inside else "warning",
                   f"{o.name} = raw {rv} -> phys {phys if phys is not None else '?'}"
                   + (f" {cm.unit}" if cm and cm.unit else "")
                   + ("" if inside else f" OUTSIDE limits [{o.lower}, {o.upper}]"),
                   [src, img_src], {"raw": rv, "phys": phys, "lower": o.lower, "upper": o.upper}, key=f"a2l.value@{o.name}")

    resolved = stats["exact"] + stats["inside"]
    pct = 100.0 * resolved / stats["objects"] if stats["objects"] else 0
    sev = "error" if stats["addr_mismatch"] else "warning" if stats["unresolved"] + stats["by_address_only"] else "info"
    st.add("a2l", "derived", sev,
           f"A2L correlation: {resolved}/{stats['objects']} objects resolved to symbols ({pct:.1f}%), "
           f"{stats['addr_mismatch']} address mismatches, {stats['unresolved']} unresolved, "
           f"{stats['decoded']} values decoded ({stats['out_of_limits']} outside limits)",
           [Source(art, "whole file")], stats, key="a2l.summary")
    return stats
