"""TriCore startup structures: entry points, CSA pools, stacks, trap/interrupt vector tables.

Symbols are found through toolchain/BSP naming conventions (inferred), sizes and
checks use cited architecture facts (TriCoreSpec). A check whose fact is null in
the spec is reported once as unknown instead of being run with an assumed value.
"""
from __future__ import annotations

from ...core.evidence import Source
from ...toolchains import conventions

ERASED = (b"\x00" * 4, b"\xff" * 4)


def _img_src(p, addr, n):
    seg = p.image.find_any(addr)
    return [Source(seg.origin, f"addr {addr:#010x}+{n:#x} ({seg.locator})")] if seg else []


def _where(p, addr):
    w = p.profile.classify(addr)
    return (w.name, w.core) if w else (None, None)


def recover_entries(p, bmhds: list[dict]) -> list[dict]:
    st, prof, out = p.store, p.profile, []
    if p.elf:
        out.append({"name": "ELF e_entry", "addr": p.elf.entry})
        st.add("startup", "observed", "info", f"ELF entry point {p.elf.entry:#010x}",
               [Source(p.elf_art.short, "ELF header e_entry")])
    seen = set()
    for conv in conventions():
        for name, s in p.symbols().items():
            for pat, label in conv.entries:
                m = pat.match(name)
                if m and name not in seen:
                    seen.add(name)
                    core = next((int(x) for x in m.groups() if x), None) if m.groups() else None
                    out.append({"name": name, "addr": s.addr, "core": core, "label": label})
                    st.add("startup", "inferred", "info", f"{label} by {conv.name} naming: {name} at {s.addr:#010x}",
                           [s.source], {"core": core})
    for b in bmhds:
        if not p.elf or b.get("crc_status") not in ("match", "inferred-match"):
            continue
        src_b = _img_src(p, b["addr"] + 4, 4)
        e = Source(p.elf_art.short, "ELF header e_entry")
        if prof.same_location(b["stad"], p.elf.entry):
            st.add("startup", "derived", "info",
                   f"{b['slot']} STAD {b['stad']:#010x} and ELF entry {p.elf.entry:#010x} are the same location",
                   src_b + [e])
        elif prof.alternate(b["stad"]) is None and prof.alternate(p.elf.entry) is None:
            st.add("startup", "unknown", "note",
                   f"{b['slot']} STAD {b['stad']:#010x} vs ELF entry {p.elf.entry:#010x}: different addresses, and the "
                   "profile documents no bus alias that could relate them", src_b + [e])
        else:
            st.conflict("startup", "warning",
                        f"{b['slot']} STAD {b['stad']:#010x} and ELF entry {p.elf.entry:#010x} are different locations",
                        [(src_b[0], hex(b["stad"])), (e, hex(p.elf.entry))])
    return out


def recover_csa_stacks(p) -> dict:
    st, syms, res = p.store, p.symbols(), {"csa": {}, "stacks": {}}
    csa_size, csa_src = p.arch.fact("csa_size")
    csa_align, align_src = p.arch.fact("csa_align")
    stack_align, _ = p.arch.fact("stack_align")
    for conv in conventions():
        for name, s in syms.items():
            for pat, end_fmt in conv.csa:
                m = pat.match(name)
                if not m:
                    continue
                c = int(m.group(1))
                e = syms.get(end_fmt.format(c=c))
                if e is None:
                    st.add("startup", "unknown", "note", f"CSA begin {name} has no end symbol", [s.source])
                    continue
                lo, hi = sorted((s.addr, e.addr))
                win, wcore = _where(p, lo)
                rec = {"core": c, "start": lo, "size": hi - lo, "frames": (hi - lo) // csa_size if csa_size else None,
                       "physical": win, "physical_core": wcore, "naming": conv.name}
                res["csa"][c] = rec
                st.add("startup", "derived", "info",
                       f"CPU{c} CSA area [{lo:#010x}..{hi:#010x}) = {hi - lo:#x} bytes"
                       + (f" = {(hi - lo) // csa_size} frames of {csa_size} B" if csa_size else "")
                       + (f"; physical: {win}" if win else "; physical: UNKNOWN"),
                       [s.source, e.source] + ([csa_src] if csa_src else []), rec)
                if csa_align and lo % csa_align:
                    st.add("startup", "derived", "error", f"CPU{c} CSA start {lo:#010x} is not {csa_align}-byte aligned",
                           [s.source, align_src])
                if csa_size and (hi - lo) % csa_size:
                    st.add("startup", "derived", "warning",
                           f"CPU{c} CSA size {hi - lo:#x} is not a multiple of the {csa_size}-byte frame",
                           [s.source, e.source, csa_src])
            for pat, end_fmt, kind in conv.stacks:
                m = pat.match(name)
                if not m:
                    continue
                c = int(m.group(1))
                e = syms.get(end_fmt.format(c=c))
                if e is None:
                    continue
                lo, hi = sorted((s.addr, e.addr))
                win, _ = _where(p, lo)
                rec = {"core": c, "kind": kind, "bottom": lo, "top": hi, "size": hi - lo, "physical": win}
                res["stacks"][f"{kind}{c}"] = rec
                st.add("startup", "derived", "info",
                       f"CPU{c} {kind} stack [{lo:#010x}..{hi:#010x}) = {hi - lo:#x} bytes"
                       + (f"; physical: {win}" if win else "; physical: UNKNOWN"), [s.source, e.source], rec)
    if res["stacks"] and stack_align is None:
        st.add("startup", "unknown", "note", "Stack alignment rule not documented in architecture spec; not checked",
               [Source(p.arch.artifact.short, "fact stack_align")])
    if not res["csa"]:
        st.add("startup", "unknown", "note", "No CSA symbols found by any registered naming convention", [])
    return res


def recover_vectors(p) -> list[dict]:
    st, out = p.store, []
    classes, cls_src = p.arch.fact("trap_classes")
    spacing, sp_src = p.arch.fact("trap_vector_spacing")
    align = {"trap": p.arch.fact("btv_align"), "interrupt": p.arch.fact("biv_align")}
    for conv in conventions():
        for name, s in p.symbols().items():
            for pat, kind in conv.vectors:
                m = pat.match(name)
                if not m:
                    continue
                c = int(m.group(1))
                rec = {"core": c, "kind": kind, "addr": s.addr, "naming": conv.name}
                out.append(rec)
                f = st.add("startup", "inferred", "info",
                           f"CPU{c} {kind} vector table ({'BTV' if kind == 'trap' else 'BIV'} candidate) at "
                           f"{s.addr:#010x} by {conv.name} naming", [s.source], rec)
                a_val, a_src = align[kind]
                if a_val is None:
                    st.add("startup", "unknown", "note",
                           f"CPU{c} {kind} table alignment rule not documented in architecture spec; not checked",
                           [Source(p.arch.artifact.short, f"fact {'btv' if kind == 'trap' else 'biv'}_align")], {}, [f.id])
                elif s.addr % a_val:
                    st.add("startup", "derived", "error", f"CPU{c} {kind} table {s.addr:#010x} not {a_val}-byte aligned",
                           [s.source, a_src], {}, [f.id])
                if kind == "trap" and classes and spacing and p.image.segments:
                    missing = [k for k in range(classes)
                               if p.image.read(s.addr + spacing * k, 4) in ERASED + (None,)]
                    st.add("startup", "derived", "warning" if missing else "info",
                           f"CPU{c}: trap classes {missing} have no code in the image" if missing
                           else f"CPU{c}: all {classes} trap class entries contain code",
                           _img_src(p, s.addr, classes * spacing) + [cls_src, sp_src], {"missing": missing}, [f.id])
    return out
