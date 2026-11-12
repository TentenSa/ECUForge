"""Memory layout recovery over the three address-space views.

Produces section placement and init strategy, per-region usage, and the
relations linker->physical, image->linker and section->region. Contradictions
between views are CONFLICT findings with both claims kept; nothing "wins".
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .evidence import Source
from .views import OUTSIDE, OVERLAPS, ImageMemoryRegion, LinkerSection, build_views, mem_kind, \
    relate_complete, relate_physical

# ELF / GNU section naming conventions (public ELF and GNU ld practice)
SECTION_CLASS = [
    (r"^\.(csa|CPU\d\.csa)", "csa"),
    (r"(ustack|istack|stack)", "stack"),
    (r"(inttab|int_tab|intvec)", "int-vector"),
    (r"(traptab|trap_tab|trapvec)", "trap-vector"),
    (r"(^|\.)(z|s|)bss|\.noinit|\.no_init", "bss"),
    (r"(^|\.)(z|s|)data", "data"),
    (r"(^|\.)(rodata|zrodata|srodata|const|ldata)", "rodata"),
    (r"(^|\.)text|\.code", "text"),
    (r"(^|\.)(clear_sec|copy_sec|cinit|table)$", "init-table"),
    (r"(^|\.)(bmhd|ucb)", "boot-header"),
]


def classify_section(name: str, elf_flags: str | None = None, nobits: bool | None = None) -> tuple[str, str]:
    """(class, evidence kind). ELF flags are observed; names alone are inferred."""
    if elf_flags is not None:
        if nobits:
            for pat, cls in SECTION_CLASS[:4]:
                if re.search(pat, name, re.I):
                    return cls, "inferred"
            return "bss", "observed"
        if "x" in elf_flags:
            for pat, cls in SECTION_CLASS[2:4]:
                if re.search(pat, name, re.I):
                    return cls, "inferred"
            return "text", "observed"
        return ("data" if "w" in elf_flags else "rodata"), "observed"
    for pat, cls in SECTION_CLASS:
        if re.search(pat, name, re.I):
            return cls, "inferred"
    return "unknown", "unknown"


@dataclass
class SectionRow:
    name: str
    vma: int
    lma: int
    size: int
    cls: str
    cls_kind: str
    region: str | None
    lma_region: str | None
    physical: str | None
    core: int | None
    init: str
    in_image: int | None
    source: Source
    finding: str | None = None


@dataclass
class RegionRow:
    name: str
    origin: int
    length: int
    used: int
    physical_relation: str
    physical: str | None
    core: int | None
    finding: str | None = None


@dataclass
class Layout:
    regions: list[RegionRow] = field(default_factory=list)
    sections: list[SectionRow] = field(default_factory=list)
    unexplained_image: list[dict] = field(default_factory=list)
    per_core: dict = field(default_factory=dict)
    relations: list[dict] = field(default_factory=list)


def _elf_lma(p) -> dict[str, int]:
    out = {}
    for s in p.elf.sections:
        if not s.alloc:
            continue
        for ph in p.elf.segments:
            if ph.type == 1 and ph.vaddr <= s.addr < ph.vaddr + max(ph.memsz, 1):
                out[s.name] = ph.paddr + (s.addr - ph.vaddr)
                break
    return out


def recover_layout(p) -> Layout:
    st, prof, lm = p.store, p.profile, p.map
    lay = Layout()
    elf_secs = {s.name: s for s in p.elf.sections} if p.elf else {}
    lma_of = _elf_lma(p) if p.elf else {}

    raw = []
    if lm:
        for s in lm.sections:
            raw.append((s.name, s.addr, lma_of.get(s.name, s.lma if s.lma is not None else s.addr), s.size,
                        Source(lm.artifact, f"line {s.line}", s.name)))
    elif p.elf:
        for s in p.elf.sections:
            if s.alloc and s.size:
                raw.append((s.name, s.addr, lma_of.get(s.name, s.addr), s.size,
                            Source(p.elf_art.short, f"section [{s.index}] {s.name}")))

    for name, vma, lma, size, src in raw:
        if not size:
            continue
        es = elf_secs.get(name)
        cls, ck = classify_section(name, es.perms if es else None, es.nobits if es else None)
        vr = lm.region_of(vma) if lm else None
        lr = lm.region_of(lma) if lm else None
        w = prof.classify(vma)
        if cls in ("csa", "stack"):
            init, present = "runtime (not initialised)", None
        elif cls == "bss" or (es is not None and es.nobits):
            init, present = "zero-init", None
        elif lma != vma and not prof.same_location(lma, vma):
            init = "copy-init (load address differs from run address)"
            present = p.image.coverage(lma, size) if p.image.segments else None
        else:
            kind, _ = mem_kind(p, vma)
            if kind == "ram":
                init, present = "RAM without load image", None
            else:
                init = "in place" if kind == "flash" else "in place (memory type unknown)"
                present = p.image.coverage(lma, size) if p.image.segments else None
        row = SectionRow(name, vma, lma, size, cls, ck, vr.name if vr else None, lr.name if lr else None,
                         w.name if w else None, w.core if w else None, init, present, src)
        f = st.add("layout", "observed", "info",
                   f"{name}: run {vma:#010x} load {lma:#010x} size {size:#x} ({cls}, {init})", [src],
                   {"vma": vma, "lma": lma, "size": size, "class": cls, "class_evidence": ck,
                    "region": row.region, "physical": row.physical, "core": row.core}, level="L0")
        row.finding = f.id
        lay.sections.append(row)
        if present is not None and present < size:
            st.add("layout", "derived", "warning" if present == 0 else "note",
                   f"{name}: {present}/{size} bytes of its load image are present in the image at {lma:#010x}",
                   [src] + [Source(a.short, f"addr {lma:#010x}+{size:#x}") for a in p.image_artifacts],
                   {"present": present, "size": size}, [f.id])
    p.layout_rows = lay.sections

    views = build_views(p)

    # ---- section -> linker region -------------------------------------------
    if views.linker_regions:
        for row in lay.sections:
            sp = LinkerSection("linker-section", row.name, row.vma, row.size, [row.source])
            rel = relate_complete(sp, views.linker_regions)
            lay.relations.append({"a": row.name, "b": rel.b.name if rel.b else None, "rel": rel.relation,
                                  "pair": "section-region"})
            if rel.relation == OVERLAPS:
                st.conflict("layout", "error",
                            f"{row.name} [{row.vma:#010x}+{row.size:#x}] crosses the boundary of linker region "
                            f"{rel.b.name} [{rel.b.start:#010x}+{rel.b.size:#x}]",
                            [(row.source, f"{row.vma:#x}+{row.size:#x}"),
                             (rel.b.sources[0], f"{rel.b.start:#x}+{rel.b.size:#x}")], derived_from=[row.finding])
            elif rel.relation == OUTSIDE:
                st.add("layout", "derived", "warning",
                       f"{row.name} at {row.vma:#010x} is outside every linker MEMORY region",
                       [row.source], {}, [row.finding])

    # ---- section overlaps -----------------------------------------------------
    srt = sorted(lay.sections, key=lambda r: prof.canonical(r.vma))
    for a, b in zip(srt, srt[1:]):
        if prof.canonical(a.vma) + a.size > prof.canonical(b.vma):
            st.conflict("layout", "error", f"Sections {a.name} and {b.name} overlap at run address",
                        [(a.source, f"{a.vma:#x}+{a.size:#x}"), (b.source, f"{b.vma:#x}+{b.size:#x}")],
                        derived_from=[a.finding, b.finding])

    # ---- linker region -> physical -------------------------------------------
    for r in views.linker_regions:
        used = sum(s.size for s in lay.sections if s.region == r.name) + sum(
            s.size for s in lay.sections if s.lma_region == r.name and s.lma_region != s.region
            and s.init.startswith("copy"))
        rel = relate_physical(prof, r, views.physical)
        core = rel.b.meta.get("core") if rel.b else None
        rr = RegionRow(r.name, r.start, r.size, used, rel.relation, rel.b.name if rel.b else None, core)
        pct = 100.0 * used / r.size if r.size else 0.0
        f = st.add("layout", "derived", "error" if used > r.size else "info",
                   f"Linker region {r.name} [{r.start:#010x}+{r.size:#x}] used {used:#x} ({pct:.1f}%); "
                   f"physical: {rel.relation}" + (f" {rel.b.name}" if rel.b else "") +
                   (f" ({rel.note})" if rel.note else ""),
                   r.sources + (rel.b.sources if rel.b else []),
                   {"used": used, "length": r.size, "pct": round(pct, 2), "physical_relation": rel.relation,
                    "physical": rr.physical, "core": core})
        rr.finding = f.id
        lay.relations.append({"a": r.name, "b": rr.physical, "rel": rel.relation, "pair": "linker-physical"})
        if rel.relation == OVERLAPS:
            st.conflict("layout", "warning",
                        f"Linker region {r.name} [{r.start:#010x}..{r.end:#010x}) and documented {rel.b.name} "
                        f"[{rel.b.start:#010x}..{rel.b.end:#010x}) disagree on boundaries",
                        [(r.sources[0], f"{r.start:#x}..{r.end:#x}"),
                         ((rel.b.sources or [Source(prof.artifact.short, rel.b.name)])[0],
                          f"{rel.b.start:#x}..{rel.b.end:#x}")], derived_from=[f.id])
        lay.regions.append(rr)

    # ---- image -> linker load ranges -----------------------------------------
    if p.image.segments and lay.sections:
        loads = [LinkerSection("linker-section", s.name, prof.canonical(s.lma), s.size, [s.source])
                 for s in lay.sections if s.in_image is not None]
        for seg in views.image:
            for g0, g1 in _uncovered(prof.canonical(seg.start), seg.size, loads):
                gap = ImageMemoryRegion("image", f"{g0:#010x}", g0, g1 - g0, seg.sources)
                prel = relate_physical(prof, gap, views.physical)
                info = {"start": g0, "size": g1 - g0, "physical_relation": prel.relation,
                        "physical": prel.b.name if prel.b else None}
                lay.unexplained_image.append(info)
                lay.relations.append({"a": gap.name, "b": None, "rel": OUTSIDE, "pair": "image-linker"})
                boot_slot = prel.b is not None and prel.b.meta.get("kind") == "ucb-bmhd"
                st.add("layout", "derived", "note" if boot_slot else "warning",
                       f"Image bytes [{g0:#010x}+{g1 - g0:#x}] are OUTSIDE every linked load range"
                       + (f"; documented as {prel.b.name}" if prel.b else "; no documented physical region"),
                       seg.sources + (prel.b.sources if prel.b else []), info)

    # ---- per core (documented windows only) ----------------------------------
    for s in lay.sections:
        if s.core is not None and s.cls in ("data", "bss", "csa", "stack"):
            pc = lay.per_core.setdefault(s.core, {"data": 0, "bss": 0, "csa": 0, "stack": 0})
            pc[s.cls] += s.size
    unplaced = [s.name for s in lay.sections if s.cls in ("data", "bss", "csa", "stack") and s.physical is None]
    if unplaced:
        st.add("layout", "unknown", "note",
               f"{len(unplaced)} RAM sections cannot be attributed to a CPU: no documented physical region "
               f"covers them in profile {prof.id}", [], {"sections": unplaced[:50]})
    return lay


def _uncovered(start, size, loads):
    parts = [(start, start + size)]
    for l in loads:
        a, b = l.start, l.end
        nxt = []
        for x, y in parts:
            if b <= x or a >= y:
                nxt.append((x, y))
            else:
                if x < a:
                    nxt.append((x, a))
                if b < y:
                    nxt.append((b, y))
        parts = nxt
    return [q for q in parts if q[1] - q[0] >= 4]


def linker_draft(p, lay: Layout) -> str:
    """GNU-LD style MEMORY{} + placement skeleton from evidence. A draft for review:
    alignment, KEEP() and input ordering are not recoverable from a map alone."""
    out = ["/* Linker layout draft reconstructed by rea-auto - review before use.",
           f" * profile {p.profile.id}; evidence ids in comments. */", "", "MEMORY", "{"]
    for r in lay.regions:
        out.append(f"  {r.name:<16} : ORIGIN = {r.origin:#010x}, LENGTH = {r.length:#x}"
                   f"   /* used {r.used:#x}; physical {r.physical_relation} {r.physical or ''}; {r.finding} */")
    out += ["}", "", "SECTIONS", "{"]
    for s in sorted(lay.sections, key=lambda s: (s.region or "~", s.vma)):
        at = f" AT> {s.lma_region}" if s.lma_region and s.lma_region != s.region else ""
        out.append(f"  {s.name:<28} {s.vma:#010x} : {{ /* {s.size:#x} {s.cls} */ }} > "
                   f"{s.region or '/*?*/'}{at}   /* {s.finding} */")
    out.append("}")
    return "\n".join(out)
