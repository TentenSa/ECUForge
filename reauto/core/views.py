"""Three independent address-space views and the relations between them.

  Physical memory  what the silicon has        (MCU profile, documented facts only)
  Linker memory    what the build intended     (map MEMORY / LSL / ELF sections)
  Image memory     what will be programmed     (HEX / S19 / ELF load segments)

No view overrides another. Each pair is compared and the relation recorded:

  CONTAINED  fully inside
  ALIASED    inside the other bus view of a documented alias (cached / non-cached)
  OVERLAPS   partly inside; boundaries disagree -> also reported as a CONFLICT finding
  OUTSIDE    not inside any element of a view that is complete for that question
  UNKNOWN    the view has no documented element to compare against
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .evidence import Source

CONTAINED, ALIASED, OVERLAPS, OUTSIDE, UNKNOWN = "CONTAINED", "ALIASED", "OVERLAPS", "OUTSIDE", "UNKNOWN"


@dataclass
class Span:
    view: str  # physical | linker-region | linker-section | image
    name: str
    start: int
    size: int
    sources: list[Source] = field(default_factory=list)
    meta: dict = field(default_factory=dict)

    @property
    def end(self) -> int:
        return self.start + self.size


@dataclass
class Relation:
    a: Span
    b: Span | None
    relation: str
    note: str = ""


@dataclass
class Views:
    physical: list[Span]
    linker_regions: list[Span]
    linker_sections: list[Span]
    image: list[Span]
    relations: list[Relation] = field(default_factory=list)


def build_views(p) -> Views:
    prof = p.profile
    phys = [Span("physical", w.name, w.start, w.size, prof.window_source(w),
                 {"kind": w.kind, "core": w.core, "cached": w.cached}) for w in prof.windows]
    regions, sections = [], []
    if p.map:
        for r in p.map.regions:
            regions.append(Span("linker-region", r.name, r.origin, r.length,
                                [Source(p.map.artifact, f"line {r.line}" if r.line else "memory table", r.name)],
                                {"attrs": r.attrs, "aliases": list(r.aliases)}))
    for row in getattr(p, "layout_rows", []):
        sections.append(Span("linker-section", row.name, row.vma, row.size, [row.source],
                             {"lma": row.lma, "class": row.cls}))
    image = [Span("image", f"{a:#010x}+{n:#x}", a, n, [Source(o, loc)]) for a, n, o, loc in p.image.regions()]
    return Views(phys, regions, sections, image)


def relate_physical(prof, s: Span, phys: list[Span]) -> Relation:
    """Linker or image span vs documented physical windows."""
    for w in phys:
        if w.start <= s.start and s.end <= w.end:
            return Relation(s, w, CONTAINED)
    alt = prof.alternate(s.start)
    if alt is not None:
        for w in phys:
            if w.start <= alt and alt + s.size <= w.end:
                return Relation(s, w, ALIASED, f"via documented bus alias {s.start:#010x} -> {alt:#010x}")
    for w in phys:
        if s.start < w.end and w.start < s.end:
            return Relation(s, w, OVERLAPS)
    return Relation(s, None, UNKNOWN, "no documented physical region covers this address range")


def relate_complete(s: Span, view: list[Span], addr_fn=lambda x: x) -> Relation:
    """Span vs a view that is complete (e.g. image bytes vs all linked load ranges)."""
    lo, hi = addr_fn(s.start), addr_fn(s.start) + s.size
    inside = [v for v in view if v.start <= lo and hi <= v.end]
    if inside:
        return Relation(s, inside[0], CONTAINED)
    touching = [v for v in view if lo < v.end and v.start < hi]
    if touching:
        return Relation(s, touching[0], OVERLAPS)
    return Relation(s, None, OUTSIDE)


def linker_mem_kind(p, addr: int) -> tuple[str | None, Source | None]:
    """RAM/ROM as stated by the build itself (region attributes, LSL type, ELF flags)."""
    if p.map:
        r = p.map.region_of(addr)
        if r is not None:
            src = Source(p.map.artifact, f"line {r.line}" if r.line else "memory table", r.name)
            a = r.attrs.split("!")[0]
            if r.attrs.startswith("lsl:"):
                t = r.attrs[4:]
                if t in ("ram", "rom"):
                    return ("ram" if t == "ram" else "flash"), src
            elif a and "w" in a:
                return "ram", src
            elif a and ("x" in a or "r" in a):
                return "flash", src
    if p.elf:
        for s in p.elf.sections:
            if s.alloc and s.size and s.addr <= addr < s.addr + s.size:
                return ("ram" if "w" in s.perms else "flash"), Source(p.elf_art.short, f"section {s.name} flags")
    return None, None


def mem_kind(p, addr: int) -> tuple[str | None, str]:
    """Combined answer with its basis: profile (documented) first, else linker. Disagreements are
    surfaced by layout recovery, not resolved here."""
    k = p.profile.mem_kind(addr)
    if k:
        return k, "profile"
    k, _ = linker_mem_kind(p, addr)
    return (k, "linker") if k else (None, "unknown")
