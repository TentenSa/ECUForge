"""Toolchain-neutral link map model shared by the GNU/HighTec and TASKING parsers."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class MemoryRegion:
    name: str
    origin: int
    length: int
    attrs: str = ""
    line: int = 0
    # TASKING LSL can give several bus mappings for one memory (cached / non-cached)
    aliases: list[int] = field(default_factory=list)
    used: int | None = None  # bytes used, when the map reports it

    @property
    def end(self) -> int:
        return self.origin + self.length

    def contains(self, addr: int) -> bool:
        return self.origin <= addr < self.end


@dataclass
class InputSection:
    name: str
    addr: int
    size: int
    obj: str  # object file or archive(member)
    line: int = 0


@dataclass
class OutputSection:
    name: str
    addr: int  # VMA / run address
    size: int
    lma: int | None = None  # load address when different (copy-init data)
    region: str | None = None  # memory / chip name the map attributes it to
    line: int = 0
    inputs: list[InputSection] = field(default_factory=list)


@dataclass
class MapSymbol:
    name: str
    addr: int
    section: str | None = None
    obj: str | None = None
    size: int | None = None
    line: int = 0
    assignment: bool = False  # linker-script assignment (e.g. __CSA0 = .)


@dataclass
class LinkMap:
    toolchain: str  # "gnu" | "tasking"
    artifact: str
    regions: list[MemoryRegion] = field(default_factory=list)
    sections: list[OutputSection] = field(default_factory=list)
    symbols: list[MapSymbol] = field(default_factory=list)
    warnings: list[tuple[int, str]] = field(default_factory=list)

    def symbol(self, name: str) -> MapSymbol | None:
        return next((s for s in self.symbols if s.name == name), None)

    def symbol_index(self) -> dict[str, MapSymbol]:
        idx: dict[str, MapSymbol] = {}
        for s in self.symbols:
            idx.setdefault(s.name, s)
        return idx

    def region_of(self, addr: int) -> MemoryRegion | None:
        for r in self.regions:
            if r.contains(addr) or any(a <= addr < a + r.length for a in r.aliases):
                return r
        return None

    def section_of(self, addr: int) -> OutputSection | None:
        for s in self.sections:
            if s.size and s.addr <= addr < s.addr + s.size:
                return s
        return None
