"""Minimal, dependency-free ELF32 reader aimed at TriCore (EM_TRICORE = 44).

Reads section headers, program headers and the symbol table. Loads PT_LOAD
segments into a MemoryImage at their *load* (physical) address, which is what
ends up in flash and what a hex file contains.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

from .image import MemoryImage

EM_NAMES = {44: "TriCore", 40: "ARM", 20: "PowerPC", 243: "RISC-V", 0x5441: "TriCore(alt)"}
SHT_NOBITS, SHT_SYMTAB = 8, 2
SHF_WRITE, SHF_ALLOC, SHF_EXEC = 1, 2, 4
STT = {0: "notype", 1: "object", 2: "func", 3: "section", 4: "file"}
STB = {0: "local", 1: "global", 2: "weak"}


@dataclass
class ElfSection:
    index: int
    name: str
    type: int
    flags: int
    addr: int
    offset: int
    size: int

    @property
    def alloc(self) -> bool:
        return bool(self.flags & SHF_ALLOC)

    @property
    def nobits(self) -> bool:
        return self.type == SHT_NOBITS

    @property
    def perms(self) -> str:
        return ("r" + ("w" if self.flags & SHF_WRITE else "-") + ("x" if self.flags & SHF_EXEC else "-"))


@dataclass
class ElfSegment:
    type: int
    offset: int
    vaddr: int
    paddr: int
    filesz: int
    memsz: int
    flags: int


@dataclass
class ElfSymbol:
    name: str
    value: int
    size: int
    type: str
    bind: str
    section: str | None


@dataclass
class ElfFile:
    path: str
    machine: int
    entry: int
    little: bool
    sections: list[ElfSection] = field(default_factory=list)
    segments: list[ElfSegment] = field(default_factory=list)
    symbols: list[ElfSymbol] = field(default_factory=list)
    _raw: bytes = b""

    @property
    def machine_name(self) -> str:
        return EM_NAMES.get(self.machine, f"EM_{self.machine}")

    def section_bytes(self, sec: ElfSection) -> bytes | None:
        if sec.nobits:
            return None
        return self._raw[sec.offset : sec.offset + sec.size]

    def load_image(self, origin: str, image: MemoryImage | None = None) -> MemoryImage:
        img = image or MemoryImage()
        for i, ph in enumerate(self.segments):
            if ph.type == 1 and ph.filesz:  # PT_LOAD
                img.add(ph.paddr, self._raw[ph.offset : ph.offset + ph.filesz], origin,
                        f"PT_LOAD[{i}] vaddr {ph.vaddr:#010x}")
        img.entry = self.entry
        return img


def load_elf(path: str | Path) -> ElfFile:
    raw = Path(path).read_bytes()
    if raw[:4] != b"\x7fELF":
        raise ValueError("not an ELF file")
    if raw[4] != 1:
        raise ValueError("only ELF32 is supported in v1")
    little = raw[5] == 1
    e = "<" if little else ">"
    (_t, machine, _v, entry, phoff, shoff, _fl, _eh, phentsz, phnum, shentsz, shnum,
     shstrndx) = struct.unpack_from(e + "HHIIIIIHHHHHH", raw, 16)
    elf = ElfFile(str(path), machine, entry, little, _raw=raw)

    hdrs = [struct.unpack_from(e + "IIIIIIIIII", raw, shoff + i * shentsz) for i in range(shnum)]
    shstr = hdrs[shstrndx] if shnum else None

    def cstr(tab_off: int, idx: int) -> str:
        end = raw.index(b"\0", tab_off + idx)
        return raw[tab_off + idx : end].decode(errors="replace")

    for i, h in enumerate(hdrs):
        name = cstr(shstr[4], h[0]) if shstr else ""
        elf.sections.append(ElfSection(i, name, h[1], h[2], h[3], h[4], h[5]))

    for i in range(phnum):
        p = struct.unpack_from(e + "IIIIIIII", raw, phoff + i * phentsz)
        elf.segments.append(ElfSegment(p[0], p[1], p[2], p[3], p[4], p[5], p[6]))

    for i, h in enumerate(hdrs):
        if h[1] != SHT_SYMTAB:
            continue
        strtab = hdrs[h[6]]
        for j in range(h[5] // 16):
            st_name, value, size, info, _o, shndx = struct.unpack_from(e + "IIIBBH", raw, h[4] + j * 16)
            if not st_name:
                continue
            sec = elf.sections[shndx].name if 0 < shndx < len(elf.sections) else None
            elf.symbols.append(ElfSymbol(cstr(strtab[4], st_name), value, size,
                                         STT.get(info & 0xF, str(info & 0xF)),
                                         STB.get(info >> 4, str(info >> 4)), sec))
    return elf
