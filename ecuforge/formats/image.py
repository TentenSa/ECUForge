"""Sparse memory image built from HEX / S-record / ELF load data.

Bytes are stored in address-contiguous segments. Gaps are never filled, so
"not in image" stays distinguishable from "erased" (0x00 / 0xFF).
"""
from __future__ import annotations

import bisect
import struct
from dataclasses import dataclass, field


@dataclass
class Segment:
    start: int
    data: bytearray
    origin: str  # artifact short id
    locator: str  # e.g. "lines 3-410" or "ELF section .text"

    @property
    def end(self) -> int:  # exclusive
        return self.start + len(self.data)


@dataclass
class MemoryImage:
    segments: list[Segment] = field(default_factory=list)
    entry: int | None = None
    overlaps: list[tuple[int, int, str]] = field(default_factory=list)
    # optional cached/non-cached alias resolver, set by Project from the device profile
    alias: object = None
    # record accounting set by loaders: every non-blank input line is either an accepted record or an event
    stats: dict = field(default_factory=dict)

    # ---- construction -------------------------------------------------
    def add(self, addr: int, data: bytes, origin: str, locator: str) -> None:
        """Insert bytes; merges with an adjacent segment from the same origin."""
        if not data:
            return
        for s in self.segments:
            lo, hi = max(s.start, addr), min(s.end, addr + len(data))
            if lo < hi:
                self.overlaps.append((lo, hi - lo, f"{s.locator} vs {locator}"))
        starts = [s.start for s in self.segments]
        i = bisect.bisect_left(starts, addr)
        if i > 0:
            prev = self.segments[i - 1]
            if prev.end == addr and prev.origin == origin:
                prev.data.extend(data)
                self._merge_forward(i - 1)
                return
        self.segments.insert(i, Segment(addr, bytearray(data), origin, locator))
        self._merge_forward(i)

    def _merge_forward(self, i: int) -> None:
        while i + 1 < len(self.segments):
            a, b = self.segments[i], self.segments[i + 1]
            if a.end == b.start and a.origin == b.origin:
                a.data.extend(b.data)
                a.locator = _join_locators(a.locator, b.locator)
                del self.segments[i + 1]
            else:
                break

    # ---- queries --------------------------------------------------------
    def find(self, addr: int) -> Segment | None:
        starts = [s.start for s in self.segments]
        i = bisect.bisect_right(starts, addr) - 1
        if i >= 0 and self.segments[i].start <= addr < self.segments[i].end:
            return self.segments[i]
        return None

    def read(self, addr: int, n: int) -> bytes | None:
        """Return n bytes only if fully covered by a single segment.
        Falls back to the other bus alias (e.g. 0xA0.. <-> 0x80..) when set."""
        b = self._read(addr, n)
        if b is None and self.alias is not None:
            alt = self.alias(addr)
            if alt is not None:
                b = self._read(alt, n)
        return b

    def _read(self, addr: int, n: int) -> bytes | None:
        s = self.find(addr)
        if s is None or addr + n > s.end:
            return None
        off = addr - s.start
        return bytes(s.data[off : off + n])

    def find_any(self, addr: int) -> "Segment | None":
        s = self.find(addr)
        if s is None and self.alias is not None and self.alias(addr) is not None:
            s = self.find(self.alias(addr))
        return s

    def coverage(self, addr: int, n: int) -> int:
        """Number of bytes in [addr, addr+n) present in the image (alias-aware)."""
        c = self._coverage(addr, n)
        if c == 0 and self.alias is not None and self.alias(addr) is not None:
            c = self._coverage(self.alias(addr), n)
        return c

    def _coverage(self, addr: int, n: int) -> int:
        total = 0
        for s in self.segments:
            lo, hi = max(s.start, addr), min(s.end, addr + n)
            if lo < hi:
                total += hi - lo
        return total

    def u32(self, addr: int, little: bool = True) -> int | None:
        b = self.read(addr, 4)
        return None if b is None else struct.unpack("<I" if little else ">I", b)[0]

    def u16(self, addr: int, little: bool = True) -> int | None:
        b = self.read(addr, 2)
        return None if b is None else struct.unpack("<H" if little else ">H", b)[0]

    @property
    def size(self) -> int:
        return sum(len(s.data) for s in self.segments)

    def regions(self) -> list[tuple[int, int, str, str]]:
        return [(s.start, len(s.data), s.origin, s.locator) for s in self.segments]


def _join_locators(a: str, b: str) -> str:
    # "lines 3-10" + "lines 11-20" -> "lines 3-20"
    if a.startswith("lines ") and b.startswith("lines "):
        a0 = a[6:].split("-")[0]
        b1 = b[6:].split("-")[-1]
        return f"lines {a0}-{b1}"
    return f"{a}; {b}"
