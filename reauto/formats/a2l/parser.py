"""ASAM MCD-2 MC (A2L) parser - the subset needed for address/calibration correlation.

Blocks are parsed generically (/begin X ... /end X) with line numbers kept for
provenance; typed views are built for CHARACTERISTIC, MEASUREMENT, AXIS_PTS,
RECORD_LAYOUT, COMPU_METHOD, MEMORY_SEGMENT and MOD_COMMON byte order.
"""
from __future__ import annotations

import math
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path

DTYPE = {"UBYTE": (1, "B"), "SBYTE": (1, "b"), "UWORD": (2, "H"), "SWORD": (2, "h"),
         "ULONG": (4, "I"), "SLONG": (4, "i"), "A_UINT64": (8, "Q"), "A_INT64": (8, "q"),
         "FLOAT16_IEEE": (2, "e"), "FLOAT32_IEEE": (4, "f"), "FLOAT64_IEEE": (8, "d")}

RE_TOKEN = re.compile(r'"(?:[^"\\]|\\.|"")*"|/\*.*?\*/|//[^\n]*|\S+', re.S)


@dataclass
class Block:
    kind: str
    line: int
    tokens: list[tuple[str, int]] = field(default_factory=list)
    children: list["Block"] = field(default_factory=list)

    def args(self, n: int) -> list[str]:
        return [t for t, _ in self.tokens[:n]]

    def kw(self, key: str, n: int = 1) -> list[str] | None:
        toks = [t for t, _ in self.tokens]
        for i, t in enumerate(toks):
            if t == key and i >= 1:
                return toks[i + 1 : i + 1 + n]
        return None

    def child(self, kind: str) -> list["Block"]:
        return [c for c in self.children if c.kind == kind]


def _tokenize(text: str):
    line = 1
    pos = 0
    for m in RE_TOKEN.finditer(text):
        line += text.count("\n", pos, m.start())
        pos = m.start()
        t = m.group(0)
        if t.startswith("/*") or t.startswith("//"):
            continue
        if t.startswith('"'):
            t = t[1:-1].replace('\\"', '"').replace('""', '"')
            yield ("STR", t, line)
        else:
            yield ("TOK", t, line)


def parse_blocks(text: str) -> Block:
    root = Block("ROOT", 0)
    stack = [root]
    toks = list(_tokenize(text))
    i = 0
    while i < len(toks):
        typ, t, ln = toks[i]
        if typ == "TOK" and t == "/begin" and i + 1 < len(toks):
            b = Block(toks[i + 1][1], ln)
            stack[-1].children.append(b)
            stack.append(b)
            i += 2
            continue
        if typ == "TOK" and t == "/end" and i + 1 < len(toks):
            if len(stack) > 1:
                stack.pop()
            i += 2
            continue
        stack[-1].tokens.append((t, ln))
        i += 1
    return root


def _int(s: str) -> int:
    return int(s, 0)


def _float(s: str) -> float:
    try:
        return float(s)
    except ValueError:
        return float(int(s, 0))


@dataclass
class CompuMethod:
    name: str
    ctype: str
    coeffs: list[float] | None = None
    linear: tuple[float, float] | None = None
    unit: str = ""

    def to_phys(self, raw: float) -> float | None:
        if self.ctype == "IDENTICAL":
            return raw
        if self.ctype == "LINEAR" and self.linear:
            a, b = self.linear
            return a * raw + b
        if self.ctype == "RAT_FUNC" and self.coeffs:
            a, b, c, d, e, f = self.coeffs
            # raw = (a*x^2 + b*x + c) / (d*x^2 + e*x + f), solved for x when a = d = 0
            if a == 0 and d == 0 and (b - e * raw) != 0:
                return (f * raw - c) / (b - e * raw)
        return None


@dataclass
class RecordLayout:
    name: str
    fnc_dtype: str | None = None
    axis_dtype: dict[str, str] = field(default_factory=dict)  # X/Y/Z -> dtype
    no_axis_dtype: dict[str, str] = field(default_factory=dict)


@dataclass
class AxisDescr:
    attribute: str
    max_points: int
    axis_pts_ref: str | None = None


@dataclass
class A2LObject:
    kind: str  # CHARACTERISTIC | MEASUREMENT | AXIS_PTS
    name: str
    line: int
    address: int | None
    ctype: str | None = None  # VALUE, CURVE, ... for characteristics
    deposit: str | None = None
    datatype: str | None = None  # measurements
    conversion: str | None = None
    lower: float | None = None
    upper: float | None = None
    dims: list[int] = field(default_factory=list)
    axes: list[AxisDescr] = field(default_factory=list)
    symbol_link: tuple[str, int] | None = None
    ext: int | None = None


@dataclass
class MemorySegment:
    name: str
    prg_type: str
    mem_type: str
    address: int
    size: int
    line: int


@dataclass
class A2L:
    path: str
    little_endian: bool = True
    characteristics: list[A2LObject] = field(default_factory=list)
    measurements: list[A2LObject] = field(default_factory=list)
    axis_pts: list[A2LObject] = field(default_factory=list)
    layouts: dict[str, RecordLayout] = field(default_factory=dict)
    compu: dict[str, CompuMethod] = field(default_factory=dict)
    segments: list[MemorySegment] = field(default_factory=list)
    problems: list[tuple[int, str]] = field(default_factory=list)

    def objects(self):
        return self.characteristics + self.measurements + self.axis_pts

    # ---- sizing --------------------------------------------------------
    def size_of(self, o: A2LObject) -> tuple[int | None, str]:
        """Return (size_bytes, note). None when the layout is not supported."""
        if o.kind == "MEASUREMENT":
            if o.datatype not in DTYPE:
                return None, f"unknown datatype {o.datatype}"
            return DTYPE[o.datatype][0] * max(1, math.prod(o.dims or [1])), ""
        rl = self.layouts.get(o.deposit or "")
        if rl is None:
            return None, f"record layout {o.deposit} not found"
        if o.kind == "AXIS_PTS":
            dt = rl.axis_dtype.get("X")
            if dt not in DTYPE:
                return None, "AXIS_PTS layout without AXIS_PTS_X"
            n = o.dims[0] if o.dims else 0
            return DTYPE[dt][0] * n + (DTYPE[rl.no_axis_dtype["X"]][0] if "X" in rl.no_axis_dtype else 0), \
                "assumes no alignment padding"
        if rl.fnc_dtype not in DTYPE:
            return None, "record layout without FNC_VALUES"
        fsz = DTYPE[rl.fnc_dtype][0]
        if o.ctype == "VALUE":
            return fsz, ""
        if o.ctype in ("VAL_BLK", "ASCII"):
            n = math.prod(o.dims) if o.dims else 1
            return (1 if o.ctype == "ASCII" else fsz) * n, ""
        if o.ctype in ("CURVE", "MAP", "CUBOID"):
            total, cells = 0, 1
            for ax, axis in zip("XYZ", o.axes):
                cells *= axis.max_points
                if axis.attribute == "STD_AXIS":
                    adt = rl.axis_dtype.get(ax)
                    if adt not in DTYPE:
                        return None, f"STD_AXIS {ax} without AXIS_PTS_{ax} in layout"
                    total += DTYPE[adt][0] * axis.max_points
                    if ax in rl.no_axis_dtype:
                        total += DTYPE[rl.no_axis_dtype[ax]][0]
            return total + fsz * cells, "assumes no alignment padding, max axis points"
        return None, f"characteristic type {o.ctype} not sized in v1"

    def value_dtype(self, o: A2LObject) -> str | None:
        if o.kind == "MEASUREMENT":
            return o.datatype
        rl = self.layouts.get(o.deposit or "")
        return rl.fnc_dtype if rl else None

    def decode(self, o: A2LObject, raw: bytes) -> float | None:
        dt = self.value_dtype(o)
        if dt not in DTYPE or len(raw) < DTYPE[dt][0]:
            return None
        return struct.unpack(("<" if self.little_endian else ">") + DTYPE[dt][1], raw[: DTYPE[dt][0]])[0]


def parse_a2l(path: str | Path) -> A2L:
    text = Path(path).read_text(errors="replace")
    root = parse_blocks(text)
    a2l = A2L(str(path))

    def walk(b: Block):
        yield b
        for c in b.children:
            yield from walk(c)

    for b in walk(root):
        try:
            if b.kind == "MOD_COMMON":
                bo = b.kw("BYTE_ORDER")
                if bo:
                    a2l.little_endian = bo[0] in ("MSB_LAST", "LITTLE_ENDIAN")
            elif b.kind == "COMPU_METHOD":
                name, _l, ctype, _fmt, unit = b.args(5)
                cm = CompuMethod(name, ctype, unit=unit)
                c = b.kw("COEFFS", 6)
                if c:
                    cm.coeffs = [_float(x) for x in c]
                c = b.kw("COEFFS_LINEAR", 2)
                if c:
                    cm.linear = (_float(c[0]), _float(c[1]))
                a2l.compu[name] = cm
            elif b.kind == "RECORD_LAYOUT":
                rl = RecordLayout(b.args(1)[0])
                f = b.kw("FNC_VALUES", 2)
                if f:
                    rl.fnc_dtype = f[1]
                for ax in "XYZ":
                    k = b.kw(f"AXIS_PTS_{ax}", 2)
                    if k:
                        rl.axis_dtype[ax] = k[1]
                    k = b.kw(f"NO_AXIS_PTS_{ax}", 2)
                    if k:
                        rl.no_axis_dtype[ax] = k[1]
                a2l.layouts[rl.name] = rl
            elif b.kind == "MEMORY_SEGMENT":
                name, _l, prg, mem, _attr, addr, size = b.args(7)
                a2l.segments.append(MemorySegment(name, prg, mem, _int(addr), _int(size), b.line))
            elif b.kind == "CHARACTERISTIC":
                name, _l, ctype, addr, dep, _md, conv, lo, hi = b.args(9)
                o = A2LObject("CHARACTERISTIC", name, b.line, _int(addr), ctype, dep, None, conv,
                              _float(lo), _float(hi))
                md = _dims(b)
                if md:
                    o.dims = md
                for ad in b.child("AXIS_DESCR"):
                    attr, _iq, _cv, mx = ad.args(4)
                    ref = ad.kw("AXIS_PTS_REF")
                    o.axes.append(AxisDescr(attr, _int(mx), ref[0] if ref else None))
                _common(b, o)
                a2l.characteristics.append(o)
            elif b.kind == "MEASUREMENT":
                name, _l, dt, conv, _res, _acc, lo, hi = b.args(8)
                ea = b.kw("ECU_ADDRESS")
                o = A2LObject("MEASUREMENT", name, b.line, _int(ea[0]) if ea else None, None, None, dt, conv,
                              _float(lo), _float(hi))
                o.dims = _dims(b)
                _common(b, o)
                a2l.measurements.append(o)
            elif b.kind == "AXIS_PTS":
                name, _l, addr, _iq, dep, _md, conv, mx, lo, hi = b.args(10)
                o = A2LObject("AXIS_PTS", name, b.line, _int(addr), None, dep, None, conv, _float(lo), _float(hi),
                              [_int(mx)])
                _common(b, o)
                a2l.axis_pts.append(o)
        except (ValueError, IndexError, TypeError) as e:
            a2l.problems.append((b.line, f"{b.kind}: cannot parse ({e})"))
    return a2l


def _dims(b: Block) -> list[int]:
    toks = [t for t, _ in b.tokens]
    for key in ("MATRIX_DIM", "ARRAY_SIZE", "NUMBER"):
        if key in toks:
            i = toks.index(key)
            out = []
            for t in toks[i + 1 : i + 4]:
                try:
                    out.append(int(t, 0))
                except ValueError:
                    break
            return [d for d in out if d > 0] or [1]
    return []


def _common(b: Block, o: A2LObject) -> None:
    sl = b.kw("SYMBOL_LINK", 2)
    if sl:
        try:
            o.symbol_link = (sl[0], _int(sl[1]))
        except ValueError:
            o.symbol_link = (sl[0], 0)
    ext = b.kw("ECU_ADDRESS_EXTENSION")
    if ext:
        o.ext = _int(ext[0])
