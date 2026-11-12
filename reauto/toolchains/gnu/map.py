"""GNU LD / HighTec TriCore GCC map file parser.

Handles: Memory Configuration table, output sections (incl. wrapped names and
"load address" suffixes), input sections with object attribution (incl.
wrapped long names such as .text.NvM_MainFunction), symbols and linker-script
assignments (incl. PROVIDE). Discarded / common-symbol blocks are skipped.
"""
from __future__ import annotations

import re
from pathlib import Path

from ...formats.events import ParseEvent
from ...formats.map.model import InputSection, LinkMap, MapSymbol, MemoryRegion, OutputSection

H = r"0x[0-9a-fA-F]+"
RE_MEM_ROW = re.compile(rf"^(\S+)\s+({H})\s+({H})(?:\s+(\S+))?\s*$")
RE_OUT_FULL = re.compile(rf"^(\S+)\s+({H})\s+({H})(?:\s+load address\s+({H}))?\s*$")
RE_OUT_NAME = re.compile(r"^([.\w$][^\s]*)\s*$")
RE_ADDR_SIZE = re.compile(rf"^\s+({H})\s+({H})(?:\s+load address\s+({H}))?\s*$")
RE_IN_FULL = re.compile(rf"^ ([^\s*][^\s]*)\s+({H})\s+({H})\s+(\S.*)$")
RE_IN_NAME = re.compile(r"^ ([^\s*][^\s]*)\s*$")
RE_IN_CONT = re.compile(rf"^\s+({H})\s+({H})\s+(\S.*)$")
RE_SYM = re.compile(rf"^\s{{8,}}({H})\s+(\S.*)$")
RE_ASSIGN_NAME = re.compile(r"(?:PROVIDE(?:_HIDDEN)?\s*\(\s*)?([A-Za-z_.$][\w.$]*)\s*=")

SKIP_HEADS = ("LOAD ", "OUTPUT(", "START GROUP", "END GROUP", "OUTPUT_FORMAT", "TARGET(")


def parse_gnu_map(path: str | Path, artifact: str) -> LinkMap:
    lm = LinkMap("gnu", artifact)
    lines = Path(path).read_text(errors="replace").splitlines()
    mode = "pre"
    cur_out: OutputSection | None = None
    cur_in: InputSection | None = None
    pending_out: tuple[str, int] | None = None
    pending_in: tuple[str, int] | None = None

    for ln, line in enumerate(lines, 1):
        s = line.strip()
        if s == "Memory Configuration":
            mode = "mem"
            continue
        if s == "Linker script and memory map":
            mode = "map"
            continue
        if s.startswith("Discarded input sections") or s.startswith("Allocating common symbols"):
            mode = "skip"
            continue
        if s.startswith("Cross Reference Table"):
            mode = "skip"
            continue

        if mode == "mem":
            m = RE_MEM_ROW.match(line)
            if m and m.group(1) not in ("Name", "*default*"):
                lm.regions.append(MemoryRegion(m.group(1), int(m.group(2), 16), int(m.group(3), 16),
                                               m.group(4) or "", ln, mem_type=_mem_type(m.group(4) or "")))
            elif s and not s.startswith("Name") and not s.startswith("*default*"):
                lm.events.append(ParseEvent("UNRECOGNIZED_CONSTRUCT", ln, s, True, "memory table"))
            continue
        if mode != "map":
            continue

        # ---- continuation of a wrapped name --------------------------
        if pending_out:
            m = RE_ADDR_SIZE.match(line)
            if m:
                cur_out = _new_out(lm, pending_out[0], m, pending_out[1])
                cur_in = None
                pending_out = None
                continue
            lm.events.append(ParseEvent("INCOMPLETE_ENTRY", pending_out[1],
                                        f"output section name without address/size: {pending_out[0]}", True,
                                        "memory map"))
            pending_out = None
        if pending_in:
            m = RE_IN_CONT.match(line)
            if m and cur_out is not None:
                cur_in = InputSection(pending_in[0], int(m.group(1), 16), int(m.group(2), 16),
                                      m.group(3).strip(), pending_in[1])
                cur_out.inputs.append(cur_in)
                pending_in = None
                continue
            lm.events.append(ParseEvent("INCOMPLETE_ENTRY", pending_in[1],
                                        f"input section name without address/size: {pending_in[0]}", True, _ctx(cur_out)))
            pending_in = None

        if not line or line.startswith(SKIP_HEADS):
            continue

        # ---- output section (column 0) ------------------------------
        if not line[0].isspace():
            m = RE_OUT_FULL.match(line)
            if m:
                cur_out = _new_out(lm, m.group(1), m, ln, name_group=True)
                cur_in = None
                continue
            m = RE_OUT_NAME.match(line)
            if m:
                pending_out = (m.group(1), ln)
            else:
                lm.events.append(ParseEvent("UNRECOGNIZED_CONSTRUCT", ln, s, cur_out is not None, _ctx(cur_out)))
            continue

        # ---- input section (single leading space) -------------------
        if line.startswith(" ") and not line.startswith("  "):
            if s.startswith("*") or s.startswith("FILL") or s.startswith("[!provide]"):
                continue
            m = RE_IN_FULL.match(line)
            if m and cur_out is not None:
                cur_in = InputSection(m.group(1), int(m.group(2), 16), int(m.group(3), 16),
                                      m.group(4).strip(), ln)
                cur_out.inputs.append(cur_in)
                continue
            m = RE_IN_NAME.match(line)
            if m:
                pending_in = (m.group(1), ln)
            else:
                lm.events.append(ParseEvent("UNRECOGNIZED_CONSTRUCT", ln, s, cur_out is not None, _ctx(cur_out)))
            continue

        # ---- symbol / assignment ------------------------------------
        m = RE_SYM.match(line)
        if m:
            addr, rest = int(m.group(1), 16), m.group(2).strip()
            if rest.startswith("[!provide]"):
                continue
            if "=" in rest:
                a = RE_ASSIGN_NAME.search(rest)
                if a and a.group(1) == ".":
                    continue  # location-counter assignment, not a symbol
                if a:
                    lm.symbols.append(MapSymbol(a.group(1), addr, cur_out.name if cur_out else None,
                                                None, None, ln, assignment=True))
                else:
                    lm.events.append(ParseEvent("UNRECOGNIZED_CONSTRUCT", ln, s, cur_out is not None, _ctx(cur_out)))
            elif re.fullmatch(r"[A-Za-z_.$][\w.$@]*", rest):
                lm.symbols.append(MapSymbol(rest, addr, cur_out.name if cur_out else None,
                                            cur_in.obj if cur_in else None, None, ln))
            else:
                lm.events.append(ParseEvent("UNRECOGNIZED_CONSTRUCT", ln, s, cur_out is not None, _ctx(cur_out)))
            continue
        lm.events.append(ParseEvent("UNRECOGNIZED_CONSTRUCT", ln, s, cur_out is not None, _ctx(cur_out)))
    return lm


def _ctx(cur_out) -> str:
    """Content inside an output section block can change layout results; header noise cannot."""
    return f"output section {cur_out.name}" if cur_out is not None else "map header"


def _mem_type(attrs: str) -> str | None:
    """GNU ld MEMORY attributes: letters before '!' are granted, after are negated."""
    granted = attrs.split("!")[0].lower()
    if "w" in granted:
        return "ram"
    if granted and ("x" in granted or "r" in granted):
        return "rom"
    return None


def _new_out(lm: LinkMap, name: str, m: re.Match, ln: int, name_group: bool = False) -> OutputSection:
    g = 2 if name_group else 1
    addr, size = int(m.group(g), 16), int(m.group(g + 1), 16)
    lma = m.group(g + 2)
    sec = OutputSection(name, addr, size, int(lma, 16) if lma else None, None, ln)
    r = lm.region_of(addr)
    sec.region = r.name if r else None
    lm.sections.append(sec)
    return sec
