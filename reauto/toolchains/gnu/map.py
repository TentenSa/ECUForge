"""GNU LD / HighTec TriCore GCC map file parser.

Handles: Memory Configuration table; output-section headers in every syntax
variant seen in GNU ld maps, detected by syntax, never by tool version:

    .text           0x80000200      0x400                       one line
    .text           0x80000200      0x400 load address 0x...    one line with LMA
    .some_long_section_name                                     name, then
                    0x80000200      0x400                       address/size line
    .startup        memory region -> pfls0                      region clause, then
                    0x80000020        0xc                       address/size line
    .rodata                                                     empty output section
     *(.rodata .rodata.*)                                       (no address printed)

Input sections with object attribution (incl. wrapped long names), symbols and
linker-script assignments (incl. PROVIDE). Discarded / common-symbol blocks are skipped.
"""
from __future__ import annotations

import re
from pathlib import Path

from ...formats.events import ParseEvent
from ...formats.map.model import InputSection, LinkMap, MapSymbol, MemoryRegion, OutputSection

H = r"0x[0-9a-fA-F]+"
RE_MEM_ROW = re.compile(rf"^(\S+)\s+({H})\s+({H})(?:\s+(\S+))?\s*$")
RE_OUT_HEAD = re.compile(rf"^(?P<name>[.\w$][^\s]*)"
                         rf"(?:\s+(?P<addr>{H})\s+(?P<size>{H}))?"
                         rf"(?:\s+load address\s+(?P<lma>{H}))?"
                         rf"(?:\s+memory region\s*->\s*(?P<region>\S+))?\s*$")
RE_ADDR_SIZE = re.compile(rf"^\s+(?P<addr>{H})\s+(?P<size>{H})(?:\s+load address\s+(?P<lma>{H}))?\s*$")
RE_IN_FULL = re.compile(rf"^ ([^\s*][^\s]*)\s+({H})\s+({H})\s+(\S.*)$")
RE_IN_NAME = re.compile(r"^ ([^\s*][^\s]*)\s*$")
RE_IN_CONT = re.compile(rf"^\s+({H})\s+({H})\s+(\S.*)$")
RE_DATA_STMT = re.compile(rf"^\s+{H}\s+{H}\s+(BYTE|SHORT|LONG|QUAD|SQUAD)\s+{H}\b")  # linker-script data statements
RE_RELAX = re.compile(rf"^\s+{H}\s+\(size before relaxing\)\s*$")
RE_SYM = re.compile(rf"^\s{{8,}}({H})\s+(\S.*)$")
RE_ASSIGN_NAME = re.compile(r"(?:PROVIDE(?:_HIDDEN)?\s*\(\s*)?([A-Za-z_.$][\w.$]*)\s*=")

SKIP_HEADS = ("LOAD ", "OUTPUT(", "START GROUP", "END GROUP", "OUTPUT_FORMAT", "TARGET(")


def parse_gnu_map(path: str | Path, artifact: str) -> LinkMap:
    lm = LinkMap("gnu", artifact)
    lines = Path(path).read_text(errors="replace").splitlines()
    mode = "pre"
    cur_out: OutputSection | None = None
    cur_in: InputSection | None = None
    pending_out: dict | None = None
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

        # ---- continuation of an output-section header ------------------
        if pending_out:
            m = RE_ADDR_SIZE.match(line)
            if m:
                cur_out = _new_out(lm, pending_out, m, ln)
                cur_in = None
                pending_out = None
                continue
            if not s or s.startswith("*(") or s.startswith("KEEP") or not line[0].isspace():
                # valid GNU syntax: an output section with no contents prints no address
                lm.empty_sections.append((pending_out["name"], pending_out["line"]))
            else:
                lm.events.append(ParseEvent("INCOMPLETE_ENTRY", pending_out["line"],
                                            f"output section header not followed by address/size: "
                                            f"{pending_out['name']} (next line {ln}: {s[:60]})", True, "memory map"))
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

        # ---- output section header (column 0) ---------------------------
        if not line[0].isspace():
            m = RE_OUT_HEAD.match(line)
            if m and m.group("addr"):
                cur_out = _new_out(lm, {"name": m.group("name"), "line": ln, "region": m.group("region")}, m, ln)
                cur_in = None
            elif m:
                pending_out = {"name": m.group("name"), "line": ln, "region": m.group("region"),
                               "lma": m.group("lma")}
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

        # ---- symbol / assignment / data statement ---------------------
        if RE_DATA_STMT.match(line) or RE_RELAX.match(line):
            continue  # recognised; the bytes themselves are read from the image
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
    if pending_out:  # header at end of file without address: empty output section
        lm.empty_sections.append((pending_out["name"], pending_out["line"]))
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


def _new_out(lm: LinkMap, head: dict, m: re.Match, ln: int) -> OutputSection:
    """One normalised output-section record from a one- or multi-line header."""
    lma = m.group("lma") or head.get("lma")
    addr, size = int(m.group("addr"), 16), int(m.group("size"), 16)
    sec = OutputSection(head["name"], addr, size, int(lma, 16) if lma else None, None, head["line"])
    sec.line_end = ln
    if head.get("region"):
        sec.region, sec.region_declared = head["region"], True
    else:
        r = lm.region_of(addr)
        sec.region = r.name if r else None
    lm.sections.append(sec)
    return sec
