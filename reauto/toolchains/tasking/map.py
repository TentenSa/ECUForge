"""TASKING VX-toolset for TriCore (ltc) map file and LSL parser.

The map file is a set of pipe tables. Rather than relying on exact layout,
tables are recognised by their header columns:

  Link Result     [in] File | [in] Section | [in] Size | [out] Offset | [out] Section | [out] Size
  Locate Result   Chip | Group | Section | Size (MAU) | Space addr | Chip addr | Alignment
  Symbols         Name | Space addr | Chip addr | Chip
  Memory usage    Memory | Code | Data | Reserved | Free | Total

Region origins are derived from (Space addr - Chip addr) per chip; lengths come
from the memory-usage table when present, otherwise from the LSL, otherwise the
observed extent (flagged as such by the layout stage).
"""
from __future__ import annotations

import re
from pathlib import Path

from ...formats.events import ParseEvent
from ...formats.map.model import InputSection, LinkMap, MapSymbol, MemoryRegion, OutputSection

RE_IDX = re.compile(r"\s*\(\d+\)\s*$")


def _num(s: str) -> int | None:
    s = s.strip()
    if not s:
        return None
    try:
        return int(s, 0)
    except ValueError:
        return None


def _tables(lines: list[str]):
    """Yield (header_cells, rows[(line_no, cells)]) for every pipe table."""
    i = 0
    while i < len(lines):
        ln = lines[i].strip()
        if ln.startswith("|") and i + 1 < len(lines) and lines[i + 1].strip().startswith("|="):
            header = [c.strip() for c in ln.strip("|").split("|")]
            rows = []
            j = i + 2
            while j < len(lines):
                r = lines[j].strip()
                if r.startswith("|") and not r.startswith("|=") and not re.fullmatch(r"\|[-+|]*\|?", r):
                    cells = [c.strip() for c in r.strip("|").split("|")]
                    cells += [""] * (len(header) - len(cells))
                    rows.append((j + 1, cells))
                elif re.fullmatch(r"\|[-+|]*\|?", r):
                    pass
                elif r.startswith("+") or r.startswith("|=") or not r:
                    if not r or r.startswith("+"):
                        break
                else:
                    break
                j += 1
            yield header, rows
            i = j
        else:
            i += 1


def _col(header: list[str], *names: str) -> int | None:
    for n in names:
        for k, h in enumerate(header):
            if h.lower().startswith(n.lower()):
                return k
    return None


def parse_tasking_map(path: str | Path, artifact: str) -> LinkMap:
    lm = LinkMap("tasking", artifact)
    lines = Path(path).read_text(errors="replace").splitlines()
    out_to_obj: dict[str, tuple[str, str, int, int]] = {}
    chip_base: dict[str, int] = {}
    chip_extent: dict[str, int] = {}
    mem_usage: dict[str, tuple[int | None, int | None]] = {}
    seen_syms: set[tuple[str, int]] = set()
    load_copies: dict[str, tuple[int, int]] = {}

    for header, rows in _tables(lines):
        h = [x.lower() for x in header]
        if any(x.startswith("[in] file") for x in h):
            cf, cis, cisz, cos = (_col(header, "[in] File"), _col(header, "[in] Section"),
                                  _col(header, "[in] Size"), _col(header, "[out] Section"))
            last_file = ""
            for ln, c in rows:
                f = c[cf] or last_file
                last_file = f
                if cos is not None and c[cos]:
                    out_to_obj[RE_IDX.sub("", c[cos])] = (f, RE_IDX.sub("", c[cis]), _num(c[cisz]) or 0, ln)
        elif "chip" in h and "section" in h and any(x.startswith("space addr") for x in h):
            cc, cs, csz, csa, cca = (_col(header, "Chip"), _col(header, "Section"), _col(header, "Size"),
                                     _col(header, "Space addr"), _col(header, "Chip addr"))
            pending = ""
            for ln, c in rows:
                name = pending + c[cs]
                sa = _num(c[csa])
                if sa is None:  # wrapped long section name
                    pending = name
                    continue
                pending = ""
                name = RE_IDX.sub("", name)
                size = _num(c[csz]) or 0
                if name.startswith("[") and name.endswith("]"):  # ROM copy of an initialised RAM section
                    load_copies[name[1:-1]] = (sa, ln)
                    continue
                chip = c[cc] or None
                ca = _num(c[cca]) if cca is not None else None
                if chip and ca is not None:
                    chip_base.setdefault(chip, sa - ca)
                    chip_extent[chip] = max(chip_extent.get(chip, 0), ca + size)
                sec = OutputSection(name, sa, size, None, chip, ln)
                if name in out_to_obj:
                    f, isec, isz, iln = out_to_obj[name]
                    sec.inputs.append(InputSection(isec, sa, isz or size, f, iln))
                lm.sections.append(sec)
        elif h and h[0] == "name" and any(x.startswith("space addr") for x in h):
            cn, csa, cc = _col(header, "Name"), _col(header, "Space addr"), _col(header, "Chip")
            for ln, c in rows:
                a = _num(c[csa])
                if a is None or not c[cn]:
                    continue
                key = (c[cn], a)
                if key in seen_syms:
                    continue
                seen_syms.add(key)
                lm.symbols.append(MapSymbol(c[cn], a, None, None, None, ln,
                                            assignment=c[cn].startswith("_lc_")))
        elif h and h[0] == "memory" and "total" in h:
            pass
        else:
            lm.events.append(ParseEvent("UNSUPPORTED_TABLE", rows[0][0] - 2 if rows else 0,
                                        "unsupported table: " + " | ".join(header), False,
                                        "table not used by any analysis"))
            continue
        if h and h[0] == "memory" and "total" in h:
            cm, ct = _col(header, "Memory"), _col(header, "Total")
            cfree = _col(header, "Free")
            for ln, c in rows:
                if c[cm].lower() == "total":
                    continue
                mem_usage[c[cm]] = (_num(c[ct]), _num(c[cfree]) if cfree is not None else None)

    for chip, base in chip_base.items():
        total, free = mem_usage.get(chip, mem_usage.get(chip.split(":")[-1], (None, None)))
        length = total if total is not None else chip_extent[chip]
        used = total - free if total is not None and free is not None else None
        lm.regions.append(MemoryRegion(chip, base, length, "tasking-chip" + ("" if total else "(extent)"),
                                       0, [], used))
    for sec in lm.sections:
        if sec.name in load_copies:
            sec.lma = load_copies[sec.name][0]
    # attach section symbols
    for s in lm.symbols:
        sec = lm.section_of(s.addr)
        if sec:
            s.section = sec.name
            if sec.inputs:
                s.obj = sec.inputs[0].obj
    return lm


# ---------------------------------------------------------------------------
# LSL (linker script language) - v1 extracts memory declarations and groups.
# ---------------------------------------------------------------------------
RE_DEFINE = re.compile(r"^\s*#\s*define\s+(\w+)\s+(.+?)\s*$", re.M)
RE_MEMORY = re.compile(r"\bmemory\s+(\w+)\s*\{(.*?)\n\s*\}", re.S)
RE_GROUP = re.compile(r"\bgroup\s+(\w+)?\s*\(([^)]*)\)\s*\{(.*?)\}", re.S)


def _size(tok: str, defs: dict[str, str]) -> int | None:
    tok = defs.get(tok.strip(), tok.strip())
    m = re.fullmatch(r"(0x[0-9a-fA-F]+|\d+)\s*([kKmM]?)", tok)
    if not m:
        return None
    v = int(m.group(1), 0)
    return v * {"": 1, "k": 1024, "K": 1024, "m": 1 << 20, "M": 1 << 20}[m.group(2)]


def parse_lsl(path: str | Path) -> dict:
    text = Path(path).read_text(errors="replace")
    clean = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    clean = re.sub(r"//[^\n]*", "", clean)
    defs = {m.group(1): m.group(2) for m in RE_DEFINE.finditer(clean)}
    memories = []
    for m in RE_MEMORY.finditer(clean):
        body = m.group(2)
        line = clean[: m.start()].count("\n") + 1
        size = re.search(r"\bsize\s*=\s*([^;]+);", body)
        mtype = re.search(r"\btype\s*=\s*(\w+)", body)
        maps = []
        for mp in re.finditer(r"\bmap\s*(\w+)?\s*\(([^)]*)\)", body):
            args = dict(re.findall(r"(\w+)\s*=\s*([^,]+)", mp.group(2)))
            off = args.get("dest_offset")
            maps.append({"name": mp.group(1) or "", "dest_offset": _size(off, defs) if off else None,
                         "size": _size(args["size"], defs) if "size" in args else None,
                         "dest": args.get("dest", "").strip()})
        memories.append({"name": m.group(1), "line": line,
                         "size": _size(size.group(1), defs) if size else None,
                         "type": mtype.group(1) if mtype else None, "maps": maps})
    groups = []
    for g in RE_GROUP.finditer(clean):
        attrs = g.group(2)
        groups.append({
            "name": g.group(1) or "",
            "line": clean[: g.start()].count("\n") + 1,
            "run_addr": (re.search(r"run_addr\s*=\s*([^,)]+)", attrs) or [None, None])[1],
            "load_addr": (re.search(r"load_addr\s*=\s*([^,)]+)", attrs) or [None, None])[1],
            "selects": re.findall(r'select\s+"([^"]+)"', g.group(3)),
        })
    return {"defines": defs, "memories": memories, "groups": groups,
            "events": [ParseEvent("UNRECOGNIZED_CONSTRUCT", ln, raw, True, "LSL top level")
                       for ln, raw in _lsl_unsupported(clean)]}


LSL_KNOWN = {"memory", "section_layout", "group", "select", "architecture", "derivative", "processor", "bus",
             "space", "map", "section_setup", "reserved", "stack", "heap", "copytable", "include"}


def _lsl_unsupported(text: str) -> list[tuple[int, str]]:
    """Top-level LSL statements this parser does not model, kept with their line numbers."""
    out, depth = [], 0
    for ln, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if depth == 0 and s and not s.startswith("#") and s not in ("{", "}"):
            kw = re.match(r"[A-Za-z_]\w*", s)
            if kw and kw.group(0) not in LSL_KNOWN:
                out.append((ln, s[:120]))
        depth += line.count("{") - line.count("}")
    return out


def apply_lsl(lm: LinkMap, lsl: dict) -> list[str]:
    """Fill region sizes / aliases from LSL memory declarations. Returns notes."""
    notes = []
    by_short = {r.name.split(":")[-1]: r for r in lm.regions}
    for mem in lsl["memories"]:
        r = by_short.get(mem["name"])
        offs = [m["dest_offset"] for m in mem["maps"] if m["dest_offset"] is not None]
        if r is None:
            if offs and mem["size"]:
                lm.regions.append(MemoryRegion(mem["name"], offs[0], mem["size"], f"lsl:{mem['type']}",
                                               mem["line"], offs[1:],
                                               mem_type={"ram": "ram", "rom": "rom"}.get(mem["type"])))
                notes.append(f"region {mem['name']} added from LSL (no sections located in it)")
            continue
        if mem["size"] and r.attrs.endswith("(extent)"):
            r.length = mem["size"]
            r.attrs = f"lsl:{mem['type']}"
        r.mem_type = {"ram": "ram", "rom": "rom"}.get(mem["type"])
        r.aliases = [o for o in offs if o != r.origin]
    return notes
