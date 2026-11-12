"""Project: build artifacts for one image, the target description, options, and evidence."""
from __future__ import annotations

import bisect
from dataclasses import dataclass
from pathlib import Path

from ..architecture.tricore.spec import TriCoreSpec
from ..formats.elf import ElfFile, load_elf
from ..formats.hexrec import load_ihex, load_srec, sniff
from ..formats.image import MemoryImage
from ..formats.map.model import LinkMap
from ..silicon.infineon.aurix.profile import DeviceProfile
from .evidence import Artifact, EvidenceStore, Source


@dataclass
class Options:
    bmhd_crc_mode: str | None = None  # discover | profile | strict ; None -> profile's setting
    experimental: bool = False  # L2 semantics (A2L, AUTOSAR attribution)
    toolchain: str | None = None

    def to_dict(self) -> dict:
        return dict(self.__dict__)


@dataclass
class ResolvedSymbol:
    name: str
    addr: int
    size: int | None
    origin: str  # elf | map
    source: Source
    section: str | None = None
    obj: str | None = None
    size_kind: str = "exact"  # exact | upper-bound | unknown


class Project:
    def __init__(self, device: str = "tc38x", options: Options | None = None):
        self.options = options or Options()
        self.store = EvidenceStore()
        self.profile = DeviceProfile.load(device)
        self.arch = TriCoreSpec()
        self.store.register(self.profile.artifact)
        self.store.register(self.arch.artifact)
        d = self.profile.describe()
        self.store.add("input", "observed", "info",
                       f"MCU profile {d['id']} v{d['version']}: {d['unknown_facts']} facts unknown (null), "
                       f"{d['synthetic_facts']} synthetic", [Source(self.profile.artifact.short, "whole file")],
                       {"profile": d, "unknown": self.profile.facts_unknown()})
        if d["synthetic_facts"]:
            self.store.add("input", "observed", "warning",
                           f"Profile {d['id']} contains synthetic facts: results are for testing only",
                           [Source(self.profile.artifact.short, "whole file")])
        self.image = MemoryImage(alias=self.profile.alternate)
        self.image_from_elf = False
        self.image_artifacts: list[Artifact] = []
        self.elf: ElfFile | None = None
        self.elf_art: Artifact | None = None
        self.map: LinkMap | None = None
        self.map_art: Artifact | None = None
        self.lsl: dict | None = None
        self.a2l = None
        self.a2l_art: Artifact | None = None
        self.layout_rows: list = []
        self._symbols: dict[str, ResolvedSymbol] | None = None

    # ---- loading ------------------------------------------------------------
    def add_image(self, path: str) -> Artifact:
        kind = sniff(path)
        if kind == "elf":
            return self.add_elf(path)
        if kind not in ("hex", "srec"):
            raise ValueError(f"{path}: not Intel HEX, S-record or ELF")
        art = self.store.register(Artifact.from_path(path, kind, f"formats.hexrec.{kind}"))
        if self.image_from_elf:
            self.image = MemoryImage(alias=self.profile.alternate)
            self.image_from_elf = False
        problems: list = []
        (load_ihex if kind == "hex" else load_srec)(path, art.short, self.image, problems)
        self.image_artifacts.append(art)
        from ..formats.events import health_from
        text = Path(path).read_text(errors="replace")
        self._record_parse(art, problems, health_from(text, problems, self.image.stats.get("accepted_records", 0),
                                                      {"records": 1},
                                                      {"records": self.image.stats.get("accepted_records", 0)}))
        self.store.add("input", "observed", "info",
                       f"{art.type} image: {len(self.image.segments)} contiguous segment(s), {self.image.size} bytes",
                       [Source(art.short, "whole file")],
                       {"segments": [(hex(a), n) for a, n, *_ in self.image.regions()]})
        return art

    def add_elf(self, path: str) -> Artifact:
        art = self.store.register(Artifact.from_path(path, "elf", "formats.elf"))
        self.elf, self.elf_art = load_elf(path), art
        self.store.add("input", "observed", "info" if self.elf.machine == 44 else "warning",
                       f"ELF32 {self.elf.machine_name} ({'LE' if self.elf.little else 'BE'}), "
                       f"{len(self.elf.sections)} sections, {len(self.elf.symbols)} symbols, "
                       f"entry {self.elf.entry:#010x}", [Source(art.short, "ELF header")])
        if not self.image_artifacts:
            self.elf.load_image(art.short, self.image)
            self.image_from_elf = True
            self.store.add("input", "derived", "note",
                           "No HEX/S19 given; image reconstructed from ELF PT_LOAD segments. A post-build "
                           "image may differ (boot headers, CRCs, signatures).", [Source(art.short, "program headers")])
        self._symbols = None
        return art

    def add_map(self, path: str, toolchain: str | None = None) -> Artifact:
        from ..toolchains import detect_map_toolchain, parse_map
        tc = toolchain or self.options.toolchain or detect_map_toolchain(path)
        art = self.store.register(Artifact.from_path(path, f"{tc}-map", f"toolchains.{tc}.map"))
        self.map, self.map_art = parse_map(tc, path, art.short), art
        self._record_parse(art, self.map.events, self.map.health)
        self.store.add("input", "observed", "info",
                       f"{tc} map: {len(self.map.regions)} regions, {len(self.map.sections)} output sections, "
                       f"{sum(len(s.inputs) for s in self.map.sections)} input sections, "
                       f"{len(self.map.symbols)} symbols", [Source(art.short, "whole file")])
        self._symbols = None
        return art

    def add_lsl(self, path: str) -> Artifact:
        from ..toolchains.tasking.map import apply_lsl, parse_lsl
        art = self.store.register(Artifact.from_path(path, "lsl", "toolchains.tasking.lsl"))
        self.lsl = parse_lsl(path)
        notes = apply_lsl(self.map, self.lsl) if self.map else []
        self._record_parse(art, self.lsl["events"], self.lsl["health"])
        self.store.add("input", "observed", "info",
                       f"LSL: {len(self.lsl['memories'])} memory declarations, {len(self.lsl['groups'])} groups",
                       [Source(art.short, "whole file")], {"notes": notes})
        return art

    def add_a2l(self, path: str) -> Artifact:
        from ..formats.a2l.parser import parse_a2l
        art = self.store.register(Artifact.from_path(path, "a2l", "formats.a2l"))
        self.a2l, self.a2l_art = parse_a2l(path), art
        self._record_parse(art, self.a2l.problems, self.a2l.health)
        self.store.add("input", "observed", "info",
                       f"A2L: {len(self.a2l.characteristics)} characteristics, {len(self.a2l.measurements)} "
                       f"measurements, {len(self.a2l.axis_pts)} axis_pts, {len(self.a2l.segments)} memory segments",
                       [Source(art.short, "whole file")], level="L0")
        return art

    def _record_parse(self, art: Artifact, events: list, health) -> None:
        """Keep every parse event (telemetry); derive findings from parse health, never from
        the parser's local state. At most one finding per consequence per artifact."""
        from dataclasses import asdict
        for ev in events:
            self.store.parse_events.append({"artifact": art.short, "sha256": art.sha256, **asdict(ev)})
        h = asdict(health) if health is not None else {}
        self.store.parse_health[art.short] = h
        src = [Source(art.short, "whole file")]
        lines = lambda kind: [e.line for e in events if e.kind == kind]
        for struct in (health.missing() if health is not None else []):
            self.store.add("input", "unknown", "error",
                           f"{art.type}_STRUCTURE_NOT_RECOVERED: {art.short} announces {struct.replace('_', ' ')} "
                           f"(line {health.announced[struct]}) but the parser recovered none; "
                           f"{health.unrecognized_lines} of {health.nonblank_lines} lines remain unclassified",
                           [Source(art.short, f"line {health.announced[struct]}")],
                           {"code": f"{art.type}_STRUCTURE_NOT_RECOVERED", "structure": struct, "health": h}, level="L0")
        for kind, code, sev, what in (
                ("REJECTED_RECORD", "PARSE_RECORDS_REJECTED", "error", "records rejected; their bytes are UNKNOWN"),
                ("INCOMPLETE_ENTRY", "PARSE_INCOMPLETE_RECORDS", "warning", "structural records incomplete"),
                ("UNPARSED_BLOCK", "PARSE_BLOCKS_NOT_PARSED", "warning", "blocks could not be parsed")):
            ls = lines(kind)
            if ls:
                self.store.add("input", "unknown", sev, f"{code}: {len(ls)} {what} in {art.short} "
                               f"(lines {', '.join(map(str, ls[:10]))}{', ...' if len(ls) > 10 else ''})",
                               [Source(art.short, f"line {ln}") for ln in ls[:10]],
                               {"code": code, "lines": ls, "health": h}, level="L0")
        other = len(lines("UNRECOGNIZED_CONSTRUCT")) + len(lines("UNSUPPORTED_TABLE"))
        if other:
            self.store.add("input", "observed", "note",
                           f"PARSE_LINES_UNCLASSIFIED: {other} lines or tables in {art.short} not modelled; "
                           "preserved in evidence.json parse_events", src,
                           {"code": "PARSE_LINES_UNCLASSIFIED", "count": other, "health": h}, level="L0")

    # ---- unified symbol view --------------------------------------------------
    def symbols(self) -> dict[str, ResolvedSymbol]:
        if self._symbols is not None:
            return self._symbols
        out: dict[str, ResolvedSymbol] = {}
        if self.map:
            for s in self.map.symbols:
                out.setdefault(s.name, ResolvedSymbol(s.name, s.addr, s.size, "map",
                                                      Source(self.map.artifact, f"line {s.line}"), s.section, s.obj,
                                                      "exact" if s.size else "unknown"))
            self._bound_map_sizes(out)
        if self.elf:
            for s in self.elf.symbols:
                if s.type in ("file", "section"):
                    continue
                prev = out.get(s.name)
                if prev and prev.origin == "elf" and s.bind == "local":
                    continue
                out[s.name] = ResolvedSymbol(s.name, s.value, s.size or None, "elf",
                                             Source(self.elf_art.short, f"symtab {s.name}"), s.section,
                                             prev.obj if prev else None, "exact" if s.size else "unknown")
        self._symbols = out
        return out

    def _bound_map_sizes(self, out: dict[str, ResolvedSymbol]) -> None:
        ordered = sorted((s for s in out.values() if not s.name.startswith("_lc_")), key=lambda s: (s.addr, s.name))
        addrs = [s.addr for s in ordered]
        secs = sorted((x for x in self.map.sections if x.size), key=lambda x: x.addr)
        starts = [x.addr for x in secs]
        for s in ordered:
            if s.size:
                continue
            j = bisect.bisect_right(addrs, s.addr)
            nxt = addrs[j] if j < len(addrs) else None
            k = bisect.bisect_right(starts, s.addr) - 1
            limit = secs[k].addr + secs[k].size if k >= 0 and s.addr < secs[k].addr + secs[k].size else None
            ends = [x for x in (limit, nxt) if x is not None]
            if ends:
                s.size, s.size_kind = min(ends) - s.addr, "upper-bound"

    def symbol_at(self, addr: int) -> ResolvedSymbol | None:
        best = None
        for s in self.symbols().values():
            if self.profile.same_location(s.addr, addr) and (best is None or (s.size or 0) > (best.size or 0)):
                best = s
            elif s.size and s.addr <= addr < s.addr + s.size:
                best = best or s
        return best

    # ---- reproducibility ---------------------------------------------------------
    def run_record(self) -> dict:
        from .. import __version__
        return {
            "tool": {"name": "ecuforge", "version": __version__},
            "target": {"architecture": self.profile.data.get("architecture", "tricore"), "silicon": self.profile.id},
            "profile": self.profile.describe(),
            "architecture_spec": {"id": self.arch.data["id"], "sha256": self.arch.artifact.sha256},
            "artifacts": [{"type": a.type, "path": Path(a.path).name, "sha256": a.sha256, "parser": a.parser}
                          for a in self.store.artifacts.values() if a.type not in ("MCU_PROFILE", "ARCH_SPEC")],
            "analysis": {"options": self.options.to_dict()},
        }
