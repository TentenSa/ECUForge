"""Evidence and provenance model.

Kinds (what supports a claim):
  observed  read directly from an input artifact (map line, ELF symbol, image bytes)
  derived   computed deterministically from observed facts and documented rules
  inferred  heuristic, candidate search or pattern based; may be wrong
  unknown   the question was asked, the inputs cannot answer it
  conflict  two or more sources make contradictory claims; every claim is kept,
            none is preferred

Levels (how deep the recovery goes), independent of kind:
  L0  artifact facts       what a single file says (records, sections, symbols)
  L1  structural recovery  layout, address-space relations, startup structures
  L2  semantic recovery    calibration, AUTOSAR, diagnostics (experimental in 0.1.x)

Every Source names what established the claim: a source type (ELF, HEX, S19,
MAP, LSL, A2L, MCU_PROFILE, ARCH_SPEC, DISASSEMBLY, USER), the artifact's
SHA-256 and the parser that read it.
"""
from __future__ import annotations

import hashlib
import itertools
import json
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Any, Iterable

from .. import __version__

KINDS = ("observed", "derived", "inferred", "unknown", "conflict")
LEVELS = ("L0", "L1", "L2")
SEVERITIES = ("info", "note", "warning", "error")
TOPIC_LEVEL = {"input": "L0", "layout": "L1", "symbols": "L1", "startup": "L1",
               "a2l": "L2", "autosar": "L2"}
SOURCE_TYPES = ("ELF", "HEX", "S19", "MAP", "LSL", "A2L", "MCU_PROFILE", "ARCH_SPEC", "DISASSEMBLY", "USER")
ROLE_TYPE = {"hex": "HEX", "srec": "S19", "elf": "ELF", "gnu-map": "MAP", "tasking-map": "MAP", "lsl": "LSL",
             "a2l": "A2L", "mcu_profile": "MCU_PROFILE", "arch_spec": "ARCH_SPEC", "user": "USER"}


@dataclass(frozen=True)
class Artifact:
    """An input file, identified by content digest so evidence survives renames."""

    path: str
    sha256: str
    role: str
    parser: str = ""

    @staticmethod
    def from_path(path: str | Path, role: str, parser: str = "") -> "Artifact":
        p = Path(path)
        h = hashlib.sha256()
        with p.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return Artifact(str(p.resolve()), h.hexdigest(), role, f"{parser}@{__version__}" if parser else "")

    @property
    def short(self) -> str:
        return f"{Path(self.path).name}@{self.sha256[:12]}"

    @property
    def type(self) -> str:
        return ROLE_TYPE.get(self.role, "USER")


@dataclass(frozen=True)
class Source:
    """A pointer into an artifact: a line, a byte address, a symbol, a profile fact."""

    artifact: str  # Artifact.short
    locator: str
    excerpt: str | None = None
    type: str | None = None
    sha256: str | None = None
    parser: str | None = None

    def __str__(self) -> str:
        s = f"{self.artifact} {self.locator}"
        return f"{s}: {self.excerpt}" if self.excerpt else s


@dataclass
class Finding:
    id: str
    topic: str
    kind: str
    severity: str
    claim: str
    sources: list[Source] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)
    derived_from: list[str] = field(default_factory=list)
    level: str = "L0"

    def __post_init__(self) -> None:
        if self.kind not in KINDS:
            raise ValueError(f"bad kind {self.kind}")
        if self.severity not in SEVERITIES:
            raise ValueError(f"bad severity {self.severity}")
        if self.level not in LEVELS:
            raise ValueError(f"bad level {self.level}")
        if self.kind == "conflict" and len(self.data.get("claims", [])) < 2:
            raise ValueError("a conflict finding needs at least two competing claims")

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["sources"] = [asdict(s) for s in self.sources]
        return d


class EvidenceStore:
    def __init__(self) -> None:
        self.artifacts: dict[str, Artifact] = {}
        self.findings: list[Finding] = []
        self.parse_events: list[dict] = []  # every ParseEvent, with its artifact; all preserved
        self.parse_health: dict[str, dict] = {}  # per artifact
        self._counters: dict[str, itertools.count] = {}

    def register(self, art: Artifact) -> Artifact:
        self.artifacts[art.short] = art
        return art

    def _enrich(self, s: Source) -> Source:
        a = self.artifacts.get(s.artifact)
        if a is None:
            return s
        return replace(s, type=s.type or a.type, sha256=s.sha256 or a.sha256, parser=s.parser or a.parser)

    def add(self, topic: str, kind: str, severity: str, claim: str, sources: Iterable[Source] = (),
            data: dict[str, Any] | None = None, derived_from: Iterable[str] = (),
            level: str | None = None) -> Finding:
        c = self._counters.setdefault(topic, itertools.count(1))
        f = Finding(id=f"{topic.upper()}-{next(c):04d}", topic=topic, kind=kind, severity=severity, claim=claim,
                    sources=[self._enrich(s) for s in sources], data=data or {},
                    derived_from=list(derived_from), level=level or TOPIC_LEVEL.get(topic, "L1"))
        self.findings.append(f)
        return f

    def conflict(self, topic: str, severity: str, claim: str, claims: list[tuple[Source, Any]],
                 data: dict[str, Any] | None = None, derived_from: Iterable[str] = (),
                 level: str | None = None) -> Finding:
        """Record contradictory evidence; each (source, value) pair is kept, none is preferred."""
        d = dict(data or {})
        d["claims"] = [{"source": str(self._enrich(s)), "type": self._enrich(s).type, "value": v}
                       for s, v in claims]
        return self.add(topic, "conflict", severity, claim, [s for s, _ in claims], d, derived_from, level)

    def get(self, fid: str) -> Finding | None:
        return next((f for f in self.findings if f.id == fid), None)

    def query(self, topic: str | None = None, kind: str | None = None, min_severity: str | None = None,
              level: str | None = None) -> list[Finding]:
        floor = SEVERITIES.index(min_severity) if min_severity else 0
        return [f for f in self.findings
                if (topic is None or f.topic == topic) and (kind is None or f.kind == kind)
                and (level is None or f.level == level) and SEVERITIES.index(f.severity) >= floor]

    def summary(self) -> dict[str, Any]:
        out: dict[str, Any] = {"total": len(self.findings), "by_kind": {}, "by_severity": {}, "by_level": {}}
        for f in self.findings:
            for key, val in (("by_kind", f.kind), ("by_severity", f.severity), ("by_level", f.level)):
                out[key][val] = out[key].get(val, 0) + 1
        return out

    def to_json(self) -> str:
        return json.dumps({"artifacts": [asdict(a) | {"type": a.type} for a in self.artifacts.values()],
                           "summary": self.summary(), "findings": [f.to_dict() for f in self.findings],
                           "parse_events": self.parse_events, "parse_health": self.parse_health},
                          indent=2)
