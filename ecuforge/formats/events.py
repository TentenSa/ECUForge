"""Parse telemetry: events and health.

ParseEvent = lossless telemetry. Everything a parser could not turn into model
data is kept with its line and raw text; nothing is discarded silently. Events
never decide severity on their own.

ParseHealth = what the parser recovered against what the input announced. A
consequence for analysis (a Finding) is derived from health, not from the
parser's local state: e.g. a map that announces output sections but yields none
is a structural failure, however its unrecognised lines were classified.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .text import split_lines

KINDS = ("UNRECOGNIZED_CONSTRUCT", "REJECTED_RECORD", "UNSUPPORTED_TABLE", "UNPARSED_BLOCK", "INCOMPLETE_ENTRY")


@dataclass(frozen=True)
class ParseEvent:
    kind: str
    line: int
    raw: str
    context: str = ""  # where it occurred; descriptive only

    def __post_init__(self) -> None:
        if self.kind not in KINDS:
            raise ValueError(f"bad parse event kind {self.kind}")


@dataclass
class ParseHealth:
    nonblank_lines: int = 0
    recognized_lines: int = 0
    structural_records: int = 0
    unrecognized_lines: int = 0
    fatal_errors: int = 0
    # structures the input itself announces (e.g. a "Memory Configuration" heading) -> evidence line
    announced: dict = field(default_factory=dict)
    # how many records of each announced structure were recovered
    recovered: dict = field(default_factory=dict)

    def missing(self) -> list[str]:
        return [k for k in self.announced if not self.recovered.get(k)]


def health_from(text: str, events: list, structural_records: int, announced: dict, recovered: dict,
                fatal_kinds: tuple = ("REJECTED_RECORD",)) -> ParseHealth:
    nonblank = sum(1 for line in split_lines(text) if line.strip())
    unrec = sum(1 for e in events if e.kind != "UNSUPPORTED_TABLE")
    return ParseHealth(nonblank, max(nonblank - unrec, 0), structural_records, unrec,
                       sum(1 for e in events if e.kind in fatal_kinds), announced, recovered)
