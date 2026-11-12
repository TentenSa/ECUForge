"""Parse events: everything a parser could not turn into model data.

Rule: nothing is discarded silently. Every unrecognised construct, rejected record
or unparsed block becomes a ParseEvent with file line and raw text. Events are all
kept in the evidence output; only events that can change an analysis result
(`affects=True`) are promoted to user-facing UNKNOWN findings, so decorative map
noise does not flood the report.
"""
from __future__ import annotations

from dataclasses import dataclass

KINDS = ("UNRECOGNIZED_CONSTRUCT", "REJECTED_RECORD", "UNSUPPORTED_TABLE", "UNPARSED_BLOCK", "INCOMPLETE_ENTRY")


@dataclass(frozen=True)
class ParseEvent:
    kind: str
    line: int
    raw: str
    affects: bool  # True when the lost content can change an analysis result
    context: str = ""  # where it occurred, e.g. "memory table", "output section .text"

    def __post_init__(self) -> None:
        if self.kind not in KINDS:
            raise ValueError(f"bad parse event kind {self.kind}")
