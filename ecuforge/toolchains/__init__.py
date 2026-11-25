"""Toolchain plug-ins. Each toolchain owns its map/LSL formats, linker-generated
structures and symbol naming conventions, and registers them here."""
from __future__ import annotations

from ..formats.text import read_text


def detect_map_toolchain(path: str) -> str:
    head = read_text(path)[:20000]
    return "tasking" if ("TASKING" in head or "|=====" in head) else "gnu"


def parse_map(toolchain: str, path: str, artifact: str):
    if toolchain == "tasking":
        from .tasking.map import parse_tasking_map
        return parse_tasking_map(path, artifact)
    from .gnu.map import parse_gnu_map
    return parse_gnu_map(path, artifact)


def conventions():
    """All registered startup-symbol conventions (a build may mix BSP and toolchain names)."""
    from .gnu.conventions import GNU_ILLD
    from .tasking.conventions import TASKING
    return [GNU_ILLD, TASKING]


def init_table_decoders():
    from .gnu.inittables import decode_gnu_tables
    from .tasking.copytable import decode_tasking_table
    return [decode_gnu_tables, decode_tasking_table]
