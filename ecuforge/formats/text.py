"""Platform-independent text input for artifact parsers.

Artifacts are read as UTF-8 (undecodable bytes replaced) whatever the host's locale, and split into records
only at line feeds, with a trailing carriage return dropped. str.splitlines() is not used: it also breaks at
characters such as U+0085, U+000C or U+2028, so the same file would yield different records, and different
line numbers, depending on the bytes inside a line.
"""
from __future__ import annotations

from pathlib import Path


def read_text(path) -> str:
    return Path(path).read_bytes().decode("utf-8", errors="replace")


def split_lines(text: str) -> list[str]:
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return [line[:-1] if line.endswith("\r") else line for line in lines]
