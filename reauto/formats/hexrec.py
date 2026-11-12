"""Intel HEX and Motorola S-record decoders.

Fail-safe rule: a record that fails its length or checksum check is not decoded
and not guessed at; it is recorded in `problems` with its line number and the
rest of the file continues. Its bytes stay absent (UNKNOWN) in the image. A file
whose first record is not of the expected format raises RecordError.
"""
from __future__ import annotations

from pathlib import Path

from .events import ParseEvent
from .image import MemoryImage


class RecordError(ValueError):
    pass


def load_ihex(path: str | Path, origin: str, image: MemoryImage | None = None,
              problems: list | None = None) -> MemoryImage:
    img = image or MemoryImage()
    probs = problems if problems is not None else []
    base = 0
    first = True
    accepted = 0
    eof = False
    for ln, raw in enumerate(Path(path).read_text(errors="replace").splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        if eof:
            probs.append(ParseEvent("UNRECOGNIZED_CONSTRUCT", ln, line[:80], False, "after end-of-file record"))
            continue
        bad = None
        rec = b""
        if not line.startswith(":"):
            bad = "not an Intel HEX record"
        else:
            try:
                rec = bytes.fromhex(line[1:])
            except ValueError:
                bad = "bad hex digits"
        if bad is None and (len(rec) < 5 or len(rec) != rec[0] + 5):
            bad = "length mismatch"
        if bad is None and sum(rec) & 0xFF:
            bad = "checksum error"
        if bad:
            if first:
                raise RecordError(f"{path}:{ln}: {bad}")
            probs.append(ParseEvent("REJECTED_RECORD", ln, f"{bad}: {line[:80]}", True, "record"))
            continue
        first = False
        addr, rtype, data = (rec[1] << 8) | rec[2], rec[3], rec[4:-1]
        accepted += rtype in (0x00, 0x01, 0x02, 0x03, 0x04, 0x05)
        if rtype == 0x00:
            img.add(base + addr, data, origin, f"lines {ln}-{ln}")
        elif rtype == 0x01:
            eof = True
        elif rtype == 0x02:
            base = int.from_bytes(data, "big") << 4
        elif rtype == 0x04:
            base = int.from_bytes(data, "big") << 16
        elif rtype in (0x03, 0x05):
            img.entry = int.from_bytes(data, "big")
        else:
            probs.append(ParseEvent("REJECTED_RECORD", ln, f"unknown record type {rtype:#x}: {line[:80]}", True,
                                    "record"))
    img.stats = {"accepted_records": accepted, "events": len(probs)}
    return img


_SREC_ADDR = {"0": 2, "1": 2, "2": 3, "3": 4, "5": 2, "6": 3, "7": 4, "8": 3, "9": 2}


def load_srec(path: str | Path, origin: str, image: MemoryImage | None = None,
              problems: list | None = None) -> MemoryImage:
    img = image or MemoryImage()
    probs = problems if problems is not None else []
    first = True
    accepted = 0
    for ln, raw in enumerate(Path(path).read_text(errors="replace").splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        bad, rec = None, b""
        if len(line) < 4 or line[0] != "S" or line[1] not in _SREC_ADDR:
            bad = "not an S-record"
        else:
            try:
                rec = bytes.fromhex(line[2:])
            except ValueError:
                bad = "bad hex digits"
        if bad is None and len(rec) != rec[0] + 1:
            bad = "length mismatch"
        if bad is None and (sum(rec) & 0xFF) != 0xFF:
            bad = "checksum error"
        if bad:
            if first:
                raise RecordError(f"{path}:{ln}: {bad}")
            probs.append(ParseEvent("REJECTED_RECORD", ln, f"{bad}: {line[:80]}", True, "record"))
            continue
        first = False
        accepted += 1
        alen = _SREC_ADDR[line[1]]
        addr = int.from_bytes(rec[1 : 1 + alen], "big")
        data = rec[1 + alen : -1]
        if line[1] in "123":
            img.add(addr, data, origin, f"lines {ln}-{ln}")
        elif line[1] in "789":
            img.entry = addr
    img.stats = {"accepted_records": accepted, "events": len(probs)}
    return img


def sniff(path: str | Path) -> str | None:
    with open(path, "rb") as fh:
        head = fh.read(64)
    if head.startswith(b"\x7fELF"):
        return "elf"
    if head.startswith(b":"):
        return "hex"
    if head[:1] == b"S" and head[1:2].isdigit():
        return "srec"
    return None
