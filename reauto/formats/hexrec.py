"""Intel HEX and Motorola S-record decoders (strict, checksum-verified)."""
from __future__ import annotations

from pathlib import Path

from .image import MemoryImage


class RecordError(ValueError):
    pass


def load_ihex(path: str | Path, origin: str, image: MemoryImage | None = None) -> MemoryImage:
    img = image or MemoryImage()
    base = 0
    for ln, raw in enumerate(Path(path).read_text(errors="replace").splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        if not line.startswith(":"):
            raise RecordError(f"{path}:{ln}: not an Intel HEX record")
        try:
            rec = bytes.fromhex(line[1:])
        except ValueError as e:
            raise RecordError(f"{path}:{ln}: bad hex digits") from e
        if len(rec) < 5 or len(rec) != rec[0] + 5:
            raise RecordError(f"{path}:{ln}: length mismatch")
        if sum(rec) & 0xFF:
            raise RecordError(f"{path}:{ln}: checksum error")
        n, addr, rtype, data = rec[0], (rec[1] << 8) | rec[2], rec[3], rec[4:-1]
        if rtype == 0x00:
            img.add(base + addr, data, origin, f"lines {ln}-{ln}")
        elif rtype == 0x01:
            break
        elif rtype == 0x02:
            base = int.from_bytes(data, "big") << 4
        elif rtype == 0x04:
            base = int.from_bytes(data, "big") << 16
        elif rtype in (0x03, 0x05):
            img.entry = int.from_bytes(data, "big")
        else:
            raise RecordError(f"{path}:{ln}: unknown record type {rtype:#x}")
    return img


_SREC_ADDR = {"0": 2, "1": 2, "2": 3, "3": 4, "5": 2, "6": 3, "7": 4, "8": 3, "9": 2}


def load_srec(path: str | Path, origin: str, image: MemoryImage | None = None) -> MemoryImage:
    img = image or MemoryImage()
    for ln, raw in enumerate(Path(path).read_text(errors="replace").splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        if len(line) < 4 or line[0] != "S" or line[1] not in _SREC_ADDR:
            raise RecordError(f"{path}:{ln}: not an S-record")
        rec = bytes.fromhex(line[2:])
        if len(rec) != rec[0] + 1:
            raise RecordError(f"{path}:{ln}: length mismatch")
        if (sum(rec) & 0xFF) != 0xFF:
            raise RecordError(f"{path}:{ln}: checksum error")
        alen = _SREC_ADDR[line[1]]
        addr = int.from_bytes(rec[1 : 1 + alen], "big")
        data = rec[1 + alen : -1]
        if line[1] in "123":
            img.add(addr, data, origin, f"lines {ln}-{ln}")
        elif line[1] in "789":
            img.entry = addr
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
