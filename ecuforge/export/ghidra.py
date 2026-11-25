"""Ghidra export: the consumer-neutral model plus what a Ghidra apply step needs.

One-way (ECUForge -> Ghidra). The file is usable without Ghidra; applying it is a separate step.

Added on top of the model
- sections carry permissions taken from ELF section flags (observed); null where no ELF is loaded
- a BMHD structure type (field offsets from the MCU profile) and its instances at recovered headers
- one bookmark per finding that has an address, category by evidence kind
- findings without an address become program notes (one summary place, not scattered bookmarks)
"""
from __future__ import annotations

from .model import build_export

FORMAT = "ecuforge-ghidra"
SCHEMA_VERSION = 1
CATEGORY = {"observed": "ECUForge.Observed", "derived": "ECUForge.Derived", "inferred": "ECUForge.Inferred",
            "unknown": "ECUForge.Unknown", "conflict": "ECUForge.Conflict"}
_BMHD_SIZES = {"BMI": 2, "BMHDID": 2, "STAD": 4, "CRCBMHD": 4, "CRCBMHD_N": 4}  # as read by silicon/.../bmhd.py


def _comment(f: dict) -> str:
    src = "; ".join(f"{s['type']}@{(s['artifact_sha256'] or '')[:12]} {s['locator']}" for s in f["sources"])
    return f"{f['key']} | {f['kind']} {f['level']} | {f['claim']}" + (f" | sources: {src}" if src else "")


def _bmhd(p, res: dict) -> tuple[list[dict], list[dict]]:
    fields, _ = p.profile.fact("bmhd.fields")
    if not fields:
        return [], []
    comps = sorted(({"name": n, "offset": off, "size": _BMHD_SIZES[n]} for n, off in fields.items()
                    if n in _BMHD_SIZES), key=lambda c: c["offset"])
    size = max(c["offset"] + c["size"] for c in comps)
    types = [{"name": "ECUForge_BMHD", "size": size, "fields": comps, "source": "MCU profile bmhd.fields"}]
    inst = [{"type": "ECUForge_BMHD", "address": b["addr"], "label": b["slot"]} for b in res["startup"]["bmhd"]]
    return types, inst


def build_ghidra_export(p, res: dict) -> dict:
    model = build_export(p, res)
    elf_perm = {s.name: s.perms for s in p.elf.sections if s.alloc} if p.elf else {}
    for s in model["sections"]:
        s["permissions"] = elf_perm.get(s["name"])
        s["permissions_source"] = "elf" if s["permissions"] else None
    types, instances = _bmhd(p, res)
    bookmarks, notes = [], []
    for f in model["findings"]:
        entry = {"id": f["id"], "category": CATEGORY[f["kind"]], "comment": _comment(f)}
        if f["address"] is not None:
            bookmarks.append(entry | {"address": f["address"]})
        else:
            notes.append(entry)
    return {"format": FORMAT, "schema_version": SCHEMA_VERSION, "model": model, "types": types,
            "type_instances": instances, "bookmarks": bookmarks, "program_notes": notes}
