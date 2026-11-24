"""Consumer-neutral export model.

One normalised description of what ECUForge recovered for a program image, independent of any consumer.
Exporters (Ghidra first) read this model; nothing in the analysis core knows about them.

Identity rules
- The program is the image artifact a consumer loads (HEX/S19, or the ELF when no HEX/S19 is given).
  Every stable id is anchored to its SHA-256, so ids from different builds never collide.
- Finding ids derive from the finding's semantic key ("<rule>@<subject>"), never from its claim text,
  sources or data, so improving the evidence behind a finding keeps its id.
- Physical memory is grouped by the bytes it addresses: one region, one canonical view, zero or more
  alias views that point at the canonical view. Bytes are never described twice.
  The canonical view is the cached one, as in the analysis core (profile.canonical). The core-local
  DSPR/PSPR windows are exported as their own regions: which CPU's memory they reach depends on the
  executing core, so they cannot be tied to one region.
- Permissions are null: no profile documents them. A consumer must not invent them silently.
"""
from __future__ import annotations

import hashlib

from .. import __version__

SCHEMA_VERSION = 1


def _h(*parts: str) -> str:
    return hashlib.sha256("\0".join(parts).encode()).hexdigest()[:16]


def program_artifact(p):
    art = p.image_artifacts[0] if p.image_artifacts else p.elf_art
    if art is None:
        raise ValueError("no program image loaded")
    return art


def finding_id(program_sha: str, key: str) -> str:
    return f"ecuforge:finding:{_h(program_sha, key)}"


def symbol_id(program_sha: str, name: str, addr: int) -> str:
    return f"ecuforge:symbol:{program_sha[:12]}:{addr:08x}:{name}"


def block_id(program_sha: str, region: str) -> str:
    return f"ecuforge:block:{program_sha[:12]}:{region}"


def _memory(p, prog: str) -> list[dict]:
    """Physical regions from documented profile facts, with canonical and alias views."""
    prof = p.profile
    regions: list[dict] = []
    by_start: dict[int, dict] = {}
    aliases = []
    for w in prof.windows:
        if w.cached is False and "bus_alias" in w.facts:
            aliases.append(w)
            continue
        rid = w.name
        view = {"id": block_id(prog, rid), "name": w.name, "start": w.start, "size": w.size,
                "canonical": True, "alias_of": None, "cached": w.cached}
        reg = {"id": rid, "kind": w.kind, "core": w.core, "permissions": None, "views": [view],
               "sources": [str(s) for s in prof.window_source(w)]}
        regions.append(reg)
        by_start[w.start] = reg
    for w in aliases:
        target = prof.alternate(w.start)
        reg = by_start.get(target)
        if reg is None:  # alias of a window the profile does not document: keep it, unrelated
            regions.append({"id": w.name, "kind": w.kind, "core": w.core, "permissions": None,
                            "views": [{"id": block_id(prog, w.name), "name": w.name, "start": w.start,
                                       "size": w.size, "canonical": True, "alias_of": None, "cached": False}],
                            "sources": [str(s) for s in prof.window_source(w)]})
            continue
        canon = reg["views"][0]
        reg["views"].append({"id": block_id(prog, w.name), "name": w.name, "start": w.start, "size": w.size,
                             "canonical": False, "alias_of": canon["id"], "cached": False})
    return regions


_ADDR_KEYS = ("addr", "address", "start", "vma", "bottom")


def _address(f, by_id: dict, depth: int = 0) -> int | None:
    """Address a finding is about: its own data first, else the finding it was derived from."""
    for k in _ADDR_KEYS:
        v = f.data.get(k)
        if isinstance(v, int) and not isinstance(v, bool):
            return v
    if depth < 4:
        for d in f.derived_from:
            parent = by_id.get(d)
            a = _address(parent, by_id, depth + 1) if parent else None
            if a is not None:
                return a
    return None


def build_export(p, res: dict) -> dict:
    """Normalised export of one analysed project (``res`` is the result of ``analyze.run_all``)."""
    art = program_artifact(p)
    prog = art.sha256
    prof = p.profile.describe()
    lay = res["layout"]
    syms = sorted(p.symbols().values(), key=lambda s: (s.addr, s.name))
    by_id = {f.id: f for f in p.store.findings}
    return {
        "schema_version": SCHEMA_VERSION,
        "ecuforge_version": __version__,
        "program": {"sha256": prog, "name": art.short.split("@")[0], "type": art.type},
        "profile": {"id": prof["id"], "version": prof["version"]},
        "memory": _memory(p, prog),
        "linker_regions": [{"name": r.name, "start": r.origin, "size": r.length, "used": r.used,
                            "physical": r.physical, "relation": r.physical_relation} for r in lay.regions],
        "sections": [{"name": s.name, "vma": s.vma, "lma": s.lma, "size": s.size, "class": s.cls,
                      "init": s.init, "region": s.region, "physical": s.physical, "core": s.core}
                     for s in lay.sections],
        "symbols": [{"id": symbol_id(prog, s.name, s.addr), "name": s.name, "addr": s.addr, "size": s.size,
                     "size_kind": s.size_kind, "origin": s.origin, "section": s.section} for s in syms],
        "findings": [{"id": finding_id(prog, f.key), "key": f.key, "kind": f.kind, "level": f.level,
                      "severity": f.severity, "topic": f.topic, "claim": f.claim, "address": _address(f, by_id),
                      "sources": [{"artifact_sha256": s.sha256, "type": s.type, "locator": s.locator}
                                  for s in f.sources]}
                     for f in p.store.findings],
    }
