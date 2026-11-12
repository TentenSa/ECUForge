"""AURIX device profiles: documented silicon facts with citations.

Every hardware value in a profile is a fact object:
    {"value": ..., "source": "<source id>", "ref": "<table / section>", "verification": "..."}
or null when no public document establishing it has been checked yet. Null means
UNKNOWN, never a default. The profile describes the *physical* address space
only; it never overrides what the map, ELF or image say (see core.views).

verification values:
    documented            silicon-vendor public document
    documented-secondary  toolchain-vendor public document
    synthetic             test fixtures only; rejected in shipped profiles
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from ....core.evidence import Artifact, Source

TARGET_DIR = Path(__file__).parent / "targets"


@dataclass
class Window:
    name: str
    start: int
    size: int
    kind: str  # dspr | pspr | dspr-local | pspr-local | pflash | dflash | ucb-bmhd
    core: int | None = None
    cached: bool | None = None
    facts: list[str] = field(default_factory=list)  # fact paths backing this window

    def contains(self, addr: int) -> bool:
        return self.start <= addr < self.start + self.size

    @property
    def end(self) -> int:
        return self.start + self.size


class DeviceProfile:
    def __init__(self, data: dict, path: Path):
        self.data = data
        self.path = path
        self.artifact = Artifact.from_path(path, "mcu_profile", "silicon.infineon.aurix.profile")
        self.id = data.get("id", path.stem)
        self.version = data.get("version", "0")
        self.device = data.get("device", path.stem)
        self.sources = data.get("sources", {})
        self.windows: list[Window] = []
        self._build()

    # ---- loading ----------------------------------------------------------
    @staticmethod
    def load(name_or_path: str) -> "DeviceProfile":
        p = Path(name_or_path)
        if not p.exists():
            p = TARGET_DIR / f"{name_or_path.lower()}.json"
        if not p.exists():
            raise FileNotFoundError(f"no profile '{name_or_path}' (available: {', '.join(DeviceProfile.available())})")
        return DeviceProfile(json.loads(p.read_text()), p)

    @staticmethod
    def available() -> list[str]:
        return sorted(x.stem for x in TARGET_DIR.glob("*.json"))

    # ---- facts --------------------------------------------------------------
    def fact(self, path: str):
        """Return (value, Source) for a dotted fact path, or (None, None) when unknown."""
        node = self.data
        for part in path.split("."):
            if node is None:
                return None, None
            node = node[int(part)] if isinstance(node, list) else node.get(part)
        if not isinstance(node, dict) or "value" not in node:
            return None, None
        doc = self.sources.get(node.get("source"), {})
        excerpt = " ".join(str(x) for x in (doc.get("vendor"), doc.get("document"), doc.get("revision"),
                                             doc.get("date")) if x)
        return node["value"], Source(self.artifact.short, f"fact {path} [{node.get('verification')}]",
                                     f"{excerpt}; {node.get('ref', '')}".strip("; "))

    def facts_unknown(self) -> list[str]:
        out = []

        def walk(node, path):
            if node is None:
                out.append(path)
            elif isinstance(node, dict) and "value" not in node:
                for k, v in node.items():
                    if k not in ("sources",):
                        walk(v, f"{path}.{k}" if path else k)
            elif isinstance(node, list):
                for i, v in enumerate(node):
                    walk(v, f"{path}.{i}")
        walk({k: v for k, v in self.data.items() if k in ("cpus", "flash", "bus_alias", "bmhd")}, "")
        return out

    def synthetic_facts(self) -> list[str]:
        out = []

        def walk(node, path):
            if isinstance(node, dict):
                if node.get("verification") == "synthetic":
                    out.append(path)
                for k, v in node.items():
                    walk(v, f"{path}.{k}")
            elif isinstance(node, list):
                for i, v in enumerate(node):
                    walk(v, f"{path}.{i}")
        walk(self.data, "")
        return out

    # ---- windows ------------------------------------------------------------
    def _build(self) -> None:
        local_size = {"dspr": 0, "pspr": 0}
        local_alias = {}
        for i, c in enumerate(self.data.get("cpus", [])):
            for mem in ("dspr", "pspr"):
                base, _ = self.fact(f"cpus.{i}.{mem}.base")
                size, _ = self.fact(f"cpus.{i}.{mem}.size")
                if size:
                    local_size[mem] = max(local_size[mem], size)
                if base is not None and size:
                    self.windows.append(Window(f"CPU{c['id']} {mem.upper()}", base, size, mem, c["id"], None,
                                               [f"cpus.{i}.{mem}.base", f"cpus.{i}.{mem}.size"]))
                la, _ = self.fact(f"cpus.{i}.local_alias.{mem}")
                if la is not None:
                    local_alias[mem] = (la, f"cpus.{i}.local_alias.{mem}")
        for mem, (la, fp) in local_alias.items():
            if local_size[mem]:
                self.windows.append(Window(f"{mem.upper()} (core-local alias)", la, local_size[mem], f"{mem}-local",
                                           None, None, [fp]))
        for mem, kind in (("pflash", "pflash"), ("dflash0", "dflash")):
            base, _ = self.fact(f"flash.{mem}.base")
            size, _ = self.fact(f"flash.{mem}.size")
            if base is not None and size:
                self.windows.append(Window(mem.upper(), base, size, kind, None,
                                           True if self.alias_pair_for(base) else None,
                                           [f"flash.{mem}.base", f"flash.{mem}.size"]))
        for i, s in enumerate((self.data.get("bmhd") or {}).get("slots", [])):
            a, _ = self.fact(f"bmhd.slots.{i}.addr")
            z, _ = self.fact(f"bmhd.slots.{i}.size")
            if a is not None and z:
                self.windows.append(Window(s["name"], a, z, "ucb-bmhd", None, None, [f"bmhd.slots.{i}.addr"]))
        alias = self.data.get("bus_alias")
        if isinstance(alias, dict) and alias.get("value"):
            for pair in alias["value"]:
                c0, n0, size = pair["cached"], pair["noncached"], pair["size"]
                for w in list(self.windows):
                    if w.start == c0:
                        w.cached = True
                        self.windows.append(Window(w.name + " (non-cached)", n0, size, w.kind, w.core, False,
                                                   w.facts + ["bus_alias"]))

    def alias_pair_for(self, addr: int):
        alias = self.data.get("bus_alias")
        if not (isinstance(alias, dict) and alias.get("value")):
            return None
        for pair in alias["value"]:
            for a, b in ((pair["cached"], pair["noncached"]), (pair["noncached"], pair["cached"])):
                if a <= addr < a + pair["size"]:
                    return a, b
        return None

    def classify(self, addr: int) -> Window | None:
        hits = [w for w in self.windows if w.contains(addr)]
        return min(hits, key=lambda w: w.size) if hits else None

    def window_source(self, w: Window) -> list[Source]:
        return [s for _, s in (self.fact(f) for f in w.facts if f != "bus_alias") if s]

    def canonical(self, addr: int) -> int:
        """Cached view of an address when a documented bus alias exists; otherwise unchanged."""
        pair = self.alias_pair_for(addr)
        if pair is None:
            return addr
        a, b = pair
        alias = self.data["bus_alias"]["value"]
        is_noncached = any(p["noncached"] <= addr < p["noncached"] + p["size"] for p in alias)
        return b + (addr - a) if is_noncached else addr

    def alternate(self, addr: int) -> int | None:
        pair = self.alias_pair_for(addr)
        return None if pair is None else pair[1] + (addr - pair[0])

    def same_location(self, a: int, b: int) -> bool:
        return self.canonical(a) == self.canonical(b)

    def mem_kind(self, addr: int) -> str | None:
        """'ram' | 'flash' | 'ucb' | None (unknown from documented facts)."""
        w = self.classify(addr)
        if w is None:
            return None
        return {"dspr": "ram", "pspr": "ram", "dspr-local": "ram", "pspr-local": "ram", "pflash": "flash",
                "dflash": "flash", "ucb-bmhd": "ucb"}.get(w.kind)

    def cpu_window(self, core: int, mem: str) -> Window | None:
        return next((w for w in self.windows if w.kind == mem and w.core == core), None)

    @property
    def cores(self) -> int:
        return len(self.data.get("cpus", []))

    def describe(self) -> dict:
        return {"id": self.id, "version": self.version, "device": self.device, "sha256": self.artifact.sha256,
                "path": str(self.path), "unknown_facts": len(self.facts_unknown()),
                "synthetic_facts": len(self.synthetic_facts())}
