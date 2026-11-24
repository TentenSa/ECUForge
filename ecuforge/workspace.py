"""Project workspace: a content-addressed artifact store plus persisted, reproducible analysis runs.

Layout::

    <workspace>/
      ecuforge.json            workspace manifest (schema_version 1)
      objects/sha256/<hash>/<name>
      analysis/current.json    latest run
      analysis/runs/<run_id>.json
      exports/ghidra/
      reports/

Artifact identity (the SHA-256 of the bytes) is separate from artifact role: one stored object can be
used in several roles, and adding the same object in the same role twice changes nothing.
Persisted output never contains absolute host paths.
"""
from __future__ import annotations

import hashlib
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

from . import __version__

SCHEMA_VERSION = 1
MANIFEST = "ecuforge.json"
ROLES = ("image", "elf", "map", "lsl", "a2l", "profile")
_EXT_ROLE = {".elf": "elf", ".hex": "image", ".ihex": "image", ".s19": "image", ".srec": "image",
             ".mot": "image", ".map": "map", ".lsl": "lsl", ".a2l": "a2l"}


class WorkspaceError(Exception):
    pass


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def guess_role(path: str | Path) -> str | None:
    p = Path(path)
    if p.suffix.lower() in _EXT_ROLE:
        return _EXT_ROLE[p.suffix.lower()]
    with p.open("rb") as fh:
        if fh.read(4) == b"\x7fELF":
            return "elf"
    return None


def _dumps(obj) -> str:
    return json.dumps(obj, indent=2, sort_keys=True) + "\n"


class Workspace:
    def __init__(self, root: str | Path):
        self.root = Path(root).resolve()
        mf = self.root / MANIFEST
        if not mf.is_file():
            raise WorkspaceError(f"{self.root}: not an ECUForge workspace (no {MANIFEST}); run `ecuforge init`")
        self.data = json.loads(mf.read_text())
        if self.data.get("schema_version") != SCHEMA_VERSION:
            raise WorkspaceError(f"{mf}: unsupported schema_version {self.data.get('schema_version')!r}")

    # ---- creation -------------------------------------------------------------
    @staticmethod
    def init(root: str | Path, device: str = "tc38x", toolchain: str | None = None,
             bmhd_crc_mode: str | None = None, experimental: bool = False) -> "Workspace":
        root = Path(root)
        if (root / MANIFEST).exists():
            raise WorkspaceError(f"{root}: workspace already exists")
        for d in ("objects/sha256", "analysis/runs", "exports/ghidra", "reports"):
            (root / d).mkdir(parents=True, exist_ok=True)
        data = {"schema_version": SCHEMA_VERSION, "name": root.resolve().name,
                "target": {"device": device},
                "analysis_options": {"toolchain": toolchain, "bmhd_crc_mode": bmhd_crc_mode,
                                     "experimental": experimental},
                "artifacts": []}
        (root / MANIFEST).write_text(_dumps(data))
        ws = Workspace(root)
        dev = Path(device)
        if dev.suffix == ".json" and dev.is_file():  # a profile file: store it so the workspace is self-contained
            ws.add(dev, "profile")
            ws.data["target"]["device"] = None
            ws._save()
        return ws

    def _save(self) -> None:
        (self.root / MANIFEST).write_text(_dumps(self.data))

    # ---- artifacts ------------------------------------------------------------
    def add(self, path: str | Path, role: str | None = None) -> tuple[dict, bool]:
        """Store a file and record its use in a role. Returns (entry, added); added is False if already present."""
        src = Path(path)
        if not src.is_file():
            raise WorkspaceError(f"{src}: no such file")
        role = role or guess_role(src)
        if role not in ROLES:
            raise WorkspaceError(f"{src}: cannot tell its role; pass --role ({', '.join(ROLES)})")
        taken = [a for a in self.data["artifacts"] if a["role"] == role]
        sha = _sha256(src)
        for a in self.data["artifacts"]:
            if a["sha256"] == sha and a["role"] == role:
                return a, False
        if taken:
            raise WorkspaceError(f"role {role!r} already holds {taken[0]['name']}@{taken[0]['sha256'][:12]}; "
                                 f"remove it first (one artifact per role in schema 1)")
        obj = self.root / "objects" / "sha256" / sha / src.name
        if not obj.exists():
            obj.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, obj)
            obj.chmod(0o444)
        entry = {"sha256": sha, "name": src.name, "role": role, "size": obj.stat().st_size}
        self.data["artifacts"].append(entry)
        self.data["artifacts"].sort(key=lambda a: (ROLES.index(a["role"]), a["sha256"]))
        self._save()
        return entry, True

    def remove(self, role: str) -> dict | None:
        for a in self.data["artifacts"]:
            if a["role"] == role:
                self.data["artifacts"].remove(a)
                self._save()
                return a
        return None

    def object_path(self, entry: dict) -> Path:
        p = self.root / "objects" / "sha256" / entry["sha256"] / entry["name"]
        if not p.is_file() or _sha256(p) != entry["sha256"]:
            raise WorkspaceError(f"object {entry['name']}@{entry['sha256'][:12]} is missing or modified")
        return p

    def by_role(self, role: str) -> dict | None:
        return next((a for a in self.data["artifacts"] if a["role"] == role), None)

    # ---- analysis -------------------------------------------------------------
    def open(self):
        from .analyze import open_project
        o = self.data["analysis_options"]
        prof = self.by_role("profile")
        device = str(self.object_path(prof)) if prof else self.data["target"]["device"]
        paths = {r: (str(self.object_path(e)) if (e := self.by_role(r)) else None)
                 for r in ("image", "elf", "map", "lsl", "a2l")}
        image = paths["image"] or paths["elf"]
        if image is None:
            raise WorkspaceError("workspace has no image or ELF; `ecuforge add` one first")
        return open_project(image, paths["elf"], paths["map"], paths["lsl"], paths["a2l"], device,
                            o.get("toolchain"), o.get("bmhd_crc_mode"), bool(o.get("experimental")))

    def _scrub(self, obj):
        """Replace absolute paths: workspace objects become relative, anything else keeps only its file name."""
        root = str(self.root) + "/"
        if isinstance(obj, dict):
            return {k: self._scrub(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self._scrub(v) for v in obj]
        if isinstance(obj, str) and obj.startswith("/"):
            return obj[len(root):] if obj.startswith(root) else "<builtin>/" + Path(obj).name
        return obj

    def analyze(self) -> tuple[dict, str]:
        """Run all analyses and persist the result. Returns (record, run_id)."""
        from .analyze import run_all
        p = self.open()
        res = run_all(p)
        prof = p.profile.describe()
        body = {
            "schema_version": SCHEMA_VERSION,
            "ecuforge_version": __version__,
            "profile_id": prof["id"],
            "profile_version": prof["version"],
            "artifacts": [{"sha256": a["sha256"], "name": a["name"], "role": a["role"]}
                          for a in self.data["artifacts"]],
            "analysis_options": self.data["analysis_options"],
            "run": res["run"],
            "evidence": json.loads(p.store.to_json()),
            "linker_draft": res["linker_draft"],
        }
        body = self._scrub(body)
        canon = json.dumps(body, sort_keys=True, separators=(",", ":"))
        run_id = hashlib.sha256(canon.encode()).hexdigest()[:16]
        record = {"run_id": run_id, "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                  "result": body}
        runs = self.root / "analysis" / "runs"
        runs.mkdir(parents=True, exist_ok=True)
        (runs / f"{run_id}.json").write_text(_dumps(record))
        (self.root / "analysis" / "current.json").write_text(_dumps(record))
        return record, run_id

    def export_ghidra(self, output: str | Path | None = None) -> Path:
        """Write the Ghidra export for the current workspace state. Returns the file path."""
        from .analyze import run_all
        from .export.ghidra import build_ghidra_export
        p = self.open()
        data = self._scrub(build_ghidra_export(p, run_all(p)))
        out = Path(output) if output else self.root / "exports" / "ghidra" / "ecuforge-ghidra.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(_dumps(data))
        return out

    def current(self) -> dict | None:
        f = self.root / "analysis" / "current.json"
        return json.loads(f.read_text()) if f.is_file() else None
