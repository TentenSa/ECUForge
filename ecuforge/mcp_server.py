"""MCP server exposing ECUForge to agents (stdio). Requires `pip install mcp`.

Register e.g. in Claude Code:
  claude mcp add ecuforge -- python -m ecuforge.mcp_server
"""
from __future__ import annotations

import uuid

try:  # MCP Python SDK 2.x
    from mcp.server.mcpserver import MCPServer as _Server
except ImportError:  # SDK 1.x
    from mcp.server.fastmcp import FastMCP as _Server

from .analyze import open_project, render_markdown, run_all
from .silicon.infineon.aurix.profile import DeviceProfile

mcp = _Server("ecuforge")
_sessions: dict[str, dict] = {}


def _get(sid: str) -> dict:
    if sid not in _sessions:
        raise ValueError(f"unknown session {sid}; call open_build first")
    return _sessions[sid]


@mcp.tool()
def list_profiles() -> list[str]:
    """List AURIX device profiles (classification windows) shipped with ECUForge."""
    return DeviceProfile.available()


@mcp.tool()
def open_build(image: str | None = None, elf: str | None = None, map_file: str | None = None,
               lsl: str | None = None, a2l: str | None = None, device: str = "tc38x",
               toolchain: str | None = None, bmhd_crc_mode: str | None = None, experimental: bool = False) -> dict:
    """Open build artifacts (absolute paths). image = hex/s19/elf; map_file = GNU/HighTec or TASKING map;
    toolchain forces 'gnu' or 'tasking'; bmhd_crc_mode = discover|profile|strict; experimental enables L2
    (A2L, AUTOSAR). Returns a session id and input findings."""
    p = open_project(image, elf, map_file, lsl, a2l, device, toolchain, bmhd_crc_mode, experimental)
    sid = uuid.uuid4().hex[:8]
    _sessions[sid] = {"project": p, "result": None}
    return {"session_id": sid, "inputs": [f.to_dict() for f in p.store.query(topic="input")]}


@mcp.tool()
def analyze(session_id: str, max_issues: int = 50) -> dict:
    """Run layout recovery, address-space relations, startup recovery, map/ELF correlation (and L2 when
    experimental). Returns the summary, run record and top issues with evidence ids."""
    s = _get(session_id)
    p = s["project"]
    if s["result"] is None:
        s["result"] = run_all(p)
    issues = p.store.query(min_severity="warning")
    issues.sort(key=lambda f: (f.severity != "error", f.id))
    return {"summary": p.store.summary(), "run": s["result"]["run"],
            "issues": [{"id": f.id, "severity": f.severity, "kind": f.kind, "claim": f.claim}
                       for f in issues[:max_issues]],
            "truncated": max(0, len(issues) - max_issues)}


@mcp.tool()
def get_findings(session_id: str, topic: str | None = None, kind: str | None = None,
                 min_severity: str | None = None, level: str | None = None, limit: int = 100,
                 offset: int = 0) -> dict:
    """Page through findings. topic: input|layout|symbols|startup|a2l|autosar.
    kind: observed|derived|inferred|unknown|conflict. level: L0|L1|L2."""
    p = _get(session_id)["project"]
    fs = p.store.query(topic, kind, min_severity, level)
    return {"total": len(fs), "findings": [f.to_dict() for f in fs[offset: offset + limit]]}


@mcp.tool()
def get_evidence(session_id: str, finding_id: str) -> dict:
    """Full finding with sources (artifact digest + locator) and findings it was derived from."""
    p = _get(session_id)["project"]
    f = p.store.get(finding_id)
    if f is None:
        raise ValueError(f"no finding {finding_id}")
    d = f.to_dict()
    d["derived_from_findings"] = [p.store.get(x).to_dict() for x in f.derived_from if p.store.get(x)]
    d["artifacts"] = {k: vars(v) for k, v in p.store.artifacts.items()}
    return d


@mcp.tool()
def lookup(session_id: str, what: str) -> dict:
    """Resolve a symbol name, or an address (0x...) to symbol/section/region/device window."""
    p = _get(session_id)["project"]
    try:
        addr = int(what, 0)
    except ValueError:
        s = p.symbols().get(what)
        if not s:
            return {"found": False}
        return {"found": True, "name": s.name, "addr": hex(s.addr), "size": s.size, "origin": s.origin,
                "section": s.section, "obj": s.obj, "source": str(s.source)}
    sym = p.symbol_at(addr)
    win = p.profile.classify(addr)
    return {"addr": hex(addr),
            "symbol": sym.name if sym else None,
            "section": (p.map.section_of(addr).name if p.map and p.map.section_of(addr) else None),
            "region": (p.map.region_of(addr).name if p.map and p.map.region_of(addr) else None),
            "physical": win.name if win else None, "core": win.core if win else None}


@mcp.tool()
def read_memory(session_id: str, address: str, length: int = 64) -> dict:
    """Read bytes from the flash image (hex/s19/ELF load data). Gaps return null, never filler."""
    p = _get(session_id)["project"]
    a = int(address, 0)
    data = p.image.read(a, min(length, 4096))
    seg = p.image.find_any(a)
    return {"address": hex(a), "bytes": data.hex() if data else None,
            "present": p.image.coverage(a, length),
            "source": f"{seg.origin} {seg.locator}" if seg else None}


@mcp.tool()
def verify_manifest(manifest_path: str) -> str:
    """Check ECUForge against a hand-verified fixture manifest (L0/L1/L2). Returns the verdict text."""
    from .verify import render, verify
    vr, _ = verify(manifest_path)
    return render(vr, manifest_path)  # score: correct / unknown / conflict / false_claim


@mcp.tool()
def linker_draft(session_id: str) -> str:
    """GNU-LD style MEMORY/SECTIONS draft reconstructed from evidence (review before use)."""
    s = _get(session_id)
    if s["result"] is None:
        s["result"] = run_all(s["project"])
    return s["result"]["linker_draft"] or "no linker regions available"


@mcp.tool()
def report(session_id: str) -> str:
    """Markdown report of the whole analysis."""
    s = _get(session_id)
    if s["result"] is None:
        s["result"] = run_all(s["project"])
    return render_markdown(s["project"], s["result"])


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
