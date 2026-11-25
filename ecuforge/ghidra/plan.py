"""Plan what applying an ECUForge export changes in a Ghidra program.

Pure Python: no Ghidra import. The PyGhidra adapter reads a ProgramState from the program, calls plan_apply,
and executes the returned actions. Everything that decides *what* to change lives here, so it is testable
without Ghidra.

Rules (approved for 0.2)
- One-way: ECUForge -> Ghidra. Nothing is read back into ECUForge.
- Refuse when the program's image hash differs from the export's (no stale-object cleanup in 0.2).
- Never modify or delete blocks, symbols or data that ECUForge did not create.
- Applying the same export twice changes nothing: every action is checked against the current state.

Memory
- Within one physical region, the view whose range already holds loaded bytes carries the bytes; every other
  view of that region with nothing loaded at its range becomes a byte-mapped block onto it. So an image loaded
  at the non-cached alias works the same as one loaded at the cached address.
- A region with no loaded bytes at all gets one uninitialized block for its canonical view.
- A view that partly overlaps existing blocks is left alone and reported.
- Permissions: a block that ECUForge creates gets the ELF permissions of the sections inside it when they all
  agree; otherwise read/write/execute is left on and a note says the permissions are undocumented.

Symbols
- Same name already at the address: nothing to do.
- A user-defined symbol at the address: kept as primary; the ECUForge name is added as a secondary label and
  reported as a conflict.
- Otherwise the ECUForge name is added and made primary.

Bookmarks
- Ghidra keeps one bookmark per (address, type, category) and replaces its comment on a second set, so findings
  that share an address and category are merged into one comment, ordered by finding id.
- A bookmark whose address is outside every block (before or after this apply) becomes a program note.
"""
from __future__ import annotations

from dataclasses import dataclass, field

BOOKMARK_TYPE = "ECUForge"
OPTIONS = "ECUForge"
NOTES_CATEGORY = "ECUForge.Notes"


@dataclass(frozen=True)
class Block:
    name: str
    start: int
    end: int  # inclusive
    initialized: bool = True
    mapped_to: int | None = None  # byte-mapped source start

    def overlaps(self, lo: int, hi: int) -> bool:
        return self.start <= hi and lo <= self.end

    def covers(self, lo: int, hi: int) -> bool:
        return self.start <= lo and hi <= self.end


@dataclass
class ProgramState:
    sha256: str | None
    blocks: list[Block]
    symbols: dict[int, list[tuple[str, str, bool]]] = field(default_factory=dict)  # addr -> (name, source, primary)
    types: dict[str, list[tuple[str, int, int]]] = field(default_factory=dict)  # /ECUForge types: name -> fields
    data_at: dict[int, str | None] = field(default_factory=dict)  # addr -> defined data type name, None = undefined
    bookmarks: dict[tuple[int, str], str] = field(default_factory=dict)  # (addr, category) -> comment, ours only
    notes: str | None = None
    owned: dict = field(default_factory=dict)  # what earlier applies recorded in the program options


@dataclass
class Plan:
    refused: str | None = None
    actions: list[dict] = field(default_factory=list)
    report: list[str] = field(default_factory=list)

    def kinds(self) -> list[str]:
        return [a["do"] for a in self.actions]


def _in_memory(blocks: list[Block], addr: int) -> bool:
    return any(b.start <= addr <= b.end for b in blocks)


def _perms_for(view_lo: int, view_hi: int, sections: list[dict]) -> str | None:
    inside = {s["permissions"] for s in sections
              if s.get("permissions") and s["size"] and view_lo <= s["vma"] and s["vma"] + s["size"] - 1 <= view_hi}
    return inside.pop() if len(inside) == 1 else None


def _plan_memory(ex: dict, st: ProgramState, plan: Plan) -> list[Block]:
    blocks = list(st.blocks)
    owned_blocks = set(st.owned.get("blocks", []))
    for region in ex["model"]["memory"]:
        views = region["views"]
        rng = {v["id"]: (v["start"], v["start"] + v["size"] - 1) for v in views}
        holder = None
        for v in views:
            lo, hi = rng[v["id"]]
            if any(b.overlaps(lo, hi) and b.initialized and b.mapped_to is None for b in blocks):
                holder = v
                break
        for v in views:
            lo, hi = rng[v["id"]]
            if any(b.name == v["name"] and b.start == lo for b in blocks):
                # created by an earlier apply (report its permissions again, so notes stay identical) or loaded
                if v["name"] in owned_blocks and _perms_for(lo, hi, ex["model"]["sections"]) is None:
                    plan.report.append(f"memory {v['name']}: permissions undocumented, left read/write/execute")
                continue
            if any(b.overlaps(lo, hi) for b in blocks):
                if v is not holder:
                    plan.report.append(f"memory {v['name']}: range {lo:#010x}-{hi:#010x} partly loaded, left as is")
                continue
            if holder is not None and v is not holder:
                hlo, _ = rng[holder["id"]]
                act = {"do": "create_byte_mapped", "name": v["name"], "start": lo, "size": v["size"], "mapped_to": hlo,
                       "id": v["id"]}
                blocks.append(Block(v["name"], lo, hi, True, hlo))
            elif holder is None and v["canonical"]:
                act = {"do": "create_uninitialized", "name": v["name"], "start": lo, "size": v["size"], "id": v["id"]}
                blocks.append(Block(v["name"], lo, hi, False))
            else:
                continue
            perms = _perms_for(lo, hi, ex["model"]["sections"])
            act["permissions"] = perms or "rwx"
            if perms is None:
                plan.report.append(f"memory {v['name']}: permissions undocumented, left read/write/execute")
            plan.actions.append(act)
    return blocks


def _plan_symbols(ex: dict, st: ProgramState, plan: Plan, blocks: list[Block]) -> None:
    for s in ex["model"]["symbols"]:
        addr, name = s["addr"], s["name"]
        if not _in_memory(blocks, addr):
            continue
        here = st.symbols.get(addr, [])
        user = [n for n, src, primary in here if src == "USER_DEFINED" and primary and n != name]
        if user:  # reported on every apply, so the notes stay identical once the label exists
            plan.report.append(f"symbol conflict at {addr:#010x}: kept your '{user[0]}', added '{name}' as secondary")
        if any(n == name for n, _, _ in here):
            continue
        if user:
            plan.actions.append({"do": "add_label", "addr": addr, "name": name, "primary": False, "id": s["id"]})
        else:
            plan.actions.append({"do": "add_label", "addr": addr, "name": name, "primary": True, "id": s["id"]})


def _plan_types(ex: dict, st: ProgramState, plan: Plan, blocks: list[Block]) -> None:
    for t in ex["types"]:
        fields = [(f["name"], f["offset"], f["size"]) for f in t["fields"]]
        if st.types.get(t["name"]) != fields:
            plan.actions.append({"do": "define_struct", "name": t["name"], "size": t["size"], "fields": t["fields"]})
    for i in ex["type_instances"]:
        a = i["address"]
        if not _in_memory(blocks, a):
            continue
        have = st.data_at.get(a)
        if have == i["type"]:
            continue
        if have is not None:
            plan.report.append(f"type {i['type']} at {a:#010x}: '{have}' already defined there, left as is")
            continue
        plan.actions.append({"do": "apply_type", "addr": a, "type": i["type"], "label": i["label"]})


def _plan_bookmarks(ex: dict, st: ProgramState, plan: Plan, blocks: list[Block]) -> list[dict]:
    merged: dict[tuple[int, str], list[dict]] = {}
    homeless = []
    for b in ex["bookmarks"]:
        if _in_memory(blocks, b["address"]):
            merged.setdefault((b["address"], b["category"]), []).append(b)
        else:
            homeless.append(b)
    for (addr, cat), bs in sorted(merged.items()):
        comment = "\n".join(f"[{b['id']}] {b['comment']}" for b in sorted(bs, key=lambda b: b["id"]))
        if st.bookmarks.get((addr, cat)) != comment:
            plan.actions.append({"do": "set_bookmark", "addr": addr, "type": BOOKMARK_TYPE, "category": cat,
                                 "comment": comment})
    return homeless


def plan_apply(ex: dict, st: ProgramState) -> Plan:
    plan = Plan()
    if ex.get("format") != "ecuforge-ghidra" or ex.get("schema_version") != 1:
        plan.refused = "not an ECUForge Ghidra export (schema 1)"
        return plan
    want = ex["model"]["program"]["sha256"]
    if st.sha256 and st.sha256.lower() != want.lower():
        plan.refused = (f"program image hash {st.sha256[:12]} differs from the export's {want[:12]}; "
                        f"import the matching image into a new program")
        return plan
    blocks = _plan_memory(ex, st, plan)
    _plan_symbols(ex, st, plan, blocks)
    _plan_types(ex, st, plan, blocks)
    homeless = _plan_bookmarks(ex, st, plan, blocks)
    notes = [f"[{n['id']}] {n['category']}: {n['comment']}" for n in ex["program_notes"]]
    notes += [f"[{b['id']}] {b['category']} at {b['address']:#010x} (not in memory): {b['comment']}" for b in homeless]
    notes += [f"apply: {r}" for r in plan.report]
    text = "\n".join(notes)
    if st.notes != text:
        plan.actions.append({"do": "set_notes", "text": text})
    owned = {"program_sha256": want,
             "blocks": sorted(set(st.owned.get("blocks", [])) |
                              {a["name"] for a in plan.actions if a["do"].startswith("create_")})}
    if st.owned != owned:
        plan.actions.append({"do": "set_owned", "value": owned})
    return plan
