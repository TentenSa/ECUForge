"""PyGhidra adapter: read a ProgramState from a Ghidra program and execute a Plan on it.

Thin on purpose: every decision is made in plan.py. Written against the Ghidra 12.3 API (Memory,
SymbolTable, BookmarkManager, DataTypeManager, Options) and PyGhidra (open_project, program_context,
transaction, task_monitor). Needs PyGhidra and a Ghidra install (GHIDRA_INSTALL_DIR); imported only when used.
"""
from __future__ import annotations

import json

from .plan import BOOKMARK_TYPE, OPTIONS, Block, Plan, ProgramState, plan_apply

CATEGORY_PATH = "/ECUForge"
_FIELD_TYPES = {1: "byte", 2: "word", 4: "dword"}


def _addr(program, value: int):
    return program.getAddressFactory().getDefaultAddressSpace().getAddress(value)


def read_state(program, ex: dict) -> ProgramState:
    from ghidra.program.model.data import CategoryPath

    blocks = []
    for b in program.getMemory().getBlocks():
        mapped = None
        if b.isMapped():
            rng = b.getSourceInfos()[0].getMappedRange()
            if rng.isPresent():
                mapped = rng.get().getMinAddress().getOffset()
        blocks.append(Block(str(b.getName()), b.getStart().getOffset(), b.getEnd().getOffset(),
                            bool(b.isInitialized() or b.isMapped()), mapped))
    st = ProgramState(sha256=str(program.getExecutableSHA256() or "") or None, blocks=blocks)
    table = program.getSymbolTable()
    mem = program.getMemory()
    for s in ex["model"]["symbols"]:
        a = _addr(program, s["addr"])
        if mem.contains(a):
            st.symbols[s["addr"]] = [(str(x.getName()), str(x.getSource().name()), bool(x.isPrimary()))
                                     for x in table.getSymbols(a)]
    dtm = program.getDataTypeManager()
    for t in ex["types"]:
        dt = dtm.getDataType(CategoryPath(CATEGORY_PATH), t["name"])
        if dt is not None:
            st.types[t["name"]] = [(str(c.getFieldName()), c.getOffset(), c.getLength()) for c in dt.getComponents()]
    listing = program.getListing()
    for i in ex["type_instances"]:
        a = _addr(program, i["address"])
        if not mem.contains(a):
            continue
        d = listing.getDefinedDataAt(a)
        if d is not None:
            st.data_at[i["address"]] = str(d.getDataType().getName())
        elif listing.getInstructionAt(a) is not None:
            st.data_at[i["address"]] = "instruction"
        else:
            st.data_at[i["address"]] = None
    bm = program.getBookmarkManager()
    for b in ex["bookmarks"]:
        a = _addr(program, b["address"])
        if mem.contains(a):
            x = bm.getBookmark(a, BOOKMARK_TYPE, b["category"])
            if x is not None:
                st.bookmarks[(b["address"], b["category"])] = str(x.getComment())
    opts = program.getOptions(OPTIONS)
    notes = opts.getString("notes", None)
    st.notes = str(notes) if notes is not None else None
    st.owned = json.loads(str(opts.getString("owned", "{}")))
    return st


def _struct(program, a: dict):
    from ghidra.program.model.data import (
        ByteDataType,
        CategoryPath,
        DataTypeConflictHandler,
        DWordDataType,
        StructureDataType,
        WordDataType,
    )
    base = {1: ByteDataType.dataType, 2: WordDataType.dataType, 4: DWordDataType.dataType}
    s = StructureDataType(CategoryPath(CATEGORY_PATH), a["name"], a["size"])
    for f in a["fields"]:
        s.replaceAtOffset(f["offset"], base[f["size"]], f["size"], f["name"], None)
    return program.getDataTypeManager().addDataType(s, DataTypeConflictHandler.REPLACE_HANDLER)


def execute(program, plan: Plan) -> None:
    import pyghidra
    from ghidra.program.model.data import CategoryPath
    from ghidra.program.model.symbol import SourceType

    mem, table, listing = program.getMemory(), program.getSymbolTable(), program.getListing()
    opts, bm, dtm = program.getOptions(OPTIONS), program.getBookmarkManager(), program.getDataTypeManager()
    with pyghidra.transaction(program, "ECUForge apply"):
        for a in plan.actions:
            d = a["do"]
            if d == "create_uninitialized":
                blk = mem.createUninitializedBlock(a["name"], _addr(program, a["start"]), a["size"], False)
            elif d == "create_byte_mapped":
                blk = mem.createByteMappedBlock(a["name"], _addr(program, a["start"]),
                                                _addr(program, a["mapped_to"]), a["size"], False)
            if d.startswith("create_"):
                p = a["permissions"]
                blk.setRead("r" in p)
                blk.setWrite("w" in p)
                blk.setExecute("x" in p)
            elif d == "add_label":
                sym = table.createLabel(_addr(program, a["addr"]), a["name"], SourceType.IMPORTED)
                if a["primary"]:
                    sym.setPrimary()
            elif d == "define_struct":
                _struct(program, a)
            elif d == "apply_type":
                at = _addr(program, a["addr"])
                listing.createData(at, dtm.getDataType(CategoryPath(CATEGORY_PATH), a["type"]))
                if not any(str(s.getName()) == a["label"] for s in table.getSymbols(at)):
                    table.createLabel(at, a["label"], SourceType.IMPORTED)
            elif d == "set_bookmark":
                bm.setBookmark(_addr(program, a["addr"]), a["type"], a["category"], a["comment"])
            elif d == "set_notes":
                opts.setString("notes", a["text"])
            elif d == "set_owned":
                opts.setString("owned", json.dumps(a["value"], sort_keys=True))
            else:
                raise ValueError(f"unknown action {d}")


def apply_export(ex: dict, ghidra_project: str, program_path: str, dry_run: bool = False) -> Plan:
    """Open the program in a Ghidra project, plan, and (unless dry_run) execute and save."""
    from pathlib import Path

    import pyghidra
    if not pyghidra.started():
        pyghidra.start()
    proj_dir = Path(ghidra_project)
    project = pyghidra.open_project(str(proj_dir.parent), proj_dir.name)
    try:
        with pyghidra.program_context(project, program_path) as program:
            plan = plan_apply(ex, read_state(program, ex))
            if plan.refused or dry_run or not plan.actions:
                return plan
            execute(program, plan)
            program.save("ECUForge apply", pyghidra.task_monitor())
            return plan
    finally:
        project.close()
