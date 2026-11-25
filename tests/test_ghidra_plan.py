"""Plan for applying a Ghidra export, checked against a fake program that follows Ghidra's rules:
one bookmark per (address, type, category) with its comment replaced on a second set; labels added, primary
switched only when asked; blocks never overlap."""
import copy
from dataclasses import replace

import pytest

from ecuforge.analyze import open_project, run_all
from ecuforge.export.ghidra import build_ghidra_export
from ecuforge.formats.hexrec import load_ihex
from ecuforge.ghidra.plan import Block, ProgramState, plan_apply


@pytest.fixture(scope="module")
def ex(gen, syn_profile):
    p = open_project(gen / "app.hex", gen / "app.elf", gen / "app_gnu.map", None, None, syn_profile)
    return build_ghidra_export(p, run_all(p))


def loaded_state(gen, ex, shift=0):
    """Blocks as Ghidra's Intel HEX loader makes them: one per contiguous range (optionally moved by shift)."""
    img = load_ihex(gen / "app.hex", "HEX")
    blocks = [Block(f"ram_{a + shift:08x}", a + shift, a + shift + n - 1) for a, n, *_ in img.regions()]
    return ProgramState(sha256=ex["model"]["program"]["sha256"], blocks=blocks)


def execute(st: ProgramState, plan) -> ProgramState:
    st = copy.deepcopy(st)
    for a in plan.actions:
        d = a["do"]
        if d in ("create_uninitialized", "create_byte_mapped"):
            new = Block(a["name"], a["start"], a["start"] + a["size"] - 1, d == "create_byte_mapped",
                        a.get("mapped_to"))
            assert not any(b.overlaps(new.start, new.end) for b in st.blocks), "Ghidra refuses overlapping blocks"
            st.blocks.append(new)
        elif d == "add_label":
            syms = st.symbols.setdefault(a["addr"], [])
            if a["primary"]:
                syms[:] = [(n, s, False) for n, s, _ in syms]
            syms.append((a["name"], "IMPORTED", a["primary"] or not syms))
        elif d == "define_struct":
            st.types[a["name"]] = [(f["name"], f["offset"], f["size"]) for f in a["fields"]]
        elif d == "apply_type":
            st.data_at[a["addr"]] = a["type"]
        elif d == "set_bookmark":
            st.bookmarks[(a["addr"], a["category"])] = a["comment"]
        elif d == "set_notes":
            st.notes = a["text"]
        elif d == "set_owned":
            st.owned = a["value"]
        else:
            raise AssertionError(d)
    return st


def test_second_apply_changes_nothing(gen, ex):
    s0 = loaded_state(gen, ex)
    p1 = plan_apply(ex, s0)
    assert p1.refused is None and p1.actions
    s1 = execute(s0, p1)
    p2 = plan_apply(ex, s1)
    assert p2.actions == [], p2.kinds()


def test_alias_is_byte_mapped_onto_loaded_view(gen, ex):
    s1 = execute(loaded_state(gen, ex), plan_apply(ex, loaded_state(gen, ex)))
    alias = next(b for b in s1.blocks if b.start == 0xA0000000)
    assert alias.mapped_to == 0x80000000 and alias.initialized


def test_image_loaded_at_alias_maps_cached_view_onto_it(gen, ex):
    s0 = loaded_state(gen, ex, shift=0x20000000)  # flash bytes at 0xA0000000
    s0.blocks = [b for b in s0.blocks if not b.start >= 0xCF000000]  # keep it simple: only the flash part
    s1 = execute(s0, plan_apply(ex, s0))
    cached = next(b for b in s1.blocks if b.start == 0x80000000)
    assert cached.mapped_to == 0xA0000000
    assert plan_apply(ex, s1).actions == []


def test_unloaded_region_gets_one_uninitialized_canonical_block(gen, ex):
    s1 = execute(loaded_state(gen, ex), plan_apply(ex, loaded_state(gen, ex)))
    dspr = [b for b in s1.blocks if 0x70000000 <= b.start < 0x70100000]
    assert len(dspr) == 1 and not dspr[0].initialized


def test_user_symbol_is_kept_and_conflict_reported(gen, ex):
    s0 = loaded_state(gen, ex)
    main = next(s for s in ex["model"]["symbols"] if s["name"] == "main")
    s0.symbols[main["addr"]] = [("my_main", "USER_DEFINED", True)]
    p1 = plan_apply(ex, s0)
    add = next(a for a in p1.actions if a["do"] == "add_label" and a["name"] == "main")
    assert add["primary"] is False
    assert any("kept your 'my_main'" in r for r in p1.report)
    s1 = execute(s0, p1)
    assert ("my_main", "USER_DEFINED", True) in s1.symbols[main["addr"]]
    assert plan_apply(ex, s1).actions == []


def test_hash_mismatch_refused(gen, ex):
    s0 = replace(loaded_state(gen, ex), sha256="0" * 64)
    p = plan_apply(ex, s0)
    assert p.refused and "differs" in p.refused and p.actions == []


def test_bookmarks_merge_per_address_and_category(gen, ex):
    p = plan_apply(ex, loaded_state(gen, ex))
    keys = [(a["addr"], a["category"]) for a in p.actions if a["do"] == "set_bookmark"]
    assert len(keys) == len(set(keys))
    hdr = next(a for a in p.actions if a["do"] == "set_bookmark" and a["addr"] == 0xAF400000
               and a["category"] == "ECUForge.Observed")
    assert "bmhd.header@UCB_BMHD0_ORIG" in hdr["comment"]


def test_every_finding_lands_somewhere(gen, ex):
    s1 = execute(loaded_state(gen, ex), plan_apply(ex, loaded_state(gen, ex)))
    text = s1.notes + "\n" + "\n".join(s1.bookmarks.values())
    for f in ex["model"]["findings"]:
        assert f"[{f['id']}]" in text


def test_bmhd_type_applied_once(gen, ex):
    s1 = execute(loaded_state(gen, ex), plan_apply(ex, loaded_state(gen, ex)))
    assert s1.data_at[0xAF400000] == "ECUForge_BMHD"
    assert s1.types["ECUForge_BMHD"][0] == ("BMI", 0, 2)


def test_existing_data_not_overwritten(gen, ex):
    s0 = loaded_state(gen, ex)
    s0.data_at[0xAF400000] = "dword"
    p = plan_apply(ex, s0)
    assert not any(a["do"] == "apply_type" for a in p.actions)
    assert any("'dword' already defined" in r for r in p.report)


def test_owned_blocks_recorded(gen, ex):
    s1 = execute(loaded_state(gen, ex), plan_apply(ex, loaded_state(gen, ex)))
    created = {b.name for b in s1.blocks if not b.name.startswith("ram_")}
    assert set(s1.owned["blocks"]) == created and s1.owned["program_sha256"] == ex["model"]["program"]["sha256"]


def test_adapter_handles_every_planned_action():
    """The PyGhidra adapter cannot run here; at least it must name every action the plan can emit."""
    import inspect
    import re

    import ecuforge.ghidra.adapter as adapter
    import ecuforge.ghidra.plan as plan
    emitted = set(re.findall(r'"do": "([a-z_]+)"', inspect.getsource(plan)))
    handled = set(re.findall(r'd == "([a-z_]+)"', inspect.getsource(adapter.execute)))
    assert emitted and emitted <= handled, emitted - handled
