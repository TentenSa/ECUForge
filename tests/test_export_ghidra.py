import json

import pytest

from ecuforge.analyze import open_project, run_all
from ecuforge.cli import main
from ecuforge.export.ghidra import CATEGORY, build_ghidra_export
from ecuforge.workspace import Workspace


@pytest.fixture(scope="module")
def gx(gen, syn_profile):
    p = open_project(gen / "app.hex", gen / "app.elf", gen / "app_gnu.map", None, None, syn_profile)
    return p, build_ghidra_export(p, run_all(p))


def test_every_finding_lands_once(gx):
    p, e = gx
    ids = [b["id"] for b in e["bookmarks"]] + [n["id"] for n in e["program_notes"]]
    assert sorted(ids) == sorted(f["id"] for f in e["model"]["findings"])
    assert len(ids) == len(set(ids))
    assert {b["category"] for b in e["bookmarks"]} <= set(CATEGORY.values())


def test_bookmark_comment_carries_provenance(gx):
    _, e = gx
    b = next(b for b in e["bookmarks"] if b["comment"].startswith("bmhd.header@UCB_BMHD0_ORIG"))
    assert b["address"] == 0xAF400000 and b["category"] == "ECUForge.Observed"
    assert "observed L1" in b["comment"] and "HEX@" in b["comment"]


def test_derived_finding_inherits_parent_address(gx):
    _, e = gx
    b = next(b for b in e["bookmarks"] if b["comment"].startswith("bmhd.bmi@UCB_BMHD0_ORIG"))
    assert b["address"] == 0xAF400000


def test_section_permissions_come_from_elf(gx):
    p, e = gx
    secs = {s["name"]: s for s in e["model"]["sections"]}
    assert secs[".text"]["permissions"] == "r-x" and secs[".text"]["permissions_source"] == "elf"
    assert secs[".data"]["permissions"] == "rw-"
    assert secs[".rodata"]["permissions"] == "r--"


def test_no_elf_means_no_permissions(gen, syn_profile):
    p = open_project(gen / "app_tasking.s19", None, gen / "app_tasking.map", gen / "app.lsl", None, syn_profile,
                     "tasking")
    e = build_ghidra_export(p, run_all(p))
    assert all(s["permissions"] is None and s["permissions_source"] is None for s in e["model"]["sections"])


def test_bmhd_type_from_profile_offsets(gx):
    _, e = gx
    t = e["types"][0]
    assert t["name"] == "ECUForge_BMHD" and t["size"] == 16
    assert [(f["name"], f["offset"]) for f in t["fields"]] == [
        ("BMI", 0), ("BMHDID", 2), ("STAD", 4), ("CRCBMHD", 8), ("CRCBMHD_N", 12)]
    assert {"type": "ECUForge_BMHD", "address": 0xAF400000, "label": "UCB_BMHD0_ORIG"} in e["type_instances"]


def test_cli_export_is_deterministic_and_path_free(tmp_path, gen, syn_profile):
    root = tmp_path / "w"
    Workspace.init(root, device=syn_profile)
    for f in ("app.hex", "app.elf", "app_gnu.map"):
        assert main(["add", str(gen / f), "-C", str(root)]) == 0
    assert main(["export", "ghidra", "-C", str(root)]) == 0
    out = root / "exports/ghidra/ecuforge-ghidra.json"
    first = out.read_text()
    assert main(["export", "ghidra", "-C", str(root)]) == 0
    assert out.read_text() == first
    assert str(tmp_path) not in first and '"/' not in first
    d = json.loads(first)
    assert d["format"] == "ecuforge-ghidra" and d["model"]["program"]["name"] == "app.hex"
