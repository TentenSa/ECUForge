"""Synthetic class: maps, address-space views and conflicting evidence (L0/L1)."""
from conftest import find, has
from reauto.analyze import open_project, run_all


def test_gnu_map(gen):
    p = open_project(elf=gen / "app.elf", map_=gen / "app_gnu.map")
    text = next(s for s in p.map.sections if s.name == ".text")
    assert [i.name for i in text.inputs][1] == ".text.NvM_MainFunction"
    assert next(s for s in p.map.sections if s.name == ".data").lma == 0x80001300


def test_tasking_map_and_lsl(gen):
    p = open_project(image=gen / "app_tasking.s19", map_=gen / "app_tasking.map", lsl=gen / "app.lsl")
    assert p.map.toolchain == "tasking"
    pf = next(r for r in p.map.regions if r.name == "mpe:pfls0")
    assert pf.length == 0x300000 and 0xA0000000 in pf.aliases
    assert next(s for s in p.map.sections if s.name == ".data").lma == 0x80001300


def test_relations_documented_profile(gen):
    p = open_project(image=gen / "app.hex", elf=gen / "app.elf", map_=gen / "app_gnu.map")
    lay = run_all(p)["layout"]
    rel = {r.name: r.physical_relation for r in lay.regions}
    assert rel == {"pfls0": "UNKNOWN", "dsram0": "CONTAINED", "dsram1": "CONTAINED"}
    assert has(p, r"0x80100000\+0x8\] are OUTSIDE every linked load range", topic="layout", min_severity="warning")
    assert has(p, r"0xaf400000.*documented as UCB_BMHD0_ORIG", topic="layout")


def test_relations_aliased_with_synthetic_profile(gen, syn_profile):
    p = open_project(image=gen / "app.hex", elf=gen / "app.elf", map_=gen / "app_gnu.map", device=syn_profile)
    run_all(p)
    assert has(p, r"Linker region pfls0 .* physical: CONTAINED PFLASH", topic="layout")
    assert has(p, r"synthetic facts", topic="input", min_severity="warning")


def test_linker_vs_physical_boundary_conflict(gen, tmp_path):
    m = (gen / "app_gnu.map").read_text().replace(
        "dsram1           0x60000000         0x0003c000", "dsram1           0x60000000         0x00040000")
    (tmp_path / "m.map").write_text(m)
    p = open_project(elf=gen / "app.elf", map_=tmp_path / "m.map")
    run_all(p)
    c = find(p, r"Linker region dsram1 .* and documented CPU1 DSPR .* disagree", kind="conflict")
    types = sorted(x["type"] for x in c.data["claims"])
    assert types == ["MAP", "MCU_PROFILE"]  # both kept; nothing wins


def test_map_elf_conflict(gen, tmp_path):
    m = (gen / "app_gnu.map").read_text().replace("0x80000500                EcuM_Init",
                                                    "0x80000504                EcuM_Init")
    (tmp_path / "o.map").write_text(m)
    p = open_project(elf=gen / "app.elf", map_=tmp_path / "o.map")
    run_all(p)
    c = find(p, r"EcuM_Init: map says 0x80000504, ELF says 0x80000500", kind="conflict")
    assert [x["value"] for x in c.data["claims"]] == ["0x80000504", "0x80000500"]


def test_levels(gen):
    p = open_project(image=gen / "app.hex", elf=gen / "app.elf", map_=gen / "app_gnu.map")
    run_all(p)
    assert {f.level for f in p.store.query(topic="input")} == {"L0"}
    assert {f.level for f in p.store.query(topic="startup")} == {"L1"}
    assert any(f.level == "L0" for f in p.store.query(topic="layout"))  # per-section artifact facts


def test_views_are_typed_and_not_mixed():
    import pytest
    from reauto.core.views import ImageMemoryRegion, LinkerMemoryRegion, PhysicalMemoryRegion, relate_complete, \
        relate_physical
    from reauto.silicon.infineon.aurix.profile import DeviceProfile
    phys = PhysicalMemoryRegion("physical", "P", 0x1000, 0x100)
    link = LinkerMemoryRegion("linker-region", "L", 0x1000, 0x80)
    img = ImageMemoryRegion("image", "I", 0x1000, 0x10)
    prof = DeviceProfile.load("tc38x")
    assert relate_physical(prof, link, [phys]).relation == "CONTAINED"
    with pytest.raises(TypeError):
        relate_physical(prof, phys, [phys])  # physical is never a subject
    with pytest.raises(TypeError):
        relate_complete(img, [phys])  # physical view is incomplete by construction
