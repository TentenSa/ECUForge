"""Synthetic classes: startup structures, copy tables, RAM init (L1)."""
import json
import struct

from conftest import find, has
from reauto.analyze import open_project, run_all


def _gnu(gen, **kw):
    p = open_project(image=gen / "app.hex", elf=gen / "app.elf", map_=gen / "app_gnu.map", **kw)
    return p, run_all(p)


def _tasking(gen, **kw):
    p = open_project(image=gen / "app_tasking.s19", map_=gen / "app_tasking.map", lsl=gen / "app.lsl", **kw)
    return p, run_all(p)


def test_csa_uses_cited_frame_size(gen):
    p, res = _gnu(gen)
    f = find(p, r"CPU0 CSA area .* = 128 frames of 64 B", topic="startup")
    assert any(s.type == "ARCH_SPEC" for s in f.sources)
    assert not has(p, r"holds only", topic="startup")  # undocumented heuristic removed


def test_vector_alignment_unknown_until_documented(gen):
    p, _ = _gnu(gen)
    assert has(p, r"trap table alignment rule not documented", topic="startup", kind="unknown")
    assert has(p, r"all 8 trap class entries contain code", topic="startup")


def test_gnu_init_tables_validated_and_coverage(gen):
    p, res = _gnu(gen)
    t = res["startup"]["init"]["tables"][0]
    assert t["kind"] == "derived" and t["copy"][0]["section"] == ".data" and t["clear"][0]["section"] == ".bss"
    assert has(p, r"\.CPU1\.bss .* no init-table record covers it", topic="startup", min_severity="warning")


def test_tasking_table_derived_with_rejection_reasons(gen):
    p, res = _tasking(gen)
    t = res["startup"]["init"]["tables"][0]
    assert t["kind"] == "derived" and t["layout"].startswith("untagged")
    rejected = {c["layout"]: c["reason"] for c in t["candidates"] if c["status"] == "REJECTED"}
    assert set(rejected) == {"tagged 16B: action,dst,src,len", "12B: dst,src,len (src=0 clear)"}
    assert all(rejected.values())
    assert has(p, r"\.CPU1\.bss .* no init-table record covers it", topic="startup")  # parity with GNU


def test_tasking_tagged_encoding_found(gen):
    p = open_project(image=gen / "app_tasking.s19", map_=gen / "app_tasking.map", lsl=gen / "app.lsl")
    seg = p.image.find(0x80001220)
    seg.data[0x80001220 - seg.start:] = struct.pack("<12I", 1, 0x70000000, 0x80001300, 0x40, 2, 0x70000100, 0,
                                                     0x80, 0, 0, 0, 0)
    t = run_all(p)["startup"]["init"]["tables"][0]
    assert t["kind"] == "derived" and t["layout"].startswith("tagged")


def test_tasking_garbage_is_unknown_with_reasons(gen):
    p = open_project(image=gen / "app_tasking.s19", map_=gen / "app_tasking.map", lsl=gen / "app.lsl")
    seg = p.image.find(0x80001220)
    seg.data[0x80001220 - seg.start:0x80001220 - seg.start + 0x24] = bytes(range(0x24))
    t = run_all(p)["startup"]["init"]["tables"][0]
    assert t["kind"] == "unknown" and all(c["status"] == "REJECTED" and c["reason"] for c in t["candidates"])


def test_tasking_pinned_layout(gen, tmp_path):
    prof = json.loads(open(gen / "profile_synthetic_tc38x.json").read())
    prof["tasking_copy_table"] = {"layout": "untagged 12B: copy(src,dst,len) / clear(dst,len,0)"}
    pf = tmp_path / "pin.json"
    pf.write_text(json.dumps(prof))
    p, res = _tasking(gen, device=str(pf))
    t = res["startup"]["init"]["tables"][0]
    assert t["pinned"] and len(t["candidates"]) == 1
