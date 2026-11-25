import json
from dataclasses import replace

import pytest

from ecuforge.analyze import open_project, run_all
from ecuforge.export.model import build_export, finding_id


@pytest.fixture(scope="module")
def gnu(gen, syn_profile):
    p = open_project(gen / "app.hex", gen / "app.elf", gen / "app_gnu.map", None, gen / "app.a2l", syn_profile,
                     experimental=True)
    return p, run_all(p)


@pytest.fixture(scope="module")
def tasking(gen, syn_profile):
    p = open_project(gen / "app_tasking.s19", None, gen / "app_tasking.map", gen / "app.lsl", None, syn_profile,
                     "tasking")
    return p, run_all(p)


@pytest.mark.parametrize("case", ["gnu", "tasking"])
def test_every_finding_has_a_unique_key(case, request):
    p, _ = request.getfixturevalue(case)
    keys = [f.key for f in p.store.findings]
    assert all(keys), [f.claim for f in p.store.findings if not f.key]
    assert len(set(keys)) == len(keys)
    assert not [k for k in keys if "#" in k]  # no rule emitted the same subject twice


def test_ids_unique_and_serialisable(gnu):
    e = build_export(*gnu)
    ids = [x["id"] for k in ("symbols", "findings") for x in e[k]]
    ids += [v["id"] for r in e["memory"] for v in r["views"]]
    assert len(ids) == len(set(ids))
    text = json.dumps(e)
    assert '"/' not in text  # no host paths


def test_finding_id_ignores_evidence_detail(gnu):
    p, _ = gnu
    f = p.store.findings[0]
    prog = build_export(*gnu)["program"]["sha256"]
    richer = replace(f, claim=f.claim + " (more evidence)", sources=f.sources + f.sources, data={"x": 1})
    assert finding_id(prog, richer.key) == finding_id(prog, f.key)


def test_finding_id_anchored_to_program(gnu):
    a = finding_id("a" * 64, "bmhd.header@UCB_BMHD0_ORIG")
    b = finding_id("b" * 64, "bmhd.header@UCB_BMHD0_ORIG")
    assert a != b


def test_export_is_deterministic(gen, syn_profile, gnu):
    p2 = open_project(gen / "app.hex", gen / "app.elf", gen / "app_gnu.map", None, gen / "app.a2l", syn_profile,
                      experimental=True)
    assert build_export(p2, run_all(p2)) == build_export(*gnu)


def test_alias_is_one_region_with_canonical_view(gnu):
    e = build_export(*gnu)
    pf = next(r for r in e["memory"] if r["id"] == "PFLASH")
    canon = [v for v in pf["views"] if v["canonical"]]
    alias = [v for v in pf["views"] if not v["canonical"]]
    assert len(canon) == 1 and canon[0]["start"] == 0x80000000
    assert len(alias) == 1 and alias[0]["start"] == 0xA0000000 and alias[0]["alias_of"] == canon[0]["id"]
    for r in e["memory"]:
        assert sum(v["canonical"] for v in r["views"]) == 1
        assert r["permissions"] is None


def test_alias_of_points_inside_same_region(gnu):
    for r in build_export(*gnu)["memory"]:
        ids = {v["id"] for v in r["views"]}
        assert all(v["alias_of"] in ids for v in r["views"] if v["alias_of"])
