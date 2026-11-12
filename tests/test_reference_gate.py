"""Release gate: committed reference builds must verify with no unexpected unknowns,
conflicts, false claims or unexplained findings. Rebuild/reproducibility runs only
where a TriCore GCC is installed."""
import json
import shutil
import subprocess

import pytest

from conftest import ROOT
from reauto.verify import verify

REFS = sorted(p.parent for p in (ROOT / "fixtures/reference").glob("*/manifest.json"))


@pytest.mark.parametrize("ref", REFS, ids=[r.name for r in REFS])
def test_reference_gate(ref):
    m = json.loads((ref / "manifest.json").read_text())
    assert "allow_unknown" not in m
    assert m["verification"]["allow_unexpected_unknown"] is False
    vr, rec = verify(ref / "manifest.json")
    s = vr.score()
    assert (s["correct"], s["unknown"], s["conflict"], s["false_claim"], s["unexplained"]) == (
        s["expected_facts"] - s["expected_unknown"], 0, 0, 0, 0), rec["failures"] + rec["unexplained"]
    assert rec["result"] == "PASS"


@pytest.mark.skipif(shutil.which("tricore-elf-gcc") is None, reason="TriCore GCC not installed")
@pytest.mark.parametrize("ref", REFS, ids=[r.name for r in REFS])
def test_reference_rebuild_is_reproducible_and_matches_committed(ref, tmp_path):
    if not (ref / "check_reproducible.sh").exists():
        pytest.skip("no reproducibility script")
    assert subprocess.run([str(ref / "check_reproducible.sh")], capture_output=True).returncode == 0
    work = tmp_path / ref.name
    shutil.copytree(ref, work, ignore=shutil.ignore_patterns("out"))
    subprocess.run([str(work / "build_gnu.sh")], check=True, capture_output=True)
    for f in ("reference.elf", "reference.hex", "reference.map"):
        assert (work / "out" / f).read_bytes() == (ref / "out" / f).read_bytes(), f


def _manifest(gen, tmp_path, **policy):
    m = json.loads((gen / "manifest.json").read_text())
    m["artifacts"] = {k: str(gen / v) for k, v in m["artifacts"].items()}
    m["device"] = str(gen / m["device"])
    m["expect"]["L1"]["csa"].append({"core": 3, "start": "0x40000000", "size": "0x100"})  # rea-auto: no value
    m["verification"] = policy
    f = tmp_path / "m.json"
    f.write_text(json.dumps(m))
    return f


def test_unexpected_unknown_fails_gate(gen, tmp_path):
    vr, _ = verify(_manifest(gen, tmp_path, allow_unexpected_unknown=False, expected_unknowns=[]))
    assert vr.score()["unknown"] == 1 and not vr.ok


def test_listed_expected_unknown_passes_with_id_and_reason(gen, tmp_path):
    eu = [{"id": "EU-001", "what": "CSA CPU3", "reason": "fixture deliberately has no CPU3 CSA symbols"}]
    vr, rec = verify(_manifest(gen, tmp_path, allow_unexpected_unknown=False, expected_unknowns=eu))
    assert vr.score()["expected_unknown"] == 1 and vr.ok and rec["policy"]["expected_unknowns"][0]["id"] == "EU-001"


def test_expected_unknown_without_reason_rejected(gen, tmp_path):
    with pytest.raises(SystemExit):
        verify(_manifest(gen, tmp_path, allow_unexpected_unknown=False, expected_unknowns=[{"what": "CSA CPU3"}]))


def test_blanket_allow_unknown_rejected(gen, tmp_path):
    m = json.loads((gen / "manifest.json").read_text())
    m["allow_unknown"] = True
    f = tmp_path / "b.json"
    f.write_text(json.dumps(m))
    with pytest.raises(SystemExit):
        verify(f)


def test_image_coverage_expectation(gen, tmp_path):
    m = json.loads((gen / "manifest.json").read_text())
    m["artifacts"] = {k: str(gen / v) for k, v in m["artifacts"].items()}
    m["device"] = str(gen / m["device"])
    m["expect"]["L0"]["image"] = [{"addr": "0x80001000", "size": "0x100"}, {"addr": "0x90000000", "size": "0x10"}]
    f = tmp_path / "i.json"
    f.write_text(json.dumps(m))
    vr, _ = verify(f)
    cats = {c.what: c.category for c in vr.checks if c.what.startswith("image")}
    assert cats == {"image 0x80001000+0x100": "correct", "image 0x90000000+0x10": "unknown"}
