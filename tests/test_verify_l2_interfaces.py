"""Verification scoring, run record, experimental L2, CLI and MCP."""
import json
import subprocess
import sys

import pytest

from conftest import ROOT, has
from ecuforge.analyze import open_project, run_all
from ecuforge.verify import verify


def test_manifest_passes_with_full_score(gen):
    vr, rec = verify(gen / "manifest.json")
    s = vr.score()
    assert vr.ok and s["correct"] == s["expected_facts"] == 35 and s["false_claim"] == 0
    assert rec["result"] == "PASS" and rec["manifest"]["fixture_class"] == "synthetic"
    assert {a["type"] for a in rec["artifacts"]} == {"ELF", "HEX", "MAP", "A2L"}
    assert rec["profile"]["synthetic_facts"] > 0 and len(rec["profile"]["sha256"]) == 64


def _manifest(gen, tmp_path, mutate):
    m = json.loads((gen / "manifest.json").read_text())
    m["artifacts"] = {k: str(gen / v) for k, v in m["artifacts"].items()}
    m["device"] = str(gen / m["device"])
    mutate(m)
    f = tmp_path / "m.json"
    f.write_text(json.dumps(m))
    return f


def test_false_claim_and_unknown_are_distinguished(gen, tmp_path):
    def mutate(m):
        m["expect"]["L1"]["csa"][0]["size"] = "0x4000"  # ECUForge will confidently say 0x2000
        m["expect"]["L1"]["csa"].append({"core": 3, "start": "0x40000000", "size": "0x100"})  # absent
        m["verification"] = {"allow_unexpected_unknown": False, "expected_unknowns": []}
    vr, rec = verify(_manifest(gen, tmp_path, mutate))
    s = vr.score()
    assert s["false_claim"] == 1 and s["unknown"] == 1 and not vr.ok
    assert rec["failures"][0]["category"] in ("false_claim", "unknown")


def test_unexplained_findings_fail(gen, tmp_path):
    vr, _ = verify(_manifest(gen, tmp_path, lambda m: m.update(allowed_findings=[])))
    assert not vr.ok and any("Cal_Offset" in u for u in vr.unexplained)


def test_l2_is_gated(gen, syn_profile):
    p = open_project(image=gen / "app.hex", elf=gen / "app.elf", map_=gen / "app_gnu.map", a2l=gen / "app.a2l")
    res = run_all(p)
    assert res["a2l"] == {} and has(p, r"L2 semantics are experimental", topic="a2l")
    q = open_project(image=gen / "app.hex", elf=gen / "app.elf", map_=gen / "app_gnu.map", a2l=gen / "app.a2l",
                     device=syn_profile, experimental=True)
    r = run_all(q)
    assert r["a2l"]["addr_mismatch"] == 1 and r["modules"]["NvM"]["text"] == 0x100
    assert has(q, r"Cal_Gain = raw 1.25", topic="a2l")  # non-cached alias via synthetic bus alias


def test_cli(gen, tmp_path):
    r = subprocess.run([sys.executable, "-m", "ecuforge.cli", "analyze", "--image", str(gen / "app.hex"), "--elf",
                        str(gen / "app.elf"), "--map", str(gen / "app_gnu.map"), "-o", str(tmp_path)],
                       cwd=ROOT, capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr  # documented profile: no errors on the clean synthetic build
    run = json.loads((tmp_path / "run.json").read_text())
    assert run["tool"]["name"] == "ecuforge" and run["target"]["silicon"] == "infineon.aurix.tc3xx.tc38x"
    v = subprocess.run([sys.executable, "-m", "ecuforge.cli", "verify", str(gen / "manifest.json")], cwd=ROOT,
                       capture_output=True, text=True)
    assert v.returncode == 0 and "RESULT: PASS" in v.stdout


def test_mcp_tools(gen):
    pytest.importorskip("mcp")
    from ecuforge import mcp_server
    sid = mcp_server.open_build(str(gen / "app.hex"), str(gen / "app.elf"), str(gen / "app_gnu.map"))["session_id"]
    res = mcp_server.analyze(sid)
    assert res["run"]["tool"]["name"] == "ecuforge"
    assert mcp_server.get_findings(sid, kind="unknown")["total"] > 0
    assert mcp_server.read_memory(sid, "0x80001000", 2)["bytes"] == "2003"
    assert "MEMORY" in mcp_server.linker_draft(sid)
