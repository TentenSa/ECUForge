import json

import pytest

from ecuforge.cli import main
from ecuforge.workspace import Workspace, WorkspaceError


@pytest.fixture
def ws(tmp_path, gen, syn_profile):
    w = Workspace.init(tmp_path / "proj", device=syn_profile)
    for f in ("app.hex", "app.elf", "app_gnu.map", "app.a2l"):
        w.add(gen / f)
    return w


def test_layout_and_manifest(ws):
    for d in ("objects/sha256", "analysis/runs", "exports/ghidra", "reports"):
        assert (ws.root / d).is_dir()
    m = json.loads((ws.root / "ecuforge.json").read_text())
    assert m["schema_version"] == 1
    assert {a["role"] for a in m["artifacts"]} == {"image", "elf", "map", "a2l", "profile"}
    assert m["target"]["device"] is None  # profile file stored as an object, no host path


def test_add_is_idempotent(ws, gen):
    before = (ws.root / "ecuforge.json").read_text()
    entry, added = ws.add(gen / "app.elf")
    assert not added and entry["role"] == "elf"
    assert (ws.root / "ecuforge.json").read_text() == before


def test_identity_separate_from_role(tmp_path, gen, syn_profile):
    w = Workspace.init(tmp_path / "p2", device=syn_profile)
    a, _ = w.add(gen / "app.elf", "image")
    b, _ = w.add(gen / "app.elf", "elf")
    assert a["sha256"] == b["sha256"] and a["role"] != b["role"]
    assert len(list((w.root / "objects/sha256").iterdir())) == 2  # profile + one ELF object


def test_role_collision_rejected(ws, gen):
    with pytest.raises(WorkspaceError, match="already holds"):
        ws.add(gen / "app.s19", "image")


def test_modified_object_detected(ws):
    obj = ws.object_path(ws.by_role("map"))
    obj.chmod(0o644)
    obj.write_text(obj.read_text() + "\n")
    with pytest.raises(WorkspaceError, match="missing or modified"):
        ws.analyze()


def test_analysis_reproducible_and_path_free(ws):
    r1, id1 = ws.analyze()
    r2, id2 = ws.analyze()
    assert id1 == id2 and r1["result"] == r2["result"]
    assert len(list((ws.root / "analysis/runs").iterdir())) == 1
    text = (ws.root / "analysis/current.json").read_text()
    assert str(ws.root) not in text
    assert '"/' not in text  # no absolute paths of any kind
    res = r1["result"]
    assert res["schema_version"] == 1 and res["profile_id"] and res["ecuforge_version"]


def test_workspace_matches_file_mode(ws, gen, syn_profile):
    from ecuforge.analyze import open_project, run_all
    p = open_project(gen / "app.hex", gen / "app.elf", gen / "app_gnu.map", None, gen / "app.a2l", syn_profile)
    run_all(p)
    rec, _ = ws.analyze()
    assert [f.claim for f in p.store.findings] == [f["claim"] for f in rec["result"]["evidence"]["findings"]]


def test_cli_flow(tmp_path, gen, syn_profile, capsys):
    root = str(tmp_path / "cli")
    assert main(["init", root, "--device", syn_profile]) == 0
    for f in ("app.hex", "app.elf", "app_gnu.map"):
        assert main(["add", str(gen / f), "-C", root]) == 0
    assert main(["add", str(gen / "app.elf"), "-C", root]) == 0
    assert "already present" in capsys.readouterr().out
    assert main(["analyze", "-C", root]) == 0
    assert main(["show", "findings", "--topic", "symbols", "-C", root]) == 0
    assert "SYMBOLS-" in capsys.readouterr().out
    assert main(["analyze", "-C", str(tmp_path)]) == 2  # not a workspace
