from ecuforge.cli import main
from ecuforge.ghidra.doctor import TC162_ONLY, check, render

LDEFS = '<language_definitions><language id="tricore:LE:32:default"/><language id="tricore:LE:32:tc29x"/>' \
        '</language_definitions>'


def fake_install(tmp_path, sinc: str, version="12.3"):
    root = tmp_path / "ghidra"
    lang = root / "Ghidra" / "Processors" / "tricore" / "data" / "languages"
    lang.mkdir(parents=True)
    (root / "Ghidra" / "application.properties").write_text(f"application.name=Ghidra\napplication.version={version}\n")
    (lang / "tricore.ldefs").write_text(LDEFS)
    (lang / "tricore.sinc").write_text(sinc)
    return root


def test_reports_missing_tc162_mnemonics(tmp_path):
    root = fake_install(tmp_path, ":crc32 Rd is op=1 {}\n:crcn Rd is op=2 {}\n")
    r = check(str(root))
    assert r["version"] == "12.3" and not r["version_tested"]
    assert r["tricore_languages"] == ["tricore:LE:32:default", "tricore:LE:32:tc29x"]
    assert "crcn" not in r["tc162_missing"] and "shuffle" in r["tc162_missing"]
    text, _ = render(r)
    assert "not yet tested" in text and "shuffle" in text and "TC4x" in text


def test_all_tc162_named(tmp_path):
    root = fake_install(tmp_path, "".join(f":{m} Rd is op=1 {{}}\n" for m in TC162_ONLY))
    assert check(str(root))["tc162_missing"] == []


def test_no_install(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("GHIDRA_INSTALL_DIR", raising=False)
    r = check(None)
    assert not r["install_dir_set"] and not r["tricore_module"]
    assert main(["doctor", "ghidra"]) == 1
    assert "not set" in capsys.readouterr().out


def test_apply_without_export_fails_cleanly(tmp_path, gen, syn_profile, capsys):
    from ecuforge.workspace import Workspace
    Workspace.init(tmp_path / "w", device=syn_profile)
    rc = main(["ghidra", "apply", "--ghidra-project", str(tmp_path / "P.gpr"), "--program", "/app.hex",
               "-C", str(tmp_path / "w")])
    assert rc == 2 and "run `ecuforge export ghidra` first" in capsys.readouterr().err
