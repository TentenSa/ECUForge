"""Repository guard: provenance, binary placement, size cap."""
import importlib.util
import shutil

import pytest

from conftest import ROOT

pytest.importorskip("yaml")
spec = importlib.util.spec_from_file_location("check_repo", ROOT / "scripts/check_repo.py")
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


def test_repository_is_clean():
    assert guard.run(5.0) == []


@pytest.fixture
def tree(tmp_path, monkeypatch):
    for d in ("fixtures/synthetic", "fixtures/fuzz", "fixtures/reference"):
        shutil.copytree(ROOT / d, tmp_path / d, ignore=shutil.ignore_patterns("__pycache__"))
    (tmp_path / "fixtures/public").mkdir()
    monkeypatch.setattr(guard, "ROOT", tmp_path)
    monkeypatch.setattr(guard, "tracked_files", lambda: [
        str(p.relative_to(tmp_path)) for p in tmp_path.rglob("*") if p.is_file()])
    return tmp_path


def test_binary_outside_fixtures_fails(tree):
    (tree / "src").mkdir()
    (tree / "src/app.hex").write_text(":00000001FF\n")
    (tree / "notes.dat").write_bytes(b"abc\0def")
    errs = guard.run(5.0)
    assert any("src/app.hex" in e for e in errs) and any("notes.dat" in e for e in errs)


def test_unlisted_or_changed_fixture_file_fails(tree):
    (tree / "fixtures/fuzz/seeds/extra.map").write_text("x\n")
    (tree / "fixtures/fuzz/seeds/minimal.hex").write_text(":00000001FF\n")
    errs = guard.run(5.0)
    assert any("extra.map: not listed" in e for e in errs)
    assert any("minimal.hex: sha256 differs" in e for e in errs)


def test_public_fixture_needs_rights(tree):
    d = tree / "fixtures/public/example"
    d.mkdir()
    (d / "a.elf").write_bytes(b"\x7fELF")
    assert any("missing provenance.yaml" in e for e in guard.run(5.0))
    (d / "provenance.yaml").write_text("schema_version: 1\norigin: {type: public}\nrights: {license: MIT}\n"
                                       "purpose: {fixture_class: public}\nverification: {reviewed: true}\n")
    errs = guard.run(5.0)
    assert any("redistribution_allowed" in e for e in errs) and any("source_url" in e for e in errs)


def test_size_cap(tree):
    (tree / "fixtures/fuzz/big.txt").write_text("x" * 2048)
    assert any("exceeds" in e for e in guard.run(0.001))
