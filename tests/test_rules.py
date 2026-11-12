"""Project rules enforced as tests: fail-safe parsers, no toolchain branching in
analyzers, no unexplained hardware constants in analysis code."""
import re
from pathlib import Path

from conftest import ROOT, has
from reauto.analyze import open_project, run_all

PKG = ROOT / "reauto"


def test_gnu_map_unknown_construct_is_reported_not_dropped(gen, tmp_path):
    m = (gen / "app_gnu.map").read_text().replace(
        "LOAD obj/main.o", "LOAD obj/main.o\nSOME_FUTURE_DIRECTIVE (foo, bar)\n")
    m = m.replace(" *(.text .text.*)", " *(.text .text.*)\n                0x80000200                . = ALIGN (0x4)")
    (tmp_path / "u.map").write_text(m)
    p = open_project(elf=gen / "app.elf", map_=tmp_path / "u.map")
    f = next(f for f in p.store.query(topic="input", kind="unknown") if "SOME_FUTURE_DIRECTIVE" in f.claim)
    assert f.sources[0].locator.startswith("line ") and f.sources[0].type == "MAP"
    assert "." not in {s.name for s in p.map.symbols}  # location counter is not a symbol


def test_tasking_unknown_table_and_lsl_statement(gen, tmp_path):
    m = (gen / "app_tasking.map").read_text() + (
        "\n+----------------+\n| Future | Column |\n|================|\n| a      | b      |\n+----------------+\n")
    (tmp_path / "t.map").write_text(m)
    (tmp_path / "t.lsl").write_text((gen / "app.lsl").read_text() + "\nunknown_block foo { x = 1; }\n")
    p = open_project(map_=tmp_path / "t.map", lsl=tmp_path / "t.lsl")
    claims = [f.claim for f in p.store.query(topic="input", kind="unknown")]
    assert any("unsupported table: Future | Column" in c for c in claims)
    assert any("LSL statement not modelled" in c and "unknown_block" in c for c in claims)


def test_bad_hex_record_is_reported_and_bytes_stay_unknown(gen, tmp_path):
    lines = (gen / "app.hex").read_text().splitlines()
    i = next(k for k, l in enumerate(lines) if l.startswith(":10100000"))  # first record of .rodata
    lines[i] = lines[i][:-2] + ("00" if lines[i][-2:] != "00" else "01")
    (tmp_path / "b.hex").write_text("\n".join(lines) + "\n")
    p = open_project(image=tmp_path / "b.hex")
    f = next(f for f in p.store.query(topic="input", kind="unknown") if "checksum error" in f.claim)
    assert f.severity == "error" and f.sources[0].locator == f"line {i + 1}"
    assert p.image.read(0x80001000, 2) is None  # not guessed
    assert p.image.read(0x80000200, 4) is not None  # rest of the file still loaded


def test_no_toolchain_branching_in_analyzers():
    pat = re.compile(r"""(toolchain|compiler)\s*==|startswith\(["'](gnu|tasking|lsl|hightec|ghs)""", re.I)
    for d in ("core", "architecture", "silicon", "semantics"):
        for f in (PKG / d).rglob("*.py"):
            assert not pat.search(f.read_text()), f


def test_no_unexplained_hardware_constants_in_analysis_code():
    """Integer literals >= 0x10000 in analysis code must be format-level or cited in the module docstring.
    Hardware addresses belong in profiles / architecture specs with provenance."""
    import ast
    allowed = {0xFFFFFFFF}
    cited = {"crc.py": {0x04C11DB7}}  # IEEE 802.3 polynomial, cited in crc.py docstring (AP32381)
    for d in ("core", "architecture", "silicon", "semantics"):
        for f in (PKG / d).rglob("*.py"):
            for node in ast.walk(ast.parse(f.read_text())):
                if isinstance(node, ast.Constant) and isinstance(node.value, int) and not isinstance(node.value, bool):
                    v = node.value
                    if v >= 0x10000 and v not in allowed:
                        assert v in cited.get(f.name, set()), (str(f), hex(v))
