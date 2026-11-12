"""Project rules enforced as tests: fail-safe parsers, no toolchain branching in
analyzers, no unexplained hardware constants in analysis code."""
import re

from conftest import ROOT, has
from reauto.analyze import open_project

PKG = ROOT / "reauto"


def test_gnu_map_events_preserved_and_promoted_only_when_affecting(gen, tmp_path):
    m = (gen / "app_gnu.map").read_text().replace(
        "LOAD obj/main.o", "LOAD obj/main.o\nSOME_HEADER_NOISE (foo, bar)")  # outside any section
    m = m.replace(" *(.text .text.*)", " *(.text .text.*)\n ??? odd_input_construct\n"
                  "                0x80000200                . = ALIGN (0x4)")  # inside .text
    (tmp_path / "u.map").write_text(m)
    p = open_project(elf=gen / "app.elf", map_=tmp_path / "u.map")
    raws = {e["raw"]: e for e in p.store.parse_events}
    assert "SOME_HEADER_NOISE (foo, bar)" in raws and not raws["SOME_HEADER_NOISE (foo, bar)"]["affects"]
    assert raws["??? odd_input_construct"]["affects"]
    claims = [f.claim for f in p.store.query(topic="input", kind="unknown")]
    assert any("odd_input_construct" in c and "output section .text" in c for c in claims)
    assert not any("SOME_HEADER_NOISE" in c for c in claims)  # preserved, not promoted
    assert has(p, r"1 parse events .* do not affect any analysis", topic="input")
    assert "." not in {s.name for s in p.map.symbols}
    assert all(e["sha256"] for e in p.store.parse_events)


def test_tasking_unknown_table_and_lsl_statement(gen, tmp_path):
    m = (gen / "app_tasking.map").read_text() + (
        "\n+----------------+\n| Future | Column |\n|================|\n| a      | b      |\n+----------------+\n")
    (tmp_path / "t.map").write_text(m)
    (tmp_path / "t.lsl").write_text((gen / "app.lsl").read_text() + "\nunknown_block foo { x = 1; }\n")
    p = open_project(map_=tmp_path / "t.map", lsl=tmp_path / "t.lsl")
    kinds = {e["kind"] for e in p.store.parse_events}
    assert {"UNSUPPORTED_TABLE", "UNRECOGNIZED_CONSTRUCT"} <= kinds
    claims = [f.claim for f in p.store.query(topic="input", kind="unknown")]
    assert any("LSL top level" in c and "unknown_block" in c for c in claims)
    assert not any("Future | Column" in c for c in claims)


def test_bad_hex_record_is_reported_and_bytes_stay_unknown(gen, tmp_path):
    lines = (gen / "app.hex").read_text().splitlines()
    i = next(k for k, l in enumerate(lines) if l.startswith(":10100000"))  # first record of .rodata
    lines[i] = lines[i][:-2] + ("00" if lines[i][-2:] != "00" else "01")
    (tmp_path / "b.hex").write_text("\n".join(lines) + "\n")
    p = open_project(image=tmp_path / "b.hex")
    f = next(f for f in p.store.query(topic="input", kind="unknown") if "checksum error" in f.claim)
    assert f.data["event"] == "REJECTED_RECORD"
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
