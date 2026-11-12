"""Project rules enforced as tests: fail-safe parsers, no toolchain branching in
analyzers, no unexplained hardware constants in analysis code."""
import re

from conftest import ROOT
from reauto.analyze import open_project

PKG = ROOT / "reauto"


def test_events_are_telemetry_findings_are_aggregate(gen, tmp_path):
    m = (gen / "app_gnu.map").read_text().replace(
        "LOAD obj/main.o", "LOAD obj/main.o\nSOME_HEADER_NOISE (foo, bar)")
    m = m.replace(" *(.text .text.*)", " *(.text .text.*)\n ??? odd_input_construct\n"
                  "                0x80000200                . = ALIGN (0x4)")
    (tmp_path / "u.map").write_text(m)
    p = open_project(elf=gen / "app.elf", map_=tmp_path / "u.map")
    raws = {e["raw"] for e in p.store.parse_events}
    assert {"SOME_HEADER_NOISE (foo, bar)", "??? odd_input_construct"} <= raws  # lossless
    assert all(e["sha256"] for e in p.store.parse_events)
    unclassified = [f for f in p.store.query(topic="input") if f.data.get("code") == "PARSE_LINES_UNCLASSIFIED"]
    assert len(unclassified) == 1 and unclassified[0].data["count"] == 2  # one finding, not one per line
    assert "." not in {s.name for s in p.map.symbols}
    assert p.store.parse_health[p.map_art.short]["recovered"]["output_sections"] == 13


def test_structural_failure_detected_regardless_of_parser_state(gen, tmp_path):
    """Recreates the reference-build failure: section headers in a form the parser does not
    know, so it never enters a section and every line looks like header noise."""
    lines = []
    for line in (gen / "app_gnu.map").read_text().splitlines():
        if line and not line[0].isspace() and line.startswith("."):
            line = line.split()[0] + "  @@unknown header form@@"
        lines.append(line)
    (tmp_path / "x.map").write_text("\n".join(lines) + "\n")
    p = open_project(elf=gen / "app.elf", map_=tmp_path / "x.map")
    errs = [f for f in p.store.query(topic="input", min_severity="error")]
    assert len(errs) == 1 and errs[0].data["code"] == "MAP_STRUCTURE_NOT_RECOVERED"
    assert "recovered none" in errs[0].claim and errs[0].data["health"]["unrecognized_lines"] > 0
    assert len(p.store.parse_events) == errs[0].data["health"]["unrecognized_lines"]  # all kept as telemetry


def test_tasking_unknown_table_and_lsl_statement(gen, tmp_path):
    m = (gen / "app_tasking.map").read_text() + (
        "\n+----------------+\n| Future | Column |\n|================|\n| a      | b      |\n+----------------+\n")
    (tmp_path / "t.map").write_text(m)
    (tmp_path / "t.lsl").write_text((gen / "app.lsl").read_text() + "\nunknown_block foo { x = 1; }\n")
    p = open_project(map_=tmp_path / "t.map", lsl=tmp_path / "t.lsl")
    kinds = {e["kind"] for e in p.store.parse_events}
    assert {"UNSUPPORTED_TABLE", "UNRECOGNIZED_CONSTRUCT"} <= kinds
    assert not p.store.query(topic="input", min_severity="error")
    assert len([f for f in p.store.query(topic="input") if f.data.get("code") == "PARSE_LINES_UNCLASSIFIED"]) == 2


def test_lsl_without_recoverable_memory_is_structural_failure(tmp_path):
    (tmp_path / "b.lsl").write_text("memory pfls0 ( this is not lsl syntax\n")
    p = open_project(lsl=tmp_path / "b.lsl")
    assert any(f.data.get("code") == "LSL_STRUCTURE_NOT_RECOVERED" for f in p.store.query(topic="input"))


def test_bad_hex_record_is_reported_and_bytes_stay_unknown(gen, tmp_path):
    lines = (gen / "app.hex").read_text().splitlines()
    i = next(k for k, line in enumerate(lines) if line.startswith(":10100000"))
    lines[i] = lines[i][:-2] + ("00" if lines[i][-2:] != "00" else "01")
    (tmp_path / "b.hex").write_text("\n".join(lines) + "\n")
    p = open_project(image=tmp_path / "b.hex")
    f = next(f for f in p.store.query(topic="input") if f.data.get("code") == "PARSE_RECORDS_REJECTED")
    assert f.severity == "error" and f.data["lines"] == [i + 1]
    assert p.image.read(0x80001000, 2) is None and p.image.read(0x80000200, 4) is not None


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
