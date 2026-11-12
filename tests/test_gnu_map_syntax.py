"""GNU map output-section header variants, detected by syntax (not tool version)."""
from reauto.toolchains.gnu.map import parse_gnu_map

HEAD = """Memory Configuration

Name             Origin             Length             Attributes
rom              0x80000000         0x00010000         xr
ram              0x70000000         0x00001000         w!x
*default*        0x00000000         0xffffffff

Linker script and memory map

"""


def parse(tmp_path, body):
    f = tmp_path / "m.map"
    f.write_text(HEAD + body)
    return parse_gnu_map(f, "m")


def by_name(lm):
    return {s.name: s for s in lm.sections}


def test_single_line_header(tmp_path):
    lm = parse(tmp_path, ".text           0x80000000       0x20\n .text  0x80000000  0x20 a.o\n")
    s = by_name(lm)[".text"]
    assert (s.addr, s.size, s.line, s.line_end, s.region, s.region_declared) == (0x80000000, 0x20, 10, 10, "rom", False)
    assert lm.events == []


def test_two_line_header_with_memory_region(tmp_path):
    lm = parse(tmp_path, ".startup        memory region -> rom\n                0x80000020        0xc\n"
                         " .startup       0x80000020        0xc s.o\n")
    s = by_name(lm)[".startup"]
    assert (s.addr, s.size, s.region, s.region_declared, s.line, s.line_end) == (0x80000020, 0xC, "rom", True, 10, 11)
    assert s.inputs[0].obj == "s.o" and lm.events == []


def test_two_line_header_without_region_and_with_load_address(tmp_path):
    lm = parse(tmp_path, ".a_very_long_output_section_name\n                0x70000000       0x10 load address 0x80000100\n")
    s = by_name(lm)[".a_very_long_output_section_name"]
    assert (s.addr, s.size, s.lma) == (0x70000000, 0x10, 0x80000100)


def test_region_clause_with_load_address_on_continuation(tmp_path):
    lm = parse(tmp_path, ".data           memory region -> ram\n"
                         "                0x70000000       0x14 load address 0x80008000\n")
    s = by_name(lm)[".data"]
    assert (s.lma, s.region, s.region_declared) == (0x80008000, "ram", True)


def test_multiple_consecutive_sections_and_orphans(tmp_path):
    body = (".text           memory region -> rom\n                0x80000000       0x10\n"
            ".calib_curve    memory region -> rom\n                0x80000010       0x10\n"  # orphan
            " .calib_curve   0x80000010       0x10 m.o\n"
            ".zeroed         memory region -> ram\n                0x70000000        0x4\n")  # orphan
    lm = parse(tmp_path, body)
    assert [s.name for s in lm.sections] == [".text", ".calib_curve", ".zeroed"]
    assert by_name(lm)[".zeroed"].region == "ram" and lm.events == []


def test_empty_output_section_is_recognised_not_an_event(tmp_path):
    lm = parse(tmp_path, ".rodata\n *(.rodata .rodata.*)\n.text 0x80000000 0x4\n")
    assert lm.empty_sections == [(".rodata", 10)] and lm.events == []
    assert [s.name for s in lm.sections] == [".text"]


def test_interrupted_two_line_record(tmp_path):
    lm = parse(tmp_path, ".startup        memory region -> rom\n                garbage here\n")
    assert lm.sections == []
    ev = [e for e in lm.events if e.kind == "INCOMPLETE_ENTRY"]
    assert ev and ev[0].line == 10 and ".startup" in ev[0].raw


def test_unexpected_continuation_line(tmp_path):
    lm = parse(tmp_path, ".text 0x80000000 0x10\n                0x80000000       0x10\n")  # stray addr/size
    assert len(lm.sections) == 1 and any(e.line == 11 for e in lm.events)


def test_data_statements_and_relaxation_lines_recognised(tmp_path):
    lm = parse(tmp_path, ".tab            memory region -> rom\n                0x80000000        0x8\n"
                         "                0x80000000        0x4 LONG 0x70001000 ADDR (.bss)\n"
                         "                0x80000004        0x4 LONG 0xffffffffffffffff\n"
                         "                0x2e (size before relaxing)\n")
    assert len(lm.sections) == 1 and lm.events == []
